// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Sealing by what the host has (ADR 0025, step 1b). A SEV-SNP guest has a
// key of its own derived by the chip (ADR 0016); a TDX Trust Domain, an
// Azure confidential VM and most servers have a TPM 2.0, virtual or
// discrete (ADR 0022); a Nitro enclave has KMS, released to its
// attestation document (ADR 0036); the simulated TEE has its weak key.
// tee.sealer says which the daemon uses — "auto" takes the TEE's own key
// where there is one and the TPM otherwise — and every sealed file names
// the sealer it was made with, so a file sealed one way is not opened as
// another.

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/shared/awskms"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/vsock"
)

// SealerMode is the daemon's tee.sealer.
type SealerMode string

const (
	// SealerModeAuto: the TEE's own key where it has one (SEV-SNP; on a
	// Nitro enclave, KMS released to its attestation), the host's TPM 2.0
	// otherwise (TDX, Azure), the simulated key off hardware.
	SealerModeAuto SealerMode = "auto"
	// SealerModeTEE: the TEE's own key only; refused on a TEE that has none.
	SealerModeTEE SealerMode = "tee"
	// SealerModeTPM2: the host's TPM 2.0 — a vTPM or a discrete TPM —
	// whatever the TEE, through tpm2-tools (ADR 0022).
	SealerModeTPM2 SealerMode = "tpm2"
	// SealerModeBoth: the TEE's own key and the host's TPM 2.0, nested
	// (ADR 0037) — a file opens only on this chip, at this measurement and
	// policy, and on a boot the TPM's PCR policy names. SEV-SNP only: the
	// TEEs without a key of their own have the TPM alone.
	SealerModeBoth SealerMode = "both"
)

// ParseSealerMode parses tee.sealer; empty means auto.
func ParseSealerMode(s string) (SealerMode, error) {
	switch m := SealerMode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return SealerModeAuto, nil
	case SealerModeAuto, SealerModeTEE, SealerModeTPM2, SealerModeBoth:
		return m, nil
	default:
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("tee.sealer %q: want auto, tee, tpm2 or both", s), nil)
	}
}

// SealerKind names the sealer behind a sealed file.
type SealerKind string

const (
	SealerKindSEVDerivedKey SealerKind = "sev-snp-derived-key"
	SealerKindTPM2          SealerKind = "tpm2"
	// SealerKindSEVDerivedKeyTPM2 is the chip's derived key nested inside
	// the TPM 2.0's sealed object (ADR 0037).
	SealerKindSEVDerivedKeyTPM2 SealerKind = "sev-snp-derived-key+tpm2"
	SealerKindSimulated         SealerKind = "simulated"
)

// SealerOptions is what a host's sealer needs beyond its producer.
type SealerOptions struct {
	// Mode is tee.sealer; empty means auto.
	Mode SealerMode
	// SEVGuestDevice is the sev-guest device a SEV-SNP host derives its
	// sealing key through.
	SEVGuestDevice string
	// TPM2ToolsDir and VTPMSealPCRs configure the TPM 2.0 sealer (ADR
	// 0022); empty means PATH and the default selection.
	TPM2ToolsDir string
	VTPMSealPCRs string
	// AWSKMS configures a Nitro enclave's sealer (ADR 0036).
	AWSKMS *AWSKMSSealerOptions
}

// AWSKMSSealerOptions are a Nitro enclave's sealer's settings, all from the
// image's configuration: the KMS key, and the parent's vsock ports that
// carry the enclave to KMS's endpoint and to the instance metadata
// service, which the parent forwards (the enclave has no other network).
type AWSKMSSealerOptions struct {
	KeyARN string
	// Endpoint is KMS's host; empty means kms.<the key's Region>.amazonaws.com.
	Endpoint      string
	KMSVsockPort  uint32
	IMDSVsockPort uint32
}

// awsKMSClientForEnclave builds the KMS client an enclave uses: TLS to the
// endpoint through the parent's vsock port, credentials from the instance
// metadata service through another.
var awsKMSClientForEnclave = func(o AWSKMSSealerOptions) (*awskms.Client, error) {
	region, err := ParseAWSKMSKeyARN(o.KeyARN)
	if err != nil {
		return nil, err
	}
	if o.KMSVsockPort == 0 || o.IMDSVsockPort == 0 || o.KMSVsockPort == o.IMDSVsockPort {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			"sealer: the enclave reaches KMS and the instance metadata service through two distinct vsock ports of its parent; both are required", nil)
	}
	kmsPort, imdsPort := o.KMSVsockPort, o.IMDSVsockPort
	return awskms.New(awskms.Config{
		Region:   region,
		Endpoint: o.Endpoint,
		Dial: func(ctx context.Context) (net.Conn, error) {
			return vsock.Dial(ctx, vsock.CIDNitroParent, kmsPort)
		},
		Credentials: &awskms.IMDSCredentials{Dial: func(ctx context.Context) (net.Conn, error) {
			return vsock.Dial(ctx, vsock.CIDNitroParent, imdsPort)
		}},
	})
}

// SealerKindForProvider says which sealer a host of the given family uses
// under mode, without touching the host. The TEE's own key exists on
// SEV-SNP only; a mode that demands it elsewhere is refused by name.
func SealerKindForProvider(p Provider, mode SealerMode) (SealerKind, error) {
	if mode == "" {
		mode = SealerModeAuto
	}
	if p == ProviderAWSNitro {
		if mode == SealerModeTPM2 || mode == SealerModeBoth {
			return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				"tee.sealer="+string(mode)+": a Nitro enclave has no TPM; its sealer is KMS, released to its attestation (ADR 0036) — set tee.sealer to auto or tee", nil)
		}
		return SealerKindAWSKMSAttested, nil
	}
	if mode == SealerModeTPM2 {
		return SealerKindTPM2, nil
	}
	if mode == SealerModeBoth {
		if p != ProviderGCPSEVSNP && p != ProviderGCPSEVSNPVTPM {
			return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("tee.sealer=both: %s gives the guest no sealing key of its own to nest inside the TPM's; set tee.sealer to tpm2 or auto (ADR 0037)", p), nil)
		}
		return SealerKindSEVDerivedKeyTPM2, nil
	}
	switch p {
	case ProviderSimulated:
		return SealerKindSimulated, nil
	case ProviderGCPSEVSNP:
		return SealerKindSEVDerivedKey, nil
	case ProviderAWSSEVSNP:
		// The firmware's derived key, as on Compute Engine; on EC2 it is
		// the fleet's, not a chip's: a file opens on any EC2 SEV-SNP guest
		// of the same launch measurement and guest policy (ADR 0038).
		return SealerKindSEVDerivedKey, nil
	case ProviderGCPSEVSNPVTPM:
		// The family that attests with the vTPM seals to it too: under
		// auto, the chip's key nested in the vTPM's (ADR 0037); tee keeps
		// the chip's key alone.
		if mode == SealerModeTEE {
			return SealerKindSEVDerivedKey, nil
		}
		return SealerKindSEVDerivedKeyTPM2, nil
	case ProviderGCPTDX, ProviderAzureCGPU, ProviderAzureSEVSNP:
		if mode == SealerModeTEE {
			return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("tee.sealer=tee: %s gives the guest no sealing key of its own; its TPM 2.0 is the sealer — set tee.sealer to tpm2 or auto (ADR 0022)", p), nil)
		}
		return SealerKindTPM2, nil
	default:
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("sealer: %s has no sealer in this build", p), nil)
	}
}

// providerOf names the family a producer attests for, for sealing.
func providerOf(p Producer) (Provider, bool) {
	switch p.(type) {
	case *Simulated:
		return ProviderSimulated, true
	case *GCPSEVProducer:
		return ProviderGCPSEVSNP, true
	case *GCPSEVVTPMProducer:
		return ProviderGCPSEVSNPVTPM, true
	case *AWSSEVSNPProducer:
		return ProviderAWSSEVSNP, true
	case *GCPTDXProducer:
		return ProviderGCPTDX, true
	case *AzureCGPUProducer:
		return ProviderAzureCGPU, true
	case *AzureSEVSNPProducer:
		return ProviderAzureSEVSNP, true
	case *AWSNitroProducer:
		return ProviderAWSNitro, true
	default:
		return "", false
	}
}

// SealerKindFor is SealerKindForProvider for a producer.
func SealerKindFor(p Producer, mode SealerMode) (SealerKind, error) {
	family, ok := providerOf(p)
	if !ok {
		return "", fmt.Errorf("sealer: %T has no sealer in this build", p)
	}
	return SealerKindForProvider(family, mode)
}

// sevSNPGuest is a producer on a SEV-SNP guest: what the chip's sealing key
// is derived with.
type sevSNPGuest interface {
	Measurement() Measurement
	Policy() uint64
}

// SealerFor returns the sealer of the host the producer attests for under
// opts.Mode, what to close when done with it (nil when nothing was
// opened), and the kind every file it seals is named with.
func SealerFor(p Producer, opts SealerOptions) (Sealer, io.Closer, SealerKind, error) {
	kind, err := SealerKindFor(p, opts.Mode)
	if err != nil {
		return nil, nil, "", err
	}
	switch kind {
	case SealerKindSimulated:
		return p.(*Simulated), nil, kind, nil
	case SealerKindSEVDerivedKey:
		t := p.(sevSNPGuest)
		dev, err := os.OpenFile(opts.SEVGuestDevice, os.O_RDWR, 0)
		if err != nil {
			return nil, nil, "", fmt.Errorf("sealer: open %s (the sev-guest driver must be loaded; the daemon needs access to it): %w", opts.SEVGuestDevice, err)
		}
		return NewGCPSEVSealer(dev, t.Measurement(), t.Policy()), dev, kind, nil
	case SealerKindTPM2:
		s, err := NewVTPMSealer(VTPMSealerConfig{TPM2ToolsDir: opts.TPM2ToolsDir, PCRs: opts.VTPMSealPCRs})
		if err != nil {
			return nil, nil, "", err
		}
		return s, nil, kind, nil
	case SealerKindSEVDerivedKeyTPM2:
		t := p.(sevSNPGuest)
		pcrs := opts.VTPMSealPCRs
		if pcrs == "" {
			// The boot, not the run: the firmware's PCRs and GRUB's, which
			// hold across a reboot and move with the kernel (ADR 0037).
			pcrs = DefaultGCEBootPCRs
		}
		vt, err := NewVTPMSealer(VTPMSealerConfig{TPM2ToolsDir: opts.TPM2ToolsDir, PCRs: pcrs})
		if err != nil {
			return nil, nil, "", err
		}
		dev, err := os.OpenFile(opts.SEVGuestDevice, os.O_RDWR, 0)
		if err != nil {
			return nil, nil, "", fmt.Errorf("sealer: open %s (the sev-guest driver must be loaded; the daemon needs access to it): %w", opts.SEVGuestDevice, err)
		}
		s, err := NewSEVSNPVTPMSealer(NewGCPSEVSealer(dev, t.Measurement(), t.Policy()), vt)
		if err != nil {
			_ = dev.Close()
			return nil, nil, "", err
		}
		return s, dev, kind, nil
	case SealerKindAWSKMSAttested:
		if opts.AWSKMS == nil {
			return nil, nil, "", shared_errors.Structural(shared_errors.CodeRequiredFieldMissing,
				"sealer: a Nitro enclave's sealer needs tee.aws_kms — the KMS key and the parent's vsock ports (ADR 0036)", nil)
		}
		client, err := awsKMSClientForEnclave(*opts.AWSKMS)
		if err != nil {
			return nil, nil, "", err
		}
		np := p.(*AWSNitroProducer)
		s, err := NewAWSNitroSealer(AWSNitroSealerConfig{KeyARN: opts.AWSKMS.KeyARN, Measurement: np.Measurement(), KMS: client, Attest: np.attestRecipient})
		if err != nil {
			return nil, nil, "", err
		}
		return s, nil, kind, nil
	default:
		return nil, nil, "", fmt.Errorf("sealer: %q is not a sealer this build has", kind)
	}
}
