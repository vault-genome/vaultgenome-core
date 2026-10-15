// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Sealing by what the host has (ADR 0025, step 1b). A SEV-SNP guest has a
// key of its own derived by the chip (ADR 0016); a TDX Trust Domain, an
// Azure confidential VM and most servers have a TPM 2.0, virtual or
// discrete (ADR 0022); the simulated TEE has its weak key. tee.sealer
// says which the daemon uses — "auto" takes the TEE's own key where there
// is one and the TPM otherwise — and every sealed file names the sealer
// it was made with, so a file sealed one way is not opened as another.

import (
	"fmt"
	"io"
	"os"
	"strings"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// SealerMode is the daemon's tee.sealer.
type SealerMode string

const (
	// SealerModeAuto: the TEE's own key where it has one (SEV-SNP), the
	// host's TPM 2.0 otherwise (TDX, Azure), the simulated key off hardware.
	SealerModeAuto SealerMode = "auto"
	// SealerModeTEE: the TEE's own key only; refused on a TEE that has none.
	SealerModeTEE SealerMode = "tee"
	// SealerModeTPM2: the host's TPM 2.0 — a vTPM or a discrete TPM —
	// whatever the TEE, through tpm2-tools (ADR 0022).
	SealerModeTPM2 SealerMode = "tpm2"
)

// ParseSealerMode parses tee.sealer; empty means auto.
func ParseSealerMode(s string) (SealerMode, error) {
	switch m := SealerMode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return SealerModeAuto, nil
	case SealerModeAuto, SealerModeTEE, SealerModeTPM2:
		return m, nil
	default:
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("tee.sealer %q: want auto, tee or tpm2", s), nil)
	}
}

// SealerKind names the sealer behind a sealed file.
type SealerKind string

const (
	SealerKindSEVDerivedKey SealerKind = "sev-snp-derived-key"
	SealerKindTPM2          SealerKind = "tpm2"
	SealerKindSimulated     SealerKind = "simulated"
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
}

// SealerKindForProvider says which sealer a host of the given family uses
// under mode, without touching the host. The TEE's own key exists on
// SEV-SNP only; a mode that demands it elsewhere is refused by name.
func SealerKindForProvider(p Provider, mode SealerMode) (SealerKind, error) {
	if mode == "" {
		mode = SealerModeAuto
	}
	if mode == SealerModeTPM2 {
		return SealerKindTPM2, nil
	}
	switch p {
	case ProviderSimulated:
		return SealerKindSimulated, nil
	case ProviderGCPSEVSNP:
		return SealerKindSEVDerivedKey, nil
	case ProviderGCPTDX, ProviderAzureCGPU:
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
	case *GCPTDXProducer:
		return ProviderGCPTDX, true
	case *AzureCGPUProducer:
		return ProviderAzureCGPU, true
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
		t := p.(*GCPSEVProducer)
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
	default:
		return nil, nil, "", fmt.Errorf("sealer: %q is not a sealer this build has", kind)
	}
}
