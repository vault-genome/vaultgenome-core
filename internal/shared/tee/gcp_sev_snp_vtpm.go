// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// gcp-sev-snp-vtpm: a Compute Engine Confidential VM on AMD SEV-SNP that
// attests with its chip and its vTPM under one challenge (ADR 0037).
//
// The chip's launch measurement on Compute Engine is Google's UEFI — the
// value Google precomputes per vCPU count — and says nothing of the kernel
// or the disk; the boot after the firmware is measured into the vTPM. So the
// evidence carries both: the chip's report, whose REPORT_DATA is
// SHA-256(nonce) in its first half and SHA-256 of the vTPM attestation key's
// SubjectPublicKeyInfo in its second, and a TPM2_Quote by that key over the
// boot PCRs with SHA-256(nonce) in extraData, with the key's certificate and
// the intermediates to Google's EK/AK root. The verifier holds the chip as
// gcp-sev-snp does (the AMD chain, the attack record, the launch
// measurement), the key to Google's pinned root and to the instance's
// project, the quote to the nonce, and the PCR digest to the digests the
// policy names — which it must name: there is no default that accepts any
// boot.

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// GCPSEVVTPMEvidenceSchema names the envelope.
const GCPSEVVTPMEvidenceSchema = "vault-genome/gcp-sev-snp-vtpm/v1"

type gcpSEVVTPMEvidence struct {
	Schema          string   `json:"schema"`
	Report          []byte   `json:"report"`
	AKCertificate   []byte   `json:"ak_certificate"`
	AKIntermediates [][]byte `json:"ak_intermediates"`
	QuoteMessage    []byte   `json:"quote_message"`
	QuoteSignature  []byte   `json:"quote_signature"`
}

// GCPSEVVTPMProducerConfig configures the producer.
type GCPSEVVTPMProducerConfig struct {
	SEV GCPSEVProducerConfig
	// TPM2ToolsDir is where the tpm2_* tools live; empty means PATH.
	TPM2ToolsDir string
	// PCRs is the selection quoted; empty means DefaultGCEBootPCRs.
	PCRs string
	// IntermediatesPEM are the certificates between the AK certificate and
	// Google's root; empty means the one the certificate's issuer URL serves.
	IntermediatesPEM []byte
	// Timeout bounds each tool invocation; zero means two minutes.
	Timeout time.Duration
}

// GCPSEVVTPMProducer attests with the chip's report and the vTPM's quote.
type GCPSEVVTPMProducer struct {
	chip *GCPSEVProducer
	vtpm *gceVTPM
	mu   sync.Mutex
}

// NewGCPSEVVTPMProducer opens the chip (configfs-tsm) and the vTPM.
func NewGCPSEVVTPMProducer(cfg GCPSEVVTPMProducerConfig) (*GCPSEVVTPMProducer, error) {
	chip, err := NewGCPSEVProducer(cfg.SEV)
	if err != nil {
		return nil, err
	}
	vt, err := openGCEVTPM(cfg.TPM2ToolsDir, cfg.PCRs, cfg.IntermediatesPEM, cfg.Timeout)
	if err != nil {
		_ = chip.Close()
		return nil, err
	}
	return &GCPSEVVTPMProducer{chip: chip, vtpm: vt}, nil
}

// Quote implements Producer.
func (p *GCPSEVVTPMProducer) Quote(nonce Nonce) (Evidence, error) {
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "gcp-sev-snp-vtpm: nonce must be at least NonceMinBytes", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var rd [64]byte
	prefix := computeReportDataPrefix(nonce)
	ak := sha256.Sum256(p.vtpm.akSPKI)
	copy(rd[:32], prefix[:])
	copy(rd[32:], ak[:])
	report, err := p.chip.reportWithData(rd)
	if err != nil {
		return nil, err
	}
	msg, sig, err := p.vtpm.quote(tpmQuoteExtraDataFor(nonce))
	if err != nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted, "gcp-sev-snp-vtpm: the vTPM's quote", err)
	}
	ev, err := json.Marshal(gcpSEVVTPMEvidence{Schema: GCPSEVVTPMEvidenceSchema, Report: report.Raw, AKCertificate: p.vtpm.akCert,
		AKIntermediates: p.vtpm.inter, QuoteMessage: msg, QuoteSignature: sig})
	if err != nil {
		return nil, err
	}
	return Evidence(ev), nil
}

// Measurement implements Producer: the launch measurement (Google's UEFI).
func (p *GCPSEVVTPMProducer) Measurement() Measurement { return p.chip.Measurement() }

// Policy is the guest policy the launch report carries.
func (p *GCPSEVVTPMProducer) Policy() uint64 { return p.chip.Policy() }

// VTPMBoot is what the vTPM measured of this boot: the PCRs quoted and their
// digest, which a peer pins (pcr_digests).
func (p *GCPSEVVTPMProducer) VTPMBoot() (selections []tpmPCRSelection, digest []byte) {
	return p.vtpm.boot.PCRSelections, append([]byte(nil), p.vtpm.boot.PCRDigest...)
}

// Close implements Producer.
func (p *GCPSEVVTPMProducer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := p.chip.Close()
	if cerr := p.vtpm.close(); err == nil {
		err = cerr
	}
	return err
}

// GCPSEVVTPMVerifierConfig configures the verifier.
type GCPSEVVTPMVerifierConfig struct {
	SEV GCPSEVVerifierConfig
	// PCRs is the selection the quote must cover; empty means DefaultGCEBootPCRs.
	PCRs string
	// AcceptablePCRDigests are the boots the policy names: SHA-256 over the
	// PCRs of the selection, as the quote states it. Required.
	AcceptablePCRDigests [][]byte
	// ProjectIDs, when set, are the Compute Engine projects whose instances
	// are accepted, as the AK certificate names them.
	ProjectIDs []string
	// ExtraRootsPEM are roots the operator adds to Google's pinned one.
	ExtraRootsPEM []byte
	// Now is the clock the AK certificate is checked at; nil means time.Now.
	Now func() time.Time
}

// GCPSEVVTPMVerifier verifies the chip-and-vTPM evidence.
type GCPSEVVTPMVerifier struct {
	chip     *GCPSEVVerifier
	cfg      GCPSEVVTPMVerifierConfig
	roots    *x509.CertPool
	projects map[string]bool
}

// GCPSEVVTPMVerdict is what a verified evidence said.
type GCPSEVVTPMVerdict struct {
	Measurement   Measurement
	SEVSNP        *SEVSNPReportDetail
	PCRSelections []tpmPCRSelection
	PCRDigest     []byte
	Instance      GCEInstance
}

// NewGCPSEVVTPMVerifier constructs the verifier; a policy that names no boot
// is refused here, where the operator sees it.
func NewGCPSEVVTPMVerifier(pub crypto.PublicKey, expected Measurement, cfg GCPSEVVTPMVerifierConfig) (*GCPSEVVTPMVerifier, error) {
	if len(cfg.AcceptablePCRDigests) == 0 {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing,
			"gcp-sev-snp-vtpm: the policy names no boot: pcr_digests (SHA-256 over the vTPM's boot PCRs) is required — the launch measurement on Compute Engine is Google's firmware and says nothing of the kernel (ADR 0037)", nil)
	}
	for _, d := range cfg.AcceptablePCRDigests {
		if len(d) != sha256.Size {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("gcp-sev-snp-vtpm: pcr_digests: %d bytes, want 32", len(d)), nil)
		}
	}
	if cfg.PCRs == "" {
		cfg.PCRs = DefaultGCEBootPCRs
	}
	if err := ValidatePCRSelection(cfg.PCRs); err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "gcp-sev-snp-vtpm: "+err.Error(), nil)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	chip, err := NewGCPSEVVerifier(pub, expected, cfg.SEV)
	if err != nil {
		return nil, err
	}
	roots, err := gceEKAKRoots(cfg.ExtraRootsPEM)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "gcp-sev-snp-vtpm: "+err.Error(), nil)
	}
	projects := map[string]bool{}
	for _, p := range cfg.ProjectIDs {
		projects[p] = true
	}
	return &GCPSEVVTPMVerifier{chip: chip, cfg: cfg, roots: roots, projects: projects}, nil
}

// Verify implements Verifier.
func (v *GCPSEVVTPMVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	verdict, err := v.VerifyEvidence(ev, nonce)
	if err != nil {
		return nil, err
	}
	return verdict.Measurement, nil
}

// VerifyDetailed implements DetailedVerifier.
func (v *GCPSEVVTPMVerifier) VerifyDetailed(ev Evidence, nonce Nonce) (Measurement, *AttestationDetail, error) {
	verdict, err := v.VerifyEvidence(ev, nonce)
	if err != nil {
		return nil, nil, err
	}
	return verdict.Measurement, verdict.Detail(), nil
}

// Detail is the verdict as an AttestationDetail for the audit record.
func (d *GCPSEVVTPMVerdict) Detail() *AttestationDetail {
	sel := make([]string, 0, len(d.PCRSelections))
	for _, s := range d.PCRSelections {
		sel = append(sel, s.String())
	}
	inst := d.Instance
	return &AttestationDetail{Provider: ProviderGCPSEVSNPVTPM, Product: d.SEVSNP.Product, ChipIDHex: d.SEVSNP.ChipIDHex, ReportedTCB: d.SEVSNP.ReportedTCBRaw,
		SEVSNP: d.SEVSNP, PCRSelection: strings.Join(sel, "+"), PCRDigestHex: hex.EncodeToString(d.PCRDigest), GCEInstance: &inst}
}

// VerifyEvidence verifies and says what the evidence said.
func (v *GCPSEVVTPMVerifier) VerifyEvidence(ev Evidence, nonce Nonce) (*GCPSEVVTPMVerdict, error) {
	integrity := func(code, msg string, err error) error {
		return shared_errors.Integrity(code, "gcp-sev-snp-vtpm: "+msg, err)
	}
	var env gcpSEVVTPMEvidence
	if err := json.Unmarshal(ev, &env); err != nil || env.Schema != GCPSEVVTPMEvidenceSchema {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "evidence is not a "+GCPSEVVTPMEvidenceSchema+" envelope (a chip's report alone does not carry the boot)", err)
	}
	// The chip, as gcp-sev-snp holds it: the AMD chain, the attack record,
	// the first half of REPORT_DATA, the launch measurement.
	m, snpDetail, err := v.chip.verify(Evidence(env.Report), nonce)
	if err != nil {
		return nil, err
	}
	report, err := parseSEVSNPReport(env.Report)
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "the report", err)
	}
	// The key Google certified for this instance's vTPM.
	ak, err := verifyGCEAKCertificate(env.AKCertificate, env.AKIntermediates, v.roots, v.cfg.Now())
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, err.Error(), err)
	}
	if len(v.projects) > 0 && !v.projects[ak.Instance.ProjectID] {
		return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("the instance is in project %q, which the policy does not name", ak.Instance.ProjectID), nil)
	}
	// The chip names that key: the second half of REPORT_DATA.
	spki, err := x509.MarshalPKIXPublicKey(ak.Key)
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "the AK's public key", err)
	}
	akHash := sha256.Sum256(spki)
	if !bytes.Equal(report.ReportData[32:], akHash[:]) {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "the chip's REPORT_DATA does not name the vTPM key whose quote rides with it", nil)
	}
	// The quote: by that key, for this nonce, over the selection, of a boot the policy names.
	quote, err := parseTPMQuote(env.QuoteMessage)
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "TPM quote: "+err.Error(), err)
	}
	if err := verifyTPMQuoteSignature(ak.Key, env.QuoteMessage, env.QuoteSignature); err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "TPM quote: "+err.Error(), err)
	}
	challenge := tpmQuoteExtraDataFor(nonce)
	if !bytes.Equal(quote.ExtraData, challenge[:]) {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "TPM quote does not bind challenger nonce (replay?)", nil)
	}
	if got := pcrSelectionString(quote.PCRSelections); got != v.cfg.PCRs {
		return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("the quote covers %s, the policy %s", got, v.cfg.PCRs), nil)
	}
	pinned := false
	for _, d := range v.cfg.AcceptablePCRDigests {
		if bytes.Equal(d, quote.PCRDigest) {
			pinned = true
			break
		}
	}
	if !pinned {
		return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("PCR digest %x is not in the acceptable set: the boot measured into the vTPM — the kernel, its command line and initrd, the boot loader — is not one the policy names", quote.PCRDigest), nil)
	}
	return &GCPSEVVTPMVerdict{Measurement: m, SEVSNP: snpDetail, PCRSelections: quote.PCRSelections, PCRDigest: quote.PCRDigest, Instance: ak.Instance}, nil
}

// pcrSelectionString writes a quote's selection as tpm2-tools takes it.
func pcrSelectionString(sels []tpmPCRSelection) string {
	parts := make([]string, 0, len(sels))
	for _, s := range sels {
		parts = append(parts, s.String())
	}
	return strings.Join(parts, "+")
}

// gcpSEVVTPMCapability: the chip's configfs-tsm, the vTPM and tpm2-tools.
func gcpSEVVTPMCapability() (bool, string) {
	if ok, why := gcpSEVCapability(); !ok {
		return false, why
	}
	if _, err := os.Stat("/dev/tpmrm0"); err != nil {
		return false, "GCP SEV-SNP with vTPM: no /dev/tpmrm0 (create the instance with a vTPM)"
	}
	if _, err := exec.LookPath("tpm2_quote"); err != nil {
		return false, "GCP SEV-SNP with vTPM: tpm2-tools not installed"
	}
	return true, "GCP SEV-SNP with vTPM: configfs-tsm, vTPM and tpm2-tools present"
}

var (
	_ Producer = (*GCPSEVVTPMProducer)(nil)
	_ Verifier = (*GCPSEVVTPMVerifier)(nil)
)
