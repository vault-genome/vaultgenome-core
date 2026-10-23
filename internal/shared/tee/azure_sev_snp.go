// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tee — Azure Confidential VMs on AMD SEV-SNP (DCasv5, ECasv5 and
// their kin) adapter: the chip and the vTPM, without a GPU.
//
// The evidence is the HCL report Azure keeps in the vTPM — the SNP report
// issued at boot, whose REPORT_DATA names the vTPM's attestation key — and
// a TPM quote by that key over the PCRs with the challenger's nonce in
// extraData (azure_vtpm.go): the chip vouches for the guest's launch, the
// vTPM for this boot and for the nonce. The measurement is the SNP launch
// measurement; the quote's PCR digest is what the vTPM measured of the
// boot, which a peer may pin. The sealer is the vTPM (tpm2, ADR 0022):
// the paravisor gives the guest no derived key of its own.
package tee

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// AzureSEVSNPEvidenceSchema names the Evidence envelope.
const AzureSEVSNPEvidenceSchema = "vault-genome/azure-sev-snp-evidence/v1"

// AzureSEVSNPProducerConfig configures the producer on the guest.
type AzureSEVSNPProducerConfig struct {
	// TPM2ToolsDir is where tpm2_nvread, tpm2_quote, tpm2_getcap and
	// tpm2_readpublic live; empty means PATH.
	TPM2ToolsDir string
	// AKHandle is the persistent handle of the HCL attestation key; empty
	// means: find the persistent key whose public part is HCLAkPub.
	AKHandle string
	// PCRs is the tpm2_quote PCR selection. Default DefaultTPMQuotePCRs.
	PCRs string
	// Timeout bounds each command. Default 2 minutes.
	Timeout time.Duration
}

// AzureSEVSNPVerifierConfig configures the verifier, anywhere.
type AzureSEVSNPVerifierConfig struct {
	// AMDKDSURL overrides AMD KDS; AMDRootPEM is the ASK+ARK chain (PEM)
	// of the chip's product (Milan or Genoa, as the report says), required,
	// and its root must be one the binary pins (ADR 0024); VCEKCacheDir
	// keeps fetched VCEKs; MinReportedTCB is the TCB floor.
	AMDKDSURL      string
	AMDRootPEM     []byte
	VCEKCacheDir   string
	MinReportedTCB uint64
	// SEVSNP holds the chip's report to the attack record (ADR 0033).
	SEVSNP SEVSNPPolicy
	// AcceptablePCRDigests, when set, pins the quote's PCR digest — the
	// SHA-256 over the selected PCRs' values, as TPM2_Quote computes it —
	// to one of these, so the OS measured into the vTPM is policed and not
	// only recorded. Empty: recorded only.
	AcceptablePCRDigests [][]byte
	// AcceptableMeasurements lists every SNP measurement accepted. When
	// empty, falls back to VerifierSpec.ExpectedMeasurement.
	AcceptableMeasurements []Measurement
}

// azureSEVSNPEvidence is the Evidence envelope.
type azureSEVSNPEvidence struct {
	Schema         string `json:"schema"`
	HCLReport      []byte `json:"hcl_report"`
	QuoteMessage   []byte `json:"quote_message"`
	QuoteSignature []byte `json:"quote_signature"`
}

// AzureSEVSNPProducer implements Producer on the guest.
type AzureSEVSNPProducer struct {
	vtpm *azureVTPM

	mu     sync.Mutex
	closed bool
}

// NewAzureSEVSNPProducer reads the HCL report from the vTPM, finds the
// attestation key the chip vouched for among the persistent keys, and
// fixes the measurement.
func NewAzureSEVSNPProducer(cfg AzureSEVSNPProducerConfig) (*AzureSEVSNPProducer, error) {
	v, err := openAzureVTPM(string(ProviderAzureSEVSNP), cfg.TPM2ToolsDir, cfg.AKHandle, cfg.PCRs, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	return &AzureSEVSNPProducer{vtpm: v}, nil
}

// Quote implements Producer: a TPM quote with SHA-256(nonce) in extraData
// and the HCL report, in one envelope.
func (p *AzureSEVSNPProducer) Quote(nonce Nonce) (Evidence, error) {
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-sev-snp: nonce must be at least NonceMinBytes", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-sev-snp: producer closed", nil)
	}
	quoteMsg, quoteSig, err := p.vtpm.quote(tpmQuoteExtraDataFor(nonce))
	if err != nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted, "azure-sev-snp: the vTPM's quote", err)
	}
	ev, err := json.Marshal(azureSEVSNPEvidence{Schema: AzureSEVSNPEvidenceSchema, HCLReport: p.vtpm.hcl.Raw, QuoteMessage: quoteMsg, QuoteSignature: quoteSig})
	if err != nil {
		return nil, err
	}
	return Evidence(ev), nil
}

// Measurement implements Producer: the SNP launch measurement.
func (p *AzureSEVSNPProducer) Measurement() Measurement {
	return append(Measurement(nil), p.vtpm.measurement...)
}

// VTPMBoot is what the vTPM measured of this boot: the PCRs quoted and
// their digest, which a peer may pin (AcceptablePCRDigests).
func (p *AzureSEVSNPProducer) VTPMBoot() (selections []tpmPCRSelection, digest []byte) {
	return p.vtpm.boot.PCRSelections, append([]byte(nil), p.vtpm.boot.PCRDigest...)
}

// Close implements Producer.
func (p *AzureSEVSNPProducer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// AzureSEVSNPVerifier implements Verifier for the chip-and-vTPM evidence.
type AzureSEVSNPVerifier struct {
	snp        *azureSNPChecker
	acceptable []Measurement
}

// AzureSEVSNPVerdict is what a verified evidence said.
type AzureSEVSNPVerdict struct {
	Measurement   Measurement
	Product       string
	ChipID        [64]byte
	ReportedTCB   uint64
	SEVSNP        *SEVSNPReportDetail
	PCRSelections []tpmPCRSelection
	PCRDigest     []byte
}

// NewAzureSEVSNPVerifier constructs the verifier.
func NewAzureSEVSNPVerifier(_ crypto.PublicKey, expected Measurement, cfg AzureSEVSNPVerifierConfig) (*AzureSEVSNPVerifier, error) {
	snp, err := newAzureSNPChecker(string(ProviderAzureSEVSNP), cfg.AMDRootPEM, cfg.AMDKDSURL, cfg.VCEKCacheDir, cfg.MinReportedTCB, cfg.AcceptablePCRDigests, cfg.SEVSNP)
	if err != nil {
		return nil, err
	}
	acc := cfg.AcceptableMeasurements
	if len(acc) == 0 {
		acc = []Measurement{expected}
	}
	return &AzureSEVSNPVerifier{snp: snp, acceptable: acc}, nil
}

// Verify implements Verifier.
func (v *AzureSEVSNPVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	verdict, err := v.VerifyEvidence(ev, nonce)
	if err != nil {
		return nil, err
	}
	return verdict.Measurement, nil
}

// VerifyDetailed implements DetailedVerifier: the verdict's platform facts
// go with the measurement.
func (v *AzureSEVSNPVerifier) VerifyDetailed(ev Evidence, nonce Nonce) (Measurement, *AttestationDetail, error) {
	verdict, err := v.VerifyEvidence(ev, nonce)
	if err != nil {
		return nil, nil, err
	}
	return verdict.Measurement, verdict.Detail(), nil
}

// Detail is the verdict as an AttestationDetail for the audit record.
func (d *AzureSEVSNPVerdict) Detail() *AttestationDetail {
	sel := make([]string, 0, len(d.PCRSelections))
	for _, s := range d.PCRSelections {
		sel = append(sel, s.String())
	}
	return &AttestationDetail{Provider: ProviderAzureSEVSNP, Product: d.Product, ChipIDHex: hex.EncodeToString(d.ChipID[:]),
		ReportedTCB: d.ReportedTCB, SEVSNP: d.SEVSNP, PCRSelection: strings.Join(sel, "+"), PCRDigestHex: hex.EncodeToString(d.PCRDigest)}
}

// VerifyEvidence verifies and says what the evidence said.
func (v *AzureSEVSNPVerifier) VerifyEvidence(ev Evidence, nonce Nonce) (*AzureSEVSNPVerdict, error) {
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-sev-snp: challenger nonce too short", nil)
	}
	var env azureSEVSNPEvidence
	if err := json.Unmarshal(ev, &env); err != nil || env.Schema != AzureSEVSNPEvidenceSchema {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "azure-sev-snp: evidence is not a "+AzureSEVSNPEvidenceSchema+" envelope", err)
	}
	h, product, quote, snpDetail, err := v.snp.check(env.HCLReport, env.QuoteMessage, env.QuoteSignature, nonce)
	if err != nil {
		return nil, err
	}
	m, err := azureAcceptMeasurement(string(ProviderAzureSEVSNP), h.SNP, v.acceptable)
	if err != nil {
		return nil, err
	}
	return &AzureSEVSNPVerdict{Measurement: m, Product: product, ChipID: h.SNP.ChipID, ReportedTCB: h.SNP.ReportedTCB, SEVSNP: snpDetail,
		PCRSelections: quote.PCRSelections, PCRDigest: quote.PCRDigest}, nil
}

// azureSEVSNPCapability: the vTPM and tpm2-tools. The HCL report itself is
// read when the producer opens.
func azureSEVSNPCapability() (bool, string) {
	if _, err := os.Stat("/dev/tpmrm0"); err != nil {
		return false, "Azure SEV-SNP: no /dev/tpmrm0 (not a Confidential VM with a vTPM)"
	}
	if _, err := exec.LookPath("tpm2_quote"); err != nil {
		return false, "Azure SEV-SNP: tpm2-tools not installed"
	}
	return true, "Azure SEV-SNP: vTPM and tpm2-tools present"
}

// Compile-time interface conformance.
var (
	_ Producer = (*AzureSEVSNPProducer)(nil)
	_ Verifier = (*AzureSEVSNPVerifier)(nil)
)
