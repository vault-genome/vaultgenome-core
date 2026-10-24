// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tee — Azure Confidential VMs with NVIDIA H100 (NCC H100 v5) adapter.
//
// An Azure confidential GPU VM is an AMD SEV-SNP guest under the paravisor
// with an H100 in confidential-computing mode. Two roots of trust vouch
// for it and this adapter carries both in one Evidence:
//
//   - the chip: the SEV-SNP report Azure keeps in the vTPM (the HCL
//     report, azure_cgpu_hcl.go), whose REPORT_DATA names the vTPM's
//     attestation key, and a TPM quote by that key over the PCRs with the
//     challenge in extraData (azure_cgpu_tpm.go) — the binding of a
//     caller's nonce to a report that was issued at boot;
//   - the GPU: NVIDIA's signed attestation tokens for the same challenge
//     (nvidia_eat.go), obtained on the guest through NVIDIA's own tools.
//
// The measurement is the SNP launch measurement (48 bytes, the paravisor
// and firmware Azure measures). What NVIDIA vouched for — the GPU's model,
// driver and VBIOS with their reference manifests — is in the verdict, and
// an operator may pin it. There is no sealer: the guest has no derived-key
// interface, and sealing through the vTPM is not wired.
package tee

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// AzureCGPUEvidenceSchema names the Evidence envelope.
const AzureCGPUEvidenceSchema = "vault-genome/azure-cgpu-evidence/v1"

// DefaultTPMQuotePCRs are the PCRs the producer quotes: the measured boot
// (0–7), the kernel's IMA and the OS (8–14).
const DefaultTPMQuotePCRs = "sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14"

// AzureCGPUProducerConfig configures the producer on the guest.
type AzureCGPUProducerConfig struct {
	// GPUAttestCommand collects the GPU's evidence for a nonce through
	// NVIDIA's tools and prints NRAS's response on stdout; the nonce (64
	// hex characters) is appended as the last argument. Required.
	GPUAttestCommand []string
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

// AzureCGPUVerifierConfig configures the verifier, anywhere.
type AzureCGPUVerifierConfig struct {
	// AMDKDSURL overrides AMD KDS; AMDRootPEM is the ASK+ARK chain (PEM)
	// of the chip's product (Genoa for NCC H100 v5), required, and its root
	// must be one the binary pins (ADR 0024); VCEKCacheDir keeps fetched
	// VCEKs; MinReportedTCB is the TCB floor.
	AMDKDSURL      string
	AMDRootPEM     []byte
	VCEKCacheDir   string
	MinReportedTCB uint64
	// SEVSNP holds the chip's report to the attack record (ADR 0033).
	SEVSNP SEVSNPPolicy
	// NRASJWKSURL overrides NVIDIA's key set URL; NRASCacheDir keeps it.
	NRASJWKSURL  string
	NRASCacheDir string
	// GPU is the per-GPU claims policy.
	GPU GPUClaimsPolicy
	// GPUEvaluation says whose evaluation of the GPU's report the verdict
	// rests on: GPUEvaluationNRAS (the default) takes NVIDIA's signed
	// tokens; GPUEvaluationBoth requires them and this verifier's own
	// evaluation of the report and certificate chain the evidence carries
	// (nvidia_gpu_report.go, nvidia_rim.go); GPUEvaluationOwn would rest
	// on the own evaluation alone and is refused by this build, which does
	// not verify the manifests' XML signatures.
	GPUEvaluation string
	// GPURevocation says whether the verifier's evaluation asks NVIDIA's
	// OCSP responder about the GPU's certificate chain: GPURevocationOCSP
	// (the default under both and own) or GPURevocationOff, which leaves
	// revocation unchecked, on the record. OCSPURL overrides the responder
	// for certificates that carry no URL of their own (default
	// NVIDIAOCSPURL); answers are cached under RIMCacheDir.
	GPURevocation string
	OCSPURL       string
	// NVIDIADeviceRootPEM and NVIDIARIMRootPEM override the pinned NVIDIA
	// roots (nvidia_roots.go); RIMServiceURL overrides NVIDIA's RIM
	// service and RIMCacheDir keeps the manifests fetched.
	NVIDIADeviceRootPEM []byte
	NVIDIARIMRootPEM    []byte
	RIMServiceURL       string
	RIMCacheDir         string
	// AcceptablePCRDigests pin the quote's PCR digest — the SHA-256 over
	// the selected PCRs' values, as TPM2_Quote computes it — to one of
	// these: the boots, OS and driver, the peer may run. Required: the
	// launch measurement is Azure's paravisor and firmware, and only the
	// vTPM measures the OS (ADR 0037).
	AcceptablePCRDigests [][]byte
	// AcceptableMeasurements lists every SNP measurement accepted. When
	// empty, falls back to VerifierSpec.ExpectedMeasurement.
	AcceptableMeasurements []Measurement
	// MaxClockSkew bounds token validity checks. Default 5 minutes.
	MaxClockSkew time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
}

// The evaluations a verifier may be configured for.
const (
	GPUEvaluationNRAS = "nras"
	GPUEvaluationBoth = "both"
	GPUEvaluationOwn  = "own"

	GPURevocationOCSP = "ocsp"
	GPURevocationOff  = "off"
)

// azureCGPUEvidence is the Evidence envelope.
type azureCGPUEvidence struct {
	Schema         string          `json:"schema"`
	HCLReport      []byte          `json:"hcl_report"`
	QuoteMessage   []byte          `json:"quote_message"`
	QuoteSignature []byte          `json:"quote_signature"`
	GPUToken       json.RawMessage `json:"gpu_token"`
	// GPUEvidence is what NVIDIA's service evaluated, one entry per GPU:
	// the attestation report and the certificate chain, so a verifier can
	// evaluate them itself. Absent from evidence made by an older producer.
	GPUEvidence []gpuEvidenceItem `json:"gpu_evidence,omitempty"`
}

// gpuEvidenceItem is one GPU's raw evidence as NVIDIA's collector hands
// it out: the SPDM attestation report and the PEM certificate chain,
// both base64 on the wire.
type gpuEvidenceItem struct {
	Report    []byte `json:"evidence"`
	CertChain []byte `json:"certificate"`
}

// gpuAttestOutput is the GPU attestation command's output in its full
// form: NVIDIA's response and the raw evidence it was given. A command
// that prints NVIDIA's response alone (the older contract) still works;
// the evidence then carries no gpu_evidence.
type gpuAttestOutput struct {
	NRAS        json.RawMessage   `json:"nras"`
	GPUEvidence []gpuEvidenceItem `json:"gpu_evidence"`
}

// parseGPUAttestOutput reads the command's output in either form.
func parseGPUAttestOutput(out []byte) (token json.RawMessage, items []gpuEvidenceItem, err error) {
	var full gpuAttestOutput
	if json.Unmarshal(out, &full) == nil && len(full.NRAS) > 0 {
		token, items = full.NRAS, full.GPUEvidence
	} else {
		token = out
	}
	if _, err := parseNRASResponse(token); err != nil {
		return nil, nil, err
	}
	for i, it := range items {
		if len(it.Report) == 0 || len(it.CertChain) == 0 {
			return nil, nil, fmt.Errorf("gpu_evidence[%d] lacks the report or the certificate chain", i)
		}
	}
	return token, items, nil
}

// AzureCGPUProducer implements Producer on the guest.
type AzureCGPUProducer struct {
	cfg  AzureCGPUProducerConfig
	vtpm *azureVTPM // the chip and the vTPM (azure_vtpm.go)

	mu     sync.Mutex
	closed bool
}

// AzureCGPUVerifier implements Verifier for the composite evidence.
type AzureCGPUVerifier struct {
	cfg        AzureCGPUVerifierConfig
	acceptable []Measurement
	jwks       *nrasJWKS
	gpuEval    *GPUEvaluator    // nil unless the policy asks for the own evaluation
	ownOnly    bool             // GPUEvaluationOwn: the verdict rests on the evaluation alone
	snp        *azureSNPChecker // the chip and the vTPM (azure_vtpm.go)
}

// AzureCGPUVerdict is what a verified evidence said.
type AzureCGPUVerdict struct {
	Measurement   Measurement
	Product       string
	ChipID        [64]byte
	ReportedTCB   uint64
	SEVSNP        *SEVSNPReportDetail
	PCRSelections []tpmPCRSelection
	PCRDigest     []byte
	GPUs          []GPUVerdict
	// Evaluations are this verifier's own evaluations of the GPUs'
	// reports, one per gpu_evidence entry, when the policy asked for them.
	Evaluations []GPUEvaluation
}

// runCommand runs argv with a timeout and returns stdout; stderr goes
// into the error.
var runCommand = func(timeout time.Duration, argv ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv is the operator's configuration
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", filepath.Base(argv[0]), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// NewAzureCGPUProducer reads the HCL report from the vTPM, finds the
// attestation key the chip vouched for among the persistent keys, and
// fixes the measurement.
func NewAzureCGPUProducer(cfg AzureCGPUProducerConfig) (*AzureCGPUProducer, error) {
	if len(cfg.GPUAttestCommand) == 0 {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: GPUAttestCommand required", nil)
	}
	if cfg.PCRs == "" {
		cfg.PCRs = DefaultTPMQuotePCRs
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Minute
	}
	v, err := openAzureVTPM(string(ProviderAzureCGPU), cfg.TPM2ToolsDir, cfg.AKHandle, cfg.PCRs, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	return &AzureCGPUProducer{cfg: cfg, vtpm: v}, nil
}

// VTPMBoot is what the vTPM measured of this boot: the PCRs quoted and
// their digest, which a peer may pin (AcceptablePCRDigests).
func (p *AzureCGPUProducer) VTPMBoot() (selections []tpmPCRSelection, digest []byte) {
	return p.vtpm.boot.PCRSelections, append([]byte(nil), p.vtpm.boot.PCRDigest...)
}

// Quote implements Producer: a TPM quote with SHA-256(nonce) in extraData,
// NVIDIA's tokens for the same value, and the HCL report, in one envelope.
func (p *AzureCGPUProducer) Quote(nonce Nonce) (Evidence, error) {
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: nonce must be at least NonceMinBytes", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: producer closed", nil)
	}
	challenge := tpmQuoteExtraDataFor(nonce)
	challengeHex := hex.EncodeToString(challenge[:])
	quoteMsg, quoteSig, err := p.vtpm.quote(challenge)
	if err != nil {
		return nil, fmt.Errorf("azure-cgpu: %w", err)
	}
	argv := append(append([]string(nil), p.cfg.GPUAttestCommand...), challengeHex)
	out, err := runCommand(p.cfg.Timeout, argv...)
	if err != nil {
		return nil, fmt.Errorf("azure-cgpu: GPU attestation: %w", err)
	}
	token, items, err := parseGPUAttestOutput(out)
	if err != nil {
		return nil, fmt.Errorf("azure-cgpu: GPU attestation command output: %w", err)
	}
	ev, err := json.Marshal(azureCGPUEvidence{Schema: AzureCGPUEvidenceSchema, HCLReport: p.vtpm.hcl.Raw, QuoteMessage: quoteMsg, QuoteSignature: quoteSig, GPUToken: token, GPUEvidence: items})
	if err != nil {
		return nil, err
	}
	return Evidence(ev), nil
}

// Measurement implements Producer: the SNP launch measurement.
func (p *AzureCGPUProducer) Measurement() Measurement {
	return append(Measurement(nil), p.vtpm.measurement...)
}

// Close implements Producer.
func (p *AzureCGPUProducer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// NewAzureCGPUVerifier constructs the composite verifier.
func NewAzureCGPUVerifier(_ crypto.PublicKey, expected Measurement, cfg AzureCGPUVerifierConfig) (*AzureCGPUVerifier, error) {
	snp, err := newAzureSNPChecker(string(ProviderAzureCGPU), cfg.AMDRootPEM, cfg.AMDKDSURL, cfg.VCEKCacheDir, cfg.MinReportedTCB, cfg.AcceptablePCRDigests, cfg.SEVSNP)
	if err != nil {
		return nil, err
	}
	cfg.AMDKDSURL = snp.kdsURL
	if cfg.NRASJWKSURL == "" {
		cfg.NRASJWKSURL = DefaultNRASJWKSURL
	}
	if cfg.MaxClockSkew == 0 {
		cfg.MaxClockSkew = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	acc := cfg.AcceptableMeasurements
	if len(acc) == 0 {
		acc = []Measurement{expected}
	}
	v := &AzureCGPUVerifier{
		cfg:        cfg,
		acceptable: acc,
		jwks:       &nrasJWKS{url: cfg.NRASJWKSURL, dir: cfg.NRASCacheDir, get: nrasHTTPGet},
		snp:        snp,
	}
	switch cfg.GPUEvaluation {
	case "", GPUEvaluationNRAS:
	case GPUEvaluationOwn, GPUEvaluationBoth:
		v.ownOnly = cfg.GPUEvaluation == GPUEvaluationOwn
		device, err := parseNVIDIARoot(cfg.NVIDIADeviceRootPEM, NVIDIADeviceRootPEM)
		if err != nil {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: NVIDIA device root", err)
		}
		rimRoot, err := parseNVIDIARoot(cfg.NVIDIARIMRootPEM, NVIDIARIMRootPEM)
		if err != nil {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: NVIDIA RIM root", err)
		}
		v.gpuEval = &GPUEvaluator{DeviceRoot: device, RIMRoot: rimRoot, Now: cfg.Now,
			RIMs: &RIMFetcher{BaseURL: cfg.RIMServiceURL, CacheDir: cfg.RIMCacheDir}}
		switch cfg.GPURevocation {
		case "", GPURevocationOCSP:
			v.gpuEval.OCSP = &OCSPChecker{URL: cfg.OCSPURL, CacheDir: cfg.RIMCacheDir, Now: cfg.Now}
		case GPURevocationOff:
		default:
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("azure-cgpu: GPURevocation %q (one of ocsp, off)", cfg.GPURevocation), nil)
		}
	default:
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("azure-cgpu: GPUEvaluation %q (one of nras, both, own)", cfg.GPUEvaluation), nil)
	}
	return v, nil
}

// nrasHTTPGet fetches NVIDIA's key set; a var so tests run without network.
var nrasHTTPGet = func(url string) ([]byte, error) { return httpGet(url) }

// Verify implements Verifier.
func (v *AzureCGPUVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	verdict, err := v.VerifyEvidence(ev, nonce)
	if err != nil {
		return nil, err
	}
	return verdict.Measurement, nil
}

// VerifyDetailed implements DetailedVerifier: the verdict's platform and
// GPU facts go with the measurement.
func (v *AzureCGPUVerifier) VerifyDetailed(ev Evidence, nonce Nonce) (Measurement, *AttestationDetail, error) {
	verdict, err := v.VerifyEvidence(ev, nonce)
	if err != nil {
		return nil, nil, err
	}
	return verdict.Measurement, verdict.Detail(), nil
}

// Detail is the verdict as an AttestationDetail for the audit record.
func (d *AzureCGPUVerdict) Detail() *AttestationDetail {
	sel := make([]string, 0, len(d.PCRSelections))
	for _, s := range d.PCRSelections {
		sel = append(sel, s.String())
	}
	return &AttestationDetail{Provider: ProviderAzureCGPU, Product: d.Product, ChipIDHex: hex.EncodeToString(d.ChipID[:]),
		ReportedTCB: d.ReportedTCB, SEVSNP: d.SEVSNP, PCRSelection: strings.Join(sel, "+"), PCRDigestHex: hex.EncodeToString(d.PCRDigest),
		GPUs: d.GPUs, Evaluations: d.Evaluations}
}

// VerifyEvidence verifies and says what the evidence said.
func (v *AzureCGPUVerifier) VerifyEvidence(ev Evidence, nonce Nonce) (*AzureCGPUVerdict, error) {
	integrity := func(code, msg string, err error) error {
		return shared_errors.Integrity(code, "azure-cgpu: "+msg, err)
	}
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: challenger nonce too short", nil)
	}
	var env azureCGPUEvidence
	if err := json.Unmarshal(ev, &env); err != nil || env.Schema != AzureCGPUEvidenceSchema {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "evidence is not a "+AzureCGPUEvidenceSchema+" envelope", err)
	}

	// The chip and the vTPM (azure_vtpm.go).
	h, product, quote, snpDetail, err := v.snp.check(env.HCLReport, env.QuoteMessage, env.QuoteSignature, nonce)
	if err != nil {
		return nil, err
	}
	report := h.SNP
	challenge := tpmQuoteExtraDataFor(nonce)

	// The GPU: NVIDIA's tokens for the same challenge — unless the policy
	// rests the verdict on this verifier's own evaluation alone.
	var gpus []GPUVerdict
	if !v.ownOnly {
		token, err := parseNRASResponse(env.GPUToken)
		if err != nil {
			return nil, integrity(shared_errors.CodeSignatureInvalid, "GPU token: "+err.Error(), err)
		}
		now := v.cfg.Now()
		overall, err := v.jwks.verify(token.Overall, now, v.cfg.MaxClockSkew)
		if err != nil {
			return nil, integrity(shared_errors.CodeSignatureInvalid, "GPU overall token: "+err.Error(), err)
		}
		detached := map[string]map[string]any{}
		for key, t := range token.Detached {
			c, err := v.jwks.verify(t, now, v.cfg.MaxClockSkew)
			if err != nil {
				return nil, integrity(shared_errors.CodeSignatureInvalid, "GPU token "+key+": "+err.Error(), err)
			}
			detached[key] = c
		}
		if gpus, err = evaluateGPUClaims(overall, detached, hex.EncodeToString(challenge[:]), v.cfg.GPU); err != nil {
			return nil, integrity(shared_errors.CodeAttestationDenied, "GPU: "+err.Error(), err)
		}
	}

	// The GPU, evaluated here: the report and chain the driver produced,
	// held to NVIDIA's roots and signed manifests by this verifier, for
	// the same challenge. Under "both", every GPU NVIDIA spoke for must be
	// in the evidence and what the report says of it must be what NVIDIA
	// said; under "own", the report is the whole of the GPU's word, and
	// the policy's model and version pins are held against it.
	var evaluations []GPUEvaluation
	if v.gpuEval != nil {
		if len(env.GPUEvidence) == 0 {
			return nil, integrity(shared_errors.CodeAttestationDenied, "GPU: the evidence carries no report to evaluate (gpu_evidence), and the policy requires the verifier's own evaluation", nil)
		}
		if !v.ownOnly && len(env.GPUEvidence) != len(gpus) {
			return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("GPU: %d reports in the evidence, %d GPUs in NVIDIA's tokens", len(env.GPUEvidence), len(gpus)), nil)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		for i, item := range env.GPUEvidence {
			e := v.gpuEval.Evaluate(ctx, item.Report, item.CertChain, challenge[:])
			evaluations = append(evaluations, e)
			if !e.Complete() {
				return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("GPU %d, own evaluation: %s", i, strings.Join(e.Errors, "; ")), nil)
			}
			if v.ownOnly {
				g := GPUVerdict{Key: fmt.Sprintf("GPU-%d", i), HWModel: e.HWModel, DriverVersion: e.DriverVersion, VBIOSVersion: e.VBIOSVersion, UEID: e.UEID, Issuer: "own evaluation"}
				if err := v.cfg.GPU.holdsPins(g); err != nil {
					return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("GPU %d: %s", i, err), err)
				}
				gpus = append(gpus, g)
				continue
			}
			if e.DriverVersion != gpus[i].DriverVersion || !strings.EqualFold(e.VBIOSVersion, gpus[i].VBIOSVersion) {
				return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("GPU %d: the report names driver %s and VBIOS %s, NVIDIA's token %s and %s", i, e.DriverVersion, e.VBIOSVersion, gpus[i].DriverVersion, gpus[i].VBIOSVersion), nil)
			}
		}
	}

	// The pin.
	m, err := azureAcceptMeasurement(string(ProviderAzureCGPU), report, v.acceptable)
	if err != nil {
		return nil, err
	}
	return &AzureCGPUVerdict{Measurement: m, Product: product, ChipID: report.ChipID, ReportedTCB: report.ReportedTCB, SEVSNP: snpDetail,
		PCRSelections: quote.PCRSelections, PCRDigest: quote.PCRDigest, GPUs: gpus, Evaluations: evaluations}, nil
}

// azureCGPUCapability: the vTPM, tpm2-tools and an NVIDIA device.
func azureCGPUCapability() (bool, string) {
	if _, err := os.Stat("/dev/tpmrm0"); err != nil {
		return false, "Azure confidential GPU: no /dev/tpmrm0 (not a Confidential VM with a vTPM)"
	}
	if _, err := exec.LookPath("tpm2_quote"); err != nil {
		return false, "Azure confidential GPU: tpm2-tools not installed"
	}
	if _, err := os.Stat("/dev/nvidia0"); err != nil {
		return false, "Azure confidential GPU: no /dev/nvidia0 (no NVIDIA driver, or no GPU)"
	}
	return true, "Azure confidential GPU: vTPM, tpm2-tools and an NVIDIA device present"
}

// Compile-time interface conformance.
var (
	_ Producer = (*AzureCGPUProducer)(nil)
	_ Verifier = (*AzureCGPUVerifier)(nil)
)
