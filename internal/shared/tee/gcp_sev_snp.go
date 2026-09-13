// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tee — Google Cloud Confidential VMs (AMD SEV-SNP) adapter.
//
// GCP Confidential VMs (N2D-confidential, C3D-confidential) run on AMD
// EPYC processors with SEV-SNP (Secure Encrypted Virtualization with
// Secure Nested Paging) enabled. Inside such a VM the guest kernel
// exposes /dev/sev-guest, an ioctl interface to request:
//
//   - SEV_SNP_GUEST_MSG_REPORT: an attestation report (1184 bytes)
//   - SEV_SNP_GUEST_MSG_DERIVED_KEY: a key derived from the platform
//     sealing root, optionally bound to the policy + measurement
//
// The attestation report contains:
//
//   - VERSION (1B)
//   - GUEST_SVN, POLICY (8B): firmware version + guest policy bits
//   - FAMILY_ID, IMAGE_ID (32B): caller-defined VM identity
//   - VMPL (4B): Virtual Machine Privilege Level (0 = full)
//   - SIGNATURE_ALGO (4B): typically 1 = ECDSA-P384-SHA384
//   - PLATFORM_INFO (8B), PLATFORM_VERSION (8B)
//   - REPORT_DATA (64B): caller-supplied — we put SHA-256(nonce) here
//   - MEASUREMENT (48B): the launch measurement (SHA-384 of guest
//     pages at launch — used as our Measurement, truncated to 32B)
//   - HOST_DATA (32B), ID_KEY_DIGEST (48B), AUTHOR_KEY_DIGEST (48B)
//   - REPORT_ID (32B), REPORT_ID_MA (32B)
//   - REPORTED_TCB (8B), CPUID (24B)
//   - CHIP_ID (64B), COMMITTED_TCB / CURRENT_TCB
//   - SIGNATURE (512B): ECDSA-P384 by VCEK (Versioned Chip Endorsement Key)
//
// The VCEK is unique per CPU; AMD signs it with their AMD SEV-SNP
// signing key, which chains to the AMD Root CA. Verification:
//
//   1. Fetch VCEK certificate from AMD KDS using CHIP_ID + reported TCB
//      (URL: https://kdsintf.amd.com/vcek/v1/Milan/<CHIP_ID>?...)
//   2. Validate VCEK chain: VCEK ← ASK (Milan/Genoa) ← ARK (AMD Root)
//   3. Verify ECDSA-P384 signature over the report (excluding signature)
//   4. Check freshness via REPORT_DATA nonce binding
//   5. Check launch MEASUREMENT against expected
//
// Sealing on SEV-SNP uses derived keys from the platform sealing root.
// Unlike SGX, SEV-SNP sealing is not transparent — the guest must
// derive its own AES key from the SEV_SNP_GUEST_MSG_DERIVED_KEY
// response, then use it for AEAD. The derivation can be bound to the
// guest policy + measurement so that a different VM image cannot
// reproduce the key.

package tee

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
)

// GCPSEVProducerConfig configures the SEV-SNP producer.
type GCPSEVProducerConfig struct {
	// SEVGuestDevicePath is the path to /dev/sev-guest. Default
	// "/dev/sev-guest" (mainline kernel ≥ 5.19).
	SEVGuestDevicePath string

	// VMPL is the Virtual Machine Privilege Level requested in the
	// attestation report (0–3). Default 0 = full guest privilege.
	VMPL uint32
}

// GCPSEVVerifierConfig configures the SEV-SNP verifier.
type GCPSEVVerifierConfig struct {
	// AMDKDSURL overrides the default https://kdsintf.amd.com base URL.
	// Useful for air-gapped / mirrored deployments that cache VCEK
	// responses locally (Google publishes a mirror at
	// https://confidentialcomputing.googleapis.com/v1/...).
	AMDKDSURL string

	// AMDRootPEM overrides the pinned AMD ARK certificate (for sovereign
	// installations using their own pinned trust anchor). Default uses
	// the AMD-published Milan / Genoa / Turin roots embedded at build.
	AMDRootPEM []byte

	// AcceptableMeasurements lists every launch measurement the verifier
	// will accept. When empty, falls back to VerifierSpec.ExpectedMeasurement.
	AcceptableMeasurements [][32]byte

	// MinReportedTCB enforces minimum AMD secure firmware version. Set
	// to the current TCB at deployment time and bump on AMD security
	// advisories.
	MinReportedTCB uint64

	// MaxClockSkew bounds REPORT freshness using either REPORT_ID or
	// an external timestamp service. Default 5 minutes.
	MaxClockSkew time.Duration

	// AcceptableHostData, if non-empty, restricts which host
	// configurations (HOST_DATA field, set by the hypervisor) are
	// acceptable. GCP populates HOST_DATA with deployment-specific
	// metadata — operators can pin specific values.
	AcceptableHostData [][32]byte
}

// GCPSEVProducer implements Producer using /dev/sev-guest.
type GCPSEVProducer struct {
	cfg         GCPSEVProducerConfig
	measurement Measurement // launch MEASUREMENT (truncated to 32B)

	mu     sync.Mutex
	device *os.File
}

// GCPSEVVerifier implements Verifier for SEV-SNP attestation reports.
type GCPSEVVerifier struct {
	cfg            GCPSEVVerifierConfig
	expected       Measurement
	acceptable     [][32]byte
	minReportedTCB uint64
	maxClockSkew   time.Duration

	mu        sync.Mutex
	vcekCache map[string][]byte // CHIP_ID+TCB → VCEK PEM
}

// GCPSEVSealer implements Sealer using SEV_SNP_GUEST_MSG_DERIVED_KEY.
type GCPSEVSealer struct {
	device  *os.File
	measure Measurement
	policy  uint64 // guest policy bits embedded into derived key
}

// ----------------------------------------------------------------------------
// Constructors
// ----------------------------------------------------------------------------

// NewGCPSEVProducer opens /dev/sev-guest and reads the launch measurement.
func NewGCPSEVProducer(cfg GCPSEVProducerConfig) (*GCPSEVProducer, error) {
	if cfg.SEVGuestDevicePath == "" {
		cfg.SEVGuestDevicePath = "/dev/sev-guest"
	}
	if cfg.VMPL > 3 {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"gcp-sev: vmpl must be 0..3",
			nil,
		)
	}

	dev, err := os.OpenFile(cfg.SEVGuestDevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("gcp-sev: open %s: %v (this binary must run inside a Confidential VM)", cfg.SEVGuestDevicePath, err),
			err,
		)
	}

	p := &GCPSEVProducer{cfg: cfg, device: dev}

	// Read a one-time report with a synthetic nonce just to extract the
	// launch MEASUREMENT field. After this, every Quote() call gets a
	// fresh report with the challenger's actual nonce.
	dummyNonce := make([]byte, NonceMinBytes)
	for i := range dummyNonce {
		dummyNonce[i] = byte(i)
	}
	report, err := sevSNPGuestReport(dev, dummyNonce, cfg.VMPL)
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("gcp-sev: initial report: %w", err)
	}
	if len(report.Measurement) < 32 {
		_ = dev.Close()
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"gcp-sev: MEASUREMENT < 32 bytes",
			nil,
		)
	}
	copy(p.measurement[:], report.Measurement[:32])
	return p, nil
}

// NewGCPSEVVerifier constructs a verifier for SEV-SNP reports.
func NewGCPSEVVerifier(_ crypto.PublicKey, expected Measurement, cfg GCPSEVVerifierConfig) (*GCPSEVVerifier, error) {
	if cfg.AMDKDSURL == "" {
		cfg.AMDKDSURL = "https://kdsintf.amd.com"
	}
	if cfg.MaxClockSkew == 0 {
		cfg.MaxClockSkew = 5 * time.Minute
	}
	acc := cfg.AcceptableMeasurements
	if len(acc) == 0 {
		acc = [][32]byte{[32]byte(expected)}
	}
	return &GCPSEVVerifier{
		cfg:            cfg,
		expected:       expected,
		acceptable:     acc,
		minReportedTCB: cfg.MinReportedTCB,
		maxClockSkew:   cfg.MaxClockSkew,
		vcekCache:      map[string][]byte{},
	}, nil
}

// NewGCPSEVSealer constructs a sealer that derives an AEAD key from the
// SEV-SNP platform sealing root, bound to the launch measurement +
// guest policy.
func NewGCPSEVSealer(device *os.File, measure Measurement, policy uint64) *GCPSEVSealer {
	return &GCPSEVSealer{device: device, measure: measure, policy: policy}
}

// ----------------------------------------------------------------------------
// Producer / Verifier / Sealer
// ----------------------------------------------------------------------------

// Quote implements Producer. Issues SEV_SNP_GUEST_MSG_REPORT with
// REPORT_DATA = SHA-256(nonce) || zeros(32). Returns the raw report
// bytes (1184 bytes) as Evidence.
func (p *GCPSEVProducer) Quote(nonce Nonce) (Evidence, error) {
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"gcp-sev: nonce must be at least NonceMinBytes",
			nil,
		)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.device == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"gcp-sev: device not open",
			nil,
		)
	}
	report, err := sevSNPGuestReport(p.device, nonce, p.cfg.VMPL)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev: GUEST_MSG_REPORT: %w", err)
	}
	return Evidence(report.Raw), nil
}

// Measurement returns the cached launch MEASUREMENT.
func (p *GCPSEVProducer) Measurement() Measurement {
	return p.measurement
}

// Close releases the device handle.
func (p *GCPSEVProducer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.device == nil {
		return nil
	}
	err := p.device.Close()
	p.device = nil
	return err
}

// Verify implements Verifier. Parses the SEV-SNP report, fetches and
// validates the VCEK + AMD chain, verifies the ECDSA signature, and
// checks REPORT_DATA + MEASUREMENT against expected values.
func (v *GCPSEVVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	var zero Measurement
	if len(nonce) < NonceMinBytes {
		return zero, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"gcp-sev: challenger nonce too short",
			nil,
		)
	}
	if len(ev) < 1184 {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"gcp-sev: evidence shorter than SEV-SNP report (1184 bytes)",
			nil,
		)
	}

	report, err := parseSEVSNPReport(ev)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: parse report: %v", err),
			err,
		)
	}

	// Fetch + verify VCEK certificate chain (cached per CHIP_ID + TCB).
	vcekPEM, err := v.fetchVCEK(report.ChipID, report.ReportedTCB)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: fetch VCEK: %v", err),
			err,
		)
	}
	if err := verifyAMDChain(vcekPEM, v.cfg.AMDRootPEM); err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: AMD chain: %v", err),
			err,
		)
	}

	// Verify ECDSA-P384 signature over the report (excluding the
	// signature field).
	if err := verifySEVReportSignature(report, vcekPEM); err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: report signature: %v", err),
			err,
		)
	}

	// Reported TCB must be ≥ minimum (no rollback to vulnerable firmware).
	if report.ReportedTCB < v.minReportedTCB {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: ReportedTCB %d below minimum %d", report.ReportedTCB, v.minReportedTCB),
			nil,
		)
	}

	// Bind nonce.
	if !nonceMatchesReportDataSEV(report.ReportData, nonce) {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"gcp-sev: REPORT_DATA does not bind challenger nonce (replay?)",
			nil,
		)
	}

	// HOST_DATA policy (optional).
	if len(v.cfg.AcceptableHostData) > 0 {
		ok := false
		for _, hd := range v.cfg.AcceptableHostData {
			if hd == report.HostData {
				ok = true
				break
			}
		}
		if !ok {
			return zero, shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				fmt.Sprintf("gcp-sev: HOST_DATA %x not in acceptable set", report.HostData),
				nil,
			)
		}
	}

	// Launch MEASUREMENT must match expected (truncated to 32 bytes).
	var meas32 [32]byte
	copy(meas32[:], report.Measurement[:32])
	matched := false
	for _, m := range v.acceptable {
		if m == meas32 {
			matched = true
			break
		}
	}
	if !matched {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: MEASUREMENT %x not in acceptable set", meas32),
			nil,
		)
	}

	return Measurement(meas32), nil
}

// fetchVCEK retrieves the VCEK PEM for a given CHIP_ID + TCB combination,
// caching responses to avoid hammering AMD KDS.
func (v *GCPSEVVerifier) fetchVCEK(chipID [64]byte, tcb uint64) ([]byte, error) {
	key := fmt.Sprintf("%x-%d", chipID, tcb)
	v.mu.Lock()
	defer v.mu.Unlock()
	if c, ok := v.vcekCache[key]; ok {
		return c, nil
	}
	pem, err := amdKDSGetVCEK(v.cfg.AMDKDSURL, chipID, tcb)
	if err != nil {
		return nil, err
	}
	v.vcekCache[key] = pem
	return pem, nil
}

// Seal implements Sealer using a derived AES-256 key bound to the
// platform sealing root + measurement + policy.
func (s *GCPSEVSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	key, err := sevSNPDerivedKey(s.device, s.measure, s.policy)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-sealer: derive key: %w", err)
	}
	ciphertext, err := sevAEADSeal(key, plaintext, aad)
	zeroize(key)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-sealer: AEAD seal: %w", err)
	}
	return ciphertext, nil
}

// Unseal implements Sealer.
func (s *GCPSEVSealer) Unseal(sealed, aad []byte) ([]byte, error) {
	key, err := sevSNPDerivedKey(s.device, s.measure, s.policy)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-sealer: derive key: %w", err)
	}
	plaintext, err := sevAEADOpen(key, sealed, aad)
	zeroize(key)
	if err != nil {
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev-sealer: AEAD open: %v (different VM image / policy?)", err),
			err,
		)
	}
	return plaintext, nil
}

// ----------------------------------------------------------------------------
// Capability
// ----------------------------------------------------------------------------

func gcpSEVCapability() (bool, string) {
	if _, err := os.Stat("/dev/sev-guest"); err == nil {
		return true, "GCP SEV-SNP: /dev/sev-guest present"
	}
	return false, "GCP SEV-SNP: /dev/sev-guest not present (host lacks AMD SEV-SNP or kernel < 5.19)"
}

// ----------------------------------------------------------------------------
// Stubs (Phase 2 wiring)
// ----------------------------------------------------------------------------

type sevSNPReport struct {
	Raw         []byte
	Measurement [48]byte
	HostData    [32]byte
	ChipID      [64]byte
	ReportedTCB uint64
	ReportData  [64]byte
}

// sevSNPGuestReport issues SEV_SNP_GUEST_MSG_REPORT via ioctl.
//
// Phase 2 wiring: import "github.com/google/go-sev-guest" or implement
// the ioctl directly using golang.org/x/sys/unix. The kernel API is
// SEV_SNP_GUEST_MSG_REPORT (0xC000_5300 ioctl number).
//
// Stored as a var so integration tests can substitute a fake SEV guest.
var sevSNPGuestReport = func(_ *os.File, _ []byte, _ uint32) (*sevSNPReport, error) {
	return nil, errors.New("sevSNPGuestReport: not yet wired (Phase 2 — github.com/google/go-sev-guest)")
}

var parseSEVSNPReport = func(_ []byte) (*sevSNPReport, error) {
	return nil, errors.New("parseSEVSNPReport: not yet wired (Phase 2 — fixed-offset binary parse)")
}

// amdKDSGetVCEK GET https://kdsintf.amd.com/vcek/v1/Milan/<CHIP_ID>?...
var amdKDSGetVCEK = func(_ string, _ [64]byte, _ uint64) ([]byte, error) {
	return nil, errors.New("amdKDSGetVCEK: not yet wired (Phase 2 — net/http GET to AMD KDS)")
}

var verifyAMDChain = func(_ []byte, _ []byte) error {
	return errors.New("verifyAMDChain: not yet wired (Phase 2 — crypto/x509 chain validate against AMD ARK)")
}

var verifySEVReportSignature = func(_ *sevSNPReport, _ []byte) error {
	return errors.New("verifySEVReportSignature: not yet wired (Phase 2 — ECDSA-P384 over report excluding signature)")
}

var sevSNPDerivedKey = func(_ *os.File, _ Measurement, _ uint64) ([]byte, error) {
	return nil, errors.New("sevSNPDerivedKey: not yet wired (Phase 2 — SEV_SNP_GUEST_MSG_DERIVED_KEY ioctl)")
}

var sevAEADSeal = func(_, _, _ []byte) ([]byte, error) {
	return nil, errors.New("sevAEADSeal: not yet wired (Phase 2 — crypto/cipher AES-256-GCM)")
}

var sevAEADOpen = func(_, _, _ []byte) ([]byte, error) {
	return nil, errors.New("sevAEADOpen: not yet wired (Phase 2)")
}

func nonceMatchesReportDataSEV(reportData [64]byte, nonce []byte) bool {
	expected := computeReportDataPrefix(nonce)
	for i := 0; i < 32; i++ {
		if reportData[i] != expected[i] {
			return false
		}
	}
	return true
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Compile-time interface conformance.
var (
	_ Producer = (*GCPSEVProducer)(nil)
	_ Verifier = (*GCPSEVVerifier)(nil)
	_ Sealer   = (*GCPSEVSealer)(nil)
)
