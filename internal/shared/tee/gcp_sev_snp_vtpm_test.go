// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The evidence a gcp-sev-snp-vtpm producer gave on a Compute Engine n2d
// SEV-SNP instance (the boot-chain kit, run 20261024T160531Z, boot B, the
// probe's product step), with the nonce it answered and the VCEK the
// verifier on that guest fetched from AMD KDS for the chip.
type gceBootFixture struct {
	evidence []byte
	nonce    []byte
	digest   []byte
	measure  Measurement
	chain    []byte
	cacheDir string
}

const gceBootBDigestHex = "0f9d00f40688ca1485c732168b7cccd3b8d852f8e2a33ab3a2e7b93701317864"

func loadGCEBootB(t *testing.T) gceBootFixture {
	t.Helper()
	ev, err := os.ReadFile("testdata/gce-vtpm/boot-b/evidence.json")
	require.NoError(t, err)
	nhex, err := os.ReadFile("testdata/gce-vtpm/boot-b/nonce.hex")
	require.NoError(t, err)
	nonce, err := hex.DecodeString(strings.TrimSpace(string(nhex)))
	require.NoError(t, err)
	digest, err := hex.DecodeString(gceBootBDigestHex)
	require.NoError(t, err)
	chain, err := os.ReadFile("testdata/amd/kds-Milan-cert_chain.pem")
	require.NoError(t, err)
	var env gcpSEVVTPMEvidence
	require.NoError(t, json.Unmarshal(ev, &env))
	report, err := parseSEVSNPReport(env.Report)
	require.NoError(t, err)
	return gceBootFixture{evidence: ev, nonce: nonce, digest: digest, measure: Measurement(report.Measurement[:]), chain: chain, cacheDir: "testdata/gce-vtpm/boot-b/vcek"}
}

func (f gceBootFixture) verifier(t *testing.T, mutate func(*GCPSEVVTPMVerifierConfig)) *GCPSEVVTPMVerifier {
	t.Helper()
	cfg := GCPSEVVTPMVerifierConfig{
		SEV:                  GCPSEVVerifierConfig{AMDRootPEM: f.chain, VCEKCacheDir: f.cacheDir, AMDKDSURL: "http://127.0.0.1:1"},
		AcceptablePCRDigests: [][]byte{f.digest},
		Now:                  func() time.Time { return time.Date(2026, 10, 24, 17, 0, 0, 0, time.UTC) },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	v, err := NewGCPSEVVTPMVerifier(nil, f.measure, cfg)
	require.NoError(t, err)
	return v
}

// The verifier that ships accepts what the producer that ships gave on the
// hardware, offline: the chip to AMD's chain at the attack record's floors,
// the AK to Google's pinned root for that instance, the quote to the nonce
// and the pinned boot.
func TestGCPSEVVTPMVerifierAcceptsTheCapturedBoot(t *testing.T) {
	f := loadGCEBootB(t)
	verdict, err := f.verifier(t, func(c *GCPSEVVTPMVerifierConfig) { c.ProjectIDs = []string{"rats-probe"} }).VerifyEvidence(f.evidence, f.nonce)
	require.NoError(t, err)
	require.Equal(t, f.measure, verdict.Measurement)
	require.Equal(t, f.digest, verdict.PCRDigest)
	require.Equal(t, "rats-probe", verdict.Instance.ProjectID)
	require.True(t, verdict.Instance.IsProduction)
	d := verdict.Detail()
	require.Equal(t, ProviderGCPSEVSNPVTPM, d.Provider)
	require.Equal(t, "sha256:0,1,2,3,4,5,6,7,8,9", d.PCRSelection)
	require.Equal(t, gceBootBDigestHex, d.PCRDigestHex)
	require.NotNil(t, d.GCEInstance)
}

func TestGCPSEVVTPMVerifierRefusesWhatThePolicyDoesNotName(t *testing.T) {
	f := loadGCEBootB(t)
	other := append([]byte(nil), f.digest...)
	other[0] ^= 1

	_, err := f.verifier(t, func(c *GCPSEVVTPMVerifierConfig) { c.AcceptablePCRDigests = [][]byte{other} }).VerifyEvidence(f.evidence, f.nonce)
	require.ErrorContains(t, err, "is not in the acceptable set", "another boot: another kernel, command line or initrd")

	_, err = f.verifier(t, func(c *GCPSEVVTPMVerifierConfig) { c.ProjectIDs = []string{"someone-elses-project"} }).VerifyEvidence(f.evidence, f.nonce)
	require.ErrorContains(t, err, "which the policy does not name")

	_, err = f.verifier(t, func(c *GCPSEVVTPMVerifierConfig) { c.PCRs = "sha256:0,1,2,3,4,5,6,7" }).VerifyEvidence(f.evidence, f.nonce)
	require.ErrorContains(t, err, "the quote covers")

	otherNonce := append([]byte(nil), f.nonce...)
	otherNonce[0] ^= 1
	_, err = f.verifier(t, nil).VerifyEvidence(f.evidence, otherNonce)
	require.ErrorContains(t, err, "nonce", "a replayed answer")
}

func TestGCPSEVVTPMVerifierRefusesAnAlteredEnvelope(t *testing.T) {
	f := loadGCEBootB(t)
	v := f.verifier(t, nil)
	var env gcpSEVVTPMEvidence
	require.NoError(t, json.Unmarshal(f.evidence, &env))

	// The quote's signature, one bit off.
	bad := env
	bad.QuoteSignature = append([]byte(nil), env.QuoteSignature...)
	bad.QuoteSignature[10] ^= 1
	raw, _ := json.Marshal(bad)
	_, err := v.VerifyEvidence(raw, f.nonce)
	require.ErrorContains(t, err, "quote signature does not verify")

	// Another instance's AK certificate (the first run's), which the chip's
	// REPORT_DATA does not name.
	otherAK, err := os.ReadFile("testdata/gce-vtpm/ak-cert-rsa.der")
	require.NoError(t, err)
	swapped := env
	swapped.AKCertificate = otherAK
	raw, _ = json.Marshal(swapped)
	_, err = v.VerifyEvidence(raw, f.nonce)
	require.ErrorContains(t, err, "does not name the vTPM key")

	// The chip's report alone, without the boot.
	_, err = v.VerifyEvidence(Evidence(env.Report), f.nonce)
	require.ErrorContains(t, err, "a chip's report alone does not carry the boot")
}

func TestNewGCPSEVVTPMVerifierNeedsTheBoot(t *testing.T) {
	_, err := NewGCPSEVVTPMVerifier(nil, make(Measurement, 48), GCPSEVVTPMVerifierConfig{})
	require.ErrorContains(t, err, "the policy names no boot")
	_, err = NewGCPSEVVTPMVerifier(nil, make(Measurement, 48), GCPSEVVTPMVerifierConfig{AcceptablePCRDigests: [][]byte{{1, 2}}})
	require.ErrorContains(t, err, "want 32")
}
