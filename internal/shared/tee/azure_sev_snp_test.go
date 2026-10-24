// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// The azure-sev-snp family is the chip and the vTPM of the azure-cgpu
// fixture without NVIDIA: the same synthetic HCL report whose REPORT_DATA
// names a test attestation key, the same quotes by that key.

// sevsnpEvidence assembles the envelope an azure-sev-snp producer would
// for nonce.
func (f *azureCGPUFixture) sevsnpEvidence(t *testing.T, nonce []byte) Evidence {
	t.Helper()
	challenge := tpmQuoteExtraDataFor(nonce)
	msg, sig := f.quote(t, challenge[:])
	ev, err := json.Marshal(azureSEVSNPEvidence{Schema: AzureSEVSNPEvidenceSchema, HCLReport: f.hcl, QuoteMessage: msg, QuoteSignature: sig})
	require.NoError(t, err)
	return Evidence(ev)
}

// azureFixtureBoot is the boot the fixture's quotes report — the digest
// over its PCRs — which a verifier of the fixture pins (ADR 0037).
func azureFixtureBoot() [][]byte {
	d := sha256.Sum256([]byte("pcrs"))
	return [][]byte{d[:]}
}

func azureSEVSNPVerifier(t *testing.T, f *azureCGPUFixture, mutate func(*AzureSEVSNPVerifierConfig)) *AzureSEVSNPVerifier {
	t.Helper()
	cfg := AzureSEVSNPVerifierConfig{AMDRootPEM: f.chain, VCEKCacheDir: t.TempDir(), AcceptablePCRDigests: azureFixtureBoot()}
	if mutate != nil {
		mutate(&cfg)
	}
	v, err := NewAzureSEVSNPVerifier(nil, f.measurement, cfg)
	require.NoError(t, err)
	return v
}

func TestAzureSEVSNPVerifierAcceptsTheChipAndTheVTPM(t *testing.T) {
	f := newAzureCGPUFixture(t)
	stubAMD(t, true)
	v := azureSEVSNPVerifier(t, f, nil)
	nonce := Nonce("a return-path challenge, thirty-two bytes")
	verdict, err := v.VerifyEvidence(f.sevsnpEvidence(t, nonce), nonce)
	require.NoError(t, err)
	require.True(t, verdict.Measurement.Equal(f.measurement))
	require.Equal(t, "Genoa", verdict.Product)
	require.Equal(t, []int{0, 1, 2, 3, 4, 5, 6, 7}, verdict.PCRSelections[0].PCRs)
	digest := sha256.Sum256([]byte("pcrs"))
	require.Equal(t, digest[:], verdict.PCRDigest)
	detail := verdict.Detail()
	require.Equal(t, ProviderAzureSEVSNP, detail.Provider)
	require.Equal(t, hex.EncodeToString(digest[:]), detail.PCRDigestHex)
	require.Equal(t, "sha256:0,1,2,3,4,5,6,7", detail.PCRSelection)
	require.Empty(t, detail.GPUs, "no GPU in this family")
	require.NotEmpty(t, detail.ChipIDHex)

	m, err := v.Verify(f.sevsnpEvidence(t, nonce), nonce)
	require.NoError(t, err)
	require.True(t, m.Equal(f.measurement))
	m, d, err := v.VerifyDetailed(f.sevsnpEvidence(t, nonce), nonce)
	require.NoError(t, err)
	require.True(t, m.Equal(f.measurement))
	require.Equal(t, ProviderAzureSEVSNP, d.Provider)
	entries, err := os.ReadDir(v.snp.cacheDir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "the VCEK fetched for the chip is kept")
}

func TestAzureSEVSNPVerifierRefusesWhatItShould(t *testing.T) {
	f := newAzureCGPUFixture(t)
	nonce := Nonce("a return-path challenge, thirty-two bytes")

	t.Run("a report the chip did not sign", func(t *testing.T) {
		stubAMD(t, false)
		_, err := azureSEVSNPVerifier(t, f, nil).Verify(f.sevsnpEvidence(t, nonce), nonce)
		require.ErrorContains(t, err, "report signature")
		require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
	})
	stubAMD(t, true)
	v := azureSEVSNPVerifier(t, f, nil)

	t.Run("another nonce", func(t *testing.T) {
		_, err := v.Verify(f.sevsnpEvidence(t, nonce), Nonce("some other challenge of enough bytes"))
		require.ErrorContains(t, err, "TPM quote does not bind challenger nonce")
	})
	t.Run("a quote by another key", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		challenge := tpmQuoteExtraDataFor(nonce)
		msg, _ := f.quote(t, challenge[:])
		sum := sha256.Sum256(msg)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, other, crypto.SHA256, sum[:])
		ev, _ := json.Marshal(azureSEVSNPEvidence{Schema: AzureSEVSNPEvidenceSchema, HCLReport: f.hcl, QuoteMessage: msg, QuoteSignature: sig})
		_, err := v.Verify(Evidence(ev), nonce)
		require.ErrorContains(t, err, "does not verify under the attestation key")
	})
	t.Run("runtime data the report does not vouch for", func(t *testing.T) {
		challenge := tpmQuoteExtraDataFor(nonce)
		msg, sig := f.quote(t, challenge[:])
		hcl := append([]byte(nil), f.hcl...)
		hcl[len(hcl)-5] ^= 0x01
		ev, _ := json.Marshal(azureSEVSNPEvidence{Schema: AzureSEVSNPEvidenceSchema, HCLReport: hcl, QuoteMessage: msg, QuoteSignature: sig})
		_, err := v.Verify(Evidence(ev), nonce)
		require.ErrorContains(t, err, "not the SHA-256 of the runtime data")
	})
	t.Run("a PCR digest the policy does not name", func(t *testing.T) {
		pcrs := azureSEVSNPVerifier(t, f, func(c *AzureSEVSNPVerifierConfig) { c.AcceptablePCRDigests = [][]byte{make([]byte, 32)} })
		_, err := pcrs.Verify(f.sevsnpEvidence(t, nonce), nonce)
		require.ErrorContains(t, err, "PCR digest")
		require.Equal(t, shared_errors.CodeAttestationDenied, shared_errors.CodeOf(err))
		digest := sha256.Sum256([]byte("pcrs"))
		pinned := azureSEVSNPVerifier(t, f, func(c *AzureSEVSNPVerifierConfig) { c.AcceptablePCRDigests = [][]byte{digest[:]} })
		_, err = pinned.Verify(f.sevsnpEvidence(t, nonce), nonce)
		require.NoError(t, err)
	})
	t.Run("a measurement not pinned", func(t *testing.T) {
		w, err := NewAzureSEVSNPVerifier(nil, make(Measurement, 48), AzureSEVSNPVerifierConfig{AMDRootPEM: f.chain, AcceptablePCRDigests: azureFixtureBoot()})
		require.NoError(t, err)
		_, err = w.Verify(f.sevsnpEvidence(t, nonce), nonce)
		require.ErrorContains(t, err, "not in acceptable set")
		listed, err := NewAzureSEVSNPVerifier(nil, make(Measurement, 48), AzureSEVSNPVerifierConfig{AMDRootPEM: f.chain, AcceptablePCRDigests: azureFixtureBoot(), AcceptableMeasurements: []Measurement{f.measurement}})
		require.NoError(t, err)
		_, err = listed.Verify(f.sevsnpEvidence(t, nonce), nonce)
		require.NoError(t, err, "AcceptableMeasurements replaces the expected one")
	})
	t.Run("a debuggable guest", func(t *testing.T) {
		challenge := tpmQuoteExtraDataFor(nonce)
		msg, sig := f.quote(t, challenge[:])
		hcl := append([]byte(nil), f.hcl...)
		binary.LittleEndian.PutUint64(hcl[hclHeaderLen+sevOffPolicy:], 0x30000|sevPolicyDebug)
		ev, _ := json.Marshal(azureSEVSNPEvidence{Schema: AzureSEVSNPEvidenceSchema, HCLReport: hcl, QuoteMessage: msg, QuoteSignature: sig})
		_, err := v.Verify(Evidence(ev), nonce)
		require.ErrorContains(t, err, "DEBUG")
	})
	t.Run("a TCB below the floor", func(t *testing.T) {
		floor := azureSEVSNPVerifier(t, f, func(c *AzureSEVSNPVerifierConfig) { c.MinReportedTCB = 0x561B000000000005 }) // one above the Genoa-at-the-floors fixture
		_, err := floor.Verify(f.sevsnpEvidence(t, nonce), nonce)
		require.ErrorContains(t, err, "below minimum")
	})
	t.Run("not an envelope, or the other family's", func(t *testing.T) {
		_, err := v.Verify(Evidence(f.hcl), nonce)
		require.ErrorContains(t, err, "envelope")
		_, err = v.Verify(f.evidence(t, nonce), nonce)
		require.ErrorContains(t, err, "envelope", "an azure-cgpu envelope is not this family's")
	})
	t.Run("a short nonce", func(t *testing.T) {
		_, err := v.Verify(f.sevsnpEvidence(t, nonce), Nonce("short"))
		require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
	})
	t.Run("no AMD chain, no verifier", func(t *testing.T) {
		_, err := NewAzureSEVSNPVerifier(nil, f.measurement, AzureSEVSNPVerifierConfig{})
		require.ErrorContains(t, err, "AMDRootPEM")
	})
}

// Under Azure's paravisor the launch measurement is the paravisor's and
// the firmware's: a verifier of either family is refused a policy that
// names no boot, and a boot that is not a SHA-256 digest (ADR 0037).
func TestAzureVerifiersRequireTheBoot(t *testing.T) {
	f := newAzureCGPUFixture(t)
	_, err := NewAzureSEVSNPVerifier(nil, f.measurement, AzureSEVSNPVerifierConfig{AMDRootPEM: f.chain})
	require.ErrorContains(t, err, "azure-sev-snp: the policy names no boot")
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	_, err = NewAzureCGPUVerifier(nil, f.measurement, AzureCGPUVerifierConfig{AMDRootPEM: f.chain})
	require.ErrorContains(t, err, "azure-cgpu: the policy names no boot")
	_, err = BuildVerifier(VerifierSpec{Provider: ProviderAzureSEVSNP, ExpectedMeasurement: f.measurement, AzureSEVSNP: AzureSEVSNPVerifierConfig{AMDRootPEM: f.chain}})
	require.ErrorContains(t, err, "the policy names no boot")
	_, err = NewAzureSEVSNPVerifier(nil, f.measurement, AzureSEVSNPVerifierConfig{AMDRootPEM: f.chain, AcceptablePCRDigests: [][]byte{make([]byte, 31)}})
	require.ErrorContains(t, err, "pcr_digests: 31 bytes, want 32")
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

// stubVTPMTools makes the vTPM's tools answer from the fixture: the HCL
// report under NV read, two persistent handles of which the second is the
// attestation key, and quotes signed by it.
func stubVTPMTools(t *testing.T, f *azureCGPUFixture) *[]string {
	t.Helper()
	akPEM := pemPublicKey(t, &f.ak.PublicKey)
	old := runCommand
	t.Cleanup(func() { runCommand = old })
	calls := &[]string{}
	runCommand = func(_ time.Duration, argv ...string) ([]byte, error) {
		*calls = append(*calls, filepath.Base(argv[0]))
		switch filepath.Base(argv[0]) {
		case "tpm2_nvread":
			return f.hcl, nil
		case "tpm2_getcap":
			return []byte("- 0x81000000\n- 0x81000003\n"), nil
		case "tpm2_readpublic":
			handle, out := argv[2], argv[len(argv)-1]
			if handle == "0x81000003" {
				return nil, os.WriteFile(out, akPEM, 0o600)
			}
			other, _ := rsa.GenerateKey(rand.Reader, 2048)
			return nil, os.WriteFile(out, pemPublicKey(t, &other.PublicKey), 0o600)
		case "tpm2_quote":
			var msgPath, sigPath, q string
			for i := range argv {
				switch argv[i] {
				case "-m":
					msgPath = argv[i+1]
				case "-s":
					sigPath = argv[i+1]
				case "-q":
					q = argv[i+1]
				}
			}
			extra, _ := hex.DecodeString(q)
			msg, sig := f.quote(t, extra)
			require.NoError(t, os.WriteFile(msgPath, msg, 0o600))
			return nil, os.WriteFile(sigPath, sig, 0o600)
		}
		return nil, os.ErrNotExist
	}
	return calls
}

func TestAzureSEVSNPProducerRunsTheToolsAndAssemblesTheEnvelope(t *testing.T) {
	f := newAzureCGPUFixture(t)
	stubAMD(t, true)
	calls := stubVTPMTools(t, f)
	p, err := NewAzureSEVSNPProducer(AzureSEVSNPProducerConfig{})
	require.NoError(t, err)
	require.Equal(t, "0x81000003", p.vtpm.akHandle, "the persistent key that is HCLAkPub")
	require.True(t, p.Measurement().Equal(f.measurement))
	sel, digest := p.VTPMBoot()
	require.Equal(t, "sha256:0,1,2,3,4,5,6,7", sel[0].String())
	bootDigest := sha256.Sum256([]byte("pcrs"))
	require.Equal(t, bootDigest[:], digest, "what the vTPM measured of this boot, from the quote at construction")
	pcrs, d2, ok := VTPMBootOf(p)
	require.True(t, ok)
	require.Equal(t, []string{"sha256:0,1,2,3,4,5,6,7"}, pcrs, "the fixture quotes one bank")
	require.Equal(t, bootDigest[:], d2)
	_, _, ok = VTPMBootOf(&Simulated{})
	require.False(t, ok, "no vTPM in the simulated TEE")

	nonce := Nonce("a return-path challenge, thirty-two bytes")
	ev, err := p.Quote(nonce)
	require.NoError(t, err)
	var env azureSEVSNPEvidence
	require.NoError(t, json.Unmarshal(ev, &env))
	require.Equal(t, AzureSEVSNPEvidenceSchema, env.Schema)
	require.Equal(t, f.hcl, env.HCLReport)
	require.NotContains(t, *calls, "gpu-token", "no GPU command in this family")
	require.Contains(t, *calls, "tpm2_nvread")
	require.Contains(t, *calls, "tpm2_quote")

	v := azureSEVSNPVerifier(t, f, nil)
	m, err := v.Verify(ev, nonce)
	require.NoError(t, err, "what the producer made, the verifier accepts")
	require.True(t, m.Equal(f.measurement))
	_, err = p.Quote(Nonce("short"))
	require.Error(t, err)
	require.NoError(t, p.Close())
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "closed")

	given, err := NewAzureSEVSNPProducer(AzureSEVSNPProducerConfig{AKHandle: "0x81000003", PCRs: "sha256:0,1,2,3,4,5,6,7"})
	require.NoError(t, err, "a handle given is taken as it is")
	require.Equal(t, "0x81000003", given.vtpm.akHandle)
}

func TestAzureSEVSNPIsOneRowOfTheTable(t *testing.T) {
	p, err := ParseProvider("azure-sev-snp")
	require.NoError(t, err)
	require.Equal(t, ProviderAzureSEVSNP, p)
	require.Contains(t, AllProviders(), ProviderAzureSEVSNP)

	mt, err := EvidenceMediaType(ProviderAzureSEVSNP)
	require.NoError(t, err)
	require.Equal(t, MediaTypeAzureSEVSNPEvidence, mt)
	ev := Evidence(`{"schema":"vault-genome/azure-sev-snp-evidence/v1"}`)
	gotType, value, err := WrapEvidence(ProviderAzureSEVSNP, ev, nil)
	require.NoError(t, err)
	require.Equal(t, MediaTypeAzureSEVSNPEvidence, gotType)
	back, aux, err := UnwrapEvidence(ProviderAzureSEVSNP, gotType, value)
	require.NoError(t, err)
	require.Equal(t, ev, back)
	require.Empty(t, aux)
	_, _, err = UnwrapEvidence(ProviderAzureSEVSNP, MediaTypeAzureCGPUEvidence, value)
	require.Error(t, err, "the other Azure family's record is refused by name")

	kind, err := SealerKindForProvider(ProviderAzureSEVSNP, SealerModeAuto)
	require.NoError(t, err)
	require.Equal(t, SealerKindTPM2, kind, "the vTPM seals: the paravisor gives no derived key")
	_, err = SealerKindForProvider(ProviderAzureSEVSNP, SealerModeTEE)
	require.ErrorContains(t, err, "tee.sealer=tee")

	f := newAzureCGPUFixture(t)
	stubAMD(t, true)
	v, err := BuildVerifier(VerifierSpec{Provider: ProviderAzureSEVSNP, ExpectedMeasurement: f.measurement, AzureSEVSNP: AzureSEVSNPVerifierConfig{AMDRootPEM: f.chain, AcceptablePCRDigests: azureFixtureBoot()}})
	require.NoError(t, err)
	nonce := Nonce("a return-path challenge, thirty-two bytes")
	m, err := v.Verify(f.sevsnpEvidence(t, nonce), nonce)
	require.NoError(t, err)
	require.True(t, m.Equal(f.measurement))
	stubVTPMTools(t, f)
	prod, err := BuildProducer(ProducerSpec{Provider: ProviderAzureSEVSNP})
	require.NoError(t, err)
	require.True(t, prod.Measurement().Equal(f.measurement))
	sk, err := SealerKindFor(prod, SealerModeAuto)
	require.NoError(t, err)
	require.Equal(t, SealerKindTPM2, sk)
	_, reason := Capability(ProviderAzureSEVSNP)
	require.Contains(t, reason, "Azure SEV-SNP")
}
