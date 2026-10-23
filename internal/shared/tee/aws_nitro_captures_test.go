// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The verifier against the hypervisor's own documents. One production-mode
// attestation document of the May 2026 cohort is in the repository
// (testdata/aws-nitro, VM1 in us-east-2a, published 2026-09-22); the
// other three stay under NDA, and the test runs on them too when
// VG_NITRO_CAPTURE_DIR names a directory of cohort directories, each
// holding 04-attestation-document.bin, 02d-expected-pcrs.json and
// 01-vaultgenome-enclave-build-manifest.json.

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// nitroCapture is one captured document with what the kit recorded
// about it: the PCRs of the image (`nitro-cli describe-eif`) and the file
// whose SHA-512 the kit bound as user_data.
type nitroCapture struct {
	name     string
	doc      string
	manifest string
	pcr0     string
	pcr1     string
	pcr2     string
}

// publishedNitroCapture is the document in the repository. Its expected
// PCRs are those of scripts/hardware-test/aws-nitro/evidence/01-VM1-us-east-2a/02d-expected-pcrs.json.
var publishedNitroCapture = nitroCapture{
	name:     "2026-05-08-vm1-us-east-2a",
	doc:      "testdata/aws-nitro/2026-05-08-vm1-us-east-2a-attestation-document.bin",
	manifest: "testdata/aws-nitro/2026-05-08-vm1-us-east-2a-build-manifest.json",
	pcr0:     "69d556eff8606bd9828baaac20612f03851f29ddd989387ce5ab3a9cde8917add48d78f1f84c53dc2aafedb9ecb8734e",
	pcr1:     "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
	pcr2:     "a841e2a12857318dfabc1b2f610a812016052adad6f9b42aabf7bf332472cf07dfd7582d9664bc35f0a0cd010290fd73",
}

// ndaNitroCaptures lists the cohort directories under VG_NITRO_CAPTURE_DIR,
// or nothing when the variable is unset.
func ndaNitroCaptures(t *testing.T) []nitroCapture {
	t.Helper()
	dir := os.Getenv("VG_NITRO_CAPTURE_DIR")
	if dir == "" {
		return nil
	}
	docs, err := filepath.Glob(filepath.Join(dir, "*", "04-attestation-document.bin"))
	require.NoError(t, err)
	require.NotEmpty(t, docs, "no */04-attestation-document.bin under %s", dir)
	var out []nitroCapture
	for _, doc := range docs {
		cohort := filepath.Dir(doc)
		var expected struct {
			PCR0 string `json:"expected_pcr0"`
			PCR1 string `json:"expected_pcr1"`
			PCR2 string `json:"expected_pcr2"`
		}
		raw, err := os.ReadFile(filepath.Join(cohort, "02d-expected-pcrs.json"))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &expected))
		out = append(out, nitroCapture{
			name:     filepath.Base(cohort),
			doc:      doc,
			manifest: filepath.Join(cohort, "01-vaultgenome-enclave-build-manifest.json"),
			pcr0:     expected.PCR0,
			pcr1:     expected.PCR1,
			pcr2:     expected.PCR2,
		})
	}
	return out
}

func TestAWSNitro_GenuineProductionCaptures(t *testing.T) {
	captures := append([]nitroCapture{publishedNitroCapture}, ndaNitroCaptures(t)...)
	for _, c := range captures {
		t.Run(c.name, func(t *testing.T) {
			raw, err := os.ReadFile(c.doc)
			require.NoError(t, err)

			// The document audits at its own timestamp against the built-in root.
			report, err := AuditAWSNitroDocument(raw, nil, time.Time{})
			require.NoError(t, err)
			t.Logf("module %s signed %s; chain %d certificates, root %q", report.ModuleID, report.Timestamp.Format(time.RFC3339Nano), len(report.Chain), report.Chain[len(report.Chain)-1])
			require.Len(t, report.Chain, 5)
			require.Contains(t, report.Chain[4], "CN=aws.nitro-enclaves")
			require.Contains(t, report.Chain[0], report.ModuleID)
			require.False(t, report.Debug, "production-mode enclave: PCR0 is not zero")
			require.Nil(t, report.Nonce, "the May 2026 kit asked the NSM for no nonce")
			require.Nil(t, report.PublicKey)
			require.Len(t, report.PCRs, 16)
			require.WithinDuration(t, report.Timestamp, report.SigningCertNotBefore, 10*time.Second)
			require.Equal(t, 3*time.Hour, report.SigningCertNotAfter.Sub(report.Timestamp).Round(time.Minute))

			// PCR0..2 equal what `nitro-cli describe-eif` printed for the image.
			require.Equal(t, c.pcr0, hex.EncodeToString(report.PCRs[0]))
			require.Equal(t, c.pcr1, hex.EncodeToString(report.PCRs[1]))
			require.Equal(t, c.pcr2, hex.EncodeToString(report.PCRs[2]))

			// user_data is the SHA-512 of the build manifest the kit bound.
			manifest, err := os.ReadFile(c.manifest)
			require.NoError(t, err)
			sum := sha512.Sum512(manifest)
			require.True(t, bytes.Equal(sum[:], report.UserData), "user_data is not the manifest's SHA-512")
			// That binds the manifest's bytes, not the image: the May kit wrote
			// the manifest in its debug build and reused it for the production
			// one, so the PCR0 it names is not the one the hypervisor measured
			// (testdata/aws-nitro/README.md). The image is the PCRs above.
			var m struct {
				PCR0 string `json:"enclave_image_sha384_pcr0"`
			}
			require.NoError(t, json.Unmarshal(manifest, &m))
			require.NotEqual(t, hex.EncodeToString(report.PCRs[0]), m.PCR0, "the manifest names its debug build's PCR0, as the README says")

			// The same document at today's clock: the signing certificate
			// expired three hours after capture, and the chain check says so.
			_, err = AuditAWSNitroDocument(raw, nil, time.Now())
			require.Error(t, err)
			require.Contains(t, err.Error(), "certificate chain")

			// A Verifier with a challenge refuses the document even at its
			// capture time: it carries no nonce, and a nonce is mandatory.
			v, err := NewAWSNitroVerifier(nil, Measurement(report.PCRs[0]), AWSNitroVerifierConfig{Now: func() time.Time { return report.Timestamp }})
			require.NoError(t, err)
			_, err = v.Verify(raw, bytes.Repeat([]byte{0x42}, NonceMinBytes))
			require.Error(t, err)
			require.Contains(t, err.Error(), "nonce")

			// A byte flipped in the signature, in the payload, or in the
			// chain is refused.
			for _, off := range []int{len(raw) - 1, len(raw) / 2, 200} {
				tampered := append([]byte(nil), raw...)
				tampered[off] ^= 0x01
				_, err = AuditAWSNitroDocument(tampered, nil, time.Time{})
				require.Error(t, err, "flip at %d", off)
			}
		})
	}
}

// TestAWSNitro_PublishedCapture_Identity pins the published document to
// what testdata/aws-nitro/README.md says about it.
func TestAWSNitro_PublishedCapture_Identity(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(publishedNitroCapture.doc)
	require.NoError(t, err)
	require.Len(t, raw, 4523)
	report, err := AuditAWSNitroDocument(raw, nil, time.Time{})
	require.NoError(t, err)
	require.Equal(t, "i-0e35190ae3157095d-enc019e0512a5715d4f", report.ModuleID)
	require.Equal(t, time.Date(2026, 5, 8, 0, 52, 52, 755_000_000, time.UTC), report.Timestamp)
	require.Equal(t, "CN=i-0e35190ae3157095d-enc019e0512a5715d4f.us-east-2.aws,OU=AWS,O=Amazon,L=Seattle,ST=Washington,C=US", report.Chain[0])
	require.Equal(t, "CN=aws.nitro-enclaves,OU=AWS,O=Amazon,C=US", report.Chain[4])
}
