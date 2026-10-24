// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The AK certificate of a Compute Engine SEV-SNP instance's vTPM, read from NV
// index 0x01c10000 by the boot-chain kit (run 20261024T153800Z, boot B), and
// the intermediate its authority-information URL served that day.
func gceAKFixture(t *testing.T) (leaf, intermediate []byte) {
	t.Helper()
	leaf, err := os.ReadFile("testdata/gce-vtpm/ak-cert-rsa.der")
	require.NoError(t, err)
	intermediate, err = os.ReadFile("testdata/gce-vtpm/ek-ak-ca-intermediate.der")
	require.NoError(t, err)
	return leaf, intermediate
}

var gceFixtureTime = time.Date(2026, 10, 24, 16, 0, 0, 0, time.UTC)

func TestGCEAKCertificateVerifiesToThePinnedRoot(t *testing.T) {
	leaf, inter := gceAKFixture(t)
	roots, err := gceEKAKRoots(nil)
	require.NoError(t, err)
	ak, err := verifyGCEAKCertificate(leaf, [][]byte{inter}, roots, gceFixtureTime)
	require.NoError(t, err)
	require.Equal(t, 2048, ak.Key.N.BitLen())
	require.Equal(t, "us-central1-c", ak.Instance.Zone)
	require.Equal(t, "rats-probe", ak.Instance.ProjectID)
	require.Equal(t, "vg-bootchain-20261024t153800z", ak.Instance.InstanceName)
	require.NotZero(t, ak.Instance.InstanceID)
	require.True(t, ak.Instance.IsProduction)
}

func TestGCEAKCertificateRefusesWhatDoesNotChain(t *testing.T) {
	leaf, inter := gceAKFixture(t)
	roots, err := gceEKAKRoots(nil)
	require.NoError(t, err)

	_, err = verifyGCEAKCertificate(leaf, nil, roots, gceFixtureTime)
	require.ErrorContains(t, err, "does not chain", "without the intermediate")

	other := x509.NewCertPool()
	other.AddCert(selfSignedForTest(t))
	_, err = verifyGCEAKCertificate(leaf, [][]byte{inter}, other, gceFixtureTime)
	require.ErrorContains(t, err, "does not chain", "under another root")

	_, err = verifyGCEAKCertificate(leaf, [][]byte{inter}, roots, time.Date(2026, 10, 24, 15, 0, 0, 0, time.UTC))
	require.ErrorContains(t, err, "does not chain", "before the certificate was issued")

	bad := append([]byte(nil), leaf...)
	bad[len(bad)-10] ^= 0x01 // inside the signature
	_, err = verifyGCEAKCertificate(bad, [][]byte{inter}, roots, gceFixtureTime)
	require.Error(t, err, "a changed byte")
}

func TestParseGCEInstanceNeedsTheExtension(t *testing.T) {
	_, err := parseGCEInstance(selfSignedForTest(t))
	require.ErrorContains(t, err, "names no Compute Engine instance")
}

func TestGCEEKAKRootsTakesTheOperatorsToo(t *testing.T) {
	c := selfSignedForTest(t)
	pool, err := gceEKAKRoots(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	require.NoError(t, err)
	_, err = c.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: gceFixtureTime})
	require.NoError(t, err)
}

func selfSignedForTest(t *testing.T) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "not Google"},
		NotBefore: gceFixtureTime.Add(-time.Hour), NotAfter: gceFixtureTime.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c
}

// The template Google stores at NV 0x01c10001, read by the kit, becomes the
// arguments that make the certified key: RSA 2048, RSASSA-SHA256, a
// restricted signing key, and its 256-byte unique as tpm2-tools reads it.
func TestGCEAKTemplateBecomesCreatePrimaryArgs(t *testing.T) {
	raw, err := os.ReadFile("testdata/gce-vtpm/ak-template-rsa.bin")
	require.NoError(t, err)
	tmpl, err := parseGCEAKTemplate(raw)
	require.NoError(t, err)
	require.Equal(t, uint32(0x00050072), tmpl.Attributes)
	require.Equal(t, uint16(2048), tmpl.KeyBits)
	require.Len(t, tmpl.Unique, 256)
	dir := t.TempDir()
	args, err := tmpl.createPrimaryArgs(dir)
	require.NoError(t, err)
	require.Equal(t, []string{"-C", "e", "-g", "sha256", "-G", "rsa2048:rsassa-sha256:null",
		"-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign", "-u", filepath.Join(dir, "ak.unique")}, args)
	u, err := os.ReadFile(filepath.Join(dir, "ak.unique"))
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0x01}, u[:2], "the length word, little-endian")
	require.Equal(t, tmpl.Unique, u[2:])

	_, err = parseGCEAKTemplate(append(append([]byte(nil), raw...), 1))
	require.ErrorContains(t, err, "bytes after the template")
	ecc := append([]byte{0x00, 0x23}, raw[2:]...)
	_, err = parseGCEAKTemplate(ecc)
	require.ErrorContains(t, err, "want RSA")
}
