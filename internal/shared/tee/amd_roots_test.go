// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func amdFixtureChain(t *testing.T, product string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "amd", "kds-"+product+"-cert_chain.pem"))
	require.NoError(t, err)
	return b
}

// TestPinnedAMDRoots_MatchRecordedFingerprints: the embedded certificates
// parse, are self-signed roots named for their product line, and hash to
// the fingerprints recorded from three sources (testdata/amd/README.md).
func TestPinnedAMDRoots_MatchRecordedFingerprints(t *testing.T) {
	t.Parallel()
	roots, err := pinnedAMDRoots()
	require.NoError(t, err)
	require.Len(t, roots, len(AMDProducts))
	for i, r := range roots {
		require.Equal(t, AMDProducts[i], r.product)
		require.Equal(t, "ARK-"+r.product, r.cert.Subject.CommonName)
		require.Equal(t, r.cert.Subject.String(), r.cert.Issuer.String(), "a root is self-issued")
		require.NoError(t, r.cert.CheckSignature(r.cert.SignatureAlgorithm, r.cert.RawTBSCertificate, r.cert.Signature), "a root is self-signed")
		require.Equal(t, AMDRootFingerprintSHA256[r.product], r.fingerprint, "%s: the embedded bytes must hash to the recorded fingerprint", r.product)
		require.Equal(t, r.product, pinnedAMDRootFor(r.cert))
	}
}

// TestVerifyAMDCertChain_KDSChains: the chains AMD KDS serves for each
// product line verify and are recognised as that product's.
func TestVerifyAMDCertChain_KDSChains(t *testing.T) {
	t.Parallel()
	for _, p := range AMDProducts {
		info, err := VerifyAMDCertChain(amdFixtureChain(t, p))
		require.NoError(t, err, p)
		require.Equal(t, p, info.Product)
		require.Equal(t, "SEV-"+p, info.ASKSubjectCN)
		require.Equal(t, "ARK-"+p, info.ARKSubjectCN)
		require.Equal(t, AMDRootFingerprintSHA256[p], info.ARKFingerprintSHA256)
	}
}

// foreignAMDChain builds a chain shaped like AMD's — an RSA-PSS
// self-signed "ARK", an "ASK" it signs — under keys that are not AMD's,
// and a VCEK-shaped ECDSA P-384 leaf the fake ASK signs.
func foreignAMDChain(t *testing.T) (chainPEM, vcekDER []byte) {
	t.Helper()
	now := time.Now()
	arkKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	arkTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ARK-Milan", Organization: []string{"Not AMD"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.SHA384WithRSAPSS,
	}
	arkDER, err := x509.CreateCertificate(rand.Reader, arkTmpl, arkTmpl, &arkKey.PublicKey, arkKey)
	require.NoError(t, err)
	ark, err := x509.ParseCertificate(arkDER)
	require.NoError(t, err)

	askKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	askTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "SEV-Milan", Organization: []string{"Not AMD"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.SHA384WithRSAPSS,
	}
	askDER, err := x509.CreateCertificate(rand.Reader, askTmpl, ark, &askKey.PublicKey, arkKey)
	require.NoError(t, err)
	ask, err := x509.ParseCertificate(askDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(3),
		Subject:            pkix.Name{CommonName: "SEV-VCEK", Organization: []string{"Not AMD"}},
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
	}
	vcekDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, ask, &leafKey.PublicKey, askKey)
	require.NoError(t, err)

	chainPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: askDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: arkDER})...)
	return chainPEM, vcekDER
}

// TestAMDChain_ForeignRootRefused: a chain whose signatures all check but
// whose root is not AMD's is refused — at load (VerifyAMDCertChain), at
// verification (realVerifyAMDChain) and at construction of both verifiers.
// Before ADR 0024 the first two accepted it.
func TestAMDChain_ForeignRootRefused(t *testing.T) {
	t.Parallel()
	chain, vcek := foreignAMDChain(t)

	_, err := VerifyAMDCertChain(chain)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an AMD root this build pins")

	err = realVerifyAMDChain(vcek, chain)
	require.Error(t, err, "the leaf chains to the fake ASK and ARK, and must still be refused")
	require.Contains(t, err.Error(), "not an AMD root this build pins")

	_, err = NewGCPSEVVerifier(nil, Measurement{}, GCPSEVVerifierConfig{AMDRootPEM: chain})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an AMD root this build pins")

	_, err = NewAzureCGPUVerifier(nil, Measurement{}, AzureCGPUVerifierConfig{AMDRootPEM: chain})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an AMD root this build pins")

	// The genuine chains construct both verifiers.
	_, err = NewGCPSEVVerifier(nil, Measurement{}, GCPSEVVerifierConfig{AMDRootPEM: amdFixtureChain(t, "Milan")})
	require.NoError(t, err)
}

// TestVerifyAMDCertChain_Malformed: not a chain, one certificate, two
// roots — each refused with a reason, none accepted.
func TestVerifyAMDCertChain_Malformed(t *testing.T) {
	t.Parallel()
	_, err := VerifyAMDCertChain([]byte("not pem"))
	require.Error(t, err)
	milan := amdFixtureChain(t, "Milan")
	blk, _ := pem.Decode(milan)
	one := pem.EncodeToMemory(blk)
	_, err = VerifyAMDCertChain(one)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected 2 certs")
	// The Genoa ASK under the Milan ARK: signatures do not check.
	genoa := amdFixtureChain(t, "Genoa")
	gblk, _ := pem.Decode(genoa)
	var milanARK []byte
	for rest := milan; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		c, perr := x509.ParseCertificate(b.Bytes)
		require.NoError(t, perr)
		if c.Subject.CommonName == "ARK-Milan" {
			milanARK = pem.EncodeToMemory(b)
		}
	}
	require.NotEmpty(t, milanARK)
	_, err = VerifyAMDCertChain(append(pem.EncodeToMemory(gblk), milanARK...))
	require.Error(t, err)
	require.Contains(t, err.Error(), "ASK not signed by ARK")
}

// TestFetchAMDCertChain: fetched from a server that serves KDS's bytes,
// verified against the pinned roots; a chain of another product line, or
// an unknown product, is refused.
func TestFetchAMDCertChain(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	for _, p := range AMDProducts {
		p := p
		mux.HandleFunc("/vcek/v1/"+p+"/cert_chain", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(amdFixtureChain(t, p))
		})
	}
	// A server that answers the Milan path with the Genoa chain.
	mux.HandleFunc("/wrong/vcek/v1/Milan/cert_chain", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(amdFixtureChain(t, "Genoa"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, p := range []string{"milan", "GENOA", "Turin"} {
		chain, info, err := FetchAMDCertChain(srv.URL, p)
		require.NoError(t, err, p)
		require.Equal(t, amdFixtureChain(t, info.Product), chain, "returned byte for byte as served")
		require.Equal(t, AMDRootFingerprintSHA256[info.Product], info.ARKFingerprintSHA256)
	}
	_, _, err := FetchAMDCertChain(srv.URL+"/wrong", "milan")
	require.Error(t, err)
	require.Contains(t, err.Error(), "returned a Genoa chain for Milan")
	_, _, err = FetchAMDCertChain(srv.URL, "rome")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown AMD product line")
	_, _, err = FetchAMDCertChain(srv.URL+"/missing", "milan")
	require.Error(t, err)
}
