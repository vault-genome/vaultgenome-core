// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// selfSignedDER makes a certificate valid over [notBefore, notAfter).
func selfSignedDER(t *testing.T, cn string, notBefore, notAfter time.Time) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xBEEF), Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, cert, key
}

func TestCacheStatus_ReportsEveryKindWithItsValidity(t *testing.T) {
	now := time.Date(2026, 10, 15, 21, 0, 0, 0, time.UTC)
	root := t.TempDir()
	dirs := CacheDirs{VCEK: filepath.Join(root, "vcek"), PCS: filepath.Join(root, "pcs"), NRAS: filepath.Join(root, "nras"), RIM: filepath.Join(root, "rim")}
	for _, d := range []string{dirs.VCEK, dirs.PCS, dirs.NRAS, dirs.RIM} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(dir, name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// A VCEK good for a year, one that expired yesterday, and a file that is no certificate.
	chip := strings.Repeat("ab", 64)
	goodVCEK, _, _ := selfSignedDER(t, "SEV-VCEK", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	write(dirs.VCEK, chip+"-15.der", goodVCEK)
	oldVCEK, _, _ := selfSignedDER(t, "SEV-VCEK", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	write(dirs.VCEK, chip+"-7.der", oldVCEK)
	write(dirs.VCEK, "junk.der", []byte("not a certificate"))

	// A current TCB info with its issuer chain, and a QE identity whose chain file is missing.
	write(dirs.PCS, "tdx-tcb-00806f050000.json", []byte(`{"tcbInfo":{"id":"TDX","version":3,"fmspc":"00806F050000","issueDate":"2026-10-01T00:00:00Z","nextUpdate":"2026-10-31T00:00:00Z"},"signature":"00"}`))
	write(dirs.PCS, "tdx-tcb-00806f050000.issuer-chain.pem", []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"))
	write(dirs.PCS, "tdx-qe-identity.json", []byte(`{"enclaveIdentity":{"id":"TD_QE","version":2,"issueDate":"2026-10-01T00:00:00Z","nextUpdate":"2026-11-01T00:00:00Z"},"signature":"00"}`))

	// The NRAS key set, a RIM manifest and an OCSP answer good for a day.
	write(dirs.NRAS, "nras-jwks.json", []byte(`{"keys":[{"kty":"RSA","kid":"a"},{"kty":"RSA","kid":"b"}]}`))
	write(dirs.RIM, "NV_GPU_DRIVER_GH100_595.71.05.json", []byte(`{"rim":"x"}`))
	_, issuer, issuerKey := selfSignedDER(t, "NVIDIA test issuer", now.Add(-time.Hour), now.Add(24*time.Hour))
	// SHA-256 for the issuer hashes: the library's default is SHA-1, which
	// the cryptographic module refuses under fips140=only (ADR 0030).
	ocspDER, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{
		Status: ocsp.Good, SerialNumber: big.NewInt(0x1234), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(24 * time.Hour),
		IssuerHash: crypto.SHA256,
	}, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	write(dirs.RIM, "ocsp-0123.der", ocspDER)

	entries := CacheStatus(dirs, now)
	byFile := map[string]CacheEntry{}
	for _, e := range entries {
		byFile[e.File] = e
	}
	if len(entries) != 8 {
		t.Fatalf("entries: got %d: %+v", len(entries), entries)
	}
	check := func(file, kind string, current bool, subjectHas, noteHas string) {
		t.Helper()
		e, ok := byFile[file]
		if !ok {
			t.Fatalf("%s: not reported", file)
		}
		if e.Kind != kind || e.Current != current {
			t.Fatalf("%s: kind=%s current=%v (want %s, %v): %+v", file, e.Kind, e.Current, kind, current, e)
		}
		if subjectHas != "" && !strings.Contains(e.Subject, subjectHas) {
			t.Fatalf("%s: subject %q lacks %q", file, e.Subject, subjectHas)
		}
		if noteHas != "" && !strings.Contains(e.Note, noteHas) {
			t.Fatalf("%s: note %q lacks %q", file, e.Note, noteHas)
		}
	}
	check(chip+"-15.der", CacheKindVCEK, true, "SEV-VCEK", "chip abababababababab…, TCB 15")
	check(chip+"-7.der", CacheKindVCEK, false, "SEV-VCEK", "TCB 7")
	check("junk.der", CacheKindVCEK, false, "", "not a certificate")
	check("tdx-tcb-00806f050000.json", CacheKindPCS, true, "tcbInfo TDX fmspc=00806f050000", "")
	check("tdx-qe-identity.json", CacheKindPCS, false, "enclaveIdentity TD_QE", "issuer chain file missing")
	check("nras-jwks.json", CacheKindNRASJWKS, true, "NRAS key set", "2 keys")
	check("NV_GPU_DRIVER_GH100_595.71.05.json", CacheKindRIM, true, "NV_GPU_DRIVER_GH100_595.71.05", "does not expire")
	check("ocsp-0123.der", CacheKindOCSP, true, "serial 1234", "status good")

	if e := byFile["tdx-tcb-00806f050000.json"]; !e.NotAfter.Equal(time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("TCB info nextUpdate: %v", e.NotAfter)
	}
	earliest, ok := EarliestExpiry(entries)
	if !ok || !earliest.Equal(byFile[chip+"-7.der"].NotAfter) {
		t.Fatalf("earliest expiry: %v %v (want the expired VCEK's %v)", earliest, ok, byFile[chip+"-7.der"].NotAfter)
	}
	// With the expired VCEK gone, the OCSP answer (a day) expires first.
	if err := os.Remove(filepath.Join(dirs.VCEK, chip+"-7.der")); err != nil {
		t.Fatal(err)
	}
	earliest, _ = EarliestExpiry(CacheStatus(dirs, now))
	if !earliest.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("earliest expiry after the removal: %v", earliest)
	}

	// Past the OCSP answer's nextUpdate it is no longer current; past the
	// TCB info's, neither is that.
	later := CacheStatus(dirs, now.Add(25*time.Hour))
	for _, e := range later {
		if e.File == "ocsp-0123.der" && e.Current {
			t.Fatal("OCSP answer current past its nextUpdate")
		}
		if e.File == "tdx-tcb-00806f050000.json" && !e.Current {
			t.Fatal("TCB info not current a day later, before its nextUpdate")
		}
	}
	for _, e := range CacheStatus(dirs, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)) {
		if e.File == "tdx-tcb-00806f050000.json" && e.Current {
			t.Fatal("TCB info current past its nextUpdate")
		}
	}
}

func TestCacheStatus_MissingDirectoriesAreEmptyCaches(t *testing.T) {
	entries := CacheStatus(CacheDirs{VCEK: filepath.Join(t.TempDir(), "nowhere"), PCS: ""}, time.Now())
	if len(entries) != 0 {
		t.Fatalf("entries for missing directories: %+v", entries)
	}
	if _, ok := EarliestExpiry(nil); ok {
		t.Fatal("an expiry out of nothing")
	}
}
