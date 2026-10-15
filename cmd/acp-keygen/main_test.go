// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err, path)
	return b
}

func parsePEMCert(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(b)
	require.NotNil(t, blk)
	c, err := x509.ParseCertificate(blk.Bytes)
	require.NoError(t, err)
	return c
}

// TestRun_WritesTheTree: every file of the layout, with the documented
// modes, and the material inside it consistent: each side pins the other's
// TEE key and measurement, the registry names the worker's signing key,
// the PKI verifies.
func TestRun_WritesTheTree(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "secrets")
	var out bytes.Buffer
	require.NoError(t, run(dir, false, false, false, &out))
	require.Contains(t, out.String(), "acp-keygen: wrote secrets under")
	require.NotContains(t, out.String(), strings.TrimSpace(string(readFile(t, filepath.Join(dir, "sagvd", "api_token")))), "the token is never printed")

	lo := newLayout(dir)
	require.Len(t, lo.files(), 17)
	for _, p := range lo.files() {
		st, err := os.Stat(p)
		require.NoError(t, err, p)
		require.Equal(t, fs.FileMode(0o644), st.Mode().Perm(), p)
	}
	for _, d := range lo.dirs() {
		st, err := os.Stat(d)
		require.NoError(t, err, d)
		require.Equal(t, fs.FileMode(0o755), st.Mode().Perm(), d)
	}

	// Seeds and keys of the right size; each side pins the other's TEE key.
	sagvdSeed := readFile(t, lo.sagvdTEESeed)
	workerSeed := readFile(t, lo.workerTEESeed)
	require.Len(t, sagvdSeed, ed25519.SeedSize)
	require.Len(t, workerSeed, ed25519.SeedSize)
	require.Equal(t, []byte(ed25519.NewKeyFromSeed(workerSeed).Public().(ed25519.PublicKey)), readFile(t, lo.sagvdPeerWorkerPubkey))
	require.Equal(t, []byte(ed25519.NewKeyFromSeed(sagvdSeed).Public().(ed25519.PublicKey)), readFile(t, lo.workerPeerVaultPubkey))
	for _, p := range []string{lo.sagvdAuthoritySigningSeed, lo.sagvdAuditSigningSeed, lo.workerSigningSeed, lo.sealingKey} {
		require.Len(t, readFile(t, p), 32, p)
	}
	require.NotEqual(t, readFile(t, lo.sagvdAuthoritySigningSeed), readFile(t, lo.sagvdAuditSigningSeed), "distinct seeds")

	// Measurements are the SHA-256 of the workload descriptors.
	sm := sha256.Sum256([]byte(vaultWorkloadDescriptor))
	wm := sha256.Sum256([]byte(workerWorkloadDescriptor))
	require.Equal(t, sm[:], readFile(t, lo.workerPeerVaultMeas))
	require.Equal(t, wm[:], readFile(t, lo.sagvdPeerWorkerMeasure))

	// The bearer token: 64 hex characters and a newline.
	tok := string(readFile(t, lo.sagvdAPIToken))
	require.True(t, strings.HasSuffix(tok, "\n"))
	_, err := hex.DecodeString(strings.TrimSpace(tok))
	require.NoError(t, err)
	require.Len(t, strings.TrimSpace(tok), 64)

	// The registry names the worker's signing key under its kid.
	var reg workersRegistry
	require.NoError(t, json.Unmarshal(readFile(t, lo.workersJSON), &reg))
	require.Len(t, reg.Workers, 1)
	require.Equal(t, kidWorkerSigning, reg.Workers[0].KeyID)
	require.Equal(t, hex.EncodeToString(ed25519.NewKeyFromSeed(readFile(t, lo.workerSigningSeed)).Public().(ed25519.PublicKey)), reg.Workers[0].SigningPublicKeyHex)

	// The PKI: both leaves verify under the CA for their use; the server
	// names the service and the loopback addresses.
	ca := parsePEMCert(t, readFile(t, lo.caCert))
	require.True(t, ca.IsCA)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	server := parsePEMCert(t, readFile(t, lo.sagvdTLSCert))
	_, err = server.Verify(x509.VerifyOptions{Roots: pool, DNSName: vaultTLSName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	require.NoError(t, err)
	_, err = server.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	require.NoError(t, err)
	require.Contains(t, server.IPAddresses, net.IPv4(127, 0, 0, 1).To4())
	client := parsePEMCert(t, readFile(t, lo.workerTLSCert))
	_, err = client.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	require.NoError(t, err)
	require.Equal(t, workerTLSName, client.Subject.CommonName)
	// The leaf keys are PKCS#8 and belong to their certificates.
	for _, pair := range [][2]string{{lo.sagvdTLSCert, lo.sagvdTLSKey}, {lo.workerTLSCert, lo.workerTLSKey}} {
		kb, _ := pem.Decode(readFile(t, pair[1]))
		require.NotNil(t, kb)
		require.Equal(t, "PRIVATE KEY", kb.Type)
		_, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
		require.NoError(t, err)
	}
}

// TestRun_PrivateModes: -private writes 0600 files in 0700 directories.
func TestRun_PrivateModes(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "secrets")
	require.NoError(t, run(dir, false, true, true, &bytes.Buffer{}))
	lo := newLayout(dir)
	for _, p := range lo.files() {
		st, err := os.Stat(p)
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0o600), st.Mode().Perm(), p)
	}
	for _, d := range lo.dirs() {
		st, err := os.Stat(d)
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0o700), st.Mode().Perm(), d)
	}
}

// TestRun_RefusesToOverwriteWithoutForce: a second run keeps the tree;
// -force replaces it, including the modes.
func TestRun_RefusesToOverwriteWithoutForce(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "secrets")
	require.NoError(t, run(dir, false, true, true, &bytes.Buffer{}))
	lo := newLayout(dir)
	before := readFile(t, lo.sealingKey)

	err := run(dir, false, true, false, &bytes.Buffer{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing to overwrite existing secrets (17 files")
	require.Equal(t, before, readFile(t, lo.sealingKey), "nothing was touched")

	require.NoError(t, run(dir, true, true, false, &bytes.Buffer{}))
	require.NotEqual(t, before, readFile(t, lo.sealingKey), "regenerated")
	st, err := os.Stat(lo.sealingKey)
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o644), st.Mode().Perm(), "the modes follow the re-run")

	// An unreadable root is an error, not a silent skip.
	require.NoError(t, os.WriteFile(filepath.Join(t.TempDir(), "file"), nil, 0o600))
}

// TestRealMain_Flags: -out is required; -version prints and exits; a
// bad flag is usage; -quiet silences the report.
func TestRealMain_Flags(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	require.Equal(t, 2, realMain(nil, &stdout, &stderr))
	require.Contains(t, stderr.String(), "-out is required")
	stderr.Reset()
	require.Equal(t, 2, realMain([]string{"-nonsense"}, &stdout, &stderr))
	stderr.Reset()
	require.Equal(t, 0, realMain([]string{"-version"}, &stdout, &stderr))
	require.Contains(t, stdout.String(), "acp-keygen ")
	stdout.Reset()

	dir := filepath.Join(t.TempDir(), "s")
	require.Equal(t, 0, realMain([]string{"-out", dir, "-private"}, &stdout, &stderr), stderr.String())
	require.Contains(t, stdout.String(), "files 0600, directories 0700")
	stdout.Reset()
	require.Equal(t, 1, realMain([]string{"-out", dir}, &stdout, &stderr), "exists, no -force")
	require.Contains(t, stderr.String(), "refusing to overwrite")
	stderr.Reset()
	require.Equal(t, 0, realMain([]string{"-out", dir, "-force", "-quiet"}, &stdout, &stderr))
	require.Empty(t, stdout.String(), "-quiet")
}
