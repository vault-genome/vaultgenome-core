// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/vault/failover"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// The operator's and the sentinel's keys follow the suite (ADR 0031):
// keygen writes the suite's file form, issue reads it under the suite the
// operator names, verify reads the suite from the PEM, and a list or
// policy is refused under a key of another suite before any signature is
// checked. On the FIPS module v1.0.0 ml-dsa-87 is refused at keygen with
// the module's reason.
func TestOperatorAndSentinelKeys_UnderEverySuite(t *testing.T) {
	t.Parallel()
	for _, suite := range crypto.Suites() {
		suite := suite
		t.Run(string(suite), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			opKey, opPub := filepath.Join(dir, "operator.key"), filepath.Join(dir, "operator.pem")
			code, stdout, stderr := runStop("keygen", "-out", opKey, "-pub", opPub, "-signature-suite", string(suite))
			if err := suite.Available(); err != nil {
				require.Equal(t, 2, code, stderr)
				require.Contains(t, stderr, "unavailable in FIPS 140-3 Go Cryptographic Module")
				return
			}
			require.Equal(t, 0, code, stderr)
			require.Contains(t, stdout, "("+string(suite)+")")
			file, err := os.ReadFile(opKey)
			require.NoError(t, err)
			if n := suite.KeyFileSize(); n > 0 {
				require.Len(t, file, n)
			} else {
				require.True(t, strings.HasPrefix(string(file), "-----BEGIN PRIVATE KEY-----"))
			}
			pemBytes, err := os.ReadFile(opPub)
			require.NoError(t, err)
			pub, err := crypto.ParsePublicKeyFile(pemBytes)
			require.NoError(t, err)
			require.Equal(t, suite, pub.Suite)

			// A stop list: issued under the suite, verified from the PEM.
			list := filepath.Join(dir, "stop.json")
			code, _, stderr = runStop("issue", "--key", opKey, "--signature-suite", string(suite), "--kid", "operator-1", "--serial", "3", "--all", "--reason", "drill", "--out", list)
			require.Equal(t, 0, code, stderr)
			raw, err := os.ReadFile(list)
			require.NoError(t, err)
			var l revocation.List
			require.NoError(t, json.Unmarshal(raw, &l))
			require.Equal(t, crypto.RecordAlg(suite), l.Alg)
			require.Len(t, l.Signature, suite.SignatureSize())
			code, stdout, stderr = runStop("verify", "--in", list, "--pubkey", opPub, "--kid", "operator-1", "--json")
			require.Equal(t, 0, code, stderr)
			require.Contains(t, stdout, `"serial":3`)
			// The key file read under another suite is refused.
			other := crypto.SuiteECDSAP384SHA384
			if suite == other {
				other = crypto.SuiteEd25519
			}
			code, _, stderr = runStop("issue", "--key", opKey, "--signature-suite", string(other), "--kid", "operator-1", "--serial", "4", "--all", "--out", filepath.Join(dir, "other.json"))
			require.NotEqual(t, 0, code)
			require.Contains(t, stderr, "--key")

			// The sentinel's key under the suite; its identity names it.
			sKey, sPub := filepath.Join(dir, "sentinel.key"), filepath.Join(dir, "sentinel.pem")
			code, stdout, stderr = runCmd(sentinelRun, "keygen", "--out", sKey, "--pub", sPub, "--signature-suite", string(suite))
			require.Equal(t, 0, code, stderr)
			require.Contains(t, stdout, "sentinel-")
			teeSeed := filepath.Join(dir, "tee.seed")
			require.NoError(t, os.WriteFile(teeSeed, bytes.Repeat([]byte{0x31}, 32), 0o600))
			code, stdout, stderr = runCmd(sentinelRun, "identity", "--tee", "simulated", "--tee-seed", teeSeed, "--workload-descriptor", "primary-drill", "--key", sKey, "--signature-suite", string(suite))
			require.Equal(t, 0, code, stderr)
			var id sentinelIdentity
			require.NoError(t, json.Unmarshal([]byte(stdout), &id))
			require.Equal(t, string(suite), id.SentinelSignatureSuite)
			sentinelPub, err := crypto.ParsePublicKeyFile([]byte(id.SentinelPublicKeyPEM))
			require.NoError(t, err)
			require.Equal(t, sentinel.KeyID(sentinelPub), id.SentinelKeyID)

			// A failover policy pins the sentinel key with its suite and is
			// signed under the operator's.
			policy := filepath.Join(dir, "failover.json")
			code, stdout, stderr = runCmd(failoverRun, "issue", "--key", opKey, "--signature-suite", string(suite), "--kid", "operator-1", "--serial", "5",
				"--sentinel-pub", sPub, "--standby-kind", "gcp-sev-snp", "--standby-endpoint", "https://standby.example:8443",
				"--standby-measurement", strings.Repeat("ab", 48), "--out", policy)
			require.Equal(t, 0, code, stderr)
			require.Contains(t, stdout, "("+string(suite)+")")
			raw, err = os.ReadFile(policy)
			require.NoError(t, err)
			var p failover.Policy
			require.NoError(t, json.Unmarshal(raw, &p))
			require.Equal(t, crypto.RecordAlg(suite), p.Alg)
			require.Equal(t, crypto.RecordAlg(suite), p.SentinelAlg)
			require.Equal(t, sentinelPub.Bytes, p.SentinelPublicKey)
			code, _, stderr = runCmd(failoverRun, "verify", "--in", policy, "--pubkey", opPub, "--kid", "operator-1", "--json")
			require.Equal(t, 0, code, stderr)

			// Under a key of another suite the records are refused before
			// any signature is checked.
			otherKey, err := crypto.GenerateSigningKey(other, nil)
			require.NoError(t, err)
			otherPEM, err := otherKey.Public().PEM()
			require.NoError(t, err)
			otherPub := filepath.Join(dir, "other.pem")
			require.NoError(t, os.WriteFile(otherPub, otherPEM, 0o644))
			code, _, stderr = runStop("verify", "--in", list, "--pubkey", otherPub, "--kid", "operator-1")
			require.Equal(t, 4, code, stderr)
			require.Contains(t, stderr, "does not match the key's suite")
			code, _, stderr = runCmd(failoverRun, "verify", "--in", policy, "--pubkey", otherPub, "--kid", "operator-1")
			require.Equal(t, 4, code, stderr)
			require.Contains(t, stderr, "does not match the key's suite")
		})
	}
}

func TestSuiteFlag_RefusesAnUnknownSuite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	code, _, stderr := runStop("keygen", "-out", filepath.Join(dir, "k"), "-pub", filepath.Join(dir, "p"), "-signature-suite", "rsa-pss")
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "--signature-suite")
	code, _, stderr = runCmd(sentinelRun, "keygen", "--out", filepath.Join(dir, "k2"), "--pub", filepath.Join(dir, "p2"), "--signature-suite", "")
	require.Equal(t, 0, code, stderr, "an empty suite is ed25519")
}
