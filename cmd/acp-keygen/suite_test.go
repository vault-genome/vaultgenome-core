// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
)

// -signature-suite writes the three signing keys in the suite's file form
// and names the suite in the worker registry; the TEE seeds stay the
// simulated TEE's Ed25519 keys. On the FIPS module v1.0.0 ml-dsa-87 is
// refused with the module's reason.
func TestRun_SignatureSuite(t *testing.T) {
	t.Parallel()
	for _, suite := range crypto.Suites() {
		suite := suite
		t.Run(string(suite), func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join(t.TempDir(), "secrets")
			var stdout, stderr bytes.Buffer
			rc := realMain([]string{"-out", dir, "-signature-suite", string(suite)}, &stdout, &stderr)
			if err := suite.Available(); err != nil {
				require.Equal(t, 2, rc, stderr.String())
				require.Contains(t, stderr.String(), "unavailable in FIPS 140-3 Go Cryptographic Module")
				return
			}
			require.Equal(t, 0, rc, stderr.String())
			require.Contains(t, stdout.String(), "signature suite:             "+string(suite))
			lo := newLayout(dir)
			for _, p := range []string{lo.sagvdAuthoritySigningSeed, lo.sagvdAuditSigningSeed, lo.workerSigningSeed} {
				file, err := os.ReadFile(p)
				require.NoError(t, err)
				if n := suite.KeyFileSize(); n > 0 {
					require.Len(t, file, n, p)
				} else {
					require.True(t, strings.HasPrefix(string(file), "-----BEGIN PRIVATE KEY-----"), p)
				}
				key, err := crypto.LoadSigningKey(suite, file)
				require.NoError(t, err, p)
				require.Equal(t, suite, key.Suite())
			}
			// The TEE seeds are not on the suite.
			for _, p := range []string{lo.sagvdTEESeed, lo.workerTEESeed} {
				file, err := os.ReadFile(p)
				require.NoError(t, err)
				require.Len(t, file, 32, p)
			}
			// The registry names the suite beside the worker's raw key.
			raw, err := os.ReadFile(lo.workersJSON)
			require.NoError(t, err)
			var reg workersRegistry
			require.NoError(t, json.Unmarshal(raw, &reg))
			require.Len(t, reg.Workers, 1)
			require.Equal(t, string(crypto.RecordAlg(suite)), reg.Workers[0].Suite)
			pub, err := hex.DecodeString(reg.Workers[0].SigningPublicKeyHex)
			require.NoError(t, err)
			require.Len(t, pub, suite.PublicKeySize())
			workerFile, err := os.ReadFile(lo.workerSigningSeed)
			require.NoError(t, err)
			workerKey, err := crypto.LoadSigningKey(suite, workerFile)
			require.NoError(t, err)
			require.Equal(t, workerKey.PublicKeyBytes(), pub)
			if suite == crypto.SuiteEd25519 {
				require.NotContains(t, string(raw), `"suite"`, "an ed25519 registry is the one every earlier release wrote")
			}
		})
	}
	var stdout, stderr bytes.Buffer
	require.Equal(t, 2, realMain([]string{"-out", filepath.Join(t.TempDir(), "s"), "-signature-suite", "rsa-pss"}, &stdout, &stderr))
	require.Contains(t, stderr.String(), "-signature-suite")
}
