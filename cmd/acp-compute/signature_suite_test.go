// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// The worker reads its signing key under the suite the configuration
// names, prints the suite in its identity, seals the key file whatever
// its form and opens it again. On the FIPS module v1.0.0 a configuration
// that names ml-dsa-87 is refused with the module's reason.
func TestLoadMaterials_WorkerSigningKeyUnderEverySuite(t *testing.T) {
	for _, suite := range crypto.Suites() {
		suite := suite
		t.Run(string(suite), func(t *testing.T) {
			cfg, dir := testKeyDir(t)
			if suite.Available() != nil {
				cfg.Keys.WorkerSigning.Suite = string(suite)
				require.NoError(t, cfg.Validate())
				_, err := LoadMaterials(cfg, testClock(t))
				require.Error(t, err)
				require.Contains(t, err.Error(), "unavailable in FIPS 140-3 Go Cryptographic Module")
				return
			}
			key, err := crypto.GenerateSigningKey(suite, nil)
			require.NoError(t, err)
			file, err := key.KeyFileBytes()
			require.NoError(t, err)
			cfg.Keys.WorkerSigning.SeedPath = filepath.Join(dir, "worker.key")
			cfg.Keys.WorkerSigning.Suite = string(crypto.RecordAlg(suite))
			require.NoError(t, os.WriteFile(cfg.Keys.WorkerSigning.SeedPath, file, 0o600))
			require.NoError(t, cfg.Validate())

			mat, err := LoadMaterials(cfg, testClock(t))
			require.NoError(t, err)
			require.Equal(t, suite, mat.SigningSuite)
			require.Equal(t, key.PublicKeyBytes(), mat.SigningPublicKey)
			sig, err := mat.Store.Sign(mat.SigningKeyID, keys.PurposeSigningAuthority, []byte("frame"))
			require.NoError(t, err)
			require.NoError(t, key.Public().VerifyRecord(crypto.RecordAlg(suite), []byte("frame"), sig))
			mat.Store.Zeroize()

			raw, err := json.Marshal(cfg)
			require.NoError(t, err)
			cfgPath := filepath.Join(dir, "acp-compute.json")
			require.NoError(t, os.WriteFile(cfgPath, raw, 0o600))
			var out bytes.Buffer
			require.NoError(t, runIdentityCmd([]string{"-config", cfgPath}, &out))
			var id workerIdentity
			require.NoError(t, json.Unmarshal(out.Bytes(), &id))
			require.Equal(t, string(suite), id.SigningSignatureSuite)
			pub, err := crypto.ParsePublicKeyFile([]byte(id.SigningPublicKeyPEM))
			require.NoError(t, err)
			require.Equal(t, key.Public(), pub)

			var stdout, stderr bytes.Buffer
			require.NoError(t, runSealKeysCmd([]string{"-config", cfgPath}, &stdout, &stderr))
			sealed, err := os.ReadFile(cfg.Keys.WorkerSigning.SeedPath)
			require.NoError(t, err)
			require.True(t, tee.IsSealedSecret(sealed))
			after, err := LoadMaterials(cfg, testClock(t))
			require.NoError(t, err)
			require.Equal(t, key.PublicKeyBytes(), after.SigningPublicKey)
			after.Store.Zeroize()
		})
	}
	cfg, _ := testKeyDir(t)
	cfg.Keys.WorkerSigning.Suite = "rsa-pss"
	require.ErrorContains(t, cfg.Validate(), "keys.worker_signing.suite")
}
