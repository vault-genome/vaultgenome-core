// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// The destination pins the source authority's key from its PEM, whose
// algorithm names the suite (ADR 0031); the raw form is Ed25519 only.
func TestLoadSourceAuthorityResolver_UnderEverySuite(t *testing.T) {
	t.Parallel()
	for _, suite := range crypto.Suites() {
		suite := suite
		if suite.Available() != nil {
			continue
		}
		t.Run(string(suite), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			key, err := crypto.GenerateSigningKey(suite, nil)
			require.NoError(t, err)
			pemBytes, err := key.Public().PEM()
			require.NoError(t, err)
			path := filepath.Join(dir, "authority.pem")
			require.NoError(t, os.WriteFile(path, pemBytes, 0o644))
			r, err := loadSourceAuthorityResolver(SourceAuthorityConfig{KeyID: "authority-1", PublicKeyPath: path}, kms.DefaultSignaturePolicy(), shared_time.NewSystemClock())
			require.NoError(t, err)
			vk, err := r.Resolve("authority-1", keys.PurposeSigningAuthority)
			require.NoError(t, err)
			require.Equal(t, suite, vk.Suite)
			require.Equal(t, key.PublicKeyBytes(), vk.PublicKey)
			sig, err := key.Sign([]byte("handshake"))
			require.NoError(t, err)
			require.NoError(t, vk.VerifyRecord(crypto.RecordAlg(suite), []byte("handshake"), sig))

			rawPath := filepath.Join(dir, "authority.raw")
			require.NoError(t, os.WriteFile(rawPath, key.PublicKeyBytes(), 0o644))
			_, err = loadSourceAuthorityResolver(SourceAuthorityConfig{KeyID: "authority-1", PublicKeyPath: rawPath}, kms.DefaultSignaturePolicy(), shared_time.NewSystemClock())
			if suite == crypto.SuiteEd25519 {
				require.NoError(t, err, "the raw 32 bytes name Ed25519 without guessing")
			} else {
				require.Error(t, err, "a raw key of another suite is not a form the daemon reads")
			}
		})
	}
}
