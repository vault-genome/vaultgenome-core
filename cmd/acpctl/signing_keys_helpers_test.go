// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
)

// ed25519KeyFromSeed is the Ed25519 key of a 32-byte seed, as the
// commands read a key file under the default suite.
func ed25519KeyFromSeed(t *testing.T, seed []byte) *crypto.SigningKey {
	t.Helper()
	key, err := crypto.SigningKeyFromSeed(crypto.SuiteEd25519, seed)
	require.NoError(t, err)
	return key
}
