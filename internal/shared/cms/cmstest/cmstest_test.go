// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmstest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/cms"
)

// What cmstest writes, the reader opens: the fake KMS speaks the profile.
func TestTheReaderOpensWhatCmstestWrites(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)
	for _, n := range []int{0, 1, 15, 16, 32, 4096} {
		plain := make([]byte, n)
		_, err := rand.Read(plain)
		require.NoError(t, err)
		ber, err := EnvelopedData(&key.PublicKey, plain)
		require.NoError(t, err)
		got, err := cms.Decrypt(ber, key)
		require.NoError(t, err, "%d bytes", n)
		require.True(t, bytes.Equal(plain, got), "%d bytes", n)
	}
	_, err = EnvelopedData(&rsa.PublicKey{N: key.N, E: 1}, []byte("x"))
	require.Error(t, err)
	require.Panics(t, func() { oid(3) })
}
