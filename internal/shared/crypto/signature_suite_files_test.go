// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// The file form of a key under each suite loads back under the suite the
// configuration names, and never under another: a 32-byte file is an
// Ed25519 seed or an ML-DSA seed by the suite alone.
func TestSigningKey_FileFormRoundTrips(t *testing.T) {
	t.Parallel()
	for _, suite := range Suites() {
		suite := suite
		t.Run(string(suite), func(t *testing.T) {
			t.Parallel()
			if suite.Available() != nil {
				_, err := LoadSigningKey(suite, make([]byte, 32))
				require.Error(t, err)
				require.Contains(t, err.Error(), "unavailable in FIPS 140-3 Go Cryptographic Module")
				return
			}
			k, err := GenerateSigningKey(suite, nil)
			require.NoError(t, err)
			file, err := k.KeyFileBytes()
			require.NoError(t, err)
			if n := suite.KeyFileSize(); n > 0 {
				require.Len(t, file, n)
			} else {
				require.True(t, strings.HasPrefix(string(file), "-----BEGIN PRIVATE KEY-----"))
			}
			back, err := LoadSigningKey(suite, file)
			require.NoError(t, err)
			require.Equal(t, k.Public(), back.Public())
			require.Equal(t, suite, back.Public().Suite)
			require.Len(t, back.Public().Bytes, suite.PublicKeySize())

			// The public key file forms: PEM names the suite; raw is ed25519 only.
			pemBytes, err := k.Public().PEM()
			require.NoError(t, err)
			got, err := ParsePublicKeyFile(pemBytes)
			require.NoError(t, err)
			require.Equal(t, k.Public(), got)
			raw, err := ParsePublicKeyFile(k.Public().Bytes)
			if suite == SuiteEd25519 {
				require.NoError(t, err)
				require.Equal(t, k.Public(), raw)
			} else {
				require.Error(t, err)
			}

			// A record signed under the key verifies with the alg it carries.
			msg := []byte("an operator's list")
			sig, err := k.Sign(msg)
			require.NoError(t, err)
			require.NoError(t, k.Public().Verify(msg, sig))
			require.NoError(t, k.Public().VerifyRecord(RecordAlg(suite), msg, sig))
			for _, other := range Suites() {
				if other == suite {
					continue
				}
				err := k.Public().VerifyRecord(RecordAlg(other), msg, sig)
				require.Error(t, err)
				require.Equal(t, shared_errors.CodeSignatureInvalid, shared_errors.CodeOf(err))
				// A key file read under another suite: the seed-form suites
				// share the 32-byte form, so the suite alone decides what the
				// file is — and the key differs; the PEM form of ECDSA is
				// refused outright, as a seed is for ECDSA.
				if other.Available() != nil {
					continue
				}
				wrong, err := LoadSigningKey(other, file)
				if suite.KeyFileSize() > 0 && other.KeyFileSize() > 0 {
					require.NoError(t, err)
					require.NotEqual(t, k.Public().Bytes, wrong.Public().Bytes)
					require.Equal(t, other, wrong.Public().Suite)
				} else {
					require.Error(t, err)
				}
			}
		})
	}
	_, err := ParsePublicKeyFile([]byte("31 bytes of nothing in particular"))
	require.Error(t, err)
	require.Error(t, SuitePublicKey{}.Verify([]byte("m"), make([]byte, 64)))
	_, err = LoadSigningKey("rsa-pss", nil)
	require.Error(t, err)
}

func TestSuiteOrDefault(t *testing.T) {
	t.Parallel()
	s, err := SuiteOrDefault("")
	require.NoError(t, err)
	require.Equal(t, SuiteEd25519, s)
	s, err = SuiteOrDefault("ml-dsa-87")
	require.NoError(t, err)
	require.Equal(t, SuiteMLDSA87, s)
	_, err = SuiteOrDefault("ED25519")
	require.Error(t, err, "suite ids are exact")
}
