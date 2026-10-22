// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"crypto/fips140"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// TestInMemoryStore_SignsUnderEverySuite registers a key of each suite,
// signs, resolves and verifies, and checks what a record carries as alg.
// Under the FIPS module v1.0.0 ml-dsa-87 is refused with the module's
// reason — availability is reported, never assumed.
func TestInMemoryStore_SignsUnderEverySuite(t *testing.T) {
	t.Parallel()
	msg := []byte("a verdict")
	for _, suite := range crypto.Suites() {
		suite := suite
		t.Run(string(suite), func(t *testing.T) {
			t.Parallel()
			st := NewInMemoryStore(nil)
			kid := ids.KeyID("k-" + string(suite))
			vk, err := st.GenerateSigningSuite(kid, PurposeSigningAuthority, suite)
			if suite == crypto.SuiteMLDSA87 && fips140.Enabled() && suite.Available() != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), "unavailable in FIPS 140-3 Go Cryptographic Module")
				_, err = st.Suite(kid)
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, suite, vk.Suite)
			require.Len(t, vk.PublicKey, suite.PublicKeySize())

			got, err := st.Suite(kid)
			require.NoError(t, err)
			require.Equal(t, suite, got)
			alg, err := RecordAlg(st, kid)
			require.NoError(t, err)
			require.Equal(t, crypto.RecordAlg(suite), alg)
			if suite == crypto.SuiteEd25519 {
				require.Empty(t, alg, "an ed25519 record carries no alg: the bytes every earlier reader verifies")
			} else {
				require.Equal(t, suite, alg)
			}

			sig, err := st.Sign(kid, PurposeSigningAuthority, msg)
			require.NoError(t, err)
			require.Len(t, sig, suite.SignatureSize())
			rvk, err := st.Resolve(kid, PurposeSigningAuthority)
			require.NoError(t, err)
			require.NoError(t, rvk.Verify(msg, sig))
			require.NoError(t, rvk.VerifyRecord(alg, msg, sig))

			// The record's alg must be the key's suite: a record cannot
			// choose an algorithm the key was not made for.
			for _, other := range crypto.Suites() {
				if other == suite {
					continue
				}
				err := rvk.VerifyRecord(crypto.RecordAlg(other), msg, sig)
				require.Error(t, err)
				require.Equal(t, shared_errors.CodeSignatureInvalid, shared_errors.CodeOf(err))
			}
			err = rvk.VerifyRecord("no-such-suite", msg, sig)
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

			// Purpose binding holds for every suite.
			_, err = st.Sign(kid, PurposeSigningAudit, msg)
			require.Error(t, err)

			// Zeroize: the key is gone.
			st.Zeroize()
			_, err = st.Sign(kid, PurposeSigningAuthority, msg)
			require.Error(t, err)
			_, err = st.Suite(kid)
			require.Error(t, err)
		})
	}
}

func TestInMemoryStore_RegisterSigningKey_Refusals(t *testing.T) {
	t.Parallel()
	st := NewInMemoryStore(nil)
	_, err := st.RegisterSigningKey(ids.KeyID("k"), PurposeSigningAuthority, nil)
	require.Error(t, err)
	_, err = st.RegisterSigningKey(ids.KeyID("k"), PurposeSigningAuthority, &crypto.SigningKey{})
	require.Error(t, err)
	key, err := crypto.GenerateSigningKey(crypto.SuiteECDSAP384SHA384, nil)
	require.NoError(t, err)
	_, err = st.RegisterSigningKey(ids.KeyID(""), PurposeSigningAuthority, key)
	require.Error(t, err)
	_, err = st.RegisterSigningKey(ids.KeyID("k"), PurposeSealing, key)
	require.Error(t, err)
	_, err = st.RegisterSigningKey(ids.KeyID("k"), PurposeSigningAuthority, key)
	require.NoError(t, err)
	_, err = st.RegisterSigningKey(ids.KeyID("k"), PurposeSigningAuthority, key)
	require.Error(t, err, "no silent overwrite of a registered kid")
	_, err = st.GenerateSigningSuite(ids.KeyID("k2"), PurposeSigningAuthority, "rsa-pss")
	require.Error(t, err)

	// A verifying key without a suite verifies nothing.
	bare := VerifyingKey{KeyID: "k", Purpose: PurposeSigningAuthority, PublicKey: key.PublicKeyBytes()}
	require.Error(t, bare.Verify([]byte("m"), make([]byte, 96)))
	require.Error(t, bare.VerifyRecord("", []byte("m"), make([]byte, 64)))
}

func TestInMemoryStore_FromSeedIsEd25519(t *testing.T) {
	t.Parallel()
	st := NewInMemoryStore(nil)
	seed := make([]byte, crypto.Ed25519SeedSize)
	vk, err := st.RegisterSigningFromSeed(ids.KeyID("seeded"), PurposeSigningAudit, seed)
	require.NoError(t, err)
	require.Equal(t, crypto.SuiteEd25519, vk.Suite)
	pub, _, err := crypto.Ed25519FromSeed(seed)
	require.NoError(t, err)
	require.Equal(t, []byte(pub), vk.PublicKey)
	alg, err := RecordAlg(st, ids.KeyID("seeded"))
	require.NoError(t, err)
	require.Empty(t, alg)
}

func TestTenantSigning_FollowsTheMastersSuite(t *testing.T) {
	t.Parallel()
	for _, suite := range []crypto.SignatureSuite{crypto.SuiteEd25519, crypto.SuiteMLDSA87} {
		suite := suite
		t.Run(string(suite), func(t *testing.T) {
			t.Parallel()
			if suite.Available() != nil {
				t.Skipf("%s unavailable on this build: %v", suite, suite.Available())
			}
			st := NewInMemoryStore(nil)
			master := ids.KeyID("master-" + string(suite))
			_, err := st.GenerateSigningSuite(master, PurposeSigningAuthority, suite)
			require.NoError(t, err)
			vk, err := st.DeriveTenantSigning(master, TenantID("acme"), PurposeSigningAuthority)
			require.NoError(t, err)
			require.Equal(t, suite, vk.Suite)
			sig, err := st.Sign(vk.KeyID, PurposeSigningAuthority, []byte("m"))
			require.NoError(t, err)
			require.NoError(t, vk.Verify([]byte("m"), sig))
			// Idempotent.
			again, err := st.EnsureTenantSigning(master, TenantID("acme"), PurposeSigningAuthority)
			require.NoError(t, err)
			require.Equal(t, vk.PublicKey, again.PublicKey)
		})
	}
	t.Run("ecdsa master has no seed form", func(t *testing.T) {
		t.Parallel()
		st := NewInMemoryStore(nil)
		_, err := st.GenerateSigningSuite(ids.KeyID("master-ec"), PurposeSigningAuthority, crypto.SuiteECDSAP384SHA384)
		require.NoError(t, err)
		_, err = st.DeriveTenantSigning(ids.KeyID("master-ec"), TenantID("acme"), PurposeSigningAuthority)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	})
}
