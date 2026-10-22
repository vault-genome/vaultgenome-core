// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"testing"

	"github.com/stretchr/testify/require"

	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// The table of ADR 0031: what each profile signs with and accepts.
func TestSignaturePolicy_Table(t *testing.T) {
	t.Parallel()
	ed, ec, ml := shared_crypto.SuiteEd25519, shared_crypto.SuiteECDSAP384SHA384, shared_crypto.SuiteMLDSA87
	for _, tc := range []struct {
		profile Profile
		signs   shared_crypto.SignatureSuite
		accepts []shared_crypto.SignatureSuite
	}{
		{ProfileGeneral, ed, []shared_crypto.SignatureSuite{ed, ec, ml}},
		{ProfileFIPS, ed, []shared_crypto.SignatureSuite{ed, ec}},
		{ProfileCNSA, ec, []shared_crypto.SignatureSuite{ec, ml}},
	} {
		require.Equal(t, tc.signs, tc.profile.SignsWith(), string(tc.profile))
		require.Equal(t, tc.accepts, tc.profile.AcceptsSignatures(), string(tc.profile))
		pol, err := NewSignaturePolicy(tc.profile, "")
		require.NoError(t, err)
		require.Equal(t, tc.profile, pol.Profile())
		require.Equal(t, tc.signs, pol.SignsWith())
		require.Equal(t, tc.accepts, pol.Accepts())
		require.False(t, pol.IsZero())
		for _, s := range shared_crypto.Suites() {
			want := false
			for _, a := range tc.accepts {
				want = want || a == s
			}
			require.Equal(t, want, pol.Allows(s), "%s allows %s", tc.profile, s)
			err := pol.CheckAcceptedKey("worker registry entry kid=w", s)
			if want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
				require.Contains(t, err.Error(), "does not accept")
			}
		}
	}
	require.Empty(t, Profile("x").SignsWith())
	require.True(t, SignaturePolicy{}.IsZero())
}

// crypto.signature_suite picks within the profile's list and never widens it.
func TestSignaturePolicy_PickWithinTheProfile(t *testing.T) {
	t.Parallel()
	// The X9 bank: fips with ecdsa-p384-sha384.
	pol, err := NewSignaturePolicyFromNames("fips", "ecdsa-p384-sha384")
	require.NoError(t, err)
	require.Equal(t, shared_crypto.SuiteECDSAP384SHA384, pol.SignsWith())
	require.Equal(t, []string{"ed25519", "ecdsa-p384-sha384"}, pol.AcceptIDs())
	require.NoError(t, pol.CheckSigningKey("keys.authority_signing", shared_crypto.SuiteECDSAP384SHA384))
	err = pol.CheckSigningKey("keys.authority_signing", shared_crypto.SuiteEd25519)
	require.Error(t, err)
	require.Contains(t, err.Error(), "keys.authority_signing is a ed25519 key, but the fips profile signs with ecdsa-p384-sha384")

	// cnsa may pick ml-dsa-87; fips may not; nobody picks an unknown suite.
	pol, err = NewSignaturePolicyFromNames("cnsa", "ml-dsa-87")
	require.NoError(t, err)
	require.Equal(t, shared_crypto.SuiteMLDSA87, pol.SignsWith())
	_, err = NewSignaturePolicyFromNames("fips", "ml-dsa-87")
	require.Error(t, err)
	require.Contains(t, err.Error(), "which the fips profile does not accept")
	_, err = NewSignaturePolicyFromNames("cnsa", "ed25519")
	require.Error(t, err)
	_, err = NewSignaturePolicyFromNames("general", "rsa-pss")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown suite")
	_, err = NewSignaturePolicyFromNames("quantum", "")
	require.Error(t, err)

	// The default: the default profile's own suite.
	def := DefaultSignaturePolicy()
	require.False(t, def.IsZero())
	require.Equal(t, shared_crypto.SuiteEd25519, def.SignsWith())
}
