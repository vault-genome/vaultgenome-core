// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// The profiles of ADR 0029: what each writes and accepts.
func TestProfiles_WriteAndAccept(t *testing.T) {
	t.Parallel()
	require.Equal(t, SuiteHPKEX25519, ProfileGeneral.Writes())
	require.Equal(t, AllSuites(), ProfileGeneral.Accepts())
	require.Equal(t, SuiteHPKEP384, ProfileFIPS.Writes())
	require.Equal(t, []Suite{SuiteHPKEP384, SuiteHPKEMLKEM768, SuiteHPKEMLKEM1024P384}, ProfileFIPS.Accepts())
	require.Equal(t, SuiteHPKEMLKEM1024P384, ProfileCNSA.Writes())
	require.Equal(t, []Suite{SuiteHPKEMLKEM1024P384}, ProfileCNSA.Accepts())
	for _, p := range AllProfiles() {
		require.True(t, p.Writes().Known(), p)
		require.Contains(t, p.Accepts(), p.Writes(), "%s writes a suite it accepts", p)
	}
	// Nothing X25519 is accepted under fips or cnsa.
	for _, p := range []Profile{ProfileFIPS, ProfileCNSA} {
		for _, s := range p.Accepts() {
			require.NotEqual(t, SuiteHPKEX25519, s, p)
			require.NotEqual(t, SuiteHPKEXWing, s, p)
		}
	}
	require.Equal(t, Suite(""), Profile("nope").Writes())
	require.Empty(t, Profile("nope").Accepts())
}

func TestParseProfile(t *testing.T) {
	t.Parallel()
	p, err := ParseProfile("")
	require.NoError(t, err)
	require.Equal(t, ProfileGeneral, p)
	for _, name := range []string{"general", "fips", "cnsa"} {
		p, err := ParseProfile(name)
		require.NoError(t, err)
		require.Equal(t, Profile(name), p)
	}
	_, err = ParseProfile("FIPS")
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
	require.ErrorContains(t, err, "unknown crypto profile")
}

// A policy is a profile, possibly narrowed and reordered — never widened.
func TestSuitePolicy(t *testing.T) {
	t.Parallel()
	require.True(t, SuitePolicy{}.IsZero())
	require.False(t, SuitePolicy{}.Allows(SuiteHPKEX25519), "a zero policy allows nothing")
	require.Equal(t, Suite(""), SuitePolicy{}.Writes())

	def := DefaultSuitePolicy()
	require.False(t, def.IsZero())
	require.Equal(t, ProfileGeneral, def.Profile())
	require.Equal(t, AllSuites(), def.Suites())
	require.Equal(t, SuiteHPKEX25519, def.Writes())
	require.Equal(t, []string{"hpke-x25519-v1", "hpke-p384-v1", "hpke-mlkem768-v1", "hpke-mlkem1024-p384-v1", "hpke-xwing-v1"}, def.SuiteIDs())

	// Narrowing: a subset in the operator's order; the first is written.
	p, err := NewSuitePolicy(ProfileGeneral, []Suite{SuiteHPKEMLKEM768, SuiteHPKEX25519})
	require.NoError(t, err)
	require.Equal(t, SuiteHPKEMLKEM768, p.Writes())
	require.True(t, p.Allows(SuiteHPKEX25519))
	require.False(t, p.Allows(SuiteHPKEP384))

	// Widening is refused: fips cannot be made to accept X25519.
	_, err = NewSuitePolicy(ProfileFIPS, []Suite{SuiteHPKEX25519})
	require.Error(t, err)
	require.ErrorContains(t, err, "does not accept")
	_, err = NewSuitePolicy(ProfileFIPS, []Suite{Suite("hpke-p256-v1")})
	require.ErrorContains(t, err, "unknown suite")
	_, err = NewSuitePolicy(ProfileFIPS, []Suite{SuiteHPKEP384, SuiteHPKEP384})
	require.ErrorContains(t, err, "twice")
	_, err = NewSuitePolicy(Profile("nope"), nil)
	require.ErrorContains(t, err, "unknown crypto profile")

	fips, err := NewSuitePolicy(ProfileFIPS, nil)
	require.NoError(t, err)
	require.Equal(t, SuiteHPKEP384, fips.Writes())
	require.False(t, fips.Allows(SuiteLegacyX25519))
}

// Choose takes the first suite the source offers that the destination's
// policy allows; the source's order decides, nothing below either list is chosen.
func TestSuitePolicy_Choose(t *testing.T) {
	t.Parallel()
	fips, err := NewSuitePolicy(ProfileFIPS, nil)
	require.NoError(t, err)
	general := DefaultSuitePolicy()
	cnsa, err := NewSuitePolicy(ProfileCNSA, nil)
	require.NoError(t, err)

	s, ok := fips.Choose(general.SuiteIDs())
	require.True(t, ok)
	require.Equal(t, SuiteHPKEP384, s, "a general source meets a fips destination on the first suite fips allows")

	s, ok = general.Choose(fips.SuiteIDs())
	require.True(t, ok)
	require.Equal(t, SuiteHPKEP384, s, "a fips source's first preference")

	s, ok = cnsa.Choose(fips.SuiteIDs())
	require.True(t, ok)
	require.Equal(t, SuiteHPKEMLKEM1024P384, s)

	_, ok = cnsa.Choose([]string{"hpke-x25519-v1", "hpke-p384-v1"})
	require.False(t, ok, "nothing the cnsa destination allows")
	_, ok = fips.Choose(nil)
	require.False(t, ok)
	_, ok = fips.Choose([]string{"x25519-kem-v1"})
	require.False(t, ok, "the legacy ECIES is never a choice")
}
