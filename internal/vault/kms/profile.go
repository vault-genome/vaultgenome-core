// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"fmt"
	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Profile is the cryptographic profile of a deployment (ADR 0029): it
// names the suite a daemon writes and the suites it accepts.
type Profile string

const (
	// ProfileGeneral is the default: X25519 written, every suite of the
	// build accepted.
	ProfileGeneral Profile = "general"
	// ProfileFIPS writes P-384 and accepts only suites whose primitives
	// the Go Cryptographic Module (CMVP #5247) lists as approved: P-384,
	// ML-KEM-768, and the MLKEM1024-P384 hybrid.
	ProfileFIPS Profile = "fips"
	// ProfileCNSA writes and accepts the MLKEM1024-P384 hybrid only
	// (CNSA 2.0: ML-KEM-1024 with P-384 for the transition).
	ProfileCNSA Profile = "cnsa"
)

// profileSuites lists what each profile accepts, in preference order;
// the first entry is what the profile writes.
var profileSuites = map[Profile][]Suite{
	ProfileGeneral: {SuiteHPKEX25519, SuiteHPKEP384, SuiteHPKEMLKEM768, SuiteHPKEMLKEM1024P384, SuiteHPKEXWing},
	ProfileFIPS:    {SuiteHPKEP384, SuiteHPKEMLKEM768, SuiteHPKEMLKEM1024P384},
	ProfileCNSA:    {SuiteHPKEMLKEM1024P384},
}

// AllProfiles returns the profiles in a fixed order.
func AllProfiles() []Profile { return []Profile{ProfileGeneral, ProfileFIPS, ProfileCNSA} }

// ParseProfile accepts a profile name from a configuration; the empty
// string is the general profile.
func ParseProfile(name string) (Profile, error) {
	if name == "" {
		// The default is general; under fips140=only general cannot keep
		// its promise (its first suite is X25519), so the default there is
		// fips — a configuration that names general is refused below, so
		// an operator who wrote it hears why (ADR 0030).
		if shared_crypto.FIPSOnly() {
			return ProfileFIPS, nil
		}
		return ProfileGeneral, nil
	}
	p := Profile(name)
	if _, ok := profileSuites[p]; !ok {
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms: unknown crypto profile %q (known: %v)", name, AllProfiles()), nil)
	}
	return p, nil
}

// Accepts returns the suites the profile accepts, in preference order.
func (p Profile) Accepts() []Suite { return append([]Suite(nil), profileSuites[p]...) }

// Writes returns the suite the profile encapsulates under.
func (p Profile) Writes() Suite {
	if s := profileSuites[p]; len(s) > 0 {
		return s[0]
	}
	return ""
}

// SuitePolicy is a profile as a deployment applies it: the suites it
// accepts, in preference order, the first being what it writes. A
// configuration may narrow a profile's list and reorder it; it may not
// widen it.
type SuitePolicy struct {
	profile Profile
	suites  []Suite
}

// NewSuitePolicy makes the policy of profile, narrowed to the suites
// named (in that order) when any are; every named suite must be one the
// profile accepts, and none may repeat.
func NewSuitePolicy(profile Profile, narrow []Suite) (SuitePolicy, error) {
	accepted, ok := profileSuites[profile]
	if !ok {
		return SuitePolicy{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms: unknown crypto profile %q", string(profile)), nil)
	}
	if len(narrow) == 0 {
		return SuitePolicy{profile: profile, suites: append([]Suite(nil), accepted...)}, nil
	}
	seen := map[Suite]bool{}
	out := make([]Suite, 0, len(narrow))
	for _, s := range narrow {
		if !s.Known() {
			return SuitePolicy{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("kms: kem_suites names unknown suite %q", string(s)), nil)
		}
		if !contains(accepted, s) {
			return SuitePolicy{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("kms: kem_suites names %q, which the %s profile does not accept (it accepts %v)", s, profile, accepted), nil)
		}
		if seen[s] {
			return SuitePolicy{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("kms: kem_suites names %q twice", s), nil)
		}
		seen[s] = true
		out = append(out, s)
	}
	return SuitePolicy{profile: profile, suites: out}, nil
}

// DefaultSuitePolicy is the general profile, unnarrowed.
// DefaultSuitePolicy is the policy of the default profile — general, or
// fips under fips140=only (ParseProfile of the empty name; ADR 0030) —
// what a zero configuration gets.
func DefaultSuitePolicy() SuitePolicy {
	p, _ := ParseProfile("")
	pol, _ := NewSuitePolicy(p, nil)
	return pol
}

// IsZero reports whether p was never set; a zero policy allows nothing.
func (p SuitePolicy) IsZero() bool { return p.profile == "" }

// Profile returns the profile the policy was made from.
func (p SuitePolicy) Profile() Profile { return p.profile }

// Suites returns what the policy accepts, in preference order.
func (p SuitePolicy) Suites() []Suite { return append([]Suite(nil), p.suites...) }

// SuiteIDs returns Suites as strings, for a wire field.
func (p SuitePolicy) SuiteIDs() []string {
	out := make([]string, 0, len(p.suites))
	for _, s := range p.suites {
		out = append(out, string(s))
	}
	return out
}

// Writes returns the suite the policy encapsulates under: the first it accepts.
func (p SuitePolicy) Writes() Suite {
	if len(p.suites) == 0 {
		return ""
	}
	return p.suites[0]
}

// Allows reports whether the policy accepts s.
func (p SuitePolicy) Allows(s Suite) bool { return contains(p.suites, s) }

// Choose picks, from the suites a source offers in its order of
// preference, the first this policy accepts. The source's order wins so
// that the two sides agree on the same suite without a second round; no
// suite below either side's list is ever chosen. What is returned is the
// policy's own entry, not the offered string.
func (p SuitePolicy) Choose(offered []string) (Suite, bool) {
	for _, id := range offered {
		for _, s := range p.suites {
			if string(s) == id {
				return s, true
			}
		}
	}
	return "", false
}

func contains(list []Suite, s Suite) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// NewSuitePolicyFromNames makes a policy from a configuration's strings:
// the profile name (empty is general) and the optional narrowing list.
// PolicyForThisProcess is the general profile's policy, or the fips
// profile's where this process runs under fips140=only (ADR 0030): what a
// caller uses when it needs a policy this process can honour and has no
// configuration to say which — tools, demonstrations, tests. A deployment
// names its profile in its configuration instead.
func PolicyForThisProcess() SuitePolicy { return DefaultSuitePolicy() }

func NewSuitePolicyFromNames(profile string, suites []string) (SuitePolicy, error) {
	p, err := ParseProfile(profile)
	if err != nil {
		return SuitePolicy{}, err
	}
	// Under fips140=only the module refuses X25519, so the general profile
	// — which writes hpke-x25519-v1 first — cannot keep its own promise;
	// the operator names fips or cnsa instead (ADR 0030).
	if p == ProfileGeneral && shared_crypto.FIPSOnly() {
		return SuitePolicy{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms: crypto.profile general offers %s, which this process cannot make under fips140=only; name fips or cnsa", ProfileGeneral.Writes()), nil)
	}
	narrow := make([]Suite, 0, len(suites))
	for _, s := range suites {
		narrow = append(narrow, Suite(s))
	}
	return NewSuitePolicy(p, narrow)
}
