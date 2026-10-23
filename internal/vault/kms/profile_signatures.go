// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"fmt"

	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// profileSignatureSuites lists the signature suites each profile accepts
// (ADR 0031), in preference order; the first entry is what the profile
// signs with. general keeps ed25519, what every deployment before ADR
// 0031 signs with, and accepts every suite the build has; fips signs
// with ed25519 and accepts the two suites on the certificate of the Go
// Cryptographic Module v1.0.0; cnsa signs with ecdsa-p384-sha384, the
// transition suite of CNSA 2.0, and accepts ml-dsa-87, its destination.
var profileSignatureSuites = map[Profile][]shared_crypto.SignatureSuite{
	ProfileGeneral: {shared_crypto.SuiteEd25519, shared_crypto.SuiteECDSAP384SHA384, shared_crypto.SuiteMLDSA87},
	ProfileFIPS:    {shared_crypto.SuiteEd25519, shared_crypto.SuiteECDSAP384SHA384},
	ProfileCNSA:    {shared_crypto.SuiteECDSAP384SHA384, shared_crypto.SuiteMLDSA87},
}

// AcceptsSignatures returns the signature suites the profile accepts, in
// preference order.
func (p Profile) AcceptsSignatures() []shared_crypto.SignatureSuite {
	return append([]shared_crypto.SignatureSuite(nil), profileSignatureSuites[p]...)
}

// SignsWith returns the signature suite the profile signs with.
func (p Profile) SignsWith() shared_crypto.SignatureSuite {
	if s := profileSignatureSuites[p]; len(s) > 0 {
		return s[0]
	}
	return ""
}

// SignaturePolicy is a profile as a deployment applies it to signatures
// (ADR 0031): the suite the daemon signs with and the suites it accepts.
// A configuration may pick the signing suite from the profile's list
// (crypto.signature_suite); it may not sign with, or accept, a suite
// outside it.
type SignaturePolicy struct {
	profile Profile
	signs   shared_crypto.SignatureSuite
	accepts []shared_crypto.SignatureSuite
}

// NewSignaturePolicy makes the signature policy of profile; signs, when
// not empty, picks the signing suite from the profile's list.
func NewSignaturePolicy(profile Profile, signs shared_crypto.SignatureSuite) (SignaturePolicy, error) {
	accepted, ok := profileSignatureSuites[profile]
	if !ok {
		return SignaturePolicy{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms: unknown crypto profile %q", string(profile)), nil)
	}
	pick := accepted[0]
	if signs != "" {
		if !signs.Valid() {
			return SignaturePolicy{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("kms: crypto.signature_suite names unknown suite %q", string(signs)), nil)
		}
		if !containsSignature(accepted, signs) {
			return SignaturePolicy{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("kms: crypto.signature_suite names %q, which the %s profile does not accept (it accepts %v)", signs, profile, accepted), nil)
		}
		pick = signs
	}
	return SignaturePolicy{profile: profile, signs: pick, accepts: append([]shared_crypto.SignatureSuite(nil), accepted...)}, nil
}

// NewSignaturePolicyFromNames builds the policy from a configuration's
// profile name (the empty string is the default profile, as ParseProfile
// reads it) and its crypto.signature_suite (empty: the profile's own).
func NewSignaturePolicyFromNames(profile, signs string) (SignaturePolicy, error) {
	p, err := ParseProfile(profile)
	if err != nil {
		return SignaturePolicy{}, err
	}
	return NewSignaturePolicy(p, shared_crypto.SignatureSuite(signs))
}

// DefaultSignaturePolicy is the policy of the default profile.
func DefaultSignaturePolicy() SignaturePolicy {
	p, _ := ParseProfile("")
	pol, _ := NewSignaturePolicy(p, "")
	return pol
}

// IsZero reports whether the policy is unset.
func (p SignaturePolicy) IsZero() bool { return p.profile == "" }

// Profile is the profile the policy comes from.
func (p SignaturePolicy) Profile() Profile { return p.profile }

// SignsWith is the suite the daemon signs with: the profile's, or the
// configuration's pick within the profile's list.
func (p SignaturePolicy) SignsWith() shared_crypto.SignatureSuite { return p.signs }

// Accepts returns the suites the daemon accepts a signature under, in
// preference order.
func (p SignaturePolicy) Accepts() []shared_crypto.SignatureSuite {
	return append([]shared_crypto.SignatureSuite(nil), p.accepts...)
}

// AcceptIDs is Accepts as strings, for identity output.
func (p SignaturePolicy) AcceptIDs() []string {
	out := make([]string, 0, len(p.accepts))
	for _, s := range p.accepts {
		out = append(out, string(s))
	}
	return out
}

// Allows reports whether the policy accepts signatures under s.
func (p SignaturePolicy) Allows(s shared_crypto.SignatureSuite) bool {
	return containsSignature(p.accepts, s)
}

// CheckSigningKey refuses a signing key of a suite other than the one
// the policy signs with — the key material and the configuration's
// intent must agree, so a daemon never signs under a suite its profile
// did not name. field names the key's configuration section.
func (p SignaturePolicy) CheckSigningKey(field string, suite shared_crypto.SignatureSuite) error {
	if suite == p.signs {
		return nil
	}
	return shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
		fmt.Sprintf("kms: %s is a %s key, but the %s profile signs with %s (crypto.signature_suite picks within %v)", field, suite, p.profile, p.signs, p.accepts), nil)
}

// CheckAcceptedKey refuses a pinned verifying key of a suite the policy
// does not accept — a record signed under it would be refused, so the
// key is refused where it is pinned, with the reason. what names the key
// ("worker registry entry kid=…", "operator key").
func (p SignaturePolicy) CheckAcceptedKey(what string, suite shared_crypto.SignatureSuite) error {
	if p.Allows(suite) {
		return nil
	}
	return shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
		fmt.Sprintf("kms: %s is a %s key, which the %s profile does not accept (it accepts %v)", what, suite, p.profile, p.accepts), nil)
}

func containsSignature(list []shared_crypto.SignatureSuite, s shared_crypto.SignatureSuite) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
