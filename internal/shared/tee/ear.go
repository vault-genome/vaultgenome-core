// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The EAT Attestation Result (EAR, draft-ietf-rats-ear) a RATS Verifier
// returns, read with the standard library: a compact JWS signed ES256
// under the Verifier's key, its claims the profile's — the nonce the
// session was opened with, the submodules' status and trustworthiness
// vector (AR4SI), the policy that appraised, the Verifier's identity.
// Nothing here appraises; this file verifies the signature and reads
// the claims, and refuses what is not an EAR.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// EARProfile is the EAT profile of an EAR as Veraison's library writes
// it (github.com/veraison/ear, EatProfile).
const EARProfile = "tag:github.com,2023:veraison/ear"

// EAR statuses (AR4SI trust tiers as the EAR names them).
const (
	EARStatusNone            = "none"
	EARStatusAffirming       = "affirming"
	EARStatusWarning         = "warning"
	EARStatusContraindicated = "contraindicated"
)

// EAR is a verified attestation result: the claims the Verifier signed.
type EAR struct {
	// Raw is the compact JWS as received, for the audit record.
	Raw string
	// Profile is eat_profile.
	Profile string
	// IssuedAt is iat, seconds since the epoch.
	IssuedAt int64
	// Nonce is eat_nonce decoded.
	Nonce []byte
	// VerifierID is ear.verifier-id: who the Verifier says it is.
	VerifierID EARVerifierID
	// Submods are the appraisals, one per attester component, by name.
	Submods map[string]EARAppraisal
}

// EARVerifierID is ear.verifier-id.
type EARVerifierID struct {
	Developer string `json:"developer"`
	Build     string `json:"build"`
}

// EARAppraisal is one submodule's appraisal.
type EARAppraisal struct {
	// Status is ear.status: none, affirming, warning or contraindicated.
	Status string
	// TrustVector is ear.trustworthiness-vector: AR4SI claim values by
	// name (instance-identity, configuration, executables, file-system,
	// hardware, runtime-opaque, storage-opaque, sourced-data).
	TrustVector map[string]int
	// PolicyID is ear.appraisal-policy-id.
	PolicyID string
	// AnnotatedEvidence is ear.veraison.annotated-evidence as sent, for
	// the record; its shape is the scheme's.
	AnnotatedEvidence json.RawMessage
}

func earErr(msg string, cause error) error {
	return shared_errors.Integrity(shared_errors.CodeAttestationDenied, "tee: EAR: "+msg, cause)
}

// ParseEARPublicKey reads the Verifier's EAR signing key: a PEM "PUBLIC
// KEY" (PKIX) block, or a JSON Web Key as Veraison publishes it
// (`ear-verification-key`: kty EC, crv P-256, x, y). ES256 means P-256.
func ParseEARPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "tee: EAR public key: PEM is not a PUBLIC KEY block", nil)
		}
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "tee: EAR public key: not PKIX", err)
		}
		pub, ok := k.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "tee: EAR public key: ES256 needs an EC P-256 key", nil)
		}
		return pub, nil
	}
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal([]byte(trimmed), &jwk); err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "tee: EAR public key: neither PEM nor a JWK", err)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("tee: EAR public key: JWK kty %q crv %q, ES256 needs EC P-256", jwk.Kty, jwk.Crv), nil)
	}
	x, errX := base64.RawURLEncoding.DecodeString(strings.TrimRight(jwk.X, "="))
	y, errY := base64.RawURLEncoding.DecodeString(strings.TrimRight(jwk.Y, "="))
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "tee: EAR public key: JWK x and y must be 32 bytes base64url", nil)
	}
	// The uncompressed point 0x04 || x || y; ParseUncompressedPublicKey
	// refuses a point that is not on the curve.
	point := append(append([]byte{4}, x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "tee: EAR public key: the JWK point is not on P-256", err)
	}
	return pub, nil
}

// VerifyEAR verifies the compact JWS under key (ES256 only) and reads
// the claims. It does not judge them: the caller holds the policy.
func VerifyEAR(token string, key *ecdsa.PublicKey) (*EAR, error) {
	if key == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "tee: EAR: no verifier key", nil)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, earErr("not a compact JWS (three parts)", nil)
	}
	enc := base64.RawURLEncoding
	headerBytes, err := enc.DecodeString(parts[0])
	if err != nil {
		return nil, earErr("header is not base64url", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, earErr("header is not JSON", err)
	}
	if header.Alg != "ES256" {
		return nil, earErr(fmt.Sprintf("alg %q, this verifier accepts ES256 only", header.Alg), nil)
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, earErr("signature is not 64 bytes base64url (ES256 r||s)", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return nil, earErr("signature does not verify under the Verifier's key", nil)
	}
	payload, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, earErr("payload is not base64url", err)
	}
	var claims struct {
		Profile    string                     `json:"eat_profile"`
		IssuedAt   *int64                     `json:"iat"`
		Nonce      string                     `json:"eat_nonce"`
		VerifierID EARVerifierID              `json:"ear.verifier-id"`
		Submods    map[string]json.RawMessage `json:"submods"`
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		return nil, earErr("claims are not JSON", err)
	}
	if claims.Profile != EARProfile {
		return nil, earErr(fmt.Sprintf("eat_profile %q, want %q", claims.Profile, EARProfile), nil)
	}
	if claims.IssuedAt == nil {
		return nil, earErr("iat missing", nil)
	}
	if claims.Nonce == "" {
		return nil, earErr("eat_nonce missing", nil)
	}
	nonce, err := enc.DecodeString(strings.TrimRight(claims.Nonce, "="))
	if err != nil {
		return nil, earErr("eat_nonce is not base64url", err)
	}
	if len(claims.Submods) == 0 {
		return nil, earErr("no submods: nothing was appraised", nil)
	}
	out := &EAR{Raw: token, Profile: claims.Profile, IssuedAt: *claims.IssuedAt, Nonce: nonce, VerifierID: claims.VerifierID, Submods: map[string]EARAppraisal{}}
	for name, raw := range claims.Submods {
		var sub struct {
			Status            string          `json:"ear.status"`
			TrustVector       map[string]int  `json:"ear.trustworthiness-vector"`
			PolicyID          string          `json:"ear.appraisal-policy-id"`
			AnnotatedEvidence json.RawMessage `json:"ear.veraison.annotated-evidence"`
		}
		if err := json.Unmarshal(raw, &sub); err != nil {
			return nil, earErr(fmt.Sprintf("submod %q is not an appraisal", name), err)
		}
		switch sub.Status {
		case EARStatusNone, EARStatusAffirming, EARStatusWarning, EARStatusContraindicated:
		default:
			return nil, earErr(fmt.Sprintf("submod %q: ear.status %q is not a trust tier", name, sub.Status), nil)
		}
		out.Submods[name] = EARAppraisal{Status: sub.Status, TrustVector: sub.TrustVector, PolicyID: sub.PolicyID, AnnotatedEvidence: sub.AnnotatedEvidence}
	}
	return out, nil
}
