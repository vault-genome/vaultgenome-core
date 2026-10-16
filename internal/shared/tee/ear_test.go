// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee/ratstest"
)

func testEARClaims(nonce []byte) map[string]any {
	return map[string]any{
		"eat_profile": EARProfile, "iat": 1760580000,
		"eat_nonce":       base64.RawURLEncoding.EncodeToString(nonce),
		"ear.verifier-id": map[string]string{"developer": "ratstest", "build": "1"},
		"submods": map[string]any{"SIM": map[string]any{
			"ear.status": "affirming", "ear.appraisal-policy-id": "policy:sim",
			"ear.trustworthiness-vector":      map[string]int{"hardware": 2, "runtime-opaque": 2},
			"ear.veraison.annotated-evidence": map[string]any{"size": 123},
		}},
	}
}

func TestParseEARPublicKey_PEMAndJWK(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	fromPEM, err := ParseEARPublicKey(pemBytes)
	require.NoError(t, err)
	require.True(t, fromPEM.Equal(&key.PublicKey))

	srv := &ratstest.Server{Key: key}
	fromJWK, err := ParseEARPublicKey(srv.PublicJWK())
	require.NoError(t, err)
	require.True(t, fromJWK.Equal(&key.PublicKey))

	// What is neither is refused, as is a curve ES256 does not use.
	for _, bad := range []string{"", "not a key", `{"kty":"RSA"}`, `{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}`, `{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`} {
		_, err := ParseEARPublicKey([]byte(bad))
		require.Error(t, err, bad)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	_, err = ParseEARPublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der384}))
	require.ErrorContains(t, err, "P-256")
}

func TestVerifyEAR_ReadsWhatTheVerifierSigned(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	nonce := []byte("a thirty-two byte challenger nonce!")
	token, err := ratstest.SignEAR(key, testEARClaims(nonce))
	require.NoError(t, err)
	ear, err := VerifyEAR(token, &key.PublicKey)
	require.NoError(t, err)
	require.Equal(t, token, ear.Raw)
	require.Equal(t, EARProfile, ear.Profile)
	require.Equal(t, int64(1760580000), ear.IssuedAt)
	require.Equal(t, nonce, ear.Nonce)
	require.Equal(t, EARVerifierID{Developer: "ratstest", Build: "1"}, ear.VerifierID)
	sub, ok := ear.Submods["SIM"]
	require.True(t, ok)
	require.Equal(t, EARStatusAffirming, sub.Status)
	require.Equal(t, "policy:sim", sub.PolicyID)
	require.Equal(t, map[string]int{"hardware": 2, "runtime-opaque": 2}, sub.TrustVector)
	require.JSONEq(t, `{"size":123}`, string(sub.AnnotatedEvidence))
}

func TestVerifyEAR_RefusesWhatIsNotTheVerifiersEAR(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	nonce := []byte("a thirty-two byte challenger nonce!")
	good, err := ratstest.SignEAR(key, testEARClaims(nonce))
	require.NoError(t, err)
	parts := strings.Split(good, ".")
	enc := base64.RawURLEncoding

	// Another key.
	_, err = VerifyEAR(good, &other.PublicKey)
	require.ErrorContains(t, err, "does not verify")
	// A tampered payload under the same signature.
	claims := testEARClaims(nonce)
	claims["submods"].(map[string]any)["SIM"].(map[string]any)["ear.status"] = "contraindicated"
	p, _ := json.Marshal(claims)
	_, err = VerifyEAR(parts[0]+"."+enc.EncodeToString(p)+"."+parts[2], &key.PublicKey)
	require.ErrorContains(t, err, "does not verify")
	// alg none and an HMAC alg are refused by the header alone.
	for _, alg := range []string{"none", "HS256", "ES384"} {
		h, _ := json.Marshal(map[string]string{"alg": alg})
		_, err = VerifyEAR(enc.EncodeToString(h)+"."+parts[1]+"."+parts[2], &key.PublicKey)
		require.ErrorContains(t, err, "ES256 only", alg)
	}
	// Not a JWS at all.
	for _, bad := range []string{"", "a.b", good + ".d", "x.y.z"} {
		_, err = VerifyEAR(bad, &key.PublicKey)
		require.Error(t, err, bad)
	}
	// Claims a verifier signed that are not an EAR.
	sign := func(mutate func(map[string]any)) string {
		c := testEARClaims(nonce)
		mutate(c)
		tok, err := ratstest.SignEAR(key, c)
		require.NoError(t, err)
		return tok
	}
	cases := map[string]func(map[string]any){
		"eat_profile":       func(c map[string]any) { c["eat_profile"] = "tag:example.com,2026:other" },
		"iat missing":       func(c map[string]any) { delete(c, "iat") },
		"eat_nonce missing": func(c map[string]any) { delete(c, "eat_nonce") },
		"no submods":        func(c map[string]any) { c["submods"] = map[string]any{} },
		"not a trust tier": func(c map[string]any) {
			c["submods"].(map[string]any)["SIM"].(map[string]any)["ear.status"] = "excellent"
		},
		"submod not an object": func(c map[string]any) { c["submods"] = map[string]any{"SIM": "affirming"} },
	}
	for name, mutate := range cases {
		_, err = VerifyEAR(sign(mutate), &key.PublicKey)
		require.Error(t, err, name)
		require.Equal(t, shared_errors.CodeAttestationDenied, shared_errors.CodeOf(err), name)
	}
	// No key: nothing can be verified.
	_, err = VerifyEAR(good, nil)
	require.Error(t, err)
}
