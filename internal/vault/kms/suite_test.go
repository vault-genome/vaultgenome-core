// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// The table of ADR 0029: every suite is known, carries the HPKE ids the
// registries assign, and generates keys and encapsulations of the sizes
// RFC 9180 §7.1 and draft-ietf-hpke-pq-05 §8 state.
func TestSuites_TableMatchesTheStandards(t *testing.T) {
	t.Parallel()
	want := map[Suite]struct {
		kem, kdf, aead uint16
		pk, enc        int
	}{
		// v2: export-only HPKE (AEAD id 0xFFFF), the module's AES-256-GCM
		SuiteHPKEX25519:        {0x0020, 0x0001, 0xFFFF, 32, 32},
		SuiteHPKEP384:          {0x0011, 0x0002, 0xFFFF, 97, 97},
		SuiteHPKEMLKEM768:      {0x0041, 0x0001, 0xFFFF, 1184, 1088},
		SuiteHPKEMLKEM1024P384: {0x0051, 0x0002, 0xFFFF, 1665, 1665},
		SuiteHPKEXWing:         {0x647a, 0x0001, 0xFFFF, 1216, 1120},
	}
	require.ElementsMatch(t, CurrentSuites(), []Suite{SuiteHPKEX25519, SuiteHPKEP384, SuiteHPKEMLKEM768, SuiteHPKEMLKEM1024P384, SuiteHPKEXWing})
	require.ElementsMatch(t, AllSuites(), append(CurrentSuites(), SuiteHPKEX25519V1, SuiteHPKEP384V1, SuiteHPKEMLKEM768V1, SuiteHPKEMLKEM1024P384V1, SuiteHPKEXWingV1))
	for _, v1 := range []Suite{SuiteHPKEX25519V1, SuiteHPKEP384V1, SuiteHPKEMLKEM768V1, SuiteHPKEMLKEM1024P384V1, SuiteHPKEXWingV1} {
		require.True(t, v1.ReadOnly(), v1)
		_, _, aead := v1.IDs()
		require.Equal(t, uint16(0x0002), aead, "v1 kept the AEAD inside HPKE")
		require.Equal(t, v1.Latest().Family(), v1.Family())
		require.False(t, v1.Latest().ReadOnly())
		require.True(t, v1.SameFamily(v1.Latest()))
	}
	for s, w := range want {
		t.Run(string(s), func(t *testing.T) {
			t.Parallel()
			if !s.Available() {
				t.Skip("unavailable under fips140=only")
			}
			require.True(t, s.Known())
			kem, kdf, aead := s.IDs()
			require.Equal(t, w.kem, kem, "KEM id")
			require.Equal(t, w.kdf, kdf, "KDF id")
			require.Equal(t, w.aead, aead, "AEAD id")
			require.Equal(t, w.pk, s.PublicKeySize())
			require.Equal(t, w.enc, s.EncapsulationSize())
			priv, pub, err := s.GenerateRecipientKey()
			require.NoError(t, err)
			require.Len(t, pub, w.pk, "Npk of a generated key")
			require.NotEmpty(t, priv)
			wrapped, err := s.Wrap(PurposeCrossCloudDEK, []byte("dek"), pub, []byte("aad"))
			require.NoError(t, err)
			require.Len(t, wrapped, w.enc+shared_crypto.GCMNonceSize+len("dek")+aeadTagSize, "enc ‖ nonce ‖ ciphertext ‖ tag")
		})
	}
	require.False(t, SuiteLegacyX25519.Known(), "the ECIES of ADR 0009 is not an HPKE suite")
	require.False(t, Suite("hpke-p256-v1").Known())
	_, err := ParseSuite("x25519-kem-v1")
	require.Error(t, err)
	s, err := ParseSuite("hpke-p384-v2")
	require.NoError(t, err)
	require.Equal(t, SuiteHPKEP384, s)
	v1, err := ParseSuite("hpke-p384-v1")
	require.NoError(t, err, "a v1 suite is still known: what 0.7.0 wrapped opens")
	require.Equal(t, SuiteHPKEP384V1, v1)
	require.Equal(t, SuiteHPKEP384, v1.Latest())
}

// A v1 suite is read-only: Wrap refuses it by name, Unwrap opens what
// 0.7.0 wrapped (the fixtures were written by the 0.7.0 tree at b0ee2a5).
func TestSuite_V1IsReadOnly(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/kms-v1-wraps.json")
	require.NoError(t, err)
	var fx []struct {
		Suite      string `json:"suite"`
		Purpose    string `json:"purpose"`
		AADHex     string `json:"aad_hex"`
		PrivHex    string `json:"recipient_private_hex"`
		PubHex     string `json:"recipient_public_hex"`
		PlainHex   string `json:"plaintext_hex"`
		WrappedHex string `json:"wrapped_hex"`
	}
	require.NoError(t, json.Unmarshal(raw, &fx))
	require.Len(t, fx, 5)
	for _, f := range fx {
		t.Run(f.Suite, func(t *testing.T) {
			t.Parallel()
			s := Suite(f.Suite)
			require.True(t, s.Known())
			require.True(t, s.ReadOnly())
			if !s.Latest().Available() {
				t.Skip("the family is unavailable under fips140=only")
			}
			priv, _ := hex.DecodeString(f.PrivHex)
			pub, _ := hex.DecodeString(f.PubHex)
			aad, _ := hex.DecodeString(f.AADHex)
			plain, _ := hex.DecodeString(f.PlainHex)
			wrapped, _ := hex.DecodeString(f.WrappedHex)
			_, err := s.Wrap(f.Purpose, plain, pub, aad)
			require.ErrorContains(t, err, "read-only since 0.8")
			if shared_crypto.FIPSOnly() {
				_, err := s.Unwrap(f.Purpose, wrapped, priv, aad)
				require.ErrorContains(t, err, "cannot open under fips140=only")
				return
			}
			got, err := s.Unwrap(f.Purpose, wrapped, priv, aad)
			require.NoError(t, err)
			require.Equal(t, plain, got)
			// the same key writes and opens the v2 of its family
			v2 := s.Latest()
			w2, err := v2.Wrap(f.Purpose, plain, pub, aad)
			require.NoError(t, err)
			got2, err := v2.Unwrap(f.Purpose, w2, priv, aad)
			require.NoError(t, err)
			require.Equal(t, plain, got2)
			_, err = s.Unwrap(f.Purpose, w2, priv, aad)
			require.Error(t, err, "a v2 wrap does not open under the v1 suite")
		})
	}
}

// Round trip and the refusals, suite by suite: a wrong key, a tampered
// byte, another AAD, another purpose, and material too short to carry
// an encapsulation all end in an Integrity refusal.
func TestSuite_RoundTripAndRefusals(t *testing.T) {
	t.Parallel()
	for _, s := range CurrentSuites() {
		t.Run(string(s), func(t *testing.T) {
			t.Parallel()
			if !s.Available() {
				t.Skip("unavailable under fips140=only")
			}
			priv, pub, err := s.GenerateRecipientKey()
			require.NoError(t, err)
			dek := []byte("a-32-byte-data-encryption-key!!!")
			aad := []byte("token=abc|kid=1")
			wrapped, err := s.Wrap(PurposeCrossCloudDEK, dek, pub, aad)
			require.NoError(t, err)
			require.False(t, bytes.Contains(wrapped, dek))

			got, err := s.Unwrap(PurposeCrossCloudDEK, wrapped, priv, aad)
			require.NoError(t, err)
			require.Equal(t, dek, got)

			again, err := s.Wrap(PurposeCrossCloudDEK, dek, pub, aad)
			require.NoError(t, err)
			require.NotEqual(t, wrapped, again, "a fresh encapsulation every time")

			otherPriv, _, err := s.GenerateRecipientKey()
			require.NoError(t, err)
			_, err = s.Unwrap(PurposeCrossCloudDEK, wrapped, otherPriv, aad)
			require.Error(t, err, "another recipient's key")
			require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))

			tampered := append([]byte(nil), wrapped...)
			tampered[len(tampered)-1] ^= 0x01
			_, err = s.Unwrap(PurposeCrossCloudDEK, tampered, priv, aad)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity), "a flipped tag byte")

			tampered = append([]byte(nil), wrapped...)
			tampered[0] ^= 0x01
			_, err = s.Unwrap(PurposeCrossCloudDEK, tampered, priv, aad)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity), "a flipped encapsulation byte")

			_, err = s.Unwrap(PurposeCrossCloudDEK, wrapped, priv, []byte("token=abc|kid=2"))
			require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity), "another AAD")

			_, err = s.Unwrap(PurposeEscrowDEK, wrapped, priv, aad)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity), "another purpose")

			_, err = s.Unwrap(PurposeCrossCloudDEK, wrapped[:s.EncapsulationSize()+aeadTagSize-1], priv, aad)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity), "too short")
			require.ErrorContains(t, err, "too short")

			_, err = s.Wrap(PurposeCrossCloudDEK, nil, pub, aad)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural), "nothing to wrap")
			_, err = s.Wrap("", dek, pub, aad)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural), "no purpose")
			_, err = s.Unwrap("", wrapped, priv, aad)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural), "no purpose")
			_, err = s.Unwrap(PurposeCrossCloudDEK, wrapped, priv[:len(priv)-1], aad)
			require.Error(t, err, "a private key of the wrong length")
		})
	}
}

// A ciphertext of one suite never opens under another, whatever the
// key: the suite is in the HPKE info and the sizes differ.
func TestSuite_CrossSuiteConfusionRefused(t *testing.T) {
	t.Parallel()
	var all []Suite
	for _, s := range CurrentSuites() {
		if s.Available() {
			all = append(all, s)
		}
	}
	for _, from := range all {
		_, pub, err := from.GenerateRecipientKey()
		require.NoError(t, err)
		wrapped, err := from.Wrap(PurposeCrossCloudDEK, []byte("dek"), pub, []byte("aad"))
		require.NoError(t, err)
		for _, to := range all {
			if to == from {
				continue
			}
			toPriv, _, err := to.GenerateRecipientKey()
			require.NoError(t, err)
			_, err = to.Unwrap(PurposeCrossCloudDEK, wrapped, toPriv, []byte("aad"))
			require.Error(t, err, "%s material under %s", from, to)
		}
	}
}

// What a suite refuses as a recipient key: the wrong length, bytes that
// are not a key of the KEM, and — for X25519 — a low-order point.
func TestSuite_ValidateRecipientPublicKey(t *testing.T) {
	t.Parallel()
	if !SuiteHPKEX25519.Available() {
		t.Skip("X25519 is unavailable under fips140=only (ADR 0030)")
	}
	for _, s := range AllSuites() {
		t.Run(string(s), func(t *testing.T) {
			t.Parallel()
			_, pub, err := s.GenerateRecipientKey()
			require.NoError(t, err)
			require.NoError(t, s.ValidateRecipientPublicKey(pub))
			require.Error(t, s.ValidateRecipientPublicKey(nil))
			require.Error(t, s.ValidateRecipientPublicKey(pub[:len(pub)-1]))
			require.Error(t, s.ValidateRecipientPublicKey(append(append([]byte(nil), pub...), 0)))
			for _, other := range AllSuites() {
				if other.PublicKeySize() != s.PublicKeySize() {
					_, otherPub, err := other.GenerateRecipientKey()
					require.NoError(t, err)
					require.Error(t, s.ValidateRecipientPublicKey(otherPub), "a %s key is not a %s key", other, s)
				}
			}
		})
	}
	// X25519: the low-order points of RFC 7748 give an all-zero shared secret.
	require.Error(t, SuiteHPKEX25519.ValidateRecipientPublicKey(make([]byte, 32)))
	require.Error(t, SuiteHPKEX25519.ValidateRecipientPublicKey(append([]byte{1}, make([]byte, 31)...)))
	// P-384: 97 bytes that are not a point on the curve.
	notOnCurve := make([]byte, 97)
	notOnCurve[0] = 0x04
	require.Error(t, SuiteHPKEP384.ValidateRecipientPublicKey(notOnCurve))
	// ML-KEM-768: an encapsulation key whose coefficients are not reduced
	// modulo q fails the FIPS 203 encapsulation-key check.
	overflow := bytes.Repeat([]byte{0xff}, 1184)
	require.Error(t, SuiteHPKEMLKEM768.ValidateRecipientPublicKey(overflow))
}

// The v2 challenge commits to the suite, the key and the nonce, each
// behind its length, and differs from the v1 challenge of ADR 0009.
func TestRecipientChallengeV2_BindsSuiteKeyAndNonce(t *testing.T) {
	t.Parallel()
	if !SuiteHPKEX25519.Available() {
		t.Skip("X25519 is unavailable under fips140=only (ADR 0030)")
	}
	_, pub, err := SuiteHPKEX25519.GenerateRecipientKey()
	require.NoError(t, err)
	_, other, err := SuiteHPKEX25519.GenerateRecipientKey()
	require.NoError(t, err)
	nonce := []byte("0123456789abcdef")

	c := RecipientChallengeV2(SuiteHPKEX25519, pub, nonce)
	require.Len(t, c, 64)
	require.Equal(t, c, RecipientChallengeV2(SuiteHPKEX25519, pub, nonce), "deterministic")
	require.NotEqual(t, c, RecipientChallengeV2(SuiteHPKEP384, pub, nonce), "the suite label is committed")
	require.NotEqual(t, c, RecipientChallengeV2(SuiteHPKEX25519, other, nonce), "a substituted key changes it")
	require.NotEqual(t, c, RecipientChallengeV2(SuiteHPKEX25519, pub, []byte("0123456789abcdeX")), "a different nonce changes it")
	require.NotEqual(t, c, RecipientChallenge(pub, nonce), "v1 and v2 never coincide")
	// Length prefixes: moving a byte from the suite into the key is another challenge.
	require.NotEqual(t, c, RecipientChallengeV2(Suite(string(SuiteHPKEX25519)[:len(SuiteHPKEX25519)-1]),
		append([]byte{SuiteHPKEX25519[len(SuiteHPKEX25519)-1]}, pub...), nonce))
}

// The info of a suite and a purpose is unambiguous: every part is
// length-prefixed, so the same bytes cannot be read two ways.
func TestSuiteInfo_LengthPrefixed(t *testing.T) {
	t.Parallel()
	a := suiteInfo(SuiteHPKEX25519, "ab")
	b := suiteInfo(Suite(string(SuiteHPKEX25519)+"a"), "b")
	require.NotEqual(t, a, b)
	require.Equal(t, 4+len(hpkeInfoLabel)+4+len(SuiteHPKEX25519)+4+2, len(a))
}

// A private key names its public half under every suite, and a private
// key of another suite or another length is refused.
func TestSuite_PublicKeyOf(t *testing.T) {
	t.Parallel()
	if !SuiteHPKEX25519.Available() {
		t.Skip("X25519 is unavailable under fips140=only (ADR 0030)")
	}
	for _, s := range AllSuites() {
		t.Run(string(s), func(t *testing.T) {
			t.Parallel()
			priv, pub, err := s.GenerateRecipientKey()
			require.NoError(t, err)
			got, err := s.PublicKeyOf(priv)
			require.NoError(t, err)
			require.Equal(t, pub, got)
			_, err = s.PublicKeyOf(priv[:len(priv)-1])
			require.Error(t, err)
			_, err = s.PublicKeyOf(nil)
			require.Error(t, err)
		})
	}
	_, err := Suite("nope").PublicKeyOf([]byte{1})
	require.Error(t, err)
}
