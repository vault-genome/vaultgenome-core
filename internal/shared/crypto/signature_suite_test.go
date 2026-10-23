// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/fips140"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// mldsaOnThisBuild reports whether ml-dsa-87 is available here; under the
// Go Cryptographic Module v1.0.0 it is not, and the suite says so.
func mldsaOnThisBuild(t *testing.T) bool {
	t.Helper()
	err := SuiteMLDSA87.Available()
	if err == nil {
		return true
	}
	require.True(t, fips140.Enabled(), "ml-dsa-87 unavailable outside the FIPS module: %v", err)
	require.Contains(t, err.Error(), "unavailable in FIPS 140-3 Go Cryptographic Module")
	return false
}

func TestSignatureSuite_Registry(t *testing.T) {
	t.Parallel()
	require.Equal(t, []SignatureSuite{"ed25519", "ecdsa-p384-sha384", "ml-dsa-87"}, Suites())
	for _, s := range Suites() {
		got, err := ParseSignatureSuite(string(s))
		require.NoError(t, err)
		require.Equal(t, s, got)
		require.True(t, s.Valid())
	}
	_, err := ParseSignatureSuite("")
	require.Error(t, err)
	_, err = ParseSignatureSuite("rsa-pss")
	require.Error(t, err)
	require.False(t, SignatureSuite("rsa-pss").Valid())

	require.Equal(t, 64, SuiteEd25519.SignatureSize())
	require.Equal(t, 32, SuiteEd25519.PublicKeySize())
	require.Equal(t, 96, SuiteECDSAP384SHA384.SignatureSize())
	require.Equal(t, 97, SuiteECDSAP384SHA384.PublicKeySize())
	require.Equal(t, 4627, SuiteMLDSA87.SignatureSize())
	require.Equal(t, 2592, SuiteMLDSA87.PublicKeySize())
	require.Equal(t, 0, SignatureSuite("x").SignatureSize())

	// A record's alg: absent is ed25519; the other suites are named.
	s, err := RecordSuite("")
	require.NoError(t, err)
	require.Equal(t, SuiteEd25519, s)
	require.Equal(t, SignatureSuite(""), RecordAlg(SuiteEd25519))
	require.Equal(t, SuiteECDSAP384SHA384, RecordAlg(SuiteECDSAP384SHA384))
	_, err = RecordSuite("x")
	require.Error(t, err)
}

func TestSignatureSuite_SignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	msg := []byte("the record under test")
	for _, suite := range Suites() {
		suite := suite
		t.Run(string(suite), func(t *testing.T) {
			t.Parallel()
			if suite == SuiteMLDSA87 && !mldsaOnThisBuild(t) {
				_, err := GenerateSigningKey(suite, nil)
				require.Error(t, err)
				require.Contains(t, err.Error(), "unavailable in FIPS 140-3 Go Cryptographic Module")
				return
			}
			require.NoError(t, suite.Available())
			k, err := GenerateSigningKey(suite, nil)
			require.NoError(t, err)
			require.Equal(t, suite, k.Suite())
			pub := k.PublicKeyBytes()
			require.Len(t, pub, suite.PublicKeySize())
			sig, err := k.Sign(msg)
			require.NoError(t, err)
			require.Len(t, sig, suite.SignatureSize())
			require.NoError(t, VerifySuite(suite, pub, msg, sig))

			// Tampered message, tampered signature, wrong length: Integrity.
			err = VerifySuite(suite, pub, []byte("another record"), sig)
			require.Error(t, err)
			require.Equal(t, shared_errors.CodeSignatureInvalid, shared_errors.CodeOf(err))
			bad := append([]byte(nil), sig...)
			bad[len(bad)/2] ^= 0x01
			err = VerifySuite(suite, pub, msg, bad)
			require.Error(t, err)
			require.Equal(t, shared_errors.CodeSignatureInvalid, shared_errors.CodeOf(err))
			err = VerifySuite(suite, pub, msg, sig[:len(sig)-1])
			require.Error(t, err)
			require.Equal(t, shared_errors.CodeSignatureInvalid, shared_errors.CodeOf(err))
			// A key of another suite does not verify it.
			for _, other := range Suites() {
				if other == suite {
					continue
				}
				require.Error(t, VerifySuite(other, pub, msg, sig))
			}

			// PKIX names the algorithm; the parse returns the suite.
			der, err := PublicKeyPKIX(suite, pub)
			require.NoError(t, err)
			gotSuite, gotPub, err := ParsePublicKeyPKIX(der)
			require.NoError(t, err)
			require.Equal(t, suite, gotSuite)
			require.Equal(t, pub, gotPub)
			pemBytes, err := PublicKeyPEMSuite(suite, pub)
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(string(pemBytes), "-----BEGIN PUBLIC KEY-----"))
			gotSuite, gotPub, err = ParsePublicKeyPEM(pemBytes)
			require.NoError(t, err)
			require.Equal(t, suite, gotSuite)
			require.Equal(t, pub, gotPub)

			// PKCS#8 round-trips the private key with its suite.
			p8, err := k.PKCS8()
			require.NoError(t, err)
			k2, err := ParseSigningKeyPKCS8(p8)
			require.NoError(t, err)
			require.Equal(t, suite, k2.Suite())
			require.Equal(t, pub, k2.PublicKeyBytes())
			sig2, err := k2.Sign(msg)
			require.NoError(t, err)
			require.NoError(t, VerifySuite(suite, pub, msg, sig2))

			// The seed form, where the suite has one.
			if n := suite.SeedSize(); n > 0 {
				seed := k.Seed()
				require.Len(t, seed, n)
				k3, err := SigningKeyFromSeed(suite, seed)
				require.NoError(t, err)
				require.Equal(t, pub, k3.PublicKeyBytes())
				_, err = SigningKeyFromSeed(suite, seed[:n-1])
				require.Error(t, err)
			} else {
				require.Nil(t, k.Seed())
				_, err := SigningKeyFromSeed(suite, make([]byte, 32))
				require.Error(t, err)
			}

			k.Zeroize()
			_, err = k.Sign(msg)
			require.Error(t, err)
		})
	}
}

func TestSignatureSuite_RefusesForeignAlgorithms(t *testing.T) {
	t.Parallel()
	// A P-256 key is not the registered ECDSA suite.
	_, _, err := ParsePublicKeyPKIX(mustPKIXP256(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "P-384")
	_, err = ParseSigningKeyPKCS8(mustPKCS8P256(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "P-384")
	_, _, err = ParsePublicKeyPEM([]byte("not pem"))
	require.Error(t, err)
	require.Error(t, VerifySuite("rsa-pss", nil, nil, nil))
	require.Error(t, VerifySuite(SuiteEd25519, make([]byte, 31), nil, make([]byte, 64)))
	_, err = PublicKeyPKIX(SuiteECDSAP384SHA384, make([]byte, 97)) // not a point on the curve
	require.Error(t, err)
}

func TestSignatureSuite_Ed25519MatchesTheLegacyHelpers(t *testing.T) {
	t.Parallel()
	// The suite's ed25519 is byte-for-byte what Sign/Verify made before
	// ADR 0031: records signed by earlier releases verify unchanged.
	seed := make([]byte, Ed25519SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	pub, priv, err := Ed25519FromSeed(seed)
	require.NoError(t, err)
	k, err := SigningKeyFromSeed(SuiteEd25519, seed)
	require.NoError(t, err)
	require.Equal(t, []byte(pub), k.PublicKeyBytes())
	msg := []byte("a record written by 0.8.0")
	legacy, err := Sign(priv, msg)
	require.NoError(t, err)
	sig, err := k.Sign(msg)
	require.NoError(t, err)
	require.Equal(t, legacy, sig)
	require.NoError(t, Verify(pub, msg, sig))
	require.NoError(t, VerifySuite(SuiteEd25519, k.PublicKeyBytes(), msg, legacy))
	legacyPEM, err := PublicKeyPEM(pub)
	require.NoError(t, err)
	suitePEM, err := PublicKeyPEMSuite(SuiteEd25519, k.PublicKeyBytes())
	require.NoError(t, err)
	require.Equal(t, legacyPEM, suitePEM)
}
