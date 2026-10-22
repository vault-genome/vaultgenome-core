// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// SignatureSuite names a signature algorithm, its parameter set and its
// hash (ADR 0031). A suite id never changes meaning; a new triple is a
// new id. Every signed record carries the id of the suite its signature
// was made under in its `alg` field — absent, the record is ed25519,
// what every record before ADR 0031 carried.
type SignatureSuite string

const (
	// SuiteEd25519 is EdDSA on Ed25519 (FIPS 186-5 §7; RFC 8032): a
	// 64-byte signature over the message, a 32-byte public key. Approved
	// and on the certificate of the Go Cryptographic Module v1.0.0; not
	// registered by X9 SD-34-2025.
	SuiteEd25519 SignatureSuite = "ed25519"

	// SuiteECDSAP384SHA384 is ECDSA on P-384 with SHA-384 (FIPS 186-5 §6,
	// as X9 SD-34-2025 entry 00009 directs: SEC1 §4.1.3 and §4.1.4 on a
	// curve of FIPS 186-4 Appendix D). The signature is the fixed-length
	// r ‖ s of 96 bytes; the public key the 97-byte uncompressed point
	// (SEC1 §2.3.3). The nonce is randomized as crypto/ecdsa produces it
	// (Go 1.26 and later always draw it from the system's random source);
	// verification does not depend on how the nonce was chosen. On the
	// certificate of the module v1.0.0; the transition suite of CNSA 2.0.
	SuiteECDSAP384SHA384 SignatureSuite = "ecdsa-p384-sha384"

	// SuiteMLDSA87 is ML-DSA-87 (FIPS 204) in pure mode with an empty
	// context string: a 4627-byte signature, a 2592-byte public key.
	// Registered by X9 SD-34-2025 (entry 00015) and named by CNSA 2.0 as
	// the destination. The standard library's implementation; unavailable
	// in the Go Cryptographic Module v1.0.0 — Available reports it.
	SuiteMLDSA87 SignatureSuite = "ml-dsa-87"
)

const (
	ecdsaP384ScalarSize   = 48
	ecdsaP384PublicSize   = 1 + 2*ecdsaP384ScalarSize // uncompressed point
	ecdsaP384SignatureLen = 2 * ecdsaP384ScalarSize
)

// Suites lists every suite in registry order.
func Suites() []SignatureSuite {
	return []SignatureSuite{SuiteEd25519, SuiteECDSAP384SHA384, SuiteMLDSA87}
}

// ParseSignatureSuite returns the suite named by s, which must be one of
// the registered ids; the empty string is not a suite here (a record's
// absent alg is resolved by RecordSuite).
func ParseSignatureSuite(s string) (SignatureSuite, error) {
	switch SignatureSuite(s) {
	case SuiteEd25519, SuiteECDSAP384SHA384, SuiteMLDSA87:
		return SignatureSuite(s), nil
	}
	return "", shared_errors.Structural(
		shared_errors.CodeFieldValueInvalid,
		"crypto: unknown signature suite "+quote(s)+" (ed25519, ecdsa-p384-sha384, ml-dsa-87)",
		nil,
	)
}

// RecordSuite resolves the alg a record carries: absent means ed25519.
func RecordSuite(alg SignatureSuite) (SignatureSuite, error) {
	if alg == "" {
		return SuiteEd25519, nil
	}
	return ParseSignatureSuite(string(alg))
}

// RecordAlg is the alg a record signed under suite carries: absent for
// ed25519, so a record under the suite every earlier release wrote keeps
// the bytes every earlier reader verifies; the suite id otherwise.
func RecordAlg(suite SignatureSuite) SignatureSuite {
	if suite == SuiteEd25519 {
		return ""
	}
	return suite
}

func quote(s string) string {
	if len(s) > 64 {
		s = s[:64] + "…"
	}
	return "\"" + s + "\""
}

// String returns the suite id.
func (s SignatureSuite) String() string { return string(s) }

// Valid reports whether s is a registered suite.
func (s SignatureSuite) Valid() bool {
	_, err := ParseSignatureSuite(string(s))
	return err == nil
}

// SignatureSize is the length of a signature under s; 0 for an unknown
// suite.
func (s SignatureSuite) SignatureSize() int {
	switch s {
	case SuiteEd25519:
		return ed25519.SignatureSize
	case SuiteECDSAP384SHA384:
		return ecdsaP384SignatureLen
	case SuiteMLDSA87:
		return mldsa.MLDSA87SignatureSize
	}
	return 0
}

// PublicKeySize is the length of a public key's raw encoding under s; 0
// for an unknown suite.
func (s SignatureSuite) PublicKeySize() int {
	switch s {
	case SuiteEd25519:
		return ed25519.PublicKeySize
	case SuiteECDSAP384SHA384:
		return ecdsaP384PublicSize
	case SuiteMLDSA87:
		return mldsa.MLDSA87PublicKeySize
	}
	return 0
}

// SeedSize is the length of the seed a private key of s is derived from,
// or 0 for a suite with no seed form (ECDSA keys are PKCS#8).
func (s SignatureSuite) SeedSize() int {
	switch s {
	case SuiteEd25519:
		return ed25519.SeedSize
	case SuiteMLDSA87:
		return mldsa.PrivateKeySize
	}
	return 0
}

// Available reports whether this process can sign and verify under s: nil,
// or the reason it cannot. ML-DSA-87 is unavailable when the binary runs
// on the Go Cryptographic Module v1.0.0 (the -fips build of ADR 0030), and
// the reason is the module's own — availability is measured, never
// assumed.
func (s SignatureSuite) Available() error {
	switch s {
	case SuiteEd25519, SuiteECDSAP384SHA384:
		return nil
	case SuiteMLDSA87:
		if _, err := mldsa.NewPublicKey(mldsa.MLDSA87(), make([]byte, mldsa.MLDSA87PublicKeySize)); err != nil {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"crypto: signature suite ml-dsa-87 is unavailable on this build: "+err.Error(),
				err,
			)
		}
		return nil
	}
	return shared_errors.Structural(
		shared_errors.CodeFieldValueInvalid,
		"crypto: unknown signature suite "+quote(string(s)),
		nil,
	)
}

// SigningKey is a private key of one suite. The zero value is unusable;
// construct one with GenerateSigningKey, SigningKeyFromSeed or
// ParseSigningKeyPKCS8. Do not log or persist one unsealed.
type SigningKey struct {
	suite SignatureSuite
	ed    ed25519.PrivateKey
	ec    *ecdsa.PrivateKey
	ml    *mldsa.PrivateKey
	seed  []byte // the seed a seed-form key was built from (ed25519, ml-dsa-87)
}

// GenerateSigningKey makes a fresh key of suite. rng is the source for
// Ed25519 (nil means crypto/rand); ECDSA and ML-DSA draw from the
// system's random source as the standard library requires.
func GenerateSigningKey(suite SignatureSuite, rng io.Reader) (*SigningKey, error) {
	if rng == nil {
		rng = rand.Reader
	}
	switch suite {
	case SuiteEd25519:
		_, priv, err := ed25519.GenerateKey(rng)
		if err != nil {
			return nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid, "crypto: ed25519 key generation failed", err)
		}
		return &SigningKey{suite: suite, ed: priv, seed: priv.Seed()}, nil
	case SuiteECDSAP384SHA384:
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rng)
		if err != nil {
			return nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid, "crypto: ecdsa P-384 key generation failed", err)
		}
		return &SigningKey{suite: suite, ec: priv}, nil
	case SuiteMLDSA87:
		priv, err := mldsa.GenerateKey(mldsa.MLDSA87())
		if err != nil {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ml-dsa-87 key generation failed: "+err.Error(), err)
		}
		return &SigningKey{suite: suite, ml: priv, seed: priv.Bytes()}, nil
	}
	return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: unknown signature suite "+quote(string(suite)), nil)
}

// SigningKeyFromSeed derives the key of suite from its seed: the 32-byte
// Ed25519 seed (RFC 8032 §5.1.5) or the 32-byte ML-DSA seed (FIPS 204
// Algorithm 6). ECDSA has no seed form; load it with ParseSigningKeyPKCS8.
func SigningKeyFromSeed(suite SignatureSuite, seed []byte) (*SigningKey, error) {
	switch suite {
	case SuiteEd25519:
		if len(seed) != ed25519.SeedSize {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ed25519 seed must be 32 bytes", nil)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		return &SigningKey{suite: suite, ed: priv, seed: priv.Seed()}, nil
	case SuiteMLDSA87:
		if len(seed) != mldsa.PrivateKeySize {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ml-dsa-87 seed must be 32 bytes", nil)
		}
		priv, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
		if err != nil {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ml-dsa-87 key from seed failed: "+err.Error(), err)
		}
		return &SigningKey{suite: suite, ml: priv, seed: priv.Bytes()}, nil
	case SuiteECDSAP384SHA384:
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ecdsa-p384-sha384 has no seed form; the key is PKCS#8", nil)
	}
	return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: unknown signature suite "+quote(string(suite)), nil)
}

// ParseSigningKeyPKCS8 loads a private key from its PKCS#8 DER (RFC 5958)
// and names its suite from the key's own algorithm: Ed25519, ECDSA on
// P-384 (any other curve is refused), ML-DSA-87 (any other parameter
// set is refused).
func ParseSigningKeyPKCS8(der []byte) (*SigningKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: parse PKCS#8 private key", err)
	}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return &SigningKey{suite: SuiteEd25519, ed: k, seed: k.Seed()}, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P384() {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ECDSA private key must be on P-384 (ecdsa-p384-sha384), got "+k.Curve.Params().Name, nil)
		}
		return &SigningKey{suite: SuiteECDSAP384SHA384, ec: k}, nil
	case *mldsa.PrivateKey:
		if k.PublicKey().Parameters() != mldsa.MLDSA87() {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ML-DSA private key must be ML-DSA-87, got "+k.PublicKey().Parameters().String(), nil)
		}
		return &SigningKey{suite: SuiteMLDSA87, ml: k, seed: k.Bytes()}, nil
	}
	return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: PKCS#8 private key is not of a registered signature suite", nil)
}

// Suite is the key's suite.
func (k *SigningKey) Suite() SignatureSuite { return k.suite }

// Seed returns a copy of the seed of a seed-form key (ed25519, ml-dsa-87)
// and nil for ECDSA.
func (k *SigningKey) Seed() []byte {
	if k == nil || k.seed == nil {
		return nil
	}
	return append([]byte(nil), k.seed...)
}

// PKCS8 encodes the private key as PKCS#8 DER — the file form of an ECDSA
// key and an interchange form for the others.
func (k *SigningKey) PKCS8() ([]byte, error) {
	var priv any
	switch {
	case k == nil:
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crypto: nil signing key", nil)
	case k.ed != nil:
		priv = k.ed
	case k.ec != nil:
		priv = k.ec
	case k.ml != nil:
		priv = k.ml
	default:
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crypto: empty signing key", nil)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: marshal PKCS#8 private key", err)
	}
	return der, nil
}

// PublicKeyBytes is the raw encoding of the public key under the suite:
// 32 bytes (Ed25519), the 97-byte uncompressed point (ECDSA P-384), 2592
// bytes (ML-DSA-87).
func (k *SigningKey) PublicKeyBytes() []byte {
	switch {
	case k == nil:
		return nil
	case k.ed != nil:
		return append([]byte(nil), k.ed.Public().(ed25519.PublicKey)...)
	case k.ec != nil:
		b, err := k.ec.PublicKey.Bytes()
		if err != nil {
			return nil
		}
		return b
	case k.ml != nil:
		return k.ml.PublicKey().Bytes()
	}
	return nil
}

// Sign produces the suite's signature over msg: Ed25519 over msg; ECDSA
// over SHA-384(msg) as the fixed-length r ‖ s; ML-DSA-87 over msg in pure
// mode. The length is the suite's SignatureSize.
func (k *SigningKey) Sign(msg []byte) ([]byte, error) {
	switch {
	case k == nil:
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crypto: nil signing key", nil)
	case k.ed != nil:
		return ed25519.Sign(k.ed, msg), nil
	case k.ec != nil:
		h := sha512.Sum384(msg)
		der, err := ecdsa.SignASN1(rand.Reader, k.ec, h[:])
		if err != nil {
			return nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid, "crypto: ecdsa P-384 signing failed", err)
		}
		return ecdsaFixedFromASN1(der)
	case k.ml != nil:
		sig, err := k.ml.Sign(nil, msg, nil)
		if err != nil {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ml-dsa-87 signing failed: "+err.Error(), err)
		}
		return sig, nil
	}
	return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crypto: empty signing key", nil)
}

// Zeroize wipes what can be wiped: the Ed25519 private key and the seeds
// (Ed25519, ML-DSA). The ECDSA scalar and the expanded ML-DSA key live in
// representations crypto/ecdsa (Go 1.26 and later) and crypto/mldsa do
// not expose for wiping; they are dropped for the collector, and the
// sealed key file of ADR 0023 remains the material's boundary.
func (k *SigningKey) Zeroize() {
	if k == nil {
		return
	}
	for i := range k.seed {
		k.seed[i] = 0
	}
	k.seed = nil
	if k.ed != nil {
		for i := range k.ed {
			k.ed[i] = 0
		}
		k.ed = nil
	}
	k.ec = nil
	k.ml = nil
}

// ecdsaFixedFromASN1 converts an ASN.1 DER ECDSA signature to the
// fixed-length r ‖ s (48 bytes each, big-endian, zero-padded).
func ecdsaFixedFromASN1(der []byte) ([]byte, error) {
	var rs struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &rs)
	if err != nil || len(rest) != 0 || rs.R == nil || rs.S == nil || rs.R.Sign() <= 0 || rs.S.Sign() <= 0 ||
		rs.R.BitLen() > 8*ecdsaP384ScalarSize || rs.S.BitLen() > 8*ecdsaP384ScalarSize {
		return nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid, "crypto: ecdsa signature encoding invalid", err)
	}
	out := make([]byte, ecdsaP384SignatureLen)
	rs.R.FillBytes(out[:ecdsaP384ScalarSize])
	rs.S.FillBytes(out[ecdsaP384ScalarSize:])
	return out, nil
}

// VerifySuite returns nil if sig is a valid signature of msg under the raw
// public key pub of suite. A wrong key or signature length, or a
// signature that does not verify, is an Integrity-classified error; a
// suite this build cannot verify (ml-dsa-87 on the module v1.0.0) is a
// Structural one carrying the module's reason.
func VerifySuite(suite SignatureSuite, pub, msg, sig []byte) error {
	if size := suite.PublicKeySize(); size == 0 {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: unknown signature suite "+quote(string(suite)), nil)
	} else if len(pub) != size {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: "+string(suite)+" public key length wrong", nil)
	}
	if len(sig) != suite.SignatureSize() {
		return shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "crypto: "+string(suite)+" signature length wrong", nil)
	}
	switch suite {
	case SuiteEd25519:
		if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "crypto: ed25519 signature verification failed", nil)
		}
		return nil
	case SuiteECDSAP384SHA384:
		pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), pub)
		if err != nil {
			return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ecdsa P-384 public key invalid", err)
		}
		h := sha512.Sum384(msg)
		r := new(big.Int).SetBytes(sig[:ecdsaP384ScalarSize])
		s := new(big.Int).SetBytes(sig[ecdsaP384ScalarSize:])
		if !ecdsa.Verify(pk, h[:], r, s) {
			return shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "crypto: ecdsa-p384-sha384 signature verification failed", nil)
		}
		return nil
	case SuiteMLDSA87:
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pub)
		if err != nil {
			if avail := suite.Available(); avail != nil {
				return avail
			}
			return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ml-dsa-87 public key invalid", err)
		}
		if err := mldsa.Verify(pk, msg, sig, nil); err != nil {
			return shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "crypto: ml-dsa-87 signature verification failed", err)
		}
		return nil
	}
	return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: unknown signature suite "+quote(string(suite)), nil)
}

// PublicKeyPKIX encodes the raw public key of suite as PKIX
// SubjectPublicKeyInfo DER, which names the algorithm itself (id-Ed25519,
// id-ecPublicKey with secp384r1, id-ML-DSA-87).
func PublicKeyPKIX(suite SignatureSuite, pub []byte) ([]byte, error) {
	if size := suite.PublicKeySize(); size == 0 || len(pub) != size {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: "+string(suite)+" public key length wrong", nil)
	}
	var key stdcrypto.PublicKey
	switch suite {
	case SuiteEd25519:
		key = ed25519.PublicKey(pub)
	case SuiteECDSAP384SHA384:
		pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), pub)
		if err != nil {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ecdsa P-384 public key invalid", err)
		}
		key = pk
	case SuiteMLDSA87:
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pub)
		if err != nil {
			if avail := suite.Available(); avail != nil {
				return nil, avail
			}
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ml-dsa-87 public key invalid", err)
		}
		key = pk
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: marshal public key", err)
	}
	return der, nil
}

// PublicKeyPEMSuite encodes the raw public key of suite as a PEM "PUBLIC
// KEY" block — the form operators exchange and the daemons' key loaders
// accept.
func PublicKeyPEMSuite(suite SignatureSuite, pub []byte) ([]byte, error) {
	der, err := PublicKeyPKIX(suite, pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePublicKeyPKIX reads PKIX SubjectPublicKeyInfo DER and returns the
// suite its algorithm names and the raw public key. An algorithm outside
// the registry (an ECDSA curve other than P-384, an ML-DSA parameter set
// other than 87, RSA) is refused.
func ParsePublicKeyPKIX(der []byte) (SignatureSuite, []byte, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: parse PKIX public key", err)
	}
	switch k := key.(type) {
	case ed25519.PublicKey:
		return SuiteEd25519, append([]byte(nil), k...), nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P384() {
			return "", nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ECDSA public key must be on P-384 (ecdsa-p384-sha384), got "+k.Curve.Params().Name, nil)
		}
		raw, err := k.Bytes()
		if err != nil {
			return "", nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ecdsa P-384 public key invalid", err)
		}
		return SuiteECDSAP384SHA384, raw, nil
	case *mldsa.PublicKey:
		if k.Parameters() != mldsa.MLDSA87() {
			return "", nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: ML-DSA public key must be ML-DSA-87, got "+k.Parameters().String(), nil)
		}
		return SuiteMLDSA87, k.Bytes(), nil
	}
	return "", nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: public key is not of a registered signature suite", nil)
}

// ParsePublicKeyPEM reads a PEM "PUBLIC KEY" block as ParsePublicKeyPKIX.
func ParsePublicKeyPEM(data []byte) (SignatureSuite, []byte, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: expected a PEM \"PUBLIC KEY\" block", nil)
	}
	return ParsePublicKeyPKIX(block.Bytes)
}
