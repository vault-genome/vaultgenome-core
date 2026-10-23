// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package escrow

// The keys of this package under a KEM suite (ADR 0029). An escrow key,
// and the operator's recovery key, is a KEM key pair of one suite; the
// suite is what every document names, what a PEM carries, and what
// decides how a document is opened. The X25519 keys of earlier releases
// are the hpke-x25519-v1 keys: the same 32 bytes, read by the same code.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// LegacySuite is the suite of every key and document of releases before
// ADR 0029 — the X25519 keys, which hpke-x25519-v1 reads unchanged.
const LegacySuite = kms.SuiteHPKEX25519

// legacyKeySize is the raw X25519 key the files of earlier releases hold.
const legacyKeySize = 32

// maxKeyFileBytes bounds what is read as a key file.
const maxKeyFileBytes = 8 << 10

// PEM block types of the keys no PKIX form exists for (ML-KEM and the
// hybrids); the suite is a header of the block, the body is the KEM's
// serialized key. X25519 and P-384 keys travel as PKIX "PUBLIC KEY".
const (
	pemHPKEPublic  = "VAULT GENOME HPKE PUBLIC KEY"
	pemHPKEPrivate = "VAULT GENOME HPKE PRIVATE KEY"
	pemSuiteHeader = "Suite"
)

// PublicKey is an escrow or recovery public key under a suite.
type PublicKey struct {
	suite kms.Suite
	raw   []byte
}

// NewPublicKey accepts raw as a public key of suite — a usable one, by
// the suite's own check.
func NewPublicKey(suite kms.Suite, raw []byte) (PublicKey, error) {
	if !suite.Known() {
		return PublicKey{}, fmt.Errorf("escrow: unknown KEM suite %q", string(suite))
	}
	if err := suite.ValidateRecipientPublicKey(raw); err != nil {
		return PublicKey{}, err
	}
	return PublicKey{suite: suite, raw: append([]byte(nil), raw...)}, nil
}

// Suite returns the key's suite.
func (p PublicKey) Suite() kms.Suite { return p.suite }

// Bytes returns the key in the KEM's SerializePublicKey form.
func (p PublicKey) Bytes() []byte { return append([]byte(nil), p.raw...) }

// IsZero reports whether p holds no key.
func (p PublicKey) IsZero() bool { return p.suite == "" }

// Equal reports whether q is the same key.
func (p PublicKey) Equal(q PublicKey) bool { return p.suite == q.suite && bytes.Equal(p.raw, q.raw) }

// PrivateKey is an escrow or recovery private key under a suite, with
// its public half.
type PrivateKey struct {
	suite kms.Suite
	raw   []byte
	pub   PublicKey
}

// GenerateKey makes a key pair under suite.
func GenerateKey(suite kms.Suite) (*PrivateKey, error) {
	priv, pub, err := suite.GenerateRecipientKey()
	if err != nil {
		return nil, err
	}
	public, err := NewPublicKey(suite, pub)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{suite: suite, raw: priv, pub: public}, nil
}

// NewPrivateKey accepts raw as a private key of suite (the KEM's
// SerializePrivateKey form; the 32 raw bytes of an earlier release's
// X25519 key are that form) and derives its public half.
func NewPrivateKey(suite kms.Suite, raw []byte) (*PrivateKey, error) {
	if !suite.Known() {
		return nil, fmt.Errorf("escrow: unknown KEM suite %q", string(suite))
	}
	pub, err := suite.PublicKeyOf(raw)
	if err != nil {
		return nil, err
	}
	public, err := NewPublicKey(suite, pub)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{suite: suite, raw: append([]byte(nil), raw...), pub: public}, nil
}

// Suite returns the key's suite.
func (k *PrivateKey) Suite() kms.Suite { return k.suite }

// Bytes returns the private key in the KEM's SerializePrivateKey form.
func (k *PrivateKey) Bytes() []byte { return append([]byte(nil), k.raw...) }

// PublicKey returns the public half.
func (k *PrivateKey) PublicKey() PublicKey { return k.pub }

// Equal reports whether o is the same key.
func (k *PrivateKey) Equal(o *PrivateKey) bool {
	return k != nil && o != nil && k.suite == o.suite && bytes.Equal(k.raw, o.raw)
}

// Clear overwrites the private bytes; the key is unusable afterwards.
func (k *PrivateKey) Clear() {
	if k != nil {
		clear(k.raw)
	}
}

// KeyTag names a public key: the first 16 hex of the SHA-256 of its
// bytes — for an X25519 key, the tag earlier releases gave it.
func KeyTag(pub PublicKey) string {
	sum := sha256.Sum256(pub.raw)
	return hex.EncodeToString(sum[:8])
}

// PublicPEM encodes a public key for a file sealers and operators pass
// around: PKIX "PUBLIC KEY" for X25519 and P-384, which every tool
// reads; the product's own block, with the suite as a header, for the
// keys PKIX has no form for.
func PublicPEM(pub PublicKey) ([]byte, error) {
	switch pub.suite.Family() {
	case kms.SuiteHPKEX25519.Family(), kms.SuiteHPKEP384.Family():
		curve := ecdh.X25519()
		if pub.suite.Family() == kms.SuiteHPKEP384.Family() {
			curve = ecdh.P384()
		}
		key, err := curve.NewPublicKey(pub.raw)
		if err != nil {
			return nil, fmt.Errorf("escrow: %w", err)
		}
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("escrow: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
	case "":
		return nil, errors.New("escrow: no public key to encode")
	default:
		return pem.EncodeToMemory(&pem.Block{Type: pemHPKEPublic, Headers: map[string]string{pemSuiteHeader: string(pub.suite)}, Bytes: pub.raw}), nil
	}
}

// ParsePublicPEM decodes a public key PublicPEM wrote, or the PKIX PEM of
// an earlier release: an X25519 key is hpke-x25519-v1, a P-384 key
// hpke-p384-v1; a key of any other curve, or a block of any other kind,
// is refused. The key must be usable under its suite.
func ParsePublicPEM(b []byte) (PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return PublicKey{}, errors.New("escrow: not a PEM public key")
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return PublicKey{}, fmt.Errorf("escrow: %w", err)
		}
		switch k := key.(type) {
		case *ecdh.PublicKey:
			if k.Curve() != ecdh.X25519() {
				return PublicKey{}, fmt.Errorf("escrow: key is on %v, want X25519 or P-384", k.Curve())
			}
			return NewPublicKey(kms.SuiteHPKEX25519, k.Bytes())
		case *ecdsa.PublicKey:
			ek, err := k.ECDH()
			if err != nil || ek.Curve() != ecdh.P384() {
				return PublicKey{}, fmt.Errorf("escrow: key is on %v, want X25519 or P-384", k.Curve.Params().Name)
			}
			return NewPublicKey(kms.SuiteHPKEP384, ek.Bytes())
		default:
			return PublicKey{}, fmt.Errorf("escrow: key is %T, want an X25519 or P-384 public key", key)
		}
	case pemHPKEPublic:
		suite, err := kms.ParseSuite(block.Headers[pemSuiteHeader])
		if err != nil {
			return PublicKey{}, fmt.Errorf("escrow: %s: %w", pemHPKEPublic, err)
		}
		// a key belongs to a family, not a version: a 0.7.0 key labelled
		// v1 is the same key, and this build writes v2 with it (ADR 0030)
		return NewPublicKey(suite.Latest(), block.Bytes)
	default:
		return PublicKey{}, errors.New("escrow: not a PEM public key")
	}
}

// PrivatePEM encodes a private key for a file of mode 0600, or a pipe:
// the product's own block, with the suite as a header.
func PrivatePEM(k *PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemHPKEPrivate, Headers: map[string]string{pemSuiteHeader: string(k.suite)}, Bytes: k.raw})
}

// ParsePrivate decodes a private key: the PEM PrivatePEM wrote, or the
// raw 32-byte X25519 key of an earlier release's `acpctl escrow keygen`.
func ParsePrivate(raw []byte) (*PrivateKey, error) {
	if len(raw) == legacyKeySize {
		return NewPrivateKey(LegacySuite, raw)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != pemHPKEPrivate {
		return nil, fmt.Errorf("escrow: not a private key (neither a raw %d-byte X25519 key nor a %s PEM)", legacyKeySize, pemHPKEPrivate)
	}
	suite, err := kms.ParseSuite(block.Headers[pemSuiteHeader])
	if err != nil {
		return nil, fmt.Errorf("escrow: %s: %w", pemHPKEPrivate, err)
	}
	return NewPrivateKey(suite.Latest(), block.Bytes)
}

// ReadPrivate reads a private key file, refusing one other users can read.
func ReadPrivate(path string) (*PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("escrow: %s is open to other users (mode %04o); chmod 600 it", path, perm)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxKeyFileBytes {
		return nil, fmt.Errorf("escrow: %s is larger than %d bytes: not a key file", path, maxKeyFileBytes)
	}
	k, err := ParsePrivate(raw)
	if err != nil {
		return nil, fmt.Errorf("escrow: %s: %w", path, err)
	}
	return k, nil
}
