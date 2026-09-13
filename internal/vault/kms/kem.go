// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

// X25519 key-encapsulation (ECIES) — the honest replacement for the symmetric,
// measurement-derived SimulatedKeyWrapper (see wrapper.go and KNOWN_ISSUES
// defect (b)). A per-token DEK is encapsulated to the destination's X25519
// public key using an ephemeral X25519 key, HKDF-SHA256, and AES-256-GCM. Only
// the holder of the destination private key can unwrap. In production that
// private key is generated INSIDE the destination TEE and never leaves it, and
// its public key is bound into the attestation REPORT_DATA (proven end-to-end
// by the SEV-SNP keybind evidence), so a measurement — a public value — is no
// longer sufficient to unwrap.
//
// Wrapped layout: ephPub(32) || nonce(12) || ciphertext-with-tag.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"

	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
)

const kemInfoLabel = "vault-genome-xcc-kem-v1"

// X25519KeyWrapper encapsulates a DEK to a recipient X25519 public key.
type X25519KeyWrapper struct{}

// NewX25519KeyWrapper returns a stateless wrapper.
func NewX25519KeyWrapper() *X25519KeyWrapper { return &X25519KeyWrapper{} }

// Wrap encapsulates plaintext to recipientPub (a 32-byte X25519 public key).
// aad is bound into the AES-GCM tag.
func (X25519KeyWrapper) Wrap(plaintext, recipientPub, aad []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.Wrap: plaintext required", nil)
	}
	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms.Wrap: invalid recipient X25519 public key", err)
	}
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted, "kms.Wrap: ephemeral key generation failed", err)
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid, "kms.Wrap: ECDH failed", err)
	}
	key, err := deriveKEMKey(shared, eph.PublicKey().Bytes(), recipientPub)
	if err != nil {
		return nil, err
	}
	ct, err := aeadSeal(key, plaintext, aad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(eph.PublicKey().Bytes())+len(ct))
	out = append(out, eph.PublicKey().Bytes()...)
	out = append(out, ct...)
	return out, nil
}

// X25519KeyUnwrapper is the destination-side counterpart.
type X25519KeyUnwrapper struct{}

// NewX25519KeyUnwrapper returns a stateless unwrapper.
func NewX25519KeyUnwrapper() *X25519KeyUnwrapper { return &X25519KeyUnwrapper{} }

// Unwrap recovers plaintext using recipientPriv (a 32-byte X25519 private key),
// held only inside the destination TEE in production.
func (X25519KeyUnwrapper) Unwrap(wrapped, recipientPriv, aad []byte) ([]byte, error) {
	if len(wrapped) < 32 {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "kms.Unwrap: wrapped material too short", nil)
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(recipientPriv)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms.Unwrap: invalid recipient X25519 private key", err)
	}
	ephBytes := wrapped[:32]
	ephPub, err := curve.NewPublicKey(ephBytes)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "kms.Unwrap: invalid ephemeral public key", err)
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "kms.Unwrap: ECDH failed", err)
	}
	key, err := deriveKEMKey(shared, ephBytes, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	return aeadOpen(key, wrapped[32:], aad)
}

func deriveKEMKey(shared, ephPub, recipientPub []byte) ([]byte, error) {
	info := make([]byte, 0, len(kemInfoLabel)+len(ephPub)+len(recipientPub))
	info = append(info, []byte(kemInfoLabel)...)
	info = append(info, ephPub...)
	info = append(info, recipientPub...)
	k, err := crypto.HKDFSHA256(nil, shared, info, 32)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms: HKDF derivation failed", err)
	}
	return k, nil
}

func aeadSeal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms: aes init failed", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms: gcm init failed", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted, "kms: nonce generation failed", err)
	}
	return append(nonce, gcm.Seal(nil, nonce, plaintext, aad)...), nil
}

func aeadOpen(key, blob, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms: aes init failed", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms: gcm init failed", err)
	}
	if len(blob) < gcm.NonceSize() {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "kms: ciphertext too short", nil)
	}
	plain, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], aad)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "kms: tag verification failed (wrong key, AAD, or tampering)", err)
	}
	return plain, nil
}
