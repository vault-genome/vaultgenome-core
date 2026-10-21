// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"slices"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// GCM constants. The key is 32 bytes (AES-256); the nonce is 12 bytes
// (standard GCM). Both are frozen per docs/doctrine/open-decisions-resolved.md R-10
// and match disclosure_message.GCMNonceSize.
const (
	AES256KeySize = 32
	GCMNonceSize  = 12
	GCMTagSize    = 16
)

// NewGCM constructs an AES-256-GCM AEAD from a 32-byte key.
// NewGCM returns AES-256-GCM over key with the nonce generated inside the
// cryptographic module (cipher.NewGCMWithRandomNonce): Seal takes no nonce
// and prepends the 96-bit random nonce it drew to the ciphertext; Open
// expects that nonce in front. The module's own IV generation is the
// approved construction (ADR 0030; the Security Policy of CMVP #5247 §2.7,
// IG C.H scenario 2) — an AEAD fed an arbitrary nonce is not, and
// cipher.NewGCM cannot be constructed at all under fips140=only. The
// helpers below keep the nonce beside the ciphertext, so every format
// that stores them apart is unchanged on disk and on the wire. No more
// than 2^32 seals may be made under one key (the module's limit).
func NewGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != AES256KeySize {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: AES-256 key must be 32 bytes",
			nil,
		)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"crypto: AES cipher construction failed",
			err,
		)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"crypto: GCM mode construction failed",
			err,
		)
	}
	return aead, nil
}

// Seal encrypts plaintext under key with the module-generated nonce and
// returns the nonce and the ciphertext (tag included) separately, as every
// caller stores them.
func Seal(key []byte, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	aead, err := NewGCM(key)
	if err != nil {
		return nil, nil, err
	}
	out := aead.Seal(nil, nil, plaintext, aad)
	if len(out) < GCMNonceSize+GCMTagSize {
		return nil, nil, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"crypto: GCM seal produced a short output",
			nil,
		)
	}
	nonce = append([]byte(nil), out[:GCMNonceSize]...)
	ciphertext = out[GCMNonceSize:]
	return nonce, ciphertext, nil
}

func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := NewGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != GCMNonceSize {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: GCM nonce must be 12 bytes",
			nil,
		)
	}
	// The module opens nonce ‖ ciphertext ‖ tag as one slice; slices.Concat
	// sizes the join itself (and refuses an overflow), so no size arithmetic
	// of our own stands in front of the allocation.
	plaintext, err := aead.Open(nil, nil, slices.Concat(nonce, ciphertext), aad)
	if err != nil {
		// Authentication failure is an integrity event.
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"crypto: GCM open failed (authentication)",
			err,
		)
	}
	return plaintext, nil
}
