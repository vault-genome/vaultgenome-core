// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
)

// KeyWrapper seals plaintext DEKs under a key derived from the
// destination's verified TEE measurement. Only a TEE matching that
// measurement (and using a compatible Unwrap implementation) can
// recover the plaintext.
//
// # MVP design (SimulatedKeyWrapper)
//
// The Phase 4 MVP implementation derives an AES-256 wrapping key
// deterministically:
//
//	wrap_key = SHA-256("vault-genome-xcc-wrap-v1" || destination_measurement)
//
// AES-256-GCM with a fresh 12-byte random nonce is used to seal each
// DEK. The output format is:
//
//	wrapped = nonce || ciphertext_with_tag
//
// where ciphertext_with_tag is exactly len(plaintext)+16 bytes.
//
// # Production caveat
//
// This MVP wrapper is symmetric: any party that knows the destination
// measurement can both wrap AND unwrap. That is acceptable when
// either:
//
//   - The destination measurement is itself a hardware-bound secret
//     (i.e., only the destination TEE knows it).
//   - The transport channel and audit chain prevent unauthorised
//     parties from learning the measurement.
//
// Real production deployments will switch to a key-encapsulation
// scheme where the destination advertises its TEE-bound public key
// in the handshake response, and the source uses that to perform a
// hybrid (RSA-OAEP / X25519) encapsulation of a per-token DEK. That
// upgrade is non-breaking — the KeyWrapper interface stays the same;
// only the SimulatedKeyWrapper implementation is replaced.
//
// # Compatibility with destination Sealer
//
// The destination's CrossCloudReceiver Unwrap path mirrors this
// derivation exactly: the receiver has a local
// tee.Producer.Measurement() that equals the wrap input on the
// source side. The receiver derives the same AES-256 key and unseals.
// This pairing is documented in ADR 0006 §"Threat Model" point 5.
type KeyWrapper interface {
	Wrap(plaintext, destinationMeasurement, aad []byte) (ciphertext []byte, err error)
}

// KeyUnwrapper is the destination-side counterpart to KeyWrapper. It
// is implemented by the CrossCloudReceiver and consumes the same
// derivation. Defined here so the symmetric pairing is visible from
// one place.
type KeyUnwrapper interface {
	Unwrap(ciphertext, destinationMeasurement, aad []byte) (plaintext []byte, err error)
}

// SimulatedKeyWrapper implements KeyWrapper using deterministic
// SHA-256 derivation + AES-256-GCM. Production deployments replace
// this with a hardware-bound implementation; tests use it as-is.
type SimulatedKeyWrapper struct{}

// NewSimulatedKeyWrapper returns a stateless wrapper instance.
// Multiple instances are interchangeable.
func NewSimulatedKeyWrapper() *SimulatedKeyWrapper {
	return &SimulatedKeyWrapper{}
}

// derivedKey is the canonical wrap-key derivation. Centralised here
// so the source-side wrapper and the destination-side unwrapper
// derive identically.
const wrapDerivationLabel = "vault-genome-xcc-wrap-v1"

func deriveWrapKey(destinationMeasurement []byte) ([32]byte, error) {
	if len(destinationMeasurement) != 32 {
		return [32]byte{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms: wrap-key derivation requires 32-byte measurement; got %d", len(destinationMeasurement)),
			nil,
		)
	}
	buf := make([]byte, 0, len(wrapDerivationLabel)+32)
	buf = append(buf, []byte(wrapDerivationLabel)...)
	buf = append(buf, destinationMeasurement...)
	return crypto.SHA256(buf), nil
}

// Wrap seals plaintext under the destination-derived AES-256 key
// using AES-256-GCM with a fresh random nonce. The output is
// nonce || ciphertext-with-tag.
//
// AAD is bound into the GCM tag — a destination unsealing the
// ciphertext MUST supply the identical AAD or the tag check fails
// with an Integrity error.
func (w *SimulatedKeyWrapper) Wrap(
	plaintext, destinationMeasurement, aad []byte,
) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"kms.Wrap: plaintext required",
			nil,
		)
	}
	wk, err := deriveWrapKey(destinationMeasurement)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(wk[:])
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"kms.Wrap: aes cipher init failed",
			err,
		)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"kms.Wrap: gcm init failed",
			err,
		)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"kms.Wrap: nonce generation failed (RNG fault)",
			err,
		)
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// SimulatedKeyUnwrapper is the destination-side counterpart, kept in
// this package so the wrapper / unwrapper derivation stays in lockstep.
// The actual destination CrossCloudReceiver wires this in; tests
// exercise the round-trip here too.
type SimulatedKeyUnwrapper struct{}

// NewSimulatedKeyUnwrapper returns a stateless unwrapper.
func NewSimulatedKeyUnwrapper() *SimulatedKeyUnwrapper {
	return &SimulatedKeyUnwrapper{}
}

// Unwrap recovers the plaintext from a Wrap output, given the same
// destinationMeasurement and AAD. Tag mismatch (wrong measurement,
// wrong AAD, or tampering) returns an Integrity-classified error.
func (u *SimulatedKeyUnwrapper) Unwrap(
	ciphertext, destinationMeasurement, aad []byte,
) ([]byte, error) {
	wk, err := deriveWrapKey(destinationMeasurement)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(wk[:])
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"kms.Unwrap: aes cipher init failed",
			err,
		)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"kms.Unwrap: gcm init failed",
			err,
		)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"kms.Unwrap: wrapped material too short",
			nil,
		)
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ct := ciphertext[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"kms.Unwrap: tag verification failed (measurement, AAD, or ciphertext tampered)",
			err,
		)
	}
	return plain, nil
}
