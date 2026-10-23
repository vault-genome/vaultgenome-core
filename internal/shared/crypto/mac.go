// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// HMACSize is the HMAC-SHA-256 tag length in bytes.
const HMACSize = sha256.Size

// HMACSHA256 computes HMAC-SHA-256(key, msg). Returns a freshly-allocated
// slice of length HMACSize. Thin wrapper over crypto/hmac so every MAC
// path in the codebase goes through the same primitive.
//
// The key length is NOT policed here: HMAC is defined for arbitrary key
// lengths (shorter keys are zero-padded, longer keys are hashed down).
// Callers that require a specific key length (e.g. 32 bytes for the
// Return Path session MAC key) MUST validate length at their own layer.
func HMACSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// HMACSHA256Verify returns nil if tag equals HMAC-SHA-256(key, msg),
// using a constant-time comparison. On mismatch returns an Integrity-
// classified error (so callers' audit routing treats it as a
// tamper-adjacent event).
//
// tag MUST be exactly HMACSize bytes. A length mismatch is itself an
// integrity failure — a truncated tag on the wire is indistinguishable
// from an adversarial shortening and is handled identically.
func HMACSHA256Verify(key, msg, tag []byte) error {
	if len(tag) != HMACSize {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"crypto: HMAC-SHA-256 tag length wrong",
			nil,
		)
	}
	expected := HMACSHA256(key, msg)
	if !hmac.Equal(expected, tag) {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"crypto: HMAC-SHA-256 verification failed",
			nil,
		)
	}
	return nil
}

// HKDFSHA256 implements the RFC 5869 Extract-then-Expand key-derivation
// function over SHA-256. It is a literal transcription of the RFC — no
// hand-rolled crypto, only the stdlib HMAC primitive chained per the
// spec.
//
// Parameters
//
//   - salt: optional; pass nil for the default all-zero salt of HashSize
//     bytes. Typical use in this codebase is a domain-separation label.
//   - ikm:  input keying material. For a session-key derivation after a
//     simulated TEE handshake, this is the concatenation of both peers'
//     nonces; in a real-hardware Phase-3 swap it would be the shared
//     secret output by the attestation protocol.
//   - info: per-context label; MUST uniquely identify (protocol,
//     version, key-purpose). The Return Path wire derivation uses
//     "rp-wire-v1.0 session-mac" plus the per-handshake
//     DerivationContext.
//   - length: number of bytes to output. RFC 5869 caps this at
//     255*HashSize (= 8160 for SHA-256); we enforce that limit.
//
// Returns the derived bytes, or a Structural error if length is out of
// range. The function never returns an Integrity error — every step is
// a stdlib call over well-formed inputs.
// HKDFSHA256 is HKDF (RFC 5869) with HMAC-SHA-256, computed by the
// cryptographic module's own crypto/hkdf (ADR 0030): the module keys the
// extract step's HMAC with the salt, which the Security Policy allows to
// be shorter than a MAC key (CMVP #5247 §2.7, IG C.M); an HMAC keyed with
// a short salt outside the module is refused under fips140=only. The
// output is the one RFC 5869 defines, whatever computes it.
func HKDFSHA256(salt, ikm, info []byte, length int) ([]byte, error) {
	if length < 0 {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: HKDF output length must be non-negative",
			nil,
		)
	}
	if length > 255*HashSize {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: HKDF output length exceeds 255*HashSize (RFC 5869)",
			nil,
		)
	}
	if length == 0 {
		return []byte{}, nil
	}
	okm, err := hkdf.Key(sha256.New, ikm, salt, string(info), length)
	if err != nil {
		return nil, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"crypto: HKDF failed",
			err,
		)
	}
	return okm, nil
}
