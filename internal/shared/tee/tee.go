// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
)

// Measurement is the TEE's cryptographic measurement of the code running
// inside it — for real hardware this is the MRENCLAVE / TD report / VCEK
// report of the attested workload. It is stored and compared byte-wise.
type Measurement [crypto.HashSize]byte

// IsZero reports whether the measurement is all zero (i.e., unset).
func (m Measurement) IsZero() bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}

// Evidence is an opaque, TEE-signed blob that a verifier inspects to
// decide whether the producer is a genuine TEE running the expected
// workload. The internal structure depends on the TEE flavor; callers
// outside this package treat it as bytes only.
type Evidence []byte

// Nonce is challenger-provided fresh randomness, included in every
// attestation so that replay of a past quote does not satisfy a present
// check.
//
// The Nonce MUST carry at least NonceMinBytes of fresh entropy.
// Implementations of Producer.Quote and Verifier.Verify reject shorter
// nonces with a Structural error — see docs/doctrine/open-decisions-resolved.md
// R-10. This is part of the frozen V1 interface contract (iteration 5):
// when the simulated backend is replaced by real SGX/TDX/SEV in V2, the
// minimum-nonce rule carries over without callers having to opt in.
type Nonce []byte

// NonceMinBytes is the minimum acceptable length of a challenge nonce.
//
// Rationale. A nonce shorter than 16 bytes degrades the replay-protection
// guarantee: with 8 bytes of entropy a passive observer collecting quotes
// over a long session has a non-negligible collision probability. The
// floor is aligned with the 128-bit challenge sizes recommended by
// RFC 9334 §10.1 for remote-attestation evidence.
//
// The Nonce is opaque to the producer — it only contributes to the signed
// payload — so tightening this floor in a future revision remains a
// backward-compatible change for verifiers that already supply longer
// nonces.
const NonceMinBytes = 16

// Producer is the TEE-side capability of generating attestation evidence.
// Real hardware would be an SGX / TDX / SEV SDK; the MVP simulated
// implementation produces Ed25519-signed evidence bound to a fixed
// measurement.
type Producer interface {
	// Quote returns Evidence that authenticates the current workload under
	// the given Nonce.
	Quote(nonce Nonce) (Evidence, error)
	// Measurement returns the measurement this Producer will attest to.
	// Useful for the verifier to pre-register an expected measurement.
	Measurement() Measurement
}

// Verifier is the challenger-side capability of validating Evidence and
// extracting the Measurement it attests to.
type Verifier interface {
	// Verify checks Evidence against Nonce and returns the Measurement
	// the TEE is attesting to. A failure returns an Integrity-classified
	// error.
	Verify(evidence Evidence, nonce Nonce) (Measurement, error)
}

// Sealer is the TEE-side capability of sealing a plaintext so that only
// this TEE, running the same measurement, can unseal it. For the MVP
// this is AES-256-GCM with a key derived from the simulated measurement;
// production would delegate to the hardware sealing key.
type Sealer interface {
	Seal(plaintext, aad []byte) (sealed []byte, err error)
	Unseal(sealed, aad []byte) (plaintext []byte, err error)
}

// ---- helpers ---------------------------------------------------------------

// MeasurementFromBytes constructs a Measurement from a 32-byte digest.
func MeasurementFromBytes(b []byte) (Measurement, error) {
	var m Measurement
	if len(b) != crypto.HashSize {
		return m, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"tee: measurement must be 32 bytes",
			nil,
		)
	}
	copy(m[:], b)
	return m, nil
}

// MeasurementOf returns a deterministic measurement derived from the
// canonical bytes of a workload descriptor. Used by the simulator to
// generate test-stable measurements.
func MeasurementOf(canonicalDescriptor []byte) Measurement {
	return Measurement(crypto.SHA256(canonicalDescriptor))
}
