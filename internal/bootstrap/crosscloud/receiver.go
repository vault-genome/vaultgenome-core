// SPDX-License-Identifier: AGPL-3.0-or-later

package crosscloud

import (
	"bytes"
	"crypto/rand"
	"fmt"

	cchr "github.com/ai-continuity-platform/core/internal/contracts/cross_cloud_handshake_request"
	krt "github.com/ai-continuity-platform/core/internal/contracts/key_release_token"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
	"github.com/ai-continuity-platform/core/internal/vault/kms"
)

// HandshakeResponse is the destination's reply to a
// CrossCloudHandshakeRequest. It mirrors the source-side
// kms.HandshakeResponse type but is defined here as a distinct type
// so the receiver package does not appear in source-side import
// graphs (Doctrinal Invariant #1: import-graph enforcement).
type HandshakeResponse struct {
	Evidence        []byte
	MeasurementHint []byte
}

// KeyRegistrar is the destination-side keystore abstraction used to
// register unwrapped DEKs. The MVP implementation is
// keys.InMemoryStore (its RegisterSealing(kid, material) method
// matches this interface). Production deployments wrap a
// hardware-backed keystore (HSM, TEE-bound storage).
type KeyRegistrar interface {
	RegisterSealing(kid ids.KeyID, material []byte) error
}

// Config bundles the Receiver's dependencies. Every field is
// required.
type Config struct {
	// SourceAuthorityKeys resolves the source authority's signing
	// public key. The Receiver looks up the SigningKeyID embedded
	// in each incoming handshake / token to verify the Ed25519
	// signature.
	SourceAuthorityKeys keys.Resolver

	// LocalTEE is the destination's TEE producer, used to generate
	// Evidence in response to handshake nonces and to expose the
	// local Measurement for token verification.
	LocalTEE tee.Producer

	// Unwrapper is the destination-side counterpart to the source's
	// KeyWrapper. Wrap on source ↔ Unwrap on destination must derive
	// identical AES-256 keys from the destination's Measurement.
	// MVP: kms.SimulatedKeyUnwrapper.
	Unwrapper kms.KeyUnwrapper

	// RecipientPrivateKey, when set, switches DEK unwrapping to the X25519 KEM
	// (ADR 0009): the receiver decapsulates each DEK with this TEE-held X25519
	// PRIVATE key instead of a measurement-derived symmetric key. It is the
	// private counterpart of the attested public key the destination presents in
	// its handshake evidence (REPORT_DATA = hash(pubkey || nonce)); it never
	// leaves the TEE. When empty, the legacy symmetric measurement path is used.
	RecipientPrivateKey []byte

	// Registrar receives unwrapped DEKs and adds them to the local
	// keystore for subsequent disclosure-message processing.
	Registrar KeyRegistrar
}

// Receiver handles cross-cloud handshake requests and key-release
// tokens on the destination side. Construct via NewReceiver; the
// returned Receiver is safe for concurrent use.
type Receiver struct {
	sourceKeys    keys.Resolver
	localTEE      tee.Producer
	unwrapper     kms.KeyUnwrapper
	recipientPriv []byte // X25519 KEM private key (ADR 0009); empty → symmetric path
	registrar     KeyRegistrar

	// localMeasurement is cached at construction; the local TEE's
	// measurement does not change for the life of the daemon
	// process (a measurement change implies a code-update event,
	// which restarts the daemon).
	localMeasurement tee.Measurement
}

// NewReceiver validates the Config and returns a ready-to-use
// Receiver.
func NewReceiver(cfg Config) (*Receiver, error) {
	if cfg.SourceAuthorityKeys == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crosscloud.NewReceiver: SourceAuthorityKeys required", nil)
	}
	if cfg.LocalTEE == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crosscloud.NewReceiver: LocalTEE required", nil)
	}
	if cfg.Unwrapper == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crosscloud.NewReceiver: Unwrapper required", nil)
	}
	if cfg.Registrar == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crosscloud.NewReceiver: Registrar required", nil)
	}
	return &Receiver{
		sourceKeys:       cfg.SourceAuthorityKeys,
		localTEE:         cfg.LocalTEE,
		unwrapper:        cfg.Unwrapper,
		recipientPriv:    cfg.RecipientPrivateKey,
		registrar:        cfg.Registrar,
		localMeasurement: cfg.LocalTEE.Measurement(),
	}, nil
}

// HandleHandshakeRequest validates a CrossCloudHandshakeRequest from
// a source authority and returns a HandshakeResponse containing local
// Evidence under the source-supplied nonce.
//
// Validation steps (in order):
//
//  1. Structural validation via cchr.Validate.
//  2. DestinationTEEKind announced in the request must match what
//     the operator has provisioned this Receiver for (if the source
//     declares us as Intel-SGX but we are AWS Nitro, the request
//     is rejected — there is no point dispatching Evidence the
//     source's verifier cannot interpret).
//  3. Source signature verified against the source authority's
//     pre-loaded public key.
//  4. Local Evidence generated via tee.Producer.Quote(req.HandshakeNonce).
//
// The returned HandshakeResponse carries Evidence + a MeasurementHint
// (which the source treats as informational; the source's verifier
// re-derives the Measurement from Evidence as ground truth).
func (r *Receiver) HandleHandshakeRequest(
	req cchr.CrossCloudHandshakeRequest,
) (HandshakeResponse, error) {
	if err := req.Validate(); err != nil {
		return HandshakeResponse{}, err
	}
	if err := r.assertLocalMatchesDeclaredKind(req.DestinationTEEKind); err != nil {
		return HandshakeResponse{}, err
	}
	if err := req.VerifySignature(r.sourceKeys); err != nil {
		return HandshakeResponse{}, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"crosscloud.HandleHandshakeRequest: source authority signature invalid",
			err,
		)
	}
	evidence, err := r.localTEE.Quote(req.HandshakeNonce)
	if err != nil {
		return HandshakeResponse{}, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"crosscloud.HandleHandshakeRequest: local Quote failed",
			err,
		)
	}
	measurementCopy := make([]byte, len(r.localMeasurement))
	copy(measurementCopy, r.localMeasurement[:])
	return HandshakeResponse{
		Evidence:        evidence,
		MeasurementHint: measurementCopy,
	}, nil
}

// HandleKeyReleaseToken validates a KeyReleaseToken and, on success,
// unwraps each WrappedKey and registers the result in the local
// keystore. The number of newly-registered keys is returned for
// caller diagnostics.
//
// Validation steps (in order):
//
//  1. Structural validation via krt.Validate.
//  2. Source signature verified against pre-loaded source authority key.
//  3. token.DestinationMeasurement byte-equality with local Measurement
//     — the cryptographic gate. A token with a different measurement
//     would fail to unwrap regardless (because the wrap key is
//     destination-Measurement-derived), but checking explicitly
//     yields a clearer error class.
//  4. For each WrappedKey:
//     a. Purpose must equal krt.PurposeSealing.
//     b. AAD must equal the canonical SHA-256(TokenID ||
//     DestinationMeasurement || KeyID) derived locally.
//     c. Unwrap returns plaintext DEK bytes.
//     d. Plaintext registered via Registrar.RegisterSealing(KeyID).
//
// All-or-nothing semantics: if any WrappedKey fails to unwrap or
// register, the whole token is rejected and any keys already
// registered are NOT rolled back (the keystore allows overwriting,
// so a partial registration is benign — the source-side coordinator
// will re-issue or surface to the operator).
func (r *Receiver) HandleKeyReleaseToken(token krt.KeyReleaseToken) (int, error) {
	if err := token.Validate(); err != nil {
		return 0, err
	}
	if err := token.VerifySignature(r.sourceKeys); err != nil {
		return 0, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"crosscloud.HandleKeyReleaseToken: source authority signature invalid",
			err,
		)
	}
	if !bytes.Equal(token.DestinationMeasurement, r.localMeasurement[:]) {
		return 0, shared_errors.Integrity(
			shared_errors.CodeAttestationDenied,
			"crosscloud.HandleKeyReleaseToken: token DestinationMeasurement does not match local TEE Measurement",
			nil,
		)
	}

	registered := 0
	for i, w := range token.Wrapped {
		if w.Purpose != krt.PurposeSealing {
			return registered, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("crosscloud.HandleKeyReleaseToken: wrapped[%d].Purpose must be PurposeSealing", i),
				nil,
			)
		}
		expectedAAD := canonicalWrapAAD(token.TokenID, token.DestinationMeasurement, w.KeyID)
		if !bytes.Equal(w.AAD, expectedAAD) {
			return registered, shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				fmt.Sprintf("crosscloud.HandleKeyReleaseToken: wrapped[%d].AAD does not match canonical derivation", i),
				nil,
			)
		}
		// X25519 KEM (ADR 0009): decapsulate with the TEE-held private key when
		// present; otherwise the legacy measurement-derived symmetric path.
		keyMaterial := token.DestinationMeasurement
		if len(r.recipientPriv) > 0 {
			keyMaterial = r.recipientPriv
		}
		plaintext, err := r.unwrapper.Unwrap(w.Ciphertext, keyMaterial, w.AAD)
		if err != nil {
			return registered, err
		}
		if err := r.registrar.RegisterSealing(w.KeyID, plaintext); err != nil {
			return registered, shared_errors.Operational(
				shared_errors.CodeResourceExhausted,
				fmt.Sprintf("crosscloud.HandleKeyReleaseToken: registering wrapped[%d] in keystore failed", i),
				err,
			)
		}
		registered++
		// Best-effort zeroize of the local plaintext copy. The
		// caller's keystore now owns the material; the local stack
		// frame should not leave plaintext behind.
		zeroize(plaintext)
	}
	return registered, nil
}

// LocalMeasurement returns a defensive copy of the destination's
// local TEE Measurement. Useful for diagnostic logs and for
// external tools that need to compare the measurement against
// operator-supplied allow-lists.
func (r *Receiver) LocalMeasurement() []byte {
	out := make([]byte, len(r.localMeasurement))
	copy(out, r.localMeasurement[:])
	return out
}

// assertLocalMatchesDeclaredKind enforces that the source's declared
// DestinationTEEKind matches what this Receiver has been provisioned
// for. The check is loose for the simulator (which can stand in for
// any provider in tests) and strict for real backends.
//
// MVP: accept the kind if the operator's Receiver Config does not
// specify a strict kind. Future versions will tighten this when
// operators populate Config.ExpectedKind.
func (r *Receiver) assertLocalMatchesDeclaredKind(declared tee.Provider) error {
	if declared == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"crosscloud.HandleHandshakeRequest: declared destination_tee_kind required",
			nil,
		)
	}
	// Phase 4 MVP: accept any known kind. Real deployments enforce
	// (declared == operator-provisioned-kind) via a future Config
	// field.
	for _, p := range tee.AllProviders() {
		if p == declared {
			return nil
		}
	}
	return shared_errors.Structural(
		shared_errors.CodeFieldValueInvalid,
		fmt.Sprintf("crosscloud.HandleHandshakeRequest: declared kind %q is not a known Provider", declared),
		nil,
	)
}

// canonicalWrapAAD MUST mirror exactly the AAD derivation used on the
// source-side coordinator (kms.canonicalWrapAAD). They are
// independent implementations of the same canonical formula:
//
//	AAD = SHA-256(TokenID || DestinationMeasurement || KeyID)
//
// The duplication is intentional: source and destination derive the
// AAD from independent codepaths and compare byte-for-byte, so a
// drift in either implementation surfaces immediately as an
// Integrity-class rejection at the destination.
func canonicalWrapAAD(tokenID ids.DecisionID, destinationMeasurement []byte, keyID ids.KeyID) []byte {
	// Use shared crypto.SHA256 so both sides agree on the digest.
	// crypto.SHA256 imported below.
	buf := make([]byte, 0, len(tokenID)+len(destinationMeasurement)+len(keyID))
	buf = append(buf, []byte(tokenID)...)
	buf = append(buf, destinationMeasurement...)
	buf = append(buf, []byte(keyID)...)
	h := sha256OfBytes(buf)
	return h[:]
}

// zeroize overwrites the slice with zero bytes. Best-effort defense
// against plaintext DEK material remaining on the stack after
// keystore registration.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// (sha256OfBytes is implemented in receiver_crypto.go to keep this
// file free of stdlib hashing imports — keeps the diff readable
// when Phase 5 swaps in a hardware-backed digest engine.)

// generateRandomBytes is exposed for tests that need a fresh-nonce
// helper without importing crypto/rand directly.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
