// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ai-continuity-platform/core/internal/contracts/audit_event"
	cchr "github.com/ai-continuity-platform/core/internal/contracts/cross_cloud_handshake_request"
	krt "github.com/ai-continuity-platform/core/internal/contracts/key_release_token"
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
)

// AuditEmitter is the abstraction the Coordinator uses to append
// audit events to the release-side audit chain. The chain itself is
// implemented in /internal/audit/chain — this interface keeps the kms
// package decoupled from chain internals (hash linking, signature
// over hash chain, persistence) and lets tests substitute a mock.
//
// Emit MUST be synchronous and atomic from the caller's perspective:
// either the event is durably appended and a non-zero AuditEventID is
// returned, or an error is returned and no chain mutation has
// occurred. Partial appends are not permitted.
type AuditEmitter interface {
	Emit(
		kind audit_event.Kind,
		payload []byte,
		sessionID ids.SessionID,
		manifestID ids.ManifestID,
		requestID ids.RequestID,
	) (ids.AuditEventID, error)
}

// IDGenerator produces fresh, unique identifiers for cross-cloud
// flows. The Coordinator generates one RequestID per CoordinateRestore
// invocation and one TokenID per KeyReleaseToken dispatched. Tests
// substitute deterministic generators; production uses crypto/rand.
type IDGenerator interface {
	NewRequestID() (ids.RequestID, error)
	NewDecisionID() (ids.DecisionID, error)
}

// NonceSource produces fresh handshake / wrap nonces. Separated from
// IDGenerator because nonces are raw bytes whereas IDs are typed
// strings, and tests for adversarial paths often want to substitute
// only one of them.
type NonceSource func(n int) ([]byte, error)

// Coordinator is the release-side orchestrator for cross-cloud
// KMS-mediated restore. It is constructed once at daemon startup with
// all dependencies injected. CoordinateRestore is safe for concurrent
// invocation across distinct DecisionIDs.
type Coordinator struct {
	auditChain  AuditEmitter
	keySigner   keys.Signer
	verifiers   *tee.Registry
	policy      KeyReleasePolicy
	wrapper     KeyWrapper
	transport   Transport
	idGenerator IDGenerator
	nonceSource NonceSource
	clock       shared_time.Clock
	signingKID  ids.KeyID
}

// Config bundles the Coordinator's dependencies. Every field is
// required (no implicit defaults) — operators construct the
// Coordinator explicitly so missing wiring fails at startup, not
// mid-flight.
type Config struct {
	AuditChain  AuditEmitter
	Signer      keys.Signer
	Verifiers   *tee.Registry
	Policy      KeyReleasePolicy
	Wrapper     KeyWrapper
	Transport   Transport
	IDGenerator IDGenerator
	NonceSource NonceSource
	Clock       shared_time.Clock

	// SigningKeyID is the source-authority signing key under
	// keys.PurposeSigningAuthority. Used to sign both the
	// CrossCloudHandshakeRequest and the KeyReleaseToken.
	SigningKeyID ids.KeyID
}

// NewCoordinator validates the Config and returns a ready-to-use
// Coordinator. Returns Structural errors when any required field is
// missing.
func NewCoordinator(cfg Config) (*Coordinator, error) {
	if cfg.AuditChain == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.NewCoordinator: AuditChain required", nil)
	}
	if cfg.Signer == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.NewCoordinator: Signer required", nil)
	}
	if cfg.Verifiers == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.NewCoordinator: Verifiers registry required", nil)
	}
	if cfg.Policy == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.NewCoordinator: Policy required", nil)
	}
	if cfg.Wrapper == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.NewCoordinator: Wrapper required", nil)
	}
	if cfg.Transport == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.NewCoordinator: Transport required", nil)
	}
	if cfg.IDGenerator == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.NewCoordinator: IDGenerator required", nil)
	}
	if cfg.NonceSource == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.NewCoordinator: NonceSource required", nil)
	}
	if cfg.Clock == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.NewCoordinator: Clock required", nil)
	}
	if cfg.SigningKeyID.IsZero() {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.NewCoordinator: SigningKeyID required", nil)
	}
	return &Coordinator{
		auditChain:  cfg.AuditChain,
		keySigner:   cfg.Signer,
		verifiers:   cfg.Verifiers,
		policy:      cfg.Policy,
		wrapper:     cfg.Wrapper,
		transport:   cfg.Transport,
		idGenerator: cfg.IDGenerator,
		nonceSource: cfg.NonceSource,
		clock:       cfg.Clock,
		signingKID:  cfg.SigningKeyID,
	}, nil
}

// KeyMaterial is the plaintext-DEK input the operator supplies to the
// Coordinator. The Coordinator wraps each entry under the
// destination's verified measurement and dispatches them in a
// KeyReleaseToken.
//
// The operator is responsible for sourcing the plaintext from its
// own keystore (typically by privileged unwrap inside the source TEE).
// The Coordinator does not interact with the operator's keystore —
// that boundary is intentional: the keystore stays sealed; the
// Coordinator only orchestrates the cross-cloud delivery.
type KeyMaterial struct {
	KeyID     ids.KeyID
	Purpose   uint8 // expected krt.PurposeSealing
	Plaintext []byte
}

// CoordinationRequest bundles all per-restore inputs.
type CoordinationRequest struct {
	DecisionID          ids.DecisionID
	DestinationKind     tee.Provider
	DestinationEndpoint string
	KeysToRelease       []KeyMaterial

	// SessionID and ManifestID are propagated into audit events as
	// correlators. Both may be zero if the cross-cloud operation
	// is not bound to a specific Session / Manifest (rare in
	// practice — the source-side ReleaseDecision typically supplies
	// both).
	SessionID  ids.SessionID
	ManifestID ids.ManifestID

	// SourceEvidence + SourceMeasurement are optional mutual-
	// attestation fields. When empty, the destination cannot
	// authenticate the source TEE; only the source authority's
	// signing key authenticates the handshake. Production
	// deployments SHOULD supply both for defence-in-depth.
	SourceEvidence    []byte
	SourceMeasurement []byte

	// RecipientPublicKey, when set, switches DEK delivery to the X25519 KEM
	// (ADR 0009): each DEK is encapsulated to this attested X25519 PUBLIC key
	// instead of sealed under the destination measurement. It MUST be the
	// destination's in-TEE public key, bound to the verified Evidence
	// (REPORT_DATA = hash(pubkey || handshake nonce)), so only the destination
	// TEE — holding the private key — can unwrap. When empty, the legacy
	// symmetric measurement path (SimulatedKeyWrapper, simulation only) is used.
	RecipientPublicKey []byte
}

// CoordinationResult is returned on successful CoordinateRestore. All
// four IDs are populated when the function returns nil error; on
// failure, intermediate IDs may be populated to assist diagnostics.
//
// The CompletionAuditID is NOT populated by CoordinateRestore — it
// is filled in by a later RecordCompletion call once the destination
// signals successful restore.
type CoordinationResult struct {
	HandshakeRequestID     ids.RequestID
	HandshakeAuditID       ids.AuditEventID
	AttestationAuditID     ids.AuditEventID
	KeyReleaseAuditID      ids.AuditEventID
	DestinationMeasurement []byte
	PolicyVersion          string
	TokenID                ids.DecisionID
	DispatchedAt           time.Time
}

// --- Audit payload types -------------------------------------------

// handshakeInitiatedPayload is the JSON payload of a
// KindCrossCloudHandshakeInitiated audit event. The handshake nonce
// itself is NOT included — only its SHA-256 hash, so the audit chain
// can correlate without leaking the nonce value.
type handshakeInitiatedPayload struct {
	DecisionID          ids.DecisionID `json:"decision_id"`
	RequestID           ids.RequestID  `json:"request_id"`
	DestinationKind     tee.Provider   `json:"destination_kind"`
	DestinationEndpoint string         `json:"destination_endpoint"`
	HandshakeNonceHash  []byte         `json:"handshake_nonce_hash"`
	HandshakeNonceLen   int            `json:"handshake_nonce_len"`
	InitiatedAt         time.Time      `json:"initiated_at"`
}

// attestationVerifiedPayload is the JSON payload of a
// KindCrossCloudAttestationVerified audit event.
type attestationVerifiedPayload struct {
	DecisionID             ids.DecisionID `json:"decision_id"`
	RequestID              ids.RequestID  `json:"request_id"`
	DestinationKind        tee.Provider   `json:"destination_kind"`
	DestinationMeasurement []byte         `json:"destination_measurement"`
	EvidenceHash           []byte         `json:"evidence_hash"`
	VerifiedAt             time.Time      `json:"verified_at"`
}

// keyReleaseAuthorizedPayload is the JSON payload of a
// KindKeyReleaseAuthorized audit event. Recorded only on policy
// approval; denial returns an error and emits no Authorized event.
type keyReleaseAuthorizedPayload struct {
	DecisionID             ids.DecisionID `json:"decision_id"`
	RequestID              ids.RequestID  `json:"request_id"`
	TokenID                ids.DecisionID `json:"token_id"`
	DestinationKind        tee.Provider   `json:"destination_kind"`
	DestinationMeasurement []byte         `json:"destination_measurement"`
	KeyIDs                 []ids.KeyID    `json:"key_ids"`
	PolicyVersion          string         `json:"policy_version"`
	PolicyReason           string         `json:"policy_reason"`
	AuthorizedAt           time.Time      `json:"authorized_at"`
}

// completedPayload is the JSON payload of a KindCrossCloudRestoreCompleted
// audit event recorded asynchronously via RecordCompletion.
type completedPayload struct {
	DecisionID         ids.DecisionID `json:"decision_id"`
	RequestID          ids.RequestID  `json:"request_id"`
	TokenID            ids.DecisionID `json:"token_id"`
	RestoredGenomeHash []byte         `json:"restored_genome_hash"`
	DestinationOutcome string         `json:"destination_outcome"`
	CompletedAt        time.Time      `json:"completed_at"`
}

// --- Coordinator main logic ----------------------------------------

// CoordinateRestore runs the full cross-cloud handshake → verify →
// policy → wrap → dispatch flow synchronously. Returns once the
// KeyReleaseToken has been dispatched; the destination's restore
// completion is signalled out-of-band and recorded via
// RecordCompletion.
//
// The function emits exactly three audit events on the success path
// (Handshake → Attestation → KeyRelease). Each emission is
// audit-first-class: the record is durably appended BEFORE the
// outward action it describes is taken.
//
// On any failure, the function returns immediately. Already-emitted
// audit events stay in the chain — they record what was decided up
// to the point of failure, which is the desired audit-trail
// behaviour.
func (c *Coordinator) CoordinateRestore(
	ctx context.Context,
	req CoordinationRequest,
) (CoordinationResult, error) {
	if err := c.validateRequest(req); err != nil {
		return CoordinationResult{}, err
	}

	// 1. Generate request id + handshake nonce.
	requestID, err := c.idGenerator.NewRequestID()
	if err != nil {
		return CoordinationResult{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"kms.CoordinateRestore: request id generation failed",
			err,
		)
	}
	nonce, err := c.nonceSource(tee.NonceMinBytes)
	if err != nil {
		return CoordinationResult{}, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"kms.CoordinateRestore: nonce generation failed",
			err,
		)
	}
	if len(nonce) < tee.NonceMinBytes {
		return CoordinationResult{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.CoordinateRestore: nonceSource returned %d bytes; minimum is %d", len(nonce), tee.NonceMinBytes),
			nil,
		)
	}

	now := c.clock.Now().UTC()

	// 2. Emit KindCrossCloudHandshakeInitiated BEFORE dispatch.
	nonceHash := crypto.SHA256(nonce)
	hsPayload, err := json.Marshal(handshakeInitiatedPayload{
		DecisionID:          req.DecisionID,
		RequestID:           requestID,
		DestinationKind:     req.DestinationKind,
		DestinationEndpoint: req.DestinationEndpoint,
		HandshakeNonceHash:  nonceHash[:],
		HandshakeNonceLen:   len(nonce),
		InitiatedAt:         now,
	})
	if err != nil {
		return CoordinationResult{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"kms.CoordinateRestore: handshake audit payload marshal failed",
			err,
		)
	}
	hsAuditID, err := c.auditChain.Emit(
		audit_event.KindCrossCloudHandshakeInitiated,
		hsPayload,
		req.SessionID,
		req.ManifestID,
		requestID,
	)
	if err != nil {
		return CoordinationResult{}, err
	}

	// 3. Build + sign + dispatch CrossCloudHandshakeRequest.
	hsReq := cchr.CrossCloudHandshakeRequest{
		SchemaVersion:       cchr.SchemaVersionCurrent,
		RequestID:           requestID,
		DecisionID:          req.DecisionID,
		DestinationTEEKind:  req.DestinationKind,
		DestinationEndpoint: req.DestinationEndpoint,
		HandshakeNonce:      nonce,
		SourceEvidence:      req.SourceEvidence,
		SourceMeasurement:   req.SourceMeasurement,
		InitiatedAt:         now,
		SigningKeyID:        c.signingKID,
		// Signature filled by SignWith.
		AuditEventID: hsAuditID,
	}
	// Pre-fill a sentinel signature so Validate (called by SignWith→
	// CanonicalJSON's contract caller chain) does not reject; SignWith
	// nulls the signature and signs over the canonical bytes anyway.
	hsReq.Signature = []byte{0x00}
	if err := hsReq.SignWith(c.keySigner); err != nil {
		return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID}, err
	}

	hsResp, err := c.transport.SendHandshakeRequest(ctx, req.DestinationEndpoint, hsReq)
	if err != nil {
		return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID},
			shared_errors.Operational(
				shared_errors.CodeResourceExhausted,
				"kms.CoordinateRestore: handshake transport failed",
				err,
			)
	}
	if len(hsResp.Evidence) == 0 {
		return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID},
			shared_errors.Integrity(
				shared_errors.CodeAttestationDenied,
				"kms.CoordinateRestore: destination returned empty Evidence",
				nil,
			)
	}

	// 4. Verify destination's Evidence.
	verifier, err := c.verifiers.Resolve(req.DestinationKind)
	if err != nil {
		return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID}, err
	}
	measurement, err := verifier.Verify(hsResp.Evidence, nonce)
	if err != nil {
		return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID},
			shared_errors.Integrity(
				shared_errors.CodeAttestationDenied,
				"kms.CoordinateRestore: destination Evidence verification failed",
				err,
			)
	}
	measurementBytes := measurement[:]

	// 5. Emit KindCrossCloudAttestationVerified.
	evidenceHash := crypto.SHA256(hsResp.Evidence)
	avPayload, err := json.Marshal(attestationVerifiedPayload{
		DecisionID:             req.DecisionID,
		RequestID:              requestID,
		DestinationKind:        req.DestinationKind,
		DestinationMeasurement: measurementBytes,
		EvidenceHash:           evidenceHash[:],
		VerifiedAt:             c.clock.Now().UTC(),
	})
	if err != nil {
		return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID},
			shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"kms.CoordinateRestore: attestation audit payload marshal failed",
				err,
			)
	}
	avAuditID, err := c.auditChain.Emit(
		audit_event.KindCrossCloudAttestationVerified,
		avPayload,
		req.SessionID,
		req.ManifestID,
		requestID,
	)
	if err != nil {
		return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID}, err
	}

	// 6. Apply policy.
	keyIDs := make([]ids.KeyID, 0, len(req.KeysToRelease))
	for _, k := range req.KeysToRelease {
		keyIDs = append(keyIDs, k.KeyID)
	}
	verdict, err := c.policy.AuthorizeKeyRelease(req.DestinationKind, measurementBytes, req.DecisionID, keyIDs)
	if err != nil {
		return CoordinationResult{
			HandshakeRequestID:     requestID,
			HandshakeAuditID:       hsAuditID,
			AttestationAuditID:     avAuditID,
			DestinationMeasurement: measurementBytes,
		}, err
	}
	if !verdict.Authorized {
		return CoordinationResult{
				HandshakeRequestID:     requestID,
				HandshakeAuditID:       hsAuditID,
				AttestationAuditID:     avAuditID,
				DestinationMeasurement: measurementBytes,
			},
			shared_errors.Authority(
				shared_errors.CodeAttestationDenied,
				fmt.Sprintf("kms.CoordinateRestore: policy denied key release: %s", verdict.Reason),
				nil,
			)
	}

	// 7. Allocate token id; build per-key wraps.
	tokenID, err := c.idGenerator.NewDecisionID()
	if err != nil {
		return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID, AttestationAuditID: avAuditID, DestinationMeasurement: measurementBytes},
			shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"kms.CoordinateRestore: token id generation failed",
				err,
			)
	}
	wrappedKeys := make([]krt.WrappedKey, 0, len(req.KeysToRelease))
	for i, m := range req.KeysToRelease {
		if m.Purpose != krt.PurposeSealing {
			return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID, AttestationAuditID: avAuditID, DestinationMeasurement: measurementBytes},
				shared_errors.Structural(
					shared_errors.CodeFieldValueInvalid,
					fmt.Sprintf("kms.CoordinateRestore: KeysToRelease[%d].Purpose must be PurposeSealing (=%d); got %d", i, krt.PurposeSealing, m.Purpose),
					nil,
				)
		}
		aad := canonicalWrapAAD(tokenID, measurementBytes, m.KeyID)
		// X25519 KEM (ADR 0009) when an attested recipient pubkey is present;
		// otherwise the legacy symmetric measurement path.
		keyMaterial := measurementBytes
		if len(req.RecipientPublicKey) > 0 {
			keyMaterial = req.RecipientPublicKey
		}
		ct, err := c.wrapper.Wrap(m.Plaintext, keyMaterial, aad)
		if err != nil {
			return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID, AttestationAuditID: avAuditID, DestinationMeasurement: measurementBytes}, err
		}
		wrappedKeys = append(wrappedKeys, krt.WrappedKey{
			KeyID:      m.KeyID,
			Purpose:    m.Purpose,
			Ciphertext: ct,
			AAD:        aad,
		})
	}

	authorizedAt := c.clock.Now().UTC()

	// 8. Emit KindKeyReleaseAuthorized BEFORE dispatching token.
	krPayload, err := json.Marshal(keyReleaseAuthorizedPayload{
		DecisionID:             req.DecisionID,
		RequestID:              requestID,
		TokenID:                tokenID,
		DestinationKind:        req.DestinationKind,
		DestinationMeasurement: measurementBytes,
		KeyIDs:                 keyIDs,
		PolicyVersion:          c.policy.PolicyVersion(),
		PolicyReason:           verdict.Reason,
		AuthorizedAt:           authorizedAt,
	})
	if err != nil {
		return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID, AttestationAuditID: avAuditID, DestinationMeasurement: measurementBytes},
			shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"kms.CoordinateRestore: key release audit payload marshal failed",
				err,
			)
	}
	krAuditID, err := c.auditChain.Emit(
		audit_event.KindKeyReleaseAuthorized,
		krPayload,
		req.SessionID,
		req.ManifestID,
		requestID,
	)
	if err != nil {
		return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID, AttestationAuditID: avAuditID, DestinationMeasurement: measurementBytes}, err
	}

	// 9. Build + sign + dispatch KeyReleaseToken.
	token := krt.KeyReleaseToken{
		SchemaVersion:          krt.SchemaVersionCurrent,
		TokenID:                tokenID,
		DecisionID:             req.DecisionID,
		RequestID:              requestID,
		DestinationMeasurement: measurementBytes,
		Wrapped:                wrappedKeys,
		PolicyVersion:          c.policy.PolicyVersion(),
		AuthorizedAt:           authorizedAt,
		SigningKeyID:           c.signingKID,
		AuditEventID:           krAuditID,
		Signature:              []byte{0x00},
	}
	if err := token.SignWith(c.keySigner); err != nil {
		return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID, AttestationAuditID: avAuditID, KeyReleaseAuditID: krAuditID, DestinationMeasurement: measurementBytes}, err
	}
	if err := c.transport.SendKeyReleaseToken(ctx, req.DestinationEndpoint, token); err != nil {
		return CoordinationResult{HandshakeRequestID: requestID, HandshakeAuditID: hsAuditID, AttestationAuditID: avAuditID, KeyReleaseAuditID: krAuditID, DestinationMeasurement: measurementBytes},
			shared_errors.Operational(
				shared_errors.CodeResourceExhausted,
				"kms.CoordinateRestore: token transport failed",
				err,
			)
	}

	return CoordinationResult{
		HandshakeRequestID:     requestID,
		HandshakeAuditID:       hsAuditID,
		AttestationAuditID:     avAuditID,
		KeyReleaseAuditID:      krAuditID,
		DestinationMeasurement: measurementBytes,
		PolicyVersion:          c.policy.PolicyVersion(),
		TokenID:                tokenID,
		DispatchedAt:           authorizedAt,
	}, nil
}

// RecordCompletion is called once the destination signals that it
// successfully unwrapped the keys and completed local restore. This
// is the audit slot for KindCrossCloudRestoreCompleted — separated
// from CoordinateRestore because completion is asynchronous and may
// arrive minutes or hours later via an out-of-band channel.
//
// The caller supplies the original DecisionID + TokenID + RequestID
// so the audit record cross-references the earlier
// KindKeyReleaseAuthorized event.
func (c *Coordinator) RecordCompletion(
	decisionID ids.DecisionID,
	tokenID ids.DecisionID,
	requestID ids.RequestID,
	restoredGenomeHash []byte,
	destinationOutcome string,
	sessionID ids.SessionID,
	manifestID ids.ManifestID,
) (ids.AuditEventID, error) {
	if decisionID.IsZero() {
		return "", shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.RecordCompletion: decision_id required", nil)
	}
	if tokenID.IsZero() {
		return "", shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.RecordCompletion: token_id required", nil)
	}
	if requestID.IsZero() {
		return "", shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.RecordCompletion: request_id required", nil)
	}
	if destinationOutcome == "" {
		return "", shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.RecordCompletion: destination_outcome required", nil)
	}
	payload, err := json.Marshal(completedPayload{
		DecisionID:         decisionID,
		RequestID:          requestID,
		TokenID:            tokenID,
		RestoredGenomeHash: restoredGenomeHash,
		DestinationOutcome: destinationOutcome,
		CompletedAt:        c.clock.Now().UTC(),
	})
	if err != nil {
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms.RecordCompletion: payload marshal failed", err)
	}
	return c.auditChain.Emit(audit_event.KindCrossCloudRestoreCompleted, payload, sessionID, manifestID, requestID)
}

// validateRequest runs structural checks on a CoordinationRequest.
// The request must specify a non-zero DecisionID, a known
// DestinationKind, a non-empty DestinationEndpoint, and at least one
// KeyMaterial entry with non-empty plaintext.
func (c *Coordinator) validateRequest(req CoordinationRequest) error {
	if req.DecisionID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.CoordinateRestore: DecisionID required", nil)
	}
	if req.DestinationKind == "" {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.CoordinateRestore: DestinationKind required", nil)
	}
	if !c.verifiers.Has(req.DestinationKind) {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.CoordinateRestore: no verifier registered for %q (available: %v)", req.DestinationKind, c.verifiers.Providers()),
			nil,
		)
	}
	if req.DestinationEndpoint == "" {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.CoordinateRestore: DestinationEndpoint required", nil)
	}
	if len(req.KeysToRelease) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.CoordinateRestore: KeysToRelease must contain at least one key", nil)
	}
	for i, m := range req.KeysToRelease {
		if m.KeyID.IsZero() {
			return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, fmt.Sprintf("kms.CoordinateRestore: KeysToRelease[%d].KeyID required", i), nil)
		}
		if len(m.Plaintext) == 0 {
			return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, fmt.Sprintf("kms.CoordinateRestore: KeysToRelease[%d].Plaintext required", i), nil)
		}
	}
	if len(req.SourceMeasurement) != 0 && len(req.SourceMeasurement) != cchr.MeasurementSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.CoordinateRestore: SourceMeasurement must be exactly %d bytes when present", cchr.MeasurementSize),
			nil,
		)
	}
	return nil
}

// canonicalWrapAAD computes the AAD bound into each WrappedKey's
// AES-GCM tag. The AAD is SHA-256(TokenID || DestinationMeasurement
// || KeyID), encoded as raw bytes. Both source-side wrapping and
// destination-side unwrapping derive identical AAD.
func canonicalWrapAAD(tokenID ids.DecisionID, destinationMeasurement []byte, keyID ids.KeyID) []byte {
	buf := make([]byte, 0, len(tokenID)+len(destinationMeasurement)+len(keyID))
	buf = append(buf, []byte(tokenID)...)
	buf = append(buf, destinationMeasurement...)
	buf = append(buf, []byte(keyID)...)
	h := crypto.SHA256(buf)
	return h[:]
}
