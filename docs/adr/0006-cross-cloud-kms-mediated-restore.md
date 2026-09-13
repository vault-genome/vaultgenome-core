# ADR 0006: Cross-Cloud KMS-Mediated Restore

**Status:** Proposed (Phase 4)
**Date:** 2026-05-09
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Phase:** Phase 4 — production-ready cross-cloud workload portability

---

## Status

Proposed. Implementation starts 2026-05-09; target merge by 2026-05-16.

This ADR extends ADR 0001 (frozen Producer/Verifier/Sealer interface) and ADR 0002 (multi-TEE adapter dispatch). It is consistent with R-10 (TEE adapter dispatch), R-11 (Reconstructor swap discipline), and R-14 (frozen wire contracts with versioned schemas).

---

## Context

Phase 2P / 2Q closed with four production-ready TEE backends — AWS Nitro Enclaves, Azure SGX, GCP SEV-SNP, simulator — each independently validated end-to-end on hardware-attested cohorts. The fifth backend (Azure SEV-SNP) is code-complete and awaits Microsoft's PAYG platform rollout. Today, however, the platform's recovery flow operates inside a **single TEE family at a time**: a workload sealed under Azure SGX can only be restored under Azure SGX. Customers in regulated industries (banking, healthcare, sovereign government) require the next capability tier:

- A workload sealed in **TEE A** (e.g., GCP SEV-SNP)
- Recovered byte-identically inside **TEE B** (e.g., AWS Nitro Enclave)
- With the decryption key released **only after** TEE B proves itself to TEE A's authority via cross-cloud attestation handshake
- And every state transition recorded in the audit chain with non-repudiable signatures

This is the **cross-cloud KMS-mediated restore** capability. No commercial competitor offers it today. It is the headline investor demo and the foundational primitive for sovereign-AI continuity across hyperscalers.

### Why this is hard

1. Each TEE family has its own attestation chain (AWS PCA root, AMD VCEK, Intel attestation key, MAA dual-PKI, Microsoft Azure JWT). A verifier must hold roots of trust for **all source vendors** that may have sealed material.
2. The existing `tee.Verifier` interface is **frozen** (R-10, ADR 0001) — single Provider per dispatch. Cross-cloud requires multiple verifiers active simultaneously without modifying the frozen interface.
3. Audit-first-class invariant (Doctrinal Invariant #8) requires every authority decision to emit an `AuditEvent` *before* the decision becomes visible to callers. Cross-cloud introduces 4 new authority decision points, each requiring a Kind.
4. The release-side authority and the destination-side bootstrap orchestrator must agree on a shared cryptographic protocol for the handshake. The protocol must be replay-resistant, non-repudiable, and attestation-bound.
5. Wire-contract freezing (R-14) means new functionality is added by introducing **new contracts** (with `SchemaVersionMin = SchemaVersionMax = SchemaVersionCurrent = 1`) or **safe extension** of existing contracts (Min stays, Max bumps). Never reorder, never reinterpret.

---

## Decision

We add cross-cloud KMS-mediated restore as an **optional orchestration mode** that the existing 8-stage release-side lifecycle can opt into. The local single-TEE flow is unchanged. The new mode introduces:

1. **Verifier Registry** — wraps existing `tee.BuildVerifier` factory; allows multiple verifiers (one per source-TEE family) to be loaded into one process.
2. **KMS Coordinator** — release-side orchestrator that runs the cross-cloud attestation handshake, applies a `KeyReleasePolicy`, and authorizes wrapped-key delivery.
3. **Two new wire contracts** — `cross_cloud_handshake_request` and `key_release_token`, both at SchemaVersion 1.
4. **Four new audit Kinds** with `audit_event` schema bumped v3 → v4: `KindCrossCloudHandshakeInitiated`, `KindCrossCloudAttestationVerified`, `KindKeyReleaseAuthorized`, `KindCrossCloudRestoreCompleted`.
5. **State machine extension** — optional Stage 8.5 (`StateCrossCloudHandshake`) inserted between `StateRelease` and the existing `StateAuditChainClosed`.
6. **CrossCloudReceiver** — destination-side handler that validates source authority signatures, generates local Evidence, receives `KeyReleaseToken`, and unwraps DEKs into the local keystore for the existing bootstrap orchestrator to consume.
7. **SDK extensions** — `submit_cross_cloud_restore()` and `poll_cross_cloud_restore()` on `acp_sdk.ACPClient`.

The frozen R-10 interfaces (`Producer`, `Verifier`, `Sealer`) are **not modified**. The frozen R-11 `Reconstructor` interface is **not modified**. The 14 existing wire contracts are **not modified** (one of them, `release_decision`, may receive a safe Max bump in v2 to add an optional `CrossCloudRestoreID` reference; this is a backward-compatible extension).

---

## Consequences

### Positive

- The headline investor capability lands without breaking any frozen contract or interface.
- Local single-TEE flows are unaffected — existing customers see zero behavioral change.
- New code is additive: 1 new ADR, 1 new package (`internal/vault/kms/`), 2 new contract subdirectories, 4 new audit Kinds, 1 new state, ~6 new SDK methods. All under doctrinal CI enforcement.
- Sets up Phase 5 cleanly: NVIDIA H100 Confidential Compute joins the verifier registry as a new entry; no further architectural change required.
- The audit chain is the integration point for compliance auditors (DORA, OCC, FDA): every cross-cloud key release is hash-chained, signed, and replayable.

### Negative / risks

- **Verifier registry is now a multi-vendor trust store** — operational complexity rises (per-vendor root rotation, vendor compromise scenarios). Mitigated by: (a) registry is read-only after process startup, (b) all verifiers fail closed on unknown roots, (c) policy enforces measurement allow-listing.
- **Key release policy is a new authority decision point** — it must be audit-first-class (covered by `KindKeyReleaseAuthorized`).
- **Cross-cloud handshake transport is new wire surface** — must be tested adversarially: replay, MITM, vendor-attestation forgery, measurement substitution.
- **Coordination test surface grows** — adversarial scenarios increase from ~149 to ~190; CI runtime grows ~15%.

### Neutral

- The receive-side (destination) must run a daemon that holds the `tee.Sealer` capability for its local TEE; this is the existing `acp-bootstrap` daemon plus a new `CrossCloudReceiver` handler. No new daemon process is introduced.
- No new external dependencies. All cryptography uses existing primitives (Ed25519 signing, AES-256-GCM sealing, SHA-256 hashing).

---

## Detailed Design

### Protocol Flow (cross-cloud GCP→AWS example)

```
┌─────────────────────┐         ┌──────────────────────┐         ┌─────────────────────┐
│  Operator (CLI/SDK) │         │  Release Authority   │         │ Destination Bootstrap│
│                     │         │  (sagvd, GCP-side)   │         │  (acp-bootstrap, AWS)│
└──────────┬──────────┘         └───────────┬──────────┘         └──────────┬──────────┘
           │                                │                                │
           │  1. submit_cross_cloud_restore │                                │
           │     (release_decision_id,      │                                │
           │      destination_tee_kind,     │                                │
           │      destination_endpoint)     │                                │
           │───────────────────────────────>│                                │
           │                                │                                │
           │                                │ 2. Generate handshake nonce    │
           │                                │    (16+ bytes /dev/urandom)    │
           │                                │                                │
           │                                │ 3. EMIT AuditEvent             │
           │                                │    KindCrossCloudHandshake     │
           │                                │    Initiated                   │
           │                                │                                │
           │                                │ 4. Send                        │
           │                                │    CrossCloudHandshakeRequest  │
           │                                │    (signed by source authority)│
           │                                │───────────────────────────────>│
           │                                │                                │
           │                                │                                │ 5. Verify source
           │                                │                                │    authority signature
           │                                │                                │    (pre-loaded source
           │                                │                                │     authority pubkey)
           │                                │                                │
           │                                │                                │ 6. Local TEE Producer:
           │                                │                                │    Quote(handshake_nonce)
           │                                │                                │    → destination Evidence
           │                                │                                │
           │                                │ 7. Send Evidence + measurement │
           │                                │<───────────────────────────────│
           │                                │                                │
           │                                │ 8. Resolve verifier for        │
           │                                │    destination_tee_kind via    │
           │                                │    VerifierRegistry            │
           │                                │                                │
           │                                │ 9. Verify Evidence;            │
           │                                │    extract Measurement         │
           │                                │                                │
           │                                │ 10. EMIT AuditEvent            │
           │                                │     KindCrossCloudAttestation  │
           │                                │     Verified                   │
           │                                │                                │
           │                                │ 11. Apply KeyReleasePolicy     │
           │                                │     (measurement allow-list,   │
           │                                │      vendor allow-list,        │
           │                                │      decision_id binding)      │
           │                                │                                │
           │                                │ 12. EMIT AuditEvent            │
           │                                │     KindKeyReleaseAuthorized   │
           │                                │                                │
           │                                │ 13. For each DEK in scope:     │
           │                                │     destSealer.Seal(dek, aad)  │
           │                                │     where destSealer is        │
           │                                │     reconstructed from         │
           │                                │     destination Measurement    │
           │                                │                                │
           │                                │ 14. Send                       │
           │                                │     KeyReleaseToken(           │
           │                                │       wrapped_keys,            │
           │                                │       destination_measurement, │
           │                                │       signature                │
           │                                │     )                          │
           │                                │───────────────────────────────>│
           │                                │                                │
           │                                │                                │ 15. Verify token signature
           │                                │                                │     (source authority key)
           │                                │                                │
           │                                │                                │ 16. Verify token's
           │                                │                                │     destination_measurement
           │                                │                                │     == local measurement
           │                                │                                │
           │                                │                                │ 17. local Sealer.Unseal()
           │                                │                                │     each wrapped key
           │                                │                                │
           │                                │                                │ 18. Register unwrapped
           │                                │                                │     keys in local
           │                                │                                │     keystore
           │                                │                                │
           │                                │                                │ 19. Resume existing
           │                                │                                │     bootstrap orchestrator
           │                                │                                │     (Stage F flow:
           │                                │                                │      DisclosureMessage
           │                                │                                │      reception →
           │                                │                                │      reassembly →
           │                                │                                │      receive-side
           │                                │                                │      validation →
           │                                │                                │      ReconstitutionDecision)
           │                                │                                │
           │                                │ 20. Restore complete signal    │
           │                                │     (out-of-band per ops doc)  │
           │                                │<───────────────────────────────│
           │                                │                                │
           │                                │ 21. EMIT AuditEvent            │
           │                                │     KindCrossCloudRestore      │
           │                                │     Completed                  │
           │                                │                                │
           │  22. poll_cross_cloud_restore  │                                │
           │      → status: COMPLETE        │                                │
           │<───────────────────────────────│                                │
           │                                │                                │
```

### Audit Kinds (v4)

```go
// Cross-cloud (SchemaVersion 4). Added in Phase 4 to bind cross-cloud
// authority decisions into the release-side audit chain. Each cross-cloud
// restore emits four kinds in order:
//
//  1. KindCrossCloudHandshakeInitiated — recorded BEFORE the handshake
//     request is dispatched to the destination.
//  2. KindCrossCloudAttestationVerified — recorded AFTER local
//     verification of the destination's Evidence and BEFORE the
//     KeyReleasePolicy is applied.
//  3. KindKeyReleaseAuthorized — recorded AFTER policy approval and
//     BEFORE the KeyReleaseToken is dispatched. Pins the destination
//     measurement, key IDs released, and policy version.
//  4. KindCrossCloudRestoreCompleted — recorded after the destination
//     signals successful restore (out-of-band confirmation).
//
// All four kinds are release-side; the receive-side chain records its
// existing KindDisclosureReceived / KindRecvValidationStarted /
// KindRecvValidationCompleted / KindReconstitutionDecided as today —
// the cross-cloud handshake adds NO new receive-side kinds because the
// receive-side decision points are unchanged (DEKs are simply unwrapped
// before disclosure messages flow).
KindCrossCloudHandshakeInitiated  Kind = "CROSS_CLOUD_HANDSHAKE_INITIATED"
KindCrossCloudAttestationVerified Kind = "CROSS_CLOUD_ATTESTATION_VERIFIED"
KindKeyReleaseAuthorized          Kind = "KEY_RELEASE_AUTHORIZED"
KindCrossCloudRestoreCompleted    Kind = "CROSS_CLOUD_RESTORE_COMPLETED"
```

Schema bump:
```go
SchemaVersionMin     uint16 = 1   // unchanged — v1 readers must still reject v4
SchemaVersionMax     uint16 = 4   // bumped 3 → 4
SchemaVersionCurrent uint16 = 4   // bumped 3 → 4
```

`TestInvariant_08_AuditFirstClass` updated to assert these four kinds are present in the Kind enum (additive assertion; does not retire existing required kinds).

### New Wire Contracts

#### `internal/contracts/cross_cloud_handshake_request/cross_cloud_handshake_request.go`

```go
type CrossCloudHandshakeRequest struct {
    SchemaVersion uint16

    RequestID  ids.RequestID
    DecisionID ids.DecisionID  // bound to the source-side ReleaseDecision

    // Destination identification.
    DestinationTEEKind tee.Provider  // "aws-nitro", "azure-sgx", "gcp-sev-snp", "intel-sgx-dcap"
    DestinationEndpoint string        // operator-supplied; not authenticated by this contract

    // Source authority asks destination to attest under this nonce.
    HandshakeNonce []byte  // ≥ 16 bytes per tee.NonceMinBytes

    // Source attestation Evidence (optional; allows mutual attestation).
    // When non-empty, the destination MUST verify this before responding.
    SourceEvidence    []byte           // tee.Evidence opaque
    SourceMeasurement tee.Measurement  // hex-encoded for canonicalization

    InitiatedAt time.Time

    SigningKeyID ids.KeyID
    Signature    []byte
}

const (
    SchemaVersionMin     uint16 = 1
    SchemaVersionMax     uint16 = 1
    SchemaVersionCurrent uint16 = 1
)
```

#### `internal/contracts/key_release_token/key_release_token.go`

```go
type KeyReleaseToken struct {
    SchemaVersion uint16

    TokenID    ids.DecisionID
    DecisionID ids.DecisionID  // bound to the same ReleaseDecision

    // Destination's verified measurement (must match what destination's
    // Sealer will produce locally).
    DestinationMeasurement tee.Measurement

    // Wrapped DEKs. Each entry is a key ID + ciphertext sealed under
    // the destination's TEE-derived sealing key. The destination's
    // local Sealer.Unseal() recovers the plaintext DEK.
    Wrapped []WrappedKey

    // Policy reference — the policy version applied at authorization.
    PolicyVersion string

    AuthorizedAt time.Time

    SigningKeyID ids.KeyID
    Signature    []byte
}

type WrappedKey struct {
    KeyID      ids.KeyID
    Purpose    keys.Purpose  // PurposeSealing typically
    Ciphertext []byte         // sealed under destination measurement
    AAD        []byte         // canonical (TokenID || DestMeasurement || KeyID)
}

const (
    SchemaVersionMin     uint16 = 1
    SchemaVersionMax     uint16 = 1
    SchemaVersionCurrent uint16 = 1
)
```

### Verifier Registry

`internal/shared/tee/registry.go` (new file).

```go
// Registry holds verifiers for multiple TEE Provider families
// simultaneously. Used by cross-cloud authorities that must verify
// Evidence from any of the supported source TEEs.
//
// Registry is read-only after construction. All Resolve calls are
// lock-free and safe for concurrent use.
type Registry struct {
    verifiers map[Provider]Verifier
}

// NewRegistry constructs a Registry from a slice of (Provider, VerifierSpec)
// pairs. Each spec is dispatched through BuildVerifier — the existing
// frozen factory — so new providers added to factory.go automatically
// become available here.
func NewRegistry(specs []RegistrySpec) (*Registry, error)

type RegistrySpec struct {
    Provider Provider
    Spec     VerifierSpec
}

// Resolve returns the Verifier for a given Provider, or a Structural
// error if the Provider is not registered. Resolve is the entry point
// for cross-cloud attestation flows.
func (r *Registry) Resolve(p Provider) (Verifier, error)

// Providers returns the set of Providers registered, in stable order.
func (r *Registry) Providers() []Provider
```

This wraps the existing `BuildVerifier` factory without modifying R-10 frozen interfaces. The construction path is: operator config → daemon startup → `NewRegistry(specs)` → registry passed into KMS Coordinator.

### KMS Coordinator

New package `internal/vault/kms/`.

```go
// Coordinator runs the cross-cloud attestation handshake and key release
// flow. It is invoked by the release-side authority's StagedSequencer
// after StateRelease and before StateAuditChainClosed when the
// orchestration mode is cross-cloud.
//
// All four cross-cloud audit kinds are emitted from this package. The
// audit chain is appended via the chain.Chain dependency (mirroring how
// the StagedSequencer wires audit today).
type Coordinator struct {
    chain          chain.Chain
    keyResolver    keys.Resolver
    keySigner      keys.Signer
    keySealer      keys.Sealer
    verifiers      *tee.Registry
    policy         KeyReleasePolicy
    transport      Transport
    clock          shared_time.Clock
    nonceProvider  func() ([]byte, error)
}

// CoordinateRestore runs the full handshake → verify → policy → wrap →
// dispatch flow synchronously, emitting audit events at each decision
// point. Returns the four AuditEventIDs in order.
func (c *Coordinator) CoordinateRestore(
    ctx context.Context,
    decisionID ids.DecisionID,
    destinationKind tee.Provider,
    destinationEndpoint string,
    keysToRelease []ids.KeyID,
) (CoordinationResult, error)

type CoordinationResult struct {
    HandshakeAuditID    ids.AuditEventID
    AttestationAuditID  ids.AuditEventID
    KeyReleaseAuditID   ids.AuditEventID
    CompletionAuditID   ids.AuditEventID  // may be nil if completion not yet signaled
    DestinationMeasurement tee.Measurement
    PolicyVersion        string
}

// KeyReleasePolicy gates whether wrapped keys are dispatched given a
// destination measurement. The MVP policy is an allow-list of
// (Provider, Measurement) pairs loaded from operator config; production
// will support attribute-based policy expressions.
type KeyReleasePolicy interface {
    AuthorizeKeyRelease(
        destinationKind tee.Provider,
        destinationMeasurement tee.Measurement,
        decisionID ids.DecisionID,
        keys []ids.KeyID,
    ) (PolicyVerdict, error)
    PolicyVersion() string
}

type PolicyVerdict struct {
    Authorized bool
    Reason     string  // diagnostic for audit payload
}

// Transport abstracts the wire delivery of CrossCloudHandshakeRequest
// and KeyReleaseToken to the destination, and the receipt of the
// destination's attestation response. The MVP transport is a TLS-mutual-
// authenticated HTTP/2 channel; alternative transports (e.g., gRPC
// over message bus) plug in here.
type Transport interface {
    SendHandshakeRequest(
        ctx context.Context,
        endpoint string,
        req cchr.CrossCloudHandshakeRequest,
    ) (cchr.CrossCloudHandshakeResponse, error)

    SendKeyReleaseToken(
        ctx context.Context,
        endpoint string,
        token krt.KeyReleaseToken,
    ) error
}
```

The Coordinator constructor (`New`) accepts all dependencies via parameters — no globals, no init(). This keeps the unit-test surface clean.

### State Machine Extension

Add `StateCrossCloudHandshake` between `StateRelease` and `StateAuditChainClosed`. The existing transition from `StateRelease → StateAuditChainClosed` remains valid for local single-TEE flows. The new transitions are:

```go
StateRelease → StateCrossCloudHandshake     // cross-cloud orchestration mode
StateCrossCloudHandshake → StateAuditChainClosed   // success
StateCrossCloudHandshake → StateIncident           // attestation failure / policy denial
```

The orchestration mode is determined by an explicit operator-supplied flag on `RecoveryRequest` (new optional field, gated by Max bump on `recovery_request` v1 → v2). Default is `local` (current behavior); cross-cloud is opt-in.

### CrossCloudReceiver (Destination Side)

`internal/bootstrap/cross_cloud_receiver.go` (new file).

```go
// CrossCloudReceiver handles the destination side of cross-cloud
// restore. It is wired into the acp-bootstrap daemon as a new HTTP/2
// handler.
type CrossCloudReceiver struct {
    auditChain    chain.Chain         // receive-side audit chain
    teeProducer   tee.Producer        // local TEE
    teeSealer     tee.Sealer          // local TEE — for unwrapping
    sourceVerifierRegistry *tee.Registry
    sourceAuthorityKeys    keys.Resolver  // pre-loaded source authority pubkeys
    localKeyStore keys.Signer         // typed wrapper exposing a Register method
    clock         shared_time.Clock
}

// HandleHandshakeRequest receives the source authority's handshake,
// verifies the source signature, generates local Evidence, returns
// the response. Synchronous.
func (r *CrossCloudReceiver) HandleHandshakeRequest(
    ctx context.Context,
    req cchr.CrossCloudHandshakeRequest,
) (cchr.CrossCloudHandshakeResponse, error)

// HandleKeyReleaseToken receives a signed token, verifies it, unwraps
// the embedded DEKs, and registers them in the local keystore for the
// existing bootstrap orchestrator to consume. Synchronous.
func (r *CrossCloudReceiver) HandleKeyReleaseToken(
    ctx context.Context,
    token krt.KeyReleaseToken,
) error
```

The destination uses the existing `acp-bootstrap` daemon's HTTP server; the new handler is wired alongside the existing `POST /v1/disclosures` and `POST /v1/manifests` endpoints.

### SDK Surface (Python)

```python
class ACPClient:
    # ... existing methods ...

    def submit_cross_cloud_restore(
        self,
        release_decision_id: str,
        destination_tee_kind: str,  # "aws-nitro" | "azure-sgx" | "gcp-sev-snp" | "intel-sgx-dcap"
        destination_endpoint: str,
        keys_to_release: list[str],
    ) -> str:
        """Initiate a cross-cloud KMS-mediated restore. Returns
        cross_cloud_restore_id for subsequent polling."""

    def poll_cross_cloud_restore(
        self,
        cross_cloud_restore_id: str,
    ) -> "CrossCloudRestoreStatus":
        """Returns the current state of the handshake (PENDING_HANDSHAKE,
        ATTESTATION_VERIFIED, KEY_RELEASE_AUTHORIZED, COMPLETED, FAILED)
        plus any audit event IDs accumulated."""

    def await_cross_cloud_restore(
        self,
        cross_cloud_restore_id: str,
        timeout: float = 300.0,
    ) -> "CrossCloudRestoreResult":
        """Blocks until COMPLETED or FAILED. Convenience wrapper over
        poll_cross_cloud_restore + tenacity."""
```

---

## Threat Model

### In scope (defenses required)

1. **Replay of stale handshake** → defended by handshake nonce (≥ 16 bytes fresh entropy per request).
2. **Replay of stale KeyReleaseToken** → defended by `TokenID` uniqueness + `AuthorizedAt` freshness check + `DecisionID` binding (token usable for one specific release decision only).
3. **MITM substituting destination Evidence** → defended by source authority verifying Evidence under fresh nonce; substitution attempts produce different Measurement → policy rejection.
4. **MITM substituting destination Measurement in KeyReleaseToken** → defended by destination's local `Sealer.Unseal()` failing on wrong measurement (the sealing key derives from local measurement; substituted token has wrapped keys for a different measurement).
5. **Compromised destination operator forwarding token to non-attested host** → token's wrapped keys are bound to a specific Measurement; only the destination TEE that produced that Measurement can unwrap.
6. **Compromised source authority issuing tokens to attacker-controlled destinations** → policy enforces destination Measurement allow-listing; defense-in-depth via operator-side audit review of `KindKeyReleaseAuthorized` events before they accumulate uncontested.
7. **Vendor-attestation forgery (e.g., faked AWS Nitro Evidence)** → defended by per-vendor Verifier loaded with vendor root certificate chain; forged Evidence fails signature verification.
8. **Cross-vendor measurement confusion** → defended by `DestinationTEEKind` field on token + `Provider`-keyed Verifier registry; an Intel-SGX measurement cannot satisfy an AMD-SEV-SNP destination claim.

### Out of scope (deferred)

1. **Compromised source-authority signing key** — out of scope for Phase 4; defended by HSM-backed signing in production deployments (post-Series A engineering).
2. **Side-channel leakage from destination TEE** — out of scope; managed by TEE vendor.
3. **Quantum-resistant signatures** — out of scope; deferred to Phase 6+ (PQC migration plan).
4. **Multi-party computation across N>2 TEEs** — out of scope for Phase 4; revisit if customer demand emerges.

---

## Test Strategy

### Unit tests (per package)

- `internal/contracts/cross_cloud_handshake_request`: round-trip canonicalize, signature verify, schema-version-fuzz, AAD canonicalization.
- `internal/contracts/key_release_token`: round-trip, signature, wrapped-key tamper detection, AAD canonicalization, time freshness.
- `internal/shared/tee/registry`: Resolve happy path, unknown Provider rejection, concurrent reader safety.
- `internal/vault/kms`: Coordinator state machine (every transition + every error path), policy verdict propagation to audit payload, Transport mock with replay/forgery scenarios.
- `internal/bootstrap/cross_cloud_receiver`: source signature verify, local Evidence generation, token unwrap, key registration into keystore.

### Integration tests

- `internal/integration/cross_cloud_demo_test.go` (new): End-to-end test using simulator + simulator (acting as "two clouds"), exercising the full 22-step protocol flow.
- `internal/integration/cross_cloud_real_pairs_test.go` (new, build-tagged): Run between actual TEE pairs (AWS↔GCP, AWS↔Azure SGX, GCP↔Azure SGX) when hardware is available; gated by build tag `e2e_real_tee`.

### Adversarial tests

Add ~40 new scenarios to existing 149:

- Replay of handshake with stale nonce.
- KeyReleaseToken modified after signing (each field tampered separately).
- DestinationMeasurement substituted in token.
- Wrong vendor Verifier resolved (Provider mismatch).
- Source signing key revoked between handshake and token issuance.
- Destination's TEE Producer returns an Evidence that decodes correctly but verifies under a different Measurement.
- Policy-denied destination attempts to consume a previously-issued token.
- Token's `DecisionID` does not match any active ReleaseDecision.

### Doctrine invariants

Update `TestInvariant_08_AuditFirstClass` to require the four new Kinds (additive). Update `TestInvariant_09_ContractsFrozen` to discover the two new contract subdirectories (additive). Add `TestInvariant_12_KMSCoordinatorAuditFirst` (new): asserts every Coordinator decision path emits a corresponding audit event before returning to caller.

---

## Migration Path

Phase 4 is purely additive. Existing deployments running single-TEE local flows continue to operate without modification. Operators that want cross-cloud restore opt in via:

1. Config: enable `cross_cloud.enabled = true` in daemon config + provide `cross_cloud.policy.measurement_allow_list` + `cross_cloud.transport.endpoints`.
2. Pre-flight: exchange source-authority Ed25519 public key with destination operators (out-of-band, one-time).
3. Pre-flight: pre-load destination's expected Measurement into source's policy.
4. First restore: source operator submits via SDK `submit_cross_cloud_restore()`; the four-step handshake flows automatically.

No data migration. No schema changes that break existing readers. Existing audit chains remain readable; new chains contain v4 events that v3 readers must reject (per `SchemaVersionMin = 1` discipline).

---

## Out of Scope (this ADR)

- Multi-source escrow (N>2 source authorities co-signing release).
- Time-limited tokens (token expiration semantics — current design uses `AuthorizedAt` freshness check at point of consumption, deferred to Phase 5).
- Persistent cross-cloud session (handshake amortized across many tokens — Phase 5 optimization).
- Browser-based operator console (CLI + SDK only for Phase 4).

These are recorded as future work in the project's open-decisions ledger.

---

## References

- ADR 0001 — Frozen Producer/Verifier/Sealer Interface (R-10)
- ADR 0002 — Multi-TEE Adapter Dispatch
- ADR 0004 — Doctrine Invariants as Tests
- docs/doctrine/bootstrap-contracts.md §5 — Contract Freezing Discipline
- docs/doctrine/open-decisions-resolved.md R-10, R-11, R-14
- docs/doctrine/validation-thresholds.md §9 — Audit-First-Class Discipline
- RFC 9334 §10.1 — Remote Attestation Evidence Nonce Sizing

---

**Implementation tracking:** see `docs/internal/status-journal.md` Phase 4 section. Implementation order is documented in the master execution plan (`/Users/serhiinikolaichuk/Desktop/Vault Genome — Accelerator Applications/08_Master_Plan.md` Track B).
