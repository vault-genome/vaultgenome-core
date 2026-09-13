// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package kms (Key Management System) implements the release-side
// orchestrator for Phase 4 cross-cloud KMS-mediated restore.
//
// # Doctrinal role
//
// The Coordinator runs the cross-cloud attestation handshake, applies
// a KeyReleasePolicy to authorise key release, wraps DEKs under a
// destination-derived sealing key, and dispatches the resulting
// KeyReleaseToken to the destination's CrossCloudReceiver. Every
// authority decision the Coordinator makes is recorded in the audit
// chain BEFORE the decision becomes visible to its caller —
// audit-first-class invariant (Doctrinal Invariant #8) extended into
// cross-cloud authority decisions.
//
// The Coordinator emits four audit kinds, in strict order:
//
//  1. KindCrossCloudHandshakeInitiated — before the handshake request
//     is dispatched to the destination.
//  2. KindCrossCloudAttestationVerified — after local verification of
//     the destination's Evidence and BEFORE policy is consulted.
//  3. KindKeyReleaseAuthorized — after policy approval and BEFORE the
//     KeyReleaseToken is dispatched.
//  4. KindCrossCloudRestoreCompleted — recorded asynchronously once
//     the destination confirms successful restore (via
//     RecordCompletion).
//
// # Frozen boundaries respected
//
// The R-10 TEE interfaces (Producer / Verifier / Sealer in
// /internal/shared/tee/tee.go) are NOT modified. The Coordinator uses
// the new tee.Registry layer (Phase 4 Step 2) to resolve a verifier
// for the destination's declared TEE family.
//
// The R-14 frozen wire contracts are NOT modified. The Coordinator
// produces and consumes the two new Phase 4 contracts
// (cross_cloud_handshake_request and key_release_token) introduced
// fresh at SchemaVersion 1.
//
// The R-11 Reconstructor interface is NOT modified. Cross-cloud restore
// does not change reconstruction; it changes only how DEKs reach the
// destination's keystore prior to the existing reassembly flow.
//
// # Extension points
//
// The Coordinator depends on five replaceable abstractions, each
// behind an interface:
//
//   - Transport — wire delivery of handshake + token (mTLS HTTP/2 in
//     production; mock in tests).
//   - KeyReleasePolicy — gate function: given destination measurement
//     and key set, return Authorized true/false (allow-list policy in
//     MVP; attribute-based policy in future).
//   - KeyWrapper — derive a wrapping key from destination measurement
//     and AES-GCM-seal a DEK (simulator-friendly key derivation in
//     MVP; hardware-rooted key agreement in production).
//   - AuditEmitter — append a Kind+payload to the release-side audit
//     chain, returning the new AuditEventID. The Coordinator never
//     touches the chain's hash-link directly — that is the chain
//     package's concern.
//   - Clock + NonceSource — small replaceable utilities for
//     deterministic tests.
//
// # See also
//
//   - ADR 0006 — Cross-Cloud KMS-Mediated Restore (overall design)
//   - docs/doctrine/bootstrap-contracts.md §5 — contract freezing
//   - docs/doctrine/validation-thresholds.md §9 — audit-first-class
package kms
