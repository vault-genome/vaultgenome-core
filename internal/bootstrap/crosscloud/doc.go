// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package crosscloud implements the destination-side handler for
// Phase 4 cross-cloud KMS-mediated restore. The Receiver type is
// wired into the acp-bootstrap daemon to handle two new HTTP endpoints
// (POST /v1/crosscloud/handshake and POST /v1/crosscloud/token), and
// in tests it is exercised directly via its HandleHandshakeRequest
// and HandleKeyReleaseToken methods.
//
// # Doctrinal role
//
// Per ADR 0006 §"Detailed Design — Receive-Side":
//
//  1. The Receiver verifies the source authority's Ed25519 signature
//     on every CrossCloudHandshakeRequest and KeyReleaseToken, using
//     a pre-loaded source-authority public key (exchanged
//     out-of-band — the operator's responsibility).
//
//  2. On handshake, the Receiver generates fresh local Evidence via
//     its tee.Producer.Quote(handshakeNonce) and returns it to the
//     source along with the local Measurement hint.
//
//  3. On token receipt, the Receiver:
//     a. Validates the token's structural fields (delegates to
//     krt.KeyReleaseToken.Validate).
//     b. Verifies the token's signature against the source-
//     authority pubkey.
//     c. Verifies that the token's DestinationMeasurement matches
//     the local TEE Producer's Measurement byte-for-byte —
//     this is the cryptographic gate that prevents an attacker
//     in possession of the token bytes from extracting the
//     DEKs on a different host.
//     d. For each WrappedKey, invokes the KeyUnwrapper with the
//     local Measurement and the WrappedKey's AAD; on success,
//     registers the unwrapped material in the destination's
//     KeyRegistrar (typically keys.InMemoryStore.RegisterSealing).
//
// # No new audit kinds
//
// Per ADR 0006 explicitly: the cross-cloud handshake adds NO new
// receive-side audit kinds. The destination's keystore registration
// is a privileged-interface operation; the receive-side audit chain
// captures the subsequent disclosure-message flow that uses those
// keys (KindDisclosureReceived, KindRecvValidationStarted, etc.).
// Forensic auditors who need to trace a cross-cloud event correlate
// the source-side chain (which has all four cross-cloud kinds) with
// the destination-side chain (which has the disclosure-flow kinds)
// via the shared DecisionID, ManifestID, and SessionID correlators.
//
// # Frozen boundaries respected
//
// The Receiver consumes the new Phase 4 wire contracts
// (cross_cloud_handshake_request and key_release_token) and uses
// the existing R-10 tee.Producer / R-10-compatible KeyUnwrapper.
// It does NOT modify any frozen interface or contract.
//
// # See also
//
//   - ADR 0006 — Cross-Cloud KMS-Mediated Restore
//   - internal/vault/kms — release-side Coordinator (the symmetric peer)
package crosscloud
