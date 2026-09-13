// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Command acp-bootstrap is the destination-side daemon for Phase 4
// cross-cloud KMS-mediated restore. It hosts the
// /v1/crosscloud/handshake and /v1/crosscloud/token endpoints that a
// source-side sagvd Coordinator dispatches to.
//
// Topology (per ADR 0006):
//
//	[ source: sagvd + Coordinator ]  --mTLS HTTP/2-->  [ destination: acp-bootstrap ]
//
// The daemon loads:
//
//   - Local TEE producer (simulated for MVP demo; tee.Provider*
//     backends in production)
//   - Source-authority pubkey (pre-loaded out-of-band; identifies
//     the source authority)
//   - Local keystore (where unwrapped DEKs are registered)
//
// And exposes:
//
//   - HTTP listener on a configured listen address, mounting the two
//     crosscloud routes
//   - Optional bearer-token auth on those routes
//   - /healthz, /readyz, /metrics on a separate health listener
//
// On every successful KeyReleaseToken, the daemon registers the
// unwrapped DEKs into the local keystore for the existing
// /internal/bootstrap/ orchestrator to consume in the receive-side
// flow. acp-bootstrap is INTENTIONALLY scoped to the cross-cloud
// surface only — the orchestrator runs as a separate process or as
// a sidecar that connects to the keystore.
//
// See:
//
//   - ADR 0006 — docs/adr/0006-cross-cloud-kms-mediated-restore.md
//   - Operator runbook 06 — docs/operator/06_cross_cloud_restore.md
//   - source-side equivalent: cmd/sagvd `crosscloud-restore` subcommand
package main
