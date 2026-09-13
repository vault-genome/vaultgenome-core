// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package main (cmd/acp-compute) is the entry point for the external
// compute worker of the AI Continuity Platform.
//
// # Doctrinal role
//
// acp-compute executes delegated reconstruction jobs described by a
// signed ReconstructionJobManifest. It is explicitly NOT an authority.
// It cannot issue a ReleaseDecision, it cannot authorize staged
// disclosure, and it must never import any package under
// /internal/vault beyond the read-only keystore it uses to hold its
// own signing identity and a pre-shared session-sealing key.
//
// The worker receives work only over the Return Path inbound side,
// produces a CandidateOutput only (never a validated or released
// artifact), and emits its result back into the vault-side Return Path
// handler, which performs operational checks before Validation runs.
//
// See docs/doctrine/terminology.md §2 for the canonical definitions of
// "Delegated External Compute," "Return Path," and "Candidate Output."
//
// # Phase 1 status
//
// Production-shape daemon. Dials sagvd over TCP (optionally wrapped
// in mTLS v1.3), runs the 4-frame Return Path handshake backed by a
// simulated TEE, serves exactly one ReconstructionJob per session,
// signs the resulting CandidateOutputFrame under an operator-
// provisioned Ed25519 key, then closes and reconnects. Reconstruction
// is handled by the deterministic R-11 placeholder in
// /internal/compute/worker; Phase 3 swaps that implementation for the
// real generative backend without touching this daemon's wiring.
//
// # Configuration
//
// The daemon is configured via a single JSON file (see
// cmd/acp-compute/config.go for the full schema). Top-level keys:
//
//   - vault.address          host:port of sagvd's Return Path listener
//   - vault.tls              mTLS material when TLS is enabled
//   - tee.workload_descriptor string hashed into the simulator's measurement
//   - tee.seed_path          32-byte Ed25519 seed for TEE attestation
//   - tee.peer.*             peer's pinned pubkey + measurement files
//   - keys.worker_signing    kid + 32-byte Ed25519 seed for frame signing
//   - keys.session_sealing   kid + 32-byte AES-256 key for unsealing
//   - runtime.*              dial / handshake / job timeouts and backoff
//   - health.listen_address  HTTP listener for /healthz /readyz /metrics
//   - log.level, log.format  debug|info|warn|error, json|text
//
// # HTTP surface
//
// Exposes three read-only endpoints on the configured health listener:
//
//   - GET /healthz → 200 "ok\n" while the process is alive
//   - GET /readyz  → 200 "ready\n" after the first successful job
//   - GET /metrics → Prometheus text-format exposition
//
// Metrics family (all `acp_compute_*`):
//
//   - jobs_total{outcome=success|reject|fail}
//   - handshake_failures_total{phase=...}
//   - dial_failures_total
//   - sessions_opened_total
//   - last_success_unix
//   - session_active (gauge 0/1)
//   - start_unix
//
// # Operational notes
//
// The daemon is intentionally single-threaded in the dial loop: Phase 1
// processes one job at a time with exponential backoff on failure. A
// bounded pool lands in Phase 2 when multi-tenant parallelism is on
// the critical path.
//
// SIGINT and SIGTERM trigger a graceful shutdown: health flips to 503,
// the in-flight session is allowed to finish (bounded by JobTimeout),
// the HTTP server drains, and the in-memory keystore is zeroized.
//
// # Binaries
//
// Three binaries ship together:
//
//   - acp-compute : THIS daemon (worker side).
//   - sagvd       : the vault / authority side.
//   - acpctl      : operator control-plane CLI.
//
// See docs/internal/phase1-v2-plan.md for how these three compose into the
// investor-demo round-trip.
package main
