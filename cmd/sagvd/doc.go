// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package main (cmd/sagvd) is the entry point for the Secure AI Genome
// Vault Daemon — the authority process of the AI Continuity Platform.
//
// # Doctrinal role
//
// sagvd is the sole authority on every continuity-relevant decision:
// trust admission, trusted-session issuance, staged-disclosure
// authorization, validation coordination, and release. No other binary
// in this repository may produce authority artifacts. This constraint
// is enforced by the doctrine tests in /test/doctrine and by the
// import-graph rule that /internal/compute and
// /internal/validation/semantic may not import any package under
// /internal/vault.
//
// Corresponds to the "Neural Seed Vault" daemon in USPTO filing P1
// (April 2026). The canonical name in this repository is the Secure AI
// Genome Vault (SAGV), per docs/doctrine/terminology.md §1.1.
//
// # Phase 1 status
//
// Production-shape authority daemon. Listens on two TCP sockets:
//
//   - vault.listen_address — Return Path inbound: acp-compute workers
//     dial here, complete the 4-frame handshake, and receive one
//     JobRequest per session backed by a pre-sealed ReconstructionJobManifest.
//   - http_api.listen_address — operator REST API: POST /v1/jobs
//     enqueues a job, GET /v1/jobs/{id} reports status plus the
//     worker's CandidateOutput on success.
//
// Dispatch is single-worker in Phase 1 (one handshake in flight at a
// time). A bounded dispatcher pool lands in Phase 2 when multi-tenant
// parallelism is on the critical path.
//
// Candidate validation in Phase 1 is the conservative stub in
// /internal/compute/worker: the CandidateOutputFrame is checked for
// signature integrity, manifest binding, and output-kind binding, but
// the full R-13..R-15 semantic/behavioural battery is wired in under
// task #78. Phase 1 is enough for the investor-demo round trip.
//
// # Configuration
//
// Configured via a single JSON file (see cmd/sagvd/config.go for the
// full schema). Top-level keys:
//
//   - vault.listen_address      TCP listener for Return Path inbound
//   - vault.tls                 mTLS material when TLS is enabled
//   - http_api.listen_address   TCP listener for the operator REST API
//   - http_api.bearer_token     optional Bearer token for POST /v1/jobs
//   - tee.workload_descriptor   hashed into the simulator's measurement
//   - tee.seed_path             32-byte Ed25519 seed for TEE attestation
//   - tee.peer.*                worker TEE pubkey + measurement (pinned)
//   - keys.authority_signing    kid + seed for authority-bound signatures (Phase-3 forward)
//   - keys.session_sealing      kid + AES-256 key for SealedMaterial (pre-shared with worker)
//   - workers.registry_path     JSON file of {kid, signing_pubkey_hex}
//   - runtime.*                 handshake / job / http timeouts
//   - health.listen_address     HTTP listener for /healthz /readyz /metrics
//   - log.level, log.format     debug|info|warn|error, json|text
//
// # HTTP surfaces
//
// Operator REST API (configured by http_api.listen_address):
//
//   - POST /v1/jobs                 → {"job_id":"..."}
//     Body: {manifest_id, session_id, expected_output_kind,
//     expected_output_max_bytes, deadline_seconds_from_now,
//     payload_base64}
//   - GET  /v1/jobs/{id}            → status + candidate (if done)
//
// Health / observability (configured by health.listen_address):
//
//   - GET /healthz → 200 "ok\n" while the process is alive
//   - GET /readyz  → 200 "ready\n" after bootstrap validation
//   - GET /metrics → Prometheus text-format exposition
//
// Metrics family (all `sagvd_*`, backed by
// /internal/observability/metrics):
//
//   - jobs_submitted_total            (counter)
//   - jobs_completed_total{outcome}   (counter: success|reject|fail)
//   - sessions_opened_total           (counter)
//   - handshake_failures_total        (counter)
//   - http_requests_total{route,status} (counter)
//   - queue_depth                     (gauge)
//   - last_success_unix               (gauge)
//   - start_unix                      (gauge)
//
// # Operational notes
//
// Graceful shutdown: SIGINT / SIGTERM flip health to 503, drain the
// two HTTP servers, stop accepting new Return Path connections, allow
// the in-flight session to finish (bounded by RuntimeConfig.JobTimeout),
// then Zeroize the in-memory keystore.
//
// # Binaries
//
// Three binaries ship together:
//
//   - sagvd       : THIS authority / vault daemon.
//   - acp-compute : external compute worker.
//   - acpctl      : operator control-plane CLI.
//
// See docs/internal/phase1-v2-plan.md for how these three compose into the
// investor-demo round-trip.
package main
