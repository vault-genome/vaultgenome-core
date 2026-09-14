# Operator triage table

When an alert fires or a release gets stuck, the on-call operator walks down
this table from top to bottom. Each row maps an observable signal (log line,
metric, HTTP status, command report, audit event) to the class of incident,
the immediate response, and the escalation path.

The first table covers what the shipped binaries emit. The second covers codes
that appear only when the library flow runs (the tests and `make demo`); no
deployment produces them today.

## Signals from the shipped binaries

| Severity | Symptom (observable) | Source surface | Class | Immediate action | Escalation | Reference |
|---|---|---|---|---|---|---|
| **CRIT** | `acpctl audit verify` reports `audit chain BROKEN` (exit 4), or `sagvd crosscloud-restore` / `crosscloud-confirm` stops with "the stored audit log does not verify; refusing to extend it" | acpctl; sagvd stderr | Integrity | Run no releases (sagvd refuses them anyway). Copy the log file off the host. Do not edit it. | SecOps lead | [DR scenario 6](runbooks/disaster_recovery.md#scenario-6-audit-log-corruption-or-tampering-detected); `internal/audit/chain` |
| **CRIT** | `acpctl audit verify` reports fewer events, or a different tip, than the latest kept `crosscloud-restore` / `crosscloud-confirm` report | acpctl + kept reports | Integrity | Treat as truncation or replacement of the log: as above | SecOps lead | 04 §2.2 |
| **CRIT** | A destination logs `crosscloud token accepted` for a `request_id` that has no `KEY_RELEASE_AUTHORIZED` event in the source's audit log | acp-bootstrap log; `acpctl audit query --kind KEY_RELEASE_AUTHORIZED --json` | Authority | Suspect the authority signing key. Stop the destination's listener until it pins a new key. | SecOps lead → CISO | [DR scenario 1](runbooks/disaster_recovery.md#scenario-1-authority-signing-key-compromised) |
| **HIGH** | Unexpected `crosscloud-restore` refusal with `error.category: integrity` | command report; audit log (`KEY_RELEASE_DENIED`) | Integrity | Possible impersonation: re-check the identities each side pinned. No key was released. | SecOps lead | 06 "When a release is refused" |
| **HIGH** | `sagvd worker signature verification failed` (with `worker_kid`) | sagvd log | Integrity | Compare `worker_kid` with `workers.registry_path`. If the worker is suspect, remove its entry and restart sagvd. | SecOps + the worker fleet owner | [DR scenario 8](runbooks/disaster_recovery.md#scenario-8-worker-compromise-acp-compute-identity-mismatch) |
| **HIGH** | `sagvd integrity failure on wire`, or `integrity failure on wire` on the worker | sagvd / acp-compute log | Integrity | Investigate the network path between the two; check the mTLS material | SRE lead | `internal/compute/returnpath` |
| **HIGH** | `crosscloud-confirm` refused (`integrity`, or `authority` for a key not released under that decision) | command report | Integrity | Nothing was recorded. Do not re-run blindly: compare the destination's restore with the operator's bundle. | Release owner | 06 "Confirming the restore" |
| **MED** | `sagvd TLS handshake failed`; `sagvd_handshake_failures_total{phase="tls"}` rising | sagvd log, `/metrics` | Operational | Check the worker's client certificate, the CA bundle and TLS 1.3 support | Worker fleet owner | `cmd/sagvd/daemon.go` |
| **MED** | `sagvd return-path handshake failed`; `sagvd_handshake_failures_total{phase="handshake"}` rising | sagvd log, `/metrics` | By `code` in the log line | For an Evidence mismatch, check the TEE pins on both sides (`tee.peer.*`, `tee.workload_descriptor`) | Worker fleet owner | 01 §4 |
| **MED** | `GET /v1/jobs/{id}` shows `"status": "failed"` | sagvd REST API; `sagvd job failed` log line | By `error.category` | Read `error.code` and `error.message` | Workflow owner | `cmd/sagvd/job_queue.go` |
| **MED** | `crosscloud-restore` refused with `authority` | command report; audit log | Authority | Intended when an operator stop or the allow-list refuses; lift only with a new list or allow-list version | Release owner | 06 "The operator stop" |
| **LOW** | `POST /v1/jobs` returns 401 (`auth_missing`, `auth_invalid`) | sagvd REST API | Authority | Check the client's bearer token against `http_api.bearer_token_file` | None unless persistent | `cmd/sagvd/http_api.go` |
| **LOW** | `POST /v1/jobs` returns 400 or 413 | sagvd REST API | Structural / Operational | Fix the request: required fields, `deadline_seconds_from_now` ≤ `runtime.default_job_deadline_seconds`, decoded payload ≤ `runtime.max_payload_bytes` | None | `cmd/sagvd/http_api.go` |
| **LOW** | `return-path cycle failed` repeating on the worker | acp-compute log | Operational | The worker retries with exponential backoff (`runtime.dial_backoff_initial_ms` up to `dial_backoff_max_ms`). Check sagvd `/readyz` and the network path. | None unless it lasts > 5 min | `cmd/acp-compute/daemon.go` |
| **LOW** | `crosscloud-restore` refused with `operational` | command report | Operational | Check the destination's listener, certificates and bearer token, then run it again; a new handshake mints a new key. If it repeats, read the destination's `crosscloud handshake rejected` or `crosscloud token rejected` log line. | None unless it repeats | 06 |
| **INFO** | `/readyz` returns 503 `not ready` | health listener | Operational | Expected until the Return Path listener is bound, and during shutdown | None unless it lasts > 60 s | `internal/observability/health` |

sagvd's REST API error statuses are 400, 401, 404, 405, 413 and 500; it has no
rate limiting. No component sends Return Path heartbeat frames (sagvd skips
any it receives), so a missing heartbeat is not a signal.

## Signals from the library flow (tests and `make demo` only)

| Symptom | Where it appears | Meaning |
|---|---|---|
| `INCIDENT_DETECTED` with payload `"severity": "critical"` | release-side audit chain | The incident module handled `attestation_failure`: session invalidated, keys zeroized (03 §1) |
| `op.attestation_valid` / `op.attestation_ttl` in a ValidationResult finding | release-side ValidationResult | Attestation outcome not `allow`, bad signature, or expired (03 §1) |
| `op.tamper_absent` | release-side ValidationResult | A tamper signal was raised for the session (03 §2, §4) |
| `op.policy_alignment` | release-side ValidationResult | Session policy version differs from the active one (03 §2) |
| `reassembly_sealed_open_failed` | receive-side Reassembler | AAD drift or ciphertext tamper (02 §7.9) |
| `reassembly_component_hash_mismatch` after a tier-1 wire-hash pass | receive-side Reassembler | Suspect release-side forgery re-sealed under the correct AAD (02 §7.1) |
| `reassembly_genome_id_round_trip_mismatch` | receive-side Reassembler | The AGD's GenomeID does not match its content (02 §7.6) |
| `bootstrap.agreement.disclosure_order_mismatch` | receive-side Orchestrator | The release side reordered disclosures (02 §7.2) |
| `op.recv.*` finding | receive-side ValidationResult | A receive-side operational sub-check failed (02 §7.7) |

## Severity definitions

- **CRIT**: page within 15 minutes; potential active tamper or
  authority-grade failure. The audit log MUST be copied off the host before
  any remediation.
- **HIGH**: page within 1 hour; integrity guarantees may be at risk
  but not actively breached.
- **MED**: ticket within the same business day; service-level issue
  but no integrity or authority concern.
- **LOW**: ticket within 48 hours; transient or expected operational
  event.
- **INFO**: log only; not actionable on its own.

## Audit-log snapshot (always)

Before any remediation that touches key files or the audit log, the operator
MUST snapshot the log: copy `crosscloud.audit_log_path` off the host, and keep
the output of `acpctl audit verify --audit <copy> --audit-pubkey <audit.pem>
--audit-kid <kid> --json` (event count and tip) with it. This is procedure,
not something CI enforces.

## Cross-reference

The table above pairs with:

- [06_cross_cloud_restore.md](06_cross_cloud_restore.md) — "When a release is refused"
- [runbooks/disaster_recovery.md](runbooks/disaster_recovery.md)
- `internal/shared/errors/errors.go` — canonical error categories and codes
- `internal/contracts/audit_event/audit_event.go` — full `AuditEvent.Kind` enum

---

_Document history: 2026-09-14 — checked line by line against the code; commands and names the binaries do not have were removed._
