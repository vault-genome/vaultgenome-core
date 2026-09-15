# Observability

**Audience:** Vault operator, administrator, external auditor.
**Purpose:** how to prove, after the fact, exactly what happened. The
platform's trust model assumes that every continuity-relevant event is
externally verifiable from first principles — this document is the procedure
for doing that verification with the tools that exist today.

---

## 1. The three observability surfaces

The design has three independent, cross-referenced observability surfaces.
Consistency across all three is the operational definition of a "clean"
session. Only the audit chain exists on a deployment today.

| Surface | Contents | Integrity primitive | Package | On a deployment |
| - | - | - | - | - |
| Audit chain | Signed, hash-linked AuditEvents | SHA-256 hash chain; Ed25519 signature per event | `/internal/audit` (`chain`, `store`) | Yes — the cross-cloud log at `crosscloud.audit_log_path`, written by `sagvd crosscloud-restore` and `crosscloud-confirm`. The sagvd daemon writes no audit log. |
| Witness log | Signed tree heads over the genome-descriptor state | RFC 6962 Merkle tree, STH signatures | `/internal/genome/witness` | No — in-memory library, exercised by tests |
| Session ledger | SessionObjects and their ReleaseDecisions | Ed25519 signatures under the `signing_authority` key purpose | `/internal/vault/session`, `/internal/contracts/release_decision` | No — library, exercised by tests |

§5 lists the runtime metrics and logs the daemons expose.

---

## 2. Audit chain inspection

The audit chain is a linear hash chain of AuditEvents
(`/internal/contracts/audit_event/audit_event.go`). Each event carries a Kind
(one of 23: 14 release-side, 4 receive-side, 5 cross-cloud), correlators
(SessionID, ManifestID, RequestID — any may be empty), a timestamp, the
previous event's hash, its own hash, and a signature under the audit signing
key. The cross-cloud log holds `CROSS_CLOUD_HANDSHAKE_INITIATED`,
`CROSS_CLOUD_ATTESTATION_VERIFIED`, then `KEY_RELEASE_AUTHORIZED` or
`KEY_RELEASE_DENIED`, and `CROSS_CLOUD_RESTORE_COMPLETED` for each confirmed
restore.

### 2.1 Verify the chain in-place

```
acpctl audit verify --audit /var/lib/acp/xcc-audit.db \
  --audit-pubkey sagvd-audit.pem --audit-kid sagvd-audit --json
```

It replays the chain from its first event (whose previous hash must be 32 zero
bytes), checks every hash link and every signature under the one key given,
and prints `ok`, `event_count` and `tip` (the hash of the last event).
`--audit-pubkey` takes the PEM `sagvd identity` prints as
`audit_public_key_pem`, or the 32 raw bytes.

**Expected output:** `"ok": true`, exit 0. On the first inconsistency it
reports the offending event's index — `event #N: prev_hash does not link to
event #N-1` for a broken link, `event #N: …` for a signature that does not
verify — and exits 4. It does not check the order of kinds within a session.

acpctl opens the file read-write and takes the same lock a running
`crosscloud-restore` holds (it gives up after 5 seconds): run it between
releases, or on a copy. A mistyped `--audit` path creates an empty log, which
verifies with 0 events.

### 2.2 Verify against an external tip pin

A chain cannot show by itself that its tail was cut off. Pin the tip outside
the host:

1. Keep the JSON report of every `sagvd crosscloud-restore` and
   `crosscloud-confirm` run; each carries `audit_chain_length` and `audit_tip`.
2. Later, run §2.1. Its `event_count` and `tip` must equal the values in the
   most recent report.

Fewer events, or a different tip with no newer report to explain it, means the
audit log has been truncated or replaced — critical incident, treat per
`03_incident_response.md` §4.

### 2.3 Session and request reconstruction from audit

```
acpctl lineage --audit /var/lib/acp/xcc-audit.db --session-id <session-id>
acpctl lineage --audit /var/lib/acp/xcc-audit.db --manifest-id <manifest-id>
```

Lists every event carrying that ID in time order: index, time, kind, event ID
and request ID (`--json` for machine output). Cross-cloud events carry a
session or manifest ID only when `crosscloud-restore` was given `-session-id`
or `-manifest-id`. Every cross-cloud event carries the handshake request ID,
which `audit query` prints:

```
acpctl audit query --audit /var/lib/acp/xcc-audit.db \
  --kind KEY_RELEASE_AUTHORIZED --since 2026-09-01T00:00:00Z --json
```

`--since` and `--until` take RFC 3339 times; `--limit 0` returns every match.
`acpctl status --audit PATH` prints a summary: event count, time range, a
histogram of kinds, and the most recent event.

---

## 3. Witness log verification

Not available on a deployment. The witness transparency log
(`/internal/genome/witness`) is an in-memory library: it appends entries, signs
tree heads under a `signing_witness` key, and answers inclusion and
consistency proofs; `DetectFork` (`/internal/contracts/witness`) compares two
signed tree heads. Tests exercise all of it. No binary runs a witness log or
publishes signed tree heads, and `acpctl` has no witness command.

---

## 4. Session ledger cross-check

Not available on a deployment: no binary keeps sessions or release decisions.
The contracts require, for a given SessionID:

- SessionObject.SessionID must match ReleaseDecision.SessionID.
- ReleaseDecision.ValidationResultID must point to a ValidationResult
  produced for this session (invariant #5).
- ReleaseDecision.AuditEventID must point to a `RELEASE_DECIDED`
  AuditEvent (invariant #8).
- The audit event at AuditEventID must reference this SessionID.
- Every DisclosureMessage emitted during this session must have a
  matching `DISCLOSURE_AUTHORIZED` audit event with the same SessionID
  and a strictly monotonic SequenceIndex.

A mismatch in any of these is a doctrine violation — by construction, a
valid session must satisfy all of them. `internal/integration/vertical_slice_test.go`
asserts the ID correlations; there is no CLI for this cross-check.

---

## 5. Runtime signals

Both daemons serve Prometheus text at `/metrics` on their health listener
(`health.listen_address`, default `127.0.0.1:9091` for both — give one of them
another address on a shared host), next to `/healthz` (`ok`) and `/readyz`
(`ready`).

| sagvd metric | Meaning |
| - | - |
| `sagvd_http_requests_total{route,status}` | REST API requests |
| `sagvd_jobs_submitted_total` | Jobs accepted by `POST /v1/jobs` |
| `sagvd_jobs_completed_total{outcome}` | Jobs finished: `success`, `reject` (operational or structural error, including a gate that refused the model), `fail` |
| `sagvd_gate_verdicts_total{level}` | Gate verdicts on restored models: `EXACT`, `EQUIVALENT`, `FAIL`, `ERROR` (the answer could not be judged) |
| `sagvd_sessions_opened_total` | Return Path handshakes completed |
| `sagvd_handshake_failures_total{phase}` | `tls` or `handshake` |
| `sagvd_queue_depth` | Jobs waiting for a worker |
| `sagvd_last_success_unix`, `sagvd_start_unix` | Timestamps |
| `vg_tee_attestation_total{provider,result,role}`, `vg_tee_attestation_duration_seconds` | Return Path Evidence produced and verified; `provider` is always `simulated` in sagvd |
| `vg_tee_capability_total{provider,available}` | Recorded once at startup as `simulated` / `true`; sagvd probes no hardware |

acp-compute exports `acp_compute_jobs_total`,
`acp_compute_handshake_failures_total`, `acp_compute_dial_failures_total`,
`acp_compute_sessions_opened_total`, `acp_compute_session_active`,
`acp_compute_last_success_unix` and `acp_compute_start_unix`.
`deploy/grafana/` holds dashboards for these metrics.

Both daemons log to stderr only — JSON lines by default (`log.format: "text"`
for text) with `time`, `level`, `msg` and, on failures, `err`. Collect stderr
with your own agent.

---

## 6. Routine observability cadence

| Cadence | Check | Who |
| - | - | - |
| Every `crosscloud-restore` / `crosscloud-confirm` run | Keep the JSON report (`audit_tip`, `audit_chain_length`) off the host | Administrator |
| Every preflight | `acpctl audit verify`, compared with the latest report (§2.2) | Vault operator |
| Every 30 days | The same, plus `acpctl audit query` over the period against the releases you intended | Vault operator |
| After any incident | All of the above | Administrator |

---

## 7. What observability does NOT do

It is useful to be explicit:

- Observability does not replace doctrine. A clean log does not excuse
  an operational choice that violated an invariant; it merely makes the
  violation visible.
- Observability does not replace preflight. A green preflight a week ago
  does not cover a release run today.
- Observability does not provide real-time anomaly response. That is the
  incident module's job; it covers three scenarios (attestation failure,
  validation hard-fail, audit-append failure) and runs only in-library — the
  rest are operator judgment.
- Observability does not protect against a compromised
  authority signing or audit signing key. A key compromise is the
  scenario under which the whole chain becomes unreliable. The only
  defence there is the key-custody procedures in preflight §3 and the
  out-of-band external pin cadence above.

---

_Document history: 2026-09-14 — checked line by line against the code; commands and names the binaries do not have were removed._
