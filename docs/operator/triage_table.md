# Operator triage table

When an alert fires or a recovery flow gets stuck, the on-call operator
walks down this table from top to bottom. Each row maps an observable
signal (log line, audit event, validator code, HTTP status) to the
class of incident, the immediate response, and the escalation path.

This is the standalone copy of the table previously embedded in
`02_recovery_flow.md` §7.8 (closes `docs/investor/readiness-analysis.md`
§10.2 item 11).

## Layout

| Severity | Symptom (observable) | Source surface | Class | Immediate action | Escalation | Reference |
|---|---|---|---|---|---|---|
| **CRIT** | `RECONSTRUCTION_FAILED` audit event with `incident_severity=Critical` | sagvd JSON log or `GET /v1/audit/stream` | Incident | `acpctl session zeroize --session <id>` immediately, halt all in-flight recoveries on the workflow, page SecOps | SecOps lead → CISO if attestation also failed in the same session | 00_Bootstrap_Contracts_Doctrine §6, internal/vault/incident |
| **CRIT** | `op.attestation_valid` returns false in `ValidationResult.Findings` | `/v1/jobs/{id}` JSON body | Authority | Pause new sessions on the affected worker kid, rotate the worker's TEE seed, re-run `acpctl worker enroll` | SecOps + the worker fleet owner | internal/validation/operational §1.1 |
| **CRIT** | `reassembly_sealed_open_failed` (Integrity) on a **release-side** disclosure | recv-side audit chain | Integrity | Treat as in-flight tamper. Halt the disclosure window for that GenomeID, snapshot audit chain, escalate. | SecOps lead → SRE lead | 00_Bootstrap_Contracts_Doctrine §8.4, internal/reassembly |
| **CRIT** | `reassembly_genome_id_round_trip_mismatch` | recv-side audit chain | Integrity | Refuse the candidate, mark reconstitution_decision rejected, snapshot. Escalate. | SecOps lead | 00_Bootstrap_Contracts_Doctrine §8.4 acid-test |
| **HIGH** | `reassembly_component_hash_mismatch` (tier-2) on a candidate that passed tier-1 wire-hash | recv-side audit chain | Integrity | Suspect release-side forgery (re-sealed under correct AAD). Halt, snapshot, page SecOps. | SecOps lead | 00_Bootstrap_Contracts_Doctrine §8.4 acid-test |
| **HIGH** | `op.tamper_absent` returns false | `/v1/jobs/{id}` Findings | Incident | Inspect `IncidentEvent` records for the session, decide on zeroization scope | SecOps lead | internal/vault/incident |
| **HIGH** | `op.policy_alignment` returns false | Findings | Operational | Re-issue session under current policy, drop the stale session | Workflow owner | internal/validation/operational §1.5 |
| **HIGH** | `beh.critical_probe_failed` | Findings | Operational | The candidate failed a critical behavioral probe — release blocked. Inspect probe id and the failing input. | Workflow owner; data-science lead if pattern repeats | internal/validation/behavioral §3 |
| **MED**  | `beh.non_critical_below_conditional` (pass rate < 85%) | Findings | Operational | Review which probes failed, decide if the suite needs tightening or the candidate is genuinely off-spec | Workflow owner | internal/validation/behavioral §3.3 |
| **MED**  | `sem.byte_equality` returns mismatch with non-zero offset | Findings | Operational | Determine whether the fixture or the candidate is canonical. Re-pin if fixture was wrong. | Workflow owner | internal/validation/semantic |
| **MED**  | `op.attestation_ttl` expired | Findings | Authority | Re-attest the worker, re-issue the session; old session is dead | Workflow owner | internal/validation/operational §1.2 |
| **MED**  | `bootstrap.agreement.disclosure_order_mismatch` | recv-side audit chain | Structural | Receive-side rejected because release-side reordered disclosures. Re-issue with stable order. | Release-side ops | internal/bootstrap §3 |
| **LOW**  | HTTP 429 on `POST /v1/jobs` | sagvd HTTP API | Operational | Back off, retry with jitter (SDK does this automatically). Investigate if persistent. | None unless persistent > 5 min | cmd/sagvd/http_api |
| **LOW**  | `JobTimeoutError` from SDK | client | Operational | Increase `await_job(timeout=…)` if the workload is genuinely slow; otherwise the worker is wedged | Workflow owner | sdk/python/acp-sdk |
| **INFO** | `Heartbeat` frame at 30s cadence missing | Return Path log | Operational | The peer is gone. acp-compute will reconnect via DialBackoff; verify health endpoint. | None unless lasts > 60 s | internal/compute/returnpath |

## Severity definitions

- **CRIT**: page within 15 minutes; potential active tamper or
  authority-grade failure. Audit chain MUST be snapshotted before any
  remediation.
- **HIGH**: page within 1 hour; integrity guarantees may be at risk
  but not actively breached.
- **MED**: ticket within the same business day; service-level issue
  but no integrity or authority concern.
- **LOW**: ticket within 48 hours; transient or expected operational
  event.
- **INFO**: log only; not actionable on its own.

## Audit-chain invariant (always)

Before any remediation that touches `/internal/vault/keys` or
`/internal/audit/store`, the operator MUST snapshot the chain head
(`acpctl audit snapshot --out <path>`). This is a structural
prerequisite — `vault-gate` CI rejects any change that adds a new
remediation path without first calling the snapshot helper.

## Cross-reference

The table above pairs with:

- `docs/doctrine/validation-thresholds.md` — threshold definitions
- `docs/doctrine/bootstrap-contracts.md` §8.4 — acid-test attack tree
- `core/internal/shared/errors/codes.go` — canonical code constants
- `core/internal/audit/event/kinds.go` — full AuditEvent.Kind enum
