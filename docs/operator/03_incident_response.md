# Incident Response

**Audience:** Vault operator, in real time.
**Prerequisite reading:** `00_overview.md`, `02_recovery_flow.md`.
**Scope:** the incident scenarios the incident module
(`/internal/vault/incident`) handles per resolution R-15, the two
"always-escalate" scenarios it defers, and what an operator does.

**What runs where.** The incident module is a library. No shipped binary
wires it, so on a deployment nothing detects these scenarios or appends
incident events for you; it runs in its own tests and in
`internal/integration/phase1_demo_test.go`. No operator command appends audit
events either. On the shipped cross-cloud path, `sagvd crosscloud-restore`
records its own refusals as `KEY_RELEASE_DENIED`
([06](06_cross_cloud_restore.md), "When a release is refused").

---

## 0. The "never do these" list

Before the scenarios, four things an operator must never do during an
incident:

1. **Never reboot the Vault to clear an error.** A reboot that bypasses a
   tamper condition is itself a doctrine violation.
2. **Never issue a ReleaseDecision by hand.** The CLI does not expose that
   surface by design. If you find yourself reaching for it, you are in an
   incident.
3. **Never rewrite the audit chain.** A discontinuous chain is a signal;
   "fixing" it destroys the signal. No repair command exists, by design.
4. **Never disable a validation sub-check to "unblock" a session.** A
   disabled check does not make the underlying problem go away, it makes
   it invisible.

---

## How the incident module handles a scenario

Each MVP-covered handler — `HandleAttestationFailure`,
`HandleValidationHardFail`, `HandleAuditAppendFailure` — runs the same
sequence on the release-side audit chain it was given:

1. Append `INCIDENT_DETECTED` (payload: `scenario`, `severity`, `session_id`,
   `manifest_id`, `code`, `detail`, and the cause's category and code).
2. Invalidate the session through its SessionInvalidator seam. A failure is
   recorded, not fatal.
3. Zeroize key material through its Zeroizer seam — only at severity
   `critical`.
4. Append `INCIDENT_TERMINATED`, citing the DETECTED event and recording
   `session_invalidated` and `zeroized`.

| Scenario | Severity | Session invalidated | Keys zeroized |
| - | - | - | - |
| `attestation_failure` | `critical` | yes | yes |
| `validation_hard_fail` | `error` | yes | no |
| `audit_append_failure` | `error` | yes | no |
| `physical_tamper_signal` | — | — | — |
| `side_channel_anomaly` | — | — | — |

The last two are V2+: `HandlePhysicalTamperSignal` and
`HandleSideChannelAnomaly` return the classified error `incident.v2_deferred`
and append nothing.

If the chain refuses the DETECTED append, nothing else happens. If it refuses
the TERMINATED append, DETECTED stands without a TERMINATED — itself an
operator signal.

---

## 1. Attestation failure (MVP-covered)

**Symptom (library):** `op.attestation_valid` or `op.attestation_ttl` fails
during Stage 7 validation.

**What it means:** the TEE Evidence behind the trust decision does not verify
or has expired. With the simulated TEE this almost always indicates a bug, a
wrong pin or a clock issue; with real hardware it can indicate compromise or
misconfiguration.

**What the code does:** an operational failure fails validation, so the
release decision cannot release (invariant #6). A caller that detects the
failure invokes `HandleAttestationFailure`, which runs the sequence above at
severity `critical`.

**In the shipped binaries**, Evidence is checked in two places:

- The Return Path handshake between sagvd and acp-compute (simulated TEE on
  both sides). A failure is logged as `sagvd return-path handshake failed` and
  counted in `sagvd_handshake_failures_total{phase="handshake"}`; no session
  opens and no job is dispatched.
- Cross-cloud release. Evidence that does not verify for the presented key is
  refused with `integrity` and recorded as `KEY_RELEASE_DENIED` (06).

**Correct response:**

1. Nothing to append — the code records what it saw.
2. Do not retry blindly. Compare the pinned identities: `sagvd identity` against
   the workers' `tee.peer.*` files, `acp-bootstrap identity` against sagvd's
   verifier registry and allow-list.
3. Run preflight (`01_preflight.md` §4) before trying again.
4. If a second attempt in the same preflight cycle also fails on
   attestation, escalate to the administrator. Do not attempt a third on the
   same host without an external review.

**Doctrine reference:** this is R-15 MVP scenario 1. The module covers three
scenarios (`attestation_failure`, `validation_hard_fail`,
`audit_append_failure`) and returns `incident.v2_deferred` for the other two.

---

## 2. Validation hard-fail (MVP-covered)

**Symptom (library):** any sub-check in `/internal/validation/operational`
fails. The aggregated ValidationResult verdict is fail.

**What it means:** something in the operational envelope — session,
manifest integrity, policy alignment, tamper signal, attestation — is
off. The specific failing sub-check identifies the axis.

**What the code does:** the validation service skips the semantic and
behavioral dimensions once operational validation fails and returns a fail
verdict. A caller invokes `HandleValidationHardFail`, which runs the sequence
above at severity `error`: the session is invalidated, keys are not zeroized.

No shipped binary validates candidates: sagvd returns a worker's output
through `GET /v1/jobs/{id}` without validating it.

**What each sub-check means:**

- `op.session_valid` — the session is not active, has expired, is not the
  manifest's session, or its signature fails. Issue a new session through the
  normal flow; do not reuse the old one.
- `op.manifest_integrity` — the ReconstructionJobManifest signature no longer
  verifies: it changed after issue, or names the wrong key. Do NOT reissue;
  open an incident review — something altered the manifest between issue and
  validation.
- `op.policy_alignment` — the session's PolicyVersion differs from the active
  policy version. Expected if the policy was rotated during the session
  (`session.Issuer.RotatePolicy`); restart from stage 1 against the new
  policy. If no rotation occurred, this is an incident.
- `op.tamper_absent` — a tamper signal was raised for this session. Treat as
  a critical incident; proceed to §4 below.
- `op.attestation_valid`, `op.attestation_ttl` — see §1.

---

## 3. Audit-append failure (MVP-covered as terminal)

**Symptom (library):** the Stage 4 StagedSequencer could not append a
`DISCLOSURE_AUTHORIZED` event. It finalizes the StagedIssuer
(`StagedIssuer.Finalize`) and returns the append error instead of the
message.

**What it means:** the audit subsystem is not healthy. Per invariant #8
"audit is first-class", the correct treatment is to refuse to continue the
session rather than produce a disclosure without an audit counterpart.
The StagedSequencer enforces this automatically.

**What the code does:** a caller invokes `HandleAuditAppendFailure`, which
appends `INCIDENT_DETECTED` and `INCIDENT_TERMINATED` (scenario
`audit_append_failure`, severity `error`) through the same chain. If that
chain is broken at the byte level, those appends fail too and the handler
returns the error.

**In the shipped binaries:** `sagvd crosscloud-restore` persists every audit
event before the step it records. If persisting fails, the chain does not
advance and the step is not taken — no key leaves. A log that does not verify
when it is opened stops every release.

**Correct response:**

1. Check the disk and the file at `crosscloud.audit_log_path`.
2. Verify the log and compare its tip with the last report's `audit_tip`
   (`04_observability.md` §2.1–§2.2).
3. Run no releases until it verifies and matches. If it does not verify,
   follow [runbooks/disaster_recovery.md](runbooks/disaster_recovery.md)
   scenario 6 and escalate to the administrator.

---

## 4. Physical tamper signal (V2+ — always escalate in MVP)

**Symptom:** an external tamper sensor raises a signal, the audit log fails
verification, or its tip no longer matches a tip you recorded.

**What it means:** the integrity assumption under which the Vault
operates may be violated. `HandlePhysicalTamperSignal` returns
`incident.v2_deferred` and appends nothing (patent P3 §[0017] describes the
automatic V2+ response); the response is manual escalation plus the
procedure below.

**Correct response:**

1. Do not restart the Vault.
2. Capture the current state to an external medium: a copy of the audit log
   file and the output of `acpctl audit verify … --json` (event count, tip),
   signed separately from the Vault's keys.
3. Stop key releases: sign a stop list with `acpctl stop issue … -all -reason
   "…"` and install it at `crosscloud.operator_stop.list_path`; every later
   `crosscloud-restore` run refuses.
4. Take the Vault offline. "Offline" in the full sense: stop the process
   (SIGTERM shuts sagvd down gracefully and wipes its in-memory keys) and stop
   accepting incoming connections, not merely mark it unhealthy.
5. Escalate to the administrator and initiate an out-of-band review. The
   Vault is designed so that its continuity object remains useless outside
   the authorised secure path — this is where that property earns its keep.

---

## 5. Side-channel or pattern anomaly (V2+ — not recognised by MVP code)

**Symptom:** external observability systems flag an anomalous pattern of
access — unusual timing, unusual volume, access at an unusual hour.

**What it means:** something in the access pattern is off.
`HandleSideChannelAnomaly` returns `incident.v2_deferred`; no code recognises
this scenario yet.

**Correct response:**

1. Treat as §4 above, conservatively. Better to escalate than to miss an
   emerging incident. Manual escalation is cheaper than a compromised
   recovery.
2. Document the anomalous pattern — an external pattern-anomaly report
   will later inform the V2+ rule set.

---

## 6. After any incident

For every incident — MVP-covered or escalated:

1. The record is the audit chain: where the incident module ran, its
   `INCIDENT_DETECTED` / `INCIDENT_TERMINATED` pair; on the shipped
   cross-cloud path, the audit log and the commands' JSON reports. No
   informal notes.
2. A post-incident review produces a written artifact. If the cause was
   doctrinal (for example, an invariant was weakened by a recent
   change), the review must name the invariant and either restore it or
   amend it through an ADR (`docs/adr/`).
3. The operator who handled the incident writes the preflight check that
   would have caught it earlier, if any.
4. No keys are released and no work is submitted until the preflight passes
   green against the updated checklist.

---

_Document history: 2026-09-14 — checked line by line against the code; commands and names the binaries do not have were removed._
