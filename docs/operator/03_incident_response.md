# Incident Response

**Audience:** Vault operator, in real time.
**Prerequisite reading:** `00_overview.md`, `02_recovery_flow.md`.
**Scope:** the incident scenarios that the MVP incident module handles per
resolution R-15, plus the two "always-escalate" scenarios that are above
MVP scope but must still be recognised by an operator on call.

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
   "fixing" it destroys the signal.
4. **Never disable a validation sub-check to "unblock" a session.** A
   disabled check does not make the underlying problem go away, it makes
   it invisible.

---

## 1. Attestation failure (MVP-covered)

**Symptom:** `op.attestation_valid` or `op.attestation_ttl` reports FAIL
during Stage 7 validation.

**What it means:** the TEE (emulated or real) is either not producing a
valid quote or the quote has expired. In MVP (emulated TEE), this almost
always indicates a bug or a clock issue; in production (real TEE), it
indicates enclave compromise or misconfiguration.

**Correct response:**

1. The orchestration state machine automatically blocks the release —
   you do not need to intervene to prevent a bad release.
2. Append an `INCIDENT_DECLARED` audit event with Kind
   `ATTESTATION_FAILED` and the failing sub-check identifier.
3. Terminate the session.
4. Run preflight (`01_preflight.md` §4) before opening another session.
5. If a second session in the same preflight cycle also fails on
   attestation, escalate to the administrator. Do not attempt a third
   session on the same Vault instance without an external review.

**Doctrine reference:** this scenario is one of the two R-15 scenarios
the MVP incident module handles. See
`/internal/vault/incident` for the code path. The module's interface is
production-shaped; MVP implements these two scenarios explicitly and
returns `NotImplementedInMVP` for the others.

---

## 2. Validation hard-fail (MVP-covered)

**Symptom:** any sub-check in `/internal/validation/operational` reports
FAIL. The aggregated ValidationResult is below threshold.

**What it means:** something in the operational envelope — session,
manifest integrity, policy alignment, tamper signal, attestation — is
off. The specific failing sub-check identifies the axis.

**Correct response:**

1. The orchestration state machine automatically blocks the release.
2. Append an `INCIDENT_DECLARED` audit event with Kind
   `VALIDATION_HARD_FAIL` and the failing sub-check identifier(s).
3. Terminate the session.
4. Depending on the failing sub-check:
   - `op.session_valid` — the SessionObject is expired or revoked. Mint
     a new session through the normal flow; do not reuse the old one.
   - `op.manifest_integrity` — the ReconstructionJobManifest hash has
     changed between issue and validation. Do NOT reissue; open an
     incident review — something altered the manifest between stages 4
     and 7.
   - `op.policy_alignment` — the effective policy changed between
     session issuance and validation. Expected if the administrator
     rotated policy during the session; in that case the session is
     correctly terminated and the operator can restart from stage 1
     against the new policy. If no rotation occurred, this is an
     incident.
   - `op.tamper_absent` — a tamper signal was raised for this session.
     Treat as a critical incident; proceed to §4 below.

---

## 3. Audit-append failure (MVP-covered as terminal)

**Symptom:** Stage 4 StagedSequencer reports that it could not append a
`DISCLOSURE_AUTHORIZED` event; the sequencer has invoked `Finalize()` and
surfaced an error to the caller.

**What it means:** the audit subsystem is not healthy. Per invariant #8
"audit is first-class", the correct treatment is to refuse to continue the
session rather than produce a disclosure without an audit counterpart.
The StagedSequencer enforces this automatically.

**Correct response:**

1. Confirm the session is in fact terminated (check workflow state).
2. If the terminating append itself succeeded, append an
   `INCIDENT_DECLARED` event with Kind `AUDIT_APPEND_FAILED`; if not, the
   incident is now about audit storage itself — escalate immediately to
   the administrator.
3. Do not open new sessions until the audit subsystem has been verified
   healthy by an external check (the stored chain tip cross-check
   described in `04_observability.md` §3).

---

## 4. Physical tamper signal (V2+ — always escalate in MVP)

**Symptom:** an external tamper sensor raises a signal, or a witness-log
DetectFork fires, or the audit chain shows a discontinuity between two
pinned tips.

**What it means:** the integrity assumption under which the Vault
operates may be violated. In V2+ the incident module will respond
automatically (per patent P3 §[0017]); in MVP, the response is manual
escalation plus the procedure below.

**Correct response:**

1. Do not restart the Vault.
2. Capture the current state — audit chain tip, witness-log STH, latest
   SessionObject — to an external medium under a distinct signed
   certificate.
3. Terminate any in-flight session through the normal flow; do not
   short-circuit. If the orchestration state machine refuses to
   terminate, that is itself additional evidence of the incident.
4. Take the Vault offline. "Offline" in the full sense: stop accepting
   incoming connections, not merely mark unhealthy.
5. Escalate to the administrator and initiate an out-of-band review.
   Per the Hardware Reference Architecture, the Vault is designed so
   that its continuity object remains useless outside the authorised
   secure path — this is where that property earns its keep.

---

## 5. Side-channel or pattern anomaly (V2+ — not recognised by MVP code)

**Symptom:** external observability systems flag an anomalous pattern of
access — unusual timing, unusual volume, access at an unusual hour.

**What it means:** something in the access pattern is off. In V2+ this
will be one of the scenarios handled by the full incident module (patent
P3 §[0017]); in MVP, the code does not recognise it.

**Correct response:**

1. Treat as §4 above, conservatively. Better to escalate than to miss an
   emerging incident. Manual escalation is cheaper than a compromised
   recovery.
2. Document the anomalous pattern — an external pattern-anomaly report
   will later inform the V2+ rule set.

---

## 6. After any incident

For every incident declared — MVP-covered or escalated:

1. The `INCIDENT_DECLARED` audit event is the authoritative record. No
   informal notes.
2. A post-incident review produces a written artifact. If the cause was
   doctrinal (for example, an invariant was weakened by a recent
   change), the review must name the invariant and either restore it or
   submit an amendment under the Stage A amendment process.
3. The operator who declared the incident writes the preflight section
   that would have caught it earlier, if any.
4. No recovery session is opened until the preflight passes green
   against the updated checklist.
