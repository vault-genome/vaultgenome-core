# ADR 0015: One Binary Drives the Nine Stages

**Status:** Accepted — implemented (2026-09-16)
**Date:** 2026-09-16
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Builds on:** ADR 0013 (the worker restores the genome), ADR 0014 (the Return Path on the record), ADR 0010 (operator stop), ADR 0008 (equivalence gate), ADR 0004 (doctrine invariants as tests)
**Amends:** `sagvd` REST API (`POST /v1/jobs` body and 202 shape, `GET /v1/jobs/{id}` view); `sagvd` configuration (`operator_stop`, `runtime.evidence_max_age_seconds`); `release_decision` contract (schema v2); `internal/validation/service` (evaluated dimensions)

---

## Context

The nine-stage governed reconstruction flow — Recovery Request → Trust
Admission → Trusted Session → Staged Disclosure → Delegated External
Compute → Return Path → Validation → Release Decision → Audit — is what
this platform is. Its state machine (`internal/vault/orchestration`), its
authority packages (`session`, `disclosure`, `incident`, the validation
service) and its contracts existed and were tested end to end, but **no
shipped binary drove them**: `docs/operator/02_recovery_flow.md` said so in
its second paragraph. `sagvd` served gate jobs (ADR 0013) through a path of
its own — a job minted its manifest and session ids at submission, sealed
the model side at once under an ad-hoc AAD, and, since ADR 0014, wrote
audit events of its own shape. Intake and trust were empty packages with a
`doc.go`. The daemon's decisions were on the record; they were not the
doctrine's decisions.

## Decision

`sagvd` drives every gate job through the nine stages, with the library's
own decision-makers, in the order the transition table allows, every
decision on the audit log before it takes effect, every authority
artifact signed under the authority key. The flow is
`orchestration.Authority` (one per process) and `orchestration.Flow` (one
per request); the daemon composes them around the Return Path.

| Stage | Driver | Event(s), on the record first | Machine |
|---|---|---|---|
| 1 Recovery Request | `intake.Intake` at `POST /v1/jobs`: the request is well-formed, its `request_id` not already admitted (409) | `REQUEST_RECEIVED` | unstarted → request → trust |
| 2 Trust Admission | `trust.Admission` at dispatch, for this request and the attested peer: the operator's stop list (stop-all denies everything; a revoked measurement denies that worker), the policy profile served, a peer with a measurement | `TRUST_EVALUATED` allow or deny, with the signed `AttestationResult` | trust → session, or trust → release |
| 3 Trusted Session | `session.Issuer`: a signed `SessionObject` pinned to the policy version, living the job's deadline plus a grace | `SESSION_ISSUED` | session → disclosure |
| 4 Staged Disclosure | the bundle opened again, its model side laid out as components — a descriptor, then `genome.json`, the adapter, the prompts — and disclosed by `disclosure.StagedSequencer` to the workers' session-sealing key under the five-field recipient AAD, each envelope signed | `DISCLOSURE_AUTHORIZED` ×n | — |
| 5 Delegated Compute | a signed `ReconstructionJobManifest` naming the disclosures, the output budget and the deadline; the `JobRequest` on the wire is that manifest plus the disclosures' sealed payloads | `MANIFEST_ISSUED` | disclosure → external_compute |
| 6 Return Path | the `CandidateOutputFrame` the Return Path accepted — bound, within budget, signed by a registered worker | `CANDIDATE_RECEIVED` | external_compute → return → validation |
| 7 Validation | the validation service: the six operational sub-checks over the flow's own attestation, session and manifest, and the gate's two verdicts — **semantic**: top-1 agreement at every reference position; **behavioral**: the determinism ladder — recorded as evaluated dimensions with their evaluator's detail | `VALIDATION_STARTED`, `VALIDATION_DIMENSION_EVALUATED` ×3, `VALIDATION_FINDING` ×n, `VALIDATION_COMPLETED` | validation → release |
| 8 Release Decision | `RELEASE_DECIDED` appended, then the `ReleaseDecision` signed citing it: release on a pass, refusal on a fail, refusal citing the attestation on a trust deny | `RELEASE_DECIDED` | release → audit |
| 9 Audit | the chain's tip is the seal; a refusal after validation is the R-15 validation-hard-fail incident — `incident.Service` invalidates the session on the record | `INCIDENT_DETECTED`, `SESSION_INVALIDATED`, `INCIDENT_TERMINATED` on refusal | audit → release_authorized, or → incident_terminated |

A flow that cannot reach its decision is aborted on the record: an
`INCIDENT_DETECTED` for an Integrity failure, the session invalidated, the
machine terminated on `incident.detected`. A log that cannot take a
record stops the stage; the job fails with `audit_unavailable` and nothing
has changed.

**What the operator sees.** `POST /v1/jobs` names the genome and, at its
option, the request (`request_id`, `policy_profile`, `requester_identity`,
`contour`); it returns the job and its request ids and the flow's state.
`GET /v1/jobs/{id}` shows the flow: every transition taken, the
attestation, the session, the disclosures' digests, the manifest, the
validation result and the release decision — all signed, verifiable under
the keys `sagvd identity` prints, which now also names the policy version
and the profiles served. The worker's answer is surfaced only under a
decision with `release: true`.

**Two decisions before a flow exists.** A peer refused at the TLS or
Return Path handshake, and a peer whose Evidence is older than
`runtime.evidence_max_age_seconds` (default: the attestation TTL, five
minutes) when a job is ready for it, are `TRUST_EVALUATED` denials with no
request behind them; the stale peer is told to attest again and the job
keeps its place in the queue.

**Contract change.** `release_decision` is schema v2: `ReasonTrustDenied`
and an `AttestationID` field, so a denial at Trust Admission is a signed,
recorded decision without a session — the transition table always allowed
it; the contract could not express it. A v1 decision is a valid v2
decision.

**Service change.** `validation/service.ValidateInputs.Evaluated` records
semantic and behavioral verdicts produced by an evaluator that ran the
model, in place of the byte evaluators, with the evaluator's name and
detail in the `VALIDATION_DIMENSION_EVALUATED` payload. Operational is
always the service's own.

## Consequences

- **The operator docs stop saying "no binary drives it."** Stages 1 and 2
  have code; stages 3, 4, 7, 8 and 9 run at run time in the daemon; the
  vertical-slice tests remain the library's own proof.
- **Nothing is sealed until a worker is admitted.** The model side is
  opened at submission to be checked and to keep the references, cleared,
  and opened again at dispatch under the session it is disclosed to; a
  bundle that changed in between is refused (`genome_changed`). The
  plaintext is zeroized as soon as it is sealed.
- **The policy version is the gate.** Every session is pinned to
  `gate-policy/v1;atol=…;rtol=…;outliers=…`; a tolerance changed under a
  live session is a recorded operational failure (`op.policy_alignment`),
  not a silent drift.
- **The operator stop reaches gate jobs.** With `operator_stop`
  configured, the list is re-read at every admission; a stop-all halts
  every release the daemon would make, a revoked measurement halts that
  worker, and a rolled-back serial is refused.
- **Refusals are decisions.** A failed gate and a trust deny each end in a
  signed `ReleaseDecision` with `release: false`, on the record, and the
  metric `sagvd_release_decisions_total{decision}` counts them beside
  releases.
- **The wire is unchanged.** rp-wire-v1.0's handshake and frames are the
  same; a `SealedMaterialRef` carries its AAD, so the worker opens a
  disclosure as it opened a component. The worker is not modified.
- **Two id families on one log.** The Authority's events are
  `rp-flow-<nonce>-…`; the sequencer's, the validation service's and the
  incident service's carry their own prefixes with the same per-process
  nonce, so a log spanning restarts has no duplicate ids.

## Alternatives considered

- **Drive the flow in `acp-demo` and leave the daemon alone.** A
  demonstration binary would have retired the sentence in the docs, not
  the gap. Refused: the vault daemon is the authority.
- **Keep the daemon's own audit events and add the missing kinds.** The
  daemon would still have minted sessions without an issuer, disclosed
  without the sequencer, decided without a decision. Refused.
- **Seal at submission and issue the session later.** Disclosures are
  sealed under the session's AAD; a session that does not exist yet cannot
  be sealed to. Refused; the bundle is opened again at dispatch.
- **Sentinel ids for a trust-denied decision.** A `session_id` that names
  no session is a lie the receive side already avoids with an honesty
  marker; the contract bump is smaller and says what happened. Refused.
- **Byte-equality as the semantic dimension.** EQUIVALENT across hardware
  (ADR 0008) would then always fail semantically. Refused; the semantic
  question a restored model can answer is whether it gives the same
  answer at every reference position, and the ladder answers how close
  the numbers are.

## Proven by

- `internal/vault/orchestration/flow_test.go` — every stage in order with
  every artifact verified under the authority key and the chain under the
  audit key; a stage cannot be skipped; trust deny → a signed refusal
  without a session; a failed validation → refusal, incident, session
  invalidated; an abort; a chain that refuses a record stops the stage.
- `internal/vault/intake`, `internal/vault/trust`, `orchestration/machine_test.go`,
  `equivalence/top1_test.go`, `release_decision` v2, `service` evaluated
  dimensions — each package's own tests.
- `cmd/sagvd` — the REST API admits a request on the record before it is
  queued, names it, refuses a duplicate; the queue carries flows; the
  genome is inspected at submission and laid out at dispatch, a changed
  bundle refused; `judge` answers both dimensions.
- `test/integration/daemons_test.go` — the shipping binaries: a job's
  audit record is the nine stages, in order, correlated to its request,
  session and manifest; the job view carries the signed decision; a
  refused model ends in a signed refusal and a closed session; an unpinned
  worker is refused before the pinned one is admitted; the operator's
  stop-all denies a job at trust, on the record.
- `scripts/hardware-test/gcp-sev-snp/returnpath-e2e/` — the run on real
  SEV-SNP (see its README for the run that carries this ADR's flow).
