# Recovery Flow — Nine-Stage Walkthrough

**Purpose:** a stage-by-stage walkthrough of the nine-stage release flow and of
the receive-side round trip, as implemented in the library. For each stage the
document gives (a) what the code does, (b) what the tests check, and (c) what
the doctrine requires.

**No shipped binary runs this flow.** No `cmd/` package imports
`internal/vault/{orchestration,session,disclosure,incident}`,
`internal/validation/operational`, the root `internal/bootstrap` package or
`internal/reassembly`, and `internal/vault/intake` and `internal/vault/trust`
hold only a `doc.go`. The flow is assembled by tests from the library pieces:

- `make demo` Act I runs `go test -run TestVerticalSlice ./internal/integration/...`.
  `vertical_slice_test.go` builds each stage's contract in turn, with a
  synthetic candidate in place of a worker.
- `make demo` Act II runs `go test -run TestRoundtripSlice ./internal/integration/...`
  (the receive side, §7).
- `internal/integration/phase1_demo_test.go` adds the worker's Reconstructor,
  the validation service and the incident service; the StagedSequencer
  (stage 4) is covered by the `internal/vault/disclosure` tests.

Of the release-side audit kinds, library code appends only
`DISCLOSURE_AUTHORIZED` (StagedSequencer), the four `VALIDATION_*` kinds
(validation service) and `INCIDENT_DETECTED` / `INCIDENT_TERMINATED` (incident
service). `REQUEST_RECEIVED`, `TRUST_EVALUATED`, `SESSION_ISSUED`,
`MANIFEST_ISSUED`, `CANDIDATE_RECEIVED` and `RELEASE_DECIDED` are appended by
the tests themselves, and `vertical_slice_test.go` appends all of its events by
hand.

The **State machine** lines quote the transition table in
`internal/vault/orchestration/state.go`; nothing drives it at run time. The
**Checked** lines are what the tests assert — a deployment offers no surface
on which to check them.

The shipped daemons cover stages 5 and 6 and the behavioural check of stage
7: `POST /v1/jobs` on sagvd's REST API names a sealed genome; sagvd opens it,
keeps its reference fixtures and seals its model side under the
session-sealing key; `acp-compute` collects the job over the Return Path,
restores the model in memory through the `vg_genome` door, answers the
genome's prompts and returns a signed CandidateOutputFrame; sagvd holds the
answers to the references through the determinism ladder and records the
signed verdict, which `GET /v1/jobs/{id}` shows (ADR 0013). sagvd names the
job's `manifest_id` and `session_id` itself, but issues no SessionObject or
signed manifest, and no release decision follows the verdict.

---

## Stage 1 — Recovery Request

**Trigger:** a RecoveryRequest is presented to the Vault.

**Code:** `RecoveryRequest.Validate()` (`internal/contracts/recovery_request`)
checks that the schema version is supported and that `request_id`,
`genome_id`, `policy_profile`, `requester_identity` and `created_at` are set.
The intake package has no code yet.

**State machine:** `StateUnstarted → StateRequest` on `request.received`, then
`StateRequest → StateTrust` on `request.validated`.

**Checked:** one `REQUEST_RECEIVED` audit event for the request; its RequestID
is carried by every later event.

**Doctrine:** intake is never skipped. A session that enters the Vault
without a matching intake audit event is a per-doctrine invariant
violation of "sessions are mandatory" (#3) and must be terminated.

**Package:** `/internal/vault/intake` (`doc.go` only).

---

## Stage 2 — Trust Admission

**Trigger:** workflow state entered `StateTrust`.

**Code:** Trust Admission produces a signed AttestationResult
(`internal/contracts/attestation_result`) with Outcome `allow`, `deny` or
`restrict`. The trust package has no code yet; the tests build the
AttestationResult and append `TRUST_EVALUATED`.

**State machine:** `allow` moves `StateTrust → StateSession`. `deny` and
`restrict` both move `StateTrust → StateRelease`: a release decision without a
session. There is no separate denied state, and nothing narrows a `restrict`
admission to a subset of components.

**Checked:** the AttestationResult signature verifies; `TRUST_EVALUATED` was
appended. Later, `op.attestation_valid` fails any outcome other than `allow`.

**Doctrine:** "trust is a gate, not a log" (invariant #2). A trust
decision is not advisory — a `deny` or `restrict` mechanically constrains
the allowed state transitions, not merely the audit record. This is
enforced at the transition-table level in `/internal/vault/orchestration`.

**Package:** `/internal/vault/trust` (`doc.go` only).

---

## Stage 3 — Trusted Session

**Trigger:** workflow state entered `StateSession`.

**Code:** `session.Issuer.Issue` mints a SessionObject carrying SessionID,
RequestID, GenomeID, PolicyVersion (the Issuer's active policy), IssuedAt,
ExpiresAt (IssuedAt + TTL, default 5 minutes) and State `active`, signed under
the `signing_authority` key purpose. The Issuer keeps sessions in memory. The
tests append `SESSION_ISSUED`.

**State machine:** `StateSession → StateDisclosure` on `session.issued`.

**Checked:** SessionID is unique and non-zero; the signature verifies; the
session is not expired.

**Doctrine:** every downstream message in the flow — DisclosureMessage,
ReconstructionJobManifest, ReleaseDecision — must carry this SessionID
and fail validation without it. See invariant #3.

**Package:** `/internal/vault/session`.

---

## Stage 4 — Staged Disclosure

**Trigger:** workflow state entered `StateDisclosure`.

**Code:** the **StagedSequencer** (`/internal/vault/disclosure/sequencer.go`)
walks the ordered Component list, delegates each emission to the
**StagedIssuer**, and — critically — appends a `DISCLOSURE_AUTHORIZED`
AuditEvent **before** surfacing each DisclosureMessage to the caller. Each
message carries a single Component, its SequenceIndex, and a sealed payload
whose five-field AAD includes the recipient key ID.

**State machine:** `StateDisclosure → StateExternalCompute` on
`manifest.dispatched`.

**Checked:** exactly one AuditEvent per DisclosureMessage; no batch emission
(`SequenceIndex` strictly monotonic, one message per step, no bulk field);
plaintext zeroized on every path, including every short-circuit.

**Doctrine:**
- "Disclosure is staged" (invariant #4) — no bulk disclosure; the message
  shape itself forbids it (scalar ComponentID, no slice, Emit signature
  returns a single message).
- "Audit is first-class" (invariant #8) — audit-append failure is a
  terminal condition: the sequencer finalizes the StagedIssuer and returns
  the append error instead of the message.
- "No raw export" (invariant #7) — the import graph static audit forbids
  any non-vault package from importing the disclosure primitives.

**Package:** `/internal/vault/disclosure`.

---

## Stage 5 — Delegated External Compute

**Trigger:** the compute plane receives work for the session.

**Code:** a signed ReconstructionJobManifest
(`internal/contracts/reconstruction_job_manifest`) names the session, genome,
policy version, disclosures, expected output and deadline; the tests append
`MANIFEST_ISSUED`. The worker's Reconstructor (`internal/compute/worker`,
`GenomeReconstructor`) runs the step: it checks every component against the
job's descriptor, hands the genome's description, adapter and prompts to the
`vg_genome` door on stdin, and returns the restored model's logits at the
reference tokens (ADR 0013). The shipped `acp-compute` receives a JobRequest
over the Return Path rather than DisclosureMessages, opens its sealed
components with the session-sealing key, runs the Reconstructor and returns a
CandidateOutputFrame signed with its worker key.

**State machine:** `StateExternalCompute → StateReturn` on
`candidate.received`.

**Checked:** the candidate fits the manifest's declared maximum size and is
bound to the manifest's SessionID and ManifestID.

**Doctrine:** the compute plane has delegated execution rights only. It
cannot by itself authorise a ReleaseDecision. It stays within its scope:
it does not request additional components, persist plaintext past the
manifest's scope, or forward plaintext outside the session.

**Package:** `/internal/compute/worker`.

---

## Stage 6 — Return Path

**Trigger:** compute returns a result.

**Code:** the result comes back on the Vault-controlled Return Path
(`internal/compute/returnpath`). In the shipped daemons sagvd verifies the
CandidateOutputFrame signature against its worker registry and records the
result on the job (`GET /v1/jobs/{id}` → `result`); it appends no audit event.
The tests append `CANDIDATE_RECEIVED`.

**State machine:** `StateReturn → StateValidation` on `return.accepted`.

**Checked:** `CANDIDATE_RECEIVED` carries the session's SessionID and the
manifest's ManifestID.

**Doctrine:** the return path is a Vault surface, not a compute-plane
surface. The compute plane is a caller on this path, not its owner.

**Package:** `/internal/compute/returnpath`.

---

## Stage 7 — Validation

**Trigger:** workflow state entered `StateValidation`.

**Code:** operational validation runs six sub-checks
(`/internal/validation/operational`):

| Sub-check | Asserts |
| - | - |
| `op.attestation_valid` | AttestationResult outcome is `allow` and its signature verifies |
| `op.attestation_ttl` | TTL is positive and the attestation has not expired |
| `op.session_valid` | Session is `active`, not expired, is the manifest's session, and its signature verifies |
| `op.manifest_integrity` | The ReconstructionJobManifest signature still verifies |
| `op.tamper_absent` | No tamper signal was raised for the session (a boolean input today) |
| `op.policy_alignment` | The session's PolicyVersion equals the active policy version |

Threshold: 1.0. No partial pass; every sub-check runs, and a single failure
blocks release. The validation service (`/internal/validation/service`)
appends `VALIDATION_STARTED`, `VALIDATION_DIMENSION_EVALUATED`,
`VALIDATION_FINDING` and `VALIDATION_COMPLETED`; when operational validation
passes it also runs the semantic (byte equality) and behavioral
(byte-statistics probes that do not run a model, KNOWN_ISSUES #3) dimensions,
and when it fails it skips them.

**State machine:** `StateValidation → StateRelease` on `validation.completed`,
whatever the verdict.

**Checked:** all six sub-checks green; the ValidationResult carries the
SessionID it validates.

**Doctrine:** "validation precedes release" (invariant #5). The transition
table makes `StateRelease` reachable only from `StateValidation` or
`StateTrust` (the `StateTrust → StateRelease` edges carry `deny` and
`restrict` outcomes, which release a terminal decision without a session).

**Package:** `/internal/validation/operational`.

---

## Stage 8 — Release Decision

**Trigger:** workflow state entered `StateRelease`.

**Code:** a ReleaseDecision (`/internal/contracts/release_decision`) carries
DecisionID, SessionID, ManifestID, ValidationResultID, `release` (true or
false), Reason, DecidedAt and the AuditEventID of its `RELEASE_DECIDED` event,
signed under the `signing_authority` key purpose. The tests build and sign it
and append `RELEASE_DECIDED`.

**State machine:** `StateRelease → StateAudit` on `decision.signed`. The table
also has an optional cross-cloud sub-stage (`StateRelease →
StateCrossCloudHandshake → StateAudit`); the shipped cross-cloud release
(`sagvd crosscloud-restore`, [06](06_cross_cloud_restore.md)) runs on its own,
outside this state machine.

**Checked:** the ReleaseDecision carries both a ValidationResultID (invariant
#5 structural check) and an AuditEventID (invariant #8 structural check); the
signature verifies; the decision chains back, through its ValidationResult, to
the original RecoveryRequest.

**Doctrine:**
- "Validation precedes release" — enforced by the ValidationResultID
  field check.
- "Audit is first-class" — enforced by the AuditEventID field check.
- "Contracts are frozen" (#9) — the ReleaseDecision struct has
  SchemaVersion as its first field, with pinned `{Min, Max, Current}`
  constants.

**Package:** `/internal/contracts/release_decision` (contract);
`/internal/vault/orchestration` holds only the transition table.

---

## Stage 9 — Audit

**Trigger:** every stage transition.

**Code:** each stage's event is appended to the hash chain
(`/internal/audit/chain`) and signed under the audit signing key; the chain
tip advances with each append. The release-side kinds are `REQUEST_RECEIVED`,
`TRUST_EVALUATED`, `SESSION_ISSUED`, `SESSION_INVALIDATED`,
`DISCLOSURE_AUTHORIZED`, `MANIFEST_ISSUED`, `CANDIDATE_RECEIVED`,
`VALIDATION_STARTED`, `VALIDATION_DIMENSION_EVALUATED`, `VALIDATION_FINDING`,
`VALIDATION_COMPLETED`, `RELEASE_DECIDED`, `INCIDENT_DETECTED` and
`INCIDENT_TERMINATED`.

**State machine:** `StateAudit → StateReleaseAuthorized` on
`audit.sealed.release_true`, or `StateAudit → StateIncidentTerminated` on
`audit.sealed.release_false`. Every operational state can also move to
`StateIncidentTerminated` on `incident.detected`.

**Checked:** every stage has at least one audit event; `chain.Verify`
passes at the end of the test (no gap in the hash chain).

**Doctrine:**
- "Audit is first-class" (#8) — `AuditEvent.Kind`
  (`internal/contracts/audit_event/audit_event.go`) enumerates 23 kinds: the
  14 release-side kinds above, 4 receive-side kinds (§7) and 5 cross-cloud
  kinds (06). Release carries the AuditEventID of the authorising event;
  audit append is synchronous with the authorising transition, not deferred.

**Package:** `/internal/audit`.

---

## Session closure

What the library provides:

1. `session.Issuer.Invalidate` moves a session to `invalidated` and re-signs
   it; the incident service calls it through its SessionInvalidator seam. The
   `SESSION_INVALIDATED` kind exists, but no library code appends it yet.
2. `StagedIssuer.Finalize()` closes the disclosure sequence: afterwards `Emit`
   refuses with `issuer_finalized`. It does not zeroize anything — plaintext
   is zeroized by `Emit` and by `StagedSequencer.Run` on every path. The
   sequencer calls `Finalize` after the last component and after an
   audit-append failure; after a refused emission it calls it only when
   `SequencerOptions.FinalizeOnError` is set.
3. A session nobody closes expires at its ExpiresAt.

No binary keeps sessions, so there is nothing to close on a deployment.

---

## 7. Receive-side round trip (bootstrap flow)

The nine stages above describe the release side — the Vault's
authoritative emission of a signed Genome. The **receive side**
reverses the flow: a downstream operator uses the released
artifacts to reconstitute the Genome inside a new TEE-bounded
environment, under a distinct authority, without ever holding the
release side's signing keys. The receive side is six stages, not
nine, because it does not re-issue the Genome — it only verifies
that what arrived is what was released.

The receive-side flow is implemented by `/internal/bootstrap/`
(the Orchestrator), `/internal/reassembly/` (the Reassembler) and
`/internal/recvvalidator/`. Like the release side, no shipped binary
drives it: `make demo` Act II (`TestRoundtripSlice_*`) and
`internal/bootstrap/driver_integration_test.go` do. (`acp-bootstrap`,
the cross-cloud destination in 06, restores v3 genome bundles through a
different path: `internal/genome/bundle` and `internal/bootstrap/restorer`.)
Throughout this section, the stages are numbered **R.1–R.6** so
they do not collide with the release-side 1–9.

### 7.1 The two-tier integrity split

Everything in the receive-side flow rests on a single
architectural idea: **integrity is checked twice, in two different
places, at two different layers of the envelope**, and both checks
are independently necessary.

**Tier 1 — wire integrity.** The Orchestrator holds a SHA-256 hash
of the canonical bytes of every expected DisclosureMessage
envelope. On every `Accept`, it hashes the arriving bytes and
refuses if they diverge. This catches any modification made in
transit (a byte flipped on the wire, a replayed-but-altered
envelope, a swapped ciphertext). Refusal code:
`bootstrap.CodeAcceptWireHashMismatch`, category **Integrity**.

**Tier 2 — content integrity.** The Reassembler opens the sealed
payload (AES-256-GCM under the 5-field AAD), computes the
plaintext's SHA-256, and compares it to the AGD's committed leaf
hash for that component. It also checks byte-size against the
AGD's committed size. Refusal codes:
`reassembly.CodeComponentHashMismatch` and
`reassembly.CodeComponentByteSizeMismatch`, both category
**Integrity**.

Tier 1 alone is insufficient. A release-side adversary who holds
the envelope-signing key can re-seal a forged plaintext under the
correct AAD, re-sign the envelope, and re-pin the wire-hash
commitment — from the wire's perspective nothing is wrong. Only
tier 2 closes this attack, because tier 2 checks against the AGD's
Ed25519-signed Merkle root, which the adversary cannot forge
without also forging the AGD's signature.

Tier 2 alone is insufficient too. An in-flight tamperer would
only be caught AFTER the orchestrator has already emitted a
`DISCLOSURE_RECEIVED` audit event for a counterfeit envelope,
muddying the evidence trail. Tier 1 stops tamper BEFORE audit
commitment. Both are required.

### 7.2 Stage R.1 — BootstrapManifest issuance

**Who runs:** the receive-side authority (a distinct operator
from the release side — invariant #1).

**Input:** the release-side `ReconstructionJobManifest` (arrived
out of band) and the ordered list of `DisclosureID`s the receive
side is about to accept.

**Output:** a signed `BootstrapManifest` binding
`(BootstrapID, SessionID, ManifestID, GenomeID, PolicyVersion,
ExpectedDisclosureIDs, ExpectedComponentIDs, Deadline)` under the
receive-side authority key.

**Invariant:** the BootstrapManifest's `ExpectedDisclosureIDs`
must match the release-side RJM's `DisclosureIDs` **in order** (not
just as a set). A permutation is refused at agreement check time —
this is the `TestCheckAgreement_DisclosureOrderMismatch_PermutationRefused`
test and is doctrine-critical: the stage-position binding is what
prevents an adversary from reshuffling otherwise-valid envelopes.

**Package:** `/internal/contracts/bootstrap_manifest`.

### 7.3 Stage R.2 — Orchestrator.Start

**Code:** instantiates the `Orchestrator` with the signed
BootstrapManifest, the release-side RJM, the committed
`ExpectedWireHashes` list, the audit chain, and the receive-side
authority + audit signing keys. `Start()` validates both manifests,
verifies their signatures, and runs `CheckAgreement` across the
canonical five fields (session, manifest, policy, genome,
disclosures).

**State transition:** `StateUnstarted → StateIngress`.

**Refusal codes:** any of the six
`bootstrap.agreement.*` codes (session/manifest/policy/genome/
disclosures-length/disclosures-order mismatches); plus
`CodeAlreadyStarted` (Structural) if `Start` is called twice; plus
whatever signature-validation error `BootstrapManifest.VerifySignature`
returns (surfaced verbatim — no re-wrapping).

**Package:** `/internal/bootstrap`.

### 7.4 Stage R.3 — Accept loop (tier 1)

**Code:** for each arriving DisclosureMessage in sequence
order, calls `Orchestrator.Accept(msg)`. Accept checks the
envelope's position (must match the next expected slot), verifies
the envelope's own signature, and hashes its canonical bytes
against the committed `ExpectedWireHashes[i]`. On match, Accept
appends a `DISCLOSURE_RECEIVED` audit event **before** the
`ReceivedDisclosure` record becomes visible (invariant #8 mirror).

**State transition:** each Accept holds `StateIngress` until the
last slot is filled; the final Accept transitions to
`StateReassemble`.

**Refusal codes (all Structural unless noted):**
`CodeAcceptWireHashMismatch` (**Integrity** — the main tier-1 signal),
`CodeAcceptWrongState` (Structural — Accept called in a non-Ingress
state), `CodeAcceptSessionMismatch`, `CodeAcceptPolicyMismatch`,
`CodeAcceptDisclosureNotExpected`, `CodeAcceptOutOfOrder`,
`CodeAcceptComponentMismatch`, `CodeAcceptSequenceMismatch`. Envelope
signature/shape failures are surfaced verbatim from `msg.Validate`.

**Operator signal:** a tier-1 refusal means the wire path is
compromised. The response is procedural — terminate the session,
rotate transport keys, investigate the wire. The receive-side code
has nothing more to say about it.

### 7.5 Stage R.4 — Reassembler.Admit loop (tier 2)

**Code:** constructs an `AGDReassembler` against the signed
AGD, the caller-supplied `ComponentMap`, and the sealer. For each
accepted envelope, calls `Reassembler.Admit(msg)`. Admit rebuilds
the 5-field AAD from the envelope's `(SessionID, ComponentID,
SequenceIndex, PolicyVersion, RecipientKeyID)`, opens the sealed
payload via AES-256-GCM, computes the plaintext's SHA-256, and
compares it to the AGD's committed leaf hash for the matching
component.

**Refusal order (finalized → nil → validate → unknown → duplicate
→ AAD → Open → byte-size → SHA-256):**
`CodeReassemblerFinalized` (Operational),
`CodeNilArgument`, `CodeUnknownComponent`,
`CodeDuplicateComponent`, `CodeSealedOpenFailed` (Integrity; covers
both AAD drift and ciphertext tamper — the GCM tag is the
adjudicator), `CodeComponentByteSizeMismatch` (Integrity),
`CodeComponentHashMismatch` (Integrity — the main tier-2 signal).

Plaintext bytes are zeroized on every refusal path that reached
`Sealer.Open` (invariant #7 mirror: no plaintext substring escapes
in error messages; no plaintext lingers in memory past refusal).

**Operator signal:** a tier-2 refusal means the release-side
authority emitted a DisclosureMessage whose sealed content does
not match the genome it committed to. The response is forensic —
escalate to the incident runbook (see `03_incident_response.md`);
do NOT re-try; preserve the sealed envelope and the Orchestrator's
audit chain as evidence.

### 7.6 Stage R.5 — Reassembler.Finalize

**Code:** `Finalize()` re-verifies coverage (every committed
`ComponentID` has been admitted), rebuilds the RFC 6962 Merkle
tree from the admitted leaves, compares its root to
`agd.ComponentTreeRoot`, and asserts
`agd.DeriveID() == agd.GenomeID` (the R-14 content-addressing
invariant, mirrored at reassembly time).

**Refusal codes:** `CodeCoverageIncomplete` (Structural),
`CodeMerkleRootMismatch` (Integrity),
`CodeGenomeIDRoundTripMismatch` (Integrity).

**Idempotence:** Finalize stores its result or error on the first
call; a second call returns the same outcome verbatim. This is
covered by `TestAGDReassembler_Finalize_IdempotentOnSuccess` and
`TestAGDReassembler_Finalize_IdempotentOnFailure`
(`internal/reassembly/agd_reassembler_test.go`).

### 7.7 Stage R.5.5 — Receive-side validator (Stage G)

**Code:** once Finalize succeeds, the driver calls
`MarkReassembled` (state → `StateValidate`) and hands control to
`recvvalidator.ValidationService`. The service runs six
`op.recv.*` sub-checks (`internal/recvvalidator/operational.go`) over the
attestation + session + BootstrapManifest already cached on the receive
side:

  - `op.recv.attestation_valid` — outcome = Allow and signature
    verifies under the trust-authority key
  - `op.recv.attestation_ttl` — `Now` is within
    `[IssuedAt, IssuedAt + TTL)` and TTL is strictly positive
  - `op.recv.session_valid` — session is Active, not expired,
    signature verifies, and its `session_id` equals the
    BootstrapManifest's
  - `op.recv.bootstrap_manifest_integrity` — BootstrapManifest signature
    verifies under the receive-side authority key
  - `op.recv.reassembly_coverage` — `Admitted == Expected ==
    len(ExpectedDisclosureIDs)`
  - `op.recv.policy_alignment` — `ActivePolicy` equals both the
    session's and the manifest's `PolicyVersion`

The operational dimension is binary by doctrine: `Threshold=1.0`,
any failing sub-check yields `Verdict=Fail`; the aggregated
`OverallVerdict` follows the receive-side mirror of Stage 7 — an
operational Fail is a hard veto. On success the driver calls
`MarkValidated(vr.ValidationResultID)` (state → `StateReady`);
on failure it calls `MarkValidationFailed(vr.ValidationResultID)`
(state → `StateRejected`) and lets `Decide()` emit the signed
rejection with `Reason=ReasonValidationFailed`.

**Audit events:** the service appends
`RECV_VALIDATION_STARTED` **before** running the sub-checks and
`RECV_VALIDATION_COMPLETED` **before** returning — the
audit-event-before-surface discipline that invariant #8 pins for
the release side, applied symmetrically on the receive side. Both
events land on the same receive-side chain the orchestrator
writes `DISCLOSURE_RECEIVED` and `RECONSTITUTION_DECIDED` into,
so an auditor reads one tape end-to-end.

**Refusal codes:** `op.recv.attestation_valid`,
`op.recv.attestation_ttl`, `op.recv.session_valid`,
`op.recv.bootstrap_manifest_integrity`, `op.recv.reassembly_coverage`,
`op.recv.policy_alignment`. The validator does **not**
short-circuit — every sub-check runs so auditors see the full
correlated set of findings in a single `COMPLETED` event.

### 7.8 Stage R.6 — Orchestrator.Decide

**Code:** drives the state machine through `MarkReassembled`
→ (Stage G) → `MarkValidated(vrid)` → `Decide()` on the happy
path, or `MarkReassemblyFailed` → `Decide` / `MarkValidationFailed(vrid)`
→ `Decide` on a refusal. Decide builds a
`ReconstitutionDecision` binding `(BootstrapID, SessionID,
GenomeID, ValidationResultID, Accepted, Reason, AuditEventID,
DecidedAt)`, signs it under the receive-side authority key, and
appends a `RECONSTITUTION_DECIDED` audit event **before** the
decision becomes visible (invariant #8 mirror).

On a reassembly-failure path the driver routes via
`MarkReassemblyFailed` → `Decide`; Decide mints a sentinel
`ValidationResultID` of the form `vr-recv-noop-<bootstrapID>`
(because no validator ever ran). Observers distinguish this
sentinel from a real VRID by reading `Reason`
(`ReasonReassemblyFailed` vs. `ReasonReconstructedOK`). The
sentinel is **not** a validator identity — it is a terminal-state
honesty marker.

On a validation-failure path the driver routes via
`MarkValidationFailed(vr.ValidationResultID)` → `Decide`; Decide
cites the REAL VRID that Stage G minted, and emits the signed
rejection with `Reason=ReasonValidationFailed`. Auditors can
trace the verdict back to its `RECV_VALIDATION_COMPLETED` anchor
via the VRID alone.

**Chain length after a successful round trip:** `N + 3` — one
`DISCLOSURE_RECEIVED` per Accept, plus one
`RECV_VALIDATION_STARTED`, one `RECV_VALIDATION_COMPLETED`, and
one `RECONSTITUTION_DECIDED`. `chain.Verify(resolver)` must
succeed; if it does not, the receive side is in an inconsistent
state and the response is forensic.

### 7.9 Receive-side failure triage

When something goes wrong on the receive side, the refusal code's
**category** and **tier** are the two axes to read first:

| Tier | Category     | Example code                        | Action |
|------|--------------|-------------------------------------|--------|
| 1    | Integrity    | `CodeAcceptWireHashMismatch`        | Procedural. Terminate session, rotate transport keys, investigate wire path. Reassembler was never touched. |
| 1    | Structural   | `CodeAcceptSequenceMismatch` / `CodeAcceptOutOfOrder` | Wire reordering or a broken driver. Check envelope arrival order. |
| 2    | Integrity    | `CodeComponentHashMismatch`         | **Forensic.** Release-side authority emitted a mismatch against its own AGD. Preserve evidence; escalate per `03_incident_response.md`. |
| 2    | Integrity    | `CodeSealedOpenFailed`              | Either AAD drift (check the 5-field AAD shape on both sides) or GCM tag mismatch (ciphertext tamper that slipped past tier 1 — this should never happen; if it does, suspect shared-secret compromise). |
| 2    | Structural   | `CodeCoverageIncomplete`            | Local drop. Check receive-side driver; the orchestrator reports all accepted envelopes via `Received()`. |
| pre  | Structural   | `bootstrap.agreement.*`             | Receive-side manifest disagrees with the release-side RJM at Start time. Most often `disclosure_order_mismatch` (ordered permutation) or `genome_mismatch` (mismatched GenomeID). Do not retry without a new manifest. |

**Cross-side audit chain.** The release-side chain (Stages 1–9)
and the receive-side chain (Stages R.3/R.6) are distinct chains
under distinct audit keys. Cross-verification is by shared
identifiers — `SessionID`, `ManifestID`, `GenomeID`,
`BootstrapID`. A correct round trip produces two independently
verifiable chains whose records can be cross-joined on those
fields; a diverging chain on either side is sufficient evidence to
refuse acceptance, even if the other side verifies.

**Package:** `/internal/bootstrap` + `/internal/reassembly` +
`/internal/audit`.

---

## Session closure (receive side)

After Stage R.6 on the final BootstrapManifest, the receive-side
session is closed the same way as the release side (see Session
closure above): the audit chain tip is recorded and the Orchestrator
is allowed to go out of scope. The Orchestrator's single-shot
discipline means that once `Decide` has emitted a terminal
`ReconstitutionDecision`, every subsequent call (`Decide` again,
`Accept`, any `Mark*`) refuses with `CodeAlreadyDecided` or
`CodeAcceptWrongState` — there is no continued-use path from a
reconstituted session, by design.

---

_Document history: 2026-09-14 — checked line by line against the code; commands and names the binaries do not have were removed._
