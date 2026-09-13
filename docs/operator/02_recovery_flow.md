# Recovery Flow — Nine-Stage Walkthrough

**Purpose:** a narrated, stage-by-stage walkthrough of a recovery session
from the first Recovery Request to the final Audit append. For each stage
the runbook identifies (a) what the operator must verify, (b) what the
code does, and (c) what the doctrine requires.

**Prerequisite:** preflight (see `01_preflight.md`) completed green within
the last hour.

---

## Stage 1 — Recovery Request

**Trigger:** an administrator or an authorised upstream process submits a
RecoveryRequest to the Vault's intake surface.

**Vault does:** validates the RecoveryRequest contract (non-empty
RequestID, non-zero SchemaVersion, caller identity bound to a known
identity cert), appends `RECOVERY_REQUEST_INTAKE` to the audit chain,
moves workflow state from `StateIntake` to `StateTrust`.

**Operator verifies:** the audit event was appended (single event, not a
batch), the RequestID is unique for this session, and the workflow state
transition was recorded.

**Doctrine:** intake is never skipped. A session that enters the Vault
without a matching intake audit event is a per-doctrine invariant
violation of "sessions are mandatory" (#3) and must be terminated.

**Package:** `/internal/vault/intake`.

---

## Stage 2 — Trust Admission

**Trigger:** workflow state entered `StateTrust`.

**Vault does:** evaluates the caller against the active policy bundle.
Three possible outcomes — **admit**, **restrict**, **deny**. A `deny`
transitions to a terminal `StateDenied`; a `restrict` admits with reduced
component-class scope; an `admit` transitions to `StateSession`.

**Operator verifies:** the decision matches what policy would predict; a
`restrict` outcome produced a scoped ComponentClassFilter; an audit event
of kind `TRUST_DECISION` was appended.

**Doctrine:** "trust is a gate, not a log" (invariant #2). A trust
decision is not advisory — a `deny` or `restrict` mechanically constrains
the allowed state transitions, not merely the audit record. This is
enforced at the transition-table level in `/internal/vault/orchestration`.

**Package:** `/internal/vault/trust`.

---

## Stage 3 — Trusted Session

**Trigger:** workflow state entered `StateSession`.

**Vault does:** mints a SessionObject — a signed, TTL-bounded capability
carrying the SessionID, the admitted component-class scope, the
recipient-key identity, the approved disclosure policy hash, and the
expiry. Signature is by the `SigningAuthority` key.

**Operator verifies:** SessionID is unique and non-zero; signature
verifies; expiry is within policy bounds (not longer than the policy
cap); session is bound to a single recipient key (no multi-recipient
sessions at MVP).

**Doctrine:** every downstream message in the flow — DisclosureMessage,
ReconstructionJobManifest, ReleaseDecision — must carry this SessionID
and fail validation without it. See invariant #3.

**Package:** `/internal/vault/session`.

---

## Stage 4 — Staged Disclosure

**Trigger:** workflow state entered `StateDisclosure`.

**Vault does:** drives the **StagedSequencer** (see
`/internal/vault/disclosure/sequencer.go`). The sequencer walks the
ordered Component list, delegates each emission to **StagedIssuer**, and
— critically — appends a `DISCLOSURE_AUTHORIZED` AuditEvent **before**
surfacing each DisclosureMessage to the caller. Each message is a single
Component, carrying SequenceIndex and recipient-key-bound AAD.

**Operator verifies:** exactly one AuditEvent per DisclosureMessage; no
batch emission (`SequenceIndex` strictly monotonic, one message per step,
no bulk field); plaintext zeroization runs on every short-circuit.

**Doctrine:**
- "Disclosure is staged" (invariant #4) — no bulk disclosure; the message
  shape itself forbids it (scalar ComponentID, no slice, Emit signature
  returns a single message).
- "Audit is first-class" (invariant #8) — audit-append failure is a
  terminal condition; the sequencer finalizes the run rather than
  proceeding with a disclosure that has no audit counterpart.
- "No raw export" (invariant #7) — the import graph static audit forbids
  any non-vault package from importing the disclosure primitives.

**Package:** `/internal/vault/disclosure`.

---

## Stage 5 — Delegated External Compute

**Trigger:** the compute-plane operator receives the first
DisclosureMessage and must act.

**Compute plane does:** constructs a ReconstructionJobManifest per the
session-scoped component, unseals the DisclosureMessage using the
recipient-key (AAD-bound), runs the reconstruction step, produces a
result bound to (SessionID, ComponentID). Stays within its scope: does
not request additional components, does not persist plaintext past the
manifest's scope, does not forward plaintext outside the session.

**Operator (compute plane) verifies:** manifest integrity check passed;
the unseal step produced a valid plaintext under the AAD; the result is
bound to the correct SessionID.

**Operator (Vault) verifies:** the compute plane returned a result within
the session TTL; the result binds to the issued manifest; the compute
plane did NOT request a second component before returning the first
(sequence ordering).

**Doctrine:** the compute plane has delegated execution rights only. It
cannot by itself authorise a ReleaseDecision.

**Package:** `/internal/compute/worker`.

---

## Stage 6 — Return Path

**Trigger:** compute returns a result.

**Vault does:** accepts the return on the Vault-controlled return path,
binds it to the session, moves to `StateValidation`.

**Operator verifies:** the return was accepted into an audit event of
kind `RECONSTRUCTION_RETURNED`; the return's SessionID matches; the
state transition was recorded.

**Doctrine:** the return path is a Vault surface, not a compute-plane
surface. The compute plane is a caller on this path, not its owner.

**Package:** `/internal/compute/returnpath`.

---

## Stage 7 — Validation

**Trigger:** workflow state entered `StateValidation`.

**Vault does:** runs operational validation — six sub-checks in
`/internal/validation/operational`:

| Sub-check | Asserts |
| - | - |
| `op.attestation_valid` | Attestation body verifies against pinned root |
| `op.attestation_ttl` | Attestation not expired |
| `op.session_valid` | SessionObject signature valid, not expired, bound to current recipient key |
| `op.manifest_integrity` | ReconstructionJobManifest integrity unchanged since issue |
| `op.tamper_absent` | No tamper signal raised for this session |
| `op.policy_alignment` | Effective policy at validation time matches the policy hash pinned into the session |

Threshold: 1.0. No partial pass. A single sub-check failure blocks
release.

Semantic and behavioral validation are out of MVP scope (see `docs/internal/status-journal.md`
§3 — MVP-SCOPED — and `docs/doctrine/validation-thresholds.md` for the frozen
thresholds).

**Operator verifies:** all six operational sub-checks are individually
green; the aggregate ValidationResult carries the SessionID it validates.

**Doctrine:** "validation precedes release" (invariant #5). The
transition table makes `StateRelease` reachable only from `StateValidation`
or `StateTrust` (the `StateTrust → StateRelease` edge is for `deny`
outcomes that release a terminal decision without a session).

**Package:** `/internal/validation/operational`.

---

## Stage 8 — Release Decision

**Trigger:** workflow state entered `StateRelease`.

**Vault does:** issues a signed ReleaseDecision carrying (SessionID,
ValidationResultID, AuditEventID of the authorizing audit event, and the
release verdict). Signature is by `SigningAuthority`. The ReleaseDecision
is itself the object that downstream systems rely on.

**Operator verifies:** the ReleaseDecision carries both a
ValidationResultID (invariant #5 structural check) and an AuditEventID
(invariant #8 structural check); the signature verifies; the decision
chains back, through its referenced ValidationResult, to the original
RecoveryRequest.

**Doctrine:**
- "Validation precedes release" — enforced by the ValidationResultID
  field check.
- "Audit is first-class" — enforced by the AuditEventID field check.
- "Contracts are frozen" (#9) — the ReleaseDecision struct has
  SchemaVersion as its first field, with pinned `{Min, Max, Current}`
  constants.

**Package:** `/internal/vault/orchestration` (drives);
`/internal/contracts/release_decision` (contract).

---

## Stage 9 — Audit

**Trigger:** every stage transition.

**Vault does:** appends an AuditEvent of the appropriate stage-bearing
Kind (`RECOVERY_REQUEST_INTAKE`, `TRUST_DECISION`, `SESSION_ISSUED`,
`DISCLOSURE_AUTHORIZED`, `RECONSTRUCTION_RETURNED`, `VALIDATION_RESULT`,
`RELEASE_DECISION`, plus `PREFLIGHT_RESULT` and
`INCIDENT_DECLARED`). The chain-tip advances under `SigningAudit`.

**Operator verifies:** every stage has at least one audit event; the
chain is continuous (no gap in the hash chain); the final tip is stored
externally for later cross-check (see `04_observability.md`).

**Doctrine:**
- "Audit is first-class" (#8) — AuditEvent.Kind enumerates all nine
  stage-bearing kinds; Release carries AuditEventID of the authorizing
  event; audit append is synchronous with the authorising transition,
  not deferred.

**Package:** `/internal/audit`.

---

## Session closure

After Stage 9 on the final component, the session is terminated. Correct
termination requires:

1. A `SESSION_TERMINATED` audit event.
2. The StagedSequencer's `Finalize()` method run to completion, which in
   turn zeroizes any remaining plaintext in the disclosure buffers.
3. The session TTL to have expired OR the administrator to have
   explicitly closed it.
4. The audit chain tip to be recorded externally for cross-check.

A session that is not explicitly terminated is assumed to have failed.
The next preflight will flag any session without a terminating event.

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

The receive-side flow is pinned down by
`docs/doctrine/bootstrap-contracts.md` and implemented by the
`/internal/bootstrap/` and `/internal/reassembly/` packages.
Throughout this section, the stages are numbered **R.1–R.6** so
they do not collide with the release-side 1–9.

### 7.1 The two-tier integrity split

Everything in the receive-side flow rests on a single
architectural idea pinned in doctrine §8.4: **integrity is checked
twice, in two different places, at two different layers of the
envelope**, and both checks are independently necessary.

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

**Vault does:** instantiates the `Orchestrator` with the signed
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

**Vault does:** for each arriving DisclosureMessage in sequence
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

**Vault does:** constructs an `AGDReassembler` against the signed
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

**Vault does:** `Finalize()` re-verifies coverage (every committed
`ComponentID` has been admitted), rebuilds the RFC 6962 Merkle
tree from the admitted leaves, compares its root to
`agd.ComponentTreeRoot`, and asserts
`agd.DeriveID() == agd.GenomeID` (the R-14 content-addressing
invariant, mirrored at reassembly time).

**Refusal codes:** `CodeCoverageIncomplete` (Structural),
`CodeMerkleRootMismatch` (Integrity),
`CodeGenomeIDRoundTripMismatch` (Integrity).

**Idempotence:** Finalize stores its result or error on the first
call; a second call returns the same pointer verbatim. This is the
same-pointer (`require.Same`) discipline covered by
`TestReassembler_Finalize_IsIdempotent`.

### 7.7 Stage R.5.5 — Receive-side validator (Stage G)

**Vault does:** once Finalize succeeds, the driver calls
`MarkReassembled` (state → `StateValidate`) and hands control to
`recvvalidator.ValidationService`. The service runs six
`op.recv.*` sub-checks over the attestation + session +
BootstrapManifest already cached on the receive side:

  - `op.recv.attestation.valid` — outcome = Allow and signature
    verifies under the trust-authority key
  - `op.recv.attestation.ttl` — `Now` is within
    `[IssuedAt, IssuedAt + TTL)` and TTL is strictly positive
  - `op.recv.session.valid` — session is Active, not expired,
    signature verifies, and its `session_id` equals the
    BootstrapManifest's
  - `op.recv.bootstrap.integrity` — BootstrapManifest signature
    verifies under the receive-side authority key
  - `op.recv.reassembly.coverage` — `Admitted == Expected ==
    len(ExpectedDisclosureIDs)`
  - `op.recv.policy.alignment` — `ActivePolicy` equals both the
    session's and the manifest's `PolicyVersion`

The operational dimension is binary by doctrine: `Threshold=1.0`,
any failing sub-check yields `Verdict=Fail`; the aggregated
`OverallVerdict` follows the receive-side mirror of §5 — an
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

**Refusal codes:** `op.recv.attestation.valid`,
`op.recv.attestation.ttl`, `op.recv.session.valid`,
`op.recv.bootstrap.integrity`, `op.recv.reassembly.coverage`,
`op.recv.policy.alignment`. The validator does **not**
short-circuit — every sub-check runs so auditors see the full
correlated set of findings in a single `COMPLETED` event.

### 7.8 Stage R.6 — Orchestrator.Decide

**Vault does:** drives the state machine through `MarkReassembled`
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
(`ReasonReassemblyFailed` vs. `ReasonReconstructedOK`). This
sentinel is documented in the F.2 doctrine note and is **not** a
validator identity — it is a terminal-state honesty marker.

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
**category** and **tier** are the two axes an operator reads first:

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
session is terminated identically to the release side (see §6 /
Session closure above): the audit chain tip is recorded externally
and the Orchestrator is allowed to go out of scope. The
Orchestrator's single-shot discipline means that once `Decide` has
emitted a terminal `ReconstitutionDecision`, every subsequent call
(`Decide` again, `Accept`, any `Mark*`) refuses with
`CodeAlreadyDecided` or `CodeAcceptWrongState` — there is no
continued-use path from a reconstituted session, by design.
