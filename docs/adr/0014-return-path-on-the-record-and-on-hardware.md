# ADR 0014: The Return Path on the Record, and on Hardware

**Status:** Accepted — implemented (2026-09-16)
**Date:** 2026-09-16
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Builds on:** ADR 0013 (the worker restores the genome), ADR 0007 (variable-length measurements), ADR 0009 (SEV-SNP verification to the AMD root), ADR 0010 (recorded refusals)
**Amends:** `sagvd` configuration (an `audit` section, required with gate jobs); `sagvd` and `acp-compute` configuration (`tee.provider`, `tee.peer.provider`); `acpctl audit query --json` (payloads are embedded)

---

## Context

After ADR 0013 the Return Path carried a real model and the authority judged
what came back. Two things about it were still not what this project says of
itself.

**The daemon's decisions were not on the record.** Doctrine invariant #08 —
audit is first-class, a decision exists on the record before it takes effect —
held for the cross-cloud subcommands, whose every release and refusal goes to
a durable, signed, hash-linked log (ADR 0010, 0011). The `sagvd` daemon wrote
no log at all: a gate job was accepted, a worker admitted or refused, a
candidate received and a verdict signed, and none of it left a record an
auditor could verify. The operator docs said so plainly ("Writes no audit
log"); it was honest and it was a gap.

**Both ends of the Return Path attested with the simulator.** `acp-bootstrap`
attests with AMD SEV-SNP through the kernel's configfs-tsm and `sagvd`'s
verifier registry checks it to the AMD root; `sagvd` itself and `acp-compute`
still ran the simulated TEE only, whose Evidence a key read from a file
signs, and refused to start unless the config acknowledged that
(KNOWN_ISSUES #1). The handshake, the challenge binding and the frozen
Producer/Verifier interfaces (ADR 0001) were the same ones the hardware path
uses; only the wiring in the two daemons named a single backend.

## Decision

### Every decision the daemon takes is on the record first

`sagvd` keeps a Return Path audit log — `audit.log_path`, a bbolt file, the
same format, chain and signing key (`keys.audit_signing`) as the cross-cloud
log, in its own file because one process holds a log at a time. It is opened
and verified end to end at start; a log that does not verify stops the
daemon. With gate jobs enabled the log is required.

Events, with the existing release-side kinds (no schema bump):

| Kind | When | Before what |
|---|---|---|
| `MANIFEST_ISSUED` | a gate job was built | it is queued and its id returned |
| `TRUST_EVALUATED` (deny) | a peer's TLS or Return Path handshake was refused | the connection is closed |
| `TRUST_EVALUATED` (allow) | a job is handed to a worker whose Evidence verified | the JobRequest leaves the vault |
| `CANDIDATE_RECEIVED` | a signed candidate passed the Return Path's binding, budget and signature checks | it is judged |
| `VALIDATION_STARTED`, `VALIDATION_DIMENSION_EVALUATED`, `VALIDATION_FINDING`…, `VALIDATION_COMPLETED` | the gate ran | the verdict is surfaced |
| `SESSION_INVALIDATED` / `INCIDENT_DETECTED` | a job ended without a judged candidate | the job is marked failed |

Payloads are JSON (`vault-genome/returnpath-audit/v1`): the job id, the
genome id and digests, the peer's provider and measurement, the candidate's
digest and signer, the tolerance, every ladder attempt, the verdict's numbers
and the SHA-256 of the signed verdict. Every event about a job carries the
job's `manifest_id` and `session_id`. A refusal carries no job: it names the
peer, the phase and the reason.

**A log that cannot take an event stops the decision.** A job the log did not
record is not queued (503 `audit_unavailable`); a candidate the log did not
record is not judged; a verdict the log did not record is not surfaced, and
the job fails with `audit_unavailable`. `VALIDATION_FINDING` events precede a
failed verdict, as the doctrine has it for every validator.

`acpctl audit verify` verifies the log under the key `sagvd identity`
publishes; `acpctl audit query --json` now embeds each payload, so a reader
sees the decision's fields. `sagvd_audit_events_total{kind}` counts what was
written.

### Both daemons attest with the hardware they run on

`sagvd` and `acp-compute` take `tee.provider`: `gcp-sev-snp` — the chip
signs, reports requested through configfs-tsm, the launch measurement is the
48-byte one the chip reports — or `simulated`, which still requires
`tee.insecure_simulation: true`. The peer pin takes `tee.peer.provider`: a
simulated peer is pinned by its attestation key and measurement; a SEV-SNP
peer by its 48-byte measurement and the AMD ASK+ARK chain
(`amd_cert_chain_path`, with `vcek_cache_dir`, `amd_kds_url`,
`min_reported_tcb` as the verifier registry already has them). The verifier
is the one ADR 0009 proved: VCEK fetched from AMD KDS and chained to ARK,
ECDSA-P384 over the report, no DEBUG, VMPL 0, TCB floor, and REPORT_DATA
binding the handshake's transcript challenge — the same nonce the simulator
signed, so the frozen handshake (rp-wire-v1.0) is unchanged.

`acp-compute identity` prints what the vault pins for a worker (its signing
key, its provider and measurement), as `sagvd identity` does for the vault,
which now also names its provider.

### Proven on hardware

`scripts/hardware-test/gcp-sev-snp/returnpath-e2e/` runs the shipping
`sagvd` and `acp-compute` on one AMD SEV-SNP Confidential VM, both attesting
with the chip and each pinning the other's launch measurement, with the real
`vg_genome` door and a genome fine-tuned on the guest: a gate job goes over
the Return Path and comes back with a signed verdict, the audit log verifies,
and a worker whose Evidence does not match the pin is refused and recorded.
Its README carries the measured run.

## Consequences

- **`sagvd` writes.** Its one write is the audit log, which holds no genome
  material: digests, identifiers, measurements, verdict numbers. Invariant
  #07 is unchanged; `cmd/` is outside its scope in any case, and the log is
  the same package the cross-cloud subcommands already write with.
- **Operators run two logs.** The daemon's `audit.log_path` and the
  subcommands' `crosscloud.audit_log_path` are separate files, both under
  `keys.audit_signing`, both verified by `acpctl audit verify`. A single file
  would need one process to own it; the config refuses the same path for
  both.
- **The simulated TEE is a choice, not the only option.** KNOWN_ISSUES #1 is
  narrowed: both daemons run on SEV-SNP; the simulated backend remains for
  laptops and CI and still announces itself at start.
- **Configuration is explicit about what it trusts.** A peer pin names its
  provider; a SEV-SNP pin without the AMD chain, or a simulated pin with one,
  is refused at start.

## Alternatives considered

- **One audit log for the daemon and the subcommands.** bbolt is a single
  writer; sharing the file means the subcommands cannot run while the daemon
  is up, or the daemon reopens the log per event. Two files, one key,
  one verifier. Refused for now; a log service is a later decision.
- **A new audit kind per Return Path event.** The release-side kinds of
  schema v1 already name these decisions (`MANIFEST_ISSUED`,
  `TRUST_EVALUATED`, `CANDIDATE_RECEIVED`, the `VALIDATION_*` family); a new
  family would have said the same thing twice. Refused.
- **Record trust at the handshake callback instead of at dispatch.** The
  handshake opens a session before a job is chosen; the decision that matters
  is handing a job to that session. The admission is recorded at dispatch,
  with the job; refusals are recorded when they happen.
- **A verifier registry for the Return Path peer.** The vault admits exactly
  one worker TEE identity today; a registry of many is the multi-worker step
  and stays deferred.

## Proven by

- `cmd/sagvd/audit_returnpath_test.go` — fifteen events in order for a job
  accepted, a peer refused and one admitted, a candidate, a passing and a
  failing gate, an invalidated session and an incident; payloads; the log
  verifies under the audit key, reopens and continues; a closed log stops the
  decision; an edited log is refused.
- `cmd/sagvd/http_api_test.go` — a job is on the record under its own id
  before it is queued; a closed log refuses submissions; gate jobs cannot be
  served without a log.
- `cmd/sagvd/config_test.go`, `cmd/acp-compute/config_test.go`,
  `*/keystore_test.go` — every provider and pin combination; the SEV-SNP
  verifier is built off hardware; the SEV-SNP producer refuses to start
  without configfs-tsm.
- `test/integration/daemons_test.go` — the shipping binaries: the log after a
  gate-job round trip verifies under the published key and reads, in order,
  `MANIFEST_ISSUED, TRUST_EVALUATED, CANDIDATE_RECEIVED, VALIDATION_STARTED,
  VALIDATION_DIMENSION_EVALUATED, VALIDATION_COMPLETED`; a refused model
  carries its findings before the failed verdict; an unpinned worker's
  refusal precedes the pinned worker's admission.
- `scripts/hardware-test/gcp-sev-snp/returnpath-e2e/` — run
  `20260915T230907Z` on a GCP SEV-SNP guest: both daemons attesting with the
  chip (measurement `7dc7c12e…25acc`), a simulated-TEE worker refused at the
  handshake and recorded first, the pinned worker's job judged EXACT 6/6 in
  4.30 s, seven audit events verified under the published key.
