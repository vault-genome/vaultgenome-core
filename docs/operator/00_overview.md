# Operator Overview

**Audience:** A new operator onboarding to the AI Continuity Platform core.
**Prerequisite reading:** the eleven doctrinal invariants, asserted as tests in
`test/doctrine/invariants_test.go` ([ADR 0004](../adr/0004-doctrine-invariants-as-tests.md)).
**This document answers:** *who holds what authority, where the boundary
between the Vault and the compute plane lies, and which parts of that design
the shipped binaries run today.*

---

## 0. What ships today

| Binary | What it does | Built by `make build` |
| - | - | - |
| `sagvd` (daemon) | Return Path listener for `acp-compute` workers (mTLS required off loopback); operator REST API (`POST /v1/jobs`, `GET /v1/jobs/{id}`); health listener (`/healthz`, `/readyz`, `/metrics`). Attests with the simulated TEE only. Writes no audit log. | yes |
| `sagvd identity`, `sagvd crosscloud-restore`, `sagvd crosscloud-confirm` | Print the keys other hosts pin; release genome keys to an attested destination and confirm its restore ([06](06_cross_cloud_restore.md)). The two cross-cloud subcommands write the only audit log any binary writes (`crosscloud.audit_log_path`). | same binary |
| `acp-compute` | Worker: dials sagvd's Return Path and runs one job per session with the placeholder reconstruction backend (KNOWN_ISSUES #2). Simulated TEE only. | yes |
| `acp-bootstrap` | Cross-cloud destination: attests with AMD SEV-SNP (or the simulator), receives genome keys, restores genomes, signs receipts. | yes |
| `acpctl` | Administrative CLI (§1.3). | yes |
| `acp-demo` | Self-contained cross-hardware regeneration demo. | yes |

The nine-stage flow in §2 is library code under `internal/`. No shipped binary
drives it: it runs in-library in `make demo` (`internal/integration`,
`TestVerticalSlice_*` and `TestRoundtripSlice_*`) and in the other tests.
Documents 01–04 describe that flow and say, item by item, what a deployment
can check today.

---

## 1. Two operator roles

The platform splits responsibility across two distinct roles, and this split
is doctrine. Collapsing them is an invariant violation.

### 1.1 Vault operator

**Runs:** `sagvd` (Secure AI Genome Vault Daemon).

**Holds authority over (by design):** every continuity-relevant decision —
intake, trust admission, session issuance, policy evaluation, disclosure
sequencing, release decision, audit appendage. The Vault is **the sole source
of truth** for what is allowed to happen next in the nine-stage flow. In this
build the daemon implements none of those stages; its authority in practice is
the job queue behind the REST API and, through `sagvd crosscloud-restore`, the
release of genome keys to attested destinations under the operator's
allow-list and signed stop list (06).

**Must have:** the key files its config names — `keys.authority_signing`
(Ed25519 seed; signs cross-cloud handshakes and key-release tokens),
`keys.session_sealing` (AES-256 key shared with the workers) and, for
cross-cloud releases, `keys.audit_signing`; custody of the cross-cloud audit
log; the allow-list and verifier registry; the operator's public key for the
stop list.

**Must NOT:** run generative reconstruction workloads. The Vault is
intentionally compute-light; heavy work is delegated outward by design.

### 1.2 Compute-plane operator

**Runs:** `acp-compute` (one or more external workers).

**Holds:** delegated execution rights only. In the design, workers receive
DisclosureMessage sequences scoped to one session and component, execute the
authorised reconstruction step and return a result bound to the session. The
shipped worker does a narrower job: it dials sagvd's Return Path, completes a
handshake in which each side checks the other's TEE Evidence against pinned
values, receives one JobRequest whose payload sagvd sealed under the
session-sealing key, runs the reconstruction backend and returns a
CandidateOutputFrame signed with its worker key. It gains no continuity
authority and cannot issue a ReleaseDecision.

**Must have:** `tee.insecure_simulation: true` in its config — `acp-compute`
attests with the simulated TEE only and refuses to start otherwise (it has no
hardware backend, and no Intel TDX adapter exists anywhere in this
repository); the same `keys.session_sealing` kid and key as sagvd; a worker
signing key whose kid and public key are listed in sagvd's
`workers.registry_path`. The only binary that attests with real hardware is
`acp-bootstrap` on AMD SEV-SNP (`tee.provider: "gcp-sev-snp"`, see
[runbooks/real-tee-sev-snp.md](runbooks/real-tee-sev-snp.md)).

**Must NOT:** log, persist, or forward plaintext disclosed material outside
the bounds of the session. A worker that caches plaintext past session
termination is by definition in violation of invariant #7 ("No raw export").

### 1.3 Administrator

**Runs:** `acpctl` (administrative CLI).

**Holds:** inspection tools and the operator's signing key for stop lists.
The commands that exist:

| Command | Purpose |
| - | - |
| `acpctl status --audit PATH [--json]` | Summary of an audit log: event count, time range, kinds, latest event |
| `acpctl audit query --audit PATH [--kind K] [--session S] [--manifest M] [--since T] [--until T] [--limit N] [--json]` | List events |
| `acpctl audit verify --audit PATH --audit-pubkey FILE --audit-kid KID [--json]` | Replay the chain from its first event, check every hash and signature, print the tip |
| `acpctl lineage --audit PATH (--session-id ID \| --manifest-id ID) [--json]` | Events tied to one session or manifest |
| `acpctl genome seal \| open (alias rewind) \| verify \| inspect \| chain \| lineage \| gate` | Seal, restore and check genome bundles |
| `acpctl stop keygen \| issue \| verify` | Create and check the operator's signed stop list (06) |
| `acpctl escrow keygen` | Create the release authority's key-escrow key pair; `genome seal --escrow-to` seals genome keys to its public half (06) |
| `acpctl recover --vault PATH …` | Unseal a `VG-VAULT-01` envelope with the TEE backend it names; no shipped binary writes that format yet |

The audit commands read any audit log file; in practice the one
`sagvd crosscloud-restore` writes. No command issues a ReleaseDecision and
none appends audit events — release authority lives only in the Vault's
disclosure-and-release pipeline and is driven by validated work products, not
by CLI invocation.

---

## 2. The nine stages (one-line each)

| # | Stage | Authority holder | Package | Code today |
| - | - | - | - | - |
| 1 | Recovery Request | Vault — intake | `/internal/vault/intake` | Package holds `doc.go` only; the contract is `/internal/contracts/recovery_request` |
| 2 | Trust Admission | Vault — trust | `/internal/vault/trust` | Package holds `doc.go` only; the contract is `/internal/contracts/attestation_result` |
| 3 | Trusted Session | Vault — session | `/internal/vault/session` | In-memory session Issuer |
| 4 | Staged Disclosure | Vault — disclosure (StagedIssuer + StagedSequencer) | `/internal/vault/disclosure` | Implemented |
| 5 | Delegated External Compute | Compute plane — worker | `/internal/compute/worker` | Placeholder backend, used by `acp-compute` |
| 6 | Return Path | Compute plane, gated by Vault | `/internal/compute/returnpath` | Used by `sagvd` and `acp-compute` |
| 7 | Validation | Vault — validation/operational | `/internal/validation/operational` | Implemented, with `/internal/validation/service` |
| 8 | Release Decision | Vault — orchestration | `/internal/vault/orchestration` | Transition table only; the contract is `/internal/contracts/release_decision` |
| 9 | Audit | Vault — audit | `/internal/audit` | Hash chain and bbolt store |

Authority moves through the Vault for stages 1–4, 6–9 and through the compute
plane for stage 5 only. The legal transitions between stages are listed in
`/internal/vault/orchestration/state.go` and checked by the doctrine tests in
`/test/doctrine/invariants_test.go`; nothing drives that state machine at run
time. The tests call each stage in order and append the audit events the
library does not yet emit itself.

---

## 3. What the Vault is NOT

It is useful to state this plainly up front so first-week confusions are
avoided:

- **The Vault is not a model server.** It does not serve inference traffic.
- **The Vault is not a backup target.** It does not store model weights.
  It stores the AI Genome and the authority objects that govern its
  disclosure.
- **The Vault is not a key management service.** It uses one internally,
  but KMS-equivalent duties are a subset of its function, not the whole.
- **The Vault is not a DR tool.** Disaster recovery addresses artifact
  survival. The Vault addresses *continuity of intelligence* — the right
  and the ability to reconstruct AI capability in a new trusted environment.
- **The Vault is not a research platform.** Every function the Vault
  exposes is a production-path function. Exploratory work happens
  elsewhere.

---

## 4. Reading this runbook

- `01_preflight.md` — what to check before relying on a deployment.
- `02_recovery_flow.md` — the nine-stage flow and the receive-side round trip,
  as implemented in the library and exercised by the tests.
- `03_incident_response.md` — the incident module's three MVP scenarios, the
  two it defers, and what an operator does.
- `04_observability.md` — how to prove, after the fact, what happened.
- `05_release_procedure.md` — the signed-tag / SBOM / cosign / SLSA release loop.
- `06_cross_cloud_restore.md` — releasing genome keys to an attested
  destination and confirming its restore.
- `triage_table.md` — from an observed signal to the first action.
- `runbooks/` — disaster recovery, AWS and Azure notes, real AMD SEV-SNP.

If you find yourself wanting to take an action this runbook does not cover,
stop and open a design discussion — the runbook intentionally covers only
the doctrine-sanctioned operations.

---

_Document history: 2026-09-14 — checked line by line against the code; commands and names the binaries do not have were removed._
