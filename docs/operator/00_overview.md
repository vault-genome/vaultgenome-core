# Operator Overview

**Audience:** A new operator onboarding to the AI Continuity Platform core.
**Prerequisite reading:** `docs/internal/stage-a-summary.md` §2 (the eleven invariants).
**This document answers:** *who holds what authority, and what are the hard
boundaries between the Vault and the compute plane?*

---

## 1. Two operator roles

The platform splits responsibility across two distinct roles, and this split
is doctrine. Collapsing them is an invariant violation.

### 1.1 Vault operator

**Runs:** `sagvd` (Secure AI Genome Vault Daemon).

**Holds authority over:** every continuity-relevant decision — intake, trust
admission, session issuance, policy evaluation, disclosure sequencing, release
decision, audit appendage. The Vault is **the sole source of truth** for what
is allowed to happen next in the nine-stage flow.

**Must have:** a cryptographically bound identity, access to the purpose-
separated keystore, custody of the audit chain and the witness-log store,
and a policy snapshot that has itself been signed and pinned.

**Must NOT:** run generative reconstruction workloads. The Vault is
intentionally compute-light; heavy work is delegated outward by design (see
Hardware Reference Architecture Document v2, the "compactness / security
boundary preservation" rationale).

### 1.2 Compute-plane operator

**Runs:** `acp-compute` (one or more external workers).

**Holds:** delegated execution rights only. Workers receive
DisclosureMessage sequences scoped to a specific session and component
identifier; they execute the reconstruction step that was authorized; they
return a result bound to the session; they do not gain continuity authority
and cannot by themselves issue a ReleaseDecision.

**Must have:** attested execution environment (in MVP: emulated TEE per
R-10; in production: real SGX / TDX / SEV-SNP), a session ID issued by the
Vault, and the recipient-side key used in the AAD of each DisclosureMessage.

**Must NOT:** log, persist, or forward plaintext disclosed material outside
the bounds of the session. A worker that caches plaintext past session
termination is by definition in violation of invariant #7 ("No raw export").

### 1.3 Administrator

**Runs:** `acpctl` (administrative CLI).

**Holds:** operational inspection and bounded configuration authority. Can
query audit chain, request a continuity proof, trigger an incident review,
rotate a recipient key. Cannot directly issue a ReleaseDecision — that
authority lives only in the Vault's disclosure-and-release pipeline and is
driven by validated work products, not by CLI invocation.

---

## 2. The nine stages (one-line each)

| # | Stage | Authority holder | Package |
| - | - | - | - |
| 1 | Recovery Request | Vault — intake | `/internal/vault/intake` |
| 2 | Trust Admission | Vault — trust | `/internal/vault/trust` |
| 3 | Trusted Session | Vault — session | `/internal/vault/session` |
| 4 | Staged Disclosure | Vault — disclosure (StagedIssuer + StagedSequencer) | `/internal/vault/disclosure` |
| 5 | Delegated External Compute | Compute plane — worker | `/internal/compute/worker` |
| 6 | Return Path | Compute plane, gated by Vault | `/internal/compute/returnpath` |
| 7 | Validation | Vault — validation/operational | `/internal/validation/operational` |
| 8 | Release Decision | Vault — orchestration | `/internal/vault/orchestration` |
| 9 | Audit | Vault — audit | `/internal/audit` |

Authority moves through the Vault for stages 1–4, 6–9 and through the compute
plane for stage 5 only. Every transition between stages is enforced by
`/internal/vault/orchestration/state.go` and verified by the doctrine tests
in `/test/doctrine/invariants_test.go`.

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

- `01_preflight.md` — what to verify before your first real recovery session.
- `02_recovery_flow.md` — the nine-stage walk, stage by stage.
- `03_incident_response.md` — four R-15 scenarios and the correct response.
- `04_observability.md` — how to prove, after the fact, what happened.
- `05_release_procedure.md` — the signed-tag / SBOM / SLSA release loop.

If you find yourself wanting to take an action this runbook does not cover,
stop and open a design discussion — the runbook intentionally covers only
the doctrine-sanctioned operations.
