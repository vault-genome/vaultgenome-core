# Reference design 01 — a Tier-1 bank: continuity of fine-tuned models across two clouds

| Profile | A bank with in-house fine-tuned models in production — credit decisioning, transaction monitoring, document extraction — trained on its own data, each the work of a team and weeks of validation |
| - | - |
| Regime | DORA and its RTS on ICT risk management (EU entities); 23 NYCRR Part 500 (New York); the bank's own model-risk framework; PCI DSS only where a deployment touches the cardholder data environment — see [`../compliance/banking.md`](../compliance/banking.md) |
| Primary | GCP: the release authority on an AMD SEV-SNP Confidential VM (`gcp-sev-snp`); CPU workers on SEV-SNP or Intel TDX (`gcp-tdx`) |
| Standby | Azure: an AMD SEV-SNP Confidential VM (`azure-sev-snp`) for CPU models; an NCC H100 v5 (`azure-cgpu`) for models that need a GPU |
| Licence | AGPL-3.0-or-later, or the commercial licence for the bank's closed-source integrations (ADR 0003) |
| Revised | 2026-10-17, on v0.6.0 and the acceptance trial of October 2026; replaces the design of 2026-05-06, which stood on Intel SGX bare metal, AWS Nitro, an HSM wrap and Terraform modules that are not in the tree |

## The problem

A fine-tuned model is the bank's asset and the bank's liability: the
weights encode the training data, the regulator asks what was running
and who released it, and the continuity plan must bring it back on
other hardware inside a recovery time the bank has written down. Today
the model lives as a checkpoint in a bucket, its release is a ticket,
and its restoration elsewhere is a hope. What the bank wants is a form
of the model that is sealed, escrowed, restorable on an attested
machine in another cloud, checked against reference outputs before it
serves, with every decision on a record a third party can verify.

That is the genome path: the fine-tune's delta sealed as a genome
([C1](../../VERIFIABLE-CLAIMS.md#c1)), its key escrowed to an
authority whose own key is sealed to its chip
([C14](../../VERIFIABLE-CLAIMS.md#c14)), released to a worker only
after the worker's chip has attested in the session's handshake
([C12](../../VERIFIABLE-CLAIMS.md#c12)), restored and gated against
sealed fixtures ([C4](../../VERIFIABLE-CLAIMS.md#c4),
[C19](../../VERIFIABLE-CLAIMS.md#c19)), the record verified under the
published key ([C38](../../VERIFIABLE-CLAIMS.md#c38)).

## Architecture

### Topology

```
  Bank's operator workstation (acpctl: provision, status, audit verify, lineage)
        │ mutual TLS 1.3, client certificate, bearer token
        ▼
  ┌─ GCP, region A ──────────────────────────────────────────────────────────┐
  │  sagvd — the release authority                                           │
  │    n2d SEV-SNP Confidential VM; key files sealed to the chip (ADR 0023)  │
  │    escrow key sealed to the chip (ADR 0016); job queue on disk (ADR 0026)│
  │    audit log in closed segments → the bank's archive store (ADR 0027)    │
  │    sentinel + policy: one serial, one move, the operator's stop list     │
  │         │ the Return Path: attested handshake, sealed material, verdicts │
  │         ▼                                                                │
  │  acp-compute workers — n2d SEV-SNP or c3 TDX, pinned by launch           │
  │    measurement (ADR 0028); the integer door on the CPU (ADR 0020)        │
  └──────────────────────────────────────────────────────────────────────────┘
        │ the failover: on an attack, on silence, on a lost region (ADR 0012, 0017)
        ▼
  ┌─ Azure, region B ────────────────────────────────────────────────────────┐
  │  standby acp-compute on a DC-series SEV-SNP VM (`tee.provider: auto`)    │
  │  or an NCC H100 v5 (`azure-cgpu`): the chip, the vTPM and the GPU in one │
  │  evidence; the key released only after the standby attests              │
  └──────────────────────────────────────────────────────────────────────────┘
  (optional) a RATS Verifier — Veraison on a VM of the bank's — appraising both
  ends' Evidence by name over mutual TLS (ADR 0025; C31)
```

### Components, and what each stands on

- **Attestation on both ends.** The authority and every worker present
  the chip's report bound to the session's challenge; the Evidence
  names its family and a peer of another family is refused by name
  before any verifier runs (`controls.md` VG-002). Proven on SEV-SNP,
  TDX, Azure SEV-SNP and the H100 host — trials T1–T4.
- **Provisioning.** `acpctl provision authority` on the authority's
  host writes the key material, both configurations and the worker's
  bundle; `provision join` on each worker's host; `provision
  pin-worker` closes the loop. The worker's secrets never exist on the
  authority's host (ADR 0028, C39, trials T7–T8). A worker image that
  differs from the pinned one is a different measurement and is
  refused at the handshake.
- **The key files.** Every seed, the session sealing key and the TLS
  keys are sealed to the host — the chip's derived key on SEV-SNP, the
  vTPM on TDX and Azure — and a copy does not open elsewhere (ADR
  0023; the thief step of every trial).
- **The record.** Every decision is appended, signed and hash-chained
  before it takes effect; the live file closes into archives the daemon
  never deletes; `acpctl audit verify` checks the whole chain across
  segments with the public key alone (ADR 0014, 0027). The bank copies
  the archives to its own immutable store on its own schedule — that
  store is the bank's, not the software's.
- **The failover.** The sentinel watches the primary; the policy names
  the destinations, the serial and the stop list; a key moves once, to
  an attested destination, with the decision recorded first; seven
  wrong policies are refused for seven stated reasons (C22). Drilled on
  an attack (C8, C14), on a silent primary (C35), on a lost authority
  host (C28), to a TDX standby (C21) and to the confidential GPU (C18).
- **The gate.** The restored model is run on sealed fixtures; EXACT on
  the pinned runtime, and across devices the integer door gives the
  same bytes on a Xeon and an L4 at 0.5B and 7B (C19, trial T20).
- **The Verifier, optionally.** A bank that wants appraisal outside the
  daemons runs Veraison on a VM of its own; both daemons send the
  other's Evidence to it by name over mutual TLS, judge the EAR under
  the bank's policy, and admit nothing on a missing verdict (C31, T5).

### A job, end to end

1. The quant seals the fine-tune: `acpctl genome seal` produces the
   genome and its key; the key is escrowed to the authority.
2. The operator submits a job over the API; `REQUEST_RECEIVED` is on the
   record before anything else happens.
3. The worker opens a session: the four-frame handshake carries both
   chips' reports; `TRUST_EVALUATED` records the verdict and, for the
   GPU host, the verifier's own evaluation of the H100 — report, nonce,
   signature, chain, firmware id, measurements against NVIDIA's
   manifests, revocation (trial T4).
4. The authority releases the sealed material for this session only;
   the worker restores the model in memory and runs the fixtures.
5. The gate's signed verdict comes back; validation dimensions are
   recorded; `RELEASE_DECIDED` closes the job.
6. The operator, the auditor or the regulator verifies the chain and
   queries any request: `acpctl audit verify`, `acpctl audit query
   --request <id>`, `acpctl lineage`.

### The figures, from the records

The design makes no latency promise for inference; the software keeps
models, it does not serve them per message. What is measured:

| Quantity | Measured | Where |
| - | - | - |
| Handshake, SEV-SNP, the first report of a boot | about 10 s (the host's throttle on report requests) | C32; T6 (`handshake_ms`) |
| Handshake, subsequent sessions | 21–50 ms | T6 |
| A gate job on a CPU worker (small model, 6 fixtures) | 4–5 s | T1, T2, T7 |
| A gate job on the H100 (7B, 16 fixtures) | 56 s | T4 |
| Failover on an attack, cross-cloud to the GPU | RTO 24.99 s, RPO 12 s | C18 |
| Failover on a silent primary | detect 15.01 s, RTO 26.24 s, RPO 21 s | C35 |
| A fresh authority host after the first is deleted mid-job | RTO 489 s cold | C28 |
| One authority, three workers, an hour | 1609 jobs, every one EXACT, five audit segments | C38; T22 |

The bank runs the same kits on its own accounts and writes its own
figures next to these; they are the test hardware's, not a service
level.

## Threat model

The platform table is [`../security/threat_model.md`](../security/threat_model.md)
(reviewed 2026-10-14). The threats this design is most often asked about:

| Threat | What answers it |
| - | - |
| An insider with access to the authority's host copies the key files | sealed to the chip; they do not open elsewhere (VG-023; the thief step of T1–T5) |
| An insider edits or truncates the audit log | signed, chained, closed segments with each closing recorded in the next; a third party verifies with the public key (VG-004, VG-021) |
| A worker image is replaced | a different launch measurement; refused at the handshake (VG-002, VG-026; T1) |
| The primary is compromised and lies about its state | the failover takes the primary's word only with its chip's report on it, and silence alone triggers the move (ADR 0017; C14, C35) |
| An operator signs a policy that would move the key somewhere wrong | refused with the reason on the record (C22); an operator who signs a *valid* bad policy is outside the argument |
| The cloud provider's hypervisor | the chip's memory encryption and attestation are the vendor's; the vendor's silicon is the accepted residual risk |
| A quantum adversary later | residual risk 6 of the threat model; no post-quantum scheme ships |

## Operational concerns

- **Runbooks**: `docs/operator/runbooks/real-tee-sev-snp.md`,
  `real-tee-tdx.md`, `real-tee-azure-sev-snp.md`,
  `real-tee-azure-cgpu.md`, `delegated-verifier.md`, `air_gap.md`,
  `disaster_recovery.md`; the incident scenarios in
  `docs/operator/03_incident_response.md`.
- **Monitoring**: each daemon's `/metrics` (the names in
  `docs/operator/04_observability.md`), the dashboards in
  `deploy/grafana/`; the bank's alerting consumes them.
- **Clocks**: the hosts' clocks are synchronised by the bank to its
  reference source; the daemons' timestamps come from one clock each.
- **Upgrades**: the compatibility ledger in
  `docs/operator/08_upgrading.md`; every release verified from its
  assets before deployment (C27; T9).
- **Compliance**: the requirement-by-requirement map is
  [`../compliance/banking.md`](../compliance/banking.md), and its last
  section is the bank's own list.

## Licensing posture

The commercial licence covers the bank's closed-source integrations
with the AGPL §13 disclosure waived, support and escalation terms, and
a quarterly architecture review (ADR 0003; terms in the private
repository). A deployment that spans two clouds for one logical
workload is one deployment.
