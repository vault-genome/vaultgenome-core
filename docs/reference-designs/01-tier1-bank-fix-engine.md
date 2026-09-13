# Reference design 01 — Tier-1 bank, FIX engine model continuity

| Profile        | Tier-1 global investment bank, EMEA HQ, US + APAC subsidiaries |
|----------------|----------------------------------------------------------------|
| Trading desks  | ~12 desks, ~400 quants, ~140 distinct ML models in production  |
| Constraints    | MiFID II, FINRA 4511 audit retention; sub-millisecond inference per FIX message |
| Primary TEE    | Intel SGX bare metal (sovereign signing) + AWS Nitro (DR site)  |
| AGPL fit       | ❌ — bank's risk team will not approve linking to AGPL code     |
| Commercial license | ✅ — $250k/yr enterprise tier with 24×7 support              |

## Problem statement

The bank runs ~140 ML models that score incoming FIX messages for
trading signals. Each model is the work of 2–4 quants and weeks of
backtesting. When a model is taken out of production (planned rollback,
emergency unwind, regulatory pause), the bank needs a verifiable record
of:

- What model was running at session N
- Who authorised its release to production
- How the model's outputs flowed into the desk's order book
- Whether any release decisions bypassed validation gates

Today the bank stitches this together from CI provenance + audit log
exports + manual sign-off PDFs in SharePoint. A regulator's question
takes the head of compliance 3–5 working days to answer. They want a
single tamper-evident artefact per session that stands up in a hearing.

## Architecture

### Topology

```
   ┌─────────────────────────────────────────────────────────────┐
   │   Bank's London datacentre (primary)                         │
   │                                                              │
   │  ┌────────────────────────────────────────┐                  │
   │  │ Quant workstation (intranet)            │                  │
   │  │   ├── acpctl status                     │                  │
   │  │   ├── acpctl recover (DR drill)         │                  │
   │  │   └── REST POST /v1/jobs                │                  │
   │  └────────────────────────────────────────┘                  │
   │                  │                                           │
   │                  ▼                                           │
   │  ┌────────────────────────────────────────┐                  │
   │  │ sagvd authority cluster (HA pair)        │                  │
   │  │   ├── Intel SGX bare metal (primary)     │                  │
   │  │   ├── PCCS (locally mirrored)            │                  │
   │  │   ├── Thales HSM (FIPS 140-2 L3)         │                  │
   │  │   └── Audit chain → 7-yr WORM storage    │                  │
   │  └────────────────────────────────────────┘                  │
   │                  │                                           │
   │                  ▼                                           │
   │  ┌────────────────────────────────────────┐                  │
   │  │ acp-compute worker pool (50 nodes)        │                  │
   │  │   └── 1 SGX enclave per node              │                  │
   │  └────────────────────────────────────────┘                  │
   │                  │                                           │
   │                  ▼                                           │
   │  ┌────────────────────────────────────────┐                  │
   │  │ FIX gateway (existing)                    │                  │
   │  │   └── consumes signals from acp-compute   │                  │
   │  └────────────────────────────────────────┘                  │
   └─────────────────────────────────────────────────────────────┘
                  │
                  │  cross-region replication (every 30s)
                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │   AWS us-east-1 (DR site)                                    │
   │   ├── sagvd standby (Nitro Enclaves)                         │
   │   ├── KMS key with PCR0-bound RecipientAttestation           │
   │   └── S3 with Object Lock (regulatory mode, 7-year)          │
   └─────────────────────────────────────────────────────────────┘
```

### Components

- **TEE backend**: `intel-sgx-dcap` for primary; `aws-nitro` for DR.
  Same `sagvd` binary in both — only the config file's
  `tee.provider` differs ([ADR-0002](../adr/0002-multi-tee-adapter-dispatch.md)).
- **HSM wrap**: Intel SGX bare-metal sealing wrapped with a Thales
  HSM (PKCS#11) for the AAA layer of defence — `IntelSGXSealer.hsmSlot`
  configured to the bank's existing HSM cluster.
- **Audit retention**: Cloud Storage Object Lock in regulatory mode,
  7-year retention. Provisioned by the bank's existing Terraform
  modules; Vault Genome's
  [`deploy/terraform/aws/`](../../../deploy/terraform/aws/) module
  shows the analogous WORM bucket configuration.
- **Validation**: full 3-stage pipeline (operational + semantic +
  behavioural) on every release decision. The behavioural stage runs
  the desk's regression suite — bank-provided plugin to the existing
  `internal/validation/behavioral` framework.

### Data flow per FIX message

1. FIX message arrives at the bank's existing gateway.
2. Gateway queries the worker pool's load balancer; a free worker is
   selected. The worker has already completed the 4-frame return-path
   handshake with sagvd — this is a per-session setup, not per-message.
3. Worker (inside SGX enclave) runs the model on the message,
   producing a candidate output (signed by the worker's TEE-bound key).
4. Worker emits a `CandidateOutputFrame` to sagvd.
5. sagvd validates → verdict → release decision (if pass).
6. Released signal flows back to the worker's plaintext output channel
   (via the disclosure pipeline) and out to the FIX gateway.
7. Every step is recorded in the append-only audit chain.

Per-message latency budget (target: 800 µs end-to-end):

| Stage                 | Budget | Notes |
|-----------------------|--------|-------|
| FIX → worker          | 100 µs | LAN-local LB |
| Inference in enclave  | 350 µs | model-dependent |
| Worker → sagvd frame  | 50 µs  | shared-memory IPC for co-located SGX |
| Validation pipeline   | 150 µs | parallelised, mostly cache-resident |
| Release decision sign | 100 µs | HSM round-trip (signing only, not full sealing) |
| sagvd → FIX gateway   | 50 µs  | LAN-local |

Sealing happens once per session (not per message), so its latency
sits outside this budget.

## Threat model

Drives from the cross-platform threat table in
[`docs/security/threat_model.md`](../security/threat_model.md), narrowed
to the bank's specific scope:

| Threat (relevant) | Mitigation |
|-------------------|------------|
| Quant accidentally promotes an unreviewed model | Validation pipeline gates every release; doctrine invariant `TestInvariant_05` blocks short-circuits |
| Insider with sagvd access modifies audit log | bbolt append-only; tamper detection raises Integrity error; 7-yr WORM retention provides the 2nd witness |
| SGX side-channel against sealing key | HSM-wrap is the defence-in-depth; even with the SGX key extracted, the HSM-key is required to unseal |
| Data-centre power failure | DR replication every 30s; standby brings sagvd online in AWS us-east-1 within 5 minutes |
| Regulator subpoena for "what was running on day X at time Y" | `acpctl audit query --at 2026-04-15T13:42:00Z` (Phase 2) returns the full session manifest including MRENCLAVE + signed verdict chain |

Residual risks the bank explicitly accepts:

- Compromise of Intel SGX silicon TCB → mitigated by `MinISVSVN` floor
  + monthly Intel TCB Recovery review
- Loss of the bank's HSM master key → DR procedure assumes a fresh
  HSM, sealed material under the old HSM is read-only forensics

## Operational concerns

- **On-call rotation**: bank's existing Tier-1 24×7 SRE pool. Vault
  Genome adds 4 additional pages: sagvd-down, audit-chain-broken,
  sgx-tcb-stale, hsm-unreachable.
- **Runbook coverage**: scenarios 1-10 in
  [`docs/operator/runbooks/disaster_recovery.md`](../operator/runbooks/disaster_recovery.md).
  Quarterly DR exercise required by the bank's risk committee.
- **Compliance**: see [`docs/compliance/crosswalk.md`](../compliance/crosswalk.md);
  bank's controls map cleanly to ISO 27001 A.5.23 + A.8.24.
- **Audit retention**: 7-year regulatory mode on the WORM bucket
  satisfies MiFID II Article 16 and FINRA 4511.

## Pricing posture

Commercial license, $250k/yr enterprise tier:

- AGPL §13 source disclosure waived for the bank's closed-source
  trading apps.
- 24×7 SRE escalation, 4-hour response SLO for P1, 1-business-day for P2.
- Quarterly architecture review with the bank's risk team.
- Co-development of the behavioural-validation plugin (the desk's
  regression suite).

For the AWS DR site, no additional fee — the same license covers
multi-region deployments of the same logical workload.
