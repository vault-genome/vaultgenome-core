# Reference design 04 — Frontier AI lab, model continuity at training scale

| Profile        | Frontier AI research lab; ~600 researchers; ~$200M annual compute spend |
|----------------|--------------------------------------------------------------------------|
| Workload       | Long-running pretraining runs (28-day jobs over 8K H100 GPUs); ongoing finetune campaigns |
| Constraints    | Internal IP protection; multi-region distributed training; insider-risk mitigation |
| Primary TEE    | GCP SEV-SNP for the orchestration plane; H100 CC for inference (Phase 3 adapter) |
| AGPL fit       | 🟡 — internal tools only; AGPL acceptable for non-customer-facing infrastructure |
| Commercial license | ✅ — co-development deal: Vault Genome supplies orchestration; lab supplies the H100 CC adapter |

## Problem statement

The lab spends $200M/year on compute. A pretraining run is a
28-day, 8000-GPU campaign that produces a checkpoint worth
hundreds of millions of dollars in research and engineering time.
Three pain points:

1. **Checkpoint resilience.** A 28-day run that loses progress at
   day 22 because of a corrupted checkpoint is a $20M loss. The lab
   needs continuity guarantees that survive single-DC failures,
   ransomware, and internal-tooling bugs.
2. **Model lineage at training scale.** A finetune campaign produces
   100+ candidate adapters; the team needs deterministic provenance
   (which base model, what data, which hyperparameters, what
   safety-eval suite passed) for every released artefact. A
   distinguished researcher's question "why did we ship adapter
   variant 47?" should resolve to a single signed manifest in
   seconds, not in three days of email archaeology.
3. **Insider-risk mitigation.** A senior researcher leaving for a
   competitor is a recurring threat; the lab cannot prevent the
   departure but needs to guarantee that no single individual could
   exfiltrate a checkpoint without leaving an unalterable audit trail.

## Architecture

### Topology

```
                ┌────────────────────────────────────────────────────────┐
                │  GCP us-central1 (training primary)                     │
                │                                                         │
                │  ┌─────────────────────────────────────────────────┐   │
                │  │ sagvd-orchestrator (SEV-SNP Confidential VM)      │   │
                │  │   ├── /dev/sev-guest                              │   │
                │  │   ├── AMD VCEK chain validation                    │   │
                │  │   ├── audit → Cloud Storage WORM (7yr)             │   │
                │  │   └── lineage manifest emitter                     │   │
                │  └─────────────────────────────────────────────────┘   │
                │                  │                                      │
                │                  ▼                                      │
                │  ┌─────────────────────────────────────────────────┐   │
                │  │ acp-compute training workers (~8000 H100s)        │   │
                │  │   ├── checkpoint emission → SEV-SNP sealed store   │   │
                │  │   └── 4-frame return path per epoch boundary       │   │
                │  └─────────────────────────────────────────────────┘   │
                └────────────────────────────────────────────────────────┘
                                │  cross-region replication every 5 min
                                ▼
                ┌────────────────────────────────────────────────────────┐
                │  GCP europe-west4 (DR + EU researchers)                 │
                │                                                         │
                │  ┌─────────────────────────────────────────────────┐   │
                │  │ Same architecture; sagvd standby                  │   │
                │  └─────────────────────────────────────────────────┘   │
                └────────────────────────────────────────────────────────┘

                  Inference deployment (Phase 3 — co-developed):

                ┌────────────────────────────────────────────────────────┐
                │  Phase 3 — NVIDIA H100 CC adapter                        │
                │  Same Vault Genome control plane; new TEE backend        │
                │  in the frozen Producer/Verifier/Sealer surface          │
                └────────────────────────────────────────────────────────┘
```

### Components

- **TEE backend (orchestration)**: `gcp-sev-snp` for the sagvd /
  acp-compute training pool. SEV-SNP provides VM-level isolation
  appropriate for the long-running training workload.
- **TEE backend (inference, Phase 3)**: `nvidia-h100-cc` — a future
  Vault Genome adapter co-developed with the lab. The lab brings
  CUDA + H100 SDK expertise; Vault Genome brings the
  Producer/Verifier/Sealer abstraction. The adapter passes the
  conformance suite ([`pkg/teeconformance`](../../pkg/teeconformance))
  before being merged upstream.
- **Lineage manifest**: every released adapter, every published
  checkpoint, every safety-eval pass-or-fail recorded in the audit
  chain with a signed link to the prior manifest. The lineage is a
  tamper-evident DAG — a researcher question resolves via a single
  audit query.
- **Cross-region replication**: 5-minute replication interval on
  Cloud Storage; sagvd's session manifest is written transactionally
  so a region failover never loses an in-flight release decision.

### Per-epoch checkpoint flow

For a 28-day pretraining run:

1. Each H100 worker emits a partial checkpoint at every epoch
   boundary (~every 6 hours).
2. Worker seals its partial checkpoint via SEV-SNP-derived key + AAD
   bound to (run-id, epoch-id, worker-id).
3. acp-compute aggregator (also in SEV-SNP) merges partials into a
   global checkpoint; signed by aggregator's TEE-bound key.
4. sagvd validates the merge: did every expected partial arrive? did
   any worker emit a malformed partial?
5. On pass, sagvd writes a release decision with the global
   checkpoint's content hash; audit chain extends.
6. Cross-region replication picks up the new manifest within 5 min.

The 28-day run produces ~112 checkpoints; the audit chain has
~450 entries (validation + release events plus operator audit
queries). A failed epoch's diagnostic data is preserved in the
chain, not silently retried.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Senior researcher exfiltrates a checkpoint | Sealed checkpoint can only be unsealed by an enclave whose launch MEASUREMENT matches the lab's pinned identity; researcher leaving without that enclave's signing material has only the ciphertext. Audit log records every unseal attempt. |
| Disgruntled SRE deletes the audit log | bbolt append-only + Cloud Storage WORM (7-year, generation versioning); single-actor delete fails. Replication to a separate GCP project owned by the lab's GRC team adds the second witness. |
| Compromised CI pipeline ships a backdoored sagvd binary | Reproducible builds (`make verify-reproducible`); SLSA L3 provenance; cosign keyless signing. Lab's release-acceptance test rebuilds the binary from source and confirms byte equivalence. See [`docs/security/supply_chain.md`](../security/supply_chain.md). |
| Side-channel against SEV-SNP | TCB floor enforced (`MinReportedTCB`); AMD security advisories monitored; SMT disabled in BIOS for highest-risk runs. |
| AMD KDS unreachable mid-training | VCEK cache; lab pre-populates the cache during quiet hours; cached entries valid for the configured TCB lifetime. See DR runbook scenario 3. |

## Operational concerns

- **24×7 SRE rotation**: lab's existing 30-person SRE team. Vault
  Genome adds ~6 page surfaces (sagvd-down, audit-chain-broken,
  amd-kds-unreachable, sev-tcb-stale, region-failover-lag,
  lineage-manifest-validation-fail).
- **DR**: scenarios 4, 5, 7 from the
  [DR runbook](../operator/runbooks/disaster_recovery.md) are
  exercised quarterly. Scenario 3 (TEE root rotation) added to the
  exercise set after the 2026 AMD KDS rotation event.
- **Compliance**: SOC 2 Type II + ISO 27001 + ad-hoc internal
  policy. See compliance crosswalk for the controls map.
- **Lineage queries**: `acpctl lineage <release-id>` (Phase 2) is
  a first-class operator command; the lab's research team integrates
  it into the model card publication pipeline.

## Pricing posture

Co-development engagement, structured as:

- $400k/yr commercial license (covers AGPL §13 waiver for the lab's
  closed-source orchestration tooling).
- Joint development of the H100 CC adapter:
  - Lab assigns 2 engineers for 6 months.
  - Vault Genome assigns 1 engineer for 6 months + technical
    leadership.
  - Resulting adapter is contributed upstream under AGPL.
  - Lab receives a 12-month exclusivity window before the adapter
    appears in public releases.

The exclusivity window is a customer-friendly artefact — it does
not break the open-source story (all code is AGPL the day it lands
in the Vault Genome public repo) but gives the lab a competitive
window for the engineering investment. Past the window, every other
buyer can use the same adapter with no royalty.
