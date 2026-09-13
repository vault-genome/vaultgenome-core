# Azure SEV-SNP Deployment — Completeness Checklist

This file enumerates every documentation + tooling artefact a customer
needs to **deploy Vault Genome on Azure Confidential VMs (AMD SEV-SNP)
from zero**, with a green check where the artefact exists in this repo
and a link to where to find it.

If you spot a gap, open an issue on `vault-genome/core`.

---

## 1. Discovery & evaluation

| Need | Status | Where |
|------|--------|-------|
| Multi-deployment-format catalog | ✅ | [`docs/deployment/README.md`](../../../docs/deployment/README.md) |
| Single-source Azure guide (zero → production, both backends) | ✅ | [`docs/deployment/azure.md`](../../../docs/deployment/azure.md) |
| Reference designs by industry vertical | ✅ | [`core/docs/reference-designs/`](../../docs/reference-designs/) |
| Threat model | ✅ | [`core/docs/security/threat_model.md`](../../docs/security/threat_model.md) |
| Compliance crosswalk | ✅ | [`core/docs/compliance/crosswalk.md`](../../docs/compliance/crosswalk.md) |
| Cost estimates per tier | ✅ | [`docs/deployment/azure.md` § Cost summary](../../../docs/deployment/azure.md) |

## 2. Hardware validation (before production deploy)

| Need | Status | Where |
|------|--------|-------|
| One-shot validation kit (~30 min, ~$1-2) | ✅ | `core/scripts/hardware-test/azure-sev-snp/examples/full-test-run.sh` |
| Kit README + step-by-step | ✅ | `core/scripts/hardware-test/azure-sev-snp/README.md` |
| Bootstrap (snpguest + Go + Ollama + az CLI) | ✅ | `scripts/01-bootstrap-vm.sh` |
| Raw SEV-SNP report capture (1184 bytes from /dev/sev-guest) | ✅ | `scripts/02-capture-attestation.sh` + `snpreport.go` |
| AMD chain validation (ARK→ASK→VCEK→Report) | ✅ | `scripts/02b-cryptographic-attestation.sh` |
| **Microsoft MAA JWT capture** (Azure-specific 2nd verifier) | ✅ | `scripts/02f-capture-maa-jwt.sh` |
| REPORT_DATA = SHA-512(manifest) workload binding | ✅ | `scripts/02b-cryptographic-attestation.sh` § Step 3 |
| Cross-VM cohort matrix (dual-chain) | ✅ | `scripts/07-cross-vm-matrix.sh` |
| Workload tests (Demo 1 + 2 + tamper + inference) | ✅ | `scripts/03-demo1-single-bundle.sh` + `04-demo2-chain.sh` + `05-inference-test.sh` |
| Validation kit Terraform | ✅ | `terraform/main.tf` |

## 3. Production deployment

| Need | Status | Where |
|------|--------|-------|
| Production Terraform module | ✅ | `deploy/terraform/azure-sev-snp/{main,variables,outputs,hardening}.tf` + `cloud-init.yaml` |
| Module README | ✅ | `deploy/terraform/azure-sev-snp/README.md` |
| Minimal example (dev/staging) | ✅ | `deploy/terraform/azure-sev-snp/examples/minimal/` |
| Production example (all hardening) | ✅ | `deploy/terraform/azure-sev-snp/examples/production/` |
| Variables reference | ✅ | `deploy/terraform/azure-sev-snp/variables.tf` |
| Outputs reference | ✅ | `deploy/terraform/azure-sev-snp/outputs.tf` |
| RBAC permissions reference (deployer + VM identity) | ✅ | [`docs/deployment/azure.md` § RBAC permissions reference](../../../docs/deployment/azure.md) |
| Pre-flight checklist | ✅ | [`docs/deployment/azure.md` § Pre-flight checklist](../../../docs/deployment/azure.md) |
| Optional hardening (NSG flow, Defender, Backup, Diagnostic, Immutability) | ✅ | `deploy/terraform/azure-sev-snp/hardening.tf` |

## 4. Day-1 verification & day-2 operations

| Need | Status | Where |
|------|--------|-------|
| Operator overview | ✅ | `core/docs/operator/00_overview.md` |
| Pre-flight before launching | ✅ | `core/docs/operator/01_preflight.md` |
| Recovery flow (TEE-agnostic) | ✅ | `core/docs/operator/02_recovery_flow.md` |
| Incident response | ✅ | `core/docs/operator/03_incident_response.md` |
| Observability (logs, metrics, alerts) | ✅ | `core/docs/operator/04_observability.md` |
| Release procedure | ✅ | `core/docs/operator/05_release_procedure.md` |
| Triage table | ✅ | `core/docs/operator/triage_table.md` |
| Disaster recovery runbook | ✅ | `core/docs/operator/runbooks/disaster_recovery.md` |
| **Azure-specific day-2 runbook** (rotation, scaling, incident response) | ✅ | **`core/docs/operator/runbooks/azure-day2.md`** |
| **Azure deployment-level architecture** (ASCII + data flows) | ✅ | **`core/docs/diagrams/azure-deployment-architecture.md`** |

## 5. Architecture & diagrams

| Need | Status | Where |
|------|--------|-------|
| Component-level architecture (TEE-agnostic) | ✅ | `core/docs/diagrams/architecture-overview.svg` |
| Session flow (sealing/restore) | ✅ | `core/docs/diagrams/session-flow.svg` |
| **Azure deployment architecture (full ASCII + data flows)** | ✅ | **`core/docs/diagrams/azure-deployment-architecture.md`** |
| Trust boundary table | ✅ | `core/docs/diagrams/azure-deployment-architecture.md` § Trust boundaries |

## 6. Public evidence (third-party verifiable)

| Need | Status | Where |
|------|--------|-------|
| Captured cohort matrix (4 VMs, 2 regions, dual-chain) | 🟡 pending Phase 2 | `evidence/CROSS-VM-MATRIX.md` (will be added) |
| Per-VM dual-chain evidence | 🟡 pending Phase 2 | `evidence/0N-VM<N>-<region>/` (will be added) |
| Workload test outputs | 🟡 pending Phase 2 | `evidence/workload/` (will be added) |
| Cross-region byte-diff result | 🟡 pending Phase 2 | `evidence/workload/cross-region-result.txt` (will be added) |
| Live test matrix on public site | 🟡 pending Phase 2 | https://acp-investor-demo.fly.dev/proof |
| Open-source kit + verifier (anyone can reproduce) | ✅ | This repo, AGPL-3.0 |

## 7. Customer-facing artefacts (NDA-distributable packs)

| Need | Status | Where |
|------|--------|-------|
| Azure SEV-SNP CTO Pack | 🟡 pending Phase 2 | `~/Desktop/Vault-Genome-Azure-SEV-SNP-CTO-Pack/` (founders' Desktop) |
| Full evidence tarball (per VM) | 🟡 pending Phase 2 | `~/Desktop/Azure-SEV-SNP-Real-Hardware-Test/*.tar.gz` (founders' Desktop) |

---

## What is NOT yet in the Azure SEV-SNP deployment story (next sprints)

| Need | Status | Owner / sprint |
|------|--------|---------------|
| Cohort matrix evidence (4 VMs, dual-chain validated) | 🟡 Phase 2 of Azure sprint | next user provisioning window |
| Workload test evidence (Demo 1/2/tamper/inference + cross-region DR) | 🟡 Phase 2-3 | next user provisioning window |
| /proof page Azure column flipped to ✓ | 🟡 Phase 3 | after evidence pack lands |
| Multi-zone HA topology | 🟡 design | future sprint |
| VM Scale Set + Internal Load Balancer | 🟡 design | future sprint |
| Cross-cloud KMS-mediated restore (Azure ↔ AWS ↔ GCP) | 🟡 roadmap | Week 6 |
| Azure Marketplace listing | 🟡 stub | when GA |
| Walkthrough cast video (asciinema) for Azure deployment | 🟡 cast for SEV-SNP attestation pending Phase 2 | next sprint |

---

## How to verify completeness yourself

```bash
# Clone repo
git clone https://github.com/vault-genome/core.git
cd core

# Verify every file referenced in this checklist exists
grep -oE '`[^`]+\.(md|sh|tf|py|go|yaml|svg|json)`' \
  core/scripts/hardware-test/azure-sev-snp/DEPLOYMENT-COMPLETENESS.md \
  | sort -u | tr -d '`' | while read f; do
    [ -f "$f" ] && echo "  ✓ $f" || echo "  ✗ MISSING: $f"
  done
```

Expected: 100% checks ✓ for items marked ✅. Items marked 🟡 are
intentionally pending Phase 2 (cohort runs).

---

## Status

**As of Phase 1 (Azure sprint)**: Azure SEV-SNP deployment scaffolding
is complete end-to-end — discovery, validation kit (kit + Terraform),
production deployment (kit + Terraform + examples), operations runbook,
architecture diagram, deployment guide. A customer with no prior contact
with Vault Genome can clone the repo, read `docs/deployment/azure.md`,
run the validation kit, deploy the production Terraform module, and
operate the system without further support requests.

**Pending Phase 2**: Reference cohort evidence (4 VMs, 2 regions,
dual-chain validation) — needs the user to provision Azure VMs in their
own subscription. Once captured, /proof matrix flips Azure SEV-SNP
column to all ✓.

---

_See `docs/deployment/azure.md` for the recommended starting point._
