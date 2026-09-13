# Azure SGX Deployment — Completeness Checklist

This file enumerates every documentation + tooling artefact a customer
needs to **deploy Vault Genome on Azure with Intel SGX (DCsv3) from
zero**, with a green check where the artefact exists in this repo.

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
| One-shot validation kit (~30 min, ~$1-2) | ✅ | `core/scripts/hardware-test/azure-sgx/examples/full-test-run.sh` |
| Kit README + step-by-step | ✅ | `core/scripts/hardware-test/azure-sgx/README.md` |
| Bootstrap (Intel SGX DCAP + Open Enclave SDK + Go + Ollama + az CLI) | ✅ | `scripts/01-bootstrap-vm.sh` |
| SGX quote capture (oeutil generate-evidence) | ✅ | `scripts/02-capture-attestation.sh` |
| Intel chain validation (Quote → PCK → Intel SGX Root CA) | ✅ | `scripts/02b-cryptographic-attestation.sh` |
| **Microsoft MAA JWT capture** (Azure-specific 2nd verifier) | ✅ | `scripts/02f-capture-maa-jwt.sh` |
| REPORT_DATA = SHA-512(manifest) workload binding | ✅ | `scripts/02b-cryptographic-attestation.sh` § Step 3 |
| Cross-VM cohort matrix (dual-chain) | ✅ | `scripts/07-cross-vm-matrix.sh` |
| Workload tests (Demo 1 + 2 + tamper + inference) | ✅ | `scripts/03-demo1-single-bundle.sh` + `04-demo2-chain.sh` + `05-inference-test.sh` |
| Validation kit Terraform | ✅ | `terraform/main.tf` |

## 3. Production deployment

| Need | Status | Where |
|------|--------|-------|
| Production Terraform module | ✅ | `deploy/terraform/azure-sgx/{main,variables,outputs,hardening}.tf` + `cloud-init.yaml` |
| Module README | ✅ | `deploy/terraform/azure-sgx/README.md` |
| Minimal example (dev/staging) | ✅ | `deploy/terraform/azure-sgx/examples/minimal/` |
| Production example (all hardening) | ✅ | `deploy/terraform/azure-sgx/examples/production/` |
| Variables reference | ✅ | `deploy/terraform/azure-sgx/variables.tf` |
| Outputs reference | ✅ | `deploy/terraform/azure-sgx/outputs.tf` |
| RBAC permissions reference | ✅ | [`docs/deployment/azure.md` § RBAC permissions reference](../../../docs/deployment/azure.md) |
| Pre-flight checklist | ✅ | [`docs/deployment/azure.md` § Pre-flight checklist](../../../docs/deployment/azure.md) |
| Optional hardening flags | ✅ | `deploy/terraform/azure-sgx/hardening.tf` |

## 4. Day-1 verification & day-2 operations

| Need | Status | Where |
|------|--------|-------|
| Operator overview | ✅ | `core/docs/operator/00_overview.md` |
| Pre-flight before launching | ✅ | `core/docs/operator/01_preflight.md` |
| Recovery flow (TEE-agnostic) | ✅ | `core/docs/operator/02_recovery_flow.md` |
| Incident response | ✅ | `core/docs/operator/03_incident_response.md` |
| Observability | ✅ | `core/docs/operator/04_observability.md` |
| Release procedure | ✅ | `core/docs/operator/05_release_procedure.md` |
| Disaster recovery runbook | ✅ | `core/docs/operator/runbooks/disaster_recovery.md` |
| **Azure-specific day-2 runbook** (covers SEV-SNP + SGX) | ✅ | **`core/docs/operator/runbooks/azure-day2.md`** |
| **Azure deployment-level architecture** | ✅ | **`core/docs/diagrams/azure-deployment-architecture.md`** |

## 5. Public evidence (third-party verifiable)

| Need | Status | Where |
|------|--------|-------|
| Captured cohort matrix (4 VMs, 2 regions, dual-chain) | 🟡 pending Phase 2 | `evidence/CROSS-VM-MATRIX.md` (will be added) |
| Per-VM dual-chain evidence | 🟡 pending Phase 2 | `evidence/0N-VM<N>-<region>/` |
| Workload test outputs | 🟡 pending Phase 2 | `evidence/workload/` |
| Cross-region byte-diff result | 🟡 pending Phase 2 | `evidence/workload/cross-region-result.txt` |
| Live test matrix on public site | 🟡 pending Phase 2 | https://acp-investor-demo.fly.dev/proof |
| Open-source kit + verifier | ✅ | This repo, AGPL-3.0 |

## 6. Customer-facing artefacts (NDA-distributable packs)

| Need | Status | Where |
|------|--------|-------|
| Azure SGX CTO Pack | 🟡 pending Phase 2 | `~/Desktop/Vault-Genome-Azure-SGX-CTO-Pack/` (founders' Desktop) |
| Full evidence tarball (per VM) | 🟡 pending Phase 2 | `~/Desktop/Azure-SGX-Real-Hardware-Test/*.tar.gz` |

---

## What is NOT yet in the Azure SGX deployment story (next sprints)

| Need | Status | Owner / sprint |
|------|--------|---------------|
| Cohort matrix evidence (4 VMs, dual-chain validated) | 🟡 Phase 2 of Azure sprint | next user provisioning window |
| Workload test evidence | 🟡 Phase 2-3 | next user provisioning window |
| /proof page Azure SGX column flipped to ✓ | 🟡 Phase 3 | after evidence pack lands |
| Multi-zone HA topology | 🟡 design | future sprint |

---

## Status

**As of Phase 1 (Azure sprint)**: Azure SGX deployment scaffolding is
complete end-to-end. Customer can clone repo, run validation kit, deploy
production Terraform, operate via day-2 runbook.

**Pending Phase 2**: Reference cohort evidence — needs user to provision
Azure DCsv3 VMs in their own subscription.

---

_See `docs/deployment/azure.md` for the recommended starting point._
