# Vault Genome — Azure Confidential VMs (AMD SEV-SNP) Hardware Validation Package

Reproducible end-to-end validation kit for running the Vault Genome
continuity layer on Azure Confidential VMs (AMD EPYC SEV-SNP) — the
DCasv5 / DCadsv5 series.

This package lets a recipient — typically an acquirer's technical
evaluation team or a customer running a proof-of-concept — provision a
real Confidential VM in their own Azure subscription, run the full Vault
Genome test suite, capture **two independently-rooted** attestation
chains (AMD ARK→ASK→VCEK + Microsoft Azure Attestation JWT), and bundle
everything into a single tar archive ready for review. Total
reproduction time: ~30 minutes including model download.

## What's special about Azure SEV-SNP

This is the **only** TEE in the Vault Genome multi-cloud matrix where a
single hardware report can be verified against **two independent
PKIs**:

1. **AMD-rooted chain** (`snpguest verify certs/attestation`):
   ARK → ASK → VCEK → Report — anchored at AMD's public root CA
2. **Microsoft-attested chain** (MAA JWT):
   Isolation-tee claims signed by Azure-PKI — anchored at Microsoft's MAA root

A failure in either chain produces a hard reject. Both must pass for
`production_grade: true`. AWS Nitro has only one chain (AWS Nitro Root
CA G1); GCP SEV-SNP has only the AMD chain. Azure gives us **both** —
this is a unique strengthening that reduces single-vendor PKI risk.

## What this kit produces

After running the kit end-to-end, you will have:

1. A real AMD SEV-SNP Confidential VM in your Azure subscription
2. A 1184-byte SEV-SNP attestation report captured directly from
   `/dev/sev-guest` via ioctl (signed by the chip-specific VCEK)
3. An MAA JWT proving Azure-Compliant-CVM platform state, signed by
   Microsoft's Attestation PKI (independent of AMD's chain)
4. Full ARK→ASK→VCEK certificate chain captured from AMD KDS
5. snpguest verify output: certs valid + attestation signed by VCEK + TCB match
6. MAA JWT verify output: claims match expected `sevsnpvm` policy
7. Demo 1 evidence — full Llama 3.2 3B model sealed and restored
   byte-identical, with `acpctl genome verify` confirming every blob
   hash matches the envelope record
8. Demo 2 evidence — chain of 6 LoRA-style generations sealed,
   chain-validated, lineage walked back to genesis, mid-chain rewind
9. Tamper detection evidence — 1-byte flip in the sealed payload
   produces an AES-256-GCM authentication failure
10. (Optional) Inference comparison — same prompt + seed against
    original and restored daemons producing byte-identical output

All evidence is captured into a single tar archive ready for review or
upload to your evaluation data room.

## Prerequisites

- Azure subscription with billing enabled
- A region that supports DCasv5/DCadsv5 (eastus, eastus2, westeurope,
  northeurope, etc. — see [Microsoft regions list](https://learn.microsoft.com/en-us/azure/virtual-machines/dcasv5-dcadsv5-series))
- Subscription quota: ≥ 4 vCPU of "Standard DCASv5/DCADSv5 Family vCPUs"
  (typically not granted by default — request via Azure portal)
- IAM role / RBAC to create VMs / Storage / Network in the target subscription
- `az` CLI authenticated (`az login`)
- `terraform >= 1.6` installed
- ~30 minutes of wall time
- About $1-2 of compute (a couple of hours on `Standard_DC4as_v5`)

The kit defaults to `eastus2` region and `Standard_DC4as_v5` (4 vCPU, 16
GB). Both can be overridden via Terraform variables.

## Quick start — one command

```bash
git clone <vault-genome-repo-private-url>
cd core/scripts/hardware-test/azure-sev-snp/
./examples/full-test-run.sh   # provisions VM, bootstraps, runs all tests, packs evidence, tears down
```

The runner will print the path to the captured evidence tar at the end.

## Step-by-step (if you want to inspect each phase)

```bash
# 1. Provision VM
cd terraform/
terraform init
terraform apply
# outputs: vm_id, public_ip, ssh command

# 2. SSH in, bootstrap
ssh azureuser@<public-ip>
git clone <repo-url> && cd ai-continuity-platform/core/scripts/hardware-test/azure-sev-snp/
./scripts/01-bootstrap-vm.sh

# 3. Capture both attestation chains
./scripts/02-capture-attestation.sh           # raw 1184-byte SNP report from /dev/sev-guest
./scripts/02b-cryptographic-attestation.sh    # AMD chain (snpguest verify)
./scripts/02f-capture-maa-jwt.sh              # Microsoft MAA JWT — Azure-specific 2nd verifier

# 4. Run workloads
./scripts/03-demo1-single-bundle.sh   # seal/restore Llama 3.2 3B
./scripts/04-demo2-chain.sh           # 6-generation chain
./scripts/05-inference-test.sh        # byte-identical inference comparison

# 5. Pack evidence
./scripts/06-pack-evidence.sh         # produces ~/<vm-name>-evidence.tar.gz

# 6. Tear down
exit
cd terraform/
terraform destroy
```

## Cohort matrix (multiple VMs)

For the full multi-VM cohort matrix (4+ VMs, 2+ regions, both chains
validated per VM), see `scripts/07-cross-vm-matrix.sh`. Run after each
VM completes its individual evidence capture; this script aggregates
the per-VM evidence tars into a single matrix CSV + Markdown table.

The reference cohort matrix produced by Vault Genome's own validation
sprint is at `evidence/CROSS-VM-MATRIX.md`.

## Independent reproducibility

Anyone with the captured evidence and AMD's public root certificate +
Microsoft's MAA public PKI can re-run both verification chains from any
machine. Step-by-step guide in
`evidence/HOWTO-VERIFY-INDEPENDENTLY.md` (produced by the kit at end).

## Production deployment

This kit is for **one-shot validation**. For production deployment
(longer-running workloads, full hardening, day-2 operations), use
[`deploy/terraform/azure-sev-snp/`](../../../../deploy/terraform/azure-sev-snp/)
which mirrors this kit's VM but adds Key Vault sealing key, Storage
audit replica, Log Analytics, Defender, Backup, and immutability
policy. See `docs/deployment/azure.md` for the full deployment guide.

## See also

- `core/scripts/hardware-test/azure-sgx/` — Intel SGX track (companion kit)
- `core/scripts/hardware-test/gcp-sev-snp/` — GCP AMD SEV-SNP (same chip, single chain)
- `core/scripts/hardware-test/aws-nitro/` — AWS Nitro Enclaves (different family)
- `deploy/terraform/azure-sev-snp/` — production Terraform module
- `core/docs/operator/runbooks/azure-day2.md` — day-2 operations runbook
- `core/docs/security/threat_model.md` — threat model

---

_**Vault Genome Inc.** · AGPL-3.0-or-later (kit + tools) · NDA-scoped artifacts_
