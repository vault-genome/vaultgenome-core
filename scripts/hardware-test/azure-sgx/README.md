# Vault Genome — Azure Confidential Computing (Intel SGX) Hardware Validation Package

Reproducible end-to-end validation kit for running the Vault Genome
continuity layer on Azure VMs with Intel SGX (DCsv3 series).

This package lets a recipient — typically an acquirer's technical
evaluation team or a customer running a proof-of-concept — provision a
real SGX-capable VM in their own Azure subscription, run the full Vault
Genome test suite, capture **two independently-rooted** attestation
chains (Intel SGX Quote/PCK + Microsoft Azure Attestation JWT), and
bundle everything into a single tar archive ready for review. Total
reproduction time: ~30 minutes including model download.

This is the **Intel SGX track** — companion kit to
[`core/scripts/hardware-test/azure-sev-snp/`](../azure-sev-snp/) which
provides the AMD SEV-SNP track. Both run on Azure; choose based on
your TEE policy:

| Aspect | Azure SGX (this kit) | Azure SEV-SNP |
|--------|----------------------|---------------|
| Silicon | Intel Xeon Scalable + SGX | AMD EPYC + SEV-SNP |
| VM family | DCsv3 (e.g. Standard_DC4s_v3) | DCasv5 (e.g. Standard_DC4as_v5) |
| Trust boundary | Process-level enclave (within VM) | Whole-VM (Confidential VM) |
| Attestation | Intel SGX Quote → PCK → SGX Root CA + MAA JWT | AMD ARK→ASK→VCEK + MAA JWT |
| Best for | Smallest TCB, individual processes | Largest TCB, lift-and-shift workloads |

## What's special about Azure SGX

Like Azure SEV-SNP, this is a **dual-PKI** track:

1. **Intel SGX-rooted chain** (`oeutil verify` / `sgx_dcap_verify`):
   Quote signed by chip-specific PCK certificate, PCK signed by Intel SGX
   Root CA (Provisioning Certification Service)
2. **Microsoft-attested chain** (MAA JWT):
   Quote claims signed by Azure-PKI, anchored at Microsoft's MAA root

Both must verify for `production_grade: true`. Single-vendor PKI risk
mitigated by the second independent verifier.

## What this kit produces

After running the kit end-to-end, you will have:

1. A real Intel SGX VM (DCsv3) in your Azure subscription
2. A captured SGX **quote** (variable-size CBOR/EPID or DCAP, typically
   ~2-4 KB) generated via Open Enclave SDK's `oeutil`
3. The chip-specific PCK certificate fetched from Intel's PCS
4. Intel SGX Root CA chain verified locally (PCS root → Platform CA → PCK)
5. An MAA JWT proving Azure-attested SGX execution (Azure-specific 2nd verifier)
6. Demo 1 evidence — Llama 3.2 3B sealed/restored byte-identical
7. Demo 2 evidence — chain of 6 generations
8. Tamper detection evidence
9. (Optional) Inference comparison

## Prerequisites

- Azure subscription with billing enabled
- A region that supports DCsv3 (eastus, eastus2, westeurope, etc.)
- Subscription quota: ≥ 4 vCPU of "Standard DCSv3 Family vCPUs"
- IAM role / RBAC to create VMs / Storage / Network
- `az` CLI authenticated (`az login`)
- `terraform >= 1.6` installed
- ~30 minutes of wall time
- About $1-2 of compute (a couple of hours on `Standard_DC4s_v3`)

## Quick start

```bash
git clone https://github.com/vault-genome/vaultgenome-core
cd vaultgenome-core/scripts/hardware-test/azure-sgx/
./examples/full-test-run.sh
```

## Step-by-step

```bash
# 1. Provision VM
cd terraform/
terraform init && terraform apply

# 2. SSH in
ssh azureuser@<public-ip>

# 3. Bootstrap (installs Intel SGX DCAP + Open Enclave + Ollama + Go)
./scripts/01-bootstrap-vm.sh

# 4. Capture both attestation chains
./scripts/02-capture-attestation.sh           # SGX quote via oeutil
./scripts/02b-cryptographic-attestation.sh    # Intel chain (PCK + Root CA)
./scripts/02f-capture-maa-jwt.sh              # Microsoft MAA JWT — Azure-specific 2nd verifier

# 5. Run workloads
./scripts/03-demo1-single-bundle.sh
./scripts/04-demo2-chain.sh
./scripts/05-inference-test.sh

# 6. Pack evidence
./scripts/06-pack-evidence.sh

# 7. Tear down
exit
cd terraform/ && terraform destroy
```

## Cohort matrix

For multi-VM cohort matrix, see `scripts/07-cross-vm-matrix.sh`.
Reference matrix: `evidence/CROSS-VM-MATRIX.md`.

## Production deployment

For production deployment use [`deploy/terraform/azure-sgx/`](../../../../deploy/terraform/azure-sgx/)
which mirrors this kit's VM but adds Key Vault, Storage audit replica,
Log Analytics, Defender, Backup, and immutability policy. See
`docs/deployment/azure.md` for the full deployment guide.

## See also

- [`../azure-sev-snp/`](../azure-sev-snp/) — Azure AMD SEV-SNP companion kit
- `deploy/terraform/azure-sgx/` — production Terraform module
- `core/docs/operator/runbooks/azure-day2.md` — day-2 runbook (covers both backends)
- `core/docs/security/threat_model.md` — threat model

---

_**Vault Genome Inc.** · AGPL-3.0-or-later (kit + tools) · NDA-scoped artifacts_
