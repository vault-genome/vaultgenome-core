# Vault Genome — GCP SEV-SNP Hardware Validation Package

Reproducible end-to-end validation kit for running the Vault Genome
continuity layer on Google Cloud Confidential Computing (AMD SEV-SNP).

This package lets a recipient — typically an acquirer's technical
evaluation team or a customer running a proof-of-concept — provision a
real Confidential VM on their own GCP project, run the full Vault Genome
test suite, and capture cryptographically-rooted evidence on their own
terms. Total reproduction time: ~30 minutes including model download.

## What this kit produces

After running the kit end-to-end, you will have:

1. A real AMD SEV-SNP Confidential VM in your GCP project
2. A 1184-byte SEV-SNP attestation report captured directly from
   `/dev/sev-guest` via ioctl (signed by your VM's chip-specific VCEK)
3. Demo 1 evidence — full Llama 3.2 3B model sealed and restored
   byte-identical, with `acpctl genome verify` confirming every blob
   hash matches the envelope record
4. Demo 2 evidence — chain of 6 LoRA-style generations sealed,
   chain-validated, lineage walked back to genesis, mid-chain rewind
5. Tamper detection evidence — 1-byte flip in the sealed payload
   produces an AES-256-GCM authentication failure
6. (Optional) Inference comparison — same prompt + seed against
   original and restored daemons producing byte-identical output

All evidence is captured into a single tar archive ready for review
or upload to your evaluation data room.

## Prerequisites

- A GCP project with Compute Engine API enabled
- IAM permission to create N2D Confidential VMs (`compute.instanceAdmin`)
- `gcloud` CLI authenticated (`gcloud auth login`)
- `terraform >= 1.5` installed
- ~30 minutes of wall time
- About $1-2 of compute (a couple of hours on `n2d-standard-4`)

The kit defaults to `us-central1-a` and `n2d-standard-4` (4 vCPU, 16
GB). Both can be overridden via Terraform variables.

## Quick start — one command

```bash
git clone https://github.com/vault-genome/vaultgenome-core
cd vaultgenome-core/scripts/hardware-test/gcp-sev-snp/
./examples/full-test-run.sh   # provisions VM, bootstraps, runs all tests, packs evidence, tears down
```

The runner will print a Cloud Storage URL where it has uploaded the
evidence tar at the end.

## Step-by-step (if you want to inspect each phase)

```bash
# 1. Provision VM
cd terraform/
terraform init
terraform apply

# 2. SSH to the new VM (terraform output prints the gcloud command)
gcloud compute ssh vault-genome-sev-snp-test --zone=us-central1-a

# 3. On the VM — bootstrap (install Go, Ollama, gcloud auth, etc.)
curl -fsSL https://raw.githubusercontent.com/<this-repo>/main/scripts/01-bootstrap-vm.sh | bash

# 4. Capture SEV-SNP attestation report (raw 1184-byte report via ioctl)
./scripts/02-capture-attestation.sh

# 4b. Cryptographic chain validation: ARK → ASK → VCEK → Report
#     (workload-bound via REPORT_DATA = SHA-512(payload manifest); produces a
#      complete attestation evidence directory verified against AMD's PKI)
./scripts/02b-cryptographic-attestation.sh

# 5. Pull a model + run Demo 1 (single bundle round-trip)
./scripts/03-demo1-single-bundle.sh

# 6. Run Demo 2 (chain of 6 generations)
./scripts/04-demo2-chain.sh

# 7. (Optional) inference comparison — empirical proof of model continuity
./scripts/05-inference-test.sh

# 8. Pack evidence + upload to your bucket
./scripts/06-pack-evidence.sh

# 9. Cleanup
cd terraform/ && terraform destroy
```

## Multi-VM cross-attestation matrix

For an N-VM attestation cohort (proves N distinct physical chips):

```bash
# After running steps 1-4b on N VMs and downloading evidence dirs to your laptop:
./scripts/07-cross-vm-matrix.sh ~/path/to/evidence-root/
# Produces CROSS-VM-MATRIX.md with: distinct-Chip-ID check, per-VM verify status, REPORT_DATA bindings
```

If a VM's chain validation was deferred (e.g. AMD KDS upstream issue at
capture time), complete it later from any internet-connected machine:

```bash
./scripts/02c-deferred-vcek-fetch.sh ~/path/to/<VM-evidence-dir>/
# fetches AMD certs, runs verify, drops 08/09/10 + 99-CHAIN-VALIDATION-COMPLETED.md
# into the directory. No new VM provisioning required — captured report is immutable.
```

## Cross-region / cross-zone variants

For full disaster-recovery story, repeat steps 1-7 in a second region
or zone (the kit supports it via `TF_VAR_zone=europe-west4-a` or any
other valid SEV-SNP-supporting zone). The bundle from the first VM
can then be downloaded and restored on the second — bytes will be
identical (verify pass) and inference output will match.

For our own Week 1 validation, we ran:
- VM1: us-central1-a (Iowa zone A)
- VM2: europe-west4-a (Belgium) — cross-region restore
- VM3: us-central1-b (Iowa zone B) — cross-zone restore
- VM4: europe-west4-a — second Belgium VM for empirical inference

## Architecture

```
[ your laptop / data-room ]
            │
            │  terraform apply
            ▼
[ GCP Confidential VM (N2D, AMD SEV-SNP) ]
   │
   ├── /dev/sev-guest           direct ioctl → 1184-byte attestation report
   ├── /usr/local/bin/acpctl    Vault Genome CLI (compiled Go binary)
   ├── /usr/share/ollama        Llama 3.2 3B model (~2 GB)
   └── ./evidence/              all captured outputs
            │
            ▼
   acpctl genome seal      → 1.88 GiB .genome bundle
   acpctl genome open      → restore in <5 sec
   acpctl genome verify    → re-hash every blob, confirm match
   acpctl genome chain     → walk 6-generation lineage
   acpctl genome rewind    → time-travel to any prior generation
   1-byte tamper test      → AEAD authentication catches it
```

## What's *not* in this kit

- **Multi-cloud / cross-cloud** — this kit covers GCP only. AWS Nitro
  Enclaves, Azure SGX, Intel SGX bare-metal, and cross-cloud KMS-mediated
  restore are separate kits in their respective `hardware-test/<platform>`
  directories.

- **AGPL / commercial licensing decisions** — the bundle format and
  the conformance suite are AGPL. The reproducible deployment package
  itself (Terraform, scripts, README) is shared under your NDA scope.

## What our Week 1 test produced

Reference output of running this kit on our four-VM matrix is at
`~/Desktop/GCP-SEV-SNP-Real-Hardware-Test/` in the founders' Desktop
package, available under NDA. Headline numbers:

| Metric | Result |
|---|---|
| Confidential VMs provisioned | 4 (across 2 regions, 3 zones) |
| Distinct AMD silicon chips proven (via attestation hashes) | 4 |
| Bundle SHA-256 consistency across 5 platforms | identical |
| Cross-region restores (Iowa → Belgium, byte-identical) | 1 (full Llama 3.2 3B) |
| Cross-zone restores | 1 (Iowa-A → Iowa-B) |
| Inference outputs proven byte-identical across regions | yes |
| Tamper detection | AEAD auth failure on 1-byte flip |
| Failures of any cryptographic check | 0 |

## Support

ops@vaultgenome.com — we read every message.

If you're a security researcher who finds a bug while running this kit,
see `SECURITY.md` in the repo root for our coordinated disclosure
process.

---

*Vault Genome Inc. · AGPL-3.0-or-later (kit + tools) · NDA-scoped artifacts*
