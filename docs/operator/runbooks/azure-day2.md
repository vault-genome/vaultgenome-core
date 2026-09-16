# Day-2 Operations Runbook — Azure (SEV-SNP + SGX)

What this repository provides for Azure today, and the day-2 checks that
apply when you run the shipped daemons on an Azure VM. Both TEE backends are
covered in one place.

For TEE-agnostic disaster recovery see
[disaster_recovery.md](disaster_recovery.md).

---

## What exists for Azure

- **No Azure deployment module.** This repository has no Terraform module or
  image for running `sagvd` on Azure, and no integration with Key Vault,
  Azure Storage, Microsoft Azure Attestation or Log Analytics. The only
  packaged deployment is `deploy/compose/` (Docker Compose), which runs on
  any Linux host.
- **The shipped binaries attest on Azure hardware through the vTPM.**
  `sagvd`, `acp-compute` and `acp-bootstrap` attest as `azure-cgpu`
  (ADR 0019, [real-tee-azure-cgpu.md](real-tee-azure-cgpu.md)) on an Azure
  confidential GPU VM: the AMD report from the vTPM's HCL report, a TPM
  quote by the vTPM's attestation key binding the handshake's challenge,
  and NVIDIA's tokens for the H100. The `gcp-sev-snp` backend (configfs-tsm)
  does not apply on Azure, where the AMD report sits in the vTPM
  ([real-tee-sev-snp.md](real-tee-sev-snp.md) §B). The Azure SGX adapter in
  `internal/shared/tee` is scaffolding, refused by `sagvd`'s verifier
  registry and by all three daemons (KNOWN_ISSUES #1).
- **What is proven on Azure:** a genuine SEV-SNP report from a live Azure
  Confidential VM verifies offline — VCEK signature and chain to AMD
  ARK-Milan — in `TestRealSEVSNP_VerifiesGenuineAzureReport`, against
  `scripts/hardware-test/azure-sev-snp/live-evidence/`. To capture another,
  follow [real-tee-sev-snp.md](real-tee-sev-snp.md) §B and §C.
- **Evidence kits:** `scripts/hardware-test/azure-sev-snp/` and
  `scripts/hardware-test/azure-sgx/` (each with its own `terraform/`). The
  SGX cohort ran in DEBUG mode (KNOWN_ISSUES #8).

---

## Day-1 verification on an Azure VM

### 1. sagvd is alive and ready

The health listener (`health.listen_address`, default `127.0.0.1:9091`) is
separate from the operator REST API (`http_api.listen_address`, default
`127.0.0.1:9080`). On the VM:

```bash
curl -fsS http://127.0.0.1:9091/healthz    # ok
curl -fsS http://127.0.0.1:9091/readyz     # ready — once the Return Path listener is bound
```

Both answer plain text; `/metrics` on the same listener serves Prometheus
text. The REST API answers 404 for `/healthz`.

If there is no answer:
- Check the process (or, with `deploy/compose`, the container) is running
  and read its stderr: sagvd logs JSON lines to stderr only; a startup
  failure is the line `sagvd: terminated with error`, whose `err` names the
  cause.
- If you bound the health or REST listener beyond loopback, check that the
  NSG admits the port from your monitoring and operator hosts. Beyond
  loopback the REST API requires a bearer token of at least 32 characters and
  the Return Path requires mTLS; sagvd refuses to start otherwise.

### 2. Workers are connected

- sagvd logs `sagvd session opened` for every completed Return Path
  handshake, and `sagvd_sessions_opened_total` rises.
- A worker that cannot connect logs `return-path cycle failed` with a growing
  `backoff_ms`. Check that its `vault.address` reaches sagvd's
  `vault.listen_address` (NSG), its mTLS files, and the TEE pins on both
  sides.

### 3. Logs (if you ship them)

sagvd writes nothing to Azure Monitor itself. If you collect its stderr into
Log Analytics with your own agent, each line is a JSON object with `time`,
`level`, `msg` and, on failures, `err`; alert on `level == "ERROR"`. The table
and column names depend on how you ingest.

---

## Day-2 operations

- **Key and trust rotation**: [disaster_recovery.md](disaster_recovery.md)
  scenarios 1 and 2, and [06](../06_cross_cloud_restore.md) "Rotating what you
  trust". Every change to key files, `workers.registry_path`, TLS files or the
  bearer token takes effect at the next sagvd start.
- **Restarts**: SIGTERM shuts sagvd down gracefully and wipes its in-memory
  keys; jobs queued or running at that moment are lost (the queue is in
  memory) and must be resubmitted.

---

## Incident response

1. Pull the ERROR lines. The ones that matter most:
   `sagvd integrity failure on wire`, `sagvd worker signature verification
   failed`, `sagvd return-path handshake failed` — see
   [triage_table.md](../triage_table.md).
2. If unrecoverable, page on-call per
   [03_incident_response.md](../03_incident_response.md).

---

## Tear-down

- The SGX kit: `terraform destroy` in `scripts/hardware-test/azure-sgx/terraform/`
  (its README, step 7).
- A Confidential VM created by hand for a SEV-SNP capture:
  `az group delete -n vg-cvm-rg --yes --no-wait`
  ([real-tee-sev-snp.md](real-tee-sev-snp.md), "Cleanup").

---

## See also

- [disaster_recovery.md](disaster_recovery.md) — TEE-agnostic DR
- [real-tee-sev-snp.md](real-tee-sev-snp.md) — real AMD SEV-SNP on GCP and Azure
- [00_overview.md](../00_overview.md) — operator overview
- [03_incident_response.md](../03_incident_response.md) — incident escalation
- [`docs/security/threat_model.md`](../../security/threat_model.md) — threat model
- `scripts/hardware-test/azure-sev-snp/README.md` — SEV-SNP evidence
- `scripts/hardware-test/azure-sgx/README.md` — SGX validation kit
- `deploy/compose/README.md` — the packaged deployment

---

_Document history: 2026-09-14 — checked line by line against the code; commands and names the binaries do not have were removed (the production Terraform modules, Key Vault release policies, storage immutability and Log Analytics wiring it described are not in this repository)._
