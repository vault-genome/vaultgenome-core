# Day-2 Operations Runbook — AWS

What this repository provides for AWS today, and the day-2 checks that apply
when you run the shipped daemons on an EC2 host.

For TEE-agnostic disaster recovery see
[disaster_recovery.md](disaster_recovery.md).

---

## What exists for AWS

- **No AWS deployment module.** This repository has no Terraform module,
  AMI or enclave image for running `sagvd` on AWS, and no integration with
  AWS KMS, S3 or CloudWatch. The only packaged deployment is
  `deploy/compose/` (Docker Compose), which runs on any Linux host.
- **No Nitro attestation in the shipped binaries.** The AWS Nitro adapter in
  `internal/shared/tee` is scaffolding: `sagvd`'s cross-cloud verifier
  registry and all three daemons refuse `aws-nitro` (KNOWN_ISSUES #1). The
  hardware families the binaries run on are AMD SEV-SNP on GCP
  ([real-tee-sev-snp.md](real-tee-sev-snp.md)), Intel TDX on GCP
  ([real-tee-tdx.md](real-tee-tdx.md)) and the Azure confidential GPU VM
  ([real-tee-azure-cgpu.md](real-tee-azure-cgpu.md)); AWS has no
  confidential GPU offering.
- **An evidence-capture kit.** `scripts/hardware-test/aws-nitro/` provisions
  one Nitro-enabled EC2 test instance (its own Terraform under `terraform/`),
  builds an enclave image around `acpctl` or the `vsock-attest` probe,
  captures a Nitro attestation document and checks its certificate chain.
  See its README; KNOWN_ISSUES #8 states what those captures prove.

---

## Day-1 verification on an EC2 host

### 1. sagvd is alive and ready

The health listener (`health.listen_address`, default `127.0.0.1:9091`) is
separate from the operator REST API (`http_api.listen_address`, default
`127.0.0.1:9080`). On the host:

```bash
curl -fsS http://127.0.0.1:9091/healthz    # ok
curl -fsS http://127.0.0.1:9091/readyz     # ready — once the Return Path listener is bound
```

Both answer plain text; `/metrics` on the same listener serves Prometheus
text. The REST API answers 404 for `/healthz`.

If there is no answer:
- Check the process is running and read its stderr. sagvd logs JSON lines to
  stderr only (no log file); a startup failure is the line
  `sagvd: terminated with error`, whose `err` names the cause.
- If you bound the health or REST listener beyond loopback, check that the
  security group admits the port from your monitoring and operator hosts.
  Beyond loopback the REST API requires a bearer token of at least 32
  characters and the Return Path requires mTLS; sagvd refuses to start
  otherwise.

### 2. Workers are connected

- sagvd logs `sagvd session opened` for every completed Return Path
  handshake, and `sagvd_sessions_opened_total` rises.
- A worker that cannot connect logs `return-path cycle failed` with a growing
  `backoff_ms`. Check that its `vault.address` reaches sagvd's
  `vault.listen_address` (security group), its mTLS files, and the TEE pins on
  both sides.

### 3. Logs in CloudWatch (if you ship them)

sagvd writes nothing to CloudWatch itself. If you ship its stderr to
CloudWatch Logs with your own agent, each line is a JSON object with `time`,
`level`, `msg` and, on failures, `err`. A metric filter pattern for error
lines is `{ $.level = "ERROR" }`; a Logs Insights query:

```
fields @timestamp, level, msg, err
| filter level = "ERROR"
| sort @timestamp desc
| limit 50
```

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

1. Pull the ERROR lines (query above). The ones that matter most:
   `sagvd integrity failure on wire`, `sagvd worker signature verification
   failed`, `sagvd return-path handshake failed` — see
   [triage_table.md](../triage_table.md).
2. If unrecoverable, page on-call per
   [03_incident_response.md](../03_incident_response.md).

---

## Tear-down

For the evidence kit, destroy the test instance from its Terraform directory:

```bash
cd scripts/hardware-test/aws-nitro/terraform/
terraform destroy
```

---

## See also

- [disaster_recovery.md](disaster_recovery.md) — TEE-agnostic DR
- [00_overview.md](../00_overview.md) — operator overview
- [03_incident_response.md](../03_incident_response.md) — incident escalation
- [`docs/security/threat_model.md`](../../security/threat_model.md) — threat model
- `scripts/hardware-test/aws-nitro/README.md` — Nitro evidence kit
- `deploy/compose/README.md` — the packaged deployment

---

_Document history: 2026-09-14 — checked line by line against the code; commands and names the binaries do not have were removed (the production Terraform module, enclave image, KMS, S3 and CloudWatch wiring it described are not in this repository)._
