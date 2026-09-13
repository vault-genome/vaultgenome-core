# AWS Deployment Architecture

Full deployment-level architecture for Vault Genome on AWS Nitro
Enclaves. Maps every AWS resource provisioned by the production
Terraform module (`deploy/terraform/aws/examples/production/`) to its
role in the data flow.

For component-level architecture (TEE-agnostic) see
`core/docs/diagrams/architecture-overview.svg`. For deployment guide
see `docs/deployment/aws.md`. For day-2 operations see
`core/docs/operator/runbooks/aws-day2.md`.

---

## Top-level deployment

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          CUSTOMER'S AWS ACCOUNT                              │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │                  Region (e.g. us-east-2 / Ohio)                       │   │
│   │                                                                        │   │
│   │   ┌─────────────────────────────────────────────────────────────┐    │   │
│   │   │                    Customer's VPC                            │    │   │
│   │   │                                                              │    │   │
│   │   │  ┌─────────────────┐         ┌──────────────────────────┐  │    │   │
│   │   │  │ Optional ALB     │ ◄──────│  Workload subnets        │  │    │   │
│   │   │  │ HTTPS :443       │         │  (callers via 8080)      │  │    │   │
│   │   │  │ TLS termination  │         └──────────────────────────┘  │    │   │
│   │   │  └────────┬────────┘                                         │    │   │
│   │   │           │  TCP :8080                                        │    │   │
│   │   │           ▼                                                   │    │   │
│   │   │  ┌────────────────────────────────────────────────┐         │    │   │
│   │   │  │      Private subnet (e.g. us-east-2a)           │         │    │   │
│   │   │  │                                                   │         │    │   │
│   │   │  │   ┌──────────────────────────────────────────┐   │         │    │   │
│   │   │  │   │   EC2 m5.xlarge / m5.2xlarge              │   │         │    │   │
│   │   │  │   │   parent host (Amazon Linux 2023)         │   │         │    │   │
│   │   │  │   │                                              │   │         │    │   │
│   │   │  │   │   ┌────────────┐ ┌────────────┐ ┌────────┐ │   │         │    │   │
│   │   │  │   │   │  sagvd     │ │ acp-       │ │ nitro- │ │   │         │    │   │
│   │   │  │   │   │  :8080 API │ │ compute    │ │ cli +  │ │   │         │    │   │
│   │   │  │   │   │  :9090 hp  │ │ (worker)   │ │ alloc- │ │   │         │    │   │
│   │   │  │   │   │            │ │ :9443 mTLS │ │ ator   │ │   │         │    │   │
│   │   │  │   │   └─────┬──────┘ └─────┬──────┘ └───┬────┘ │   │         │    │   │
│   │   │  │   │         │              │            │       │   │         │    │   │
│   │   │  │   │         │  vsock CID 3 ↔ CID 16     │       │   │         │    │   │
│   │   │  │   │         ▼              ▼            ▼       │   │         │    │   │
│   │   │  │   │   ┌────────────────────────────────────┐    │   │         │    │   │
│   │   │  │   │   │     CHILD NITRO ENCLAVE              │    │   │         │    │   │
│   │   │  │   │   │     vault-genome-attest-prod.eif     │    │   │         │    │   │
│   │   │  │   │   │     (4 vCPU + 8 GB allocated)        │    │   │         │    │   │
│   │   │  │   │   │     ─────────────────────────────    │    │   │         │    │   │
│   │   │  │   │   │     /dev/nsm   (NSM ioctl)            │    │   │         │    │   │
│   │   │  │   │   │     vsock-attest binary               │    │   │         │    │   │
│   │   │  │   │   │     PCR0/1/2 chip-measured            │    │   │         │    │   │
│   │   │  │   │   │     COSE_Sign1 attestation            │    │   │         │    │   │
│   │   │  │   │   └────────────────────────────────────┘    │   │         │    │   │
│   │   │  │   │                                              │   │         │    │   │
│   │   │  │   │   IAM instance role:                         │   │         │    │   │
│   │   │  │   │     kms:Decrypt + GenerateDataKey            │   │         │    │   │
│   │   │  │   │     s3:PutObject + GetObject + DeleteObject  │   │         │    │   │
│   │   │  │   │     logs:CreateLogStream + PutLogEvents      │   │         │    │   │
│   │   │  │   └────┬───────────────┬────────────────┬─────────┘   │         │    │   │
│   │   │  │        │               │                │              │         │    │   │
│   │   │  │   KMS  │           S3  │       CloudWatch│             │         │    │   │
│   │   │  │   Decrypt           Put              Put              │         │    │   │
│   │   │  │   (PCR0-cond)       Object           LogEvents        │         │    │   │
│   │   │  └─────────────────────────────────────────────────────┘         │    │   │
│   │   │           │               │                │                       │    │   │
│   │   └───────────┼───────────────┼────────────────┼───────────────────────┘    │   │
│   │               ▼               ▼                ▼                            │   │
│   │   ┌──────────────────┐ ┌─────────────────┐ ┌──────────────────────┐       │   │
│   │   │ KMS sealing key  │ │ S3 audit bucket  │ │ CloudWatch log group │       │   │
│   │   │ Auto-rotated 1y  │ │ Versioned + AES  │ │ 7-year retention     │       │   │
│   │   │ PCR0-conditional │ │ Object Lock 7y   │ │ JSON-structured logs │       │   │
│   │   │ Decrypt policy   │ │ (COMPLIANCE)     │ │ → SIEM via subscript │       │   │
│   │   └──────────────────┘ └─────────────────┘ └──────────────────────┘       │   │
│   │                                                                            │   │
│   │   Optional hardening (opt-in via Terraform flags):                         │   │
│   │   ┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────┐  │   │
│   │   │ VPC Flow Logs        │ │ GuardDuty detector   │ │ AWS Backup vault │  │   │
│   │   │ → CloudWatch         │ │ + S3 malware protect │ │ Daily snapshots  │  │   │
│   │   │ (anomaly detection)  │ │                       │ │ 35-day retention │  │   │
│   │   └──────────────────────┘ └──────────────────────┘ └──────────────────┘  │   │
│   │                                                                            │   │
│   │   ┌──────────────────────────────────────────────────────────────────┐    │   │
│   │   │ CloudTrail trail covering KMS + S3 + EC2 API calls in this region │    │   │
│   │   └──────────────────────────────────────────────────────────────────┘    │   │
│   └────────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Data flows

### 1. Sealing flow (write path)

A caller wants to seal a model bundle:

```
caller → ALB → sagvd :8080  /api/v1/seal  (HTTP POST with bundle bytes)
                  │
                  ▼
              sagvd reads model from local disk (or S3)
                  │
                  ▼
              sagvd asks KMS GenerateDataKey   ←┐  GenerateDataKey returns
                  │                              │  ciphertext blob + plain
                  ▼                              │  (plain stays in sagvd
              sagvd encrypts payload with        │  RAM only, never persists)
              data key (AES-256-GCM)             │
                  │                              │
                  ▼                              │
              sagvd writes .genome bundle  ─────┘
              with envelope referencing
              the KMS ciphertext blob
                  │
                  ▼
              sagvd appends audit chain entry
              (timestamp, caller, bundle hash, KMS key version)
                  │
                  ▼
              sagvd writes audit entry to local disk + replicates to S3
                  │
                  ▼
              sagvd writes structured log line to CloudWatch
                  │
                  ▼
              sagvd returns bundle path/hash to caller
```

### 2. Restore flow (read path)

A caller wants to unseal a previously-sealed bundle:

```
caller → ALB → sagvd :8080  /api/v1/restore  (with bundle path/hash)
                  │
                  ▼
              sagvd reads bundle envelope from disk
                  │
                  ▼
              sagvd asks the ENCLAVE to perform Decrypt
              (sagvd-host cannot Decrypt directly — KMS policy
               requires PCR0 attestation that only the enclave provides)
                  │
                  │ vsock to enclave
                  ▼
              ┌──────────────────────────────────────┐
              │  ENCLAVE                              │
              │  - opens NSM session                  │
              │  - generates attestation document     │
              │    with PCR0 from chip + caller's     │
              │    request as user_data               │
              │  - sends to KMS:Decrypt with          │
              │    --recipient-attestation            │
              │  - KMS verifies attestation against   │
              │    its key policy (PCR0 must match    │
              │    the value pinned at apply time)    │
              │  - on match: KMS returns plaintext    │
              │    data key encrypted to enclave's    │
              │    public key (derived from attest)   │
              │  - enclave decrypts data key locally  │
              │  - enclave returns plaintext data key │
              │    to sagvd over vsock                │
              └─────────────────┬────────────────────┘
                                │
                                ▼  vsock to host
              sagvd uses plaintext data key to AES-256-GCM-decrypt
              the bundle payload
                  │
                  ▼
              sagvd verifies every component blob digest matches envelope
                  │
                  ▼
              sagvd writes restored model to /tmp/<requested-target>
                  │
                  ▼
              sagvd appends audit chain entry (restore event)
                  │
                  ▼
              sagvd returns restore path/manifest to caller
```

**Critical security property**: even if the parent EC2 host operator
fully compromises the host (e.g. installs a rootkit), they CANNOT
decrypt sealed bundles because:

- The KMS Decrypt call requires a fresh attestation document
- The attestation document requires the enclave to be running the
  exact .eif image whose PCR0 matches the KMS key policy
- The enclave's attestation private key never leaves the chip
- Therefore the host operator cannot fake the attestation

### 3. Audit replication

```
sagvd writes audit entry  ──→  local disk (parent EC2)
                          ──→  S3 audit bucket (versioned + Object Lock)

                          if cross-region replication enabled:
                          ──→  S3 destination bucket in DR region
```

Audit entries are append-only. Object Lock COMPLIANCE-mode prevents
deletion or modification until retention expires (7 years default).

### 4. Cross-region disaster recovery

```
Primary region (us-east-2):                  DR region (eu-west-1):
─────────────────────────                    ──────────────────────

   sagvd seals bundle              ──→         (DR region inactive)
            │
            ▼
   audit S3 (us-east-2)           ──→         audit S3 (eu-west-1)
                                              (cross-region replication)

Failover trigger (us-east-2 outage):

                                              terraform apply identical
                                              production module here
                                                       │
                                                       ▼
                                              new EC2 + new enclave +
                                              same KMS key policy
                                              (multi-region KMS or
                                              re-encrypt-at-restore)
                                                       │
                                                       ▼
                                              acpctl genome restore
                                              from replicated bundle
                                                       │
                                                       ▼
                                              same prompt + seed
                                              → byte-identical inference
```

This was empirically validated in our Week 2 cross-region test —
sealed Llama 3.2 3B in Ohio, restored in Ireland, byte-identical
output. See
`core/scripts/hardware-test/aws-nitro/evidence/workload/cross-region-result.txt`.

---

## Trust boundaries

| Boundary | What's inside (trusted) | What's outside (untrusted) |
|----------|--------------------------|----------------------------|
| The chip | Attestation private key, PCR0/1/2 measurements | Everything else |
| The enclave | Sealing data keys (briefly), workload manifest | Parent host operator |
| The parent EC2 | sagvd process state, audit chain replication | Other tenants on same hardware (Nitro hypervisor isolates) |
| The VPC | IAM-verified callers via ALB | Internet, other VPCs |
| The AWS account | Account root + IAM admins | Other AWS accounts |

The **strongest** boundary is the chip ↔ enclave boundary. Even AWS
itself cannot extract the attestation private key (it's burned into
the Nitro Security Module silicon at manufacture). The next strongest
is enclave ↔ parent host.

---

## What's NOT in this architecture (and why)

- **No public-facing endpoint by default** — sagvd's :8080 is
  intentionally internal. Add an ALB or PrivateLink endpoint as needed.
- **No customer data outside the enclave** — sagvd never decrypts on
  the parent host. Decryption only happens inside the enclave at
  restore time.
- **No third-party services** — no telemetry to Vault Genome, no
  external dependency at runtime. Only your AWS account + the public
  Ollama registry (for model pulls) + AWS APIs.
- **No multi-tenancy** — one Vault Genome deployment per AWS account
  by default. Multi-tenant deployments require additional design
  (separate KMS keys per tenant, per-tenant audit buckets).
- **No HA/multi-instance by default** — single-EC2 deployment. HA
  topology in roadmap.

---

## See also

- `docs/deployment/aws.md` — full deployment guide
- `core/docs/operator/runbooks/aws-day2.md` — day-2 operations
- `core/docs/security/threat_model.md` — threat model
- `core/docs/diagrams/architecture-overview.svg` — component-level (TEE-agnostic)
- `core/docs/diagrams/session-flow.svg` — sealing/restore session flow
- `deploy/terraform/aws/README.md` — Terraform module reference
