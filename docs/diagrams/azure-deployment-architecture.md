# Azure Deployment Architecture

Full deployment-level architecture for Vault Genome on Azure, covering
**both** TEE backends (AMD SEV-SNP via DCasv5 / Intel SGX via DCsv3).
Maps every Azure resource provisioned by the production Terraform
modules to its role in the data flow.

For component-level architecture (TEE-agnostic) see
`core/docs/diagrams/architecture-overview.svg`. For deployment guide
see `docs/deployment/azure.md`. For day-2 operations see
`core/docs/operator/runbooks/azure-day2.md`.

---

## Top-level deployment (SEV-SNP — Confidential VM track)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                       CUSTOMER'S AZURE SUBSCRIPTION                           │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │                  Region (e.g. eastus2)                                │   │
│   │                                                                        │   │
│   │   ┌─────────────────────────────────────────────────────────────┐    │   │
│   │   │                     Customer's VNet                          │    │   │
│   │   │                                                              │    │   │
│   │   │  ┌─────────────────┐         ┌──────────────────────────┐  │    │   │
│   │   │  │ Optional Std LB  │ ◄──────│  Workload subnets        │  │    │   │
│   │   │  │ TCP :8080        │         │  (callers via 8080)      │  │    │   │
│   │   │  │                  │         └──────────────────────────┘  │    │   │
│   │   │  └────────┬────────┘                                         │    │   │
│   │   │           │  TCP :8080                                        │    │   │
│   │   │           ▼                                                   │    │   │
│   │   │  ┌────────────────────────────────────────────────┐         │    │   │
│   │   │  │      Private subnet (e.g. eastus2-1)             │         │    │   │
│   │   │  │                                                   │         │    │   │
│   │   │  │   ┌──────────────────────────────────────────┐   │         │    │   │
│   │   │  │   │   CONFIDENTIAL VM (DC4as_v5)              │   │         │    │   │
│   │   │  │   │   AMD SEV-SNP + vTPM + Secure Boot         │   │         │    │   │
│   │   │  │   │   Ubuntu 22.04 CVM image                   │   │         │    │   │
│   │   │  │   │                                              │   │         │    │   │
│   │   │  │   │   ┌────────────┐ ┌────────────┐            │   │         │    │   │
│   │   │  │   │   │  sagvd     │ │ acp-       │            │   │         │    │   │
│   │   │  │   │   │  :8080 API │ │ compute    │            │   │         │    │   │
│   │   │  │   │   │  :9091 hp  │ │ (worker)   │            │   │         │    │   │
│   │   │  │   │   │  :9443 RP  │ │ :9443 mTLS │            │   │         │    │   │
│   │   │  │   │   └─────┬──────┘ └─────┬──────┘            │   │         │    │   │
│   │   │  │   │         │              │                    │   │         │    │   │
│   │   │  │   │  /dev/sev-guest (SNP_GET_REPORT ioctl)      │   │         │    │   │
│   │   │  │   │         │                                    │   │         │    │   │
│   │   │  │   │   ┌─────┴─────────────────────────────┐    │   │         │    │   │
│   │   │  │   │   │  AMD SEV-SNP firmware              │    │   │         │    │   │
│   │   │  │   │   │  Whole-VM trust boundary           │    │   │         │    │   │
│   │   │  │   │   │  Launch measurement = SHA-384      │    │   │         │    │   │
│   │   │  │   │   │  REPORT_DATA = SHA-512(manifest)   │    │   │         │    │   │
│   │   │  │   │   └────────────────────────────────────┘    │   │         │    │   │
│   │   │  │   │                                              │   │         │    │   │
│   │   │  │   │   Managed identity:                          │   │         │    │   │
│   │   │  │   │     KV release (MAA-conditional)             │   │         │    │   │
│   │   │  │   │     Storage Blob Data Contributor            │   │         │    │   │
│   │   │  │   │     Log Analytics Sender                     │   │         │    │   │
│   │   │  │   └────┬───────────────┬────────────────┬─────────┘   │         │    │   │
│   │   │  │        │               │                │              │         │    │   │
│   │   │  │   MAA  │       Storage │       Log Analytics│           │         │    │   │
│   │   │  │   JWT                Blob Put              Send         │         │    │   │
│   │   │  │   request           (immutable)            ↓            │         │    │   │
│   │   │  └─────────────────────────────────────────────────────┘             │   │
│   │   │           │               │                │                          │   │
│   │   │           ▼               ▼                ▼                          │   │
│   │   │   ┌──────────────┐ ┌─────────────────┐ ┌──────────────────────┐     │   │
│   │   │   │ MAA endpoint │ │ Storage GZRS    │ │ Log Analytics        │     │   │
│   │   │   │ shared OR    │ │ versioned +     │ │ 730-day direct       │     │   │
│   │   │   │ dedicated    │ │ immutability    │ │ JSON-structured      │     │   │
│   │   │   │ JWT signing  │ │ LOCKED 7-year   │ │ → SIEM via webhook   │     │   │
│   │   │   └──────┬───────┘ └─────────────────┘ └──────────────────────┘     │   │
│   │   │          │                                                          │   │
│   │   │          ▼                                                          │   │
│   │   │   ┌──────────────────────────────────────────────┐                │   │
│   │   │   │ Premium Key Vault                             │                │   │
│   │   │   │ RSA-HSM 4096 sealing key                      │                │   │
│   │   │   │ release_policy = MAA-conditional grant        │                │   │
│   │   │   │ Auto-rotation enabled                         │                │   │
│   │   │   │ Soft-delete + purge protection                │                │   │
│   │   │   └──────────────────────────────────────────────┘                │   │
│   │   │                                                                    │   │
│   │   │   Optional hardening (opt-in via Terraform flags):                 │   │
│   │   │   ┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────┐  │   │
│   │   │   │ NSG flow logs        │ │ Defender for Cloud    │ │ Recovery Services │  │   │
│   │   │   │ → Log Analytics      │ │ Servers Plan 2        │ │ Daily VM snapshots │ │   │
│   │   │   │ + Traffic Analytics  │ │                       │ │ 35-day retention  │  │   │
│   │   │   └──────────────────────┘ └──────────────────────┘ └──────────────────┘  │   │
│   │   │                                                                            │   │
│   │   │   ┌──────────────────────────────────────────────────────────────────┐   │   │
│   │   │   │ Diagnostic settings — KV, Storage, NSG audit events → Log Analytics │   │   │
│   │   │   └──────────────────────────────────────────────────────────────────┘   │   │
│   │   └────────────────────────────────────────────────────────────────────────┘   │
│   └──────────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## Top-level deployment (SGX — process-level enclave track)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                       CUSTOMER'S AZURE SUBSCRIPTION                           │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │                  Region (e.g. eastus2)                                │   │
│   │   ┌────────────────────────────────────────────────────────────────┐ │   │
│   │   │      Customer's VNet → Private subnet (eastus2-1)               │ │   │
│   │   │                                                                  │ │   │
│   │   │   ┌──────────────────────────────────────────────────────────┐ │ │   │
│   │   │   │   STANDARD VM (DC4s_v3)                                  │ │ │   │
│   │   │   │   Intel SGX-capable Xeon Scalable                         │ │ │   │
│   │   │   │   Ubuntu 24.04 LTS (regular image)                        │ │ │   │
│   │   │   │                                                           │ │ │   │
│   │   │   │   ┌──────────────────────────────────────────┐           │ │ │   │
│   │   │   │   │  sagvd container (user-space)            │           │ │ │   │
│   │   │   │   │  /dev/sgx_enclave + /dev/sgx_provision  │           │ │ │   │
│   │   │   │   │           ↓                               │           │ │ │   │
│   │   │   │   │  ┌──────────────────────────────────┐    │           │ │ │   │
│   │   │   │   │  │  SGX ENCLAVE (in-process)         │    │           │ │ │   │
│   │   │   │   │  │  Open Enclave SDK / EGo Go        │    │           │ │ │   │
│   │   │   │   │  │  MRENCLAVE = SHA-256 of binary    │    │           │ │ │   │
│   │   │   │   │  │  REPORT_DATA = SHA-512(manifest)  │    │           │ │ │   │
│   │   │   │   │  │  Quote signed by chip-PCK         │    │           │ │ │   │
│   │   │   │   │  └──────────────────────────────────┘    │           │ │ │   │
│   │   │   │   └──────────────────────────────────────────┘           │ │ │   │
│   │   │   │                                                           │ │ │   │
│   │   │   │   aesmd service + az-dcap-client (collateral cache)        │ │ │   │
│   │   │   └──────────────────────────────────────────────────────────┘ │ │   │
│   │   │                                                                  │ │   │
│   │   │   Same Key Vault / Storage / Log Analytics / NSG / MAA scaffold │ │   │
│   │   │   as the SEV-SNP track. The TEE difference is process-level     │ │   │
│   │   │   (SGX) vs whole-VM (SEV-SNP), but the production envelope is   │ │   │
│   │   │   identical — Vault Genome treats both as opaque attestation    │ │   │
│   │   │   sources behind the frozen Verifier interface.                  │ │   │
│   │   └────────────────────────────────────────────────────────────────┘ │   │
│   └──────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Data flows

### 1. Sealing flow (write path)

```
1. Caller posts payload to sagvd at :8080
2. sagvd computes SHA-256 of payload, builds .genome envelope
3. sagvd requests sealing-key release from Key Vault, presenting:
     - Managed identity OAuth token, AND
     - MAA JWT proving SEV-SNP/SGX execution (chip-attested)
4. Key Vault checks release_policy:
     - JWT signed by MAA's PKI? ✓
     - x-ms-attestation-type matches? (sevsnpvm or sgx) ✓
     - x-ms-compliance-status = azure-compliant-cvm? ✓
     - measurement matches (if bound)? ✓
5. Key Vault releases the wrapping key to sagvd
6. sagvd encrypts the .genome bundle with AES-256-GCM
7. sagvd writes:
     - Bundle to local disk (acp-compute reads it for jobs)
     - Audit chain entry to Storage container (immutable)
     - Log entry to Log Analytics workspace
8. sagvd returns 200 OK to caller with bundle SHA-256
```

### 2. Restore flow (read path)

```
1. Caller posts bundle hash + target dir to sagvd at :8080
2. sagvd reads bundle from local disk (or Storage if missing)
3. sagvd requests sealing-key release from Key Vault (same MAA-bound flow)
4. Key Vault releases the wrapping key (only to a valid TEE)
5. sagvd verifies AES-256-GCM authentication tag
6. sagvd writes restored payload to target dir
7. sagvd records "restore-attempted" + "restore-succeeded" or "-tampered"
   in audit chain
```

### 3. Audit chain replication

```
1. Every sagvd write/read produces an audit chain entry
2. Entry goes to:
     - Local /data/audit-chain (durable on the OS disk)
     - Storage container audit-chain/* (geo-replicated via GZRS)
     - Log Analytics (730-day direct queryability)
3. Storage immutability policy locks blobs: no delete, no shorten,
   no overwrite (only create) for retention window (7 years default)
4. acpctl audit verify --range latest-100 walks the chain locally,
   verifies SHA-256 chaining, returns OK or surfaces a break
```

### 4. Cross-region disaster recovery

```
1. Region eastus2 becomes unavailable
2. Operator runs `terraform apply` in westeurope (or backup region)
   with same expected_measurement + same workload manifest
3. New VM has its own Chip ID but same Key Vault release policy
   (MAA-conditional — accepts any SEV-SNP/SGX VM matching policy)
4. GZRS replication brings the audit container's geo-paired storage
   online in westeurope; sagvd reads the latest bundle
5. sagvd in westeurope unwraps the bundle (Key Vault is regional —
   if eastus2 KV survived the failure, restore from there; else use
   a pre-replicated KV in westeurope or re-create with the same key)
6. Inference output is byte-identical (deterministic sampling) — proven
   in the cohort cross-region test
```

---

## Trust boundaries

| Boundary | Inside (trusted) | Outside (verified before trust) |
|----------|------------------|-------------------------------|
| **Confidential VM (SEV-SNP)** | Whole guest OS + sagvd + acp-compute | Hypervisor, host OS, hardware vendors except AMD |
| **SGX enclave (single process)** | Just the enclave binary | Host OS, sagvd outside the enclave, hypervisor |
| **Key Vault release policy** | Sealing key material | The VM until it presents valid MAA JWT |
| **MAA-PKI** | The JWT and its claims | Microsoft's MAA certificate root must be reachable + verifiable |
| **AMD/Intel root CA** | Chain anchored at vendor root | Vendor PKI must be reachable + verifiable |
| **Storage immutability** | Audit blobs once written | Anyone with delete RBAC (locked policy = nobody) |

The Vault Genome design relies on **two independent trust anchors**:
the silicon vendor (AMD or Intel) AND the cloud vendor (Microsoft via
MAA). A failure of either anchor's PKI does not compromise the other.

---

## See also

- `docs/deployment/azure.md` — full Azure deployment guide
- `core/docs/operator/runbooks/azure-day2.md` — day-2 ops
- `core/docs/diagrams/architecture-overview.svg` — TEE-agnostic component diagram
- `core/docs/diagrams/aws-deployment-architecture.md` — AWS comparison
- `deploy/terraform/azure-sev-snp/README.md` — SEV-SNP module reference
- `deploy/terraform/azure-sgx/README.md` — SGX module reference
