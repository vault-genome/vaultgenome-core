# Reference design 02 — Healthcare AI, clinical-decision support

| Profile        | Specialist clinical-AI vendor, US + EU markets                   |
|----------------|-------------------------------------------------------------------|
| Customers      | ~80 hospital-network customers, ~6M PHI records flowing per quarter |
| Constraints    | HIPAA Privacy + Security Rule, SOC 2 Type II under audit, EU GDPR |
| Primary TEE    | AWS Nitro Enclaves (multi-region active-active in us-east-1 + eu-west-1) |
| AGPL fit       | 🟡 — vendor's customer-facing front end is closed source; AGPL §13 obligations would force disclosure |
| Commercial license | ✅ — $120k/yr scale-up tier                                  |

## Problem statement

The vendor sells a clinical-decision support model that ingests
patient lab values + imaging metadata and produces a triage
recommendation for the care team. Customers (hospital networks) sign
a Business Associate Agreement (BAA) with the vendor; under the BAA,
the vendor is liable for any unauthorised PHI disclosure.

Three painful realities the vendor has to solve:

1. **Hospital admins don't trust opaque cloud AI** — they need a
   technical answer to "can the vendor's engineers see our patients'
   data?". Today the answer is "no, but you have to take our word for
   it." A TEE-rooted attestation is what they need.
2. **Models are updated quarterly** — every update requires a fresh
   audit trail acceptable to HHS-OCR, including who released the
   update, what regression suite passed, and rollback evidence.
3. **GDPR Article 22** — patients have a right to "meaningful
   information about the logic involved" for automated decisions
   affecting them. The vendor needs a queryable lineage from any
   recommendation back to the model + training data version.

## Architecture

### Topology

```
                 ┌──────────────────────────────────────────────┐
                 │  Hospital network (operator)                  │
                 │   ├── EHR integration (FHIR)                  │
                 │   ├── HL7 bridge                              │
                 │   └── REST POST /v1/jobs (TLS + bearer)        │
                 └──────────────────────────────────────────────┘
                              │   PHI never crosses this line
                              │   except sealed under TEE-bound key
                              ▼
                 ┌──────────────────────────────────────────────┐
                 │  Vendor's AWS account                         │
                 │                                                │
                 │  ┌──────────────────────────────────────────┐ │
                 │  │ ALB (TLS 1.3 termination)                 │ │
                 │  └──────────────────────────────────────────┘ │
                 │                  │                             │
                 │                  ▼                             │
                 │  ┌──────────────────────────────────────────┐ │
                 │  │ sagvd (Nitro Enclave, EC2 m5.metal)       │ │
                 │  │   ├── /dev/nsm                            │ │
                 │  │   ├── KMS key (PCR0-bound)                │ │
                 │  │   └── audit → S3 (Object Lock, 7yr)        │ │
                 │  └──────────────────────────────────────────┘ │
                 │                  │                             │
                 │                  ▼                             │
                 │  ┌──────────────────────────────────────────┐ │
                 │  │ acp-compute pool (24 Nitro nodes)          │ │
                 │  │   ├── inference enclave                    │ │
                 │  │   └── 4-frame return-path to sagvd          │ │
                 │  └──────────────────────────────────────────┘ │
                 └──────────────────────────────────────────────┘
                              │  cross-region active replica in
                              │  eu-west-1 (Frankfurt) for GDPR
                              │  data-residency
                              ▼
                 ┌──────────────────────────────────────────────┐
                 │  AWS eu-west-1 — same architecture            │
                 └──────────────────────────────────────────────┘
```

### Components

- **TEE backend**: `aws-nitro` exclusively. The vendor's threat model
  trusts AWS Nitro hypervisor + AWS PCA root; multi-cloud is over-
  engineering for their scale.
- **Data residency**: EU customers' PHI flows to eu-west-1 via the
  ALB's geo-routing rule; never crosses the Atlantic. The EU sagvd
  has its own KMS key + sealed material; the US deployment cannot
  unseal EU-bound material because PCR0 is the same but the KMS
  policy is region-scoped.
- **HIPAA-grade audit retention**: S3 Object Lock in compliance mode,
  7-year retention, replicated to a separate AWS account owned by
  the vendor's GRC team — defence against a vendor SRE accidentally
  deleting the bucket.
- **Patient-decision lineage**: every release decision references
  the model's content-addressed manifest (Vault Genome
  `genome_descriptor`) so a GDPR Article 22 query resolves to a
  specific model version + training cutoff in the audit log.

### Per-recommendation flow

1. Hospital EHR sends FHIR-encoded request to the ALB.
2. ALB terminates TLS, forwards to sagvd's HTTP API.
3. sagvd authenticates the customer's bearer token, validates the
   request payload, and submits a job to the queue.
4. acp-compute worker (in Nitro enclave) runs the inference model.
5. Worker produces a candidate output signed by its TEE-bound key.
6. sagvd validates → verdict → release decision.
7. Released recommendation flows to the hospital's response endpoint;
   sealed material is stored in S3 with PCR0-conditional KMS access.

Per-recommendation latency budget (target: 600 ms end-to-end):

| Stage                 | Budget | Notes |
|-----------------------|--------|-------|
| EHR → ALB             | 50 ms  | hospital VPN |
| ALB → sagvd           | 5 ms   | same-AZ |
| sagvd auth + queue    | 10 ms  | bearer token verification |
| Worker pickup         | 25 ms  | bounded by 4-frame handshake |
| Inference in enclave  | 400 ms | model-dependent |
| Validation pipeline   | 60 ms  | semantic + behavioural |
| Release + return      | 50 ms  | including audit append |

## Threat model

Adapted to the healthcare context:

| Threat | Mitigation |
|--------|------------|
| Hospital IT thinks the vendor's engineers can see PHI | Nitro attestation document published per session; hospital can verify PCR0 matches the reproducible build the vendor publishes. See [`docs/security/supply_chain.md`](../security/supply_chain.md). |
| Vendor engineer with EC2 console access reads enclave memory | Impossible by Nitro design (parent EC2 has no path into enclave RAM). |
| Vendor inadvertently logs PHI to CloudWatch | Doctrine invariant `TestInvariant_07_NoRawExport` blocks any os.WriteFile / log.Println / fmt.Println of plaintext outside the disclosure path. |
| HHS-OCR audit asks "what model was running at 09:42:13 EST on 2026-04-15?" | `acpctl audit query --at <timestamp>` returns the genome descriptor + signed release decision for that session. |
| GDPR Article 22 query | Same audit chain; lineage from recommendation → model → training-data manifest is one query. |
| AWS PCA root rotation | Documented in DR runbook scenario 3; vendor's standard rotation playbook + customer notification. |

## Operational concerns

- **24×7 SRE rotation**: vendor's existing 5-person team. Vault Genome
  page surface is the same as in design 01 (sagvd-down,
  audit-chain-broken, hsm-unreachable). HSM is replaced by AWS KMS
  here, so "kms-unreachable" replaces "hsm-unreachable".
- **BAA template**: vendor's existing BAA + addendum specifying
  Vault Genome as a BAA-bound subprocessor. Vendor counsel reviews
  per customer.
- **Compliance crosswalk**: see HIPAA Security Rule section in
  [`docs/compliance/crosswalk.md`](../compliance/crosswalk.md);
  Article 25 + 32 of GDPR explicitly covered.

## Pricing posture

Commercial license, $120k/yr scale-up tier:

- AGPL §13 source disclosure waived for vendor's closed-source
  customer-facing portal.
- Business-hours support, 1-business-day response SLO for P1.
- Annual security review with vendor's GRC team.

The 7-year audit retention infrastructure (S3 Object Lock + replica)
is the vendor's responsibility; Vault Genome ships the Terraform
modules but the buyer pays AWS directly for storage.
