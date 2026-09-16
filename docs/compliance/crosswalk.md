# Compliance crosswalk — Vault Genome controls × regulatory frameworks

| Last updated | 2026-05-04 |
|--------------|------------|
| Authoritative source | This file (PR-reviewed before changes) |
| Pair docs    | [ADRs](../adr/README.md) · [Trade secrets inventory](../../business/16_trade_secrets_inventory_v2.md) |

This crosswalk maps Vault Genome's technical controls to the framework
controls enterprise customers cite during procurement. It does NOT
constitute a certification claim — see [`README.md`](README.md) for
the distinction between technical readiness and audit certification.

Status legend:
- ✅ Implemented (code + tests + ADR)
- 🟡 Partially implemented (code in place, tests or docs incomplete)
- ⏳ Planned for a specific phase (links to the milestone)
- ❌ Out of scope / responsibility of the deployer

## Table of contents

- [Vault Genome control catalogue](#vault-genome-control-catalogue)
- [SOC 2 Trust Services Criteria (TSC 2017)](#soc-2-trust-services-criteria-tsc-2017)
- [ISO/IEC 27001:2022 Annex A](#isoiec-270012022-annex-a)
- [HIPAA Security Rule (45 CFR 164.302–164.318)](#hipaa-security-rule-45-cfr-164302164318)
- [PCI DSS 4.0](#pci-dss-40)
- [FedRAMP Moderate (NIST SP 800-53 Rev 5)](#fedramp-moderate-nist-sp-800-53-rev-5)
- [EU NIS2 Directive (2022/2555)](#eu-nis2-directive-20222555)
- [GDPR (Articles 5, 25, 32)](#gdpr-articles-5-25-32)

---

## Vault Genome control catalogue

These are the *Vault Genome controls* the rest of the document references.
Each has a stable identifier (`VG-NNN`), a code-level home, and a test
or ADR that proves it is in force.

| ID      | Control                                              | Code home                              | Verified by |
|---------|------------------------------------------------------|----------------------------------------|-------------|
| VG-001  | TEE-backed processing of model material              | `internal/shared/tee/`                 | [ADR-0001](../adr/0001-frozen-producer-verifier-sealer-interface.md), `contract_test.go` |
| VG-002  | Hardware-rooted attestation per session              | `internal/shared/tee/{aws_nitro,azure_sgx,gcp_sev_snp,intel_sgx_dcap}.go` | `integration_test.go` (20 sub-tests) |
| VG-003  | AAD-bound symmetric sealing (AES-256-GCM)            | `internal/shared/crypto/gcm.go`        | `gcm_test.go`, contract sealer suite |
| VG-004  | Append-only tamper-evident audit log                 | `internal/audit/store/` (bbolt-backed) | `audit/store/*_test.go` |
| VG-005  | No raw genome export (doctrine invariant 7)          | enforced AST-wide                       | `test/doctrine/invariants_test.go::TestInvariant_07_NoRawExport` |
| VG-006  | Frozen V1 ↔ V2 interface boundary                    | `internal/shared/tee/tee.go`           | `frozen_test.go`, [ADR-0001](../adr/0001-frozen-producer-verifier-sealer-interface.md) |
| VG-007  | Operator-side recovery via `acpctl recover`          | `cmd/acpctl/recover.go`                | `cmd/acpctl/recover_test.go` (12 cases) |
| VG-008  | Replay protection via 16-byte nonce floor (R-10)     | `internal/shared/tee/tee.go::NonceMinBytes` | contract sub-test `NonceMinBytes_*` |
| VG-009  | Validation pipeline gates every release              | `internal/validation/`                 | `test/doctrine/invariants_test.go::TestInvariant_05_NoSessionShortCircuit` |
| VG-010  | Return-path verifier on every receive                | `internal/recvvalidator/`              | `test/doctrine/invariants_test.go::TestInvariant_06_NoBypassOfReturnValidator` |
| VG-011  | Reproducible builds with SBOM + cosign signatures    | `.github/workflows/release.yml`        | ✅ v0.1.0: SPDX SBOM, cosign keyless signatures, SLSA provenance, `make verify-reproducible` |
| VG-012  | Capability gating: refuses to start on wrong host    | `internal/shared/tee/factory.go::Capability` | `factory_test.go` |
| VG-013  | Doctrinal invariants tested on every CI run          | `test/doctrine/invariants_test.go`     | [ADR-0004](../adr/0004-doctrine-invariants-as-tests.md) |
| VG-014  | Distroless container base, hardened systemd units    | `deploy/docker/Dockerfile`, `deploy/packaging/systemd/` | manual review |
| VG-015  | Network policies + egress restrictions in K8s        | `deploy/helm/templates/networkpolicy.yaml` | manual review |
| VG-016  | 7-year audit log retention via cloud KMS / S3 / GCS  | `deploy/terraform/{aws,azure,gcp}/`    | manual review |
| VG-017  | Defence-in-depth: HSM wrap on top of SGX sealing     | `internal/shared/tee/intel_sgx_dcap.go` | integration test `SealingWithHSMWrap` |
| VG-018  | Tamper-evident bootstrap manifest                    | `internal/contracts/bootstrap_manifest/` | unit tests |
| VG-019  | Multi-stage validation (operational + semantic + behavioural) | `internal/validation/{operational,semantic,behavioral}/` | per-package tests |
| VG-020  | Continuous-integration security gates (CodeQL, SBOM) | `.github/workflows/`                   | ✅ vault-gate (18 checks incl. govulncheck, osv-scanner, gitleaks, SBOM), CodeQL, Semgrep |

---

## SOC 2 Trust Services Criteria (TSC 2017)

SOC 2 organises controls into five Trust Services Criteria categories
(Common, Availability, Confidentiality, Processing Integrity, Privacy)
plus the Common Criteria (CC) sub-categories. The crosswalk below
covers the controls Vault Genome's architecture demonstrably addresses.

### CC6 — Logical & physical access controls

| TSC ID  | Description                                          | VG control(s) | Status |
|---------|------------------------------------------------------|---------------|--------|
| CC6.1   | Logical access security software, infrastructure, and architectures protect information and system resources | VG-001, VG-002, VG-014, VG-015 | ✅ |
| CC6.6   | The entity implements logical access controls — encryption of data at rest | VG-003, VG-017 | ✅ |
| CC6.7   | Restricted transmission, movement, and removal of information | VG-005, VG-007 | ✅ |
| CC6.8   | Prevention or detection of unauthorised software and hardware | VG-002 (attestation), VG-018 (bootstrap manifest), VG-011 (cosign) | ✅ |

### CC7 — System operations

| TSC ID  | Description                                          | VG control(s) | Status |
|---------|------------------------------------------------------|---------------|--------|
| CC7.1   | Detection of vulnerabilities and security events     | VG-004, VG-013, VG-020 | 🟡 (CodeQL, Semgrep, govulncheck in CI; no external pen-test) |
| CC7.2   | Monitoring, logging, and alerting on anomalies       | VG-004, Prometheus metrics on every daemon (`/metrics`); no alerting stack shipped | 🟡 |
| CC7.3   | Evaluation of security incidents                     | `internal/vault/incident/` | ✅ |
| CC7.4   | Incident response                                    | `business/19_dmca_takedown_template.md`, ⏳ DR runbook | 🟡 |

### CC8 — Change management

| TSC ID  | Description                                          | VG control(s) | Status |
|---------|------------------------------------------------------|---------------|--------|
| CC8.1   | Authorisation and approval of changes                | Doctrinal invariants + ADRs (VG-006, VG-013) | ✅ |

### A1 — Availability

| TSC ID  | Description                                          | VG control(s) | Status |
|---------|------------------------------------------------------|---------------|--------|
| A1.1    | Capacity planning                                    | ⏳ not done (no load tests; hardware runs are functional, not capacity) | ⏳ |
| A1.2    | Recovery procedures (backup, DR)                     | VG-007 (recover CLI), ⏳ DR runbook | 🟡 |

### C1 — Confidentiality

| TSC ID  | Description                                          | VG control(s) | Status |
|---------|------------------------------------------------------|---------------|--------|
| C1.1    | Identification and protection of confidential information | VG-001, VG-003, VG-005, VG-006 | ✅ |
| C1.2    | Disposal of confidential information                 | TEE-bound sealing means key destruction = data destruction | ✅ |

### PI1 — Processing Integrity

| TSC ID  | Description                                          | VG control(s) | Status |
|---------|------------------------------------------------------|---------------|--------|
| PI1.1   | Definitions of data quality standards                | VG-009, VG-019 (validation pipeline) | ✅ |
| PI1.4   | Processing accuracy and completeness                 | VG-019, VG-010 (return-path validator) | ✅ |
| PI1.5   | Storage integrity                                    | VG-004 (tamper-evident audit log) | ✅ |

---

## ISO/IEC 27001:2022 Annex A

Annex A of ISO 27001:2022 has 93 controls in four themes (Organisational,
People, Physical, Technological). Below are the *technological* controls
Vault Genome's codebase addresses; *organisational* and *people* controls
(security awareness training, classification policy, supplier due
diligence) are out of scope for the codebase but addressed in
`business/27_security_program.md` (private repo).

| Annex A | Description                                          | VG control(s) | Status |
|---------|------------------------------------------------------|---------------|--------|
| A.5.10  | Acceptable use of information                        | VG-005 (no raw export) | ✅ |
| A.5.15  | Access control                                       | VG-001 (TEE-bound), VG-002 (per-session attestation) | ✅ |
| A.5.17  | Authentication information                           | VG-002 (challenger nonces) | ✅ |
| A.5.23  | Information security for use of cloud services       | VG-001 across 5 TEE backends | ✅ |
| A.5.34  | Privacy and protection of PII                        | VG-001, VG-003, VG-005 | ✅ |
| A.8.2   | Privileged access rights                             | TEE-bound: no operator can extract genome material | ✅ |
| A.8.5   | Secure authentication                                | VG-002 + VG-008 (R-10 nonce floor) | ✅ |
| A.8.7   | Protection against malware                           | Distroless image VG-014, attestation on every restart | ✅ |
| A.8.10  | Information deletion                                 | TEE sealing: key revocation = data deletion | ✅ |
| A.8.11  | Data masking                                         | n/a — we don't mask, we seal | ❌ (different paradigm) |
| A.8.12  | Data leakage prevention                              | VG-005 enforced by `TestInvariant_07_NoRawExport` | ✅ |
| A.8.16  | Monitoring activities                                | VG-004 + ⏳ Prometheus/OpenTelemetry | 🟡 |
| A.8.20  | Networks security                                    | VG-015 (NetworkPolicy), VG-014 (distroless) | ✅ |
| A.8.21  | Security of network services                         | VG-002 (attestation gates traffic), VG-015 | ✅ |
| A.8.24  | Use of cryptography                                  | VG-003, VG-017, [ADR-0001](../adr/0001-frozen-producer-verifier-sealer-interface.md) | ✅ |
| A.8.25  | Secure development life cycle                        | [ADR-0004](../adr/0004-doctrine-invariants-as-tests.md), [ADR-0005](../adr/0005-mock-based-integration-testing.md) | ✅ |
| A.8.27  | Secure system architecture                           | All ADRs | ✅ |
| A.8.28  | Secure coding                                        | VG-013 (invariants), VG-020 (CodeQL, Semgrep in CI) | 🟡 |
| A.8.31  | Separation of development, test, production         | TEE measurements differ per build | ✅ |
| A.8.32  | Change management                                    | [ADR-0004](../adr/0004-doctrine-invariants-as-tests.md), CC8.1 above | ✅ |

---

## HIPAA Security Rule (45 CFR 164.302–164.318)

HIPAA applies when a covered entity uses Vault Genome to process
Protected Health Information (PHI). The Security Rule has
Administrative, Physical, and Technical safeguards. Below are the
*Technical Safeguards* (45 CFR 164.312) — the ones our codebase
directly enables. Administrative + Physical safeguards are the
*deployer's* responsibility (covered in the Business Associate
Agreement).

| HIPAA cite       | Title                                       | VG control(s) | Status |
|------------------|---------------------------------------------|---------------|--------|
| 164.312(a)(1)    | Access control — unique user identification | TEE-bound: each session has a fresh attestation | ✅ |
| 164.312(a)(2)(i) | Emergency access procedure                  | VG-007 (acpctl recover)                       | ✅ |
| 164.312(a)(2)(iv)| Encryption and decryption                   | VG-003 (AES-256-GCM), VG-017 (HSM wrap)       | ✅ |
| 164.312(b)       | Audit controls                              | VG-004 (append-only)                          | ✅ |
| 164.312(c)(1)    | Integrity                                   | VG-002, VG-005, VG-019                        | ✅ |
| 164.312(c)(2)    | Mechanism to authenticate ePHI              | VG-002, VG-008                                | ✅ |
| 164.312(d)       | Person or entity authentication             | VG-002 attestation                            | ✅ |
| 164.312(e)(1)    | Transmission security                       | VG-001 (TEE-bound) + TLS at deployment        | ✅ |
| 164.312(e)(2)(i) | Integrity controls (transmission)           | VG-002 + AAD on every sealed transmission     | ✅ |
| 164.312(e)(2)(ii)| Encryption (transmission)                   | VG-003 + TLS                                  | ✅ |

A signed Business Associate Agreement (BAA) template lives in
`business/28_baa_template.md` (private repo). Customers must execute
the BAA before any PHI flows through Vault Genome.

---

## PCI DSS 4.0

PCI DSS applies when Vault Genome is used in a Cardholder Data
Environment (CDE). Most banking customers will deploy Vault Genome
*adjacent to* their CDE — Vault Genome handles model continuity,
not card data. Where the deployment touches the CDE, the relevant
4.0 requirements:

| PCI DSS 4.0 | Requirement                                        | VG control(s) | Status |
|-------------|----------------------------------------------------|---------------|--------|
| 1           | Network security controls                          | VG-014, VG-015 | ✅ |
| 2.2         | Configuration standards (system components)        | Distroless image, hardened systemd | ✅ |
| 3.5         | Render PAN unreadable                              | n/a (we don't process PAN) | ❌ |
| 3.6         | Protect cryptographic keys                         | VG-001 (TEE-rooted), VG-017 (HSM) | ✅ |
| 4.1         | Strong cryptography for transmission               | VG-003, VG-002, TLS | ✅ |
| 6.2         | Secure development                                 | [ADR-0004](../adr/0004-doctrine-invariants-as-tests.md), [ADR-0005](../adr/0005-mock-based-integration-testing.md) | ✅ |
| 6.3         | Identify security vulnerabilities                  | ⏳ CodeQL, ⏳ Trivy / Grype on container | ⏳ |
| 6.5         | Address common coding vulnerabilities              | VG-013, CodeQL, Semgrep; no fuzzing | 🟡 |
| 8.3         | Multi-factor authentication                        | n/a (VG is not the user-auth surface; deferred to deployer) | ❌ |
| 10          | Logging and monitoring                             | VG-004, ⏳ Prometheus + Grafana | 🟡 |
| 11.4        | Penetration testing                                | ⏳ none yet (KNOWN_ISSUES: no external review) | ⏳ |

---

## FedRAMP Moderate (NIST SP 800-53 Rev 5)

FedRAMP Moderate requires ~325 control implementations from
NIST SP 800-53 Rev 5. Below are the families where Vault Genome's
architecture is directly load-bearing. A full FedRAMP package would
include the SSP (System Security Plan), per-control implementation
narratives, and ConMon evidence — far beyond the codebase. Listed
here are the AC, AU, IA, SC, SI families' high-impact controls our
codebase addresses.

| 800-53 ID | Title                                            | VG control(s) | Status |
|-----------|--------------------------------------------------|---------------|--------|
| AC-2      | Account Management                               | TEE-rooted, attestation-gated | ✅ |
| AC-3      | Access Enforcement                               | VG-001, VG-002 | ✅ |
| AC-4      | Information Flow Enforcement                     | VG-005, VG-009 | ✅ |
| AC-6      | Least Privilege                                  | TEE confines code; no operator bypass | ✅ |
| AU-2      | Event Logging                                    | VG-004 | ✅ |
| AU-3      | Content of Audit Records                         | `internal/contracts/audit_event/` | ✅ |
| AU-9      | Protection of Audit Information                  | VG-004 (append-only, tamper-evident) | ✅ |
| AU-11     | Audit Record Retention                           | VG-016 (7-year retention via Terraform) | ✅ |
| CM-7      | Least Functionality                              | Distroless, single-purpose binary | ✅ |
| CP-9      | System Backup                                    | VG-007 (recover CLI), ⏳ DR runbook | 🟡 |
| IA-2      | User Identification & Authentication             | Per-session attestation | ✅ |
| IA-5      | Authenticator Management                         | VG-008, VG-002 | ✅ |
| IR-4      | Incident Handling                                | `internal/vault/incident/` | ✅ |
| RA-5      | Vulnerability Scanning                           | 🟡 CodeQL, govulncheck, osv-scanner in CI; no container-image scan | 🟡 |
| SC-8      | Transmission Confidentiality & Integrity         | VG-003 + TLS | ✅ |
| SC-12     | Cryptographic Key Establishment & Management     | VG-001 (TEE-rooted), [ADR-0001](../adr/0001-frozen-producer-verifier-sealer-interface.md) | ✅ |
| SC-13     | Cryptographic Protection                         | VG-003 (AES-GCM), VG-008 (Ed25519/ECDSA via TEE) | ✅ |
| SC-28     | Protection of Information at Rest                | VG-003 sealing | ✅ |
| SI-7      | Software, Firmware, Information Integrity        | VG-002 (attestation), VG-018 (bootstrap manifest) | ✅ |
| SI-10     | Information Input Validation                     | VG-019, contract validation | ✅ |
| SI-11     | Error Handling                                   | shared_errors classification (Structural/Integrity) | ✅ |

---

## EU NIS2 Directive (2022/2555)

NIS2 applies to "essential" and "important" entities — banks, healthcare
providers, cloud computing services, etc. The directive is principle-based;
member-state implementations vary. Article 21 ("cybersecurity
risk-management measures") names ten categories that align cleanly
with Vault Genome's architecture:

| NIS2 21(2)  | Category                                          | VG control(s) | Status |
|-------------|---------------------------------------------------|---------------|--------|
| (a)         | Risk analysis & information system security policies | All ADRs    | ✅ |
| (b)         | Incident handling                                 | `internal/vault/incident/` | ✅ |
| (c)         | Business continuity / crisis management           | VG-007, ⏳ DR runbook | 🟡 |
| (d)         | Supply chain security                             | VG-011 (SBOM, cosign, SLSA in v0.1.0), ADR-0003 (license boundary) | ✅ |
| (e)         | Security in network & info systems acquisition / development | All ADRs, [ADR-0004](../adr/0004-doctrine-invariants-as-tests.md) | ✅ |
| (f)         | Effectiveness assessment                          | VG-013 (invariants on every CI), [ADR-0005](../adr/0005-mock-based-integration-testing.md) | ✅ |
| (g)         | Cyber hygiene & training                          | n/a (organisational)                          | ❌ |
| (h)         | Cryptography & encryption                         | VG-003, VG-017                                | ✅ |
| (i)         | Human resources / access control                  | TEE-bound + organisational                    | 🟡 |
| (j)         | Multi-factor / continuous authentication          | n/a (deployer's responsibility)               | ❌ |

---

## GDPR (Articles 5, 25, 32)

GDPR's technical articles directly applicable to Vault Genome:

### Article 5 — Principles relating to processing of personal data

| GDPR 5(1)   | Principle                                         | VG control(s) | Status |
|-------------|---------------------------------------------------|---------------|--------|
| (a)         | Lawfulness, fairness, transparency                | n/a (data-controller's responsibility)         | ❌ |
| (b)         | Purpose limitation                                | TEE measurement binds processing to authorised code | ✅ |
| (c)         | Data minimisation                                 | Only material the authorised model needs flows through TEE | ✅ |
| (d)         | Accuracy                                          | VG-019 (validation), VG-010 (return-path)      | ✅ |
| (e)         | Storage limitation                                | VG-016 + sealed material expires with TEE measurement rotation | ✅ |
| (f)         | Integrity & confidentiality (security)            | VG-001, VG-003, VG-005                         | ✅ |
| (2)         | Accountability                                    | VG-004 (audit log), VG-013 (invariants)         | ✅ |

### Article 25 — Data protection by design and by default

| GDPR 25 | Requirement                                          | VG control(s) | Status |
|---------|------------------------------------------------------|---------------|--------|
| (1)     | Implement technical & organisational measures        | All ADRs                                       | ✅ |
| (2)     | By default only personal data necessary processed    | TEE-bound: only authorised models access material | ✅ |

### Article 32 — Security of processing

| GDPR 32 | Requirement                                          | VG control(s) | Status |
|---------|------------------------------------------------------|---------------|--------|
| (1)(a)  | Pseudonymisation and encryption                      | VG-003, VG-017                                 | ✅ |
| (1)(b)  | Confidentiality, integrity, availability, resilience | VG-001, VG-002, VG-003, VG-007                | ✅ |
| (1)(c)  | Restore availability and access                      | VG-007                                         | ✅ |
| (1)(d)  | Regular testing and evaluation                       | VG-013 (invariants), [ADR-0005](../adr/0005-mock-based-integration-testing.md) | ✅ |

---

## Roadmap to certified state

| Framework       | What the codebase covers today | Gap to certified | Realistic timeline |
|-----------------|--------------------------------|--------------------|---------------------|
| SOC 2 Type II   | ~85% of CC controls            | 6-month observation period + auditor engagement (~$30k) | 2027-Q3 if budget secured 2026-Q3 |
| ISO 27001       | ~80% of Annex A technological controls | ISMS scope statement + risk register + Stage 1+2 audit (~$50k) | 2027-Q4 |
| HIPAA           | All Technical Safeguards       | BAA negotiation per customer + Administrative Safeguards as company controls | Ready as soon as a covered entity signs |
| PCI DSS         | Crypto + access controls       | Customer's CDE remediation + ROC engagement | Customer-driven |
| FedRAMP Mod.    | Architectural controls present | Full SSP + 3PAO assessment (~$300k–1M) | 2028+ if a USG customer commits |
| NIS2 / DORA     | All Article 21 technical categories | EU entity status + member-state filing | When EU customer requires it |
| GDPR            | All Article 25 + 32 technicals | Data protection officer + Article 30 records | Ready as soon as deployed in EU |

The "Realistic timeline" column assumes a $200k Q3-2026 seed round
that funds compliance work (~$80k of audit fees + ~$120k of internal
process work). Earlier audits are possible with smaller scope (e.g.,
SOC 2 Type I before Type II) at proportional cost.
