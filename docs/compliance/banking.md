# Banking — what the software contributes to a bank's obligations, requirement by requirement

| Last updated | 2026-10-17, on v0.6.0 and the acceptance trial of October 2026 |
| - | - |
| Controls referred to | [`controls.md`](controls.md) (VG-nnn) |
| Sources read for this map | the texts named in each section, held in the maintainers' library as the published PDF or page with its SHA-256; the article and paragraph numbers below are those texts' |
| Status | the first of the sector maps; government, business and military follow, one at a time |

**Who this is for.** A bank's ICT risk, model risk or operational
resilience function asked to approve a deployment of this software for
the continuity of its fine-tuned models, and the auditor or examiner
who reads their file afterwards. Every row answers one question: *for
this requirement, what does the software do, where is the proof, and
what remains the bank's?*

**How to read the three columns.** *Software* names the control in
`controls.md` and, where it matters, the exact behaviour. *Proof* is a
claim with its evidence or a row of the acceptance trial. *The bank's*
is what the requirement asks of the institution that no software
supplies: a policy, a classification, a decision, a test schedule, a
contract clause. Where the software contributes nothing to a
requirement, the row says "—" rather than stretching.

**What this is not.** It is not a statement of conformity. The
regulations in this map are addressed to financial entities, not to
software; the bank meets them with its framework, of which a deployment
of this software is one component. No audit, assessment or attestation
of the maintainers' organisation has been commissioned.

## 1. Regulation (EU) 2022/2554 — DORA

The articles below are the ones a bank's ICT risk management framework
will cite when it assesses a system that keeps model continuity. DORA
is *lex specialis* to the NIS2 Directive for the financial entities it
covers (Art. 1(2); NIS2 Art. 4), so a bank's NIS2 questions are
answered through DORA — see §7.

| Requirement | Software | Proof | The bank's |
| - | - | - | - |
| **Art. 9(2)** — ICT security tools that keep the availability, authenticity, integrity and confidentiality of data at rest, in use and in transit | at rest: VG-003 (sealed genomes, sealed key files VG-023); in use: VG-001 (the model is restored inside an attested confidential VM); in transit: VG-014 (mutual TLS 1.3), VG-002 (the peer attested in the handshake) | C2, C3, C12, C36; T1–T4 | the classification that decides which models go through it |
| **Art. 9(3)(a)–(c)** — secure means of transfer; minimised risk of corruption, loss, unauthorised access; prevention of loss of authenticity and integrity | VG-002, VG-010, VG-029 (the restored model is checked against sealed fixtures and the verdict signed) | C4, C19; T20 | — |
| **Art. 9(4)(c)** — logical access limited to legitimate functions, access rights administered | VG-014 (client certificates required and verified), VG-026 (pins: only the named peer), VG-025 (a key moves only to an allow-listed destination) | T1 (the unpinned worker refused), C22 | the issuance and revocation of operator identities; the review of access rights |
| **Art. 9(4)(d)** — strong authentication mechanisms and protection of cryptographic keys | VG-002 (hardware-rooted attestation on every session), VG-023 and VG-024 (keys sealed to the host's chip or vTPM; a copy does not open elsewhere), VG-039 (the chip's firmware held to AMD's published floors; what the chip said on the record) | C24, C25, C46; the "thief" step of T1–T5, T7 | the key-management policy (RTS Art. 7, §2 below) |
| **Art. 9(4)(e)** — ICT change management with changes recorded, tested, approved, verified | VG-011 (every release reproducible, signed, attested; a deployment verified from the assets alone), VG-020 (the gate), the compatibility ledger in `docs/operator/08_upgrading.md` | C9, C27; T9 | the bank's own change process around a deployment |
| **Art. 10(1)–(2)** — detection of anomalous activities, alert thresholds, automatic alerts to incident response | VG-035 (attestation failure, validation hard-fail, audit-append failure detected and terminated on the record), VG-034 (metrics for alerting), VG-030 (the sentinel's silence detection: a primary that goes dark triggers the failover) | C35 (detect 15.01 s); `03_incident_response.md` | the thresholds and the alerting stack; the staff who receive the alert |
| **Art. 11(2)(a), (c)** — continuity of critical functions; plans that activate containment and recovery suited to each incident | VG-030 (policy-driven failover of the model to an attested standby, with RTO and RPO on each record), VG-025 (the policy decides, the operator can stop) | C8, C14, C18, C21, C28, C35; T11–T17; C41 (the design played end to end, the figures from the run) | the business continuity policy that names the model's function as critical or not; the RTO/RPO targets |
| **Art. 11(6)** — plans tested at least yearly, including cyber-attack scenarios and switchovers between the primary infrastructure and the redundant capacity | the drill kits are runnable by the bank's own staff on its own accounts; the acceptance trial is the maintainers' run of all of them on the released code | `TRIAL-2026-10.md` | the schedule, the independence of the tester (Art. 24(4)), the review of results |
| **Art. 11(8)** — readily accessible records of activities before and during a disruption | VG-004 (every decision on the record before it takes effect), VG-021 (the record kept in closed segments the daemon never deletes), `acpctl audit query --request` | C12, C38; T22 | — |
| **Art. 12(1)–(2)** — backup and restoration procedures; testing of restoration | the genome *is* the restorable form of a fine-tuned model: sealed, escrowed, restored on another attested host and checked EXACT (VG-029, VG-024, VG-030) | C1–C5, C11; T1–T4, T20 | the backup policy that states scope and frequency; the test schedule |
| **Art. 12(3)** — restoration on systems physically and logically segregated from the source | the standby is another VM, another region or another cloud, attested before it receives a key (VG-030) | C18 (GCP → Azure), C21 (SEV-SNP → TDX), C35 (region loss), C41 (a second region; the key released only after the standby's chip attested) | the choice of where the standby stands |
| **Art. 12(4)** — redundant ICT capacities | VG-030; the standby can be any attested family (VG-001) | C18, C21 | sizing and funding the standby |
| **Art. 17(2)–(3)(b), (f)** — incidents recorded; identified, tracked, logged, classified; response procedures | VG-035, VG-004 (`INCIDENT_DETECTED`, `INCIDENT_TERMINATED` are events of the chain) | the incident module's tests | the incident management process, classification (Art. 18 and RTS 2024/1772), reporting (Art. 19) |
| **Art. 24(1), (5)–(6); Art. 25(1)** — a testing programme; issues remedied; yearly tests of systems supporting critical functions; end-to-end and scenario-based tests | the kits under `scripts/hardware-test/` are end-to-end tests on production-class hardware, scenario-based (attack, silence, region loss, host loss); their evidence is in git | `TRIAL-2026-10.md` (22 trials); `VERIFIABLE-CLAIMS.md` | including the deployment in the programme; source-code review "where feasible" is open to the bank — the code is public |
| **Art. 26(2)–(3)** — TLPT on live production systems, with ICT third-party providers participating | — (the maintainers are not an operator; a bank that includes a deployment in its TLPT scope tests its own instance) | — | the scope and the contract clause (Art. 30(3)(d)) |
| **Art. 28(1)(a)** — the bank remains fully responsible | — | — | everything |
| **Art. 30(2)(c)** — provisions on availability, authenticity, integrity and confidentiality of data | what the software does is in this map; the contract states the bank's expectations | — | the clause |
| **Art. 30(2)(d)** — access, recovery and return of data on insolvency or termination | the formats are public and the code is public (AGPL-3.0-or-later): genomes, audit segments and keys are the bank's files on the bank's hosts; `acpctl` reads all of them without the maintainers | ADR 0003, ADR 0027 | the exit plan |
| **Art. 30(3)(c)** — the provider's own contingency plans and security measures | this map and `docs/security/` describe the software's; the maintainers' organisation is not assessed | — | due diligence (Art. 28(4)(d)) |
| **Art. 30(3)(e)(i)** — unrestricted rights of access, inspection and audit | the code, the build and the evidence are public; a release is rebuilt byte for byte by the bank (VG-011) | C9, C27 | the clause |

## 2. Commission Delegated Regulation (EU) 2024/1774 — the RTS on the ICT risk management framework

The RTS details DORA's Articles 9–12 for most financial entities. The
articles that a deployment of this software touches:

| Requirement | Software | Proof | The bank's |
| - | - | - | - |
| **Art. 6(2)(a)–(c)** — encryption of data at rest and in transit, of data in use where necessary, of internal and external connections | at rest VG-003/VG-023; in transit VG-014; in use VG-001 — the model is restored inside a confidential VM whose memory is encrypted by the chip, which is the "separated and protected environment" the second subparagraph of 6(2) asks for where encryption in use is otherwise not possible | C2, C12, C15, C36 | the policy on encryption, from the data classification |
| **Art. 6(3)** — criteria for selecting cryptographic techniques, taking account of leading practices and standards | the primitives are the Go standard library's only (assurance case §3): Ed25519 signatures, X25519 key agreement, HKDF, AES-256-GCM, SHA-256 and SHA-512, ECDSA P-256/P-384 for the vendors' chains; the registry position of each is in §6 | `internal/shared/crypto/`, `handshake.go` | the criteria; the mitigation and monitoring where a technique is outside the bank's registry (6(3), second sentence) — see §6 on Ed25519 and X25519 |
| **Art. 6(4)–(5)** — crypto-agility: updating the technology on developments in cryptanalysis; recording the measures | no post-quantum scheme ships; the threat model lists quantum cryptanalysis of Ed25519, ECDSA and AES-256 as residual risk 6; the Commission Recommendation (EU) 2024/1101 on a coordinated post-quantum transition roadmap is in the library and not yet addressed in the tree | threat model, residual risk 6 | the record of the mitigation (6(5)) |
| **Art. 7(1)–(3)** — key lifecycle: generation, storage, backup, retirement, replacement on loss or compromise | generation from `crypto/rand`; storage sealed to the host (VG-023); the escrow key re-provisioned on a fresh authority host (VG-024, C28); the disaster-recovery runbook's scenarios 1–2 (a signing key or a sealing key compromised) | C24, C28; `runbooks/disaster_recovery.md` | the policy; the rotation schedule; the register |
| **Art. 7(4)–(5)** — a register of certificates and their prompt renewal | the TLS certificates of the daemons are the operator's files, named in each configuration; the kits issue short-lived ones | `docs/operator/09_first_deployment.md` | the register and the renewal |
| **Art. 10(2)(a), (g); 10(4)(a), (d)** — vulnerability management: trustworthy information resources on vulnerabilities; monitoring and verification of remediation; patch management: available hardware patches identified and evaluated, deadlines for their installation | VG-039: the SEV-SNP verifier holds the host chip's firmware and microcode to the floors AMD's security bulletins set for the chip's variant (read 2026-10-22, the day on `identity`), refuses a chip below them or without the alias check and the mitigation bit, and puts what the chip reported on every admission and release record — remediation on the TEE host verified at every handshake, not assumed | C46; `docs/compliance/sev-snp-tcb-floors.md` | the information resource (AMD's bulletins) read on the bank's own cadence and the table refreshed with it; the deadline and the escalation when a host falls below — `tcb_floor` and `accept_below_bulletin` are the recorded decision, not the procedure |
| **Art. 11(2)(b)** — a secure configuration baseline, verified regularly | `acpctl provision` writes both configurations from one command (VG-031); `01_preflight.md` is the verification list | C37, C39; T7, T8 | adopting it as the baseline |
| **Art. 11(2)(c)** — only authorised software installed | VG-011 (signed, attested releases verified before use), VG-002 (the peer's launch measurement is what is pinned — a different image is a different measurement and is refused) | C27; T1, T9 | — |
| **Art. 11(2)(i)** — prevention of data loss and leakage | VG-005 (no raw export, a test over the tree), VG-003 | the gate | — |
| **Art. 11(2)(k)** — requirements on ICT assets operated by a third party | not applicable in the deployment this map assumes: the bank operates the software on its own cloud accounts or hosts | — | the cloud provider's share (see §5, FFIEC VII.A.4) |
| **Art. 12(2)(a)** — which events are logged, the retention period, the measures to secure the logs | the twenty-five event kinds of the audit chain (VG-004); retention by closed segments the daemon never deletes (VG-021); the daemons' operational logs are separate from the chain | ADR 0027; C38 | the retention period and the archive's second location |
| **Art. 12(2)(c)(i), (iv)** — access-control and identity events; ICT operations | `TRUST_EVALUATED`, `SESSION_ISSUED`, `SESSION_INVALIDATED`, `KEY_RELEASE_*`, `REQUEST_RECEIVED`, `RELEASE_DECIDED` on the chain | every trial's `audit-events.jsonl` | — |
| **Art. 12(2)(d)** — logs protected against tampering, deletion and unauthorised access at rest and in transit | each event signed under the audit key, hash-chained to its predecessor; a closed segment's hash recorded in the next; verification by a third party with the public key alone (VG-004, VG-021) | C12, C38; `audit verify exit=0` in every trial | file permissions and the copy to a second medium |
| **Art. 12(2)(e)** — detection of a failure of logging systems | a decision is recorded before it takes effect, so a failed append stops the action rather than losing the event (ADR 0014); audit-append failure is an incident of the incident module (VG-035) | `03_incident_response.md` scenario 3 | — |
| **Art. 12(2)(f)** — clocks synchronised to a documented reliable reference | timestamps come from one clock per daemon (VG-037) | semgrep `vg-direct-time-now` | synchronising the host clock (NTP) — finding F3 |
| **Art. 13(e)** — encryption of network connections | VG-014 | — | the network design and segmentation (Art. 13(a)–(d)) |
| **Art. 14(1)(a)** — availability, authenticity, integrity and confidentiality of data in transmission | VG-014 and VG-002 together: the channel is TLS 1.3 and the peer behind it is attested | C12 | — |
| **Art. 16(1)(c), (3), (7)–(8)** — integrity of systems during development and deployment; source-code review with static and dynamic testing; integrity of third-party source; open-source analysed before production | VG-020 (CodeQL, Semgrep, govulncheck, osv-scanner, fuzzing, mutation testing in the gate), VG-011 (reproducible builds let the bank verify what it runs is the public source) | C9, C10 | the bank's own review of the source before production — it is public |
| **Art. 17(1)(a), (e)** — changes verified against security requirements; fall-back procedures | the compatibility ledger per release (`08_upgrading.md`); a signed previous release stays verifiable and deployable (VG-011) | T9 | the change procedure |
| **Art. 24(1)(b)(ii)(2)** — recovery within an RTO and an RPO | the drills record both. The claims: RTO 16.8–26.2 s and RPO 9–21 s on the attack, silence and cross-cloud scenarios, RTO 489 s cold on a fresh authority host. The acceptance trial of 2026-10-17 on the released code: RTO 15.1–25.8 s and RPO 9.0–24.0 s across the attack on SEV-SNP, the TDX standby, the TDX authority, the H100 standby and the region loss; 226.8 s cold on a fresh authority host | C8, C14, C18, C21, C28, C35; T11, T13–T17 | the targets, set from the BIA |
| **Art. 25(2)(a), (c); 25(5)** — tests on severe but plausible scenarios, including switchover to the redundant capacity; results documented and deficiencies reported | the drills (VG-030) and the trial; every failure in the trial is a row, not an edit | `TRIAL-2026-10.md` | the test programme and the report to the management body |
| **Art. 26(2)(a), (b), (d), (g)** — scenarios: cyber-attacks and switchovers; failure of a provider; substantial failure of ICT assets; insider attacks | attack on the primary (C8, C14), region loss (C35), the authority's host deleted (C28), an operator's bad policy refused with a reason (C22) | T11–T17 | the plan that uses them |

## 3. 23 NYCRR Part 500 — the New York Department of Financial Services cybersecurity regulation

For a covered entity's information systems that run a deployment:

| Requirement | Software | Proof | The bank's |
| - | - | - | - |
| **500.6(a)(2), (b)** — audit trails designed to detect and respond to cybersecurity events; kept for not fewer than three years | VG-004, VG-021: the chain and its archives; the daemon never deletes an archive | C38; T22 | the three-year retention of the archives and their second copy |
| **500.7(a)(1)–(3)** — access privileges limited to need; privileged accounts limited | VG-014 (client certificates), VG-026 (pins), VG-025 (allow-listed destinations); no operator can read a genome's contents through the software (VG-005) | T1 | the accounts and their review (500.7(a)(4)) |
| **500.8(a)** — secure development practices; procedures for evaluating externally developed applications | VG-020, VG-011; the source and the build are public | C9, C10 | the evaluation procedure |
| **500.13(a)** — an asset inventory with owner, location, classification, support expiration, recovery time objective | the deployment's assets are files the operator names: configurations, pins, key files, genomes, audit segments; `provision.json` lists them; the drills give the recovery time | C39 | the inventory itself |
| **500.13(b)** — secure disposal | a sealed genome whose key is destroyed is unreadable; sealed key files do not open off the host (VG-003, VG-023) | C24 | the disposal procedure |
| **500.15(a)** — encryption meeting industry standards in transit over external networks and at rest | VG-014 (TLS 1.3), VG-003 (AES-256-GCM) | — | the written policy |
| **500.16(a)(1)(vi)–(viii)** — documentation of events, recovery from backups, root-cause analysis | VG-004 (the record), VG-029/VG-030 (recovery of the model from the genome on an attested host), the chain as the material for root-cause analysis | C12, C28 | the plan |
| **500.16(a)(2)(iv)–(v)** — timely recovery of critical systems; backing up essential information with sufficient frequency, stored offsite | VG-030 (the measured RTO), VG-024 (the escrow), the standby in another region or cloud | C18, C35 | the frequency and the offsite copy |
| **500.16(d)(2), (e)** — annual test of the ability to restore from backups; backups protected from unauthorised alteration or destruction | the kits are the restore test; a genome is integrity-checked on open (VG-003); the audit archives are hash-recorded in the chain (VG-021) | T1–T4, T20 | the annual schedule |

## 4. PCI DSS v4.0.1

PCI DSS applies to a cardholder data environment. A deployment of this
software is normally *out of* the CDE — it keeps fine-tuned models, not
account data — and the first thing a QSA will do is settle that scoping
question. The requirement numbers below are for the case where a bank
places a deployment inside or connected to the CDE. The requirements'
text is the PCI Security Standards Council's and is not reproduced
here; each number is given with the topic in the maintainers' words.

| Requirement | Topic (in our words) | Software | Proof |
| - | - | - | - |
| 3.6.1, 3.7.1, 3.7.4 | protection of cryptographic keys; strong key generation; key changes | VG-023, VG-024 (keys sealed to the host, re-provisioned on a fresh host), keys from `crypto/rand` | C24, C28 |
| 4.2.1 | strong cryptography on transmission over open networks | VG-014 | — |
| 6.2.1, 6.2.4 | secure development; attacks on software addressed in engineering | VG-020 (CodeQL, Semgrep, fuzzing, mutation testing) | C10 |
| 6.3.1, 6.3.2 | vulnerabilities identified; an inventory of third-party components | govulncheck, osv-scanner, Dependabot; the SBOM on every release | C9 |
| 6.5.1 | changes to production made according to defined procedures | VG-011 and the compatibility ledger | T9 |
| 8.2.1 | unique identification of users | — (the software authenticates peers and operators by certificate; user identity is the bank's) | — |
| 10.2.1, 10.2.2 | audit logs of access and actions with the stated detail | VG-004: the kinds and their payloads | every trial's `audit-events.jsonl` |
| 10.3.1–10.3.4 | audit logs protected from unauthorised access and modification; backed up; integrity-monitored | VG-004, VG-021 (signed, chained, closed segments, third-party verification) | C12, C38 |
| 10.4.1, 10.7.2 | daily review of logs; failures of critical security controls detected and alerted | VG-034 (metrics), VG-035 (incidents on the record) | — |
| 10.5.1 | retention of audit logs for the stated period | VG-021 | T22 |
| 10.6.1, 10.6.3 | time synchronisation; protection of time settings | VG-037 (one clock per daemon); the host's synchronisation is the bank's | — |
| 11.3.1, 11.5.2 | vulnerability scanning; change detection on critical files | the gate's scanners; a changed binary is a changed launch measurement and is refused (VG-002, VG-026) | C10; T1 |
| 12.3.3 | an inventory of cryptographic cipher suites and protocols in use, reviewed | §6 of this map | — |
| 12.8.1, 12.8.4 | a list of third-party service providers; their status monitored | — (the maintainers are not a service provider in the deployment this map assumes) | — |
| 12.10.1 | an incident response plan | VG-035 handles three scenarios; the plan is the bank's | — |

## 5. United States examiners — the FFIEC IT Examination Handbook

The *Architecture, Infrastructure, and Operations* booklet is what a US
examiner brings. Its sections most relevant to a deployment: III.F
(resilience), V.C.1 (internally and externally developed software),
VI.B.4 (backup and replication), VI.B.7 (log management), VI.C.4
(event, incident and problem management), VII.A.4 (shared
responsibilities in cloud computing) and VII.D (artificial intelligence
and machine learning). The library holds the booklet's index page as
captured in 2026; the booklet's body is to be captured before an
examiner conversation, and this section is kept to the section titles
until then. The *Authentication and Access to Financial Institution
Services and Systems* guidance (2021) concerns user authentication,
which the software does not provide.

## 6. The cryptography in use, against the registries banks cite

The software's primitives, where each is used, and where each stands in
the registries a bank's cryptography policy points to. "X9 SD-34" is
ASC X9's *Registry of Approved Cryptographic Resources for Financial
Services Industry Standards*, SD-34-2025 (Revision 4, 8 November 2025);
"FIPS 186-5" is NIST's Digital Signature Standard of 3 February 2023;
"SP 800-56C Rev. 2" is NIST's key-derivation recommendation.

| Primitive | Where used | Registry position | What follows |
| - | - | - | - |
| AES-256-GCM | sealed genomes, sealed key files, the cross-cloud key delivery | X9 SD-34: AES (FIPS 197) and the GCM mode (SP 800-38D, listed as Part D of the block-cipher modes) are registered | — |
| SHA-256, SHA-512 | hashes of segments and bundles; the audit chain; the vendors' signatures | X9 SD-34: the SHA-2 family (FIPS 180) is registered | — |
| HKDF (RFC 5869) | the Return Path handshake's session keys; the KDF of every HPKE suite | SP 800-56C Rev. 2 §5 specifies the approved two-step extraction-then-expansion procedure and says RFC 5869 specifies a version of it with HMAC for both steps; CMVP certificate #5247 lists KDA HKDF per SP 800-56C Rev. 2 | an institution that needs the SP 800-108 expansion step verbatim should ask; the handshake's construction is in `handshake.go` |
| The signature suite (ADR 0031): `ed25519`, `ecdsa-p384-sha384`, `ml-dsa-87` | the signatures of audit events, verdicts, tokens, manifests, tree heads, the operator's lists and policies, the sentinel's records, the authority's and the workers' identities; every record carries the suite it was signed under (`alg`, absent for ed25519) | `ed25519`: FIPS 186-5 approves EdDSA (item (3) of its Explanation; Section 7 specifies it); SP 800-186 Table 2 allows Edwards25519; CMVP certificate #5247 (the Go Cryptographic Module v1.0.0) lists EDDSA KeyGen, KeyVer and SigGen; not in X9 SD-34-2025, whose entry 00009 registers the Digital Signature Standard as FIPS 186-4. `ecdsa-p384-sha384`: FIPS 186-5 Section 6 and FIPS 186-4; X9 SD-34-2025 entry 00009 (ECDSA as SEC1 §4.1.3–4.1.4 specifies, on a curve of FIPS 186-4 Appendix D); CNSA 2.0 (P-384 for the transition); certificate #5247 lists ECDSA KeyGen, KeyVer, SigGen and SigVer on P-384. `ml-dsa-87`: FIPS 204; X9 SD-34-2025 entry 00015; CNSA 2.0 (the destination); the standard library's, not in the module v1.0.0 — refused on the `-fips` build with the module's reason | a bank held to "X9-registered only" runs `fips` with `crypto.signature_suite: ecdsa-p384-sha384`, and its records say so (`alg`, `signature_suite` in every identity and in `acpctl audit verify`); a bank under CNSA 2.0 runs `cnsa`, which signs with ECDSA P-384 and accepts ML-DSA-87; a bank whose policy is "FIPS-approved algorithms" runs `general` or `fips` on ed25519 as before. Proven on SEV-SNP under `cnsa` and under `fips` with ECDSA on the certified module (C43). Finding F2b closed |
| X25519 | the ephemeral key agreement of the Return Path handshake; the cross-cloud key delivery and the escrow under the `general` profile (ADR 0029) | not named in X9 SD-34. SP 800-186 Table 2 lists EC key establishment (per SP 800-56A) for the P-curves only and Curve25519 as an alternative representation; SP 800-56A Rev. 3 does not name Curve25519; CMVP certificate #5247 lists KAS-ECC-SSC per SP 800-56A Rev. 3 and nothing on Curve25519. X25519 key agreement is therefore outside the NIST-approved key-establishment schemes as the library's texts stand | a bank held to approved key establishment runs the `fips` or `cnsa` profile (next row) on the `-fips` build (ADR 0030): there the module's TLS "will ignore and not negotiate any protocol version, cipher suite, signature algorithm, or key exchange mechanism that is not FIPS 140-3 approved" (go.dev/doc/security/fips140), so the Return Path handshake's ephemeral key agreement is ECDHE on the NIST curves, and the kits under `fips140=only` (C42) show it. In the default build the handshake's key agreement is still X25519 (Go's TLS 1.3 default) — the mitigation record of RTS Art. 6(3) and 6(5), or the `-fips` build |
| KEM suites (ADR 0029): DHKEM(P-384, HKDF-SHA384); ML-KEM-768; MLKEM1024-P384; all with AES-256-GCM, RFC 9180 HPKE | the cross-cloud key delivery and the escrow under the `fips` profile (P-384 written; P-384, ML-KEM-768 and the hybrid accepted) and the `cnsa` profile (the MLKEM1024-P384 hybrid only); `crypto.profile` on both daemons | SP 800-56A Rev. 3 specifies ECC CDH on P-384; FIPS 203 specifies ML-KEM-768 and ML-KEM-1024; SP 800-227 §4.6 covers the PQ/T hybrid with an approved combiner, and SP 800-56C Rev. 2 the hybrid shared secret Z′ = Z ‖ T; CMVP certificate #5247 lists KAS-ECC-SSC on P-384, KDA HKDF and ML-KEM-768/1024 KeyGen and EncapDecap among its approved algorithms. CNSA 2.0 names P-384 for the transition and ML-KEM-1024 as the destination; NIST IR 8547 puts the P-curves at "Deprecated after 2030, Disallowed after 2035" | the suite and the profile are in every record (the handshake answer, the token, the escrow documents, `delivery_mode` and `crypto_profile` in the audit chain, `identity`); the three profiles are on record on SEV-SNP (`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e`, `authority-loss`). The validated-module claim is still the FIPS build of finding F2 |
| ECDSA P-256 / P-384 | verifying AMD's, Intel's and NVIDIA's certificate chains and reports; the kits' TLS certificates | X9 SD-34: the Digital Signature Standard entry, with ECDSA per SEC1 §4.1.3–4.1.4 since the withdrawal of X9.62 | — |
| TLS 1.3 | the daemons' listeners | a protocol, not a registry entry; the suites are Go's TLS 1.3 set | — |
| Random bits | `crypto/rand` (the operating system's generator) | X9 SD-34 registers SP 800-90B for entropy sources; the module validation of the host's generator is the host's | — |
| FIPS 140-3 module validation | the `-fips` release variant of every binary and both images (ADR 0030, from 0.8.0) | the product does not claim a validated product; it ships on a validated module. The Go Cryptographic Module v1.0.0 (Go 1.24 and later) holds CMVP certificate #5247, FIPS 140-3 Level 1, active, sunset 2031-04-26, with AES-GCM, SHA-2, HMAC, ECDSA and EdDSA (FIPS 186-5), HKDF (SP 800-56C), KAS-ECC (SP 800-56A Rev. 3), the TLS 1.3 KDF and the DRBGs on its approved list; v1.26.0 (Go 1.26 and later) was Pending Review as of 2026-04-28 (a ledger entry when it is certified). The `-fips` variants are built with `GOFIPS140=v1.0.0` — the version named, never an alias — and run the module in its approved mode (`fips140=on`); `version` and `identity` print the module; every build is approved-mode clean in its AEAD and KDF use (the module's own AES-GCM nonces, its HKDF, the v2 KEM suites); under `fips140=only`, the module's enforcement, the three kits pass on SEV-SNP under the `fips` and `cnsa` profiles (C42) and the confidential-GPU kit passes on an NCC H100 v5 under `fips`, with Ed25519 and with ECDSA P-384 (C44) | a bank that requires a validated module deploys the `-fips` variant under the `fips` or `cnsa` profile and records the module version from `identity`; the confidential-GPU path (Azure NCC H100 v5) is measured under the module on the same terms (C44; ADR 0030) |

## 7. Others a bank will raise, briefly

- **NIS2 (Directive (EU) 2022/2555) and Implementing Regulation
  (EU) 2024/2690.** For a bank, DORA is the sector-specific act (DORA
  Art. 1(2), NIS2 Art. 4): the questions are answered in §1–§2. The
  implementing regulation addresses digital-infrastructure entities —
  cloud providers among them — not banks; it matters to the bank's
  assessment of its cloud provider, not of this software.
- **BCBS, Principles for Operational Resilience (March 2021).**
  Principle 3 (business continuity exercised under severe but plausible
  scenarios, ¶23) and Principle 6 (incident classification and
  response, ¶34) are what §1's Art. 11 and Art. 17 rows serve;
  Principle 7, ¶38 — controls that keep the integrity of critical
  information in a cyber event, with secure storage of the data behind
  critical operations — is what a sealed, escrowed genome and an audit
  chain in closed segments are for (VG-003, VG-021, VG-024).
- **EBA Guidelines on ICT and security risk management (EBA/GL/2019/04).**
  The consolidated version of 19 May 2026 retains only section 3.8,
  payment service user relationship management; the ICT sections were
  deleted by EBA/GL/2025/02 when DORA took over. They are not mapped.
- **MiFID II and record-keeping.** The audit chain is a record of
  decisions about models, not of orders or transactions; a bank's
  record-keeping obligations for trading are met by its trading systems.
  The older reference design's claim that the audit log satisfies
  MiFID II Article 16 is withdrawn.

## 8. What the bank must do itself — the short list

1. Classify the models and the data they were trained on, and decide
   which go through the software (DORA Art. 8; RTS Art. 6(2)).
2. Write the RTO and RPO targets from the BIA and compare them with the
   drills' figures on the bank's own hardware (RTS Art. 24(1)(b)(ii)(2)).
3. Decide the retention period of the audit archives and the second
   location (RTS Art. 12(2)(a); NYDFS 500.6(b)).
4. Synchronise the hosts' clocks to a reference source and say so in the
   deployment's record (RTS Art. 12(2)(f); PCI DSS 10.6.1).
5. Issue and rotate the operators' client certificates; keep the
   certificate register (RTS Art. 7(4)–(5)).
6. Put the deployment into the testing programme and run the kits on the
   bank's accounts with an independent tester (DORA Art. 24(4), 25(1));
   the reference design's own kit plays the whole design in the bank's
   project and writes its figures (C41).
7. Record the cryptography position of §6 against the bank's own policy
   (RTS Art. 6(3), 6(5)).
8. Write the contract clauses of DORA Art. 30, if a maintainer is a
   party to one; the software's part is what this map lists.

## 9. Findings for the maintainers from this pass

| # | Finding | Where | Proposed |
| - | - | - | - |
| F1 | The client that calls a RATS Verifier accepts TLS 1.2 (`MinVersion: tls.VersionTLS12`), while every listener of the product is TLS 1.3 only. | `internal/shared/tee/rats_verifier.go` | raise the floor to TLS 1.3; the Verifier used in C30, C31 and T5 is a Go server and speaks it |
| F2 | Ed25519 is FIPS 186-5-approved and on the Go module's CMVP certificate, but not in X9 SD-34 Revision 4; X25519 key agreement is outside the NIST-approved schemes (SP 800-186 Table 2, SP 800-56A Rev. 3, certificate #5247). **Closed (2026-10-21, ADR 0029 and ADR 0030):** the cross-cloud key delivery and the escrow run under named KEM suites and a profile — `fips` writes P-384 and accepts P-384, ML-KEM-768 and the MLKEM1024-P384 hybrid, `cnsa` the hybrid only — proven on SEV-SNP under all three profiles (ADR 0029); the release carries a `-fips` variant of every binary and image on the certified Go Cryptographic Module v1.0.0, every build is approved-mode clean, and the kits under `fips140=only` pass under `fips` and `cnsa` on SEV-SNP, the Return Path handshake's key agreement on the NIST curves there (C42; ADR 0030). | §6 | **F2b closed (2026-10-22, ADR 0031, parts one to three):** the signature suite is named on every record (`alg`), the keys follow it (`keys.<name>.suite`, `acp-keygen -signature-suite`), and the profile decides it — `fips` with `crypto.signature_suite: ecdsa-p384-sha384` is the deployment a bank held to X9 runs, `cnsa` signs with ECDSA P-384 and accepts ML-DSA-87; proven on SEV-SNP under `cnsa` and under `fips` with ECDSA on the certified module (C43). The confidential-GPU path under the module followed on 2026-10-22 (C44; ADR 0030). What remains: the module version that certifies ML-DSA, when it is certified (ADR 0031, part four) |
| F3 | No operator document states that the host clock must be synchronised to a reference source. | `docs/operator/01_preflight.md` | one item in the preflight list |
| F4 | The assurance case §4 says secrets are redacted from logs by `slog` `LogValuer` methods; the tree has no `LogValuer` — the one redaction is a `fmt.Stringer` on a key type (`internal/vault/keys/tenant.go`). | `docs/security/assurance_case.md` | state the mechanism that exists, or add the one the case describes, and a test that logs a key and asserts it is not in the output |
| F5 | The catalogue of 2026-05-04 credited Kubernetes network policies, Terraform retention and an HSM wrap that are not in the tree; the threat model cites VG-014 for mutual TLS, which this catalogue keeps as VG-014's meaning. | the former `docs/compliance/crosswalk.md` (removed with the catalogue), `docs/security/threat_model.md` | the threat model's citations are checked against the new catalogue in the pull request that lands it |
