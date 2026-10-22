# ADR 0031 — The signature suite: ECDSA P-384 beside Ed25519 for the registries banks cite, ML-DSA-87 named as the destination, and the suite on every record

- **Status:** Proposed (2026-10-22)
- **Tags:** crypto, signatures, audit, profile, fips, x9, cnsa, post-quantum
- **Extends:** ADR 0029 (the profile: what each daemon writes and accepts), ADR 0030 (the module each build runs on), ADR 0010 and ADR 0014 (the signed, hash-chained records), ADR 0023 (sealed key files)
- **Closes:** finding F2b of the banking map (`docs/compliance/banking.md` §9), once parts one to three are in the tree

## Context

Every signature the product makes is Ed25519, and it makes many: the
audit chain's events (`signing_key_id`, `signature` on every
`AuditEvent`, schema v7), the authority's signed verdicts and release
decisions, the bootstrap manifests, the key-release tokens, the
witness's signed tree heads, the sentinel's seal records, heartbeats and
compromise notices, the operator's failover policies and revocation
lists, the workers' candidate outputs. Two paths carry them: the `keys`
package (`Signer.Sign(kid, purpose, msg)`, `Resolver.Resolve(kid,
purpose)` → `VerifyingKey`) behind the audit chain, the verdicts, the
tokens, the manifests and the tree heads; and `crypto/ed25519` called
directly by the sentinel, the failover policy, the revocation list, the
`acpctl` commands that issue and check them, and the two PEM readers of
`sagvd` and `acp-bootstrap`, which accept nothing but an Ed25519 public
key. Every signing key is a 32-byte seed in a file sealed to its host
(ADR 0023); every public key is published as PKIX PEM, which names its
algorithm.

The banking map's finding F2 — closed in part by ADR 0029 (the KEM
suites and the profile) and ADR 0030 (the certified module) — left the
signatures: what remains is "the signature suite beside Ed25519 for a
policy that names X9 only" (F2b). The sources, all in the library:

- **FIPS 186-5** (2023-02-03) approves both EdDSA (Section 7, Ed25519)
  and ECDSA (Section 6). The Go Cryptographic Module v1.0.0, CMVP
  certificate #5247, lists among its approved algorithms ECDSA KeyGen,
  KeyVer, SigGen and SigVer — and deterministic ECDSA — on P-224, P-256,
  P-384 and P-521 (FIPS 186-5; CAVP A6650, A8668), and EdDSA KeyGen,
  KeyVer and SigGen on Ed25519; it lists no ML-DSA (Security Policy
  `140sp5247`, the algorithm tables; the measurement log counts the
  lines).
- **X9 SD-34-2025**, the Registry of Approved Cryptographic Resources
  that a bank's auditor reads, has one signature entry for the classical
  algorithms, number 00009 "Digital Signature Algorithms", whose citation
  is **FIPS 186-4** (July 2013; last update of the entry 2020-02-14): it
  directs that ECDSA signatures be generated and verified as SEC1
  §4.1.3 and §4.1.4 specify (X9.62 being withdrawn), on a curve of FIPS
  186-4 Appendix D, with an approved hash of entries 00003 or 00011, the
  implementation validated. The registry mentions EdDSA and Ed25519
  nowhere. It does register the post-quantum signatures: entry 00015
  ML-DSA (FIPS 204, "implement ML-DSA as specified in FIPS 204; ML-DSA
  and hash functions shall be validated"), entry 00016 SLH-DSA (FIPS
  205), entry 00017 LMS and XMSS. So a bank whose policy reads
  "X9-registered only" has no entry for Ed25519 and does have entries for
  ECDSA and ML-DSA.
- **CNSA 2.0** (NSA Cybersecurity Advisory of 2022-09-07) names ECDSA on
  "Curve P-384 for all classification levels" (FIPS 186-4) and ECDH on
  P-384 (SP 800-56A) for the transition, SHA-384 or SHA-512, AES-256; and
  for the destination ML-KEM-1024 and ML-DSA-87 (FIPS 203, 204), with
  LMS and XMSS (SP 800-208) for software and firmware signing. Its
  timeline: software and firmware signing "support and prefer CNSA 2.0 by
  2025, and exclusively use CNSA 2.0 by 2030"; the rest "by 2033";
  "custom applications and legacy equipment: update or replace by 2033".
  Ed25519 appears nowhere in it.
- **NIST IR 8547** (initial public draft, 2024-11) puts ECDSA and EdDSA
  at 112 bits of security on the path "deprecated after 2030, disallowed
  after 2035", and every parameter set of either, at 128 bits and above,
  "disallowed after 2035".
- **Go 1.27.3**: `crypto/ecdsa` is in the module, and the certificate
  covers it; `crypto/mldsa` (ML-DSA-44, -65, -87 of FIPS 204) is in the
  standard library. Measured on 2026-10-22: in the default build
  ML-DSA-87 generates a key, signs (4627-byte signature) and verifies;
  built with `GOFIPS140=v1.0.0` — the `-fips` variant of ADR 0030 — key
  generation returns "mldsa: unavailable in FIPS 140-3 Go Cryptographic
  Module v1.0.0", under enforcement the same.

What the product offers today, then, is approved under FIPS 186-5 and
on the certificate, and is not in the registry a United States bank is
told to cite, and is not on the path the NSA names for the next decade.
A bank held to X9 needs ECDSA on a FIPS 186-4 curve; a bank under CNSA
2.0 needs P-384 now and ML-DSA-87 by 2030 to 2033; every bank needs the
suite written on the record it will show its auditor.

## Decision

1. **Signature suites, named.** A suite is a string id over an
   algorithm, a parameter set and a hash; a suite id never changes
   meaning, a new triple is a new id. The registry at launch:

   | Suite | Algorithm | Signature | Public key | Where it is approved or registered | In the certified module v1.0.0 | Profiles that allow it |
   | - | - | - | - | - | - | - |
   | `ed25519` | EdDSA on Ed25519 (FIPS 186-5 §7; RFC 8032) | 64 bytes | 32 bytes | FIPS 186-5; #5247 | yes | general, fips |
   | `ecdsa-p384-sha384` | ECDSA on P-384 with SHA-384 (FIPS 186-5 §6; SEC1 §4.1.3–4.1.4 as X9 SD-34 00009 directs), deterministic per RFC 6979 as the module implements it, the signature the fixed-length `r ‖ s` of 96 bytes | 96 bytes | 97 bytes (uncompressed point; PKIX in files) | FIPS 186-5 and 186-4; X9 SD-34 00009; CNSA 2.0 (transition); #5247 | yes | general, fips, cnsa |
   | `ml-dsa-87` | ML-DSA-87 (FIPS 204), pure mode, no context string | 4627 bytes | 2592 bytes | FIPS 204; X9 SD-34 00015; CNSA 2.0 (destination) | **no** — the standard library's implementation in the default build; unavailable in the `-fips` build until the module version that certifies it | general, cnsa |

   The suite is what a verifier checks: the key's algorithm must be the
   suite's, the signature's length the suite's, the hash the suite's.

2. **The profile names the suite, the override narrows it.**
   `crypto.profile` of ADR 0029 — `general`, `fips`, `cnsa` — also names
   the suite a daemon signs with and the suites it accepts:

   | Profile | Signs with | Accepts |
   | - | - | - |
   | `general` | `ed25519` | `ed25519`, `ecdsa-p384-sha384`, `ml-dsa-87` |
   | `fips` | `ed25519` | `ed25519`, `ecdsa-p384-sha384` |
   | `cnsa` | `ecdsa-p384-sha384` | `ecdsa-p384-sha384`, `ml-dsa-87` |

   `crypto.signature_suite` picks the suite a daemon signs with from its
   profile's list — never one outside it. That is the knob for the X9
   bank: `fips` with `ecdsa-p384-sha384`. A `cnsa` deployment on the
   default build may pick `ml-dsa-87` today; on the `-fips` build the
   pick is refused at startup with the module's reason. When a certified
   module carries ML-DSA, `cnsa` signs with `ml-dsa-87` by a ledger entry
   of `08_upgrading.md`, as the KEM suites moved. There is no
   negotiation: a record names its suite, and a verifier accepts it only
   if its list has it — a `cnsa` authority refuses an `ed25519` verdict.

3. **The suite is written on every record that carries a signature.**
   Beside every `signing_key_id` and `signature` the record carries
   `alg`, the suite id; absent, it means `ed25519` — what every record
   before this ADR carried, so every record ever written verifies as it
   did. The audit event schema becomes v8 for the field; `AuditEvent`,
   the signed verdict and release decision, the key-release token, the
   bootstrap manifest, the signed tree head and witness receipt, the
   sentinel's records, the failover policy and the revocation list all
   gain it the same way. `identity` prints `signature_suite` beside each
   signing key's PKIX PEM — PKIX names the algorithm itself (id-Ed25519,
   id-ecPublicKey with secp384r1, id-ML-DSA-87), so the published keys
   need no second field. A reader of this release opens records of every
   earlier release; a reader of an earlier release cannot verify a record
   signed under `ecdsa-p384-sha384` or `ml-dsa-87` — readers before
   writers, and under `cnsa` both daemons move together.

4. **Key material by suite, sealed as before.** `acp-keygen` takes
   `--signature-suite` (default `ed25519`) and writes each signing key
   in its suite's form: an Ed25519 key stays the 32-byte seed every
   deployment has; an ECDSA P-384 key is PKCS#8 PEM; an ML-DSA-87 key is
   its 32-byte seed (FIPS 204 Algorithm 6, `mldsa.NewPrivateKey`). Each
   key's configuration names its suite (`keys.<name>.suite`, default
   `ed25519`), so a 32-byte file is read as the suite says and never
   guessed. The sealed-file discipline of ADR 0023 is unchanged: the
   file's bytes are sealed to the host whatever the suite; `seal-keys`,
   `identity` and the kits say which suite each key is.

5. **One signing abstraction.** The `keys` package is the only place
   that signs and verifies: `VerifyingKey` carries the suite,
   `Signer.Sign` returns the suite's signature, a `Verify` by the key's
   suite replaces every direct `ed25519.Sign`/`ed25519.Verify` — in the
   sentinel, the failover policy, the revocation list, the `acpctl`
   commands, the PEM readers of `sagvd` and `acp-bootstrap` (which accept
   any PKIX key of a suite the profile lists). `crypto.Sign` and
   `crypto.Verify` of `internal/shared/crypto` become suite-aware over
   the module's `crypto/ed25519` and `crypto/ecdsa` and the library's
   `crypto/mldsa`.

6. **Availability per build is reported, never assumed.** The `-fips`
   build offers `ed25519` and `ecdsa-p384-sha384`, both on the
   certificate; `ml-dsa-87` reports itself unavailable there with the
   module's own reason, and a configuration that picks it is refused at
   startup; the default build offers all three, and a record signed
   under `ml-dsa-87` says so by its `alg`, its `identity` saying which
   module the signer ran on (ADR 0030). The assessment under
   `fips140=only` covers the two suites the module has.

7. **Not decided here:** dual signatures (ECDSA and ML-DSA on one
   record — CNSA 2.0 names no hybrid for signatures, the registry has
   none, and the records would double); SLH-DSA; X.509 certificates for
   the product's keys (its keys are key ids in records, published as
   PKIX); the TLS certificates of the Return Path and the cross-cloud
   endpoint (ECDSA P-256 today — CNSA 2.0 asks P-384 there too; a later
   ADR); the simulated TEE's Ed25519 evidence key, a test construct.

## Alternatives considered

- **Move everything to ECDSA P-384.** Rejected: every record and every
  key of every deployment would change; Ed25519 is approved under FIPS
  186-5 and on the certificate, and the X9 gap is the policy of some
  banks, not a defect of the algorithm. The suite is a choice on the
  record, as the KEM suite is.
- **Dual signatures (ECDSA + ML-DSA) now.** Rejected for now: no
  registry entry and no CNSA 2.0 guidance names a signature hybrid, and
  every audit event would carry 4.7 KB more; the record's `alg` leaves
  the door open to a `dual-…` suite id later.
- **SLH-DSA.** Rejected: FIPS 205 signatures of 7 to 49 KB on every
  audit event and verdict; registered by X9 (00016) and named by CNSA 2.0
  nowhere for this use.
- **A policy flag outside the profile.** Rejected: ADR 0029 made the
  profile the one knob a deployment turns; the override lives inside it
  and cannot widen the list.
- **Wait for ML-DSA in the certified module.** Rejected: the X9 bank
  needs ECDSA now, the destination is named now, and the move to
  `ml-dsa-87` under `cnsa` is a ledger entry when the module arrives.

## Consequences

- A signature grows from 64 bytes to 96 under `ecdsa-p384-sha384` and
  to 4627 under `ml-dsa-87`; an audit event's size with it; the
  segment's closing by count and age (ADR 0027) is unchanged.
- The audit event schema is v8 (`alg`); every signed contract gains the
  field; readers of this release open everything earlier; readers of
  earlier releases verify only `ed25519` — `08_upgrading.md` says so,
  and under `cnsa` both daemons move together, as ADR 0029 made the rule.
- `acpctl audit verify --audit-pubkey` takes any PKIX key of a listed
  suite; the third party of design 01 verifies an ECDSA-signed chain
  with `acpctl` alone (C41's step, under `cnsa`).
- The claims: C43 — the key-release kit and reference design 01 on real
  SEV-SNP under `cnsa` with every record signed under
  `ecdsa-p384-sha384`, and the `-fips` build signing under it; a record
  signed under `ml-dsa-87` on the default build, opened by `acpctl`.
- `docs/compliance/banking.md` §6: the Ed25519 row says the suite a bank
  held to X9 runs (`ecdsa-p384-sha384`) and the one CNSA 2.0 names
  (`ml-dsa-87`, with its module status); §9 closes F2b when parts one to
  three are in the tree. `controls.md` VG-004 and VG-038 name the suite.
- No change to the KEM suites, the AEAD, the bundle or the TLS
  configuration.

## Implementation notes

- **Part one (the records):** `keys.VerifyingKey.Suite`; suite-aware
  `Sign`/`Verify` in `internal/shared/crypto` and the `keys` store;
  `alg` on `AuditEvent` (schema v8), the signed verdict and release
  decision, the token, the bootstrap manifest, the tree head and the
  witness receipt; `acpctl audit verify` by the key's suite; fixtures of
  records signed under each suite, written by this tree and verified
  from the file; the doctrine tests.
- **Part two (the keys):** `acp-keygen --signature-suite`;
  `keys.<name>.suite` in every daemon's configuration; the sentinel, the
  failover policy, the revocation list and the `acpctl` commands through
  the `keys` abstraction; the PEM readers; `identity` with
  `signature_suite`; `seal-keys` naming the suite.
- **Part three (the profile and the proof):** the profile table and
  `crypto.signature_suite`; the refusals (`cnsa` refusing `ed25519`, the
  `-fips` build refusing `ml-dsa-87`); the kits `keyrelease-e2e` and
  `reference-design-01` under `cnsa` on SEV-SNP, and under `VG_FIPS=1`
  with `ecdsa-p384-sha384`; claim C43; `06_cross_cloud_restore.md`, the
  ledger in `08_upgrading.md`, `banking.md` §6 and §9, `controls.md`,
  `CHANGELOG.md`.
- **Part four (the destination):** `ml-dsa-87` on the default build under
  `general` and `cnsa`; the ledger entry when a certified module carries
  ML-DSA.

## References

- NIST FIPS 186-5, Digital Signature Standard (2023-02-03) — §6 ECDSA,
  §7 EdDSA; FIPS 186-4 (2013-07), as X9 SD-34 cites it
  (`banking/nist/FIPS186-5.pdf`, `FIPS186-4.pdf`).
- ASC X9 SD-34-2025, Registry of Approved Cryptographic Resources —
  entries 00009 (Digital Signature Algorithms), 00015 (ML-DSA), 00016
  (SLH-DSA), 00017 (LMS/XMSS)
  (`banking/x9/ASC-X9-SD-34-2025_Registry-of-Approved-Cryptographic-Resources.pdf`).
- CMVP certificate #5247, Go Cryptographic Module v1.0.0 — the Security
  Policy's algorithm tables (`140sp5247`).
- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard
  (2024-08) (`banking/nist/FIPS204.pdf`); FIPS 205.
- NSA, Commercial National Security Algorithm Suite 2.0 — the advisory of
  2022-09-07 (Tables I and III, the timeline) and its FAQ (both the
  Internet Archive's captures: `tier4/pq-nsa/wayback/CSA_CNSA_2.0_ALGORITHMS___wayback-20241215203633.PDF`,
  `banking/nsa/CSI_CNSA_2.0_FAQ___wayback-20261020053325.PDF`; the
  publisher's server refuses non-browser clients).
- NIST IR 8547 (ipd, 2024-11), Transition to Post-Quantum Cryptography
  Standards — Table 3 (`banking/nist/IR8547-ipd.pdf`); SP 800-186
  (`banking/nist/SP800-186.pdf`).
- Go 1.27.3: `crypto/ecdsa`, `crypto/ed25519`, `crypto/mldsa`
  (`GenerateKey`, `NewPrivateKey`, `Verify`, `MLDSA87`); RFC 6979; RFC
  8032; SEC1.
- ADR 0010, 0014 (the records), ADR 0023 (sealed key files), ADR 0029
  (the profile), ADR 0030 (the module); `docs/compliance/banking.md` §6
  and §9 (F2, F2b).
- The measurement: `0031-the-signature-suite.measurement-20261022.log`.
