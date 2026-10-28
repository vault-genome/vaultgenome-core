# ADR 0034 — The verifier held to readings nobody here wrote: the differential corpus

- **Status:** Accepted (2026-10-22) — part one (every genuine SEV-SNP report on record as a corpus; Google's go-sev-guest as a second reading through a module of its own; the test that calls both on the verdict, the fields and every single-byte mutant; the laxity it found on its first run, and the fix) and part two (VirTEE's `snpguest` as the third reading, on the record from Linux in the `differential` workflow's first green run) and part three (the auditor's own verifier of the audit log, in Python with no dependencies, held equal to `acpctl audit verify` on every log on record, on logs under each suite and on mutants) and part four (the corpus whole on its own with what every verifier must read, a harness any verifier runs through a command, and the corpus as part of the public conformance package for Go verifiers) in the tree; claims C47 and C48. Part five (version-aware must-be-zero checks in the signed body; a hardware day adding a fresh report; the receipts under the auditor's tool; the corpus as a release asset) follows
- **Date:** 2026-10-22
- **Deciders:** Serhii Nikolaichuk, Rodion Sorokin

## Context

The product's SEV-SNP verifier was written here from AMD's specification
(56860, in the project library at Rev 1.59) and has been proven on real
chips: the key release and the Return Path on GCP Milan, the confidential
GPU on Azure Genoa, with the reports kept as evidence. The protocols are
modelled (ADR 0032) and the firmware is held to the attack record
(ADR 0033). What had only the product's own word was the reading of the
report itself — which bytes are which, what must be zero, what the
signature covers, how r and s lie in their slots. A second implementation
by the same hands reads the same page the same way; a reviewer at a bank,
a cloud or an acquirer asks for a reading nobody here wrote, and for a
test that runs both on the same bytes. The project's own lesson of
2026-09-22 says the same: a second implementation of one piece of
mathematics is only worth what the test that *calls* both proves.

Two such readings exist and are maintained by others. Google's
`go-sev-guest` is the library behind Google's own confidential-computing
tooling; VirTEE's `snpguest` is the Rust tool AMD's documentation points
guests to, written with AMD's engineers. Veraison, the standards verifier,
is already the product's delegated verifier (ADR 0025 step 2b, C30) and
appraises as a service with its own scheme. None of them is the product's
code.

## Decision

1. **The corpus is every genuine report on record.** `test/corpus/sev-snp/`
   holds a manifest of every genuine SEV-SNP attestation report in this
   tree — the raw reports the hardware kits kept and the reports embedded
   in the restore receipts of the key-release kits — each with the VCEK it
   verifies under (from beside the report when the kit kept one, otherwise
   from AMD KDS by the chip id and reported TCB the report names) and
   AMD's ASK+ARK chain for its product from KDS. `build.py`, the standard
   library only, writes the manifest, extracts the receipts' reports,
   fetches what is missing, and keeps `SHA256SUMS` over all of it. On
   2026-10-28, later: 68 reports (31 files, 37 receipts), 28 distinct chips,
   Milan and Genoa, report versions 3 and 5, firmware from SNP 0x17 to
   0x1d. Two files of the demo kits of 2026-10-14/15 are not reports but
   the kernel's ioctl response with a 32-byte header and the signature cut;
   `build.py` keeps only what parses as a report (1184 bytes, VERSION 2–5,
   SIG_ALGO 1) and says what it skipped.
2. **The second reading is Google's, in a module of its own.**
   `tools/oracle` is a Go module separate from the product
   (`tools/oracle/go.mod`): it depends on `go-sev-guest` v0.15.0, the
   product's dependency allowlist (`ci-security-policy` §3.1) is untouched,
   and nothing of it ships in a binary. `oracle sevsnp` parses a report
   with `abi.ReportToProto`, verifies it with `verify.SnpAttestation` under
   the given VCEK and chain with fetching disabled, prints the parsed
   report as JSON, and with `-sweep` flips every byte in turn and records
   whether the mutant still verifies. VirTEE's `snpguest` is the third
   reading (`verify certs`, `verify attestation`, `display report`); it is
   Rust for Linux x86-64 (its `rdrand` dependency does not build on Apple
   silicon), so it runs where the workflow and the hardware kits run, named
   by `VG_SNPGUEST`.
3. **One test calls both.** `internal/shared/tee/differential_test.go`
   (build tag `differential`; `make differential`) walks the manifest and,
   per report, runs the product's parse, AMD-chain check and signature
   check in-process, runs the oracle, and requires: both verify; the
   product line agrees; nineteen fields are equal — version, guest SVN,
   policy, PLATFORM_INFO, VMPL, signature algorithm, the current,
   reported, committed and launch TCBs, the measurement, host data, report
   data and chip id, both mitigation vectors, the current and committed
   firmware versions, and the CPUID family/model/stepping as the FMS
   value; and that of the 1184 single-byte mutants of the report neither
   side verifies one. The stage of each refusal — at the parse or at the
   signature — is recorded per offset for both sides and may differ; the
   verdict may not. With `VG_SNPGUEST` set, `snpguest` must verify the
   chain and the report and show the measurement and chip id the product
   read. `VG_DIFFERENTIAL_RECORD` writes the run as JSON; the runs on
   record are in `test/corpus/sev-snp/results/`.
4. **What the first run found, and what changed.** On every one of the 41
   reports the product verified 416 mutants that go-sev-guest refused:
   offsets 0x2D0–0x2E7 and 0x318–0x49F — the 24 bytes above the 48-byte r
   and s in their 72-byte slots, and the 368 reserved bytes after s. They
   are not under the signature; the product read 48 bytes of each
   component and ignored the rest, so a report with anything in those
   bytes verified — not a break of authenticity, the signed body being
   intact, but the acceptance of a report that is not what the firmware
   emitted. go-sev-guest refuses the reserved bytes at the parse (must be
   zero) and reads the full 72-byte components, so a high byte set fails
   the signature. The product now refuses at the parse any non-zero byte in
   those three spans (`sev report: reserved byte … of the signature block
   is not zero`), with a unit test on the genuine report
   (`TestSEVSNPParse_RefusesANonZeroSignatureReserve`), and the sweep
   shows no verified mutant on either side. The stages still differ in the
   signed body: go-sev-guest refuses at the parse what the product refuses
   at the signature (the policy's must-be-one bit 17 and reserved bits,
   the reserved bytes 0x4C–0x4F, 0x18B–0x19F and 0x208–0x29F, the top byte
   of each build field); both refuse. Version-aware must-be-zero checks in
   the signed body are part two's question, with the specification open.
5. **The claim is narrow.** The product's reading equals Google's on
   every report on record, VirTEE's tool verifies each under the same
   certificates and shows the same measurement and chip id, and no
   single-byte mutant verifies on either library reading — on the corpus
   of 2026-10-22 and in the workflow that reproduces it (C47). Nothing is
   claimed for a report the corpus does not hold, for another TEE family,
   or for the records (part three).

## Alternatives considered

- **A second implementation written here, in Python or Rust.** The same
  hands reading the same specification; a reviewer sees a self-check. Not
  taken as the second reading of the chip's report; taken, in part three,
  for the records — the audit chain, the receipts — where no third-party
  implementation exists and an auditor's own small verifier is the point.
- **go-sev-guest inside the product.** The dependency allowlist exists so
  that the product's trust base is the standard library's; and the product
  needs none of it at runtime. A module of its own, test-only.
- **Veraison as the only second reading.** It is already the delegated
  verifier (C30) and appraises as a service with its own scheme and
  deployment; a library that runs on every report in seconds is the
  differential test's tool. Veraison's reading of the corpus belongs to
  the hardware day of part two.

## Consequences

- A drift between the product's reading and Google's — a field, a verdict,
  a mutant accepted — is a red test, not a note. The corpus grows with
  every kit run (`build.py` after a run; `--no-fetch` offline).
- The product refuses a report with anything but zero in the reserved
  bytes of its signature block. Genuine firmware never emits one; the 41
  on record all pass; a synthetic report in a test must keep those bytes
  zero.
- The oracle's dependency is Google's library (Apache-2.0), in a module the
  product does not import; the VirTEE leg needs a Linux x86-64 host.

## Implementation notes

- **Part one (2026-10-22):** `test/corpus/sev-snp/{build.py,manifest.tsv,reports/,vcek/,chains/,SHA256SUMS,README.md,results/}`;
  `tools/oracle/{go.mod,go.sum,main.go}`; `internal/shared/tee/differential_test.go`;
  the parser's check in `gcp_sev_snp_verify.go` and
  `sev_snp_signature_block_test.go`; `make differential`; the
  `differential` workflow. The first run on record:
  `results/differential-20261022T220839Z.json` — 41 reports, product and
  go-sev-guest both verified on each, 19 fields equal on each; mutants per
  report: product 416 refused at the parse and 768 at the signature,
  go-sev-guest 557 at the parse and 627 at verification, none verified by
  either.
- **Part two (2026-10-22):** the `differential` workflow's first green run
  on the pull request (run 39864468613, ubuntu-24.04, x86-64): `snpguest`
  0.10.0 built from crates.io in 1 min 45 s, then one test with all three
  readings — 41 of 41 verified by the product, by go-sev-guest and by
  `snpguest` (`verify certs`, `verify attestation`; `display report`
  showing the measurement and chip id the product read), 19 fields equal,
  no mutant verified by either library reading; the record
  `results/differential-ci-20261022T222534Z.json` is the workflow's
  artifact. Claim C47; control VG-040; `banking.md` (RTS Art. 16).
- **Part three (2026-10-22):** `tools/auditor/verify_audit.py` — the
  standard library of Python only: the bbolt file read as pages, the
  canonical JSON re-encoded as the Go side encodes it (keys sorted
  bytewise, Go's HTML-safe string escaping), SHA-256 over it, the link to
  the previous hash from the genesis or from a continued segment's
  `prev_tip_hex`, and the signature over the hash under the audit public
  key — Ed25519 after RFC 8032 and ECDSA P-384 after SEC 1 written out in
  the file; ML-DSA-87 reported as not implemented, not as broken.
  `internal/audit/chain/auditor_differential_test.go` (tag `differential`)
  calls it and `acpctl audit verify` (built from the tree) on every
  genuine log on record (the three authority logs of the region-loss
  drills, five events each), on a log written under each suite with
  payloads that exercise the encoding (`<`, `&`, quotes, U+2028, Cyrillic
  and CJK, nested objects, an empty string, a zero), and on six mutants
  (a byte of a kind, of a signature, of a prev_hash, in a written and in
  a genuine log): the verdicts, the counts and the tips agree, every
  mutant is refused by both, and the ML-DSA-87 log is verified by the
  product and declined by the tool, as documented. The record of the
  first run: `test/corpus/audit/results/auditor-20261022T233609Z.json`.
  Claim C48; control VG-041; `banking.md` (RTS Art. 12(2)(d)). The
  receipts stay with part five.
- **Part four (2026-10-23):** the corpus is whole on its own — every
  report and VCEK copied into `test/corpus/sev-snp/` (the manifest's
  `source` column says where each was kept), AMD's chains, `SHA256SUMS`
  — and `expected.tsv` holds what every verifier must read from each
  report, taken from the raw bytes at the specification's offsets with no
  verifier involved (the fields of C47; the three readings agree with
  them). `tools/corpus-harness/run.py` runs any verifier given as a
  command with `{report} {vcek} {chain} {product}` on every report, reads
  one JSON object from it (`verified`, and the fields it chooses to
  expose), holds the fields to `expected.tsv`, and with `--mutants N`
  flips N bytes of each report across the signed body and the signature
  and requires every one refused; adapters for Google's oracle and
  VirTEE's `snpguest` come with it, and the run on record
  (`results/harness-oracle-<stamp>.json`: the Google reading, 68 reports,
  11 fields each, 8 of 8 mutants refused on each) is in the tree. For Go
  verifiers the corpus is part of the public conformance package:
  `teeconformance.RunSEVSNPCorpus(t, dir, read)` loads the manifest and
  the expected values and holds a reader to them and to two mutants per
  report; the product's own reading is its first user
  (`TestSEVSNPCorpus_ProductReading`, in the gate). The `differential`
  workflow runs the harness with both adapters on every push. The three
  directories are Apache-2.0 by the decision of both copyright holders
  (ADR 0003, amendment of 2026-10-23), so that any verifier can take the
  corpus into its own tests.
- **Part five:** must-be-zero in the signed body, version-aware, from the
  specification; a hardware day adding a fresh report to the corpus by the
  kit; the receipts (the restore receipt and the report quoted over it)
  under the auditor's tool; the corpus directory as a release asset.

## References

- Google, `go-sev-guest` v0.15.0 (Apache-2.0): `abi`, `verify`, `verify/trust`, `kds`.
- VirTEE, `snpguest` v0.10.0 (Apache-2.0).
- AMD, *SEV Secure Nested Paging Firmware ABI Specification*, 56860 Rev 1.59 (project library): the attestation report, the signature.
- ADR 0032 (the protocols in ProVerif), ADR 0033 (the attack record in the policy), ADR 0025 step 2b and C30 (Veraison).
