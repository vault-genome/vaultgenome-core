# The SEV-SNP corpus — every genuine report on record, for any verifier to run

This directory is whole on its own: every genuine AMD SEV-SNP attestation
report Vault Genome has on record, the VCEK each one verifies under, AMD's
ASK+ARK chain for each product, what every verifier must read from each
report, and the digests of all of it. A tarball of this directory is the
corpus. On 2026-10-23: 42 reports from 25 distinct chips, Milan and Genoa,
report versions 3 and 5, firmware from SNP 0x17 to 0x1d.

| File | What it is |
| - | - |
| `manifest.tsv` | one row per report: id, product line (by CPUID), version, reported TCB, chip id, the files, the SHA-256 of the report, where the VCEK came from, and `source` — where the report was kept in the tree it came from |
| `expected.tsv` | what every verifier must read from each report, taken from the raw bytes at the specification's offsets (AMD 56860, the attestation report) with no verifier involved: version, guest SVN, policy, PLATFORM_INFO, VMPL, the signature algorithm, the four TCBs, the measurement, host data, report data, chip id, both mitigation vectors, both firmware versions, CPUID as FMS; and the verdict, `verifies`, for every report under its VCEK and chain |
| `reports/` | the raw 1184-byte reports, one per id |
| `vcek/` | the VCEKs, DER — copied from beside the report when the kit kept one, otherwise fetched from AMD KDS by the chip id and reported TCB the report names. KDS issues the certificate afresh on every request — the same key for the same chip and TCB, a new `notBefore` (about a day before the request) and a new signature — so a VCEK fetched again is not byte-identical; the corpus keeps the one it fetched first, and `build.py` fetches only what is missing |
| `chains/` | AMD's ASK+ARK bundle per product, as KDS serves it |
| `SHA256SUMS` | the digests of all of the above |
| `results/` | the runs on record (below) |
| `build.py` | makes all of it from the hardware kits' evidence (the standard library only); `--no-fetch` stays offline |

Where the reports come from: the hardware kits of this repository kept
them — the key-release and Return Path kits on GCP Milan, the confidential
GPU and vTPM kits on Azure Genoa — and the restore receipts of the
key-release kits embed the report the destination's chip signed. The
manifest's `source` column names the evidence directory of each; two
files of the demo kits of 2026-10-14/15 are not reports (the kernel's
ioctl response, its signature cut) and are left out. Nothing here is
secret: a report, a VCEK and AMD's chain are what any verifier is handed.

## Run your verifier against it

**Any language.** The harness runs a command once per report and reads one
JSON object from its standard output:

```bash
python3 -I tools/corpus-harness/run.py --corpus test/corpus/sev-snp \
  --cmd 'myverifier --report {report} --vcek {vcek} --chain {chain}' --mutants 8 --record run.json
```

The object must carry `verified` (true or false); every other field is
optional and, when present, is held to `expected.tsv`: `measurement_hex`,
`chip_id_hex`, `report_data_hex`, `host_data_hex`, `version`, `policy`,
`platform_info`, `reported_tcb`, `current_tcb`, `committed_tcb`,
`launch_tcb` (numbers as integers or `0x…` strings). `--mutants N` flips
N bytes of each report, spread over the signed body and the signature,
and requires `verified: false` for every one. Two adapters come with the
harness: `adapters/oracle.py` for Google's go-sev-guest through
`tools/oracle`, and `adapters/snpguest.py` for VirTEE's `snpguest`
(Linux x86-64).

**Go.** The corpus is part of the public conformance package:

```go
teeconformance.RunSEVSNPCorpus(t, "test/corpus/sev-snp", func(report, vcek, chain []byte) (teeconformance.SEVSNPReading, error) { … })
```

Every report must verify with the fields the corpus expects, and two
mutants of each — a byte of the measurement, a byte of the signature —
must be refused. The product's own reading is the first user
(`internal/shared/tee/sev_snp_corpus_test.go`).

## The runs on record

- `results/differential-ci-20261022T222534Z.json` — the product, Google's
  go-sev-guest and VirTEE's `snpguest` on every report, nineteen fields
  equal, no single-byte mutant of the 1184 verified by either library
  reading; the `differential` workflow's first green run (ADR 0034, C47).
- `results/differential-20261022T220839Z.json` — the local run after the
  first run's finding was fixed (the reserved bytes of the signature
  block), the Google reading alone.
- `results/differential-20261023T205052Z.json` — the corpus at 42 (the
  receipt of the 0.10.0 record added), the Google reading alone: both
  verify every report, nineteen fields equal, no mutant verified by
  either.
- `results/differential-ci-20261023T205603Z.json` — the `differential`
  workflow on the corpus at 42 (run 40022715298, ubuntu-24.04 x86-64):
  the product, Google's go-sev-guest and VirTEE's `snpguest` verify
  every report, nineteen fields equal, no single-byte mutant verified by
  either library reading.
- `results/harness-oracle-20261023T205108Z.json` — the harness with the
  Google adapter: 42 reports, eleven fields each, eight of eight mutants
  refused on each.

## Licence

This directory — the reports, the manifest, the expected values, the
script and this text — is licensed under the Apache License, Version 2.0
([`LICENSE`](LICENSE) here), so that any verifier can carry the corpus in
its own tests; the harness (`tools/corpus-harness`) and the public
conformance package (`pkg/teeconformance`) are Apache-2.0 too, while the
product around them stays AGPL-3.0-or-later (ADR 0003, amendment of
2026-10-23). AMD's certificates are AMD's, redistributed here as its Key
Distribution Service serves them.
