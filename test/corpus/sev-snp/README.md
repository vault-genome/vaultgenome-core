# The SEV-SNP corpus — every genuine report on record, for the differential test (ADR 0034)

`manifest.tsv` names every genuine AMD SEV-SNP attestation report this tree
holds — the raw reports the hardware kits kept and the reports embedded in
the restore receipts of the key-release kits — with the VCEK each one
verifies under and AMD's ASK+ARK chain for its product. `build.py` makes it
(the standard library only): it walks `scripts/hardware-test`, keeps a file
only if it is a report (1184 bytes, VERSION 2–5, ECDSA P-384 named), takes
the VCEK from beside the report when the kit kept one and otherwise from AMD
KDS by the chip id and reported TCB the report carries, and fetches each
product's chain from KDS once. `reports/` holds the reports extracted from
receipts, `vcek/` the certificates fetched, `chains/` the product chains,
`SHA256SUMS` the digests of all of it. Nothing here is secret: a report, a
VCEK and AMD's chain are what any verifier is handed.

`internal/shared/tee/differential_test.go` (build tag `differential`) walks
the manifest and holds the product's reading of every report against
Google's go-sev-guest (`tools/oracle`) and VirTEE's `snpguest`: the verdict,
the fields, and the refusal of every single-byte mutant.

```bash
python3 -I test/corpus/sev-snp/build.py        # rebuild after a kit adds a report; --no-fetch stays offline
make differential                              # the test; VG_SNPGUEST=/path/to/snpguest adds the VirTEE leg
```
