# The corpus harness — any SEV-SNP verifier against the corpus (ADR 0034, part four)

`run.py` runs a verifier, given as a command, once per report of
`test/corpus/sev-snp/` with the report, the VCEK it verifies under and
AMD's chain for its product, reads one JSON object from the verifier's
standard output, holds the fields it exposes to `expected.tsv`, and with
`--mutants N` flips N bytes of each report across the signed body and the
signature and requires every one refused. The standard library only; exit
0 when every report verified as expected and every mutant was refused.

```bash
go build -C tools/oracle -o /tmp/oracle .
python3 -I tools/corpus-harness/run.py --corpus test/corpus/sev-snp --mutants 8 --record /tmp/harness-oracle.json \
  --cmd 'python3 -I tools/corpus-harness/adapters/oracle.py --oracle /tmp/oracle --report {report} --vcek {vcek} --chain {chain}'
python3 -I tools/corpus-harness/run.py --corpus test/corpus/sev-snp --mutants 8 --record /tmp/harness-snpguest.json \
  --cmd 'python3 -I tools/corpus-harness/adapters/snpguest.py --snpguest ~/.cargo/bin/snpguest --report {report} --vcek {vcek} --chain {chain}'
```

The JSON the verifier prints: `verified` (required), and any of
`measurement_hex`, `chip_id_hex`, `report_data_hex`, `host_data_hex`,
`version`, `policy`, `platform_info`, `reported_tcb`, `current_tcb`,
`committed_tcb`, `launch_tcb`. The two adapters show the shape: one for
Google's go-sev-guest (`tools/oracle`), one for VirTEE's `snpguest`
(Linux x86-64; it verifies the chain and the report and reads the
measurement and chip id from `snpguest display report`).
