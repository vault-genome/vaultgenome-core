# returnpath-parallel (TDX) — the TDX twin of gcp-sev-snp/returnpath-parallel

The same two rounds (N workers, 2N jobs, `runtime.max_sessions` 1 then
N) on a c3-standard-8 Intel TDX Trust Domain, derived from
`../returnpath-e2e/cvm-returnpath-tdx.sh`. Besides the parallel numbers
it answers one question the SEV-SNP run raised: whether a burst of
attestation requests on a GCP TDX guest is rate-limited the way SEV-SNP
guest requests are (KNOWN_ISSUES #17).

```bash
VG_WORKERS=3 scripts/hardware-test/gcp-tdx/returnpath-parallel/run.sh <project> [zone]
```

Run on record: `evidence/20261016T123114Z/` (claim C32) — 23.7 s at one
session at a time, 9.6 s at three, twelve jobs EXACT, no throttling:
three sessions opening at once at 90–165 ms each.
