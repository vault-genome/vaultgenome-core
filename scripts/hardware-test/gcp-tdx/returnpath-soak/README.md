# returnpath-soak — one authority and N workers for an hour on TDX

The TDX twin of `../../gcp-sev-snp/returnpath-soak/`: the returnpath-e2e
guest up to the sealed genome on a c3 Trust Domain, then sagvd at
`runtime.max_sessions: N` with N workers (`VG_WORKERS`, default 3; the real
CPU door) and 2N jobs kept in flight for `VG_SOAK_MINUTES` (default 60).
Every completion is recorded with its queue, run and total time
(`jobs.csv`); every minute the daemons' resident memory and open
descriptors, the load and sagvd's session, queue, handshake-failure and
refusal metrics (`snapshots.csv`); the logs are kept by their sizes,
warnings, ends and every `handshake_ms`; the audit log of the whole soak is
verified and counted by kind at the end. The guest is a c3-standard-8
(`VG_MACHINE`).

```bash
VG_WORKERS=3 VG_SOAK_MINUTES=60 scripts/hardware-test/gcp-tdx/returnpath-soak/run.sh <project> [zone]
```

After the run, `../../gcp-sev-snp/returnpath-soak/summarize.py <evidence dir>`
derives the percentiles, the rate and the drifts into `summary.json`.

Run on record: `evidence/20261016T130106Z/` (claim C33) — 2429 jobs in
sixty minutes, every one EXACT, nothing refused or failed; 40.4 a minute
from the first minute to the last, p50 8.6 s and p99 9.3 s from
submission to verdict, handshakes p50 94 ms and none above half a
second; 38,864 audit events verified in 3.2 s; and the authority's
memory 16 → 280 MB over the hour (KNOWN_ISSUES #18).
