# returnpath-soak — one authority and N workers for an hour on SEV-SNP

The returnpath-e2e guest up to the sealed genome, then the soak: sagvd at
`runtime.max_sessions: N` with N workers (`VG_WORKERS`, default 3; the real
CPU door) and 2N jobs kept in flight for `VG_SOAK_MINUTES` (default 60).
Every completion is recorded with its queue, run and total time from the
job view's own timestamps (`jobs.csv`); every minute the daemons' resident
memory and open descriptors, the load and sagvd's session, queue,
handshake-failure and refusal metrics (`snapshots.csv`); the logs are kept
by their sizes, their warnings and errors, their ends and every
`handshake_ms`; the audit log of the whole soak is verified with the
published key and counted by kind at the end. The guest is an
n2d-standard-8 (`VG_MACHINE`).

```bash
VG_WORKERS=3 VG_SOAK_MINUTES=60 scripts/hardware-test/gcp-sev-snp/returnpath-soak/run.sh <project> [zone]
```

After the run, `summarize.py <evidence dir>` derives the percentiles, the
rate and the drifts from `jobs.csv` and `snapshots.csv` into
`summary.json` beside them.

Run on record: `evidence/20261016T130128Z/` (claim C33) — 1607 jobs in
sixty minutes, every one EXACT, nothing refused or failed; 26.7 a minute,
p50 11.3 s and p99 17.7 s from submission to verdict, half of the
handshakes held 1–7 s by the host's throttle (KNOWN_ISSUES #17); 25,712
audit events verified in 2.4 s; and the authority's memory 17 → 205 MB
over the hour (KNOWN_ISSUES #18). The TDX twin: `../../gcp-tdx/returnpath-soak/`.
