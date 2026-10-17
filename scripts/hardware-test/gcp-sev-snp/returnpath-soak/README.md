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

With `VG_SEGMENT_EVENTS=N` the authority closes its audit log into
segments of N events and with `VG_RETAIN_SECONDS=S` it expires finished
jobs after S seconds (ADR 0027; both 0 unless set, as 0.5.0 behaved).
The snapshots then carry the live file, the archives and the views in
bytes with the two counters; at the end the whole log is verified across
its archives (`audit-verify.json`, `archives.txt`), the oldest archive is
moved away and the verifier refuses, then verifies with `--from-tip`
(`audit-verify-shipped.json`, `audit-verify-from-tip.json`), a copy with
one byte appended to an archive is refused (`audit-verify-tampered.json`),
and sagvd is started again over the log to time its open
(`restart_ready_seconds` in `steps.txt`, `restart-audit-open.json`).

Run on record: `evidence/20261016T130128Z/` (claim C33) — 1607 jobs in
sixty minutes, every one EXACT, nothing refused or failed; 26.7 a minute,
p50 11.3 s and p99 17.7 s from submission to verdict, half of the
handshakes held 1–7 s by the host's throttle (KNOWN_ISSUES #17); 25,712
audit events verified in 2.4 s; and the authority's memory 17 → 205 MB
over the hour (KNOWN_ISSUES #18).

Two-hour runs after the fix: `evidence/20261016T153649Z/` (the first two
fixes; the authority's anonymous memory 6.4 → 11.8 MB over 3225 jobs)
and `evidence/20261016T174802Z/` (claim C34, the finished fix: 3223 jobs,
every one EXACT, anonymous memory 6.0 → 11.4 MB and never above 13.8 MB,
file-backed 10 → 88 MB with the audit log at 117 MB and the views at
50 MB on disk). The TDX twin: `../../gcp-tdx/returnpath-soak/`.
