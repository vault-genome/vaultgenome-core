# returnpath-parallel — sessions in parallel on SEV-SNP, measured

The returnpath-e2e guest up to the sealed genome, then two rounds with N
workers (`VG_WORKERS`, default 3; the real CPU door) and 2N queued jobs
each: the authority at `runtime.max_sessions: 1` and at `N`. Each round
records the wall time from the first submission to the last verdict,
every session's `handshake_ms`, the peak of `sagvd_sessions_active`, the
queue depth, the refusals (busy) and the verdicts; both rounds are on one
audit chain, verified at the end. The guest is an n2d-standard-8
(`VG_MACHINE`).

```bash
VG_WORKERS=3 scripts/hardware-test/gcp-sev-snp/returnpath-parallel/run.sh <project> [zone]
```

Run on record: `evidence/20261016T122044Z/` (claim C32) — 28.7 s at one
session at a time, 17.2 s at three, twelve jobs EXACT; and the host's
rate limit on the chip's guest requests, found by the run
(KNOWN_ISSUES #17). The TDX twin: `../../gcp-tdx/returnpath-parallel/`.
