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

The TDX twin: `../../gcp-tdx/returnpath-soak/`.
