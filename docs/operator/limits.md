# Limits, as measured

**Audience:** the operator sizing a deployment, and anyone deciding
whether a number here is enough for them. Every figure is from a run on
record (its claim in [`VERIFIABLE-CLAIMS.md`](../../VERIFIABLE-CLAIMS.md)
or its evidence directory); what has not been measured is said so.

## One authority

| Limit | Value | Where measured |
| - | - | - |
| Sessions served at once | `runtime.max_sessions` (1 unless set); the kit below ran 3 workers on one n2d-standard-8 | `scripts/hardware-test/gcp-sev-snp/returnpath-parallel` (see the table below) |
| Jobs in flight | one per session; the rest wait in the queue on disk (`queue.path`, ADR 0026) and survive a restart | C27, C28 |
| Handshake, builtin verifiers | 219 ms sagvd / 220 ms worker on one n2d (the first handshake fetches the VCEK from KDS; later ones read the cache) | C31 |
| Handshake, delegated to a Verifier on another VM | 145 ms / 146 ms, mutual TLS by name | C31 |
| Evidence on the wire | 7980 bytes each way for SEV-SNP (the 1184-byte report with the host's certificate table); 10704 bytes for TDX | C31, wire 1.1 |
| Handshake and evidence, Azure SEV-SNP (`azure-sev-snp`) | 104 ms on a DC4as_v5 with both daemons on it; 4515 bytes each way (the vTPM's 2900-byte HCL report and the TPM quote) | C36 |
| Authority lost, the same authority back on a fresh chip | 49–50 s from a standby with the runtime in place | C28 |
| Air-gapped, from caches filled while connected | the same flow, no route; the VCEK cache good for seven years | C29 |
| Sustained: one host, three workers, an hour | 40.4 jobs a minute on TDX, 26.7 on SEV-SNP (the chip's throttle, below); every job EXACT, nothing refused or failed, the hour's audit log one verified chain | C33 (the soak, below) |
| Authority's private memory under load | 9–15 MB over two hours of three workers (4901 jobs on TDX, 3223 on SEV-SNP), flat within the collector's swing; the first soak found 110 KB a job retained, fixed the same day | C34, KNOWN_ISSUES #18 |
| Disk per job served | 48–52 KB: the audit log 34–37 KB (sixteen events), the job's view 14–16 KB; 2.8 GB a day at 40 jobs a minute; the daemon's resident set carries the touched pages of both bbolt files as file-backed memory, the kernel's to reclaim; nothing rotates them yet | C34 |

## Parallel restores on one host

Run `20261016T122044Z` (`scripts/hardware-test/gcp-sev-snp/returnpath-parallel`,
claim C32): one n2d-standard-8, three workers (the real CPU door), six
jobs per round, the same sealed genome, every job EXACT.

| `max_sessions` | Wall time, first submission → last verdict | Per job | Peak `sessions_active` | Peak queue depth | Handshakes (ms, in order) |
| - | - | - | - | - | - |
| 1 | 28.7 s | 4.8 s | 1 | 4 | 10436, 28, 28, 22, 23, 25, 24 |
| 3 | 17.2 s | 2.9 s | 3 | 2 | 49, 10299, 10299, 1521, 25, 29, 33, 28, 25 |

**The chip's own limit, found by this run.** A handshake costs about 25 ms
once the VCEK cache is warm — except the ones that hit the host's rate
limit on SEV-SNP guest requests: the authority's report for a session,
and each worker's report at startup, is a request to the chip through
the kernel's sev-guest driver, and on this host a burst of requests
leaves all but the first answered about 10 s later (`handshake_ms`
10436 / 10299 / 1521; `vg_tee_attestation_duration_seconds` on the
authority's side: 7 quotes in round 1 of which one took 10.2 s, 9 in
round 3 of which two took 11.8 s together; the three workers' own
identity reports at startup all answered 10.3 s after they asked). No
kernel message marks it; the driver retries the host's «busy» answer
and succeeds on the schedule above. So: one SEV-SNP guest serves a burst
of N handshakes at the cost of about 10 s for all but the first; sessions
that arrive spaced out cost 25 ms each. Stagger workers' dials
(`dial_backoff_initial_ms`, `idle_between_jobs_ms`) rather than start a
fleet at the same second, and size `max_sessions` for the host's cores,
not for the chip. Whether Intel TDX guests on GCP throttle the same way
is measured by the TDX twin of the kit (see below).


**The TDX twin** (`scripts/hardware-test/gcp-tdx/returnpath-parallel`, run
`20261016T123114Z`, one c3-standard-8 Trust Domain, the same three
workers and six jobs per round, every job EXACT):

| `max_sessions` | Wall time | Per job | Peak `sessions_active` | Peak queue depth | Handshakes (ms, in order) |
| - | - | - | - | - | - |
| 1 | 23.7 s | 3.9 s | 1 | 4 | 425, 87, 84, 85, 85, 85, 87 |
| 3 | 9.6 s | 1.6 s | 3 | 2 | 90, 165, 122, 124, 255, 148, 90, 160, 151 |

No throttling on TDX: the authority's nine quotes in round 3 took 0.52 s
together (none above 250 ms), the workers' identities came three seconds
after they started (the vTPM unsealing their key files, not the chip
waiting), and three sessions opening at once cost 90–165 ms each. The
TDX guest's quote goes to the host's quoting service over a different
path than SEV-SNP's guest request, and on GCP it is not rate-limited the
same way. A bank that wants many handshakes per second on one authority
host has its answer in these two tables.

Workers are the real door: the model restored in memory on the guest's
CPU. N workers contend for the cores, so the per-job time at N is the
host's to give, not the protocol's. A fleet puts workers on their own
machines; the authority's cost per session is the handshake, the
disclosures and the gate, measured above.

## One authority over an hour (the soak)

Runs `20261016T130106Z` (`scripts/hardware-test/gcp-tdx/returnpath-soak`)
and `20261016T130128Z` (`scripts/hardware-test/gcp-sev-snp/returnpath-soak`),
claim C33: one host for the authority and three workers (the real CPU
door), `runtime.max_sessions: 3`, six jobs kept in flight for sixty
minutes on the same sealed genome; every completion timed from the job
view's own stamps, the daemons' memory and descriptors and the
authority's metrics snapshotted every minute; the kit's `summarize.py`
derives every number below from the evidence.

| | TDX, c3-standard-8 | SEV-SNP, n2d-standard-8 |
| - | - | - |
| Jobs in sixty minutes, every one EXACT | 2429 | 1607 |
| Jobs a minute (the slowest and fastest minute) | 40.4 (38–42) | 26.7 (24–30) |
| Submission → verdict, p50 / p90 / p99 / max | 8.58 / 8.71 / 9.26 / 9.41 s | 11.30 / 17.34 / 17.74 / 17.98 s |
| of which waiting for a session, p50 / p99 | 4.42 / 4.79 s | 6.34 / 12.69 s |
| of which the worker's restore and answer, p50 / p99 | 4.15 / 4.50 s | 4.95 / 5.21 s |
| The first ten minutes → the last ten, p50 | 8.58 → 8.59 s | 11.35 → 11.29 s |
| Handshake, p50 / p90 / p99 / max | 94 / 107 / 126 / 490 ms | 58 ms / 6.16 s / 6.20 s / 10.3 s |
| Handshakes above one second | 0 of 2432 | 767 of 1609 (48 %) |
| Refused (busy) / handshake failures / jobs failed | 0 / 0 / 0 | 0 / 0 / 0 |
| Audit events (sixteen a job), verified at the end | 38,864 in 3.2 s | 25,712 in 2.4 s |
| Authority's resident memory, start → end | 16 → 280 MB (+108 KB a job) | 17 → 205 MB (+117 KB a job) |
| Authority's open descriptors | 13, at most 14 | 13, at most 14 |
| The three workers' resident memory | 48 → 51 MB | 39 → 50 MB |
| Load (one minute) on 8 vCPU, mean / max | 3.3 / 4.9 | 3.3 / 5.0 |

**What the numbers say.** The submitter keeps six jobs in flight, so each
job waits for roughly one job ahead of it before its session opens: the
queue time is the restore time of the job before, and the figure to size
by is the rate, not the latency. The rate is the workers' restore time
plus the handshake: on TDX three workers at 4.15 s a restore and 94 ms a
handshake give 40 jobs a minute; on SEV-SNP 4.95 s a restore and the
host's throttle (half of the handshakes wait 1–7 s, 2610 s of waiting in
the hour across the three workers) give 27. Neither chip drifted: the
median job of the last ten minutes is the median job of the first ten,
and the per-minute count stayed within four of its mean. No refusal, no
handshake failure, no warning or error in any daemon's log; the hour's
audit log — 38,864 events on TDX, 25,712 on SEV-SNP, sixteen a job in
ten kinds — is one chain that verifies under the published key.

**What the soak found, and what the fix shows.** The authority's resident
memory grew linearly, about 110 KB for every job served, on both chips;
the workers' memory and the authority's descriptors stayed flat. Three
things kept every job: the in-memory job map held each finished job's
flow and verdict although the store on disk already had the view (ADR
0026); the persistent audit chain kept every sealed event in memory and
loaded them all when it opened; the session issuer kept every session it
ever issued. KNOWN_ISSUES #18 has the three fixes. The same soak, run for
two hours on the fixed code (claim C34; runs `20261016T174732Z` on TDX
and `20261016T174802Z` on SEV-SNP), with the resident set split into
anonymous pages — the heap and the stacks — and file-backed pages — the
two bbolt files the daemon maps:

| | TDX, c3-standard-8 | SEV-SNP, n2d-standard-8 |
| - | - | - |
| Jobs in 120 minutes, every one EXACT | 4901 | 3223 |
| Jobs a minute (the slowest and fastest minute) | 40.8 (39–42) | 26.8 (24–31) |
| Submission → verdict, p50 / p99 | 8.51 / 8.71 s | 11.50 / 17.93 s |
| The first ten minutes → the last ten, p50 | 8.45 → 8.54 s | 11.58 → 11.46 s |
| Handshake, p50 / p90 / max | 92 / 105 / 545 ms | 46 ms / 6.17 s / 20.3 s |
| Handshakes above one second | 0 of 4904 | 1309 of 3224 (41 %) |
| Refused (busy) / handshake failures / jobs failed | 0 / 0 / 0 | 0 / 0 / 0 |
| Audit events, verified at the end | 78,416 in 6.3 s | 51,568 in 5.0 s |
| Authority's anonymous memory, start → end (never above) | 6.5 → 12.2 MB (14.6) | 6.0 → 11.4 MB (13.8) |
| … over the last hour | 9.8–14.6 MB | 9.1–13.8 MB |
| Authority's file-backed memory, start → end | 10 → 103 MB | 10 → 88 MB |
| The two bbolt files after two hours (audit log, views) | 168 MB, 67 MB | 117 MB, 50 MB |
| Authority's open descriptors | 13, at most 14 | 13, at most 14 |

The anonymous line is flat: it rises in the first ten minutes as the
heap finds its size and then swings between 9 and 15 MB for the rest of
the two hours, on both chips, where the first soak's rate would have
put 540 MB on TDX. The file-backed line follows the two files on disk
— the audit log at 2.1–2.3 KB an event, sixteen events a job, and the
views at 14–16 KB a job — as the kernel keeps the pages the daemon has
touched; it is the page cache, reclaimed under pressure, not the
process's own. So the authority's memory to size is its private
working set, tens of megabytes at this rate; what to size for the
months is the disk, 48–52 KB a job, and nothing rotates it yet. The
two-hour runs between the first two fixes and the third
(`20261016T153617Z`, `20261016T153649Z`) are on record too: they are
where the anonymous line still rose about a kilobyte a job and pointed
at the session issuer.

## Models

| Limit | Value | Where measured |
| - | - | - |
| Largest model through the genome path | 32B, EXACT on a confidential H100 | C26 |
| Genome size | 2.2 MB for 0.5B (1/447 of the weights), 10 MB for 7B (1/1502), 33.6 MB for 32B | C16, C26 |
| Cross-device equivalence (the integer door) | the same bytes on an Intel Xeon and an NVIDIA L4 at 0.5B and 7B | C19 |
| 70B | not measured: one 94 GB confidential H100 does not hold a 140 GB bfloat16 model | ROADMAP |

## Failover

| Limit | Value | Where measured |
| - | - | - |
| Detect → restored and gated, SEV-SNP to SEV-SNP | detect 2.53 s, RPO 9.0 s, RTO 16.81 s | C14 |
| To an Azure confidential H100 across the Internet | RTO 24.99 s | C18 |
| To an Intel TDX Trust Domain | RTO 24.09 s | C21 |

## Not measured yet

Longer than an hour (the memory growth of KNOWN_ISSUES #18 bounds it
until fixed), many workers on many hosts against one authority, a
Verifier across the Internet, more than one confidential GPU in one
restore.
