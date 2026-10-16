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
| Authority lost, the same authority back on a fresh chip | 49–50 s from a standby with the runtime in place | C28 |
| Air-gapped, from caches filled while connected | the same flow, no route; the VCEK cache good for seven years | C29 |

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

Throughput of one authority over hours (a soak), many workers on many
hosts against one authority, a Verifier across the Internet, more than
one confidential GPU in one restore.
