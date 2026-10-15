# ADR 0026 — The job queue is on disk: a restart resumes what was accepted

- **Status:** Accepted (2026-10-15)
- **Tags:** sagvd, queue, durability, restart, bbolt, audit
- **Extends:** ADR 0014 (the Return Path audit log), ADR 0015 (the nine-stage flow)

## Context

`sagvd` kept its accepted jobs in memory. A restart — a crash, a host
lost, an upgrade — forgot every job that was queued or in flight, and the
disaster-recovery runbook's scenario 4 said so: "jobs that were queued or
running are gone — resubmit them." The authority-loss drill of 2026-10-15
measured exactly that on real SEV-SNP: a fresh host became the same
authority in fifty seconds from its runtime being ready, and the one
thing it could not do was continue the job the old host had in flight —
an operator had to submit it again (KNOWN_ISSUES #16). For a bank's
operation that is a gap: the authority's own restart is routine, and a
job the operator accepted must not depend on the operator noticing.

The audit log was already on disk (bbolt, ADR 0014) and already the
record of every decision; what was missing was the record of what had
been *accepted and not yet decided*.

## Decision

1. **A job store beside the audit log.** `queue.path` names a bbolt file
   of the daemon's own (`internal/vault/jobstore`). Every submission
   writes a record — the request as accepted, re-encoded, with its
   request id fixed; the resolved deadline; the first acceptance time;
   the status; the number of admissions — and every transition of the
   in-memory queue (queued, running, requeued, succeeded, failed) updates
   it. A finished job also leaves its view, as `GET /v1/jobs/{id}`
   renders it, so the answer outlives the process.
2. **At start, what was unfinished is admitted again.** Before the API
   serves and before the dispatcher runs, the daemon takes every record
   that is queued or running — oldest acceptance first — and runs the
   submission path for it under the same job id and the same request id,
   as one more attempt: the genome inspected again, the request admitted
   at intake again, `REQUEST_RECEIVED` on the record again with a
   `resumed` detail that names the attempt and the reason. The job then
   runs as any other. The worker's answer to the old process, if it ever
   arrives, lands on a dead connection; the resumed job is dispatched
   afresh — gate jobs are idempotent, and the verdict is signed once per
   dispatch, on the record.
3. **What cannot be resumed is failed on the record, not dropped.** A
   record without its request, a record admitted `queue.max_resume_attempts`
   times (default 3) and never finished — a job that crashes the
   authority must not crash it forever — or a request the admission
   refuses (the bundle gone, the key file gone) becomes a failed job with
   the reason, visible to `GET /v1/jobs/{id}`, and counted in
   `sagvd_jobs_resume_failed_total`. Resumed jobs count in
   `sagvd_jobs_resumed_total`.
4. **The store is the record, not the authority.** A store write that
   fails is logged, and the job goes on in memory: durability is what is
   lost, not the decision, whose record is the audit log. The store never
   holds plaintext of a genome or a key; it holds what the submission
   named.
5. **Without `queue.path`** the queue is in memory as before, and the
   daemon says at start what that loses when gate jobs are enabled. The
   reference deployment, the compose deployment and the hardware kits set
   it.

## Consequences

- An authority's restart on the same host loses nothing it accepted:
  proven by the integration test
  `TestLiveDaemons_JobsSurviveAHardKillOfTheAuthority`, which kills `sagvd`
  with SIGKILL in the middle of a job behind a four-second door, restarts
  it on the same configuration, and sees the job in flight and the one
  behind it admitted again and finish EXACT, the job finished before the
  kill answer as it was, two `REQUEST_RECEIVED` records carrying
  `resumed`, and the audit chain verify across the crash.
- A host lost needs the store's file in the operator's replica beside the
  audit log and the genomes, taken the moment a job is accepted: the
  authority-loss drill's run `20261015T204339Z` copied it so, and the lost
  job resumed by itself on the new host — the same job id and request id,
  `resumed` attempt 2 on the record, EXACT — instead of being resubmitted.
- `queue.path` is one more file the daemon holds open; it must not be the
  audit log's file, and the configuration refuses that.
- The audit record of a resumed request carries the same request id as
  the first admission: one request, admitted twice, the second time saying
  why. An auditor who counts `REQUEST_RECEIVED` per request id sees the
  restart.

## Alternatives rejected

- **Persist the flow object itself** (the nine stages' state and signed
  artifacts) and continue from the stage reached. The flow's session is
  gone with the process — a worker attests per session — so continuation
  past intake is not possible; re-admission is honest about that and
  keeps one code path for a job.
- **Keep the queue in memory and rely on resubmission** (the previous
  state). Puts an operator in the loop of every restart.
- **A message broker.** A dependency and a trust boundary for a queue of
  one authority; bbolt is already in the binary and the audit log's
  pattern.
