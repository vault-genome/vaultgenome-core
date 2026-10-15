# The authority-loss drill: the release authority's host taken away in the middle of a job, a fresh host becomes it

The failover drills ([gcp-failover](../gcp-failover), [failover-tdx](../failover-tdx),
[failover-tdx-authority](../failover-tdx-authority)) lose a *primary* and
measure how the authority moves the model. This drill loses the
**authority itself** — `sagvd`, the process that signs every verdict and
holds the escrow key — and measures how long until a fresh host *is* that
authority again: the same signing identity, the same escrow key, the same
audit chain, continued. The disaster-recovery runbook's
[scenario 4](../../../docs/operator/runbooks/disaster_recovery.md#scenario-4-vault-authority-sagvd-unreachable)
names the procedure; this drill puts numbers on it.

```bash
bash scripts/hardware-test/authority-loss/run.sh <gcp-project> [zone]
```

`run.sh` builds `sagvd`, `acp-compute`, `acpctl` and `acp-keygen` for
linux/amd64, packs `workers/genome` with its locks, and boots two AMD
SEV-SNP Confidential VMs (`n2d-standard-4`, AMD Milan) one after the other:

- **A** ([`authority-a.sh`](authority-a.sh)) — the authority and its worker
  on one chip, as in [gcp-sev-snp/returnpath-e2e](../gcp-sev-snp/returnpath-e2e).
  Before anything is sealed to the chip, the key material `acp-keygen
  -private` made goes to the **operator's safe** (an object in the run's
  private bucket, standing in for a secrets manager or an HSM-backed
  store); then every key file is sealed in place (`sagvd seal-keys`,
  `acp-compute seal-keys`, [ADR 0023](../../../docs/adr/0023-key-files-sealed-to-the-tee.md)).
  The escrow key is made inside `sagvd`, sealed to this chip and wrapped
  to the operator's recovery key (`sagvd escrow-provision`,
  [ADR 0016](../../../docs/adr/0016-the-escrow-key-sealed-to-the-tee.md));
  the envelope goes to the safe. A fine-tunes a tiny model, seals it as
  gen-0, and runs gate jobs over the Return Path in a loop, **replicating
  its state** — the audit log, the genomes and the job store
  ([ADR 0026](../../../docs/adr/0026-the-job-queue-on-disk.md)) — to the
  bucket the moment each job is accepted and again when it is done, and
  marking every job's submission, its replica and its completion.
- The runner waits until A has completed three jobs, then **deletes A
  while a job is in flight** — once A has marked the replica with that
  job in it — (`gcloud compute instances delete`, no warning to the
  guest) and records the moment.
- **B** ([`authority-b.sh`](authority-b.sh)) — a fresh VM, created at that
  moment. It takes the key material from the safe and seals it to *its*
  chip; takes the last replica and verifies the audit chain as replicated;
  re-provisions the escrow key through the recovery ceremony
  (`acpctl escrow recover | sagvd escrow-provision -stdin`); starts both
  daemons over the replicated audit log and job store — `sagvd` admits
  again, by itself, the job the store holds as accepted and unfinished;
  finds which job A lost (submitted, never completed) and checks it is the
  one resumed, by job id and by request id; waits for its verdict — the
  first after the loss — and runs a fresh job after it. (Without a job
  store in the replica, as in the first three runs, B submits the lost job
  again.) Then the whole chain — A's events and B's — is verified offline
  under the published audit key.
- Both records come back to `evidence/<stamp>/`; both VMs and the bucket
  are deleted on exit, on success or failure.

Three recovery times come out (`evidence/<stamp>/timeline.txt`):

| Number | From | To | What it says |
| - | - | - | - |
| **RTO cold** | A's deletion issued | B's first verdict | B created on demand: VM creation, boot, the runtime from the locks, everything |
| RTO from B's first line | B's script starts | B's first verdict | what the procedure itself takes on a bare image |
| **RTO warm** | B's runtime ready | B's first verdict | what a standby that already has the runtime needs: restore, seal, ceremony, start, first job |

and four facts, checked by the runner from the two records: the authority
signing key and the audit signing key the same on A and B (`sagvd
identity` on each), the escrow key the same after the ceremony
(`escrow-provision.json` on A, `escrow-reprovision.json` on B), the
replica's chain intact before B appends to it, and the final chain — A's
events and B's in one file — intact under the one audit key.

## What is the same on B, what is lost

**The same**: the authority's identity (its signing kid and key, its audit
kid and key, its TLS certificate, its API token, its worker registry) —
all from the safe, sealed to B's chip; the escrow key, from the envelope
through the ceremony; the audit chain, from the last replica; the genomes.
The worker's identity too (the same seed, the same client certificate):
the registry on B accepts it as it did on A.

**Lost**: anything A appended to its audit log after the last replica —
the drill replicates when a job is accepted and when it is done, so the
lag is at most the events of the job in flight after its acceptance; the
replica manifest says after which job, and at which of the two moments,
it was taken. The job in flight is **not** lost once the job store
travels in the replica (ADR 0026): `sagvd` on B admits it again by
itself, with the same job id and request id, and its audit record says so
(`resumed`). The three runs before the job store was in the replica
resubmitted it (runbook scenario 4 then: "jobs that were queued or
running are gone — resubmit them").

**Not the same, by design**: B's launch measurement is B's own; both
daemons read it from the chip and pin each other's, as A's did (on the
same image it is the same value).

## Result — run `20261015T204339Z`: the job store in the replica — the lost job resumed by the new host itself

The same drill with one more file in the replica: `queue.path`, the job
store ([ADR 0026](../../../docs/adr/0026-the-job-queue-on-disk.md)),
replicated the moment a job is accepted — the store then holds it as
accepted and unfinished — and again when it is done. A raw copy of the
bbolt file while `sagvd` writes it is a committed state of it: measured
before the run, 1 647 copies taken during continuous writes all opened
and read back. The runner waits for A's mark that the replica holds the
job in flight before it deletes A. B restores the replica and starts
`sagvd` over it; nothing is resubmitted.

| | [`20261015T204339Z`](evidence/20261015T204339Z/) |
| - | - |
| Jobs A completed; the job lost | 5; the 6th — submitted at 20:48:19Z and replicated the same second (`b/replica-manifest.json`: `after_job 6, when accepted`); A gone before it finished (the deletion, issued at 20:48:12.9Z, took 24.6 s to land) |
| The replica | 81 events — the five jobs' 80 and the lost job's `REQUEST_RECEIVED` — verified before `sagvd` touched it (`b/audit-verify-replica.json`), and the job store with the job in it |
| `sagvd` on B at start | `sagvd audit log open … events=81`; `sagvd job resumed after a restart`: job `e305630c…`, request `req-2e6c0bc9…`, attempt 2, `submitted_at` 20:48:19Z; `sagvd jobs from before the restart: resumed=1 failed=0` |
| The resumed job | A's lost job, by job id and by request id (`b/steps.txt`: `same_job_id=true same_request_id=true`, against `a-job-6-submit.json`, A's own submission record from the bucket); `succeeded`, **EXACT**, 6 of 6; its `REQUEST_RECEIVED` on the chain carries `resumed: {attempt: 2, …}` |
| A's deletion: issued → gone | 24.6 s |
| B created (issued → created) | 12.3 s |
| B's boot until its first line | 68.1 s |
| B's runtime from the locks | 78.1 s |
| the replica restored | 1.4 s |
| identities, the replica verified, the key files sealed | 10.5 s |
| the recovery ceremony | 11.0 s |
| both daemons up, the session open | 21.6 s |
| the first verdict after the loss — the resumed job's | 4.6 s |
| **RTO cold** — deletion issued → the resumed job's verdict | **233.5 s** |
| RTO from B's first line | 128.5 s |
| **RTO warm** — runtime ready → the resumed job's verdict | **49.1 s** |
| The fresh job after it | `succeeded`, EXACT, 6 of 6 |
| The whole chain | `b/audit-verify.json`: `ok: true`, **113 events** — A's 81 and B's 32 under the one audit key, tip `2a7cb51e…` |
| The same authority | the authority key, the audit key and the escrow key (`fc7eb877…`) the same on A and B; both launch measurements the image's (`7dc7c12e…25acc`) |

Three things the record shows beside the numbers. The replica's lag is now
at most the events of the job in flight after its acceptance: the chain B
took over ends at the lost job's `REQUEST_RECEIVED`, and B's first event
is that request's second `REQUEST_RECEIVED`, saying `resumed`. The
runner's view of "the job in flight" (job 5, when it issued the deletion)
is not the job A lost (job 6): a deletion takes some 25 s to land, and in
that time A finished job 5, accepted job 6 and replicated it — but its
mark of that replica (`job-6-synced-accepted`) never reached the bucket;
the drill reads the lost job from A's markers and the replica's manifest,
not from the runner's guess. And A's job loop runs about a second slower
than before (6.1 s a job against 5.3 s): the replica is taken while the
job runs, before the wait for its verdict begins.

## Results — three runs before the job store was in the replica, 2026-10-15

Two `n2d-standard-4` SEV-SNP Confidential VMs (AMD Milan) in
`us-central1-c`, one after the other, Ubuntu 24.04, the tiny fine-tune of
[returnpath-e2e](../gcp-sev-snp/returnpath-e2e); on A a gate job every
eight seconds or so, each 5.3 s, sixteen audit events each.

| | [`20261015T171848Z`](evidence/20261015T171848Z/) | [`20261015T173009Z`](evidence/20261015T173009Z/) | [`20261015T174115Z`](evidence/20261015T174115Z/) |
| - | - | - | - |
| Jobs A completed; the job lost | 4; the 5th | 5; the 6th | 4; the 5th |
| A's deletion: issued → gone | 25.6 s | 27.6 s | 24.2 s |
| B created (issued → created) | 11.3 s | 10.6 s | 9.4 s |
| B's boot until its first line | 68.6 s | 70.3 s | 74.8 s |
| B's runtime from the locks | 79.2 s | 77.8 s | 330.2 s |
| the replica restored | 1.2 s | 1.1 s | 1.1 s |
| identities, the replica verified, the key files sealed | 10.6 s | 10.6 s | 10.5 s |
| the recovery ceremony | 10.3 s | 10.8 s | 10.3 s |
| both daemons up, the session open | 22.2 s | 21.5 s | 22.2 s |
| the first verdict after the loss | 5.4 s | 5.4 s | 5.4 s |
| **RTO cold** — deletion issued → first verdict | **235.8 s** | **237.2 s** | **489.3 s** |
| RTO from B's first line | 130.2 s | 128.6 s | 380.9 s |
| **RTO warm** — runtime ready → first verdict | **49.7 s** | **49.3 s** | **49.5 s** |

**The same authority.** In every run `sagvd identity` on B printed the
authority signing key and the audit key A had (the runner compares the
PEMs: `timeline.txt`), the escrow key came out of the ceremony with A's
tag (`ced42a93…`, `ad0f082e…`, `a08e386a…`), and the worker registry and
the API token were A's, from the safe. Both daemons read the same launch
measurement from their chips (`7dc7c12e…25acc`: the image's).

**The chain continued.** B verified the replica before touching it
(`b/audit-verify-replica.json`: `ok: true`, 64, 80 and 64 events,
with the tip A's last manifest named); `sagvd` on B opened the file and
logged the same count and tip (`b/sagvd.log` of the third run: `sagvd audit
log open … events=64 tip=75b63362…`), and its first verdict after the loss sealed the
next events on that chain (`b/steps.txt`: the job's `tip`). The first two
runs lack the final offline verification of the whole file: their stop
step signalled the daemons' subshells, not the daemons, so `sagvd` still
held the file's lock when `acpctl audit verify` ran
(`b/audit-verify.err`: `open … timeout`) — a bug of the kit, fixed before
the third run, whose `b/audit-verify.json` covers A's events and B's
under the one audit key: `ok: true`, 96 events, tip `c3269c3e…`.

**What was lost.** Exactly the job in flight: A's markers (`a-markers.txt`
from the third run on; `lost_jobs=` in every `b/steps.txt`) name the job
submitted after A's last completed one and never done; B resubmitted it
and it gated EXACT 6/6. A's audit events for that job — appended after
its last replica — died with A; the replica's tip is the last completed
job's, and B continued from there.

**Where the time goes.** Cold: about 80 s to a running VM, about 80 s for
the runtime from the locks, about 50 s for the procedure, 5 s for the
verdict — and in the third run 330 s for the runtime instead of 80, the
package mirror's doing (the same locks, the same wheels), which is why its
cold number is 489 s while its warm number is the same 50 s as the other
two. The procedure (the warm number): the replica in a second, the
identities and the sealing of both daemons' key files to the chip 11 s,
the ceremony 11 s (a report from the chip seals the escrow key), the
daemons 22 s (`sagvd` ready in 10 s with its own report and the VCEK from
KDS, the worker's attested handshake 11 s), the verdict 5 s. A standby
that keeps the runtime and the binaries in place is 50 s from the decision
to the first verdict; what a standby with the daemons already running
would still owe is the handshake and the verdict.

## Evidence files

- `timeline.txt` — the recovery times and the four facts, as computed.
- `runner-timeline.txt` — the runner's marks: A created, A ready, the job
  in flight at the deletion, A's deletion issued and done, B created, B
  finished.
- `a-markers.txt` — A's job markers in the bucket (submitted, done), the
  one record of a job A submitted after its last upload: the lost job.
- `inputs.sha256`, `run.txt` — what was built, from which tree.
- `a/` — A's record up to its deletion (uploaded after every job):
  `timeline.txt` (job submissions and completions), `steps.txt`,
  `sagvd-identity.json`, `acp-compute-identity.json`, `escrow-provision.json`,
  `seal-keys-*.json`, `finetune.json`, `seal.json`, `job-<n>*.json`,
  `state-manifest-<n>-accepted.json` and `-finished.json` (one manifest
  per replica; `state-manifest-<n>.json` in the first three runs),
  `sagvd.log`, `acp-compute.log`, `console.log`,
  `tsm.txt`, `runtime.txt`, `pip-*.log`, `amd-chain.txt`, `metadata.txt`,
  `system.txt`, `versions.txt`, `inputs.sha256`.
- `b/` — B's record: `timeline.txt` (script start, runtime ready, state
  restored, ceremony, daemons ready, first verdict), `steps.txt` (the lost
  job, every exit code), `replica-manifest.json`, `replica-files.txt`,
  `audit-verify-replica.json` (the chain as replicated),
  `escrow-reprovision.json`, `seal-keys-*.json`, `sagvd-identity.json`,
  `a-job-<n>-submit.json` (A's own submission record of the lost job,
  from the bucket — the ids the resumed job is checked against),
  `job-first-after-loss.json` (the resumed job's view; in the first three
  runs the resubmitted job's, with its `-submit.json`),
  `job-second-after-loss*.json`,
  `audit-verify.json` and `audit-events.jsonl` (the whole chain),
  `audit-public-key.pem`, `sagvd-metrics.txt`, the logs, and the same
  system files as A's.

The evidence holds no key, seed, token or config: the safe and the replica
lived in the run's private bucket, deleted with the VMs; the sealed files'
bytes are not in the record.

## Scope

One zone, one tiny model, two `n2d-standard-4` machines in sequence. The
"safe" is a bucket object the VMs' own service account can read — the
model of a secrets manager, not one; a production safe is a KMS-wrapped
store or an HSM, and the recovery key lives off every release host. The
replica is a tar of the audit file and the genomes after every job — the
operator's replication, as in the failover drills — not a streaming one;
a job in flight is lost, by the design the runbook states, until the
durable queue lands. B is created on demand; a warm standby that already
has the runtime saves what the table's "RTO cold" and "RTO warm" differ
by — and more than that on a bad day: one run of this kit was abandoned
because the fresh VM's package mirror trickled at 10 KB/s for a quarter
of an hour (the kit now gives apt and pip timeouts and retries), which is
the cold number's weakness and the warm standby's reason.
