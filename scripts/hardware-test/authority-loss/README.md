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
  its state** — the audit log and the genomes — to the bucket after every
  job, and marking every job's submission and completion.
- The runner waits until A has completed three jobs, then **deletes A
  while a job is in flight** (`gcloud compute instances delete`, no
  warning to the guest) and records the moment.
- **B** ([`authority-b.sh`](authority-b.sh)) — a fresh VM, created at that
  moment. It takes the key material from the safe and seals it to *its*
  chip; takes the last replica and verifies the audit chain as replicated;
  re-provisions the escrow key through the recovery ceremony
  (`acpctl escrow recover | sagvd escrow-provision -stdin`); starts both
  daemons over the replicated audit log; finds which job A lost (submitted,
  never completed); submits it again; and records when the first verdict
  after the loss was signed. Then the whole chain — A's events and B's — is
  verified offline under the published audit key.
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

**Lost**: the job in flight when A was deleted — the queue is in memory
(runbook scenario 4: "jobs that were queued or running are gone —
resubmit them"); the drill records which job that was, and resubmits it.
Anything A appended to its audit log after the last replica — the drill
replicates after every job, so the lag is at most one job's events; the
replica manifest says after which job it was taken.

**Not the same, by design**: B's launch measurement is B's own; both
daemons read it from the chip and pin each other's, as A's did (on the
same image it is the same value).

## Results — three runs, 2026-10-15

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
  `state-manifest-<n>.json`, `sagvd.log`, `acp-compute.log`, `console.log`,
  `tsm.txt`, `runtime.txt`, `pip-*.log`, `amd-chain.txt`, `metadata.txt`,
  `system.txt`, `versions.txt`, `inputs.sha256`.
- `b/` — B's record: `timeline.txt` (script start, runtime ready, state
  restored, ceremony, daemons ready, first verdict), `steps.txt` (the lost
  job, every exit code), `replica-manifest.json`, `replica-files.txt`,
  `audit-verify-replica.json` (the chain as replicated),
  `escrow-reprovision.json`, `seal-keys-*.json`, `sagvd-identity.json`,
  `job-first-after-loss*.json`, `job-second-after-loss*.json`,
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
