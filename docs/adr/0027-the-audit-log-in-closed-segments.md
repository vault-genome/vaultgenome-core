# ADR 0027 — The audit log in closed segments: retention is archival, and the views expire

- **Status:** Accepted (2026-10-16)
- **Tags:** sagvd, audit, retention, bbolt, acpctl, disk
- **Extends:** ADR 0014 (the Return Path audit log), ADR 0026 (the job queue on disk)

## Context

The soak of 2026-10-16 (VERIFIABLE-CLAIMS C33, C34) closed the authority's
memory growth and left one line open in KNOWN_ISSUES #18: what still grows
is on disk, by design. Every job served writes about 34–37 KB to the audit
log (sixteen events of 2.1–2.3 KB) and 14–16 KB to the job store (the
finished job's view), 48–52 KB in all — 2.8 GB a day at 40 jobs a minute,
in two bbolt files that nothing rotates. Two hours of three workers left
168 MB and 67 MB on TDX, 117 MB and 50 MB on SEV-SNP. A bbolt file never
shrinks: pages freed by a delete are reused, the file keeps its high-water
mark. And the daemon verifies the whole audit log every time it starts
(ADR 0014): a month at that rate is twenty-seven million events, and the
start would walk them all before the first job.

The two files are not the same kind of record. The audit log is the
decision's record — every job accepted, every worker admitted or refused,
every candidate judged, signed and hash-linked before it takes effect
(doctrine invariant #08) — and a bank keeps that kind of record for years,
not days: 23 NYCRR 500.06(b) sets five years for the records that
reconstruct material financial transactions and three for the audit
trails that detect cybersecurity events; NIST SP 800-53 Rev. 5 AU-11 sets
the period as the organisation's own, AU-4(1) has the logs moved to a
system other than the one that writes them, AU-9(3) has their integrity
protected cryptographically, and AU-5(4) stops the system when logging
fails — which is what invariant #08 already does. The job's view is the
other kind: the answer `GET /v1/jobs/{id}` renders, kept so that the
answer outlives the process (ADR 0026). The decision it reports is in the
audit log under the same request id, which the submission's response
carried.

So the retention period is the operator's — their regulator's and their
policy's — and not the software's to choose. What the software owes them
is a log that is cheap to keep for years, that can be moved off the host
without a gap in its proof, and that the software itself never destroys;
and a view store whose size is a function of a window they set, not of
the authority's lifetime.

## Decision

1. **The audit log is written in segments, and a closed segment is a
   file of its own.** The live file at `audit.log_path` holds the newest
   segment. When it holds `audit.segment_events` events, or when its
   first event is older than `audit.segment_max_age_seconds`, the daemon
   closes it: the file is closed, moved into `audit.archive_dir`
   (`archive/` beside the live file unless set) under the name
   `<name>.<first>-<last><ext>` — the indices of its first and last
   events, ten digits each — and a fresh live file is created at the
   same path. The fresh file carries, in a bucket of its own, where it
   starts: the index of its first event, the hash of the event before it
   (the archive's tip) and the archive's name. The chain's count and tip
   continue across the boundary; event ids continue; the first event of
   the new file links to the last event of the archive exactly as it
   would have inside one file. Both triggers are off (0) unless set:
   an upgraded daemon keeps one file until told otherwise.
2. **The closing of a segment is itself on the record.** The first event
   of every segment after the first is `AUDIT_SEGMENT_CLOSED` (audit
   schema v7): the archive's name, its first and last index, its tip, its
   length in bytes and the SHA-256 of the closed file. It is appended
   under the chain's lock, before any other writer can, so a verifier
   reading the live file alone knows which file it continues and what
   that file must hash to. An archive is never opened for writing again
   — the daemon does not open it at all after closing it, and `acpctl`
   opens it read-only — so its hash stays what the record says.
3. **The daemon never deletes an audit event.** Retention of the audit
   log is archival: the operator ships closed segments where their
   policy keeps them (AU-4(1)) and removes the local copy when they
   choose; the archive's hash is on the chain either way. Nothing in the
   daemon or in `acpctl` deletes a segment.
4. **Closing a segment survives a crash at any step.** The four steps
   are: close the file, move it, create the fresh file, record the
   closing. A daemon that starts and finds no live file beside archives
   creates the live file from the newest archive — its index count, its
   tip — and records the closing; one that finds an empty live file
   whose bucket names an archive records the closing. In either case the
   archive must be where the record says: if it is not, the daemon
   refuses to start, because a segment closed off the record is a
   decision off the record. A crash before the move leaves one file with
   every event, and the segment closes at the next event.
5. **Verification walks the segments as one chain.** At start the
   daemon verifies its live segment, from the hash its bucket names:
   every link and every signature, as before, over at most one
   segment's events — so the start no longer grows with the history.
   `acpctl audit verify` takes `--archive-dir` (the default beside the
   file), orders the archives by their first index, checks that each
   starts where the previous one ended — index and tip — verifies every
   link and signature from the oldest present segment to the live tip in
   constant memory, and checks every `AUDIT_SEGMENT_CLOSED` record
   against the file it names: present, the stated length, the stated
   hash. It is strict: the oldest present segment must start at genesis,
   or `--from-tip` must name the hash it continues from — the tip the
   operator recorded when they shipped the earlier segments away. A
   present archive that fails, a gap between present archives, or an
   archive whose hash is not what the chain records is a broken chain
   (exit 4), as a broken link is today. `acpctl audit query`, `status`
   and `lineage` read the archives and the live file in order, and
   `query` filters by `--request` as well, so a job whose view has
   expired is found by the request id its submission returned.
6. **Finished jobs expire from the job store.** `queue.retain_finished_seconds`
   is how long a finished job's record and view are kept after it
   finished; a job older than that is deleted — record and view — in
   batches of at most ten thousand, at most once a minute, after a
   completion and at start. `GET` answers 404 for it from then on; the
   audit log answers. Jobs queued or running are never swept. 0, the
   default, keeps every finished job, as 0.5.0 did. The store indexes
   finished jobs by their completion time, so a sweep costs what it
   deletes, not what the store holds; a store written before this
   release is indexed once when it is opened.
7. **`acpctl provision` writes a bounded deployment.** The reference
   configuration it generates sets `audit.segment_events` to 100 000 —
   about 220 MB a segment, a segment every 2.6 hours at 40 jobs a
   minute — `audit.segment_max_age_seconds` to a day, so a quiet
   authority still closes a segment daily, and
   `queue.retain_finished_seconds` to thirty days.

## Consequences

- The disk the authority needs is bounded by what the operator decides:
  one live segment, the archives not yet shipped, and the views of the
  last `queue.retain_finished_seconds`. At 40 jobs a minute and the
  provisioned values that is about 220 MB live, 2 GB of archives a day
  until they are moved, and 600 MB of views for every day of the window
  (the file plateaus at the window's high-water mark; it does not
  shrink when the window passes, and an operator who needs the space
  back compacts it offline with `bbolt compact`).
- A daemon's start verifies at most `audit.segment_events` events,
  whatever the history; `acpctl audit verify` of the whole history takes
  as long as the history, in constant memory.
- A verifier needs every segment back to genesis, or the operator's word
  (`--from-tip`) for the ones they moved away. The tip to record when
  shipping a segment is in the `AUDIT_SEGMENT_CLOSED` event that follows
  it, and in the `acpctl audit verify` output.
- Audit schema v7 adds one kind and changes no field. A v6 reader
  refuses a v7 log, as every bump before it (ADR 0012).
- The cross-cloud log (`crosscloud.audit_log_path`) is not segmented: it
  is opened by short-lived subcommands, one decision at a time, and does
  not grow by the job.
- Moving the archive is a rename, so `audit.archive_dir` must be on the
  live file's filesystem; the daemon refuses a configuration where it is
  not.

## Alternatives considered

- **Delete the old events from the one file.** The file would not shrink,
  the archived events would still need a file and a format of their own,
  the sequence keys would have gaps that `At` would have to walk around,
  and the live file's start would read as genesis — the hole this ADR
  closes with the bucket that names where a segment starts.
- **A second writer that archives beside the daemon.** One process holds
  a bbolt file at a time, by design (ADR 0026); the archiver would have
  to be the daemon.
- **A second sink — syslog, object storage — written in parallel.** Two
  records of one decision, and the chain is the record; a copy is what
  the operator makes of a closed segment, with its hash already on the
  chain.
- **Rotation on by default.** It moves the same bytes between files and
  deletes none; it would change the layout under an upgraded daemon for
  no space gained. Off unless set, on in what `acpctl provision`
  generates.
- **A tombstone for an expired job, so `GET` could say "expired" rather
  than 404.** It would keep a record per job forever, which is what the
  window is for. The audit log keeps the decision under the request id.

## Evidence

- The soak with segments on real SEV-SNP, the archives verified end to
  end with the live file: VERIFIABLE-CLAIMS C38.
- Unit tests: a chain across a closing (count, tip, event ids and links
  continue; the closing record is first; a reopened chain verifies from
  the archive's tip), each crash step resumed, a daemon refusing to start
  without the archive to record, the verifier over archives and the
  strict start, the sweep deleting only finished jobs older than the
  window, with the index built for a store written before it.
