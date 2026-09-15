# ADR 0012: Sentinel and Policy-Driven Failover

**Status:** Accepted — implemented (2026-09-15)
**Date:** 2026-09-15
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Builds on:** ADR 0009 (per-handshake key delivery), ADR 0010 (operator stop and recorded refusals), ADR 0011 (genome v3, key escrow, attested self-restore)
**Amends:** audit_event schema v5 → v6 (new kind `FAILOVER_DECIDED`); doctrine invariant #07 (the sentinel's outbox joins the write-sink allowlist)

---

## Context

ADR 0011 made it possible to move a model to another machine: seal its genome,
release its key to an attested destination, confirm the destination restored it
and that it works. Every step was still started by a person. What a continuity
platform actually promises covers the moment when nobody is at the keyboard. The
machine running a model is attacked, or it dies. What it held must come back
somewhere else, as it was before anything went wrong, and nowhere the operator
did not choose.

Doing that without a person raises the question this project exists to answer:
**who decides that a model moves?** Four answers are wrong:

- **The model decides.** A model that can move itself is a worm.
- **The machine under attack decides.** Once it is compromised, whatever it says
  is the attacker's.
- **The release authority decides on its own judgement.** A standing capability to
  move keys anywhere is the most valuable thing an attacker could take over.
- **Anyone who can write to shared storage decides.** Escrow public keys are
  public, so anyone can write a genome encrypted to the authority.

## Decision

The operator decides, in advance and in writing. A **failover policy**, signed
with the operator key that signs the stop list (ADR 0010), names:

- the primary's sentinel;
- the one standby a genome may go to;
- the signs of failure that count;
- what the standby must prove.

A **sentinel** on the primary keeps the state sealed as it changes and says when
the machine can no longer be trusted. The release authority's **executor** does
nothing but carry the policy out.

### The sentinel (`acpctl sentinel watch`, `internal/genome/sentinel`)

The sentinel runs beside the workload. It watches one state, either a directory
(a LoRA adapter as it trains, a checkpoint, a corpus) or an Ollama model. It
writes everything to an **outbox** directory, which the operator replicates
anywhere: to object storage, to another cloud, or into the standby's bundle
directory. Every tick it does three things, in this order:

1. **Checks its tripwires.**
   - Path wires fire on any change to a file or tree: content, mode, symlink
     target, an entry added or removed, or the path gone. Typical wires are
     canary files, credentials no process reads, the sentinel's own binary, and
     directories an intruder would drop tools into.
   - Probe wires fire when a command stops exiting 0, fails to run, or runs past
     its timeout. A probe can wrap a file-integrity checker, a process or port
     check, or a re-attestation.

   A wire that cannot be armed at start stops the sentinel from starting.
2. **Seals the state, if it settled into something new.**
   - A cheap fingerprint (paths, sizes, times, modes; or the Ollama manifest
     digest) decides when to look. The state must stay unchanged for `--settle`
     before it is described and sealed, so a file that is still being written is
     never sealed.
   - Content already sealed is not sealed again.
   - Each new state becomes the next generation of a genome chain: a v3 bundle
     whose header names its parent. Its key is encapsulated only to the release
     authority's escrow key (ADR 0011). **The primary keeps nothing that opens
     anything it sealed.**
   - Write order: the bundle, then the escrow envelope, then the commit point, a
     **seal record** signed with the sentinel's Ed25519 key. The record names the
     bundle's SHA-256 and size, the key ID, the escrow key, the payload digest,
     the parent bundle and the seal time.
3. **Writes a signed heartbeat.** It carries a sequence number that rises across
   restarts, a status (`watching`, `stopped` or `compromised`), the newest
   generation sealed, and the number of armed wires.

When a wire fires, the tick seals nothing. That includes a tampered state from
the same tick, because wires are checked first. The sentinel writes a signed
**compromise report**: which wires fired, what they found, when, and the newest
generation it sealed before. It then writes a final heartbeat saying so, and
exits 3. An outbox holding a compromise report is closed, and the sentinel
refuses to write to it again. On SIGINT or SIGTERM it writes a `stopped`
heartbeat and exits 0, which means the operator stopped it and there is nothing
to fail over.

A sentinel restarted on the same outbox resumes its chain. It refuses an outbox
that holds records it did not sign, or whose newest genome does not check out. A
sentinel on a machine restored from a genome can continue that genome's chain
(`--parent`).

### The failover policy (`acpctl failover issue | verify`, `internal/vault/failover`)

The policy has schema `vault-genome/failover-policy/v1`. It is canonical JSON,
signed with Ed25519 by the operator key, and has these fields:

- `serial`, `issued_at` and `not_after`. A policy stands for a bounded time.
- `sentinel_public_key`. Only records, heartbeats and reports signed by this key
  count.
- `standby`: TEE kind, endpoint (https), and one or more measurements the standby
  must attest.
- `triggers`: `compromise_report` and/or `heartbeat_timeout_seconds`.
- `quarantine_seconds`. Genomes sealed this close to the trigger are not
  trusted, because an intrusion can begin before a wire sees it.
- `max_rpo_seconds`. The executor declines rather than restore a genome older
  than this.
- `require_gate`: the gate verdict the standby's receipt must carry, EQUIVALENT
  or EXACT.

### The executor (`sagvd failover`)

1. **Arms.** It verifies the policy under the operator key pinned in
   `crosscloud.operator_stop` (one operator, one key). It then checks that the
   policy stands, that the authority has a verifier for the standby's TEE kind,
   and that the verified audit log shows the policy has not been spent. Then it
   closes the audit log, so other releases can run while it waits.
2. **Watches the outbox.** It accepts only what verifies under the pinned
   sentinel key. Anything else is noted in the report and otherwise ignored, and
   so is an older heartbeat put back over a newer one.
   - The heartbeat timeout runs on the authority's own clock, from when it last
     saw the sequence number rise, so clock skew between machines does not
     matter.
   - A `stopped` heartbeat makes the executor stand down.
3. **Chooses the genome.**
   - It reads the chain of verified seal records, oldest to newest. The chain
     ends at the first gap or break, so a missing or forged record can roll the
     chain back but never extend it.
   - The cutoff is the trigger time (the sentinel's detection time, or its last
     heartbeat) minus the quarantine.
   - Of the generations sealed by the cutoff, it takes the newest whose bundle
     hashes to its record, whose header matches, and whose escrow envelope is for
     this authority. Generations that fail are set aside with the reason.
4. **Records the decision** as `FAILOVER_DECIDED` before any key moves. The
   decision is either `failover`, with the chosen generation and the decision ID
   of the release that follows, or `declined`, with the reason: no trustworthy
   genome, the RPO bound exceeded, or the policy expired. The record also carries
   the policy serial and digest, the trigger and its evidence digest, the
   generation the primary last reported, and where the verified chain ends.
5. **Releases the key**, opened from escrow only now, through the ordinary
   attested release (ADR 0009), under a release policy composed as
   `stop list ⟶ failover policy ⟶ allow-list`:
   - The operator stop refuses first, including the standby itself.
   - The failover policy refuses every destination but its standby, even one the
     allow-list admits.
   - The allow-list still has to admit the standby.

   The recorded policy version reads `…;failover=<serial>;revocation=<serial>`.
6. **Confirms** the standby's TEE-signed receipt against the recorded release and
   the chosen genome, with the required gate (ADR 0011). A restore that failed on
   the standby is a final answer (HTTP 422), so the executor stops waiting.
7. **Reports** timing:
   - `detect_seconds`: from the last heartbeat seen to the trigger, or from the
     sentinel's detection to the report being seen;
   - the release, restore and gate times;
   - `failover_seconds`: from the trigger being observed to the restore being
     confirmed;
   - `rto_seconds`: `detect_seconds` plus `failover_seconds`;
   - `rpo_seconds`: the trigger time minus the chosen genome's seal time.

**One policy serial performs at most one failover.** Moving again, including back,
needs a new policy with a higher serial. A declined trigger does not spend a
policy. An older serial than one already applied is refused.

### Where the genome is

Bundles and escrow envelopes are ciphertext, so they can live anywhere. The
standby holds a replica of the outbox in its `genome.bundle_dir` (warm standby).
At failover only the key moves, which is what keeps the recovery time short. The
restorer ignores the outbox's other files.

## Anti-worm properties

- **No autonomous hop.** Every move needs an operator signature made in advance,
  and each signature is good for one move to one named, attested destination.
  The number of hops a genome can make is bounded by the number of policies the
  operator signs.
- **The model and the primary cannot choose the destination.** The standby's
  kind, endpoint and measurement come from the operator's policy, and the attested
  release checks them (ADR 0009).
- **Writing to the outbox cannot add a genome.** Only records signed by the
  pinned sentinel key are read, and the chain cannot be extended, only cut short.
  Anyone who can write to the outbox can hide genomes, which rolls the chain
  back, but cannot plant one. A forged compromise report or heartbeat is ignored.
- **The primary holds no key.** Every genome key goes to escrow the moment it is
  sealed. An attacker on the primary can read the outbox and learns only
  ciphertext.
- **The operator stop is global.** A stop list that stops everything, or revokes
  the standby's measurement, halts a failover mid-flight. The refusal is recorded
  (`KEY_RELEASE_DENIED`).
- **Everything is on the signed audit log:** the decision, the release, the
  refusal and the restore.

## Limits, stated plainly

- **A compromised primary can lie.** It holds its sentinel's key, so it can keep
  heartbeating while subverted, or send a `stopped` heartbeat to avoid a failover.
  It cannot move a genome anywhere the policy does not name, or decrypt anything.
  Tripwires only help if they fire before the intruder reaches the sentinel.
  Independent detection (cloud monitoring, the operator) must be able to move the
  model too. The operator can always release a genome by hand
  (`sagvd crosscloud-restore -key-escrow`).
- **The sentinel seals what the state directory holds.** It cannot tell a
  malicious change from training. Tripwires, the quarantine window and the gate
  are the defences.
- **RPO is bounded by what reached the replica.** A generation sealed on the
  primary but not yet replicated to the authority does not exist for the
  executor.
- **The attested standby in the hardware drill is a CPU confidential VM.**
  Attested GPU destinations need confidential GPUs (H100 CC), a TDX producer and
  verifier. Until then, CPU→GPU fidelity is measured on a non-confidential GPU
  VM, as a separate leg (`scripts/hardware-test/gcp-drill`).

## Consequences

- New packages: `internal/genome/sentinel` (records, outbox, tripwires, watch
  loop) and `internal/vault/failover` (policy, gate, watcher, choice, executor).
- `internal/genome/bundle` gains `Describe` and `SealFile`, and
  `acpctl genome seal` and the sentinel share one sealing path.
  `contentdir.Fingerprint` and `ollama.Fingerprint` give the cheap change
  detector.
- New commands: `acpctl sentinel keygen | watch`, `acpctl failover issue |
  verify`, and `sagvd failover`.
- The audit_event schema goes to v6 (`FAILOVER_DECIDED`). v1–v5 events stay
  valid.
- Doctrine invariant #07: `internal/genome/sentinel/` joins the write-sink
  allowlist. It writes escrow envelopes (ciphertext) and signed records (public
  statements). Its bundles come from genome/bundle, and its `io.Copy` feeds
  tripwire hashes. Invariant 07c is unchanged: sagvd links the sentinel's reader
  but none of the packages that materialise a genome.
- The restorer answers a receipt request for a failed restore with 422, a final
  answer, instead of 409 ("not yet").

## Proof

- Unit tests for the sentinel cover:
  - sealing only settled, new states, and chaining them;
  - heartbeats that rise across restarts, and resuming a chain;
  - wires checked before sealing: a tampered state from the same tick is never
    sealed;
  - every kind of path change, and probe exit, timeout and missing binary;
  - a compromise closing the outbox;
  - chain breaks, forged, edited and misnamed records;
  - swapped bundles and envelopes.

  Coverage is 86%.
- Unit tests for the failover package cover:
  - policy signing, tampering and validation;
  - the gate composition, where the stop list overrides and the stop serial is
    still readable;
  - a spent policy, and a rolled-back one.

  End-to-end tests run in-process, with a real sentinel, restorer, receiver,
  HTTP transport and coordinator:
  - compromise → generation 1 restored and gated EXACT, never the tampered state;
  - a hung primary → heartbeat timeout;
  - a stopped sentinel → the executor stands down;
  - a forged report → ignored;
  - the RPO bound exceeded → declined and recorded;
  - an operator stop → refused and recorded.

  Coverage is 90%; the tests are race-clean.
- Live tests (`test/integration/failover_test.go`) run the real binaries:
  - An intrusion (canary touched, model tampered) ends with the sentinel
    exiting 3. The authority fails over to generation 1, the standby restores
    it and gates it EXACT, and there are 5 events on the verified audit log. A
    spent policy refuses to run again. Locally: detection 0.16 s, failover
    0.48 s, RTO 0.63 s, RPO 0.20 s.
  - A primary killed with SIGKILL: failover after the 3 s timeout. Detection
    3.05 s, RTO 3.53 s.

## Alternatives considered

- **The sentinel seals the state at the moment of compromise.** Rejected. That
  state is the one an intruder may have touched. The last genome sealed while
  the wires were clean is the one to trust, and the quarantine can push the
  choice back further.
- **The executor fails over on any trigger, as often as needed.** Rejected. A
  standing capability to move keys repeatedly is what an attacker would aim for,
  and it makes ping-pong and self-propagation possible. One serial, one move.
- **Trust the outbox's files by their names.** Rejected. Escrow public keys are
  public, so without the sentinel's signatures anyone who can write to the
  outbox could plant a genome that the authority would release.
- **Heartbeat timeouts on the primary's timestamps.** Rejected, because a skewed
  clock would move the trigger. The authority times the sequence number on its
  own clock.
