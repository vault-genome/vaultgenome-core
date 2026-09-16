# ADR 0017: Limits on the Primary's Word

**Status:** Accepted — implemented (2026-09-16)
**Date:** 2026-09-16
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Builds on:** ADR 0012 (sentinel and policy-driven failover), ADR 0014 (daemons on real SEV-SNP), ADR 0010 (operator stop), ADR 0001 (frozen Producer/Verifier)
**Amends:** the failover policy (`primary`, `triggers.stopped_grace_seconds`); the sentinel's records (`attestation`); `acpctl sentinel` (`--tee`, `identity`), `acpctl failover issue` (`--primary-kind`, `--primary-measurement`, `--primary-attestor-pub`, `--stopped-grace`); `sagvd failover`'s choice of genome; the `FAILOVER_DECIDED` payload (`primary_measurement_hex`)

---

## Context

Under ADR 0012 the release authority trusts the primary's sentinel by its
key: a record that verifies under the pinned sentinel key counts, and
nothing else does. That stops an outsider from adding a genome. It does
not limit what the sentinel's key itself can say. KNOWN_ISSUES #12 listed
the consequences: a compromised primary holds its sentinel's seed, so it
can keep heartbeating, so that no failover happens; it can report
`stopped`, and the authority stands down for good; and whoever holds the
seed can put records in the outbox that the authority takes as the
sentinel's — a stolen seed, used from anywhere, kept the authority quiet.

The primary in the drill was already a SEV-SNP confidential VM, and its
chip's word was worth nothing to the authority: no record carried it.

## Decision

Three limits, each in the operator's signed policy and each on the
record.

1. **The chip's word over every record.** With `--tee`, the sentinel asks
   the primary's TEE for a report over every record it writes — seal
   record, heartbeat, compromise report — with `REPORT_DATA` bound to the
   record's content (its canonical form without signature and without the
   report), then signs the record, report included. A policy that pins the
   primary (`primary.kind`, `primary.measurements`; for a simulated primary
   also its attestation key) accepts nothing from the outbox that does not
   carry a report verifying under the authority's own anchors for that
   kind (the verifier registry's AMD chain and VCEK cache) at a pinned
   measurement. An unattested record, a record from another chip, a record
   changed after the chip saw it: all ignored, noted once, and the alive
   clock does not move. A stolen seed used off the chip is silence, and
   silence is a trigger. The sentinel writes no heartbeat its chip will not
   vouch for and commits no seal the chip will not vouch for; a compromise
   report goes out even unattested, because the silence that follows fails
   over anyway. `acpctl sentinel identity` prints what the operator pins.

2. **`stopped` stands the authority down only for a grace.**
   `triggers.stopped_grace_seconds`: a sentinel that said `stopped` and is
   not back watching within that long is a trigger of its own,
   `stopped-overdue`, on the record as such. 0 keeps the old behaviour —
   `stopped` honoured indefinitely — for an operator who prefers it. The
   primary's word can no longer disarm the authority for good; the
   operator's can, through the policy or the stop list.

3. **Nothing past the sentinel's last word.** The trigger's own record — the
   compromise report, or the last heartbeat — names the last generation the
   sentinel sealed and its bundle digest. `Choose` restores nothing after
   it: a record put in the outbox past that generation is set aside. If the
   outbox holds that generation as another bundle, the outbox contradicts
   the sentinel and nothing in it is trusted: the decision is declined, on
   the record. With the chip's word on the trigger record, the tip of the
   chain is pinned by the chip, and every earlier generation by the hash
   chain that runs back from it. When the policy pins the primary, the
   chosen seal record must carry the chip's word too.

The doctrine does not change: the operator decides, in advance, in a
signed policy; the authority carries it out and records it. What changes is
that the primary's key is no longer the only thing the authority trusts
about the primary.

## Consequences

- **Against a stolen seed off the chip: closed.** The thief's records are
  ignored; the primary's silence, or its last genuine word, decides. Shown
  in `test/integration/failover_test.go` (a rogue sentinel on another
  simulated TEE, with the stolen seed and a generation of its own: ignored,
  set aside past the last word, declined on the record) and on hardware
  (the rogue attesting with the standby's real SEV-SNP chip: real reports,
  the wrong machine, refused).
- **Against an intruder with root inside the primary's guest: bounded, not
  closed.** They hold the seed and the chip. They can keep heartbeating,
  with the chip's word, and the authority believes them — until a wire
  fires, or they stop. The wires, the quarantine and the standby's gate
  remain the defences against what such an intruder seals. That stays in
  KNOWN_ISSUES #12, reduced.
- **`stopped` is no longer a permanent stand-down** where the policy sets a
  grace. Maintenance longer than the grace means a failover, unless the
  operator issues a policy that allows it; that is the cost of the primary
  not being able to disarm the authority.
- A sentinel started with `--tee` after generations sealed without it
  leaves those generations without the chip's word: under a pinning policy
  they are set aside. Restart the sentinel with `--tee` on a fresh chain
  (`--parent`) before pinning, or accept the older generations as
  unvouched.
- Each record now carries a 1184-byte report (base64 in JSON); the
  authority verifies one per poll, from the VCEK cache after the first.
  The verifier for the primary is built from the registry's entry for its
  kind, so an operator pins a primary of a kind the authority already knows
  how to verify — and the same chain, mirror and cache serve both ends.
- The heartbeat timeout still runs on the authority's clock. A verifier
  that cannot verify — the VCEK cache empty and KDS unreachable — makes
  every heartbeat silence and fails over on a healthy primary. The runbook
  says to fill the cache at arm time; a failover on a healthy primary is a
  restore on the standby, not a loss.

## Evidence

- `internal/genome/sentinel/attest_test.go`: the report binds the record;
  re-signed, relabelled, borrowed, tampered or unattested records do not
  verify; the sentinel writes no unattested heartbeat and commits no
  unattested seal while its chip is silent.
- `internal/vault/failover/limits_test.go`: the policy's pin; the drill
  under a pinning policy with the decision naming the primary; the stolen
  seed as silence; only attested genomes restored; the chain trusted only
  to the sentinel's last word, a contradicting outbox declined; `stopped`
  overdue after the grace and reset when the sentinel returns.
- `cmd/sagvd/failover_primary_test.go`: the primary's verifier from the
  policy and the registry's anchors.
- `test/integration/failover_test.go`: `TestLiveFailover_AttestedPrimary`,
  `TestLiveFailover_StoppedOverdue`, with the shipping binaries.
- On hardware: `scripts/hardware-test/gcp-failover` — the primary's sentinel
  attesting with its SEV-SNP chip, the policy pinning its measurement, the
  decision naming it; then the rogue with the stolen seed on the standby's
  chip, declined.

## Alternatives considered

- **Attest the sentinel key once, at pin time.** A one-time proof that a
  key was born in a TEE says nothing about who uses it later. The word has
  to be per record.
- **A challenge from the authority per heartbeat.** Fresh, but it makes the
  outbox a channel and the primary reachable; the outbox is a replicated
  directory by design (ADR 0012). Binding the report to the record's
  content, with a rising sequence and the primary's timestamp, replaces
  the challenge for a record that is only ever read forward.
- **Treat `stopped` as a trigger at once.** Punishes every maintenance
  stop. A grace the operator sets keeps maintenance possible and the
  authority armed.
- **Decline whenever the chain holds anything past the last word.** Hiding
  a generation is something whoever writes the replica could always do;
  the doctrine already accepted that they can hide, never add. Setting the
  extra records aside and restoring what the sentinel vouched for keeps
  continuity; a contradiction — the named generation replaced — is where
  trust ends.
