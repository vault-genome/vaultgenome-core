# ADR 0041 — A standby goes on by itself: after a gated restore it trains, seals and answers, and the authority records the chain it continues

- **Status:** Proposed (2026-11-17) — the four decisions are implemented and tested locally, the last on the release binaries with a simulated TEE (`internal/bootstrap/restorer` and `cmd/acp-bootstrap`; `internal/genome/sentinel`; `workers/genome/vg_genome/answer.py`; `internal/vault/failover`, `internal/contracts/audit_event`, `cmd/acpctl`, `cmd/sagvd`). Accepted with its record on hardware
- **Date:** 2026-11-17
- **Deciders:** Serhii Nikolaichuk, Rodion Sorokin
- **Extends:** ADR 0011 (the destination restores by itself), ADR 0012 (the sentinel; one policy serial, one failover), ADR 0013 (the worker's door), ADR 0017 (the chip's word over every record), ADR 0040 (training goes on from a genome)
- **Amends:** `acp-bootstrap` configuration (`genome.after_restore`); the failover policy (`vault-genome/failover-policy/v2`: `standby.sentinel`); `sagvd failover` (it goes on after a confirmed restore when the policy names the standby's sentinel); the audit log (one kind, `CHAIN_CONTINUED`); `vg-genome` (the command `answer`); `docs/operator/00_overview.md` §3

## Context

After a failover the standby holds the last generation, restored and judged
by its gate, and nothing runs. ADR 0040 ended on the three things that were
missing: who runs `finetune --continue` on the standby, the sentinel that
seals what it produces, and a model that answers while it trains. In the
drill of C61 a script of the kit ran the first, and nobody ran the other
two.

Four facts of the code decide what has to be built.

- The destination's restore ends in `restorer.restoreOne`: the tree is in
  place, the gate has judged it, the receipt is signed and kept, the key is
  erased. Then the function logs and returns. `genome` in the destination's
  configuration names two directories and a gate and nothing to run.
- A sentinel can continue another machine's chain (`--parent`): the first
  generation of its outbox names the parent's bundle in its header and in
  its seal record, and `acpctl genome chain` checks the link. But it held a
  new state to the last generation of its own outbox only; started on the
  state as it was restored, it sealed the parent's content again.
- `sagvd failover` carries out one policy and exits. The policy names one
  sentinel key, the primary's; a record signed by the standby's sentinel is
  nothing to the authority.
- The only question the product puts to a model is a gate job (ADR 0013).
  `00_overview.md` says "The Vault is not a model server", and nothing else
  in the tree serves one either. The worker's package has what an answer
  needs: `door.open_genome` checks a genome and loads its model, and
  `model.greedy` continues a prompt token by token with the arithmetic of
  the genome's own fixtures.

## Decision

1. **The destination runs one command after a restore its gate passed.**
   `genome.after_restore` in `acp-bootstrap`'s configuration:

   ```json
   "after_restore": {"command": ["/usr/local/bin/go-on", "{genome}", "{bundle}", "{generation}"],
                     "env": ["KEY=VALUE"], "timeout_seconds": 60}
   ```

   `{genome}` is the restored tree, `{bundle}` the bundle it was restored
   from in `bundle_dir`, `{generation}` its number. The command runs once,
   after the receipt is signed and kept, so the authority's confirmation
   does not wait for it, and only for a restore whose state is `restored`: a
   restore that failed, or whose gate said FAIL, runs nothing. The section is
   refused unless `genome.gate` is set and `required`: nothing starts on a
   model that was not proven on this machine. A daemon that restarts does
   not run it again for the restores it finds on disk. What the command did
   — its exit status, when, how long — is on the restore's record
   (`GET /v1/genome/restores`) while the daemon runs, and in the log; it
   is not in the receipt,
   which says what was restored and judged and is signed before the command
   runs. The command is there to start what goes on, so what it leaves
   running is not waited for: a command that ended with status 0 is done,
   and the record says `left_running` when a process it started still held
   its output open a few seconds later.

   The command has the standing the gate's command has: the same file, the
   same operator, a process the destination starts with the restored tree
   in its hands and no key. It moves no key and asks for none.

2. **A sentinel started with a parent does not seal the parent's state
   again.** `seal()` holds a new state to the parent's payload as well as
   to its own last generation. The payload digest covers paths and bytes
   and nothing else (`contentdir.Capture`), so a restored tree has its
   parent's. The first generation of a standby's outbox is the first state
   that differs from what was restored, whatever directory the sentinel is
   pointed at.

3. **The model answers on the machine it lives on.** `vg-genome answer
   --genome DIR --base BASE --listen HOST:PORT --token-file FILE` is a
   process of the worker's package, beside the training process, on the
   primary — and on a standby once it is one. It opens the genome the way
   the door does (the fixtures and the adapter against `genome.json`, the
   base against the manifest, the recipe's seed and thread count pinned)
   and does not start on a genome that fails any of it. `POST /v1/answer`
   with `{"prompt": …, "max_new_tokens": …}` tokenizes the prompt as the
   genome's fixtures were tokenized, continues it greedily, and returns the
   text, the token ids, and the genome it came from: the adapter's SHA-256
   and the step training stood at. When the directory holds a new state —
   training has put the next genome in its place — the process opens it
   under the same checks; a state that fails them is not served, and the
   one before it goes on answering.

   An answer is therefore a statement that can be checked: on one pinned
   runtime and one arithmetic the same prompt and the same genome give the
   same tokens, and the adapter an answer names is in a generation the
   sentinel sealed, or is about to. `vg-genome answer --genome DIR --base
   BASE --prompt P` gives the same answer once, without a listener, for
   whoever holds the generation.

   The Vault still serves no inference: `sagvd` holds no model and takes no
   prompt. What changes in `00_overview.md` §3 is the sentence around that
   line: the product now has a process that answers, on the compute side,
   and it is started, fed and bounded as this record says.

4. **The policy names the standby's sentinel, and the authority records
   the chain it continues.** `vault-genome/failover-policy/v2` is v1 with
   one section more, `standby.sentinel`: the key the standby's own sentinel
   signs under and the measurements its records must be attested at, said
   in advance about the standby the way `sentinel_public_key` and `primary`
   say them about the primary. The TEE is the standby's own — one machine,
   one chip, so the section names no kind of its own — and the key is not
   the primary's. Machines of one image attest one measurement (the policy
   of `scripts/hardware-test/training-continuity/evidence/20261111T135725Z`
   pins its primary and its standby at the same one), so the report says a
   record was made on such a machine, and the key, sealed to the standby's
   chip, says on which. The key is made and sealed there before the
   operator signs (`acpctl sentinel keygen`, `identity`, `seal-key`;
   `acpctl failover issue --standby-sentinel-pub
   --standby-sentinel-measurement`). A policy without the section is the
   v1 it was, to the byte, and is read as before.

   Under a policy that has the section, `sagvd failover` does not exit
   when the standby's restore is confirmed. From the standby's outbox
   (`-standby-outbox`, a replica like the primary's) it reads the one
   record that can continue the chain — the seal record of the generation
   after the one released — and accepts it when it verifies under the
   standby's sentinel key, names the released bundle as its parent, carries
   a report of the standby's TEE at a measurement the section pins, and its
   bundle and escrow envelope check out, the key escrowed to this
   authority. That record goes on the audit log as `CHAIN_CONTINUED`, once:
   the policy, the failover's decision, the standby's sentinel and
   measurement, the generation, its bundle and its parent, and the digest
   of the record itself. A record of that generation that fails a check is
   set aside, noted once and waited past — a file still being copied checks
   out when it is whole — and nothing else in that outbox is looked at: not
   an earlier chain under the same key, not a later generation that arrived
   first. From then on the authority watches the standby's heartbeat as it
   watched the primary's, and a trigger there is recorded as a failover
   declined: this policy names nowhere further to go.

5. **What stays the operator's.** Every key that moves still moves under a
   policy the operator signed and under the stop list (ADR 0010). One
   policy serial still performs at most one failover (ADR 0012): the
   standby that has become the primary is watched, and is not moved from,
   until a policy with a higher serial names where to. Nothing here
   re-provisions a key: the standby's sentinel key, its worker's key and
   the pins of both exist before the failure.

## Consequences

- After a failover a person is needed for the next policy and for nothing
  else. `docs/operator/07_failover.md` says so with the code;
  `KNOWN_ISSUES.md` 21 and item 10 of "What we do not claim" change with
  the record on hardware.
- An authority that restarts after the failover goes on from its audit
  log. It resumes only the policy that carried the failover out — the same
  serial and the same digest — and only a failover whose restore the log
  confirms; a failover decided and never confirmed has spent its policy,
  as before.
- If the standby's sentinel never starts, the authority waits for its
  first heartbeat and says so; there is nothing for it to decide. A
  standby whose command failed is on the standby's own record
  (`after_restore`), not on the authority's.
- A trigger on the standby after the failover is a `FAILOVER_DECIDED`
  with the decision `declined`, under the standby sentinel's ID. It does
  not spend anything and releases nothing; it is the record that the
  policy was asked to move again and could not.
- Between the restore and the first generation the standby seals, what the
  standby trains is as unprotected as any state between two generations: a
  standby lost in that window comes back from the generation it restored.
- The command of decision 1 is whatever the destination's configuration
  says. Who can edit that file decides what runs after a restore, as they
  already decide what the gate runs.
- An answer equals the primary's token for token where the gate says
  EXACT, and for the same reason; where the gate says EQUIVALENT the
  answers may part where two tokens are close. The answer names the genome,
  not the machine.
- `greedy` runs without a cache, the arithmetic of the fixtures: the cost
  of a token grows with the length before it. That is enough for the
  drill's model and short answers; a faster path is another arithmetic and
  goes through the gate before it serves.
- `answer` speaks plain HTTP and does not start off loopback without a
  token. Accounts, limits and TLS for people outside the machine are the
  deployment's, and not decided here.
- The stop list stops keys and gate jobs (ADR 0010). It does not stop a
  training process, a sentinel or `answer` that already run.
- The audit schema gains one kind and moves to v10; a v9 reader refuses a
  v10 log. A policy with the new section is refused by an authority of an
  earlier release (`Parse` reads no field it does not know).
- A sentinel attests its records, and a policy pins a TEE, on SEV-SNP on
  Compute Engine and on the simulated TEE only. The closed turn is built
  and measured there.

## Alternatives considered

- **A unit of the host that watches for the receipt** and starts the rest.
  No code changes, and the rule "not when the gate failed" would live in a
  script nobody tests. The destination already knows the moment and the
  verdict.
- **Let the authority's gate job be the answer.** It asks one attested
  worker the genome's own prompts and judges them; it is a proof, and it
  stays one. It takes no question a person has.
- **Serve answers from `sagvd`.** The Vault would hold a model and a
  queue of prompts. Its work is to decide and to record.
- **Have the standby's sentinel sign under the primary's key.** The key
  would have to leave the chip it is sealed to (ADR 0023), and a record
  would no longer say which machine sealed it.
- **Let the policy name a list of standbys and move again by itself.**
  That is the rule ADR 0012 refused. Whether a list of machines the
  operator signs may replace it is a decision of its own, not one to
  take by the way.

## Evidence

- Decision 2: `internal/genome/sentinel`, `TestParentAsRestoredIsNotSealedAgain`
  — it fails on the tree before the change (one generation sealed from the
  restored state) and passes after it.
- Decision 1: `internal/bootstrap/restorer`, `after_restore_test.go` — the
  command runs once after a gate that passed, with the restored tree, the
  bundle and the generation, and not again for a key released twice or by
  a restarted daemon; nothing runs after a gate that said FAIL or a restore
  that failed; a command that fails, does not end or cannot be run is on
  the record and the restore stays restored; one that ends well and leaves
  a process running is done (the test fails without that: the record said
  `WaitDelay expired`); `New` refuses the command without a required gate.
  `cmd/acp-bootstrap`,
  `TestValidate_GenomeAfterRestore`: the section as configured, and refused
  without `gate.required`.
- Decision 3: `workers/genome/tests/test_answer.py`, on the pinned runtime and
  the tests' tiny model — an answer names the genome's adapter and step and
  comes out the same from the same object, from a fresh one and from the
  command line; the listener answers what the command line answers, refuses
  a missing or wrong token, a malformed request and a prompt that does not
  fit the model's context, says so when the model fails on a request and
  goes on, and does not start off loopback without a token; a genome whose
  adapter was edited, or whose base is another, is not opened; the next
  genome put in the directory answers under its own name; a state that
  fails its checks leaves the one before it answering, and is opened once
  it is whole.
- Decision 4, the policy: `internal/vault/failover`, `policy_v2_test.go` — a
  policy that names the standby's sentinel is signed and read as v2, the
  section under the operator's signature; the section is refused by name
  under v1, absent under v2, with the primary's key, without a measurement,
  and with or without an attestation key as the standby's kind requires;
  and four policies recorded on hardware before v2 existed (SEV-SNP, TDX, a
  confidential GPU) still hash, read by this build, to the digest in their
  run's report. `cmd/acpctl`, `TestFailover_IssueNamesTheStandbySentinel`:
  the flags, what `verify` prints, and the refusals before anything is
  written.
- Decision 4, the audit kind: `internal/contracts/audit_event` — the
  validator knows `CHAIN_CONTINUED`, the schema it is written under is v10,
  v11 is refused, and every earlier version is read as before.
- Decision 4, the record of the chain: `internal/vault/failover`,
  `continue_test.go`, in one process with a real sentinel on each side, a
  real destination and the authority's coordinator —
  `TestTheStandbyContinuesTheChain`: the primary is intruded on, generation
  1 is restored and gated on the standby, the standby's sentinel seals
  nothing from the state as restored and generation 2 from the next one,
  and `CHAIN_CONTINUED` follows the failover's five events under its
  decision ID, once. `TestWhatDoesNotContinueTheChain`: a record signed by
  the primary's sentinel, without the chip's report, with another chip's,
  at a measurement not pinned, of a later generation under that name, with
  another parent, with a bundle or an envelope that is missing or another,
  or a key escrowed elsewhere is set aside by name; a later generation
  alone is waited for; and with any one of the checks taken out of
  `FindContinuation` the test fails. `TestTheContinuationIsWaitedFor`: a
  record whose bundle has not arrived is noted once and recorded when it
  has. `internal/genome/sentinel`, `TestReadRecordReadsOneGeneration`.
- Decision 4, the authority going on: `internal/vault/failover`,
  `progress_test.go` — `TestTheAuthorityGoesOnFromItsLog`: an authority
  that restarts after the failover reads from its log what it did, does not
  fail over again, records the chain, finds it on record at the next
  restart, sees a wire fire on the standby and declines, once;
  `TestReadProgressReadsWhatTheLogAgreesOn` and
  `TestResumeNeedsAConfirmedFailoverToGoOnFrom`: a log whose records of the
  failover do not agree with the policy or with each other, a failover
  never confirmed and a policy that names no standby sentinel have nothing
  to go on with. `cmd/sagvd`, `TestFailoverCmd_GoesOnAfterTheFailover`: the
  command, in process, on a real audit log — the flag and the policy go
  together, the chain is recorded once across restarts, a trigger on the
  standby ends the run with exit code 3 and is not recorded twice.
- Decision 4 and decision 1 together, on the release binaries
  (`test/integration`, `TestLiveFailover_TheStandbyGoesOn`, simulated TEE):
  the primary is intruded on; `sagvd failover` restores generation 1 on the
  standby, gate EXACT; `acp-bootstrap` runs its one command, which starts
  `acpctl sentinel watch --parent` on the restored tree, and a new adapter
  is written there; the authority records `CHAIN_CONTINUED` for generation
  2 (in one run 1.5 s after the restore, by the standby's clock) and stays;
  `acpctl genome chain` finds the two outboxes one chain of three
  generations; the authority is stopped and started and takes the failover
  up from its log; the standby's sentinel is killed, and three seconds
  later the trigger is declined on the record, exit code 3, seven events in
  all; one more run adds none.
