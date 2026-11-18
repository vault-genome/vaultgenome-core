# The closed turn: a standby that goes on by itself

A model is being trained on one machine, and it answers. The machine is
lost while it trains. The last sealed generation comes back on a standby
under its gate — and from there nobody does anything: the standby trains
on, seals what it trains under a sentinel of its own, and answers, each
answer naming the generation it came from. The release authority, on a
third machine, records the chain the standby continues and goes on
watching it. This kit runs that on real hardware.

```bash
bash scripts/hardware-test/closed-turn/dry-run.sh                      # no cloud: the standby's layout, on a workstation
bash scripts/hardware-test/closed-turn/run.sh <gcp-project>            # three SEV-SNP machines
bash scripts/hardware-test/closed-turn/run.sh <gcp-project> negative   # a standby whose gate cannot pass
bash scripts/hardware-test/closed-turn/check.sh <evidence directory>   # hold a record to the checks again
```

**Design:** [ADR 0041](../../../docs/adr/0041-a-standby-goes-on-by-itself.md)
(a standby goes on by itself),
[ADR 0040](../../../docs/adr/0040-a-genome-carries-the-state-training-stood-in.md)
(a genome carries the state training stood in),
[ADR 0012](../../../docs/adr/0012-sentinel-and-policy-driven-failover.md)
(the sentinel and the failover), operator runbook
[07](../../../docs/operator/07_failover.md), sections 2, 5 and 6.

## The three machines

All three are AMD SEV-SNP Confidential VMs on Compute Engine and attest
with their own chip.

| | Script | What it holds |
|---|---|---|
| **A**, the primary | [`primary.sh`](primary.sh) | the training and, beside it, the sentinel; it answers one question from generation 1 |
| **R**, the authority | [`authority.sh`](authority.sh) | `sagvd failover` and nothing else, in another region; its escrow key sealed to its chip (ADR 0016) |
| **B**, the standby | [`standby.sh`](standby.sh) | the destination (`acp-bootstrap`), its gate, and the one command it runs after a restore its gate passed: [`go-on.sh`](go-on.sh) |

A and B are one machine type in one zone; the recipe is the
training-continuity kit's ([`recipe.sh`](../training-continuity/recipe.sh)):
Qwen2.5-0.5B-Instruct at a pinned revision, LoRA rank 8, 8 threads, float32
on the CPU, on the hash-pinned runtime. The scaffolding is the failover
drill's ([`common.sh`](../gcp-failover/common.sh)); what the three scripts
share beyond it is in [`lib.sh`](lib.sh).

## What happens

1. **R** provisions the release authority and publishes its escrow public
   key and the destination's TLS material.
2. **B** makes its own sentinel's key, seals it to its chip and hands the
   public half and the chip's identity to the operator. Its `acp-bootstrap`
   is configured with `genome.after_restore`: one command, `go-on.sh`.
3. **A** takes the recipe's first 80 steps (generation 0); its sentinel
   seals it and beats a signed heartbeat.
4. The operator signs a **v2 failover policy**. Besides the primary's
   sentinel and chip and the standby's measurement it names, before any
   failure, **the standby's own sentinel**: its key, and the measurement
   every record it signs must be attested at. The only trigger is a lost
   heartbeat (30 s), and the gate must be EXACT. R arms.
5. A goes on to step 160 (generation 1), holds it to the recipe by `replay`,
   and **answers a question from it**. It goes on toward step 240 — and is
   switched off while it trains. `run.sh` sees it dead in Google's API and
   deletes it, on the record.
6. R sees the heartbeat stop, releases generation 1's escrowed key to B, and
   confirms the restore with its EXACT gate. **R does not exit.**
7. On B the gate has passed, so `acp-bootstrap` runs `go-on.sh`, once. It
   moves no key. It puts the restored genome where the model lives and
   starts three services:
   - B's **sentinel**, on the model's directory, with the bundle the genome
     was restored from as its parent;
   - the model's **answers** (`vg-genome answer --listen`), from that
     directory;
   - the **training**: `finetune --continue` to step 240, whose result takes
     the model's place when it is whole.
8. The kit's script on B starts nothing. It **asks the question again and
   again** while training goes on: the answers come from step 160 — the
   tokens A gave — and then from step 240, and each says which.
9. B's sentinel seals the trained state as **generation 2**: under its own
   key, with B's chip's report, naming A's generation 1 as its parent.
   Nothing is sealed from the state as restored.
10. R reads B's outbox, holds generation 2 to the policy, and writes
    **`CHAIN_CONTINUED`** to its audit log. It goes on watching B.
11. With R still watching, generation 2 is **opened again**: R releases its
    escrowed key to B as any attested release, B restores it beside the
    model under the gate, and the question is recomputed from it without
    the listener — the same tokens the listener gave. The second restore's
    command starts nothing again.
12. B holds what training made there to the whole recipe, on its own chip:
    `replay` from the first step, and the recipe run there in one go,
    every file compared.
13. `run.sh` tells R to stop; R was still watching, and leaves with 0.

Reports come back to `evidence/<stamp>/`; [`check.sh`](check.sh) holds
them to the list above and `run.sh` prints `RESULT: PASS` or `FAIL`. The
machines, the firewall rule and the bucket are deleted on every exit.

### The negative run

`run.sh <project> negative` boots the same three machines, and on B changes
one byte of the base model. The genome's manifest pins the base, so the
gate's backend refuses to load it: the gate cannot be passed. The restore
**fails**, `go-on.sh` is not run, and nothing starts on B — no model
directory, no outbox, no service, no listener — and no file of the genome
is left under its restore directory. B says so when R asks for
the receipt, and R leaves at once with 1: a failover decided and not
completed, `integrity[restore_failed]` and B's reason in its report, and
no `CROSS_CLOUD_RESTORE_COMPLETED` and no `CHAIN_CONTINUED` on its log.
The record goes to `evidence/negative/<stamp>/`.

## `dry-run.sh`: the standby's layout without a cloud

`dry-run.sh` runs `go-on.sh` on a workstation, with a simulated TEE and
the worker tests' tiny model: a "primary" sentinel seals generation 0,
`go-on.sh` is run the way `acp-bootstrap` runs it, and eleven checks hold
what follows — the first answer from the restored state, training taking
the model's place, one generation sealed with its parent and its report,
the chain across the two outboxes, the answers from the new state, the
same tokens without the listener, and a second restore that starts
nothing. It needs Go and a Python with the worker's runtime
(`VG_PYTHON`). It says nothing about real chips or real timings.

## What the record holds

| File | What it says |
|---|---|
| `runner.log` | the run, step by step, and every check with its verdict |
| `mode.txt`, `legs.txt`, `machines.txt` | turn or negative; how each machine ended; names, zones, addresses, the bucket and the rule |
| `code-rev.txt`, `code-dirty.txt`, `binaries.sha256`, `kit.sha256` | the tree and the binaries that ran |
| `operator-destroy.txt` | the primary seen `TERMINATED` in Google's API, then deleted |
| `primary/generation-1-training.json`, `generation-1.sha256`, `generation-1.seal.json`, `replay-1.json` | generation 1: where training stood, its files, its seal record, and the recipe held to it |
| `primary/answer-1.json` | the question answered from generation 1 on the primary |
| `authority/failover-policy.json`, `failover-verify.txt` | the v2 policy and what it names |
| `authority/report.json`, `report-continued.json` | the failover and the chain the standby continued: trigger, generation, release, restore, gate, timings; `continued` |
| `authority/reopen-restore.json`, `reopen-confirm.json` | generation 2 released again and its restore confirmed |
| `authority/audit-events.jsonl`, `audit-kinds.txt`, `audit-verify.json`, `xcc-audit.db`, `audit-public-key.pem` | the authority's audit log, its kinds in order, and its offline verification |
| `standby/after-restore-config.json`, `restore-record.json`, `go-on.log` | the one command, what the destination says it did, and what the command said |
| `standby/answers.jsonl`, `answer-restored.json`, `answer-continued.json` | every answer given while training went on; the first from each generation |
| `standby/generation-2.seal.json`, `standby-outbox-generations.txt`, `chain.txt` | the generation the standby's sentinel sealed, what its outbox holds, and the chain across the two machines |
| `standby/restore-records-after.json`, `reopened.sha256`, `answer-reopened.json` | generation 2 opened again: its files, and the question recomputed from it |
| `standby/continued-training.json`, `continued.sha256`, `replay.json`, `whole.sha256`, `compare.txt` | what training made on the standby, against the whole recipe |
| `standby/services.txt`, `services.log` | the three services at the end, and their journal |
| `standby/nothing-started.txt` | negative run: the restore's state and error, what was looked for and not found, and what is left under the restore directory |
| `*/verdict.txt`, `*/steps.txt`, `*/system.txt`, `metadata.txt` | one line; the script's own account; the machines |
| `sha256sums.txt` | every file of the record |

No adapter, optimizer state or key is in the record: digests, answers and
token IDs only.

## What it does not show

- **A second turn.** One policy serial performs one failover (ADR 0012).
  When the standby is lost in its turn the authority declines, on the
  record; that, and an authority restarted in the middle of a failover, are
  exercised by the live test on the release binaries
  (`TestLiveFailover_TheStandbyGoesOn`), not on hardware by this kit.
- **A standby that reboots.** `go-on.sh` starts transient systemd units.
  They do not come back after a reboot of the standby; units that do are
  the operator's to write.
- **Who may ask.** The listener is on loopback behind a bearer token, and
  the kit asks one question. No load, no TLS on the listener, no
  accounting of who asked.
- **A gate that runs and says FAIL.** In the negative run the gate's
  backend cannot run at all (`failed`). A backend that runs and misses the
  sealed references (`gate_failed`) takes the same branch in
  `acp-bootstrap` — the command is not run — and is covered by its unit
  tests, not here.
- **Another arithmetic.** A and B are one machine type and report one CPU
  model; the gate is required to be EXACT. See the training-continuity
  kit's [README](../training-continuity/README.md) for what has been
  measured across CPUs.

## Records

None yet: the kit has not run on hardware.

## Cost

`run.sh`: two `n2d-standard-8` and one `n2d-standard-4` SEV-SNP VMs for
about an hour, and a bucket of about a hundred megabytes. A and B are 16
N2D vCPUs in one region: where the project's quota for that family is 16,
nothing else of it starts there while the kit runs, which is why R is in
another region. Not every zone offers SEV-SNP on `n2d`; the defaults are
zones where the kits' records were made.

An outbox travels whole, some megabytes at a time. The bucket is in R's
region, so what R reads every two seconds stays there; A's and B's
uploads are free to send; B fetches A's outbox across regions every
fifteen seconds, which is the inter-region traffic the run pays for —
some gigabytes. By list prices that is under two dollars a run: an
estimate until the first record says what it was.
