# Training continuity: a model's training survives the loss of its machine

A model is being trained on one machine. The machine is lost while it
trains. On another, the last sealed generation comes back under its gate —
and training goes on from it, to where the recipe would be. This kit runs
that on real hardware and holds the result to the recipe, byte for byte.

```bash
bash scripts/hardware-test/training-continuity/run.sh <gcp-project> [zone]
bash scripts/hardware-test/training-continuity/aws.sh [region] [instance-type] [run.sh evidence stamp]
```

**Design:** [ADR 0040](../../../docs/adr/0040-a-genome-carries-the-state-training-stood-in.md)
(a genome carries the state training stood in),
[ADR 0012](../../../docs/adr/0012-sentinel-and-policy-driven-failover.md) (the
sentinel and the failover), operator runbook
[07](../../../docs/operator/07_failover.md), section 6.

## `run.sh`: two AMD SEV-SNP Confidential VMs on Compute Engine

`run.sh` builds `sagvd`, `acp-bootstrap`, `acpctl` and `keygen` for
linux/amd64, packs `workers/genome`, and boots two `n2d-standard-8` SEV-SNP
VMs in one zone. The scaffolding is the failover drill's
([`gcp-failover`](../gcp-failover/): `common.sh`, the authority and the
destination on the standby); what is new is in [`recipe.sh`](recipe.sh),
[`primary.sh`](primary.sh) and the last steps of [`standby.sh`](standby.sh).

The recipe is one, on both machines ([`recipe.sh`](recipe.sh)):
Qwen2.5-0.5B-Instruct at a pinned revision, `drill-facts.jsonl`, LoRA rank 8
on `q_proj` and `v_proj`, 8 threads, float32 on the CPU, on the hash-pinned
runtime.

1. The **standby** provisions the release authority (its escrow key made in
   its process and sealed to its chip, ADR 0016) and the destination, and
   publishes the escrow public key.
2. The **primary** takes the recipe's first **80** steps and writes
   generation 0. The sentinel — its seed sealed to the primary's chip —
   seals it, attests the record with the chip, and beats a signed heartbeat;
   the outbox is replicated to a bucket.
3. The operator signs a failover policy that pins the primary's sentinel key
   and chip and the standby's measurement, **acts on a lost heartbeat only**
   (30 s; no compromise report counts) and requires the gate to be
   **EXACT**. The authority arms.
4. The primary **goes on from its own genome**: `finetune --continue` puts
   the adapter, the optimizer and the place in the data back where step 80
   left them and takes steps 81 to **160**. The sentinel seals the result as
   generation 1. The primary then holds it to the recipe: `replay` runs steps
   1 to 160 from the base and compares the adapter.
5. The primary goes on again, toward step 240 — and **is lost**: with steps
   being taken, it writes the time and powers itself off through the
   kernel's sysrq trigger. No shutdown, no `stopped` heartbeat, no report.
   `run.sh` sees the machine dead in Google's API and deletes it, on the
   record (`operator-destroy.txt`). The steps after 160 go with it.
6. The authority sees the heartbeat stop rising, chooses generation 1 — the
   last the sentinel sealed — and releases its escrowed key to the standby,
   which attests with its own chip, restores the genome, recomputes the
   sealed fixtures and signs a receipt. The policy accepts the receipt only
   with an EXACT gate.
7. **Training goes on on the standby**: `finetune --continue` from the
   restored genome, steps 161 to **240**. The recipe, the data, the
   fixtures' prompts and the state are the genome's; the standby is given
   the number 240 and nothing else.
8. The standby holds what it produced to the whole recipe, on its own chip:
   - `replay` runs the recipe from its first step — 240 steps from the
     base — and compares the adapter and the losses with the continued
     genome's;
   - the recipe is run there in one go, 240 steps, and every file the recipe
     decides is compared: the adapter and its config, the fixtures, the
     data, the optimizer's state, the cursor, the generators;
   - the continued genome is put through `acpctl genome gate`.

Reports come back to `evidence/<stamp>/`, `run.sh` checks them and prints
`RESULT: PASS` or `FAIL`; both VMs and the bucket are deleted on every exit.

### What the record holds

| File | What it says |
|---|---|
| `runner.log` | the run, step by step, and every check with its verdict |
| `code-rev.txt`, `code-dirty.txt`, `binaries.sha256`, `kit.sha256` | the tree and the binaries that ran |
| `operator-destroy.txt` | the primary seen `TERMINATED` in Google's API, then deleted |
| `primary/finetune-0.json`, `finetune-1.json` | the two genomes written on the primary: step, `continued_from`, the adapter's SHA-256 |
| `primary/generation-1-training.json`, `generation-1.sha256` | generation 1's `training` section, and the SHA-256 of each of its files |
| `primary/replay-1.json` | generation 1 against the whole recipe, on the primary |
| `primary/finetune-2.log` | the steps being taken when the power went |
| `standby/report.json`, `failover-policy.json` | the failover: trigger, generation, key release, restore, gate, timings |
| `standby/restored.sha256`, `restored-training.json` | what came back: file by file the primary's generation 1; where training stood |
| `standby/continue.json`, `continue.log`, `continued-training.json`, `continued.sha256` | training going on from step 160 to 240 on the standby, and its result |
| `standby/replay.json` | the continued genome against the whole recipe, on the standby |
| `standby/whole.json`, `whole.sha256`, `compare.txt` | the recipe in one go on the standby, and the file-by-file comparison |
| `standby/gate-continued.json` | the gate's judgement of the continued genome |
| `standby/verdict.txt` | one line |
| `*/system.txt`, `metadata.txt`, `pip-freeze.txt` | the machines and the runtime |
| `sha256sums.txt` | every file of the record |

No adapter, optimizer state or key is in the record: digests only.

### What it does not show

- **Who starts the training.** On the standby `finetune --continue` is a
  step of the kit's script. A standby that starts it by itself after a
  failover, starts a sentinel for what it produces and takes the next
  failover is not built yet; ADR 0012's rule that one policy serial performs
  one failover is unchanged.
- **Another arithmetic.** Both machines are the same machine type and report
  the same CPU; the gate is required to be EXACT, and `replay` on the standby
  is what shows the steps taken there to be the recipe's. Where a
  destination's kernels differ in their last bits the gate says EQUIVALENT
  and training continued there is the recipe within that difference —
  `replay` on that machine says how far. `aws.sh` lays another CPU's digests
  beside these.
- **A larger model or a GPU.** The base is 0.5B on the CPU.

## `aws.sh`: the same arithmetic on EC2, and beside Compute Engine's

`aws.sh` launches one `m6a.2xlarge` with AMD SEV-SNP in `us-east-2`, and
there ([`aws-guest.sh`](aws-guest.sh)) runs the same recipe stopped at steps
80 and 160 and continued from each genome's state to 240, `replay`, and the
recipe in one go, with the same comparison. There is no sentinel, authority
or failover in it: it answers for that machine's arithmetic only.

Given the stamp of a `run.sh` record, it lays its digests beside Compute
Engine's — generation 1 at step 160 against the primary's, the continued
genome at step 240 against the standby's — in `beside-compute-engine.txt`.
The same digests on both clouds mean the two CPUs take the recipe to the
same bits, so a genome moved from one to the other is continued exactly.
Whatever the comparison shows is written down; it does not decide the
script's result. Its record is in `evidence/aws/<stamp>/`.

## Cost

`run.sh`: two `n2d-standard-8` SEV-SNP VMs for about forty minutes and a
bucket of a few megabytes. `aws.sh`: one `m6a.2xlarge` for about twenty-five
minutes. Under a dollar each.
