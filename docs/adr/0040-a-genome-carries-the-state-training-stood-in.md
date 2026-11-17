# ADR 0040 — A genome carries the state training stood in: training goes on from a restored genome and arrives where the recipe arrives

- **Status:** Accepted (2026-11-10) — implemented: `workers/genome/vg_genome/state.py`, `finetune.continue_training`, `vg-genome finetune --continue`; held by `workers/genome/tests/test_continuity.py`; on real hardware by `scripts/hardware-test/training-continuity/`: two runs on Compute Engine SEV-SNP and one on EC2 SEV-SNP, 2026-11-11 (C61)
- **Date:** 2026-11-10
- **Deciders:** Serhii Nikolaichuk, Rodion Sorokin
- **Extends:** ADR 0012 (the sentinel seals each state as the next generation; the failover), ADR 0013 (the worker restores the genome: the door), ADR 0020 (the integer door)
- **Amends:** `genome.json` (`vault-genome/lora-genome/v1`) gains the section `training`; a genome directory gains `state/`

## Context

A genome brings a fine-tuned model back and proves it came back right: the
base by content, the adapter, the recipe that produced it, fixtures a
destination recomputes. On a pinned runtime `replay` runs the recipe again
and yields the sealed adapter byte for byte.

What a genome could not do is be gone on from. `train()` loaded the base,
injected a new adapter and built a new optimizer: it could start a recipe
and nothing else. After a failover the model on the standby was restored,
judged by its gate, and at rest (`docs/operator/07_failover.md`, section 6,
ended at "start a sentinel there"). Where a kit says "keep training" —
`gcp-failover/primary.sh`, generation 1 — it runs a second recipe from the
base. The steps a primary had taken were kept as their result, not as
something more steps could be added to.

The adapter alone is not enough to add them. The loop is AdamW with gradient
clipping over a batch of one, the examples in file order, no dropout, no
shuffling. Its position after `k` steps is: the adapter; for every adapter
tensor, AdamW's first and second moments and its step count (the bias
correction is a function of it); the place in the data, `k mod examples`;
and the generators the runtime seeds — which this loop does not advance,
after the adapter's initialisation has drawn from them. Continue from the
adapter with a fresh optimizer and training arrives somewhere else: the test
`test_without_the_optimizer_state_training_would_arrive_elsewhere` zeroes the
moments of a stopped genome and gets another adapter.

## Decision

1. **Every genome the worker writes carries the state training stood in.**
   `state/optimizer.safetensors` holds, for every adapter tensor and under
   that tensor's own key, `<key>/exp_avg`, `<key>/exp_avg_sq` and
   `<key>/step` (float32). `state/cursor.json` holds the step, the number of
   examples, the example the next step takes and the data's SHA-256.
   `state/rng.json` holds the state of Python's, numpy's and torch's
   generators (and the CUDA device's when training ran there). The state is
   safetensors and JSON: tensors and numbers, nothing a loader executes.
   `genome.json` gains

   ```json
   "training": {
     "step": 160,
     "continued_from": [{"step": 80, "adapter_sha256": "sha256:…", "created_at": "…", "runtime": {}}],
     "state": {"dir": "state", "files": {"cursor.json": "sha256:…", "optimizer.safetensors": "sha256:…", "rng.json": "sha256:…"}}
   }
   ```

   The schema stays `vault-genome/lora-genome/v1`. The section is an
   addition: `internal/genome/lora.Parse` reads what the gate needs and
   allows the rest, the door reads the adapter and the fixtures, and the gate
   job ships the worker `genome.json`, the adapter's files and the prompts
   (`cmd/sagvd/genome_job.go`), so the state never leaves the bundle for a
   gate. A genome written before this has no section; it restores and passes
   its gate as before, and is not continued.

2. **`vg-genome finetune --continue GENOME --base BASE --steps N --out OUT`
   takes the steps from where the genome stands to `N`.** Everything else is
   the genome's: the base's name and manifest, the data, the recipe's
   hyper-parameters, seed, thread count, device and dtype, the fixtures'
   prompts and their parameters. A flag that would set one of them is
   refused, by name. Before a step is taken: the base is checked against the
   manifest; the data, the adapter and the fixtures against their digests in
   `genome.json`; each state file against its digest; the cursor against the
   recipe (the step, the data, the number of examples); and the optimizer's
   state against the adapter — the same keys, the same shapes, every tensor
   at the genome's step. The optimizer is given its state through its own
   `load_state_dict`.

3. **The genome written is the recipe taken to `N`**, not a second recipe.
   `recipe.steps` is `N`; `recipe.losses` holds all `N` losses, the earlier
   genome's first; `recipe.train_seconds` is the sum. `replay` is unchanged
   and needs to know nothing of the stop: it runs the recipe from its first
   step and compares with the sealed adapter. `training.continued_from`
   lists the genomes this one was continued from, oldest first: the step
   each stood at, its adapter's SHA-256, when it was written and the runtime
   it was written on. A genome can be continued any number of times.

4. **What is promised, and where.** On one pinned runtime and one
   arithmetic, training continued from a genome for the remaining steps
   yields the adapter, the fixtures and the state that the recipe yields in
   one go — byte for byte. Whether a destination has the source's arithmetic
   is measured, not assumed, and by two instruments. The gate measures the
   model's outputs: a destination that restores the genome EXACT computes
   them to the source's bits. Training uses kernels a forward pass does not,
   so an EXACT gate is the condition to expect the same steps, not the proof
   of them; the proof is `replay` on the destination, which runs the whole
   recipe there and compares it with the continued adapter. Where the
   kernels differ in their last bits — another CPU family, a GPU — the gate
   says EQUIVALENT, training continued there is the recipe within that
   difference, and `replay` states it (`max_rel_l2`). The genome's `runtime`
   and `continued_from[].runtime` say which machine took which steps. Nothing
   here claims more than what `replay` reports.

5. **The recipe's threads, device and dtype go with the genome.** The
   thread count decides how the kernels split their sums: a destination with
   fewer cores runs the recipe's count all the same. A recipe trained on
   `cuda` continues on `cuda` or is refused — the recipe names where it was
   computed, and a genome whose steps were taken on two kinds of device
   would name one of them falsely.

6. **The state is secret and sealed with the adapter.** The moments are
   made of the training data's gradients. The sentinel seals the genome
   directory whole (`contentdir.Capture`), so `state/` is in the bundle's
   ciphertext, under the same key, in the same generation, and nowhere else.

## Consequences

- A generation is larger: the state is twice the adapter (two moments per
  tensor) plus the generators (about 18 kB). For the drill's adapter —
  Qwen2.5-0.5B-Instruct, rank 8 on `q_proj` and `v_proj`, 540 672
  parameters — the adapter is 2 175 168 bytes and the state 4 382 827.
- `finetune`'s flags keep their defaults; they are applied after parsing so
  that `--continue` can tell a flag given from a flag left alone. Its summary
  gains `adapter_sha256`, `step` and `continued_from`.
- The generators are carried although this loop does not advance them:
  `state/rng.json` is the same file at every step of a recipe today. If the
  loop ever draws — dropout, a shuffled order — the equality in (4) does not
  come to depend on nobody having noticed.
- Going on is going on with the same recipe. New data, another learning
  rate, another seed are another recipe, started with `finetune`; nothing
  here mixes the two, because a genome that did would have no recipe `replay`
  could run.
- The optimizer is AdamW, as the recipe records. On `mps` the device's
  generator is not carried (the CPU's and CUDA's are).
- This ADR does not start anything by itself. Who runs `--continue` on the
  standby after a failover, the sentinel that seals what it produces, and a
  model that answers while it trains are the next decisions; ADR 0012's rule
  that one policy serial performs at most one failover stands.

## Evidence

- `workers/genome/tests/test_continuity.py`, on the pinned runtime, a tiny
  Llama built in the test: a recipe stopped at step 25 of 60 (inside a pass
  over the data) and continued is, file by file, the recipe run in one go —
  adapter, adapter config, fixtures, data, optimizer state, cursor,
  generators — with the same 60 losses; `replay` of the continued genome is
  exact; stopped twice (11, 38) it arrives there too; in bfloat16 as well;
  through the command line, in another process. With the moments zeroed it
  arrives elsewhere. An edited state file, adapter, fixtures or data, a
  cursor or an optimizer step that disagree with the recipe (their digests
  made to agree), a state missing a tensor, another base, a total not
  beyond the step reached, a genome without the section: each is refused,
  and the genome without the section still restores exactly.
- `cmd/acpctl` `TestGenomeGate_RealWorker` and `internal/compute/worker`
  `TestGenomeReconstructor_RealDoor` seal, open and gate a genome that
  carries `state/`, against the real door.
- The drill's base and recipe (Qwen2.5-0.5B-Instruct at revision
  `7ae55760…`, `drill-facts.jsonl`, rank 8, 4 threads, float32) on an Apple
  M-series Mac on the pinned libraries: stopped at step 15 and continued to
  40, the adapter (`sha256:7cd9c4f2…`), the fixtures and the state are those
  of the recipe in one go, and `replay` reports `exact: true`,
  `max_rel_l2: 0.0`, `losses_equal: true`. A developer's machine, not a
  record.
- On confidential hardware, 2026-11-11 (`VERIFIABLE-CLAIMS.md` C61,
  `scripts/hardware-test/training-continuity/`). Two AMD SEV-SNP guests on
  Compute Engine, both AMD EPYC 7B13: the primary took 80 steps, went on
  from its own genome to 160, was switched off while it trained toward 240
  and deleted; on 30 s of silence generation 1 failed over under a policy
  that requires an EXACT gate; the standby went on from the restored
  genome's state to 240. `replay` there: `exact: true`,
  `max_abs_diff: 0.0`, 240 losses equal; the recipe run there in one go: the
  same 7 files and 240 losses (`evidence/20261111T135725Z/`). The run before
  it, on two other guests, gave the same digests
  (`evidence/20261111T132834Z/`). One EC2 instance with SEV-SNP, an AMD EPYC
  7R13, stopped at 80 and 160 and continued to 240, is the recipe in one go
  there, and its digests at steps 160 and 240 are Compute Engine's
  (`evidence/aws/20261111T143104Z/`). Decision 4's two instruments agreed on
  these machines: the gate said EXACT and `replay` said exact. A CPU of
  another family and a GPU have not been measured.
