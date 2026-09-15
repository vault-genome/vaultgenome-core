# vg_genome — the model side of a genome

`vg_genome` fine-tunes a model deterministically and writes what it takes to
bring the fine-tune back, and to prove it came back right:

```
genome/
  genome.json            base model manifest, adapter, recipe, fixtures, runtime
  adapter/               the LoRA delta (PEFT layout) — the only secret part
  fixtures.json          reference outputs of the fine-tuned model
  data/train.jsonl       the training data, so the recipe can be replayed
```

- **Base model by content.** `genome.json` names the base model by the SHA-256
  of every file it loads from. The weights are public and pre-staged or fetched
  anywhere; a destination refuses a base whose files do not hash to the manifest.
- **Delta.** A LoRA adapter (`q_proj,v_proj` by default), saved in the PEFT
  layout. It is what `acpctl genome seal` protects.
- **Recipe.** Data digest, hyper-parameters, seed, thread count, the loss of
  every step, the runtime. On the same pinned runtime `replay` reproduces the
  adapter byte for byte.
- **Fixtures.** For each prompt: the float32 logits at the last position,
  gathered at the reference model's top-k tokens, and the greedy continuation.

## Commands

```bash
pip install --index-url https://download.pytorch.org/whl/cpu torch==2.7.1   # CPU; or the CUDA wheel
pip install -r requirements.txt
export PYTHONPATH=$PWD

python -m vg_genome finetune --base BASE_DIR --base-name Qwen/Qwen2.5-0.5B-Instruct \
    --data examples/drill-facts.jsonl --prompts examples/drill-prompts.json --out genome/
python -m vg_genome replay   --genome genome/ --base BASE_DIR           # recipe → same adapter?
python -m vg_genome measure  --genome genome/ --base BASE_DIR --device cuda
python -m vg_genome verify-base --genome genome/ --base BASE_DIR
```

`door` answers the equivalence gate (`internal/validation/reconstruction`) from a
restored genome; the gate runs it:

```bash
acpctl genome seal --content-dir genome/ --output gen-1.genome --key-out gen-1.key
acpctl genome open --bundle gen-1.genome --key-file gen-1.key --target restored/
acpctl genome gate --genome restored/ -- python -m vg_genome door --genome restored/ --base BASE_DIR --device cuda
```

The gate tries the byte-exact door first (`pinned-replay`), then the float
door within tolerance (`native-float`, `--atol`/`--rtol`), and fails closed
(exit 5) if neither opens. `measure` adds what a tensor comparison cannot:
whether the restored model says the same thing, token for token.

The `acp-compute` worker runs the same door with the genome delivered on
stdin, in memory (ADR 0013): the authority ships `genome.json`, the adapter
and the fixtures' prompts — never the reference outputs — and the door
answers without writing anything to disk. The base model stays on the
worker's disk and must hash to the genome's manifest.

```bash
python -m vg_genome door --stdin-genome --base BASE_DIR --device cuda   # acp-compute's genome.door.command
```

```
stdin : {"schema": "vault-genome/door-request/v1", "genome_id": "...",
         "files": {"genome.json": <base64>, "adapter/adapter_config.json": <base64>,
                   "adapter/adapter_model.safetensors": <base64>, "prompts.json": <base64>}}
stdout: {"outputs": {"fx-000": {"dtype": "f32", "shape": [k], "raw_b64": "..."}, ...}}
```

## Determinism

`determinism.pin` seeds every RNG, fixes the thread count, and requires
deterministic kernels (no TF32, no cuDNN autotuning). Training runs a batch of
one over the examples in file order, AdamW, gradient clipping, no dropout, in
float32. On one machine and library set, two runs of a recipe produce the same
adapter bytes (`tests/`). Across hardware the float kernels differ in their
last bits — which the gate measures rather than assumes.

## Measured

Qwen2.5-0.5B-Instruct, LoRA r=8 on `q_proj,v_proj` (540 672 parameters,
2.1 MiB against 953 MB of base weights), 48 steps on 12 examples, 4 CPU
threads, torch 2.7.1 on an Apple M-series Mac:

| Where the restore ran | Gate | max \|Δ logit\| | top-1 | greedy (16 tokens) |
|---|---|---|---|---|
| the same CPU | **EXACT** | 0 | 16/16 | 16/16 |
| the Mac's GPU (MPS) | **EQUIVALENT** | 1.15e-4 (rel 1.3e-5) | 16/16 | 16/16 |

Training took 10.9 s, the whole run 43 s at a 2.6 GB peak. That recipe's
learning rate (1e-3) taught the twelve facts word for word and overwrote general
knowledge; the drill recipe trains gentler.

## Tests

```bash
PYTHONPATH=. python -m pytest -q tests/        # a tiny random Llama, built locally
VG_GENOME_WORKER=$PWD go test -run TestGenomeGate_RealWorker ../../cmd/acpctl/
VG_GENOME_WORKER=$PWD go test -run TestGenomeReconstructor_RealDoor ../../internal/compute/worker/
```
