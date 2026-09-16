# The integer door across the CPU/GPU boundary

The gate's third door ([ADR 0020](../../../docs/adr/0020-the-integer-door-for-the-lora-worker.md))
computes the restored model's forward pass in integer arithmetic, so a
genome gives the same bytes on any CPU or GPU. This kit measures that on
real hardware: one NVIDIA L4 VM and its host CPUs, two genomes.

```bash
bash scripts/hardware-test/integer-door/run.sh <gcp-project>     # about an hour, roughly a dollar
```

`run.sh` builds `acpctl`, packs `workers/genome`, boots a `g2-standard-8`
(one L4, 24 GB; 8 vCPU, 32 GB) from the Deep Learning VM image, runs
[`l4-integer.sh`](l4-integer.sh) on it and brings the results back to
`evidence/<stamp>/`; the VM and the bucket are deleted on exit, on success
or failure. The adapters never leave the VM.

- **A. A genome made on the CPU.** Qwen2.5-0.5B-Instruct fine-tuned on the
  VM's CPUs in float32 (the continuity drills' recipe), its integer
  references recorded on the CPU; sealed, restored, and the integer door
  measured on the CPU and on the L4 against those references (`measure
  --door integer`); the gate run on the L4 at zero tolerance, where the
  float doors must fail (VERIFIABLE-CLAIMS C6) and the integer door must
  open, and at the default tolerance; and the float door measured on the
  L4 for the cross-device error, for context.
- **B. A genome made on the GPU.** Qwen2.5-7B-Instruct fine-tuned on the
  L4 in bfloat16, its integer references recorded on the L4; the integer
  door measured on the L4 against them (all fixtures) and on the CPU (the
  first three — a 7B integer forward on eight cores is slow) against the
  references the GPU made.

## Results — run `20260916T164511Z`

One `g2-standard-8` in us-central1-c: an NVIDIA L4 (23 GB) and eight
Intel Xeon @ 2.20 GHz vCPUs, torch 2.7.1+cu126; both devices divide
int64 exactly (`divides-exactly.txt`), so both took the door's fast path.
The whole guest run took 15.6 minutes.

**A. Qwen2.5-0.5B-Instruct, made on the CPU** (LoRA r=8 on `q_proj,v_proj`,
540 672 parameters, 120 steps in 59.0 s, float32; `a-genome.json`,
`a-fixtures.json`):

| The integer door, held to the references recorded on the CPU | exact | top-1 vs float | time |
| - | - | - | - |
| on the CPU (`a-measure-integer-cpu.json`) | **16 / 16** | 16 / 16 | 9.0 s (build 2.7 s) |
| on the L4 (`a-measure-integer-cuda.json`) | **16 / 16** | 16 / 16 | 6.6 s (build 2.9 s) |

The SHA-256 of every fixture's output is the same on the CPU and on the L4
(`results[].sha256`, 16 of 16). The float door on the L4, for context
(`a-measure-float-cuda.json`): max abs err **1.52e-4** against the CPU
references, top-1 16/16, greedy 16/16 — EQUIVALENT, never EXACT, as
[gpu-exact](../gpu-exact/README.md) found.

| `acpctl genome gate` | door 0 pinned replay | door 1 native float | door 2 integer | verdict |
| - | - | - | - | - |
| on the L4, `--atol 0 --rtol 0` (`a-gate-cuda-tol0.json`) | FAIL, 1.52e-4 | FAIL, 1.52e-4 | **EXACT, 0** | **EXACT** at rung 2 (29.5 s) |
| on the L4, default tolerance (`a-gate-cuda.json`) | FAIL, 1.52e-4 | **EQUIVALENT** | not consulted | EQUIVALENT at rung 1 (11.0 s) |
| on the CPU, default tolerance (`a-gate-cpu.json`) | **EXACT** | — | — | EXACT at rung 0 (12.5 s) |

The integer door's fidelity to the float model (`fixtures.integer.fidelity`,
recorded where the genome was made and measured again on both devices):
top-1 the same on 16/16 fixtures; max abs err **2.72**, max rel err 0.25
(per fixture between 0.9 and 2.7, on logits this fine-tune drove to
magnitudes of tens). A different arithmetic, the same answers.

**B. Qwen2.5-7B-Instruct, made on the L4 in bfloat16** (LoRA r=8,
2 523 136 parameters, 160 steps in 32.6 s; the integer references
recorded on the L4 after the float model was moved to the host's memory;
`b-genome.json`, `b-fixtures.json`):

| The integer door, held to the references recorded on the L4 | exact | top-1 vs float | time |
| - | - | - | - |
| on the L4, all 16 fixtures (`b-measure-integer-cuda.json`) | **16 / 16** | 16 / 16 | 8.6 s (build 72.5 s) |
| on the CPU, the first 3 fixtures (`b-measure-integer-cpu.json`) | **3 / 3** | 3 / 3 | 6.7 s (build 57.2 s) |

The SHA-256 of each of the three outputs is the same on the CPU and on the
L4. Fidelity at 7B: top-1 16/16, max abs err **1.32**, max rel err 0.14
(per fixture 0.37–1.32). Building the integer model of a 7B base takes
about a minute on either device (int8 weights of 7.6 GB); a 7B integer
forward of a 20-token fixture then takes about 2 s on eight Xeon cores and
about 0.5 s on the L4.

**What this shows.** The float doors cannot be EXACT across devices — the
first probe measured that ([C6](../../../VERIFIABLE-CLAIMS.md#c6)) and it
holds here (1.52e-4 on the 0.5B). The integer door is: the same genome
gives the same bytes on an Intel Xeon and an NVIDIA L4 at 0.5B and at 7B,
whichever device made the references, and the gate holds it to those
bytes at tolerance zero. What it does not show: identity with the float
model's own outputs, which is impossible across devices, and which the
integer door's measured fidelity (top-1 agreement, a logit error the
genome records) stands in for.

## Evidence files

- `a-*`: the 0.5B genome's `genome.json` and `fixtures.json` (public:
  hyper-parameters, losses, prompts, float and integer references),
  `finetune.json`/`.log`, `seal.json`, `open.json`, `verify.json`,
  `measure-integer-cpu.json`, `measure-integer-cuda.json` (per fixture:
  exact, errors, top-1, the SHA-256 of the output), `measure-float-cuda.json`,
  `gate-cuda-tol0.json`, `gate-cuda.json`, `gate-cpu.json` (the ladder,
  every attempt) and their logs.
- `b-*`: the same for the 7B genome: `genome.json`, `fixtures.json`,
  `finetune.json`/`.log`, `seal.json`, `open.json`,
  `measure-integer-cuda.json`, `measure-integer-cpu.json` (three fixtures)
  and their logs.
- `divides-exactly.txt` (the door's division self-test on both devices),
  `torch.txt`, `nvidia-smi.txt`, `gpu-memory.txt`, `system.txt`,
  `metadata.txt`, `pip-freeze.txt`, `base-size.txt`, `inputs.sha256`,
  `worker.sha256` (the door's source as run), `timeline.txt`, `steps.txt`,
  `console.log`.

The adapters (the secret part of each genome) and the bundles' keys never
left the VM; the evidence holds no key or token.
