# ADR 0020 — The integer door for the LoRA worker

- **Status:** Accepted (2026-09-16)
- **Tags:** genome, gate, determinism, integer, cross-hardware
- **Supersedes / amends:** extends ADR 0008 (the equivalence gate and its
  ladder) and ADR 0013 (the real-model worker); resolves the gap named in
  KNOWN_ISSUES #13.

## Context

The gate's ladder had two live doors for a real model: `pinned-replay`,
EXACT on the runtime that sealed the genome, and `native-float`,
EQUIVALENT within a tolerance across devices. The third rung — the
fixed-point path of `internal/canonical`, byte-portable by construction —
existed for the demo model only. VERIFIABLE-CLAIMS C6 measured why the
third rung matters: CPU and GPU float kernels diverge at the first
transformer block, in float32 and in float64, so no float door can be
EXACT across hardware. Across the CPU↔GPU boundary the only byte-portable
arithmetic is integer arithmetic (the integer GEMM of the determinism
probes was byte-identical on L4, T4 and two CPUs).

What was missing was that arithmetic for the model the worker actually
restores: a Llama-family transformer with a LoRA delta.

## Decision

`workers/genome/vg_genome/integer.py` is the restored model's forward pass
in integer arithmetic, and the gate's third door for it.

1. **The integer model.** Every linear layer's weight — the base weight
   with the LoRA delta merged in a fixed order — is an int8 tensor,
   symmetric per output channel, with a per-channel integer multiplier
   and shift that bring the accumulator back to the hidden fixed point
   (20 fraction bits, int64). Activations are quantised per row to 14
   bits with a power-of-two scale and fed to the GEMM as two int8 halves;
   the GEMM is `torch._int_mm`, int8 × int8 → int32, exact. RMSNorm uses
   an integer square root (Newton, a fixed number of steps, then a
   correction); RoPE uses cosine and sine tables computed by
   `fixedmath.py` with Python's big integers (π by Machin, ln, exp, cos
   and sin by series at 128 fraction bits) and rounded once; softmax and
   SiLU use an integer exponential (argument reduction by ln 2, a Taylor
   polynomial of r/16 squared four times). The final logits are the
   lm_head accumulator times its scale, one IEEE multiplication per entry
   on the CPU. The only other float operations are the one-time weight
   quantisation, elementwise and unfused, also on the CPU.
2. **Its own references.** When a genome is made, `finetune` records,
   beside the float references of every fixture, the integer model's
   logits at the same top-k indices (`expected_integer`), and describes
   the scheme and its fidelity to the float model (`fixtures.integer`:
   max abs error, top-1 agreement). The references are part of the
   fixtures document the genome digests and seals.
3. **The third door.** A restored genome that carries integer references
   is judged at rung 2 by the integer door — `kind: fixed-point`, name
   `integer` — held to *its own* references at tolerance zero: EXACT or
   nothing. It is consulted only when the float doors do not open
   (`acp-bootstrap`, `acpctl genome gate`: a second run of the door
   process with `"door": "integer"` in the request). On the Return Path
   the job's prompts ask the worker for the integer door's outputs beside
   the float ones (`prompts.integer`, `integer_outputs`), the authority
   budgets them, and `sagvd` judges them at rung 2 when rungs 0 and 1
   fail.
4. **Every device computes alike, or refuses.** Right shifts are the
   arithmetic shift every platform gives a signed integer; every left
   shift of a signed value is a multiplication; every division is exact
   by a self-test of the device (CPUs and CUDA divide int64 exactly) or
   is done by restoring long division in shifts and subtractions (MPS
   divides int64 through float32 and fails the self-test). Values that
   could overflow int64 are refused before the operation that would
   overflow — a refusal, being an exact integer comparison, is the same
   on every device.

## What the door proves, and what it does not

The integer door proves that the model restored on this machine is the
same integer model, bit for bit, as the one sealed: an availability
guarantee across hardware that no float door can give. It is a
*different* model from the float one — int8 weights, 14-bit activations,
its own exponential — and its fidelity to the float model is measured
where the genome is made and again by `measure --door integer`, never
assumed: on Qwen2.5-0.5B-Instruct the logits differ from the float ones
by up to a few tenths at a magnitude of about sixteen, and the top-1
token is the same on every fixture measured. The operator who relies on
the integer door across hardware relies on that fidelity, which the
genome records and the semantic dimension of the gate (top-1 agreement)
checks against the float references.

## Consequences

- **A genome carries two references per fixture** and is a little larger;
  recording the integer references costs one integer forward per fixture
  where the genome is made (about six seconds per fixture for 0.5B on
  eight CPU cores; seconds on a GPU). `finetune --no-integer-door` keeps
  the old shape.
- **The ladder is longer where it needs to be.** A pinned runtime still
  opens at rung 0 and other hardware within tolerance at rung 1; the
  integer door runs only when both fail, so nothing already working got
  slower. A genome without integer references is judged as before.
- **Byte-portability is a property of the program, not of the device.**
  The self-tested division and the overflow refusals are what let the
  same code make the same bytes on a CPU, a CUDA GPU and an Apple GPU;
  a device that computed integers wrongly would be refused, not trusted.
- **What is borrowed.** The idea of an integer-only transformer — integer
  softmax, exponential and normalisation — follows I-BERT (Kim et al.,
  2021); the arithmetic here (the exponential's reduction and squaring,
  the big-integer tables, the two-halves GEMM, the self-tested division)
  is this project's, and `docs/prior-art-and-attribution.md` says so.
- **Not a speed path.** The door is a proof of identity, run over a few
  fixtures, not an inference engine; a 7B forward on a CPU takes minutes
  per fixture.
