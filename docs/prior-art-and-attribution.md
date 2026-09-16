# Prior Art & Attribution — what is ours, what we stand on

**Status:** living document
**Date:** 2026-09-13

VaultGenome is a **reference product for AI continuity**: sealing an AI model as a
regenerable, attested asset and bringing it back to life on other hardware with a
signed guarantee. Its value is the **assembled whole**, not any single primitive.
Some pieces are our inventions; some are established techniques we integrate and
attest. This document states honestly which is which, so the reference can be
shown to any expert audience without overclaiming. If a reviewer says "X already
exists," the answer is: yes — and it is cited here, and our contribution is the
attested continuity system that composes it.

## The honest map

| Component | Status | Reference |
|---|---|---|
| **AI Genome** — model as a signed, content-addressed *recovery recipe* (not a snapshot) | **Ours** | `internal/contracts/genome_descriptor` (R-14 content addressing) |
| **Real TEE attestation** wired into the product (AMD SEV-SNP, verified to AMD KDS) | **Ours (integration)**; TEE + attestation primitives are the hardware vendors' | `internal/shared/tee`, `docs/adr/0007`, AMD SEV-SNP / AWS Nitro / Intel SGX |
| **X25519 ECIES key encapsulation** binding the restore key to the destination TEE | **Ours (integration)**; X25519/HKDF/AES-GCM are standard | `internal/vault/kms/kem.go` |
| **Governance layer** — RFC 6962 transparency log, audit chain, witness receipts, succession/probe-battery | **Ours**; builds on RFC 6962 (Merkle transparency) | `internal/contracts/{witness,probe_battery,continuity_proof}` |
| **Numerical equivalence gate** — signed EXACT/EQUIVALENT/FAIL verdict on sealed fixtures, fail-closed | **Ours** | `internal/validation/equivalence` (ADR 0008) |
| **Determinism ladder** — try recompute doors highest-fidelity → most-portable, gate each, fail-closed | **Ours (orchestration)** | `internal/validation/reconstruction` |
| ↳ rung `pinned-replay` — byte-exact replay on a pinned+attested runtime | **Ours** (the attestation/seal layer) | `KindPinnedReplay` |
| ↳ rung `reproducible-float` — byte-identical float across CPU/GPU (correct rounding incl. transcendentals + fixed reduction order) | **BORROWED** | **RepDL**, **ReproBLAS** (Demmel et al.) |
| ↳ rung `fixed-point` — integer path, byte-portable *by construction* across any CPU/GPU | **Ours** | `internal/canonical` (fixedpoint*.go) for the demo model; `workers/genome/vg_genome/integer.py` for the real LoRA model (ADR 0020) — the integer-only transformer *idea* is I-BERT's (Kim et al., 2021), the arithmetic is ours |
| **Attested cross-hardware regeneration as one continuity system** | **Ours — the assembly is the contribution** | this repository |

The `reproducible-float` rung is **integrated, not merely named**: the ladder
accepts an out-of-process backend through `reconstruction.ExternalBackend` (a
JSON stdin/stdout protocol), so a RepDL/ReproBLAS-backed runner plugs in as a
door without pulling Python or heavy numeric deps into the Go core. A reference
runner with the RepDL plug-point is at
`scripts/reconstruction/repdl-door-runner.py`. The attested Go orchestration
drives and gates it; the numeric guarantee is RepDL's, and we say so.

## What we do NOT claim

Measured honestly (see `docs/testing/cross-hardware-determinism.md`):

- **Float reproducibility across hardware is a solved research problem.** RepDL
  (bitwise-reproducible DL inference across different CPU/GPU via correct rounding
  + fixed order) and ReproBLAS (reproducible summation independent of order)
  already achieve it. We **use** this, we do not claim to have discovered it. Our
  own experiments only *confirm the mechanism* on live hardware: a canonical
  fixed-order/no-FMA GEMM is byte-identical CPU↔GPU, and the residual divergence
  in a full transformer comes from transcendentals (`exp` differs ~1 ULP on ~6%
  of values CPU vs GPU) — exactly what RepDL's correct-rounded ops address.
- **Integer/quantized inference is not new.** Our fixed-point block and the
  worker's integer door build on the I-BERT integer-softmax/exp construction
  (Kim, Gholami, Yao, Mahoney, Keutzer, *I-BERT: Integer-only BERT
  Quantization*, ICML 2021); the byte-portability of integer arithmetic is
  basic IEEE/computer-science fact, and int8 GEMMs are the hardware's. Our
  contribution there is packaging it as an attested, gate-verified
  regeneration rung held to its own sealed references — and, for the real
  model, the arithmetic that makes the same program give the same bytes on
  every device (tables from big integers, a self-tested division, overflow
  refusals; ADR 0020).
- **TEE attestation and confidential AI are not ours.** AMD/Intel/NVIDIA and the
  confidential-computing ecosystem own those. We integrate and attest.
- **Verifiable/deterministic inference exists** (e.g. batch-invariant kernels,
  verifiable-inference efforts). Those verify an *inference*; we recover and
  attest a *model as a continuity asset* — a different job.

## What is genuinely ours (the "no analogues" claim, as an assembly)

No single external work provides: an **AI genome recovery recipe** + **attested
cross-hardware regeneration** + a **signed numerical-equivalence gate** + a
**determinism ladder that finds a working door or fails closed** + **governance
(transparency log / audit chain / succession)** as **one coherent, testable
continuity system**. That assembly — AI that survives infrastructure loss and
provably returns as itself on arbitrary hardware, or safely refuses — is the
reference we are building. It stands on RepDL, ReproBLAS, RFC 6962, and the TEE
vendors, and says so.

## Citations

- RepDL — Bit-level Reproducible Deep Learning Training and Inference — arXiv:2510.09180
- ReproBLAS — Reproducible BLAS / reproducible floating-point summation — J. Demmel et al., UC Berkeley (bebop.cs.berkeley.edu/reproblas)
- i-BERT — Integer-only BERT Quantization — Kim et al., 2021
- RFC 6962 — Certificate Transparency (Merkle transparency logs)
- AMD SEV-SNP, AWS Nitro, Intel SGX/TDX — vendor attestation
