# ADR 0008: Numerical Equivalence Gate for Cross-Hardware Reconstruction

**Status:** Accepted
**Date:** 2026-09-13
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Relates to:** `internal/contracts/probe_battery`, `internal/contracts/reconstitution_decision`, ADR 0006 (cross-cloud KMS-mediated restore)

---

## Context

The platform's flagship claim is **cross-hardware regeneration**: a sealed
genome is restored and brought back to life on a *different* machine (different
CPU architecture, cloud, or accelerator) within minutes, and business keeps
running. For that claim to be safe, the destination must be able to *prove* the
reconstructed model behaves like the sealed original **before** it goes live —
otherwise an emergency failover could silently promote a wrong or corrupted
model into production.

We already had a behavioral-equivalence contract, `probe_battery`, but a direct
measurement showed it is the wrong instrument for this specific question:

- `probe_battery` compares **32-byte response hashes**. A probe either
  round-trips *bit-identically* or it counts as fully drifted; results aggregate
  into a per-method drift **fraction** (`MaxDriftReconstruct = 8%`).
- Cross-hardware determinism experiments (AMD Milan vs Intel Ice Lake, GCP CVMs,
  a real numpy transformer block) established:
  - With a **pinned runtime** (numpy 1.26.4, single-threaded BLAS, consistent
    dtype), f32 and f64 outputs are **byte-identical** AMD == Intel.
  - Under **BLAS build/version drift** (numpy 2.1.0 pip wheel) the output
    diverges both across versions *and* across architectures.
  - **Mixed-dtype promotion** (f32 accumulated in f64) is architecture-dependent
    and diverges.

The consequence: a numerically *faithful* reconstruction on non-identical
hardware differs in the last bits of nearly every float, so nearly every
response hash changes. Under `probe_battery` alone that reads as ~100% drift and
blows through the 8% reconstruct budget — a false "this is a different model"
verdict for a model that is, to any measurable tolerance, the same. Conversely,
raising the hash-drift budget to absorb this would blind the succession test to
real swaps. A hash cannot express "within 1e-6".

## Decision

Introduce a distinct **numerical reconstruction-fidelity gate** at
`internal/validation/equivalence`, operating on raw tensor **values**, not
hashes.

- **Criterion:** element-wise allclose, `|a - e| <= Atol + Rtol*|e|`, with a
  byte-exact fast path checked first. Tensors are typed (`f32`/`f64`),
  little-endian, and shape-checked.
- **Verdict levels:**
  - `EXACT` — every output byte-identical (pinned/deterministic runtime held).
  - `EQUIVALENT` — every output within tolerance but not all byte-identical
    (attested functional equivalence across hardware).
  - `FAIL` — any output outside tolerance. **Fail-closed.**
- **Critical fixtures:** a fixture marked `Critical` outside tolerance is
  **always** `FAIL`, never subject to any outlier budget. These are the
  value-level analogue of `probe_battery`'s identity probes.
- **Policy:** the default (`StrictPolicy`) is fail-closed — any outlier fails.
  An operator may knowingly permit up to *N* **non-critical** outliers
  (`MaxNonCriticalOutliers`) while still returning `EQUIVALENT`; the mismatch is
  always recorded in the verdict for audit.
- **Binding & non-repudiation:** the verdict carries a SHA-256 `FixturesHash`
  (order-independent) binding it to the exact reference set, is deterministically
  serialisable (`CanonicalBytes`), and is Ed25519-signable. Tampering with a
  signed verdict fails verification with a `CategoryIntegrity` error.

### Relationship to `probe_battery`

The two layers are complementary and compose:

| Concern | `probe_battery` | `equivalence` (this ADR) |
|---|---|---|
| Question | Is the child a legitimate behavioral *successor*? | Is the *same* genome recomputed *faithfully* on new hardware? |
| Compares | 32-byte response **hashes** | raw tensor **values** |
| Metric | drift **fraction** per DerivationMethod | allclose distance per element |
| Identity | `ProbeKindIdentity` (bit-identical) | `EXACT` / `Critical` fixtures |
| Drift | `MaxDrift*` budgets | `Tolerance{Atol,Rtol}` + `Policy` |

`probe_battery` remains the authority on cross-*genome* succession.
`equivalence` is the authority on cross-*hardware* reconstruction fidelity of a
single genome. A reconstitution decision should require **both**: a passing
numerical equivalence verdict (the model computes right *here*) and a passing
behavioral scorecard (the model is the *right lineage*).

## Consequences

- Cross-hardware failover has a concrete, signed go/no-go artifact. A
  correct-but-not-bit-identical reconstruction is admitted as `EQUIVALENT`
  instead of being falsely rejected; a wrong one is blocked, fail-closed.
- The 8% `DerivationReconstruct` hash budget is **not** repurposed to absorb
  numerical drift, so it stays sharp against genuine substitution.
- The gate is self-contained and independently testable (14 unit tests covering
  every verdict path, policy, NaN handling, signing, tamper detection, and hash
  binding). `gofmt` + `go vet` clean; `go test ./...` green.
- **Determinism ladder (the converter, `internal/canonical`):** the gate proves
  fidelity but does not *produce* it. The converter does, in two implemented
  rungs: (2) a BLAS-free float64 reference kernel (fixed evaluation order, no
  implicit FMA) — byte-identical within a pinned toolchain, gate-`EXACT`; and (3)
  a **fully integer** transformer block (integer GEMM, i-BERT-style integer
  exp/softmax, integer isqrt/LayerNorm) that is byte-portable **by construction**
  and reproduces the float64 reference to ~3.6e-3 abs / ~1.2% rel, gate-
  `EQUIVALENT`. Rung 1 (pinned + attested + *verified* runtime for byte-`EXACT`
  off-the-integer-path) and wiring the verdict into `reconstitution_decision`
  (via the receive-side `ValidationResult` → `ReasonValidationFailed`) are
  tracked separately.
