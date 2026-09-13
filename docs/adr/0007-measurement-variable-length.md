# ADR 0007: Measurement Is Variable-Length (amends ADR 0001 / R-10)

**Status:** Accepted
**Date:** 2026-09-13
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Amends:** ADR 0001 (frozen Producer/Verifier/Sealer interface), R-10

---

## Context

The honest-reference audit found that `tee.Measurement` was a fixed
`[crypto.HashSize]byte` (32 bytes, SHA-256). Real confidential-computing
measurements are wider:

- **AMD SEV-SNP** `MEASUREMENT` is **48 bytes** (SHA-384).
- **AWS Nitro** PCR0 is **48 bytes** (SHA-384).
- Intel SGX `MRENCLAVE` is 32 bytes (SHA-256); some reports use 64 bytes.

Every hardware adapter therefore **truncated** the real measurement to 32
bytes (`report.Measurement[:32]`, `pcr0[:32]`), so the platform could not
faithfully pin real hardware — a defect (defect (a) in the audit). The TAP
spec even encoded the contradiction: Appendix A.3 mandated truncation to 32
octets while §6.3 forbids prefix matches for measurement pinning.

## Decision

`tee.Measurement` becomes a **variable-length `[]byte`** holding a digest of a
supported hardware length (32 / 48 / 64 bytes), compared byte-wise via the new
`Measurement.Equal` method (a slice is not comparable with `==`).

- All adapters carry the **full-length** measurement — no truncation.
- Acceptable-measurement policy sets are `[]Measurement` (were `[][32]byte`).
- `MeasurementFromBytes` accepts 32/48/64-byte inputs.
- Because `Measurement` is now a reference type, methods that expose it return
  a defensive copy.

**The frozen interface surface (ADR 0001) is preserved.** The
`Producer` / `Verifier` / `Sealer` method signatures are textually unchanged —
they still reference the named type `Measurement`; only its underlying
representation widened. The AST-frozen-interface doctrine test continues to
pass, so this is a compatible, deliberate amendment rather than a breaking
change to the frozen contract.

## Consequences

- Real SEV-SNP / Nitro (48-byte) measurements are represented and compared at
  full length; the truncation defect is closed.
- `==` comparisons of measurements are replaced by `Measurement.Equal`.
- The TAP spec's Appendix A.3 "truncate to 32 octets" guidance is superseded by
  full-length pinning, resolving the §6.3-vs-A.3 contradiction (TAP to be
  updated to match).
- `go build ./...` and `go test ./...` are green after the change.
