# ADR-0001 — Frozen Producer / Verifier / Sealer interface as the V1 ↔ V2 boundary

| Status   | Accepted (2026-01-21) — superseding the iteration-3 informal interface |
|----------|-------------------------------------------------------------------------|
| Deciders | Founders (architectural author), Doctrine Doctrine reviewer |
| Tags     | tee · interface-contract · v1 · doctrine-r10 |

## Context

Vault Genome runs identical Go code on five distinct Trusted Execution
Environment (TEE) backends — AWS Nitro Enclaves, Azure SGX, GCP SEV-SNP,
Intel SGX bare metal, and a software-only `simulated` backend used in
tests and demos. The transition from MVP (V1, simulated-only, doctrinal
demo) to production (V2, real hardware) needed a hard boundary across
which:

- Application code in `internal/vault/*`, `internal/compute/*`, and
  `internal/audit/*` MUST work without modification.
- Adding a backend MUST be a purely additive change: one new adapter
  file plus a `case` in `factory.go`.
- Removing a backend MUST be impossible without an explicit doctrine
  amendment — operators and customers that bought a particular TEE story
  (e.g., "we run on Intel SGX bare metal because we're a sovereign bank")
  cannot have that ground shift under them.

Without an explicit boundary, the codebase risked accumulating ad-hoc
type assertions, factory functions, and platform branches scattered
across the call graph — making the V1 → V2 swap a months-long migration
instead of an afternoon of plumbing.

## Decision

Three Go interfaces in `internal/shared/tee/tee.go` are designated FROZEN:

```go
type Producer interface {
    Quote(nonce Nonce) (Evidence, error)
    Measurement() Measurement
}

type Verifier interface {
    Verify(evidence Evidence, nonce Nonce) (Measurement, error)
}

type Sealer interface {
    Seal(plaintext, aad []byte) (sealed []byte, err error)
    Unseal(sealed, aad []byte) (plaintext []byte, err error)
}
```

"Frozen" means:

- Method names, parameter types, and return types MUST NOT change after
  this ADR is accepted. Adding a new method is a breaking change.
- The contract suite in `internal/shared/tee/contract_test.go`
  (`RunProducerVerifierContract`, `RunSealerContract`) is the executable
  definition of the contract. Every backend must pass it byte-identical.
- The `NonceMinBytes = 16` constraint (R-10 in
  `docs/doctrine/open-decisions-resolved.md`) is part of the contract. A backend
  that rejects 16-byte nonces, or accepts shorter ones, fails the suite.
- Frozen status is enforced at CI time by
  `internal/shared/tee/frozen_test.go` — an AST-level test that hashes
  the interface declarations and rejects PRs that mutate them without a
  paired ADR amendment.

Concrete adapters live in `aws_nitro.go`, `azure_sgx.go`, `gcp_sev_snp.go`,
`intel_sgx_dcap.go`, `simulated.go`. Construction is dispatched from
`factory.go` via the `Provider` enum — adding a backend is one new file
+ one new constant + one `case` in `BuildProducer` / `BuildVerifier`.

## Consequences

**Positive.**

- The V1 → V2 swap is a configuration change at the daemon's startup
  boundary, not a code rewrite. Operators flip
  `tee.provider: "aws-nitro"` and the rest of the system continues
  speaking to `Producer` / `Verifier` / `Sealer`.
- Conformance is mechanically verifiable: a new TEE plugs in by passing
  the contract suite, no review of every call site needed.
- The interface itself is patentable IP. The patent disclosure
  (`business/20_patent_disclosure_v2.md`) names the abstraction — not
  any single TEE — as the novel contribution.
- New TEE generations (TDX, future ARM Realms, NVIDIA H100 confidential
  compute) become drop-in once their adapter passes the contract suite.

**Negative / accepted trade-offs.**

- The `Producer` interface cannot grow a "binds session ID" or
  "binds public key into REPORT_DATA" parameter without an ADR amendment
  — even though some real hardware (Nitro) supports it natively. Today
  these bindings travel through the AAD on `Sealer.Seal` instead.
- `Verifier.Verify` returns `Measurement` only; a future requirement
  for the verifier to surface freshness metadata, ISVSVN floor, or
  TCB version would force a new method or a parallel interface.
- Type-asserting on the concrete struct (e.g.,
  `producer.(*AWSNitroProducer).Close()`) is allowed for resource
  management, but every such assertion is a coupling point that
  reduces the abstraction's value. New call sites of this kind require
  PR-level review.

## Alternatives considered

1. **Generic interface with a single `Operate` method** — too vague,
   loses compile-time safety on the producer-vs-verifier-vs-sealer
   distinction.
2. **Separate Go modules per TEE** — would force operators to pick
   compile-time, ruling out the binary that "speaks all 5 backends."
   Marketplace listings benefit from a single binary the operator
   configures, not separate downloads per cloud.
3. **C-style virtual table on a single `TEE` struct** — Go doesn't
   need the C dance; interfaces give cleaner semantics + cleaner test
   doubles.

## Future amendments

The ONLY anticipated amendments to this ADR are:

- Adding `Close() error` to `Producer` if hardware adapters universally
  need explicit teardown (currently each adapter exposes `Close` as
  a concrete method, callable via type assertion).
- Adding a `Capabilities() Capabilities` method to advertise per-adapter
  features (e.g., "this backend supports MRSIGNER-bound sealing"),
  if multiple cross-platform features can't be expressed through
  per-config knobs alone.

Every amendment lands as a numbered ADR (this is `0001`); the frozen
declaration in `tee.go` is updated only after the new ADR is accepted.
