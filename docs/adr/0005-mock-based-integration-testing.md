# ADR-0005 — Mock-based integration testing for hardware TEE adapters

| Status   | Accepted (2026-05-04) |
|----------|-----------------------|
| Deciders | Founders |
| Tags     | testing · tee · phase-2-readiness · risk-management |

## Context

The four real-hardware TEE adapters (`aws_nitro.go`, `azure_sgx.go`,
`gcp_sev_snp.go`, `intel_sgx_dcap.go`) call out to platform-specific
helpers — Nitro NSM ioctl, AWS KMS, Azure MAA, AMD KDS, Intel DCAP /
PCCS, SGX SDK ECALLs — that need real hardware or paid cloud accounts
to exercise. As of Phase 1 (May 2026):

- 84 unit tests cover construction error paths, capability checks,
  config validation, nonce-floor enforcement.
- Zero integration tests exercised the full
  Producer → Verifier → Sealer cycle on hardware adapters because the
  helpers all returned `"not yet wired (Phase 2)"` errors.

This left a substantial wiring risk: when Phase 2 funded engineering
time + hardware budget arrived, the entire adapter call graph would
be exercised for the first time against real services. Wiring bugs
that should have been caught by tests (wrong field offset, wrong
argument order, wrong error classification) would surface as
mysterious cloud-vendor error responses, with multi-day debug cycles.

## Decision

Convert every hardware-touching helper from a package-level `func` to
a package-level `var = func`. In production builds the var defaults
to the same Phase-2-not-wired stub; in test builds (`fake_hardware_test.go`)
the var is reassigned to an in-process implementation that
round-trips a synthetic Ed25519-signed JSON envelope.

This unlocks four kinds of test coverage that were impossible before:

1. **End-to-end adapter call graph**: producer.Quote → verifier.Verify
   → sealer.Seal → sealer.Unseal exercising every if-branch, every
   error path, every mutex acquisition.
2. **Policy enforcement**: ISVSVN floor, AcceptableMRSIGNERS,
   AcceptableMeasurements, AcceptableHostData, ReportedTCB minimum —
   each policy lever can be exercised with deliberately-wrong values
   and the verifier's rejection observed.
3. **Sealing AAD binding**: every Sealer's AAD-mismatch path now has
   a test (was previously only smoke-tested via the simulated
   backend, which uses a fundamentally different sealing primitive).
4. **Threading + Close idempotency**: producer mutex semantics and
   `Close` being callable twice are exercised in real test scenarios.

The synthetic envelope format (defined in `fake_hardware_test.go`) is
intentionally NOT the real CBOR/COSE/sgx_quote3_t/SEV-SNP-1184B wire
format, because:

- `go.mod` currently has no CBOR / COSE / JWT / x509-DER libraries.
  Adding them requires the change-management process documented in
  `go.mod`'s comment block (per-dep rationale file +
  CI security policy update + PR review).
- The mock format covers the *call graph + policy + cryptographic
  binding* — what wiring tests are actually for. The
  format-specific layer (parse this byte field, validate that ASN.1
  structure) is a thin layer over standard libraries; bugs there
  are caught by manual cross-reference against the platform's
  attestation specification.

> **Update (2026-09-16).** This is how it went for SEV-SNP (ADR 0009), TDX
> (ADR 0018) and the Azure confidential GPU VM (ADR 0019): the production
> bodies were wired, the fakes stayed, and the real captures joined the
> suite as offline fixtures (`gcp_sev_snp_verify_test.go`,
> `gcp_tdx_test.go`, `azure_cgpu_evidence_test.go`). Nitro and SGX are
> still at the mock stage.

When Phase 2 funded time arrives, the same `installXxxFake(t, fh)`
test helpers stay verbatim — only the production stub bodies (the
`var = func(...)` implementations under "Phase 2 wiring") are
swapped for real CBOR/COSE/SGX-SDK calls. Tests do not need to
change because the test-side substitution always overrides the
production implementation regardless of which body the production
code carries.

## Consequences

**Positive.**

- Wiring risk for Phase 2 reduced from "untested 4-platform call
  graph" to "untested format-specific parsing." The first is
  measured in weeks of debugging; the second is measured in days
  with platform-vendor reference docs in hand.
- Concretely: 20 integration sub-tests now run on every CI build
  (6 AWS Nitro + 5 Azure SGX MAA + 1 Azure SGX DCAP + 4 GCP SEV-SNP +
  4 Intel SGX), all complete in under 1 second total. Combined with
  the 84 pre-existing unit tests, the package has 104 cases passing
  on every push.
- Sealing AAD-binding bugs that would have lurked until production
  surface as test failures in CI today.
- The pattern documents itself: a developer reading
  `fake_hardware_test.go` learns the contract that real hardware
  must satisfy — what fields the Producer puts in the envelope,
  what the Verifier extracts, what AAD binds the Sealer.

**Negative / accepted trade-offs.**

- Package-level mutable function vars require a `teeFakeMu` mutex
  to serialize test setup. This means top-level integration tests
  cannot use `t.Parallel()`. Acceptable: total runtime is sub-second
  even serial, and the constraint is enforced by code (the helper
  acquires the mutex before any override, releases in `t.Cleanup`).
- Gaps the harness CANNOT cover:
  - **Wire-format bugs**: a CBOR-COSE field renamed by AWS, an SGX
    quote layout change in a future SGX SDK version. These are
    caught only by hardware tests.
  - **External service drift**: AWS KMS API changes, MAA JWT format
    drift, AMD KDS root rotation. Caught by hardware tests +
    monitoring.
  - **Side-channel cryptographic bugs**: timing leaks in real
    hardware sealing primitives. Outside the scope of any functional
    test suite.
- The Ed25519-signed JSON envelope is a *test fixture format*, not
  a parallel TEE protocol. The fakes never run in production, never
  ship in a release. Anyone tempted to "just use the JSON format
  for production too" is ignoring the entire reason TEEs exist.

## Implementation summary

Files added:

- `internal/shared/tee/fake_hardware_test.go` (~470 lines) — the
  synthetic envelope format, the `fakeHardware` struct,
  `installAWSNitroFake` / `installSGXFake` / `installSEVSNPFake`
  helpers.
- `internal/shared/tee/integration_test.go` (~330 lines) — 20 sub-tests
  covering full cycle, replay rejection, evidence tampering, wrong
  measurement, sealing AAD binding, MRSIGNER enforcement, ISVSVN
  floor, ReportedTCB floor, HOST_DATA pinning, HSM wrap, Close
  idempotency.

Files modified:

- `internal/shared/tee/{aws_nitro,azure_sgx,gcp_sev_snp,intel_sgx_dcap}.go`:
  Phase-2 stub functions converted from `func` to `var = func`.
  Production behaviour unchanged (same error message, same return
  types). Code size grew by ~30 lines (4 keyword changes per stub
  × ~30 stubs).
- `azure_sgx.go`: `computeReportDataPrefix` corrected from
  always-zeros sentinel to real `crypto.SHA256(nonce)`. Pre-existing
  test bug; surfaced because the integration test's
  `nonceMatchesReportData` path now actually executes.
- `test/doctrine/invariants_test.go`: extended
  `allowedWriteSinkPrefixes` to include `internal/shared/tee/` with
  doctrine-paragraph rationale (TEE adapters open hardware character
  device files; this never carries genome plaintext).

## Future directions

- When `go.mod` is permitted to add `github.com/fxamacker/cbor/v2`
  (Phase 2 funded scope), implement real `parseCOSESign1` /
  `decodeNitroAttestationDoc` so the AWS Nitro adapter exercises
  CBOR + COSE on every CI run. The fake-envelope path stays as a
  fast `make test` target; the CBOR path becomes the canonical
  format test.
- Ship the conformance harness (`pkg/teeconformance`,
  see [ADR-0006 — pending](0006-conformance-suite-extraction.md))
  as a public Go package so third-party TEE adapters can validate
  themselves against our contract without copy-pasting our test
  source.
