# ADR-0002 — Multi-TEE adapter dispatch via Provider enum + factory.go

| Status   | Accepted (2026-02-08) |
|----------|-----------------------|
| Deciders | Founders, TEE doctrine reviewer |
| Tags     | tee · factory-pattern · provider-dispatch |

## Context

[ADR-0001](0001-frozen-producer-verifier-sealer-interface.md) freezes
the Producer / Verifier / Sealer interface. This ADR addresses *how*
the daemon picks between the five concrete implementations at startup,
and how new backends get added.

Constraints driving the decision:

- The same compiled binary (`sagvd`, `acp-compute`, `acpctl`) MUST be
  able to run on any of the five TEE backends. Operators choose at
  config time, not compile time. This rules out build-tag-gated
  per-backend compilation.
- Some backends (Azure SGX, Intel SGX bare metal, GCP SEV-SNP) require
  hardware (`/dev/sgx_enclave`, `/dev/sev-guest`) or external services
  (Microsoft Azure Attestation, AMD KDS, AWS KMS). Selecting an
  unavailable backend MUST surface a clear startup error, not crash
  later in a subtle way.
- Adding a new backend (e.g., AWS Nitro TDX in a future generation,
  NVIDIA H100 CC) MUST be fully additive — modifying any existing
  switch arm is a code-review red flag.

## Decision

A single `Provider` enum + a single dispatch point per role:

```go
// internal/shared/tee/factory.go
type Provider string
const (
    ProviderSimulated     Provider = "simulated"
    ProviderAWSNitro      Provider = "aws-nitro"
    ProviderAzureSGX      Provider = "azure-sgx"
    ProviderGCPSEVSNP     Provider = "gcp-sev-snp"
    ProviderIntelSGXDCAP  Provider = "intel-sgx-dcap"
)

func BuildProducer(spec ProducerSpec) (Producer, error) { switch spec.Provider {…} }
func BuildVerifier(spec VerifierSpec) (Verifier, error) { switch spec.Provider {…} }
func Capability(p Provider) (available bool, reason string) { switch p {…} }
```

The daemon's keystore loader calls `BuildProducer` exactly once at
startup; nothing downstream knows which backend was chosen. New
backends:

1. Implement `Producer` + `Verifier` + `Sealer` in a new
   `<backend>.go` file.
2. Add a `Provider` constant in `factory.go`.
3. Add a `case` to `BuildProducer`, `BuildVerifier`, and `Capability`.
4. Pass the contract suite (`internal/shared/tee/contract_test.go`)
   from a new `<backend>_test.go` that calls
   `RunProducerVerifierContract` + `RunSealerContract`.

`Capability(p)` returns `(false, reason)` when the backend is compiled
in but the host lacks the required device / service. The daemon logs
the reason and refuses to start — never silently falls back. This is
an explicit doctrinal stance: an operator who configures
`tee.provider: aws-nitro` and is somehow not running inside a Nitro
Enclave MUST find out at boot, not from a confusing attestation
verification failure 30 minutes into the first session.

`ParseProvider(string) (Provider, error)` is the only place strings
become enum values. It normalises case + trims whitespace, so
`AWS-Nitro` and `aws-nitro\n` and `AWS_NITRO` all map to the same
constant — operators don't get tripped by config-file copy-paste.

## Consequences

**Positive.**

- One `case` statement to grep when investigating "where is provider X
  wired?". No reflection, no init() side effects, no plugin loaders.
- Mismatched configurations fail fast at startup with an actionable
  diagnostic (`"AWS Nitro: /dev/nsm device not present (binary must
  run inside a Nitro Enclave)"`).
- The factory is itself patentable subject matter as part of the
  TEE-agnostic abstraction (see
  `business/20_patent_disclosure_v2.md` claim 1.2).
- Operators can keep one `sagvd` binary in their image registry and
  deploy it across mixed Nitro / SGX / SEV fleets without a CI matrix
  per backend.

**Negative / accepted trade-offs.**

- All backends are compiled in regardless of where the binary will
  run. Binary size grows ~5–10 MB per backend; for `sagvd` this is
  ~25 MB total. Acceptable — distroless image is still <40 MB total.
- An operator targeting a single backend cannot use `go build -tags`
  to strip unused code paths. If size becomes critical (e.g., embedded
  air-gapped appliance), a future ADR can introduce build tags as an
  *opt-in* slimming option, but the default stays unified.
- Plugin model (Go's `plugin.Open`, Lua-style scripting) was rejected:
  TEE adapters must be auditable + reproducibly built; runtime-loaded
  plugins break both.

## Alternatives considered

1. **Per-backend `init()` registration** — Go allows backends to
   register themselves at package import. Rejected because:
   (a) the order of init() calls is hard to reason about,
   (b) adding a backend requires importing it transitively somewhere,
   which creates non-obvious build dependencies,
   (c) testing becomes harder (init runs before t.Setup).
2. **gRPC plugin process** — each TEE adapter as a separate binary
   speaking gRPC over Unix socket. Rejected: adds an inter-process
   boundary inside the enclave's measurement boundary, which would
   either break the measurement (the plugin is now measured separately)
   or weaken it (mutual attestation between processes is more code
   to audit).
3. **Build tags (`+build aws_nitro`)** — would force operators to pick
   a build, killing the "one binary speaks all 5" promise.

## Status of each backend (as of 2026-05-04)

| Provider              | Code | Unit tests | Integration tests | Hardware tested |
|-----------------------|------|------------|-------------------|------------------|
| `simulated`           | ✅   | ✅          | ✅ (contract)     | n/a (software)   |
| `aws-nitro`           | ✅   | ✅          | ✅ (mock)         | ❌ (Phase 2)     |
| `azure-sgx` (MAA)     | ✅   | ✅          | ✅ (mock)         | ❌ (Phase 2)     |
| `azure-sgx` (DCAP)    | ✅   | ✅          | ✅ (mock)         | ❌ (Phase 2)     |
| `gcp-sev-snp`         | ✅   | ✅          | ✅ (mock)         | ❌ (Phase 2)     |
| `intel-sgx-dcap`      | ✅   | ✅          | ✅ (mock)         | ❌ (Phase 2)     |

> **Update (2026-09-16).** The column has closed for three families, at a
> cost of a few dollars of cloud time each: `gcp-sev-snp` is proven on live
> GCP and Azure chips (ADR 0009, 0014, 0016; VERIFIABLE-CLAIMS C7, C12–C14),
> `gcp-tdx` on a live Trust Domain (ADR 0018; C15), and `azure-cgpu` — an
> Azure confidential GPU VM, the chip, the vTPM and the H100 in one
> evidence — on a live NCC H100 v5 (ADR 0019; C17). `aws-nitro`, `azure-sgx`
> (MAA and DCAP) and `intel-sgx-dcap` remain scaffolding and are refused by
> the registry and the daemons (KNOWN_ISSUES #1).

Phase 2 ("hardware tested") column closes when funded engineering time
+ a $30k AWS / Azure / GCP / bare-metal test budget is secured. The
mock harness (see [ADR-0005](0005-mock-based-integration-testing.md))
brings the wiring risk to ~30% of what it would be if we deferred
testing entirely until hardware arrived.
