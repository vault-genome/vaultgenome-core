# AI Continuity Platform — Core

Defensive infrastructure for preserving AI systems and the data-center
substrate they run on through catastrophic loss — including ongoing war. The
platform is a governance-first continuity system: it treats AI continuity as a
legal-authority problem first, a cryptographic-integrity problem second, and a
computation problem third.

This repository is the reference core of the platform: the **Secure AI Genome
Vault** (SAGV) daemon, the external-compute worker, and the administrative
CLI. Together they implement the nine-stage orchestrated reconstruction flow
defined in the foundation architecture documents:

> Recovery Request → Trust Admission → Trusted Session → Staged Disclosure →
> Delegated External Compute → Return Path → Validation → Release Decision →
> Audit.

Continuity is delivered not by storing and redeploying weights, but by storing
the **AI Genome** — a compact, policy-gated representation — and rebuilding
from it through a governed process every time. (In the shipping code that
rebuild is a byte-level statistical placeholder and the TEE layer is a
simulator, both behind frozen interfaces for a later swap — see the STATUS
journal, the source of truth for what works today.)

---

## Status

**Stage:** E — Release-side MVP doctrine-closed.
**Code maturity:** MVP — release side end-to-end implemented; receive-side
self-bootstrapping (Stage F) deferred to V2 per resolution R-11.
**Doctrine invariants:** 11 of 11 CI-enforced (see §4 of `docs/internal/status-journal.md`).
**CI gate:** `vault-gate` with 17 sub-checks (fmt, vet, build, unit, race,
integration, coverage, lint, terminology, govulncheck, osv-scanner, gitleaks,
sbom, license-headers, doctrine-tests, dep-allowlist, dep-depth).
**Module path:** `github.com/ai-continuity-platform/core`.
**Minimum Go version:** 1.22.
**License:** AGPL-3.0-or-later (see `LICENSE`).

For a component-level maturity breakdown — what is DONE, what is
**MVP-SCOPED** placeholder, and what is V2+ — see `../docs/internal/status-journal.md` at
the workspace root. The STATUS document is the single source of truth
for "what works today" and supersedes any claim in this README.

---

## Doctrinal Documents

The code in this repository is governed by seven Stage A closure documents
kept at the workspace root (one directory above `core/`):

- `docs/doctrine/terminology.md` — canonical vocabulary, deprecated-terms list.
- `docs/doctrine/open-decisions-resolved.md` — 16 frozen technical decisions (R-1…R-16).
- `docs/doctrine/validation-thresholds.md` — semantic / behavioral / operational
  thresholds and aggregation rule.
- `docs/doctrine/repo-structure.md` — directory layout and module boundaries.
- `docs/doctrine/ci-security-policy.md` — supply-chain, signing, dependency, and CI
  policy.
- `docs/internal/stage-a-summary.md` — executive summary and the eleven doctrinal
  invariants.
- `docs/doctrine/positioning.md` — claim-language governance; freezes the
  canonical English / Russian phrasings for every public-facing claim and
  bans eight unbounded superlatives. All external artifacts — white paper,
  pitch deck, market memo, investor one-pager — must cite this doctrine
  in their front-matter and pass the §4 scan before circulation.

Every pull request is reviewed against these documents. Silent substitution of
terminology, weakening of operational validation, introduction of a code path
that emits the AI Genome in unsealed form, or reintroduction of a banned
positioning construction is grounds to block the PR.

---

## Repository Layout (summary)

```
core/
├── cmd/
│   ├── sagvd/          # Secure AI Genome Vault Daemon (the authority process)
│   ├── acp-compute/    # External compute worker (delegated, no authority)
│   └── acpctl/         # Administrative CLI
├── internal/
│   ├── contracts/      # Eight canonical contract packages (frozen)
│   ├── vault/          # intake, trust, session, policy, storage, keys,
│   │                   # disclosure, orchestration, incident
│   ├── compute/        # worker, manifest, returnpath
│   ├── validation/     # service, semantic, behavioral, operational
│   ├── audit/          # event, store, chain
│   └── shared/         # tee (emulated), crypto, time, errors, logging
├── test/
│   ├── doctrine/       # invariant tests (architectural assertions)
│   ├── integration/    # end-to-end flow tests
│   └── fixtures/       # genome fixtures, behavioral probes, probes
├── scripts/            # terminology/license/coverage check scripts
├── docs/               # dependencies, patent_references, runbooks
└── .github/workflows/  # vault-gate.yml, release.yml
```

Full rationale for every directory lives in `docs/doctrine/repo-structure.md`.

---

## Development

```
make build              # build all three binaries
make test               # unit tests only
make test-race          # with race detector
make test-doctrine      # architectural invariant tests
make demo               # narrated end-to-end walkthrough of the vertical slice
make vault-gate         # the full CI gate, locally (17 sub-checks)
```

The `vault-gate` target mirrors the CI workflow of the same name. A green
`vault-gate` locally is a strong predictor of a green CI.

The `demo` target runs `scripts/demo.sh`, which narrates the nine-stage
recovery flow end-to-end against the in-repo vertical slice — useful for
onboarding a new operator or for a live demo on a pilot call.

---

## Operator Runbook

Operator-facing procedures live in `docs/operator/`:

- `00_overview.md` — role map, boundary between Vault operator and
  compute-plane operator, what authority each role holds.
- `01_preflight.md` — what to check before the first recovery session
  (key material, attestation, witness-log health, policy snapshot).
- `02_recovery_flow.md` — narrated walkthrough of the nine-stage flow,
  step by step, with pointers to the packages that implement each stage.
- `03_incident_response.md` — R-15 incident scenarios: attestation fail,
  validation hard-fail, audit-append failure, physical tamper signal.
- `04_observability.md` — audit chain inspection, witness log STH
  verification, disclosure-sequence reconstruction.
- `05_release_procedure.md` — signed tag, SBOM, SLSA provenance, the
  release.yml workflow, the three signed binaries.

The runbook assumes a reader who has read `docs/internal/stage-a-summary.md` §2
(the eleven invariants) and can navigate to the Stage A and architecture
documents at the workspace root.

---

## Contributing

Before opening a pull request, read:

1. `docs/doctrine/terminology.md` — understand which terms are canonical and
   which are deprecated. CI blocks PRs that introduce deprecated terms.
2. `CONTRIBUTING.md` — PR format, commit message format, branch naming.
3. `docs/doctrine/ci-security-policy.md` — what the `vault-gate` workflow checks and
   why.

All commits on protected branches must be cryptographically signed. All PRs
must pass the full `vault-gate` workflow and carry the terminology-check
green badge.

---

## Security

Report suspected vulnerabilities privately per `SECURITY.md`. **Do not open
public issues for security bugs.** The platform is defensive infrastructure
intended to operate in adversarial conditions; responsible disclosure is
itself part of the trust model.

---

## Acknowledgements

The architecture represented by this code is the product of the patent
family P1 / P2 / P3 and documents #1–#9 authored by the project founders.
Cross-references from code to patent paragraphs are preserved in the form
documented in `docs/doctrine/terminology.md` §1.1.
