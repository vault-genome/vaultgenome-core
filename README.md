# AI Continuity Platform — Core

[![vault-gate](https://github.com/vault-genome/vaultgenome-core/actions/workflows/vault-gate.yml/badge.svg)](https://github.com/vault-genome/vaultgenome-core/actions/workflows/vault-gate.yml)
[![CodeQL](https://github.com/vault-genome/vaultgenome-core/actions/workflows/codeql.yml/badge.svg)](https://github.com/vault-genome/vaultgenome-core/actions/workflows/codeql.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)](go.mod)

Defensive infrastructure for preserving AI systems and the data-center
substrate they run on through catastrophic loss — including ongoing war. The
platform is a governance-first continuity system: it treats AI continuity as a
legal-authority problem first, a cryptographic-integrity problem second, and a
computation problem third.

This repository is the reference core of the platform. It ships four
binaries and a demo:

- **`sagvd`**, the Secure AI Genome Vault authority. It releases a genome's key
  only to an attested destination the operator's policy admits, confirms the
  destination's signed restore, and records every decision in a signed,
  hash-chained audit log.
- **`acp-bootstrap`**, the destination. It attests with AMD SEV-SNP, restores the
  genome, proves the restored model works, and signs a receipt with its TEE.
- **`acpctl`**, the administrative CLI. It seals genomes, and runs the sentinel
  that keeps a running model sealed.
- **`acp-compute`**, the external-compute worker.
- **`acp-demo`**, a one-command demonstration.

The nine-stage governed reconstruction flow of the foundation architecture —
Recovery Request → Trust Admission → Trusted Session → Staged Disclosure →
Delegated External Compute → Return Path → Validation → Release Decision →
Audit — is library code under `internal/`, exercised end to end by the tests.
[docs/operator/00_overview.md](docs/operator/00_overview.md) says what each
binary drives today.

Continuity is delivered by sealing the **AI Genome** rather than a copy of the
weights. A genome holds three things:

- the content hash of the base model;
- the fine-tune, as a sealed LoRA delta;
- the deterministic recipe that produced it.

For Qwen2.5-0.5B-Instruct, fine-tuned inside an AMD SEV-SNP confidential VM, the
genome is 2.2 MB, one 447th of the base weights. Restored on an NVIDIA L4 in
another region, the model gives the same top-1 token and the same greedy
continuation on every sealed fixture; its logits are within 1.9e-4 of the
reference. On the pinned runtime the genome comes back bit for bit
([scripts/hardware-test/gcp-drill](scripts/hardware-test/gcp-drill)).

---

## Quickstart — see the flagship in one command

No cloud, no TEE hardware, no config. This runs the **cross-hardware
regeneration** demonstration on the real platform code (simulated TEE):

```bash
go run ./cmd/acp-demo
```

or with Docker:

```bash
docker build -t vaultgenome .
docker run --rm vaultgenome
```

It seals a sample AI genome, receives it on a second "node", regenerates it, and
prints an **Ed25519-signed equivalence verdict**, showing:

- **EXACT** byte-identical regeneration on a pinned runtime;
- a simulated cross-hardware float drift falling through to the **byte-portable
  integer path** (**EQUIVALENT**) so the model still comes up; and
- a **corrupted genome blocked** (fail-closed) — never brought up.

Point it at your own file for a byte-exact sealed-continuity proof:

```bash
go run ./cmd/acp-demo --model ./path/to/your-model.safetensors
```

**What is real today:**

- attested continuity of a real fine-tuned model, sealed on SEV-SNP and
  restored on a GPU with its fidelity measured;
- key release only to attested **AMD SEV-SNP** hardware, on **GCP and Azure**
  (`scripts/hardware-test/`, `docs/adr/0008`, `0009`, `0011`);
- automatic failover of a running model under the operator's signed policy
  (ADR 0012).

**What is a labelled placeholder:** the `acp-compute` worker's reconstruction
backend, and generating a model from a recipe alone, without its sealed delta.
We say which is which, on purpose.

### Protect a real model (CLI)

Seal your own model into a portable `.genome` bundle, move it to another server,
and restore it **byte-exact** — with a validated version chain for every update
(EU-style continuous backup). A bundle is sealed under a fresh key that is not
in the file, so it can be stored or replicated anywhere:

```bash
make build                                                   # builds ./bin/acpctl

# seal your model (any directory of files, or an Ollama model ref);
# the key goes to its own 0600 file and nowhere else
./bin/acpctl genome seal --content-dir=./my-model --output=gen-0.genome --key-out=gen-0.key
# seal a fine-tune as the next generation, linked to its parent
./bin/acpctl genome seal --content-dir=./adapter-1 --parent=gen-0.genome \
    --output=gen-1.genome --key-out=gen-1.key

# on another server, with the bundles and gen-0.key copied into the working
# directory: restore byte-exact, then verify the lineage of the bundles there
./bin/acpctl genome rewind --bundle=gen-0.genome --key-file=gen-0.key --target=./restored
./bin/acpctl genome chain  --dir=.
```

Opening authenticates every 1 MiB segment before a byte of it is used, restores
into a staging directory, checks every file against the sealed snapshot and only
then moves the tree into place; an edited, truncated or wrong-key bundle leaves
the target untouched. Across clouds, the key is released only to a destination
TEE your policy admits, which restores the genome itself and signs a receipt the
source verifies before recording the restore (ADR 0011).

---

## Status

**Stage:** E — Release-side MVP doctrine-closed.
**Code maturity:** MVP — release side end-to-end implemented; receive-side
self-bootstrapping (Stage F) deferred to V2 per resolution R-11.
**Doctrine invariants:** 11 of 11 CI-enforced (asserted as tests in `test/doctrine/`; ADR 0004).
**CI gate:** `vault-gate` with 18 sub-checks (fmt, vet, build, unit, race,
integration, coverage, lint, terminology, govulncheck, osv-scanner, gitleaks,
sbom, license-headers, doctrine-tests, dep-allowlist, dep-depth,
verify-reproducible).
**Module path:** `github.com/ai-continuity-platform/core`.

### What works today

- **Byte-exact model continuity** — `acpctl genome seal / rewind / chain`: seal
  any model to a portable bundle whose key lives apart from it, restore it
  byte-exact on any server, and track versions with a validated lineage chain.
- **Attested self-restore across clouds** — the operator's policy releases a
  genome's key to an attested, allow-listed destination TEE; the destination
  restores the genome by itself and signs a receipt with its TEE; the source
  verifies the receipt and records the restore (`sagvd crosscloud-confirm`,
  ADR 0011), under an operator stop that halts every release (ADR 0010).
- **A real fine-tune survives the machine** — `workers/genome` fine-tunes a real
  model deterministically and writes its genome. Measured on hardware
  ([gcp-drill](scripts/hardware-test/gcp-drill)), for a genome sealed in a
  SEV-SNP guest:
  - on the pinned runtime it comes back bit for bit;
  - on an NVIDIA L4 it comes back EQUIVALENT: 16/16 identical top-1 tokens and
    greedy continuations, max |Δ logit| 1.9e-4;
  - on an Intel CPU it also comes back EQUIVALENT;
  - its recipe replays to a bit-identical adapter.
- **Automatic failover, decided by the operator** — a sentinel on the primary
  seals every new state with its key escrowed to the authority, and reports
  when a tripwire fires (`acpctl sentinel watch`). Under a failover policy the
  operator signed in advance, `sagvd failover` restores the last genome sealed
  before the intrusion, or before a lost heartbeat, on the one standby the
  policy names. It confirms the restore by the standby's TEE-signed gate
  verdict. One policy allows one move, and the operator stop overrides it
  (ADR 0012). Measured locally with the real binaries: RTO 0.63 s after an
  intrusion; 3.5 s after a killed primary, with a 3 s heartbeat timeout.
- **Real AMD SEV-SNP attestation** — a report from a live confidential VM is
  parsed, its ECDSA-P384 signature verified, and its VCEK chained to AMD
  ARK-Milan — proven on **two clouds, GCP and Azure** (`scripts/hardware-test/`,
  ADR 0007 / 0009).
- **Cross-hardware regeneration gate** — a signed EXACT / EQUIVALENT / FAIL
  verdict on recomputed reference fixtures, behind a determinism ladder that
  finds a working door (pinned float → reproducible float → byte-portable
  integer) or fails closed. Determinism measured on real CPUs (AMD/Intel) and
  GPUs (NVIDIA L4/T4) — `docs/testing/cross-hardware-determinism.md`, ADR 0008.
- **Honest boundaries** — the `acp-compute` worker's reconstruction backend is a
  labelled placeholder. Attested GPU destinations need confidential GPUs, which
  have not been tested yet. The reproducible-float rung stands on RepDL /
  ReproBLAS (`docs/prior-art-and-attribution.md`). KNOWN_ISSUES.md lists every
  limit.
**Minimum Go version:** 1.25.
**License:** AGPL-3.0-or-later (see `LICENSE`).

The **What works today** section above is the authoritative maturity
summary for this repository; component-level design rationale lives in the
architecture decision records under `docs/adr/`.

---

## Governance & design records

The code in this repository is governed by the documents and machine-checked
records kept in the repo:

- `docs/doctrine/terminology.md` — canonical vocabulary and the frozen
  deprecated-name list; enforced by the terminology gate (vault-gate 09).
- `docs/adr/` — twelve architecture decision records (ADR 0001–0012),
  among them the frozen producer / verifier / sealer interface (0001),
  multi-TEE adapter dispatch (0002), doctrine-invariants-as-tests (0004),
  cross-cloud KMS-mediated recovery (0006), the equivalence gate (0008), the
  X25519 KEM cross-cloud key delivery (0009), the operator stop and recorded
  refusals (0010), genome v3 with attested self-restore (0011), and the
  sentinel with policy-driven failover (0012).
- `docs/prior-art-and-attribution.md` — what the reproducible-float rung
  builds on (RepDL / ReproBLAS) versus the project's own prior art.
- `test/doctrine/` — the eleven doctrinal invariants, asserted as tests so a
  violating change fails CI (ADR 0004).

Every pull request is reviewed against these records. Silent substitution of
terminology, weakening of operational validation, or introduction of a code
path that emits the AI Genome in unsealed form is grounds to block the PR.

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

The layout above is the summary; each package documents its own
responsibility in its `doc.go`.

---

## Development

```
make build              # build sagvd, acp-compute, acpctl, acp-bootstrap, acp-demo
make test               # unit tests only
make test-race          # with race detector
make test-doctrine      # architectural invariant tests
make demo               # narrated end-to-end walkthrough of the vertical slice
make vault-gate         # 14 of the 18 CI checks, locally
```

The `vault-gate` target runs 14 of the 18 checks in the CI workflow of the
same name. It leaves out integration tests, osv-scanner, SBOM and the
reproducible-build check; run `make test-integration`, `make sbom` and
`make verify-reproducible` for three of them (osv-scanner runs only in CI).

The `demo` target runs `scripts/demo.sh`, which narrates the nine-stage
recovery flow end-to-end against the in-repo vertical slice — useful for
onboarding a new operator or for a live demo on a pilot call.

---

## Operator Runbook

Operator-facing procedures live in `docs/operator/`:

- `00_overview.md` — what each shipped binary does today, the role map, and
  which parts of the nine-stage flow are library code rather than binaries.
- `01_preflight.md` — build health, key material, the allow-list and stop
  list, audit-log verification, daemon health checks.
- `02_recovery_flow.md` — the nine-stage flow as library code, stage by
  stage, with the packages and tests that implement each.
- `03_incident_response.md` — the incident scenarios the handlers cover, and
  what an operator does with the shipped binaries in each.
- `04_observability.md` — `acpctl audit verify`, tip pinning, lineage and
  audit queries, metrics and logs.
- `05_release_procedure.md` — signed tag against pinned keys, SBOM, SLSA
  provenance, the release.yml workflow, the four signed binaries.
- `06_cross_cloud_restore.md` — releasing a genome's key to an attested
  destination, its restore, gate and receipt, key escrow and the operator
  stop.
- `07_failover.md` — the sentinel on the primary, the operator's failover
  policy, and the executor that moves a genome to the standby.

The runbook assumes a reader familiar with the eleven doctrinal invariants
(asserted in `test/doctrine/`) and the architecture decision records under
`docs/adr/`.

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
The naming used throughout the code is governed by
`docs/doctrine/terminology.md`.
