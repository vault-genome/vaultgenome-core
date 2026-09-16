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
- **`acp-compute`**, the external-compute worker. It restores a sealed genome's
  model in memory and answers the authority's questions about it.
- **`acp-demo`**, a one-command demonstration.

The nine-stage governed reconstruction flow of the foundation architecture —
Recovery Request → Trust Admission → Trusted Session → Staged Disclosure →
Delegated External Compute → Return Path → Validation → Release Decision →
Audit — is library code under `internal/`, and `sagvd` drives it for every
gate job (ADR 0015): each stage's decision on the audit log before it takes
effect, each artifact signed. [docs/operator/00_overview.md](docs/operator/00_overview.md)
says what each binary drives today.

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

> **Evaluating this project?** Start with
> **[VERIFIABLE-CLAIMS.md](VERIFIABLE-CLAIMS.md)** — every claim we make, the
> evidence file that proves it, the command that reproduces it, and an explicit
> [list of what we do not claim](VERIFIABLE-CLAIMS.md#what-we-do-not-claim).
> Then **[docs/CONTINUITY-DRILL.md](docs/CONTINUITY-DRILL.md)** — a model is
> fine-tuned inside a confidential VM, its machine is compromised, and it comes
> back gated on another machine in **16.81 s**, on real hardware.

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
- key release only to attested hardware — **AMD SEV-SNP** on **GCP and
  Azure**, and an **Azure confidential GPU** whose evidence carries the chip,
  the vTPM and the H100 (`scripts/hardware-test/`, `docs/adr/0008`, `0009`,
  `0011`, `0019`);
- automatic failover of a running model under the operator's signed policy
  (ADR 0012).

**What we do not do:** generate a model from a recipe alone, without its
sealed delta. The `acp-compute` worker restores the sealed delta onto the
public base model, in memory, and the authority proves the result with the
gate (ADR 0013); it does not invent weights. We say which is which, on
purpose.

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
  - At **7B** (Qwen2.5-7B-Instruct, fine-tuned on an NVIDIA L4 in bfloat16,
    [gpu-7b](scripts/hardware-test/gpu-7b)): a 10 MB genome against 15 GB
    of base weights (1 : 1 502), EXACT on the pinned GPU, the recipe
    replaying bit for bit there; on the host CPU the same answers token for
    token, logits one or two bfloat16 quanta apart — and the float door
    fails closed on that, as it should.
- **Automatic failover, decided by the operator** — a sentinel on the primary
  seals every new state with its key escrowed to the authority, and reports
  when a tripwire fires (`acpctl sentinel watch`). Under a failover policy the
  operator signed in advance, `sagvd failover` restores the last genome sealed
  before the intrusion, or before a lost heartbeat, on the one standby the
  policy names. It confirms the restore by the standby's TEE-signed gate
  verdict. One policy allows one move, and the operator stop overrides it
  (ADR 0012). The primary's word is bounded: every record the sentinel writes
  carries the primary chip's report, a policy that pins the primary's
  measurement ignores records without it — a stolen sentinel seed used off
  the chip is silence, and silence is a trigger — `stopped` stands the
  authority down only for a grace, and nothing past the generation the
  trigger's record names is restored (ADR 0017). The authority's escrow key
  is made in its own process and written only sealed to its chip (ADR 0016),
  and every other secret file the daemons read — seeds, TLS keys, tokens,
  the sentinel's seed — is sealed to the host too (`seal-keys`, ADR 0023).
  Measured on **two live SEV-SNP VMs**
  ([gcp-failover](scripts/hardware-test/gcp-failover)): detect 2.53 s, RPO
  9.0 s, **RTO 16.81 s** from intrusion to a gated, confirmed model — and what
  came back was the clean generation, gated **EXACT**, against a policy that
  required only EQUIVALENT. The same failover with the standby an **Azure
  confidential GPU** across the Internet
  ([failover-cgpu](scripts/hardware-test/failover-cgpu)): the key released to
  the H100 host on its chip's report, its vTPM's quote with the boot pinned
  and NVIDIA's tokens, the clean generation restored and gated **EQUIVALENT**
  on the GPU (max abs err 1.5e-4), **RTO 24.99 s**, RPO 12.0 s. And with the
  standby an **Intel TDX** Trust Domain
  ([failover-tdx](scripts/hardware-test/failover-tdx)): the key released on
  Intel's word for the platform, the TDX module and the Quoting Enclave, the
  clean generation gated **EQUIVALENT** on Intel CPUs against references
  sealed on AMD (max abs err 1.45e-4), **RTO 24.09 s**, RPO 12.0 s. Locally with
  the real binaries: RTO 0.63 s after an intrusion; 3.5 s after a killed
  primary, with a 3 s heartbeat timeout. And asked eight times against one
  attack on two live SEV-SNP VMs
  ([failover-negatives](scripts/hardware-test/failover-negatives)): an
  expired policy, an RPO bound, a quarantine, an operator stop, a foreign
  standby, a spent policy and a stranger's signature are each **refused**
  for their own stated reason — the stop and the foreign standby *after*
  the standby's chip verified — and the one move goes to the generation
  whose bytes match the sentinel's word, the corrupted newer bundle set
  aside on the record.
- **Real AMD SEV-SNP attestation** — a report from a live confidential VM is
  parsed, its ECDSA-P384 signature verified, and its VCEK chained to AMD
  ARK-Milan — proven on **two clouds, GCP and Azure** (`scripts/hardware-test/`,
  ADR 0007 / 0009). **Real Intel TDX attestation** — a quote from a live
  Trust Domain is parsed, its attestation key and PCK chain verified to the
  Intel SGX Root CA, and the platform rated against Intel's signed TCB info
  and QE identity ([gcp-tdx/capture](scripts/hardware-test/gcp-tdx/capture),
  ADR 0018).
- **Cross-hardware regeneration gate** — a signed EXACT / EQUIVALENT / FAIL
  verdict on recomputed reference fixtures, behind a determinism ladder that
  finds a working door (pinned float → reproducible float → byte-portable
  integer) or fails closed. Determinism measured on real CPUs (AMD/Intel) and
  GPUs (NVIDIA L4/T4) — `docs/testing/cross-hardware-determinism.md`, ADR 0008.
  The integer door computes the real model's forward in integer arithmetic
  (ADR 0020): a genome restored on an Intel Xeon and on an NVIDIA L4 gives
  **the same bytes**, at 0.5B and at 7B, and at zero tolerance on the GPU
  the float doors fail while the integer door opens **EXACT** — a different
  arithmetic with a measured fidelity, the same top-1 token on every fixture
  ([integer-door](scripts/hardware-test/integer-door)).
- **A worker that restores the model, judged by the authority** — a job on
  `sagvd`'s REST API names a sealed genome; the authority ships its model side
  sealed over the Return Path, `acp-compute` brings the model back in memory
  through the `vg_genome` door and answers the genome's own reference prompts,
  and the authority holds the answers to the sealed references through the
  determinism ladder, signing the verdict (ADR 0013). Nothing of the genome
  touches the worker's disk. Proven live over mutual TLS in
  `test/integration`, and with the real fine-tune and real torch in the
  `genome-worker` workflow.
- **The vault daemon drives the nine stages** — every gate job is a
  RecoveryRequest that `sagvd` takes through intake, Trust Admission (the
  attested worker, the policy profile, the operator's stop list), a signed
  session, staged disclosure of the model side to that session, a signed
  manifest, the candidate, three-dimension validation and a signed release
  decision, with every decision on a signed, hash-chained audit log before
  it takes effect; a log that cannot take the record stops the stage;
  `GET /v1/jobs/{id}` shows every stage and artifact, and `acpctl audit
  verify` checks the log under the published key (ADR 0014, 0015).
- **Both ends of the Return Path attest with the chip** — `sagvd` and
  `acp-compute` run on AMD SEV-SNP (`tee.provider: "gcp-sev-snp"`) or Intel
  TDX (`"gcp-tdx"`, ADR 0018), each pinning the other's measurement and
  verifying to the AMD or the Intel root — for TDX with Intel's signed TCB
  word on the platform, the TDX module and the Quoting Enclave; a worker
  whose Evidence is not the pinned identity gets no job. Run on a GCP
  SEV-SNP Confidential VM
  ([returnpath-e2e](scripts/hardware-test/gcp-sev-snp/returnpath-e2e)) and
  on a GCP Intel TDX Trust Domain
  ([gcp-tdx/returnpath-e2e](scripts/hardware-test/gcp-tdx/returnpath-e2e))
  with the real `vg_genome` door.
- **A confidential GPU worker** — on an Azure NCC H100 v5 (an AMD SEV-SNP
  guest with an H100 in confidential-computing mode) `sagvd` and
  `acp-compute` attest as `azure-cgpu` (ADR 0019): the chip's report from
  the vTPM, the vTPM's quote binding the handshake, and NVIDIA's signed
  tokens for the GPU, verified to AMD's, the vTPM's and NVIDIA's keys; the
  7B genome came back through the door on the H100 in confidential mode,
  **EXACT**, in 18.5 s from job to signed release
  ([azure-cgpu](scripts/hardware-test/azure-cgpu)).
- **Honest boundaries** — off hardware the daemons run a simulated TEE that
  announces itself; no AWS Nitro or SGX adapter attests; a TDX host and an
  Azure confidential GPU host seal the escrow key to their vTPM under a
  policy of the pinned boot (ADR 0022), a different root than the TEE's own
  — proven on TDX as the authority of a failover, RTO 20.27 s
  ([failover-tdx-authority](scripts/hardware-test/failover-tdx-authority)).
  An attested
  GPU has been a Return Path worker and, once, the standby of a failover,
  and a TDX Trust Domain has been the standby of a failover once;
  the GPU's measurements are evaluated by NVIDIA and, under the `both`
  policy, by this verifier too (the report's signature and chain, the
  firmware id, every measurement against NVIDIA's manifests, ADR 0021) —
  the manifests' XML signatures verified (ADR 0021, amended) — so a verdict
  may rest on our evaluation alone (`own`), and what stays NVIDIA's word is
  revocation and, under `own`, the secure-boot and debug claims only its
  tokens carry. The largest model measured is 7B, on one GPU and on
  an attested confidential GPU VM; every failover number is 0.5B scale. **We
  measured against ourselves that byte-identical float inference across CPU and
  GPU is not achievable** — divergence enters at the first transformer block in
  both float32 and float64, while top-1 tokens still agree 16/16
  ([gpu-exact](scripts/hardware-test/gpu-exact)). The reproducible-float rung
  stands on RepDL / ReproBLAS (`docs/prior-art-and-attribution.md`).
  [KNOWN_ISSUES.md](KNOWN_ISSUES.md) and
  [What we do not claim](VERIFIABLE-CLAIMS.md#what-we-do-not-claim) list every
  limit.

**Minimum Go version:** 1.25.
**License:** AGPL-3.0-or-later — full text in [LICENSE](LICENSE), scope and
attribution in [NOTICE](NOTICE). The same code is available under a
[commercial license](COMMERCIAL-LICENSE.md) for deployments that cannot satisfy
AGPL §13; there is no feature gating between the two.

The **What works today** section above is the authoritative maturity
summary for this repository; component-level design rationale lives in the
architecture decision records under `docs/adr/`.

---

## Governance & design records

The code in this repository is governed by the documents and machine-checked
records kept in the repo:

- `docs/doctrine/terminology.md` — canonical vocabulary and the frozen
  deprecated-name list; enforced by the terminology gate (vault-gate 09).
- `docs/adr/` — thirteen architecture decision records (ADR 0001–0013),
  among them the frozen producer / verifier / sealer interface (0001),
  multi-TEE adapter dispatch (0002), doctrine-invariants-as-tests (0004),
  cross-cloud KMS-mediated recovery (0006), the equivalence gate (0008), the
  X25519 KEM cross-cloud key delivery (0009), the operator stop and recorded
  refusals (0010), genome v3 with attested self-restore (0011), the sentinel
  with policy-driven failover (0012), and the worker that restores the genome
  (0013).
- `docs/prior-art-and-attribution.md` — what the reproducible-float rung
  builds on (RepDL / ReproBLAS) versus the project's own prior art.
- `test/doctrine/` — the eleven doctrinal invariants, asserted as tests so a
  violating change fails CI (ADR 0004).
- [`VERIFIABLE-CLAIMS.md`](VERIFIABLE-CLAIMS.md) — the claims register: claim →
  evidence file → reproduction command, and what we refuse to claim.
- [`MAINTAINERS.md`](MAINTAINERS.md) — the founders, their roles, and where
  release authority is pinned; [`.github/CODEOWNERS`](.github/CODEOWNERS)
  requires dual-founder review on every governed surface.
- [`CHANGELOG.md`](CHANGELOG.md) — what changed in each release, and which
  bundle and schema versions it can still open.

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
  destination, its restore, gate and receipt, key escrow (the escrow key
  sealed to the release host's TEE, and its recovery) and the operator stop.
- `07_failover.md` — the sentinel on the primary attesting with its TEE, the
  operator's failover policy pinning it, and the executor that moves a
  genome to the standby.

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
