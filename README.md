# AI Continuity Platform — Core

[![vault-gate](https://github.com/vault-genome/vaultgenome-core/actions/workflows/vault-gate.yml/badge.svg)](https://github.com/vault-genome/vaultgenome-core/actions/workflows/vault-gate.yml)
[![CodeQL](https://github.com/vault-genome/vaultgenome-core/actions/workflows/codeql.yml/badge.svg)](https://github.com/vault-genome/vaultgenome-core/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/vault-genome/vaultgenome-core/badge)](https://scorecard.dev/viewer/?uri=github.com/vault-genome/vaultgenome-core)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15491/badge)](https://www.bestpractices.dev/projects/15491)
[![Release](https://img.shields.io/github/v/release/vault-genome/vaultgenome-core?display_name=tag&color=2ea44f)](https://github.com/vault-genome/vaultgenome-core/releases)
[![proof clock](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/vault-genome/proof-clock/main/badge.json)](https://github.com/vault-genome/proof-clock)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](docs/operator/05_release_procedure.md)
[![Go](https://img.shields.io/badge/Go-1.27.2-00ADD8?logo=go&logoColor=white)](go.mod)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)

**A fine-tuned AI model that survives the loss of the machine it runs on —
and comes back only where an operator-signed policy admits, on hardware that
proves what it is, behind a signed gate that proves the model works.**

The platform seals a model as a **genome** — the base model's hash, the
fine-tune as a sealed delta, and the deterministic recipe that produced it —
instead of a copy of the weights: 2.2 MB for a 0.5B model, one 447th of its
weights; 33.6 MB for a 32B model. The genome's key is released only to a
destination that attests with its chip (AMD SEV-SNP, Intel TDX, or an NVIDIA
H100 in confidential-computing mode) under a policy the operator signed in
advance; the destination restores the model itself, the authority gates it
(EXACT / EQUIVALENT / FAIL, signed), and every decision is on a signed,
hash-chained audit log before it takes effect. It is governance-first
infrastructure for AI continuity through catastrophic loss, including war:
a legal-authority problem first, a cryptographic-integrity problem second,
a computation problem third.

## Measured on real hardware

Every number links to the claim, its evidence files and the command that
reproduces it ([`VERIFIABLE-CLAIMS.md`](VERIFIABLE-CLAIMS.md), C1–C58).
The verifier itself is held to readings nobody here wrote on every
genuine SEV-SNP report on record, and that corpus is published for any
verifier to run ([`test/corpus/sev-snp/`](test/corpus/sev-snp/), C47;
the audit log under an auditor's own tool, C48).

| What | Result | Claim |
| - | - | - |
| A model under attack on a SEV-SNP VM fails over to another SEV-SNP VM | detect 2.53 s, RPO 9.0 s, **RTO 16.81 s**, the clean generation gated **EXACT** | [drill](docs/CONTINUITY-DRILL.md), [C14](VERIFIABLE-CLAIMS.md#c14) |
| The same failover to an Azure **confidential GPU** across the Internet | key released on the chip's report, the vTPM's quote and NVIDIA's tokens; **RTO 24.99 s**, EQUIVALENT on the H100 | [C18](VERIFIABLE-CLAIMS.md#c18) |
| The same failover to an **Intel TDX** Trust Domain | key released on Intel's word for the platform, TDX module and QE; **RTO 24.09 s** | [C21](VERIFIABLE-CLAIMS.md#c21) |
| A primary that **goes dark without a word** — switched off while it trains, then deleted | no report, only silence: after 15 s the key goes to the attested H100 across the Atlantic; **RTO 25.97 s** and **26.24 s** in two runs, EQUIVALENT on the H100, done before Google logged the machine's termination | [C35](VERIFIABLE-CLAIMS.md#c27) |
| Eight policies against one attack | **seven refused** for seven stated reasons, one move to the generation whose bytes match the sentinel's word | [C22](VERIFIABLE-CLAIMS.md#c22) |
| A **32B** model through the genome path on a confidential H100 | fine-tuned, sealed, restored and gated **EXACT** (16/16) over the Return Path | [C26](VERIFIABLE-CLAIMS.md#c26) |
| A 7B genome on one GPU | 10 MB against 15 GB of weights (1 : 1 502), EXACT on the pinned runtime, the recipe replaying bit for bit | [C16](VERIFIABLE-CLAIMS.md#c16) |
| The integer door across CPU and GPU | **the same bytes** on an Intel Xeon and an NVIDIA L4, at 0.5B and 7B, at zero tolerance | [C19](VERIFIABLE-CLAIMS.md#c19) |
| The GPU evaluated by this verifier, not only by NVIDIA | the H100's report, chain, firmware id, every measurement against NVIDIA's signed manifests, revocation asked of NVIDIA's responder; on the audit record | [C20](VERIFIABLE-CLAIMS.md#c20) |
| No secret file bare on a host | the escrow key sealed to the chip or the vTPM; seeds, TLS keys, tokens and the sentinel's seed sealed in place; a sealed file on another chip does not open | [C23](VERIFIABLE-CLAIMS.md#c23), [C24](VERIFIABLE-CLAIMS.md#c24), [C25](VERIFIABLE-CLAIMS.md#c25) |

What we do **not** claim is listed just as carefully:
[what we do not claim](VERIFIABLE-CLAIMS.md#what-we-do-not-claim),
[`KNOWN_ISSUES.md`](KNOWN_ISSUES.md), [`ROADMAP.md`](ROADMAP.md).

## Quickstart

**Five minutes, no cloud, no TEE hardware, no config.** The demo runs the real
platform code with a simulated TEE (it says so in its output):

```bash
git clone https://github.com/vault-genome/vaultgenome-core.git
cd vaultgenome-core
go run ./cmd/acp-demo
```

It seals a sample genome, receives it on a second "node", regenerates it and
prints an Ed25519-signed equivalence verdict: **EXACT** on a pinned runtime;
a simulated cross-hardware float drift falling through to the byte-portable
**integer path** (EQUIVALENT); and a **corrupted genome blocked**, fail-closed.
Or with Docker: `docker build -t vaultgenome . && docker run --rm vaultgenome`.
Point it at your own file for a byte-exact sealed-continuity proof:
`go run ./cmd/acp-demo --model ./path/to/your-model.safetensors`.

**Protect a real model with the CLI** — seal it into a portable `.genome`
bundle whose key is not in the file, move it, restore it byte-exact, and
keep a validated version chain:

```bash
make build                                                   # ./bin/acpctl and the daemons
./bin/acpctl genome seal --content-dir=./my-model --output=gen-0.genome --key-out=gen-0.key
./bin/acpctl genome seal --content-dir=./adapter-1 --parent=gen-0.genome --output=gen-1.genome --key-out=gen-1.key
# on another server, with the bundles and the key file copied over:
./bin/acpctl genome rewind --bundle=gen-0.genome --key-file=gen-0.key --target=./restored
./bin/acpctl genome chain  --dir=.
```

Opening authenticates every 1 MiB segment before a byte of it is used and
leaves the target untouched on any refusal: an edited, truncated or
wrong-key bundle changes nothing.

**Prerequisites.** Go 1.27.2 for the binaries (`go.mod` names the toolchain;
`GOTOOLCHAIN=auto` fetches it). The `acp-compute` worker and the hardware
kits also need Python 3.12+ with the pinned runtime in
[`workers/genome/requirements.txt`](workers/genome/requirements.txt)
(torch 2.14.1); a vTPM host (Intel TDX, the Azure confidential GPU VM) needs
`tpm2-tools`.

## Deploy

| Path | Start here |
| - | - |
| **One button on Google Cloud** — a Confidential VM (AMD SEV-SNP, or Intel TDX with `--platform tdx`) stood up from the signed release, proven the way the reference deployment is proven, and left running: the release verified before it runs, `acpctl provision`, both daemons as services, a gate job, the audit log verified | [`deploy/gcp/`](deploy/gcp/README.md): [![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/vault-genome/vaultgenome-core&cloudshell_git_branch=main&cloudshell_workspace=deploy/gcp&cloudshell_tutorial=tutorial.md) — or `deploy/gcp/deploy.sh --project <id>` wherever `gcloud` is signed in |
| **One button on Azure** — an Azure Confidential VM (AMD SEV-SNP) that verifies the release itself, reboots once so its key files are sealed to the vTPM on a settled boot, stands the deployment up with `acpctl provision` and proves it; from the portal, or from `az` with the record brought back | [`deploy/azure/`](deploy/azure/README.md): [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fvault-genome%2Fvaultgenome-core%2Fmain%2Fdeploy%2Fazure%2Fazuredeploy.json) — or `deploy/azure/deploy.sh` wherever `az` is signed in |
| **One button on AWS** — an EC2 instance with AMD SEV-SNP (shared tenancy) that verifies the release itself, stands the deployment up with `acpctl provision` under the provider's VLEK — the family `aws-sev-snp`, the launch measurement AWS publishes, the key files sealed with the fleet's derived key — and proves it; from the CloudFormation console, or from `aws` with the record brought back | [`deploy/aws/`](deploy/aws/README.md): [![Launch Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://us-east-2.console.aws.amazon.com/cloudformation/home?region=us-east-2#/stacks/create/review?templateURL=https://s3.us-east-2.amazonaws.com/vaultgenome-deploy/template.json&stackName=vaultgenome) — or `deploy/aws/deploy.sh` wherever `aws` is signed in |
| **The proof clock** — the Google Cloud button run by GitHub Actions twice a day from the latest release on a real Confidential VM (AMD SEV-SNP at 06:00 UTC, Intel TDX at 18:00 UTC), the status decided from the guest's own record — proven only when the gate came back EXACT and the audit log replayed ok — the VM removed, the record and the counter committed where anyone can check them | [`vault-genome/proof-clock`](https://github.com/vault-genome/proof-clock): `latest.json` is the counter (the last proven run, the streak, the runs by status, the chips and launch measurements seen), `records/<date>/` the records, `tools/check-record.py` a stranger's check of one record — offline, against AMD's key server, against GitHub Releases |
| **A real deployment on confidential VMs** — the authority, a worker, a destination, the policies, the keys | [`docs/operator/`](docs/operator/00_overview.md): [preflight](docs/operator/01_preflight.md) (keys and `seal-keys`), [cross-cloud restore](docs/operator/06_cross_cloud_restore.md), [failover](docs/operator/07_failover.md), and the real-TEE runbooks for [SEV-SNP](docs/operator/runbooks/real-tee-sev-snp.md), [TDX](docs/operator/runbooks/real-tee-tdx.md) and the [Azure confidential GPU](docs/operator/runbooks/real-tee-azure-cgpu.md) |
| **Reproduce a hardware claim** — one command boots the machines, runs the drill, collects the evidence and deletes everything | [`scripts/hardware-test/`](scripts/hardware-test/): each kit's README names the machines, the cost and the time of a run (a failover drill: two SEV-SNP VMs, about 25 minutes; the H100 runs: one NCC H100 v5 VM at about $9 an hour) |
| **Run the pieces locally** — the daemons on the simulated TEE, with Docker Compose | [`deploy/compose/`](deploy/compose/README.md) |
| **Run the released images** — signed by digest, the release's own binaries inside | [`deploy/compose/README.md`](deploy/compose/README.md#run-the-released-images-instead-of-building) |

Every binary reads its secrets from files it seals to the host it runs on:
run `sagvd seal-keys`, `acp-compute seal-keys` and `acp-bootstrap seal-keys`
once after provisioning ([ADR 0023](docs/adr/0023-the-daemons-key-files-sealed-to-the-host.md)).

## Download and verify a release

A release carries the five binaries for Linux x86-64 — `sagvd`,
`acp-compute`, `acpctl`, `acp-bootstrap`, `acp-keygen` — and their `-fips`
variants on the certified Go Cryptographic Module v1.0.0 (ADR 0030); the
two tools a person runs on their own machine, `acpctl` and `acp-keygen`,
for the other platforms as well; the worker package; and a signed list of
every artifact's SHA-256, `checksums-<tag>.txt`.

| Your machine | Files |
| - | - |
| Linux x86-64 — a server; the daemons too | `acpctl`, `acp-keygen`, `sagvd`, `acp-compute`, `acp-bootstrap`; `<name>-fips` on the certified module |
| Linux arm64 | `acpctl-linux-arm64`, `acp-keygen-linux-arm64` |
| macOS, Apple silicon | `acpctl-darwin-arm64`, `acp-keygen-darwin-arm64` |
| macOS, Intel | `acpctl-darwin-amd64`, `acp-keygen-darwin-amd64` |
| Windows x64 | `acpctl-windows-amd64.exe`, `acp-keygen-windows-amd64.exe` |
| Windows Arm | `acpctl-windows-arm64.exe`, `acp-keygen-windows-arm64.exe` |

The daemons are Linux x86-64 only: they attest with hardware the other
platforms do not have
([`09_first_deployment.md`](docs/operator/09_first_deployment.md) §2 names
the hosts a release has run on).

Python: `pip install vaultgenome` is the auditor's own verifier of the
audit log (`vaultgenome-audit`, no dependencies), and `pip install
"vaultgenome[genome]"` adds the model side of a genome (`vg-genome`, on
the worker's pinned runtime). The wheel and the sdist PyPI serves are
release assets too — `vaultgenome-<version>-py3-none-any.whl` and
`vaultgenome-<version>.tar.gz`, in the checksums list and signed like the
rest ([`python/README.md`](python/README.md)).

Homebrew, on macOS and Linux: `brew install vault-genome/tap/vaultgenome`
— the formula of
[`vault-genome/homebrew-tap`](https://github.com/vault-genome/homebrew-tap)
is written from the release's signed `checksums-<tag>.txt`, so what it
installs is what the list names.

Releases are cut by [`release.yml`](.github/workflows/release.yml) from a tag
signed by a key pinned in [`.github/allowed_signers`](.github/allowed_signers):
every binary and the worker package built reproducibly, each with a
keyless cosign signature and a transparency-log entry, an SPDX SBOM, and
a SLSA level 3 provenance attestation. Check what you downloaded before
you run it — the whole download at once against the signed list, then
any file on its own:

```bash
sha256sum -c checksums-<tag>.txt            # every downloaded file against the list
cosign verify-blob --signature checksums-<tag>.txt.sig --certificate checksums-<tag>.txt.cert \
  --certificate-identity-regexp '^https://github\.com/vault-genome/vaultgenome-core/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums-<tag>.txt
cosign verify-blob --signature sagvd.sig --certificate sagvd.cert \
  --certificate-identity-regexp '^https://github\.com/vault-genome/vaultgenome-core/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com sagvd
slsa-verifier verify-artifact sagvd --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/vault-genome/vaultgenome-core --source-tag v0.14.0
git verify-tag v0.14.0
```

The same two commands verify `acp-compute`, `acpctl`, `acp-bootstrap`,
`acp-keygen`, their `-fips` variants, the tools for the other platforms,
the wheel, the sdist and the worker package `genome-worker-v0.14.0.tar.gz`; a deployment
needs nothing from the source tree
([`docs/operator/09_first_deployment.md`](docs/operator/09_first_deployment.md)).
On Windows, `certutil -hashfile acpctl-windows-amd64.exe SHA256` prints
the hash to compare with the list's line, and cosign has a Windows build.

From 0.4.3 on, every signed file also has a Sigstore bundle,
`<asset>.sigstore.json` — the signature, the certificate and the Rekor
entry in one file — so a host with no route at all verifies it too, with
the Sigstore trust root carried in as a file (`cosign initialize` on a
connected machine fetches it into its cache,
`~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json`):

```bash
cosign verify-blob --new-bundle-format --bundle sagvd.sigstore.json --trusted-root trusted_root.json \
  --certificate-identity-regexp '^https://github\.com/vault-genome/vaultgenome-core/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com sagvd
```

Not `--offline`: on the pinned cosign 2.6.5 that flag still reaches for
the TUF mirror and fails without a route (measured).
([`docs/operator/runbooks/air_gap.md`](docs/operator/runbooks/air_gap.md) is
the air-gapped procedure; the rehearsal `v0.4.3-rc2` verified all twelve
bundles this way with the network denied.)

[`docs/operator/05_release_procedure.md`](docs/operator/05_release_procedure.md)
is the whole procedure; [`docs/security/supply_chain.md`](docs/security/supply_chain.md)
says what each check proves.

## How it works

![Architecture overview](docs/diagrams/architecture-overview.svg)

Five binaries, one flow. The nine governed stages — Recovery Request →
Trust Admission → Trusted Session → Staged Disclosure → Delegated External
Compute → Return Path → Validation → Release Decision → Audit — are library
code under `internal/`, and `sagvd` drives them for every job
([ADR 0015](docs/adr/0015-one-binary-drives-the-nine-stages.md)).

| Binary | Role |
| - | - |
| `sagvd` | The authority. Releases a genome's key only to an attested destination the policy admits, gates every restore, confirms it, and writes every decision to the signed, hash-chained audit log before it takes effect. Runs the operator's REST API and the Return Path. |
| `acp-compute` | The worker. Dials the authority over mutual TLS, attests with its chip, restores the sealed genome's model in memory and answers the genome's own reference prompts; nothing of the genome touches its disk. |
| `acp-bootstrap` | The destination of a cross-cloud key release. Attests, receives the key, restores the genome, proves the model works through the door, signs a receipt with its TEE. |
| `acpctl` | The operator's CLI: seal, open and verify genomes; the sentinel that keeps a running model sealed and reports an intrusion; policies, stop lists, escrow ceremonies, audit verification. |
| `acp-demo` | The one-command demonstration above. |

A sentinel on the primary seals every new state of a running model with its
key escrowed to the authority and attests every record with the primary's
chip; when a tripwire fires, the authority moves the last clean generation
to the one standby the operator's policy names, and confirms it by the
standby's TEE-signed gate verdict
([ADR 0012](docs/adr/0012-sentinel-and-policy-driven-failover.md),
[ADR 0017](docs/adr/0017-limits-on-the-primarys-word.md)). The determinism
ladder finds a door that reproduces the sealed references — pinned float,
reproducible float, or the byte-portable integer forward
([ADR 0008](docs/adr/0008-equivalence-gate.md), [ADR 0020](docs/adr/0020-the-integer-door-for-the-lora-worker.md))
— or fails closed.

## Status

Stage E: the release side is doctrine-closed and measured on hardware; the
receive side that bootstraps itself is deferred to V2. The full maturity
summary is [`docs/STATUS.md`](docs/STATUS.md). In short:

- Real attestation is verified here for AMD SEV-SNP (GCP, Azure, and EC2
  under the provider's VLEK — a family that names no machine and seals to
  the fleet's key, C58), Intel TDX (GCP), the Azure confidential GPU VM and
  AWS Nitro Enclaves — a genome key released across clouds into a
  production-mode enclave by a SEV-SNP authority, once (C52); the Intel SGX
  family is refused until an enclave has taken a key release end to end.
- The largest model measured is 32B, on one confidential GPU; cross-device
  equivalence is measured at 0.5B and 7B; every failover number is at 0.5B.
- Byte-identical float inference across CPUs and GPUs is not achievable, and
  we measured it; the integer door is the answer.
- This is a reference implementation with a real CI gate; it is not an
  operated service, and it has had no external security audit.

## Documentation

| | |
| - | - |
| [`VERIFIABLE-CLAIMS.md`](VERIFIABLE-CLAIMS.md) | Every claim, its evidence and its reproduction command; what we do not claim |
| [`docs/CONTINUITY-DRILL.md`](docs/CONTINUITY-DRILL.md) | The failover drills, narrated, with their numbers |
| [`docs/adr/`](docs/adr/README.md) | Twenty-three architecture decision records, from the frozen TEE interface (0001) to the sealed key files (0023) |
| [`docs/operator/`](docs/operator/00_overview.md) | The operator guides 00–09 — from the overview to the first deployment measured against the reference — and the real-TEE runbooks |
| [`docs/security/`](docs/security/threat_model.md) | The threat model and the supply chain |
| [`docs/doctrine/`](docs/doctrine/terminology.md) | The canonical vocabulary (enforced by CI) and the CI security policy |
| [`docs/testing/`](docs/testing/cross-hardware-determinism.md) | Cross-hardware determinism and mutation testing |
| [`docs/compliance/`](docs/compliance/README.md), [`docs/reference-designs/`](docs/reference-designs/README.md) | The control catalogue, the sector maps and four reference designs |
| [`docs/spec/`](docs/spec/draft-vault-genome-tap-00.md) | The TEE-Agnostic Attestation Protocol draft |
| [`docs/reference/cli.md`](docs/reference/cli.md) | Every command and flag of the five binaries, generated from their own usage text |
| [`docs/reference/api.md`](docs/reference/api.md) | The operator REST API for an integrator — `POST /v1/jobs`, `GET /v1/jobs/{id}`, the error envelope, the job view, how to verify what it says |
| [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md), [`ROADMAP.md`](ROADMAP.md), [`CHANGELOG.md`](CHANGELOG.md) | Limits, what is next, what changed |

## Development

```bash
make build              # sagvd, acp-compute, acp-bootstrap, acpctl, acp-demo
make test               # unit tests
make test-race          # with the race detector
make test-doctrine      # the eleven doctrinal invariants
make vault-gate         # 14 of the 18 CI checks, locally
make test-integration && make sbom && make verify-reproducible   # three more; osv-scanner runs only in CI
```

`main` is protected: every change arrives by pull request through the
`vault-gate`, CodeQL, Semgrep and benchmark checks. Release tags are signed
by a pinned key. Dependencies are allow-listed with a written justification
each ([`docs/dependencies/`](docs/dependencies/)), capped in depth, and kept
current by Dependabot.

## Contributing, security, license

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — pull request format, branch naming,
  the terminology gate. [`SUPPORT.md`](SUPPORT.md) — where to ask what.
  [`MAINTAINERS.md`](MAINTAINERS.md) — the founders and where release
  authority is pinned.
- [`SECURITY.md`](SECURITY.md) — report vulnerabilities privately; never in
  a public issue. The platform is defensive infrastructure for adversarial
  conditions, and responsible disclosure is part of the trust model.
- **License:** AGPL-3.0-or-later ([`LICENSE`](LICENSE), scope in
  [`NOTICE`](NOTICE)); the same code under a
  [commercial license](COMMERCIAL-LICENSE.md) for deployments that cannot
  satisfy AGPL §13, with no feature gating between the two. The published
  conformance corpus, its harness and the public conformance package
  ([`test/corpus/sev-snp`](test/corpus/sev-snp/), [`tools/corpus-harness`](tools/corpus-harness/),
  [`pkg/teeconformance`](pkg/teeconformance/)) are Apache-2.0, so that any
  verifier can test against them.
- **Cite:** [`CITATION.cff`](CITATION.cff).

The architecture represented by this code is the product of the founders'
patent family and design documents; the reproducible-float rung stands on
RepDL / ReproBLAS ([`docs/prior-art-and-attribution.md`](docs/prior-art-and-attribution.md)).
