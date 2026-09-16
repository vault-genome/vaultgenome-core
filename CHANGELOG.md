# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the public surface — CLI flags, bundle format,
audit schema, policy schema — may change between minor versions. Bundle and
schema versions are stated explicitly below so an operator can tell what a
given release can still open.

## [Unreleased]

### Added

- **The worker restores the genome** ([ADR-0013](docs/adr/0013-worker-restores-the-genome.md))
  — a job on `sagvd`'s REST API names a sealed model genome in
  `genome.bundle_dir`; `sagvd` opens it (key file, or escrow envelope opened
  with `genome.key_escrow_path`), keeps the fixtures' references, and ships
  the model side — `genome.json`, the LoRA adapter, the fixtures' prompts —
  sealed component by component over the Return Path behind a descriptor
  (`internal/genome/gatejob`). `acp-compute` restores the model in memory
  through the `vg_genome` door (`python -m vg_genome door --stdin-genome`) and
  answers the prompts; `sagvd` holds the answers to the references through the
  determinism ladder and records the verdict on the job, signed by the
  authority (`gate` on `GET /v1/jobs/{id}`; `sagvd_gate_verdicts_total{level}`).
  Live over mutual TLS in `test/integration`; with the real fine-tune and real
  torch in the `genome-worker` workflow.
- `acp-compute` configuration section `genome.door` (`command`, `env`,
  `timeout_seconds`); `sagvd` configuration section `genome` (`bundle_dir`,
  `key_escrow_path`, `gate`).
- **[VERIFIABLE-CLAIMS.md](VERIFIABLE-CLAIMS.md)** — every public claim mapped
  to the evidence file that proves it and the command that reproduces it,
  including an explicit *What we do not claim* section.
- **[docs/CONTINUITY-DRILL.md](docs/CONTINUITY-DRILL.md)** — the two hardware
  drills as one narrative, with the measured numbers.
- **[NOTICE](NOTICE)** — copyright, licence scope and third-party attribution.
- **[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)** — the dual-licensing offer,
  with a public commitment that the AGPL build and the commercial build are the
  same code, and that the ADR-0012 safety invariants are not negotiable for any
  customer.
- **[MAINTAINERS.md](MAINTAINERS.md)** — both founders, their roles, and where
  release authority is pinned.
- This changelog.

### Changed

- **`POST /v1/jobs` names a genome instead of carrying a payload.** The body is
  `{"genome": {"bundle", "key_file"}, "deadline_seconds_from_now"}`;
  `manifest_id`, `session_id`, `expected_output_kind`,
  `expected_output_max_bytes` and `payload_base64` are gone from the request
  and the first three come back in the response, named by the authority. A
  job's output kind is always `bytes/fixed-length` and its size budget the
  exact size of the answer.
- `acp-compute` refuses to start without `genome.door.command`; there is no
  backend to fall back to.
- **[LICENSE](LICENSE) now carries the verbatim GNU AGPL-3.0 text.** It
  previously held only a short-form notice plus a scaffold note, so licence
  detection reported `NOASSERTION` and the repository appeared unlicensed to
  automated tooling. The licence itself is unchanged: AGPL-3.0-or-later, as it
  has been since [ADR-0003](docs/adr/0003-agpl-commercial-dual-licensing.md).
- **[`.github/CODEOWNERS`](.github/CODEOWNERS) now binds.** It previously listed
  placeholder handles that do not exist on GitHub, and prefixed every path with
  `/core/` although the repository root *is* `core` — so every rule was silently
  ignored and no file had an owner. Real handles, repository-relative paths, and
  the governance surfaces added since (failover, revocation, reconstruction,
  the claims documents).
- The repository description no longer says *"byte-exact regeneration of AI
  models across hardware"*. Our own measurement
  ([C6](VERIFIABLE-CLAIMS.md#c6)) shows byte-identical float inference across
  CPU and GPU is not achievable; the accurate ladder is EXACT on the pinned
  runtime, EQUIVALENT across devices with the error measured.

### Removed

- The placeholder reconstruction backends: the byte-level order-3 Markov
  chain (`internal/compute/worker/generative.go`) is deleted, and the SHA-256
  expansion (`reconstruction.go`) is no longer built into any binary — it
  remains a test fixture behind the frozen R-11 interface. KNOWN_ISSUES #2 is
  resolved; the skipped `TestGenerative_PartialGenomeDegradation` is gone with
  its backend.

## [0.1.0] — 2026-09-14

First public release. Four signed binaries (`sagvd`, `acpctl`,
`acp-bootstrap`, `acp-compute`) with cosign signatures and certificates, SPDX
SBOMs and SLSA provenance. Stage E, MVP maturity.

### Added

- **Genome v3 bundle format** — `magic ‖ header ‖ nonce prefix ‖ AES-256-GCM
  segments`, sealed under a fresh key that is not in the file, escrowed to the
  release authority at seal time. `acpctl genome seal / rewind / chain / verify`.
- **Attested self-restore across clouds** ([ADR-0011](docs/adr/0011-genome-v3-and-attested-self-restore.md))
  — the authority releases a genome's key only to an attested, allow-listed
  destination TEE; the destination restores the genome itself and signs a
  receipt with its TEE; the source verifies the receipt before recording the
  restore (`sagvd crosscloud-confirm`).
- **Sentinel and policy-driven failover** ([ADR-0012](docs/adr/0012-sentinel-and-policy-driven-failover.md))
  — `acpctl sentinel watch` checks tripwires before sealing each new generation
  with its key escrowed, and signs heartbeats; `sagvd failover` moves the last
  clean genome to the one standby an operator signed for in advance. One policy
  serial authorises at most one move; the operator stop list overrides any
  policy. Audit schema v6 adds `FAILOVER_DECIDED`, emitted before any key moves.
- **Equivalence gate and determinism ladder** ([ADR-0008](docs/adr/0008-equivalence-gate.md))
  — a signed EXACT / EQUIVALENT / FAIL verdict over sealed reference fixtures,
  trying `pinned-replay` first and falling through to `native-float` with the
  error measured, or failing closed.
- **Operator stop and recorded refusals** ([ADR-0010](docs/adr/0010-operator-stop-and-recorded-refusals.md))
  — a global halt that overrides every policy, with refusals written to the
  audit chain.
- **Real AMD SEV-SNP attestation**, verified to AMD ARK-Milan, on GCP and Azure.
- **Hardware drills** — [`gcp-drill`](scripts/hardware-test/gcp-drill) (fine-tune
  in a TEE, restore on L4 and Intel CPU),
  [`gcp-failover`](scripts/hardware-test/gcp-failover) (two SEV-SNP VMs,
  intrusion → failover), [`gpu-exact`](scripts/hardware-test/gpu-exact)
  (where CPU↔GPU float divergence enters a real model). Each boots its own VMs
  and deletes them on exit, including on failure.
- **Supply chain** — reproducible builds, syft SBOM, cosign keyless signing,
  SLSA generic provenance, and a release workflow that refuses any tag not
  signed by a key pinned on the default branch.
- **`vault-gate`** — 18 CI sub-checks, eleven doctrine invariants asserted as
  tests, and a coverage ratchet whose floors only rise.
- `acp-demo` — the cross-hardware regeneration demonstration in one command, no
  cloud and no TEE hardware required.

### Known limits at 0.1.0

Measured at 0.5B scale on CPU TEEs only; no attested GPU destinations; SEV-SNP
only (no TDX, Nitro or SGX verifier); `acp-compute`'s reconstruction backend is
a labelled placeholder; receive-side self-bootstrapping deferred to V2; no
external security review. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) and
[What we do not claim](VERIFIABLE-CLAIMS.md#what-we-do-not-claim).

[Unreleased]: https://github.com/vault-genome/vaultgenome-core/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vault-genome/vaultgenome-core/releases/tag/v0.1.0
