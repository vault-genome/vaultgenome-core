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

- **A bfloat16 tolerance the operator signs for.** `sagvd`'s
  `genome.gate.bfloat16 {atol, rtol}` is the tolerance a genome whose
  recipe computed in bfloat16 is held to — chosen by the genome's
  `recipe.dtype`, part of the policy version every session is pinned to,
  absent by default (a bfloat16 genome is then held to the float32
  tolerance, as before). `internal/genome/lora` reads the recipe's
  `device` and `dtype`.
- **The vTPM's boot, pinned; a destination by IP, named.** An `azure-cgpu`
  peer or registry entry takes `pcr_digests` — the digest over the quoted
  PCRs, printed by `identity` as `vtpm.pcr_digest_hex` — so what the vTPM
  measured of the boot is policed and not only recorded; the transport TLS
  client takes `server_name` for a destination whose certificate does not
  name the host of its URL.
- **A confidential GPU worker on Azure**
  ([ADR-0019](docs/adr/0019-a-confidential-gpu-worker-on-azure.md)) —
  `tee.provider: "azure-cgpu"` for `sagvd`, `acp-compute` and
  `acp-bootstrap`, `azure-cgpu` peers and verifier-registry entries. On an
  Azure NCC H100 v5 (AMD SEV-SNP under the paravisor, an H100 in
  confidential-computing mode) the producer reads the SEV-SNP report from
  the vTPM's HCL report, quotes the PCRs with the vTPM's attestation key
  and `SHA-256(nonce)` in `extraData` (tpm2-tools), and runs
  `gpu_attest_command` for NVIDIA's signed attestation tokens under the same
  value; the verifier takes the report to AMD for the chip's product
  (Genoa), checks `REPORT_DATA` names the runtime data and the quote
  verifies under the key it carries, verifies NVIDIA's tokens ES384 under
  NVIDIA's key set (`nras_jwks_url`, `nras_cache_dir`) and applies
  `gpu_policy` (secure boot, no debug, signed manifests, matched
  measurements, pinned model/driver/VBIOS). No sealer.
  `scripts/hardware-test/azure-cgpu/` captures a genuine machine and runs
  the Return Path on it with the 7B genome on the H100 (VERIFIABLE-CLAIMS
  C17). AMD KDS fetches are product-aware (`realAMDKDSGetVCEKFor`).
- **The recipe names its device and dtype** — `python -m vg_genome finetune
  --device cuda --dtype bfloat16` trains the adapter on a GPU with the base
  in bfloat16 (the adapter stays float32, and so does every measurement);
  the genome's recipe records `device` and `dtype`, the fixtures are recorded
  on the device that trained, and the door, `measure` and `replay` restore the
  base in the recipe's dtype (`--dtype` overrides it for a measurement off
  the pinned runtime). A genome that predates the fields restores in float32.
  `scripts/hardware-test/gpu-7b/` takes Qwen2.5-7B-Instruct through the
  genome path on one NVIDIA L4 (run `20260916T043622Z`: a 10 MB genome,
  EXACT on the pinned GPU, the recipe replaying bit for bit, and the float
  door failing closed across devices in bfloat16 while the answers stay the
  same — VERIFIABLE-CLAIMS C16, KNOWN_ISSUES #13).
- **Intel TDX on the Return Path**
  ([ADR-0018](docs/adr/0018-intel-tdx-on-the-return-path.md)) —
  `tee.provider: "gcp-tdx"` for `sagvd`, `acp-compute` and `acp-bootstrap`,
  `tee.peer.provider: "gcp-tdx"` and `gcp-tdx` entries in the cross-cloud
  verifier registry. The producer quotes through configfs-tsm (`tdx_guest`)
  with the challenge in REPORTDATA and reports as its 48-byte measurement the
  SHA-384 of MRTD and RTMR0..3. The verifier chains the quote's PCK
  certificates to the pinned Intel SGX Root CA, checks the attestation key's
  and the PCK leaf's signatures and the QE report's binding of the key,
  fetches Intel's TCB info and QE identity from Intel PCS (`pcs_url`;
  `pcs_cache_dir` keeps them between runs) and verifies their signatures
  before reading them, evaluates the platform, TDX-module and QE TCB
  statuses (`acceptable_tcb_statuses`: `UpToDate` by default, hardening
  statuses by choice, `OutOfDate` and `Revoked` never), refuses a debuggable
  TD, binds the nonce and pins the measurement. No TDX sealer: an escrow key
  cannot be sealed to a TDX host. `sagvd identity` and `acp-compute
  identity` print the MRTD and RTMRs a TDX measurement is made of.
  `scripts/hardware-test/gcp-tdx/capture/` holds a genuine c3 quote with
  Intel's documents, which the verifier's tests run against;
  `scripts/hardware-test/gcp-tdx/returnpath-e2e/` runs both daemons on one
  Trust Domain.
- **The escrow key is sealed to the release host's TEE**
  ([ADR-0016](docs/adr/0016-escrow-key-sealed-to-the-release-host.md)) —
  the SEV-SNP sealer is real: a key the firmware derives for this chip,
  launch measurement and guest policy (`SNP_GET_DERIVED_KEY` on
  `/dev/sev-guest`, pure Go), expanded with a label of its own, AES-256-GCM,
  derived for every call and never stored. `sagvd escrow-provision` makes
  the authority's escrow key inside its own process and writes it only
  sealed (`vault-genome/sealed-escrow-key/v1`), with `-recovery-to` wrapped
  to the operator's recovery key (`vault-genome/escrow-recovery/v1`); `-stdin`
  re-seals a recovered key on a new host. `acpctl escrow recovery-keygen`
  and `acpctl escrow recover` are the operator's side. `sagvd` unseals the
  key in memory at start and refuses a plaintext `key_escrow_path` on a
  hardware TEE; `sagvd identity` prints `key_escrow_storage`. Config:
  `tee.sev_guest_device`.
- **Limits on the primary's word**
  ([ADR-0017](docs/adr/0017-limits-on-the-primarys-word.md)) — the sentinel
  attests every record it writes with the primary's TEE
  (`acpctl sentinel watch --tee`, records carry `attestation`), and
  `acpctl sentinel identity` prints what the operator pins. The failover
  policy pins the primary (`primary.kind`, `primary.measurements`,
  `primary.attestor_public_key` for a simulated one; `acpctl failover issue
  --primary-kind --primary-measurement --primary-attestor-pub`): a record
  without a verifying report at a pinned measurement is ignored, so a stolen
  seed off the chip is silence. `triggers.stopped_grace_seconds`
  (`--stopped-grace`) bounds how long `stopped` stands the authority down;
  overdue, it is the trigger `stopped-overdue`. The executor restores
  nothing past the generation the trigger's record names and declines an
  outbox that contradicts it. `FAILOVER_DECIDED` and the report carry
  `primary_measurement_hex`; the report lists `ignored` records.
- The failover drill kit (`scripts/hardware-test/gcp-failover`) runs the
  authority on SEV-SNP with its escrow key sealed to the chip, the recovery
  ceremony, the primary attesting with its chip, and a rogue sentinel with
  the stolen seed on the standby's chip, declined.
- **One binary drives the nine stages**
  ([ADR-0015](docs/adr/0015-one-binary-drives-the-nine-stages.md)) — `sagvd`
  takes every gate job through the flow with the library's own
  decision-makers: `intake` (a RecoveryRequest, admitted once), `trust`
  (the operator's stop list, the policy profile, the attested worker →
  a signed `AttestationResult`), the session issuer, the staged disclosure
  sequencer (the genome's model side sealed to the session, one signed
  envelope per component), a signed `ReconstructionJobManifest`, the
  candidate, the validation service (six operational sub-checks over the
  job's own artifacts, plus the gate on two dimensions — top-1 agreement
  and the determinism ladder), and a signed `ReleaseDecision` citing its
  `RELEASE_DECIDED` event; a refusal closes the session through the
  incident service. `orchestration.Authority`/`Flow`/`Machine` drive it;
  every transition is the table's. `GET /v1/jobs/{id}` shows the flow's
  state, transitions and signed artifacts; `POST /v1/jobs` accepts
  `request_id`, `policy_profile`, `requester_identity`, `contour` and
  returns `request_id` and `state`. Config: `operator_stop` (the stop list
  trust consults for gate jobs), `runtime.evidence_max_age_seconds`;
  `sagvd identity` prints `policy_version` and `policy_profiles`; metric
  `sagvd_release_decisions_total{decision}`.
- `internal/validation/equivalence.Top1Agreement` — the semantic question
  a restored model can answer: the same top-1 at every reference position.
- **The Return Path on the record, and on hardware**
  ([ADR-0014](docs/adr/0014-return-path-on-the-record-and-on-hardware.md)) —
  `sagvd` keeps a Return Path audit log (`audit.log_path`, signed with
  `keys.audit_signing`, verified end to end at start, required with gate
  jobs): a job accepted, a peer refused or a worker admitted, a candidate
  received, the gate's dimensions, findings and verdict, a session ended —
  each on the record **before** it takes effect, and a log that cannot take
  the record stops the decision (`audit_unavailable`). Existing audit kinds,
  no schema bump; payloads `vault-genome/returnpath-audit/v1`;
  `acpctl audit verify` checks the log under the key `sagvd identity`
  prints; `sagvd_audit_events_total{kind}`. `sagvd` and `acp-compute` attest
  with AMD SEV-SNP (`tee.provider: "gcp-sev-snp"`, reports through
  configfs-tsm) and pin a SEV-SNP peer by its 48-byte launch measurement and
  the AMD chain (`tee.peer.provider`, `amd_cert_chain_path`, `vcek_cache_dir`,
  `amd_kds_url`, `min_reported_tcb`); the simulated backend stays, explicit.
  `acp-compute identity` prints the worker's signing key, provider and
  measurement. Run on a GCP SEV-SNP Confidential VM with the shipping
  binaries and the real `vg_genome` door
  (`scripts/hardware-test/gcp-sev-snp/returnpath-e2e/`).
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

### Fixed

- **`sagvd`'s verifier registry takes `azure-cgpu` entries.** ADR 0019 and
  its runbook said it did; the loader had no case and refused the
  provider. It takes the AMD fields (the Genoa chain), `nras_jwks_url`,
  `nras_cache_dir`, `gpu_policy` and `pcr_digests` now.

- **No test is skipped.** The eight `t.Skip("KNOWN: …")` tests run again,
  each for its real reason (KNOWN_ISSUES, "The eight that were skipped"):
  the in-memory witness log stamped every signed tree head with its clock,
  so a log whose entries carried timestamps ahead of the clock issued heads
  that predated what they covered and its own receipts failed the receipt
  contract — a head is now stamped no earlier than the newest entry it
  covers; `ContinuityProof.Verify(nil)` dereferenced the nil resolver — every
  contract's `VerifySignature` now refuses a nil resolver as Structural;
  the witness fixtures stamped heads before the entries they covered; and
  the tampered-STH test tampers as an adversary would, with the all-zero
  hash named as the Structural refusal the shape rules make it.

### Changed

- **The documents say what is shipped.** Where the operator runbooks, the
  threat model, the positioning matrix, the supply-chain and compliance
  documents and the reference designs still said "Phase 2", "scaffolding"
  or "simulated only" of things that have since run on hardware — the
  SEV-SNP sealer, the three hardware backends, SBOM and cosign in the
  release, CodeQL and Semgrep in CI, `acpctl lineage` — they now say what
  is, with pointers to the evidence; what is still not done (Nitro, SGX,
  hermetic builds, two-party review, a pen-test, fuzzing) says so.

- `key_escrow_path` (`genome`, `crosscloud`) names the sealed escrow key
  `sagvd escrow-provision` writes; a raw 32-byte key from
  `acpctl escrow keygen` is accepted under `tee.insecure_simulation` only.
- `sagvd failover` loads the authority's keys, the escrow key among them,
  before it watches, so a key that will not open on this host is known
  before any trigger.
- The executor's choice of genome is bounded by the trigger record's last
  word (ADR 0017): generations after it are set aside.
- `acpctl recover` takes the 48-byte SEV-SNP launch measurement for a
  `gcp-sev-snp` envelope, as the chip reports it (it demanded 32 bytes).

- **`release_decision` is schema v2:** `ReasonTrustDenied` and an
  `attestation_id` field, so a denial at Trust Admission is a signed,
  recorded decision without a session. A v1 decision is a valid v2 decision.
- **`validation/service` records evaluated dimensions:**
  `ValidateInputs.Evaluated` carries semantic and behavioral verdicts from an
  evaluator that ran the model, with its name and detail in the
  `VALIDATION_DIMENSION_EVALUATED` payload.
- **`POST /v1/jobs` returns `request_id` and `state`, not
  `manifest_id`/`session_id`:** the session and the manifest are issued when a
  worker is admitted, and the job view carries them then. The Return Path
  audit payloads of a gate job are the flow's (`vault-genome/orchestration-audit/v1`)
  and the services'; the daemon's own `returnpath-audit/v1` payloads remain
  for refusals before a flow exists.
- **`acpctl audit query --json` embeds each event's payload** (`payload`, or
  `payload_base64` when it is not JSON), so a reader sees the decision's
  fields without a second tool.
- **`sagvd` and `acp-compute` name their TEE.** `tee.provider` and
  `tee.peer.provider` default to `simulated`, which still needs
  `tee.insecure_simulation: true`; a SEV-SNP pin without the AMD chain, or a
  simulated pin with one, is refused at start.
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
