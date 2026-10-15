# The v0.4.0 release deployed from its signed assets — 2026-10-15

The first run of this kit, against the release that existed when the kit was
written: `v0.4.0` (tag commit `4a4f3f2a760c`). One `n2d-standard-4` SEV-SNP
Confidential VM (AMD Milan) in `us-central1-c`, Ubuntu 24.04, created at
01:28Z and deleted by the run at 01:32Z.

**What was verified before anything ran** (`verify/`):

- `assets.sha256`: the 25 release assets as downloaded.
- `cosign.txt`: eight signatures "Verified OK" — the four binaries and the
  four SBOMs — against the identity
  `https://github.com/vault-genome/vaultgenome-core/.github/workflows/release.yml@refs/tags/v…`
  and the GitHub Actions OIDC issuer (cosign v3.1.3).
- `slsa.txt`: four "PASSED: SLSA verification passed" against
  `github.com/vault-genome/vaultgenome-core` at tag `v0.4.0`
  (slsa-verifier 2.7.1).
- `tag.txt`: the tag's signature — `Good "git" signature` with the ED25519
  key pinned in `.github/allowed_signers`.
- `uploaded.sha256`: what went to the VM — the released `sagvd`,
  `acp-compute` and `acpctl`, plus `keygen`, the worker package and the AMD
  Milan chain taken from the tag's source (`tools.txt`).

This run predates the kit's rebuild step (§5.4 of the release procedure);
later runs carry `rebuild.txt`.

**What the VM did** (`results/`, the record of `gcp-sev-snp/returnpath-e2e`'s
guest script; `serial-console.txt` is the console as captured):

- `versions.txt`: `sagvd v0.4.0`, `acp-compute v0.4.0`, `acpctl v0.4.0`,
  all at commit `4a4f3f2a760c` — the released binaries report the tag.
- `steps.txt`, `sagvd-identity.json`, `acp-compute-identity.json`: both
  daemons read the same launch measurement from the chip,
  `7dc7c12e…25acc` — the measurement the September runs of the same image
  recorded — and each pinned the other's.
- `finetune.json`, `seal.json`: the worker fine-tuned a tiny model on the
  guest (9.7 s) and acpctl sealed the genome (key id
  `genome-5098f827b856-g0-…`, key in a separate file).
- `rogue-worker.log`: a worker with the same certificate and sealing key
  but a simulated TEE (measurement `874a0079…`) was refused at the Return
  Path handshake after 1 s — the pinned identity is the chip's.
- `job.json`: the gate job over the Return Path from the pinned worker:
  status `succeeded`, state `release_authorized`, gate level **EXACT** at
  rung 0 (pinned replay), 6 of 6 fixtures exact, `max_abs_err` 0, the
  verdict signed by `sagvd-authority-e2e`; the nine-stage flow's steps
  with their times, 5.2 s from submission to the sealed audit event.
- `audit-verify.json`: `ok: true`, 17 events, tip `98f14858…`, verified
  under the key `sagvd identity` published (`audit-public-key.pem`);
  `audit-events.jsonl`: every decision in order, the rogue refusal among
  them.
- `timeline.txt`: runtime install 79 s (the pinned CPU torch), fine-tune
  10 s, job 5 s; the whole guest script 99.1 s.

Keys, seeds, tokens and configs stayed on the VM and died with it.
