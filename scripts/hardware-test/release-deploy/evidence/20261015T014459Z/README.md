# The v0.4.1 release deployed from its signed assets — 2026-10-15

The post-release verification of `v0.4.1` (release procedure §5), done by
the kit within three minutes of the release being published, and the
reference deployment from those assets. One `n2d-standard-4` SEV-SNP
Confidential VM (AMD Milan) in `us-central1-c`, Ubuntu 24.04, created at
01:45Z and deleted by the run at 01:49Z.

**Verified before anything ran** (`verify/`):

- `assets.sha256`: the 25 release assets as downloaded.
- `cosign.txt`: eight signatures "Verified OK" — four binaries, four SBOMs —
  against the release workflow's identity and the GitHub Actions OIDC
  issuer (cosign v3.1.3).
- `slsa.txt`: four "PASSED: SLSA verification passed" against
  `github.com/vault-genome/vaultgenome-core` at tag `v0.4.1`
  (slsa-verifier 2.7.1).
- `tag.txt`: the tag's signature — `Good "git" signature` with the ED25519
  key pinned in `.github/allowed_signers`.
- `rebuild.txt`: the four binaries rebuilt from the tag (commit
  `09bb0999cff2`) on a different machine — go1.27.2 on Darwin arm64,
  cross-compiled for linux/amd64 with the inputs `release.yml` uses — and
  **every rebuilt sha256 equals the released file's**: `sagvd`
  `31fc5af2…`, `acp-compute` `e115aab3…`, `acpctl` `1ca10cfb…`,
  `acp-bootstrap` `2ac2fb38…`.
- `uploaded.sha256`: what went to the VM — the released `sagvd`,
  `acp-compute` and `acpctl`, plus `keygen`, the worker package and the AMD
  Milan chain from the tag's source (`tools.txt`).

**What the VM did** (`results/`; `serial-console.txt` is the console as
captured):

- `versions.txt`: `sagvd v0.4.1`, `acp-compute v0.4.1`, `acpctl v0.4.1`, all
  at commit `09bb0999cff2` — the released binaries report the tag.
- both daemons read the launch measurement from the chip and pinned each
  other's (`steps.txt`, the identity files); the worker fine-tuned a tiny
  model (9.5 s) and acpctl sealed the genome (key id
  `genome-2aba341da0b3-g0-…`);
- `rogue-worker.log`: the simulated-TEE worker refused at the Return Path
  handshake after 1 s;
- `job.json`: the gate job over the Return Path: `succeeded`,
  `release_authorized`, gate level **EXACT** at rung 0, 6 of 6 fixtures,
  `max_abs_err` 0, verdict signed by `sagvd-authority-e2e`; 5.2 s from
  submission to the sealed audit event;
- `audit-verify.json`: `ok: true`, 17 events, tip `3f2be565…`, verified
  under the published key; `audit-events.jsonl`: every decision in order;
- `timeline.txt`: runtime install 80 s, fine-tune 9.5 s, job 5.2 s; the guest
  script 100.6 s.

Keys, seeds, tokens and configs stayed on the VM and died with it.
