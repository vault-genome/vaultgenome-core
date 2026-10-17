# The v0.6.0 release deployed from its signed assets, nothing from the source tree — 2026-10-17

The post-release verification of `v0.6.0` (release procedure §5), done by
the kit two and a half minutes after the release was published
(04:12:43Z), and the reference deployment from those assets alone. One
`n2d-standard-4` SEV-SNP Confidential VM (AMD Milan) in `us-central1-c`,
Ubuntu 24.04, booted at 04:17Z and deleted by the run at 04:21Z.

**Verified before anything ran** (`verify/`, `verified at: 04:16:53Z`):

- `assets.sha256`: the 49 release assets as downloaded — the five
  binaries, the worker package `genome-worker-v0.6.0.tar.gz`, their six
  SBOMs, a signature, a certificate and a Sigstore bundle for each of
  those twelve, and the SLSA provenance.
- `cosign.txt`: twelve signatures "Verified OK" — the pairs, against the
  release workflow's identity and the GitHub Actions OIDC issuer (cosign
  v3.1.3, the machine's).
- `cosign-bundle-nonet.txt`: the same twelve files verified from their
  bundles — `cosign verify-blob --new-bundle-format --bundle
  <asset>.sigstore.json --trusted-root trusted_root.json` — with the
  network denied to the process (`sandbox-exec`, the TUF cache pointed
  nowhere); twelve "Verified OK". The trust root is the file `cosign
  initialize` cached on this machine (`cosign-initialize.txt`), SHA-256
  `6494e21e…bc0b66` (`tools.txt`) — the same bytes as for `v0.5.0`,
  `v0.4.3` and the rehearsal `v0.4.3-rc2`.
- `slsa.txt`: six "PASSED: SLSA verification passed" against
  `github.com/vault-genome/vaultgenome-core` at tag `v0.6.0`
  (slsa-verifier 2.7.1).
- `tag.txt`: the tag's signature — `Good "git" signature` with the ED25519
  key pinned in `.github/allowed_signers`.
- `rebuild.txt`: the five binaries and the package rebuilt from the tag
  (commit `cc8b204d7ba3`) on a different machine — go1.27.2, GNU tar 1.35
  and GNU gzip 1.15 on Darwin arm64, cross-compiled for linux/amd64 with
  the inputs `release.yml` uses — and **every rebuilt sha256 equals the
  released file's**: `sagvd` `0e07cc48…`, `acp-compute` `772c062f…`,
  `acpctl` `360c4c6e…`, `acp-bootstrap` `78c7d8bc…`, `acp-keygen`
  `8c40d22e…`, the package `19fed8f8…`.
- `uploaded.sha256`: what went to the VM — the released `sagvd`,
  `acp-compute`, `acpctl`, `acp-keygen` (as `keygen`) and the released
  package (as `genome-worker.tgz`), nothing else (`tools.txt`).

**What the VM did** (`results/`; `serial-console.txt` is the console as
captured). The guest script is the tree's Return Path kit of this day,
which seals both daemons' key files and tries two rogues:

- `amd-chain.txt`: the released `acpctl tee fetch-amd-chain --product
  milan` fetched the Milan chain from AMD KDS (4602 bytes) and checked its
  root against the ARK-Milan the binary pins, `69d063b4…a540bcd` (ADR 0024).
- `versions.txt`: `sagvd v0.6.0`, `acp-compute v0.6.0`, `acpctl v0.6.0`,
  `acp-keygen v0.6.0`, all at commit `cc8b204d7ba3` — the released binaries
  report the tag.
- the released `acp-keygen -private` provisioned the key material; both
  daemons, with `tee.provider: "auto"`, took their family from the kernel
  (`sev_guest` → `gcp-sev-snp`) and read the launch measurement
  `7dc7c12e…25acc` from the chip, pinning each other's; `seal-keys` sealed
  every key file to the chip (`sealed-files.txt`: seven files, `sealer:
  sev-snp-derived-key`; `seal-keys-*.json`); the worker fine-tuned a tiny
  model (8.3 s) and acpctl sealed the genome (key id
  `genome-02582f6c75c7-g0-…`);
- `rogue-sealed-worker.log`: a thief with the sealed key files and a
  simulated TEE refused before any key is read (`sealed to gcp-sev-snp,
  this host is simulated`); `rogue-worker.log`: the unpinned worker with
  plaintext copies refused at the Return Path handshake after 1 s
  (`sagvd return-path handshake failed` in `sagvd.log`);
- `job.json`: the gate job over the Return Path: `succeeded`,
  `release_authorized`, gate level **EXACT** at rung 0, 6 of 6 fixtures,
  `max_abs_err` 0, verdict signed by `sagvd-authority-e2e`; 4.2 s from
  submission to completion;
- `audit-verify.json`: `ok: true`, 17 events, tip `e9549c9d…`, verified
  under the published key; `audit-events.jsonl`: every decision in order;
- `timeline.txt`: the runtime from the hash-pinned locks 72 s
  (`pip-requirements.log`, `pip-torch.log`: torch 2.14.1+cpu, transformers
  5.19.0), fine-tune 8.3 s, the job 4.2 s; the guest script 120.7 s.

Keys, seeds, tokens and configs stayed on the VM and died with it;
`results/sha256sums.txt` covers the guest's files (39 of 39).
