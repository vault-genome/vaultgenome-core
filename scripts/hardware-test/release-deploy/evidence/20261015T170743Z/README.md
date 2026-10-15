# The v0.4.2 release deployed from its signed assets, nothing from the source tree — 2026-10-15

The post-release verification of `v0.4.2` (release procedure §5), done by
the kit three minutes after the release was published (17:04:38Z), and the
reference deployment from those assets alone. One `n2d-standard-4` SEV-SNP
Confidential VM (AMD Milan) in `us-central1-c`, Ubuntu 24.04, booted at
17:09Z and deleted by the run at 17:12Z. The first record in which the key
helper, the worker package and the AMD chain are the release's too: the
earlier runs (`v0.4.0`, `v0.4.1`) took those three from the tag's source.

**Verified before anything ran** (`verify/`):

- `assets.sha256`: the 37 release assets as downloaded — the five
  binaries, the worker package `genome-worker-v0.4.2.tar.gz`, their six
  SBOMs, a signature and a certificate for each of those twelve, and the
  SLSA provenance.
- `cosign.txt`: twelve signatures "Verified OK" — five binaries, the
  package, six SBOMs — against the release workflow's identity and the
  GitHub Actions OIDC issuer (cosign v3.1.3).
- `slsa.txt`: six "PASSED: SLSA verification passed" against
  `github.com/vault-genome/vaultgenome-core` at tag `v0.4.2`
  (slsa-verifier 2.7.1).
- `tag.txt`: the tag's signature — `Good "git" signature` with the ED25519
  key pinned in `.github/allowed_signers`.
- `rebuild.txt`: the five binaries and the package rebuilt from the tag
  (commit `9ca89dd945ec`) on a different machine — go1.27.2, GNU tar 1.35
  and GNU gzip 1.15 on Darwin arm64, cross-compiled for linux/amd64 with
  the inputs `release.yml` uses — and **every rebuilt sha256 equals the
  released file's**: `sagvd` `d0da5ce7…`, `acp-compute` `e3371cda…`,
  `acpctl` `bb33a615…`, `acp-bootstrap` `de87111c…`, `acp-keygen`
  `27d1a82c…`, the package `ad3bd979…`. (The rehearsal tag `v0.4.2-rc1`,
  on the same commit, had shown the package repacked with Apple's gzip to
  be a different file around an identical tar; GNU gzip reproduces it.)
- `uploaded.sha256`: what went to the VM — the released `sagvd`,
  `acp-compute`, `acpctl`, `acp-keygen` (as `keygen`) and the released
  package (as `genome-worker.tgz`), nothing else (`tools.txt`).

**What the VM did** (`results/`; `serial-console.txt` is the console as
captured):

- `amd-chain.txt`: the released `acpctl tee fetch-amd-chain --product
  milan` fetched the Milan chain from AMD KDS (4602 bytes) and checked its
  root against the ARK-Milan the binary pins, `69d063b4…a540bcd` (ADR 0024).
- `versions.txt`: `sagvd v0.4.2`, `acp-compute v0.4.2`, `acpctl v0.4.2`,
  `acp-keygen v0.4.2`, all at commit `9ca89dd945ec` — the released binaries
  report the tag.
- the released `acp-keygen -private` provisioned the key material; both
  daemons read the launch measurement `7dc7c12e…25acc` from the chip and
  pinned each other's (`steps.txt`, the identity files); the worker
  fine-tuned a tiny model (10.0 s) and acpctl sealed the genome (key id
  `genome-687d6064749f-g0-…`);
- `rogue-worker.log`: the simulated-TEE worker refused at the Return Path
  handshake after 1 s (`sagvd return-path handshake failed` at 17:11:19Z
  in `sagvd.log`);
- `job.json`: the gate job over the Return Path: `succeeded`,
  `release_authorized`, gate level **EXACT** at rung 0, 6 of 6 fixtures,
  `max_abs_err` 0, verdict signed by `sagvd-authority-e2e`; 5.2 s from
  submission to the sealed audit event;
- `audit-verify.json`: `ok: true`, 17 events, tip `d5279dd2…`, verified
  under the published key; `audit-events.jsonl`: every decision in order;
- `timeline.txt`: the runtime from the hash-pinned locks 84 s
  (`pip-requirements.log`, `pip-torch.log`: torch 2.14.1+cpu, transformers
  5.19.0), fine-tune 10.0 s, job 5.2 s; the guest script 103.3 s.

Keys, seeds, tokens and configs stayed on the VM and died with it.
