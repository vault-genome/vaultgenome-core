# The reference deployment: a signed release on real SEV-SNP

What an operator who downloads a release of Vault Genome does, done end to
end and recorded, so that a first deployment has something to be compared
with. One command on a laptop with `gh`, `cosign`, `slsa-verifier`, `go`,
GNU tar and GNU gzip (`gtar` and `gzip` from Homebrew on macOS) and
`gcloud`:

```bash
./scripts/hardware-test/release-deploy/run.sh <gcp-project> v0.7.0
```

It takes about fifteen minutes and one `n2d-standard-4` Confidential VM,
created and deleted by the run.

## What the run does

1. **Downloads the release's assets** — the five binaries, from 0.8.0
   their `-fips` variants on the certified module (ADR 0030), from 0.12.0
   `acpctl` and `acp-keygen` for the five other platforms
   (`<tool>-<os>-<arch>`), the Python distribution (the wheel and the
   sdist) and the signed checksums list, and the worker package, their
   keyless cosign signatures and certificates, the SBOMs with theirs, and
   the SLSA provenance — and **verifies every one** before anything runs:
   from 0.12.0 `sha256sum -c` of every artifact against the signed list
   first; `cosign verify-blob` against the release workflow's identity
   and the GitHub OIDC issuer (twelve signatures; twenty-two from 0.8.0;
   forty-seven from 0.12.0), `slsa-verifier verify-artifact` against the
   source repository and the tag (six artifacts; eleven from 0.8.0;
   twenty-four from 0.12.0), and
   the tag's own signature against the keys pinned on `main`
   (`.github/allowed_signers`). A signature that does not verify stops
   the run. From 0.4.3 the release carries a Sigstore bundle beside each
   pair, and the kit verifies the same files from their bundles with the
   Sigstore trust root as a file (`--trusted-root`, the file from `cosign
   initialize`'s cache) and, on macOS, the network denied to cosign — the
   check an air-gapped site runs. (A release before 0.4.2 has four
   binaries and no package: eight signatures, four provenances, and the
   pieces below from the tag's source — the record of `v0.4.1` says so.)
2. **Rebuilds every released binary (the five; the `-fips` five from 0.8.0; the ten cross builds from 0.12.0), the worker package and, from 0.12.0, the Python distribution from the tag** with
   the inputs `release.yml` uses (the tag as VERSION, the commit as COMMIT,
   its time as SOURCE_DATE_EPOCH, CGO off, linux/amd64 — the cross builds
   name their own GOOS/GOARCH in the Makefile; the wheel and the sdist by
   the tag's `scripts/build_python_dist.sh`, twice, from the hash-pinned
   build tools; GNU tar with sorted
   names, numeric owner 0 and that time as every mtime, GNU gzip without a
   name or a timestamp) and requires every rebuilt artifact's SHA-256 to
   equal the released file's — the release procedure's §5.4, done by the
   kit rather than by hand. The gzip must be GNU's: the rehearsal of 0.4.2
   repacked the package on macOS with Apple's gzip and got an identical
   tar inside a different file; the kit stops before the rebuild when the
   gzip it finds is not GNU's.
3. Uploads **only release assets** to the guest: the released `sagvd`,
   `acp-compute`, `acpctl`, `acp-keygen` and the worker package. The AMD
   Milan chain is fetched on the guest by the released `acpctl` from AMD
   KDS and verified against the roots the binary pins (ADR 0024). Nothing
   comes from this tree.
4. Runs the **same guest script as `gcp-sev-snp/returnpath-e2e`** on a fresh
   SEV-SNP VM, with the released `sagvd`, `acp-compute` and `acpctl`: both
   daemons attest with the chip and pin each other's launch measurement; a
   rogue worker (same certificate and sealing key, a simulated TEE instead
   of the chip) is refused at the handshake; the pinned worker is admitted
   and its Evidence verified to AMD's root; a gate job goes over the Return
   Path, the worker restores the model in memory through the door and
   answers, `sagvd` judges and signs the verdict; `acpctl audit verify`
   verifies the log under the key `sagvd identity` published.
5. Decodes the results from the serial console and deletes the VM and the
   bucket — always, also on failure.

The record is staged under the run's work directory and published into
`evidence/` by one move at the end, so a directory under `evidence/` is a
finished record and never a run in flight; a run that stops early keeps
its stage beside the raw capture, outside the tree
(`~/.cache/vaultgenome/release-deploy/failed-<stamp>`, or under `VG_E2E_RAW_DIR`).
Each run has a TUF cache of its own (`TUF_ROOT`), initialized once with
retries, and the online `cosign` and `slsa-verifier` calls are retried on
a transient error: on 2026-10-21, against `v0.8.0`, a `verify-blob`
failed on "failed to create TUF client" while another kit initialized the
shared cache beside it, and a run's stage under `evidence/` was removed
by hand because it looked like a finished record.

## What a run leaves

```
evidence/<STAMP>/
├── verify/
│   ├── assets.sha256        every downloaded file, hashed
│   ├── cosign.txt           twelve "Verified OK" (eight before 0.4.2)
│   ├── slsa.txt             six "PASSED: SLSA verification passed" (four before 0.4.2)
│   ├── tag.txt              the tag's signature, the key that made it
│   ├── rebuild.txt          every rebuilt hash equal to the released file's
│   ├── uploaded.sha256      what went to the VM: release assets only
│   └── tools.txt            the tool versions, the tag, the time
├── serial-console.txt       the guest's output as captured
└── results/                 the guest's record (as returnpath-e2e/README.md describes it):
    reports, identities, the rogue refusal, the job's verdict, the audit log and its verification
```

Keys, seeds, tokens and configs stay on the VM and die with it; the record
holds reports, decisions and logs only.

## Runs

| Release | Evidence | Outcome |
|---|---|---|
| `v0.4.0` | [`evidence/20261015T012735Z/`](evidence/20261015T012735Z/) | 8 signatures, 4 provenances and the tag verified; both daemons attested with the chip; the rogue worker refused; the gate job EXACT 6/6; the audit log verified (17 events). 99 s on the guest. |
| `v0.4.1` | [`evidence/20261015T014459Z/`](evidence/20261015T014459Z/) | 8 signatures, 4 provenances and the tag verified; the four binaries rebuilt from the tag on another machine with the same sha256 as the released files; both daemons attested with the chip; the rogue worker refused; the gate job EXACT 6/6; the audit log verified (17 events). 101 s on the guest; three minutes after the release was published. |
| `v0.4.2` | [`evidence/20261015T170743Z/`](evidence/20261015T170743Z/) | The first record with nothing from the source tree: 12 signatures, 6 provenances and the tag verified; the five binaries and the worker package rebuilt from the tag on another machine (GNU tar, GNU gzip) with the same sha256 as the released files; only release assets uploaded, the AMD Milan chain fetched on the guest by the released `acpctl` and checked against the pinned ARK-Milan (`results/amd-chain.txt`); the released `acp-keygen` provisioned the keys; both daemons attested with the chip; the rogue worker refused; the gate job EXACT 6/6; the audit log verified (17 events). 103 s on the guest; three minutes after the release was published. |
| `v0.4.3` | [`evidence/20261016T001614Z/`](evidence/20261016T001614Z/) | The first record of a release with a Sigstore bundle beside every signature: 49 assets; 12 signatures, 12 bundles verified with a trusted-root file and the network denied to cosign, 6 provenances and the tag verified; the five binaries and the worker package rebuilt from the tag with the same sha256 as the released files; only release assets uploaded, the AMD chain fetched on the guest by the released `acpctl` and checked against the pinned ARK-Milan; the released `acp-keygen` provisioned the keys; both daemons took their family from the kernel (`tee.provider: "auto"`), attested with the chip and sealed their key files to it; the thief with the sealed files refused before any key is read, the unpinned worker at the handshake; the gate job EXACT 6/6; the audit log verified (17 events). 125 s on the guest; two and a half minutes after the release was published. |
| `v0.5.0` | [`evidence/20261016T232117Z/`](evidence/20261016T232117Z/) | 49 assets; the twelve pairs and the twelve bundles verified (the bundles with `--trusted-root` and the network denied), six provenances and the tag; the five binaries and the package rebuilt from the tag byte for byte; the guest from release assets alone — `tee.provider: "auto"`, the key files sealed to the chip, the thief with the sealed files and the unpinned worker both refused, the gate job EXACT, the audit log verified (17 events); 127.5 s on the guest. The kit ran two minutes after the release was published. |
| `v0.6.0` | [`evidence/20261017T041506Z/`](evidence/20261017T041506Z/) | 49 assets; the twelve pairs and the twelve bundles verified (the bundles with `--trusted-root` and the network denied), six provenances and the tag; the five binaries and the package rebuilt from the tag byte for byte; the guest from release assets alone — `tee.provider: "auto"`, the key files sealed to the chip, the thief with the sealed files and the unpinned worker both refused, the gate job EXACT, the audit log verified (17 events); 120.7 s on the guest. The kit ran two and a half minutes after the release was published. |
| `v0.6.1` | [`evidence/20261021T132732Z/`](evidence/20261021T132732Z/) | 55 assets — the six of the images job among them; the twelve pairs and the twelve bundles verified (the bundles with `--trusted-root` and the network denied), six provenances and the tag; the five binaries and the package rebuilt from the tag byte for byte (go1.27.3); the guest from release assets alone — the key files sealed to the chip, the thief with the sealed files and the unpinned worker both refused, the gate job EXACT, the audit log verified (17 events); 128.4 s on the guest. The kit ran six minutes after the release was published; the images kit deployed the same release's images in the same minutes (`../release-deploy-images/evidence/20261021T132958Z/`). |
| `v0.7.0` | [`evidence/20261021T164732Z/`](evidence/20261021T164732Z/) | 55 assets; the twelve pairs and the twelve bundles verified (the bundles with `--trusted-root` and the network denied), six provenances and the tag; the five binaries and the package rebuilt from the tag byte for byte (go1.27.3); the guest from release assets alone — the key files sealed to the chip, the thief with the sealed files and the unpinned worker both refused, the gate job EXACT, the audit log verified (18 events — the 18th a handshake that failed as sagvd stopped, on the record as a refusal); 133.2 s on the guest. The kit ran ten minutes after the release was published; the images kit deployed the same release's images in the same minutes (`../release-deploy-images/evidence/20261021T164959Z/`), and the key-release kit ran the binaries of the tag's commit under the `fips` profile (`../gcp-sev-snp/keyrelease-e2e/evidence/20261021T164918Z/`). |
| `v0.8.0-rc1` (rehearsal, ADR 0030 part three) | [`evidence/20261021T223719Z/`](evidence/20261021T223719Z/) | 97 assets; the twenty-two pairs and the twenty-two bundles verified (the bundles with `--trusted-root` and the network denied), eleven provenances and the tag; the five binaries, their five `-fips` variants and the package rebuilt from the tag byte for byte (go1.27.3, on a Darwin arm64 host for linux/amd64 — the `-fips` builds on the certified module reproduce across hosts like the others); the guest from release assets alone — the key files sealed to the chip, both rogues refused, the gate job EXACT, the audit log verified (17 events); 128.1 s on the guest. The kit's first run against this tag stopped on its own count of signature pairs (still twelve while it verified twenty-two); the count follows the artifact count since. |
| `v0.8.0` | [`evidence/20261021T233121Z/`](evidence/20261021T233121Z/) | 97 assets; the twenty-two pairs and the twenty-two bundles verified (the bundles with `--trusted-root` and the network denied), eleven provenances and the tag; the five binaries, their five `-fips` variants and the package rebuilt from the tag byte for byte (go1.27.3, on Darwin arm64 for linux/amd64); the guest from release assets alone — the released daemons reporting `v0.8.0` at `20dc289`, the key files sealed to the chip, both rogues refused, the gate job EXACT, the audit log verified (17 events); 453.1 s on the guest, three kits sharing the project's quota in the same minutes. The kit ran eight minutes after the release was published; the images kit and the key-release kit under `fips` with `VG_FIPS=1` ran against the same release (their records in `../release-deploy-images/` and `../gcp-sev-snp/keyrelease-e2e/`). |
| `v0.8.0`, the kit's own proof | [`evidence/20261022T001053Z/`](evidence/20261022T001053Z/) | The run that proves the kit's changes of 2026-10-22: three kits in the same minutes against the published `v0.8.0` — this one, the images kit and the key-release kit — from a tree whose tracked files were clean while their records appeared beside the build. 97 assets, the twenty-two pairs and bundles, eleven provenances and the tag; the ten binaries and the package rebuilt byte for byte; the record staged under the run's work directory and published by one move; no retry needed; the guest's gate EXACT, 17 events; 714.9 s on the guest, three guests sharing the project's quota. |
| `v0.9.0` | [`evidence/20261022T154611Z/`](evidence/20261022T154611Z/) | 97 assets; the twenty-two pairs and the twenty-two bundles verified (the bundles with `--trusted-root` and the network denied), eleven provenances and the tag; the five binaries, their five `-fips` variants and the package rebuilt from the tag byte for byte (go1.27.3, on Darwin arm64 for linux/amd64); the guest from release assets alone — the released daemons reporting `v0.9.0` at `0428a5a`, the key files sealed to the chip, both rogues refused, the gate job EXACT, the audit log verified (17 events); 287.8 s on the guest. The kit ran eight minutes after the release was published; the images kit and the key-release kit under `fips` with `VG_FIPS=1` and `VG_SIGSUITE=ecdsa-p384-sha384` ran against the same release (their records in `../release-deploy-images/` and `../gcp-sev-snp/keyrelease-e2e/`). |
| `v0.10.0` | [`evidence/20261023T201852Z/`](evidence/20261023T201852Z/) | 97 assets; the twenty-two pairs and the twenty-two bundles verified (the bundles with `--trusted-root` and the network denied), eleven provenances and the tag; the five binaries, their five `-fips` variants and the package rebuilt from the tag byte for byte (go1.27.3, on Darwin arm64 for linux/amd64); the guest from release assets alone — the released daemons reporting `v0.10.0` at `84cc9b9`, the key files sealed to the chip, both rogues refused, the gate job EXACT, the audit log verified (17 events); 177.6 s on the guest. The kit ran 8 minutes after the release was published; the images kit and the key-release kit under `fips` with `VG_FIPS=1` and `VG_SIGSUITE=ecdsa-p384-sha384` ran against the same release (their records in `../release-deploy-images/` and `../gcp-sev-snp/keyrelease-e2e/`). |
| `v0.11.0` | [`evidence/20261024T185656Z/`](evidence/20261024T185656Z/) | 97 assets; the twenty-two pairs and the twenty-two bundles verified (the bundles with `--trusted-root` and the network denied), eleven provenances and the tag; the five binaries, their five `-fips` variants and the package rebuilt from the tag byte for byte (go1.27.3, on Darwin arm64 for linux/amd64); the guest from release assets alone — the released daemons reporting `v0.11.0` at `162835d`, the key files sealed to the chip, both rogues refused, the gate job EXACT, the audit log verified (17 events); 124.2 s on the guest. The kit ran 6 minutes after the release was published; the images kit and the key-release kit under `fips` with `VG_FIPS=1` and `VG_SIGSUITE=ecdsa-p384-sha384` ran against the same release (their records in `../release-deploy-images/` and `../gcp-sev-snp/keyrelease-e2e/`). |
| `v0.12.0-rc1` (rehearsal: the tools for the other platforms, the checksums list, the Python distribution) | [`evidence/20261028T020143Z/`](evidence/20261028T020143Z/) | 197 assets; `sha256sum -c` of the signed list first — 23 of 23 files; the forty-seven pairs and the forty-seven bundles verified (the bundles with `--trusted-root` and the network denied), twenty-four provenances and the tag; the twenty binaries, the package, the wheel and the sdist rebuilt from the tag byte for byte (go1.27.3 and Python 3.12.2 on Darwin arm64, each cross build for its own platform); the guest from release assets alone — the released daemons reporting `v0.12.0-rc1` at `9d51661b`, the key files sealed to the chip, both rogues refused, the gate job EXACT, the audit log verified (17 events); 124.4 s on the guest. The kit ran 10 minutes after the rehearsal's release was published; the images kit ran against the same rehearsal (its record in `../release-deploy-images/`). |
| `v0.12.0` | [`evidence/20261028T024858Z/`](evidence/20261028T024858Z/) | 197 assets; `sha256sum -c` of the signed list first — 23 of 23 files; the forty-seven pairs and the forty-seven bundles verified (the bundles with `--trusted-root` and the network denied), twenty-four provenances and the tag; the twenty binaries, the package, the wheel and the sdist rebuilt from the tag byte for byte (go1.27.3 and Python 3.12.2 on Darwin arm64, each cross build for its own platform); the guest from release assets alone — the released daemons reporting `v0.12.0` at `ed9f6d35`, the key files sealed to the chip, both rogues refused, the gate job EXACT, the audit log verified (17 events); 127.8 s on the guest. The kit ran 9 minutes after the release was published; the images kit and the key-release kit under `fips` with `VG_FIPS=1` and `VG_SIGSUITE=ecdsa-p384-sha384` ran against the same release (their records in `../release-deploy-images/` and `../gcp-sev-snp/keyrelease-e2e/`). |
