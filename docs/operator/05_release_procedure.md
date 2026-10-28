# Release Procedure

**Audience:** release engineer, administrator.
**Purpose:** the procedure for cutting a signed release with supply-chain
evidence (SBOM + SLSA provenance + signed tag + cosign signatures), as
`.github/workflows/release.yml` implements it.

**What a release contains.** `release.yml` builds with `make build
build-fips build-cross` and signs, SBOMs and publishes: the five
operational binaries for Linux x86-64 — `sagvd`, `acp-compute`, `acpctl`,
`acp-bootstrap`, `acp-keygen` — and their `-fips` variants on the
certified module (ADR 0030); `acpctl` and `acp-keygen` for `linux-arm64`,
`darwin-amd64`, `darwin-arm64`, `windows-amd64` and `windows-arm64`
(`<tool>-<os>-<arch>`, `.exe` on Windows; the list lives in the Makefile,
`make -s cross-binaries` prints it); the worker package; the Python
distribution of `pyproject.toml` — the wheel and the sdist, which the
`pypi` job publishes to PyPI on a final tag; and `checksums-<tag>.txt`,
every artifact's SHA-256, signed like the rest. `acp-demo`, which `make
build` also builds, is not published.

**Related doctrine:** `docs/doctrine/ci-security-policy.md` §6 (supply-chain
attestation), invariant #11 "supply chain attested".

---

## 1. Prerequisites

Before any release step runs, the following must already be true:

1. The vault-gate workflow is green on the exact commit you intend to tag.
   CI runs all 18 checks on every push to `main`; `make vault-gate` runs 14 of
   them locally (see §2).
2. The release notes draft names every doctrine change, every invariant
   change, and every dependency change since the prior tag.
3. You hold a key that can sign the tag (`git tag -s`), and its public half is
   pinned on the default branch: an SSH key as a line of
   `.github/allowed_signers` (`<principal> ssh-ed25519 AAAA…`), or an OpenPGP
   key in `.github/release-signing-keys.asc`.

`release.yml` has no approval gate: pushing any tag that matches `v*.*.*`
starts it. Review happens before the tag, on the pull requests that land the
changes; who may push tags is a repository permission, not part of the
workflow.

---

## 2. Pre-release checklist

| Item | Command | Pass criterion |
| - | - | - |
| Clean working tree | `git status` | No uncommitted changes |
| Local gate green | `make vault-gate` | Exit 0, `vault-gate: PASS` |
| CI-only checks | `make test-integration && make verify-reproducible` | Both exit 0 (osv-scanner runs only in CI); `verify-reproducible` covers the default build and the FIPS build |
| The FIPS variant | `make build-fips && ./bin/sagvd-fips version` | `bin/<binary>-fips` present; the line ends `fips140=on module=v1.0.0 enforced=false` (ADR 0030; `go version -m bin/sagvd-fips` shows `GOFIPS140=v1.0.0-…`) |
| SBOM generable | `make sbom` | `dist/sbom.spdx.json` present, non-empty |
| Deps within policy | `make dep-allowlist && make dep-depth` | Both exit 0 |
| The Python distribution | `scripts/build_python_dist.sh dist` | "built twice … byte-identical"; the `version` in `pyproject.toml` is the tag without its `v` (the release job refuses otherwise; a rehearsal `vX.Y.Z-rcN` passes on `X.Y.Z`) |
| Doctrine clean | `make test-doctrine` | Every `TestInvariant_NN` passes, including `TestInvariant_11_SupplyChainAttested` |
| Runbook current | Review `docs/operator/` for drift from the code | Every command, flag and path named still exists |

---

## 3. Tagging

Tags are `vMAJOR.MINOR.PATCH` per the project's version scheme. For the
first MVP tag the sequence is:

```
git tag -s v0.1.0 -m "MVP — release-side doctrine-closed, 11/11 invariants enforced"
git push origin v0.1.0
# 0.2.0 followed the same steps on 2026-09-17 (tag message: the CHANGELOG's intro)
```

The workflow's first step after checkout runs `git verify-tag` on the tag and
stops the release if it fails, so an unsigned tag produces no release. The keys
it accepts are read from the default branch — `.github/allowed_signers` for SSH
signatures, `.github/release-signing-keys.asc` for OpenPGP — never from the
tagged tree, which whoever pushed the tag controls. A tag signed by any other
key produces no release either.

---

## 4. The release.yml workflow

The tag push runs `.github/workflows/release.yml`:

1. Check out the tag and run `git verify-tag` on it against the keys pinned on
   the default branch.
2. Set up Go 1.27.3 (the toolchain `go.mod` names).
3. `make build build-fips build-cross` and `make verify-reproducible`,
   with `VERSION` = the tag name, `COMMIT` = the full commit SHA and
   `SOURCE_DATE_EPOCH` = the tagged commit's timestamp. The `-fips`
   variants (ADR 0030) are the same five binaries built on the certified
   Go Cryptographic Module (`GOFIPS140=v1.0.0`, the version named, never
   an alias) from the same commit by the same reproducible build; the job
   refuses a `-fips` binary whose build settings do not name the module,
   and prints `sagvd-fips version` (`fips140=on module=v1.0.0`). The
   cross builds are `acpctl` and `acp-keygen` for the five other
   platforms, by the same flags; the job refuses one whose build settings
   do not name the platform in its file name.
4. Pack `workers/genome` as `genome-worker-<tag>.tar.gz` with GNU tar
   from the tagged commit's time (sorted names, numeric owner 0, `gzip
   -n`), twice, and compare; build the Python distribution twice from the
   hash-pinned tools of `python/requirements-build.lock`
   (`scripts/build_python_dist.sh`: the wheel, and the sdist repacked
   like the worker package) and compare, the `version` of
   `pyproject.toml` held to the tag; write `checksums-<tag>.txt`, the
   SHA-256 of every binary (the twenty), of the package, of the wheel and
   of the sdist in `sha256sum`'s format; `syft`: one SPDX-JSON SBOM per
   published binary, `dist/<binary>.sbom.spdx.json`, and one each for the
   package, the wheel and the sdist.
5. `cosign sign-blob` (keyless): a signature and certificate for each
   binary, for the package, the wheel, the sdist and the checksums list
   (`dist/<artifact>.sig`, `.cert`) and for each SBOM (`.sbom.sig`,
   `.sbom.cert`), and beside each pair the Sigstore bundle
   (`.sigstore.json`, the new bundle format: the signature, the
   certificate and the Rekor entry in one file, for verification with a
   trusted-root file and no route).
6. Upload the twenty binaries, the package, the wheel, the sdist, the
   checksums list, the SBOMs, signatures, certificates and bundles to the
   GitHub Release: 188 assets (88 before 0.12.0, 48 before 0.8.0). The
   release's notes say which file is for which machine.
7. A second job runs the SLSA generic generator
   (`slsa-framework/slsa-github-generator`, `generator_generic_slsa3.yml`
   v2.1.0) over the twenty binaries', the worker package's, the wheel's,
   the sdist's and the checksums list's SHA-256 and uploads the
   provenance to the release.
8. The `images` job takes `bin/sagvd`, `bin/acp-compute` and their `-fips`
   variants with their Sigstore bundles from the build job, verifies each
   binary under this workflow's identity on this tag before packing it,
   builds the four release images (`deploy/image/sagvd/Dockerfile` on
   distroless static, `deploy/image/acp-compute/Dockerfile` on python-slim
   with the worker's hash-locked runtime — nothing is compiled in either;
   the `-fips` images are the same Dockerfiles over the `-fips` binaries,
   the binary at the same path inside, so a `-fips` image is a drop-in),
   pushes them to `ghcr.io/vault-genome/sagvd:<tag>`,
   `ghcr.io/vault-genome/acp-compute:<tag>`, `ghcr.io/vault-genome/sagvd-fips:<tag>`
   and `ghcr.io/vault-genome/acp-compute-fips:<tag>`, signs each by digest
   (`cosign sign`, keyless), attests an SPDX SBOM of each image to it
   (`cosign attest --type spdxjson`), and uploads `images-<tag>.txt` — the
   four images named by digest — with its signature, certificate and
   bundle, and the four image SBOMs: 8 more assets, 197 in all (the build
   job's 188, the provenance, these 8; 97 before 0.12.0, 55 before
   0.8.0). The first push of
   an image creates its package *private* — the rehearsal `v0.6.1-rc2`
   found it on 2026-10-21 (an anonymous pull answers 403) — so an org
   owner makes `ghcr.io/vault-genome/sagvd`,
   `ghcr.io/vault-genome/acp-compute` and, at their first push, the two
   `-fips` packages public once, in each package's
   settings (Change visibility → Public, confirmed by typing the
   package's name). "Public" is greyed out there — "Setting is disabled
   by organization administrators" — until the organization allows
   public containers: Organization settings → Packages → Package
   creation → Public, which the same owner enables first. §5, item 5
   checks the result.
9. `slsa-images` runs the SLSA container generator
   (`generator_container_slsa3.yml` v2.1.0) once per image (four), over
   the image's digest, and pushes the provenance to the registry beside
   the image.
10. The `pypi` job, on a final tag only (a rehearsal `vX.Y.Z-rcN` builds
    and signs the distribution and stops here: PyPI cannot take a version
    back, and the rehearsal's wheel carries the final number), takes the
    wheel and the sdist from the build job, verifies each under this
    workflow's identity on this tag, and publishes them to PyPI with
    `pypa/gh-action-pypi-publish` by trusted publishing — PyPI accepts the
    OIDC token of this repository, `release.yml` and the GitHub
    environment `pypi`; no token is stored — with PyPI's attestations
    beside them. The publisher is configured once on PyPI (owner
    `vault-genome`, repository `vaultgenome-core`, workflow
    `release.yml`, environment `pypi`); a required reviewer on the
    `pypi` environment, if the repository sets one, is an approval
    before the upload.

`TestInvariant_11_SupplyChainAttested` does not run in `release.yml`; it runs
with the doctrine tests in vault-gate. It reads `release.yml` and fails if the
workflow no longer names `syft` and `spdx-json`, `cosign` `sign-blob`, the
SLSA generator, the `v*.*.*` trigger, `verify-tag`, the five binaries or the worker package — so
a change that drops a pillar cannot merge. It does not run the workflow.

---

### 4.1 Rehearsal after a change to release.yml

`release.yml` runs only on a tag, so a pull request cannot exercise it.
The image jobs (§4, items 8–9) and the Go 1.27.3 toolchain were
rehearsed as `v0.6.1-rc1` on 2026-10-21: the build, the 49 assets and
the provenance as before; the `images` job failed at its first `COPY` —
the repository's `.dockerignore` excludes `bin/`, so a root build
context carries no binary. Each image now builds from a staged context
of its own (`dist/image-context/<name>`); the rehearsal of that,
`v0.6.1-rc2` on the same day, was green: 55 assets, both images signed
and attested with a provenance each, verified like a release (§5) — the
kits `release-deploy` and `release-deploy-images` both PASS on SEV-SNP
against it — and its release deleted, the tag kept, like rc1's. The
rehearsals found three things no job had: the packages are created
private and the organization has to allow public ones (§4, item 8);
`cosign verify` prints "Verification for", not verify-blob's "Verified
OK"; and the asset count is 55, not 54.
The `-fips` release variant of ADR 0030 (part three) was rehearsed as
`v0.8.0-rc1` on 2026-10-21 (run 39686635713, 22:27:53–22:34:53Z on the
tag's push): the build job built both variants, refused nothing, and
uploaded 88 assets; the images job built, pushed, signed and attested
the four images; the generic and the four container provenances
followed — 97 assets, four images in `images-v0.8.0-rc1.txt`. The two
new packages, `sagvd-fips` and `acp-compute-fips`, were publicly
readable at their first push (an anonymous manifest fetch answered 200),
unlike the first two on 2026-10-21 — the organization's packages
setting had been opened by then; a kit still checks. Verified like a release (§5) by the kits against the rehearsal: `release-deploy`
(`scripts/hardware-test/release-deploy/evidence/20261021T223719Z/`) — the
twenty-two signature pairs and the twenty-two bundles (with
`--trusted-root` and the network denied), the eleven provenances and the
tag; the five binaries, their five `-fips` variants and the package
rebuilt from the tag byte for byte on a Darwin arm64 host; the guest from
release assets alone, the gate job EXACT, 17 events verified — and
`release-deploy-images`
(`scripts/hardware-test/release-deploy-images/evidence/20261021T224031Z/`) —
the four images publicly readable, each signature, SBOM attestation and
container provenance verified, the binary inside each image equal to its
release asset (the `-fips` images to the `-fips` assets), the two default
images run on the guest, the gate job EXACT, 17 events verified. The
rehearsal found one thing: the `release-deploy` kit's count of verified
signature pairs was still twelve while it verified twenty-two, and the
run stopped on its own arithmetic; the count follows the artifact count
now. The rehearsal's GitHub release was deleted and the tag kept.
After any change to the workflow or to the actions it pins (a Dependabot
bump included), run the pipeline on a signed rehearsal tag before the
real one: `vX.Y.Z-rcN` on the merge commit, verified like a release (§5),
then delete the rehearsal's GitHub release and keep the tag. The Go module
proxy may already have served the tag, and a tag that was once public is
never moved or deleted (0.3.0 in the CHANGELOG is the lesson). 0.4.0 was
rehearsed as `v0.4.0-rc1` on 2026-10-14; the permissions change of this
page's revision is rehearsed as `v0.4.1-rc1`; the fifth binary and the
worker package as `v0.4.2-rc1` on 2026-10-15 (37 assets, 12 signatures,
6 provenances and the tag verified, the six artifacts rebuilt byte for
byte — once the package was repacked with GNU gzip, §5.4); the Sigstore
bundles as `v0.4.3-rc1` and `v0.4.3-rc2` on 2026-10-15 (49 assets each;
rc1's bundles were the old format, and `--offline` — the check first
written for them — turned out to reach for the TUF mirror on cosign
2.6.5 and fail without a route; rc2's are the new bundle format: the
twelve pairs online, the twelve bundles with `--trusted-root` and the
network denied, 6 provenances and the tag verified, the six artifacts
rebuilt byte for byte; on the air-gap drill's guest the twelve bundles
verified with egress denied, `scripts/hardware-test/air-gap/`).
The tools for the other platforms, the checksums list and the Python
distribution (0.12.0) were rehearsed as `v0.12.0-rc1` on 2026-10-28 (run
40616916087, 01:45–01:57Z on the tag's push): the build job built the
twenty-two binaries, the worker package and the Python distribution
twice to byte-identical files, refused nothing, and uploaded 188 assets;
the images job built, pushed, signed and attested the four images; the
generic and the four container provenances followed — 197 assets; the
`pypi` job was skipped, as a rehearsal's is. Verified like a release
(§5) by the kits against the rehearsal: `release-deploy`
(`scripts/hardware-test/release-deploy/evidence/20261028T020143Z/`) —
the signed list against the 23 downloaded artifacts, the forty-seven
signature pairs and the forty-seven bundles (with `--trusted-root` and
the network denied), the twenty-four provenances and the tag; the
twenty binaries, the package, the wheel and the sdist rebuilt from the
tag byte for byte on a Darwin arm64 host (each cross build for its own
platform, the distribution by the tag's `scripts/build_python_dist.sh`);
the guest from release assets alone, the gate job EXACT, 17 events
verified — and `release-deploy-images`
(`scripts/hardware-test/release-deploy-images/evidence/20261028T021319Z/`)
— the four images publicly readable, each signature, SBOM attestation
and container provenance verified, the binary inside each equal to its
release asset, the two default images run on the guest, the gate job
EXACT, 17 events verified. The Homebrew formula written from the
rehearsal's checksums list installed on an Apple-silicon Mac and on
x86-64 Linux (`brew install`, `brew test`, `brew audit --strict
--online`; the tap's own workflow). The rehearsal found one thing:
Homebrew reads a version from the end of a URL, and
`acpctl-darwin-arm64` gave it `64` — the formula names the version. The
rehearsal's GitHub release stays until the formula points at `v0.12.0`,
then is deleted and the tag kept.

## 5. Post-release verification

Once the release workflow completes:

1. Download all release artifacts to a clean environment (not a
   developer machine). `sha256sum -c checksums-<tag>.txt` there: every
   binary and the package against the signed list, before any single
   check.
2. Verify the checksums list, every binary, the worker package and every
   SBOM with `cosign verify-blob`, for example:
   ```
   cosign verify-blob --signature sagvd.sig --certificate sagvd.cert \
     --certificate-identity-regexp '^https://github\.com/vault-genome/vaultgenome-core/\.github/workflows/release\.yml@refs/tags/v' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     sagvd
   ```
   `docs/security/supply_chain.md` explains what a successful check proves.
   Then the bundle of each of the forty-six (the twenty binaries, the
   package, the wheel, the sdist, their SBOMs; twenty-two before 0.12.0,
   twelve before 0.8.0) and of the checksums list, with the Sigstore
   trust root as
   a file (`cosign initialize` fetches it into
   `~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json`),
   which needs no route — run it with the network denied, as the
   release-deploy kit does:
   ```
   cosign verify-blob --new-bundle-format --bundle sagvd.sigstore.json --trusted-root trusted_root.json \
     --certificate-identity-regexp '^https://github\.com/vault-genome/vaultgenome-core/\.github/workflows/release\.yml@refs/tags/v' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     sagvd
   ```
   — the check an air-gapped site runs (`runbooks/air_gap.md`). Not
   `--offline`: on cosign 2.6.5 it still updates TUF from the mirror.
3. Check that the SLSA provenance attached to the release names each of
   the twenty binaries', the worker package's, the wheel's, the sdist's
   and the checksums list's SHA-256 (for example with `slsa-verifier`).
4. Rebuild from the tag with Go 1.27.3, from any host — the binaries are
   static (`CGO_ENABLED=0`) and carry the tag's VCS stamp, so the rebuild
   must come from a git checkout of the tag, not from an archive:
   ```
   git clone https://github.com/vault-genome/vaultgenome-core.git && cd vaultgenome-core
   git checkout vX.Y.Z
   GOOS=linux GOARCH=amd64 make build build-fips build-cross VERSION=vX.Y.Z COMMIT=$(git rev-parse HEAD)
   sha256sum bin/sagvd bin/acp-compute bin/acpctl bin/acp-bootstrap bin/acp-keygen bin/*-fips bin/*-*-*
   scripts/build_python_dist.sh dist     # the wheel and the sdist, with their hashes
   ```
   Every hash must equal the released file's. The worker package repacks
   the same way with GNU tar (`--sort=name --mtime=@SOURCE_DATE_EPOCH
   --owner=0 --group=0 --numeric-owner`) and GNU gzip (`gzip -n`; the
   exact command is in `release.yml`) to the released file's hash. Both
   tools must be GNU's: Apple's gzip writes a different deflate stream for
   the same tar, so a repack on macOS needs `gzip` from Homebrew beside
   `gtar` (the rehearsal of 0.4.2 found it: the tar inside identical, the
   file not);
   `scripts/hardware-test/release-deploy/run.sh` does all of them, the
   cross builds included. `go version -m <binary>`
   prints the build settings a released binary was made with (Go
   version, GOOS/GOARCH, CGO_ENABLED, -trimpath, the VCS revision and
   time; for a `-fips` binary `GOFIPS140=v1.0.0-…`, the module snapshot
   it was built on); compare them first when hashes differ. (v0.1.0 and v0.2.0 were
   built with cgo on the runner: their rebuild needs linux/amd64 with a
   C toolchain; from v0.2.1 the binaries are static.)
5. Verify the four images by digest (two before 0.8.0), from
   `images-<tag>.txt` (itself verified like the other assets): the signature under this workflow's
   identity, the SBOM attestation, and the provenance —
   ```
   cosign verify ghcr.io/vault-genome/sagvd@sha256:… \
     --certificate-identity-regexp '^https://github\.com/vault-genome/vaultgenome-core/\.github/workflows/release\.yml@refs/tags/v' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   cosign verify-attestation --type spdxjson ghcr.io/vault-genome/sagvd@sha256:… \
     --certificate-identity-regexp '…/release\.yml@refs/tags/v' --certificate-oidc-issuer https://token.actions.githubusercontent.com
   slsa-verifier verify-image ghcr.io/vault-genome/sagvd@sha256:… \
     --source-uri github.com/vault-genome/vaultgenome-core --source-tag vX.Y.Z
   ```
   and the same for `acp-compute`, `sagvd-fips` and `acp-compute-fips`.
   All must work from a machine with no
   registry login: a private package (§4, item 8) answers 403, and an
   integrator could neither pull nor verify —
   `scripts/hardware-test/release-deploy-images/run.sh` checks exactly
   that, anonymously, before anything else. The binary inside is the
   released one: `docker create` the image, `docker cp`
   `/usr/local/bin/sagvd` out, and its SHA-256 equals the release asset's
   — `sagvd` for the `sagvd` image, `sagvd-fips` for the `sagvd-fips`
   image (the same path inside both).
6. Verify the tag signature — `git verify-tag v0.1.0`.
6a. The `-fips` variants name their module: `./sagvd-fips version` ends
   `fips140=on module=v1.0.0 enforced=false`, and so do the other four;
   `identity` on a host carries the same under `fips140` (ADR 0030). A
   deployment that needs the certified module runs these five and records
   the module version from `identity`.
7. Record the release hashes externally (the external pin is itself a
   defence against a later tag rewrite — see
   `04_observability.md` §2.2 for the parallel idea on audit chains).
8. PyPI serves the release's bytes: `pip download --no-deps
   vaultgenome==X.Y.Z -d pypi-check` (the wheel) and the same with
   `--no-binary :all:` (the sdist) give files whose SHA-256 are the lines
   of `checksums-vX.Y.Z.txt`; the project page shows the attestations of
   `release.yml` on this tag.
9. The button deploys it: `scripts/hardware-test/gcp-deploy/run.sh
   <project> vX.Y.Z` runs `deploy/gcp/deploy.sh` against the release as a
   person does — the release verified, the Confidential VM stood up by
   `acpctl provision`, the services, the gate job, the audit log — then
   resets the VM, submits a second job over ssh and verifies the chain
   across the reboot, and keeps the record (about twelve minutes, one
   `n2d-standard-4`). The release notes carry the button for this tag
   (`cloudshell_git_branch=vX.Y.Z`); a person who presses it gets this run.

No audit event is appended for a release; there is no audit kind for one.

---

## 6. Emergency release (security-driven)

A security-driven emergency release still goes through this procedure —
there is no "fast path" that bypasses vault-gate or the SBOM / cosign /
SLSA steps. The only difference is:

1. The release notes are specific about the vulnerability class and the
   affected versions (per `SECURITY.md` §"What to expect").
2. The CVE ID is claimed and recorded before the release ships.
3. The prior version is explicitly marked as withdrawn in the release
   notes.

A release that bypasses the workflow is by definition not a release —
it is an unattested binary and per invariant #11 is not shippable.

---

## 7. Release checklist (one-page)

```
[ ] Clean working tree
[ ] vault-gate CI green on the commit; make vault-gate PASS locally
[ ] make test-integration and make verify-reproducible pass
[ ] Runbook reviewed for drift
[ ] Release notes drafted
[ ] pyproject.toml version = X.Y.Z; scripts/build_python_dist.sh dist: byte-identical
[ ] Tag: git tag -s vX.Y.Z
[ ] Push: git push origin vX.Y.Z
[ ] release.yml workflow green
[ ] sha256sum -c checksums-vX.Y.Z.txt over the downloaded assets
[ ] cosign verify-blob on every binary, the checksums list and every SBOM: the pair, and the bundle with --trusted-root and the network denied
[ ] SLSA provenance names every binary's SHA-256
[ ] Rebuild from the tag is byte-identical
[ ] Tag signature verified externally
[ ] Release hash externally pinned
[ ] PyPI's wheel and sdist: SHA-256 equal to the release's (final tag)
[ ] scripts/hardware-test/gcp-deploy/run.sh on the tag: PROVEN, the reboot, the second job
[ ] "Withdrawn" marker on prior version, if emergency
```

A release is complete when every line of this checklist is green.

---

_Document history: 2026-09-14 — checked line by line against the code; commands and names the binaries do not have were removed._
