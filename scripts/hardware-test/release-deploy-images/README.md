# release-deploy-images — the Return Path on SEV-SNP from the release's container images

What it proves: a deployment that starts from the registry — the two
images a release carries (`docs/security/supply_chain.md`), verified by
digest and loaded onto a fresh GCP SEV-SNP Confidential VM — runs the
Return Path with the chip: both daemons attest from inside their
containers, the key files are sealed to the host from inside them, the
thief and the unpinned worker are refused, a real fine-tune's genome is
restored by the worker image's own door and gated EXACT, and the audit
log verifies under the published key with the released `acpctl`.
Nothing comes from this tree: the images from the registry, the tools
from the release's assets.

How the chip is reached from a container is what the kit measures and
`deploy/compose/README.md` states: the whole `configfs` bound read-write,
Docker's default AppArmor profile set aside, `/dev/sev-guest` and
`/dev/tpmrm0` passed, root inside — `configfs` creates a request's
attribute files owned by root, so the images' `nonroot` user cannot
write `inblob` whatever the host chowns (three probes on a throwaway
guest, 2026-10-21). The images serve `gcp-sev-snp`; the families that
seal to a vTPM call `tpm2-tools`, which the images do not carry.

## What a run does

1. On the runner: downloads `images-<tag>.txt` and the released
   `sagvd`, `acp-compute`, `acpctl`, `acp-keygen` and worker package
   with their Sigstore bundles and verifies all six under the release
   workflow's identity; confirms each image is publicly readable — an
   anonymous pull of its manifest, no registry login consulted, because
   a package pushed for the first time is private and an integrator
   could neither pull nor verify it (the first run found exactly that);
   then each image by digest — `cosign verify`,
   `cosign verify-attestation --type spdxjson`, `slsa-verifier
   verify-image` — and exports each to check that the binary inside is
   byte-identical to the release asset; then pulls each image into a
   tarball (`crane`, by digest).
2. Uploads the two tarballs, the released `acpctl`, `acp-keygen` and
   worker package to a new private bucket.
3. Boots an n2d SEV-SNP VM whose startup script is
   `cvm-returnpath-images.sh`: Docker, the images loaded from the
   tarballs (nothing pulled on the guest), the flow of
   `gcp-sev-snp/returnpath-e2e` with every daemon invocation a `docker
   run` of the image; the fine-tune runs on the host, the door inside the
   worker image.
4. Decodes the results from the serial console, keeps the runner's
   verification records beside them under `evidence/<stamp>/verify/`, and
   deletes the VM and the bucket — always, also on failure.

```bash
scripts/hardware-test/release-deploy-images/run.sh <project> <tag> [zone]
```

Needs `gh`, `cosign`, `slsa-verifier`, `go` (crane runs through `go
run`) and `gcloud`. Cost: one n2d-standard-4 for about fifteen minutes.

## Evidence

`evidence/<stamp>/` is the guest's record as the `returnpath-e2e` kit
keeps it — `steps.txt`, `timeline.txt`, the daemons' logs from `docker
logs`, `docker-images.txt` (the loaded images' ids and digests),
`images.txt`, `sealed-files.txt`, `job.json`, `audit-verify.json`,
`audit-events.jsonl`, `sha256sums.txt` — and `verify/` from the runner:
`images-<tag>.txt`, `public-read.txt` (the anonymous manifest pulls),
the cosign, attestation and SLSA outputs per image,
`binaries-inside.txt`, `guest-inputs.sha256`, `tag.txt`, `tools.txt`.

`20261021T034404Z` is the first run, against the rehearsal `v0.6.1-rc2`:
it stopped at the first `cosign verify` — the packages were private
(`verify/image-sagvd-cosign.txt`: "authentication required") — and has
no guest record; the public-read check and the one-time step in the
release procedure (§4, item 8) come from it. `20261021T113822Z` is the
second, once the packages were public: the images verified
(`verify/image-sagvd-cosign.txt`), but the kit counted verify-blob's
"Verified OK" where `cosign verify` prints "Verification for", and
stopped itself; the counts now read the right line.
