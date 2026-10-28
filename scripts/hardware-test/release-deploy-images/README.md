#`20261028T210305Z` is the run on the rehearsal `v0.13.0-rc1` (the Cloud
Shell button for the tag in the release notes; release procedure §4.1),
19 minutes after the rehearsal's release was published: PASS — the four
images `sagvd@sha256:225093fb…`, `acp-compute@sha256:e056f64b…`,
`sagvd-fips@sha256:dd959280…` and `acp-compute-fips@sha256:fecf03a3…`,
all publicly readable; each signature, SBOM attestation and container
provenance verified; the binary inside each equal to its release asset
(`0c20c56d…`, `fe3023c2…`, `9ff2f42e…`,
`41c75532…`); each loaded image's `RootFS.Layers` equal to the
signed config's `diff_ids` (13 layers for the two `sagvd` images, 9 for the
two workers); on the guest, from the two default images, `gate_level=EXACT`
6/6, both rogues refused, the audit log verified (17 events), 188.3 s.

`20261028T215842Z` is the run on `v0.13.0`, 18 minutes after it was
published: PASS — the four images `sagvd@sha256:d1096286…`,
`acp-compute@sha256:a5836e2e…`, `sagvd-fips@sha256:6c1b4b64…` and
`acp-compute-fips@sha256:5f969cf9…`, all publicly readable; each
signature, SBOM attestation and container provenance verified; the
binary inside each equal to its release asset (`f20619f7…`,
`349f2719…`, `cec890e2…`, `8de3e85b…`); each loaded image's
`RootFS.Layers` equal to the signed config's `diff_ids` (13 layers for
the two `sagvd` images, 9 for the two workers); on the guest, from the
two default images, `gate_level=EXACT` 6/6, both rogues refused, the
audit log verified (17 events), 295.0 s.

 release-deploy-images — the Return Path on SEV-SNP from the release's container images

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
   `sagvd`, `acp-compute`, `acpctl`, `acp-keygen` and worker package —
   from 0.8.0 `sagvd-fips` and `acp-compute-fips` too (ADR 0030) — with
   their Sigstore bundles and verifies all of them under the release
   workflow's identity; confirms each image is publicly readable — an
   anonymous pull of its manifest, no registry login consulted, because
   a package pushed for the first time is private and an integrator
   could neither pull nor verify it (the first run found exactly that);
   then each image by digest — `cosign verify`,
   `cosign verify-attestation --type spdxjson`, `slsa-verifier
   verify-image` — and exports each to check that the binary inside is
   byte-identical to the release asset (for a `-fips` image, the `-fips`
   asset: the binary sits at the same path inside, so the image is a
   drop-in); the two default images then go to the guest; then pulls each image into a
   tarball (`crane`, by digest) and records the signed manifest's config
   digest and the config's `rootfs.diff_ids`.
2. Uploads the two tarballs, the released `acpctl`, `acp-keygen` and
   worker package to a new private bucket.
3. Boots an n2d SEV-SNP VM whose startup script is
   `cvm-returnpath-images.sh`: Docker, the images loaded from the
   tarballs (nothing pulled on the guest), the flow of
   `gcp-sev-snp/returnpath-e2e` with every daemon invocation a `docker
   run` of the image; the fine-tune runs on the host, the door inside the
   worker image.
4. Decodes the results from the serial console, keeps the runner's
   verification records beside them under `evidence/<stamp>/verify/`,
   and ties the guest's record to the runner's: the six inputs the guest
   hashed are the six the runner uploaded, and each loaded image's
   `RootFS.Layers` are the signed config's `diff_ids` — docker's image
   id after `docker load` is a digest of a manifest rebuilt on the guest,
   not the registry's, so it is the layers that carry the tie. Deletes
   the VM and the bucket — always, also on failure.

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
`audit-events.jsonl`, `sha256sums.txt`, `docker-rootfs-<name>.json` — and
`verify/` from the runner: `images-<tag>.txt`, `public-read.txt` (the
anonymous manifest pulls), the cosign, attestation and SLSA outputs per
image, `config-digests.txt`, `diff-ids-<name>.json`,
`binaries-inside.txt`, `guest-inputs.sha256`, `tag.txt`, `tools.txt`.

`20261021T034404Z` is the first run, against the rehearsal `v0.6.1-rc2`:
it stopped at the first `cosign verify` — the packages were private
(`verify/image-sagvd-cosign.txt`: "authentication required") — and has
no guest record; the public-read check and the one-time step in the
release procedure (§4, item 8) come from it. `20261021T113822Z` is the
second, once the packages were public: the images verified
(`verify/image-sagvd-cosign.txt`), but the kit counted verify-blob's
"Verified OK" where `cosign verify` prints "Verification for", and
stopped itself; the counts now read the right line. `20261021T114247Z`
is the third, the PASS: both daemons from their images on SEV-SNP,
identities from the chip, keys sealed, the rogue refused,
`gate_level=EXACT` 6/6, the audit log verified (1158 s on the guest);
the six input hashes are identical on both sides. The layer comparison
and the config records came after that run, so it has neither file.
`20261021T132958Z` is the first run on a real release, `v0.6.1`, eight
minutes after it was published: PASS, and the first record with the
tie whole — the six input hashes identical on both sides, and each
loaded image's `RootFS.Layers` equal to the signed config's `diff_ids`
(13 layers for `sagvd`, 9 for `acp-compute`; `verify/config-digests.txt`
names the configs). The images are `sagvd@sha256:b7ff8436…` and
`acp-compute@sha256:6f843dc1…`, both publicly readable; the binary inside
each equals the release asset (`6291f59e…`, `a418fdfe…`); on the guest,
`gate_level=EXACT` 6/6, the rogue refused, the audit log verified, 178 s.

`20261021T164959Z` is the run on `v0.7.0`, ten minutes after it was
published: PASS — the six input hashes identical on both sides, each
loaded image's `RootFS.Layers` equal to the signed config's `diff_ids`
(13 layers for `sagvd`, 9 for `acp-compute`). The images are
`sagvd@sha256:dbd7fac6…` and `acp-compute@sha256:7216a013…`, both
publicly readable; the binary inside each equals the release asset
(`fc11d465…`, `367d4b15…`); on the guest, `gate_level=EXACT` 6/6, the
rogue refused, the audit log verified (17 events), 211 s.

`20261021T224031Z` is the run on the rehearsal `v0.8.0-rc1` of the
`-fips` release variant (ADR 0030, part three; release procedure §4.1),
ten minutes after the tag's pipeline finished: PASS — the first record
with four images. `sagvd@sha256:2fa0a32b…`, `acp-compute@sha256:db2019ae…`,
`sagvd-fips@sha256:19ed8ecf…` and `acp-compute-fips@sha256:c97ad11c…`,
all four publicly readable at their first push; each signature, SBOM
attestation and container provenance verified; the binary inside each
equal to its release asset — `sagvd-fips`'s to the `sagvd-fips` asset
(`5ed67cf2…`), `acp-compute-fips`'s to `acp-compute-fips` (`1dc2bab2…`),
the binary at the same path inside as in the default image; each loaded
image's `RootFS.Layers` equal to the signed config's `diff_ids` (13
layers for `sagvd` and `sagvd-fips`, 9 for the two workers). The two
default images ran on the guest: `gate_level=EXACT` 6/6, both rogues
refused, the audit log verified (17 events), 186.9 s. The rehearsal's
release was deleted afterwards and the tag kept (§4.1).

`20261021T235410Z` is the run on `v0.8.0`, twenty-nine minutes after it
was published: PASS — the four images `sagvd@sha256:54a0a9bf…`,
`acp-compute@sha256:3b8c34de…`, `sagvd-fips@sha256:0522af4a…` and
`acp-compute-fips@sha256:6b11c99d…`, all publicly readable; each
signature, SBOM attestation and container provenance verified; the
binary inside each equal to its release asset (`ea231f03…`,
`7537fe16…`, `9a25e112…`, `b3acc700…`); each loaded image's
`RootFS.Layers` equal to the signed config's `diff_ids` (13 layers for
the two `sagvd` images, 9 for the two workers); on the guest, from the
two default images, `gate_level=EXACT` 6/6, both rogues refused, the
audit log verified (17 events), 182.5 s. Two earlier runs against the
same release reached no verdict on the runner: one stopped on a
transient error of the TUF mirror while another kit initialized the
same cosign cache beside it, the other lost its runner-side `verify/`
to a cleanup by hand while it ran; their logs are kept outside the tree.
Both causes are fixed in #160 — a TUF cache per run with retries, and
the record staged outside `evidence/` until it is complete — and proven
there by the three kits run in the same minutes against this release.

`20261022T001419Z` is the kit's own proof after those two: the same
release, with the `release-deploy` and `keyrelease-e2e` kits running in
the same minutes — a TUF cache of this run's own, the record staged under
the run's work directory and published with the runner's `verify/` inside
it by one move, no retry needed: PASS, the four images verified and the
binary inside each equal to its asset, the guest's gate EXACT, 17
events, 1157.2 s.

`20261022T155049Z` is the run on `v0.9.0`, twelve minutes after it was
published: PASS — the four images `sagvd@sha256:4222a3fb…`,
`acp-compute@sha256:8e74b2b9…`, `sagvd-fips@sha256:01b45872…` and
`acp-compute-fips@sha256:2a876975…`, all publicly readable; each
signature, SBOM attestation and container provenance verified; the
binary inside each equal to its release asset (`35abeda8…`,
`2c1ed7d4…`, `d1ed4805…`, `34bcc8be…`); each loaded image's
`RootFS.Layers` equal to the signed config's `diff_ids` (13 layers for
the two `sagvd` images, 9 for the two workers); on the guest, from the
two default images, `gate_level=EXACT` 6/6, both rogues refused, the
audit log verified (17 events), 185.9 s.

`20261023T202952Z` is the run on `v0.10.0`, 16 minutes after it was
published: PASS — the four images `sagvd@sha256:3b1be7a5…`,
`acp-compute@sha256:26eb2c8c…`, `sagvd-fips@sha256:8ffc8005…` and
`acp-compute-fips@sha256:a4eaccde…`, all publicly readable; each
signature, SBOM attestation and container provenance verified; the
binary inside each equal to its release asset (`06a958c9…`,
`dfe31f44…`, `e6082a5f…`, `3bdc6cff…`); each loaded image's
`RootFS.Layers` equal to the signed config's `diff_ids` (13 layers for
the two `sagvd` images, 9 for the two workers); on the guest, from the
two default images, `gate_level=EXACT` 6/6, both rogues refused, the
audit log verified (17 events), 187.1 s.

`20261024T190054Z` is the run on `v0.11.0`, 10 minutes after it was
published: PASS — the four images `sagvd@sha256:f7359123…`,
`acp-compute@sha256:c7acc30b…`, `sagvd-fips@sha256:3feaf316…` and
`acp-compute-fips@sha256:dbbedc2d…`, all publicly readable; each
signature, SBOM attestation and container provenance verified; the
binary inside each equal to its release asset (`b982b6f5…`,
`5cb0e6c1…`, `187bbad2…`, `3e508a6e…`); each loaded image's
`RootFS.Layers` equal to the signed config's `diff_ids` (13 layers for
the two `sagvd` images, 9 for the two workers); on the guest, from the
two default images, `gate_level=EXACT` 6/6, both rogues refused, the
audit log verified (17 events), 180.5 s.

`20261028T021319Z` is the run on the rehearsal `v0.12.0-rc1` (the tools
for the other platforms, the checksums list and the Python distribution;
release procedure §4.1), 12 minutes after the rehearsal's release was
published: PASS — the four images `sagvd@sha256:eda7853a…`,
`acp-compute@sha256:c50fde5e…`, `sagvd-fips@sha256:97c04daa…` and
`acp-compute-fips@sha256:f2939d1a…`, all publicly readable; each
signature, SBOM attestation and container provenance verified; the
binary inside each equal to its release asset (`2e75a9ae…`,
`a328f055…`, `333ef21f…`, `42086f58…`); each loaded image's
`RootFS.Layers` equal to the signed config's `diff_ids` (13 layers for
the two `sagvd` images, 9 for the two workers); on the guest, from the
two default images, `gate_level=EXACT` 6/6, both rogues refused, the
audit log verified (17 events), 183.2 s.

`20261028T025338Z` is the run on `v0.12.0`, 14 minutes after it was
published: PASS — the four images `sagvd@sha256:72d74d0b…`,
`acp-compute@sha256:03eff4c0…`, `sagvd-fips@sha256:bf33ef13…` and
`acp-compute-fips@sha256:8d46b0b9…`, all publicly readable; each
signature, SBOM attestation and container provenance verified; the
binary inside each equal to its release asset (`c34b2f94…`,
`0b0b7bb0…`, `feeeb663…`, `79f473f6…`); each loaded image's
`RootFS.Layers` equal to the signed config's `diff_ids` (13 layers for
the two `sagvd` images, 9 for the two workers); on the guest, from the
two default images, `gate_level=EXACT` 6/6, both rogues refused, the
audit log verified (17 events), 183.1 s. A first run against the same
release, five minutes earlier, stopped on the runner at the second
image's config: a few seconds of TLS handshake timeouts to GitHub left
`crane` with an empty answer and the kit's JSON reader with nothing to
read; nothing had reached the cloud, and its log is kept outside the
tree.
