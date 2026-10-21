#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The reference deployment from the RELEASE IMAGES: the Return Path on real
# AMD SEV-SNP with sagvd and acp-compute running from the two container
# images a release carries, not from this tree and not from the release's
# binaries on the host. What an operator who deploys from the registry
# does, recorded end to end:
#
#   1. downloads the release's images-<tag>.txt and verifies it under its
#      Sigstore bundle; verifies each image by digest — the keyless
#      signature under the release workflow's identity, the SPDX SBOM
#      attestation, the SLSA container provenance — and exports each
#      image to check that the binary inside is byte-identical to the
#      release asset of the same name (the asset's bundle verified too);
#   2. pulls both images by digest into tarballs (crane) and uploads them,
#      with the released acpctl, acp-keygen and worker package, to a new
#      private bucket — the guest loads the images from there, so nothing
#      on the guest reaches the registry or trusts a tag;
#   3. boots an n2d SEV-SNP Confidential VM whose startup script is
#      cvm-returnpath-images.sh: the daemons run as containers with the
#      chip reachable the way deploy/compose/README.md states (the whole
#      configfs bound read-write, Docker's default AppArmor profile set
#      aside, the two devices passed, root inside), both attest with the
#      chip, the thief and the unpinned worker are refused, a gate job
#      runs, the verdict and the audit log come back;
#   4. decodes the results, keeps the verification records next to them,
#      and deletes the VM and the bucket — always, also on failure.
#
# Usage: run.sh <project> <tag> [zone]        (an n2d-standard-4 for ~15 min)
# Needs gh, cosign, slsa-verifier, go (crane runs through `go run`), gcloud.
set -euo pipefail
PROJECT="${1:?usage: run.sh <project> <tag> [zone]}"
TAG="${2:?usage: run.sh <project> <tag> [zone]}"
ZONE="${3:-us-central1-c}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
E2E="$ROOT/scripts/hardware-test/gcp-sev-snp/returnpath-e2e"
REPO="vault-genome/vaultgenome-core"
IDENTITY='^https://github\.com/vault-genome/vaultgenome-core/\.github/workflows/release\.yml@refs/tags/v'
ISSUER='https://token.actions.githubusercontent.com'
CRANE='github.com/google/go-containerregistry/cmd/crane@v0.20.3'
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
NAME="vg-images-$LOW"
BUCKET="$PROJECT-vg-img-$LOW"
WORK="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"
mkdir -p "$EVIDENCE/verify"
cleanup() {
  echo "cleanup: deleting $NAME and gs://$BUCKET"
  gcloud compute instances delete "$NAME" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
rec() { tee -a "$EVIDENCE/verify/$1" ; }

echo "== 1. the release $TAG: images-$TAG.txt, the two binaries, their bundles"
DL="$WORK/assets"; mkdir -p "$DL"
WORKER_PKG="genome-worker-$TAG.tar.gz"
gh release download "$TAG" --repo "$REPO" --dir "$DL" \
  --pattern "images-$TAG.txt*" --pattern sagvd --pattern 'sagvd.sigstore.json' --pattern acp-compute --pattern 'acp-compute.sigstore.json' \
  --pattern acpctl --pattern 'acpctl.sigstore.json' --pattern acp-keygen --pattern 'acp-keygen.sigstore.json' \
  --pattern "$WORKER_PKG" --pattern "$WORKER_PKG.sigstore.json" >/dev/null
( cd "$DL" && sha256sum -- * ) | rec assets.sha256 >/dev/null
for f in "images-$TAG.txt" sagvd acp-compute acpctl acp-keygen "$WORKER_PKG"; do
  ( cd "$DL" && cosign verify-blob --new-bundle-format --bundle "$f.sigstore.json" \
      --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$f" ) 2>&1 | rec cosign.txt | tail -1 | sed "s|^|  $f: |"
done
test "$(grep -c 'Verified OK' "$EVIDENCE/verify/cosign.txt")" = 6 || { echo "ERROR: an asset did not verify"; exit 1; }
cp "$DL/images-$TAG.txt" "$EVIDENCE/verify/"
cat "$DL/images-$TAG.txt" | sed 's|^|  |'

echo "== 1b. each image is publicly readable: an anonymous pull of its manifest"
# A package pushed for the first time is private, and ghcr refuses an
# anonymous reader (the first run of this kit, 2026-10-21 on v0.6.1-rc2,
# found it: HTTP 403, cosign "authentication required"). An org owner makes
# it public once — Package settings → Change visibility → Public — and the
# pull below answers 200. No local registry login is consulted: this is
# what an integrator sees.
while read -r ref; do
  repo="${ref%@*}"; repo="${repo#ghcr.io/}"; digest="${ref##*@}"
  tok="$(curl -sS "https://ghcr.io/token?scope=repository:$repo:pull" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $tok" \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json' \
    "https://ghcr.io/v2/$repo/manifests/$digest")"
  echo "  $ref: anonymous manifest HTTP $code" | rec public-read.txt
  if [ "$code" != 200 ]; then
    echo "ERROR: $ref is not publicly readable (HTTP $code): a package pushed for the first time is private."
    echo "       An org owner makes it public once: https://github.com/orgs/${REPO%%/*}/packages/container/${repo#*/}/settings"
    echo "       (Danger zone → Change visibility → Public; if Public is greyed out there, first allow public"
    echo "       containers in Organization settings → Packages → Package creation), then run again."
    exit 1
  fi
done < "$DL/images-$TAG.txt"

echo "== 2. each image by digest: the signature, the SBOM attestation, the provenance, the binary inside"
while read -r ref; do
  name="${ref##*/}"; name="${name%@*}"; digest="${ref##*@}"
  echo "  $name @ $digest"
  cosign verify "$ref" --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" --output text 2>&1 | rec "image-$name-cosign.txt" | grep -c 'Verified OK' | sed 's|^|    signature Verified OK: |'
  cosign verify-attestation --type spdxjson "$ref" --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" --output text 2>&1 | rec "image-$name-attestation.txt" | grep -c 'Verified OK' | sed 's|^|    SBOM attestation Verified OK: |'
  slsa-verifier verify-image "$ref" --source-uri "github.com/$REPO" --source-tag "$TAG" 2>&1 | rec "image-$name-slsa.txt" | tail -1 | sed 's|^|    |'
  ( cd "$ROOT" && go run "$CRANE" export "$ref" - ) | tar -xO "usr/local/bin/$name" > "$WORK/inside-$name"
  a="$(sha256sum "$WORK/inside-$name" | awk '{print $1}')"; b="$(sha256sum "$DL/$name" | awk '{print $1}')"
  if [ "$a" = "$b" ]; then echo "    binary inside = release asset ($a)" | rec binaries-inside.txt; else echo "    MISMATCH $name: image $a asset $b" | rec binaries-inside.txt; exit 1; fi
  ( cd "$ROOT" && go run "$CRANE" pull "$ref" "$WORK/$name.tar" )
  echo "    pulled to $name.tar ($(stat -f %z "$WORK/$name.tar" 2>/dev/null || stat -c %s "$WORK/$name.tar") bytes)"
done < "$DL/images-$TAG.txt"
test "$(grep -c 'Verified OK' "$EVIDENCE"/verify/image-*-cosign.txt | awk -F: '{s+=$2} END {print s}')" -ge 2 || { echo "ERROR: an image signature did not verify"; exit 1; }
test "$(grep -c 'PASSED: SLSA verification passed' "$EVIDENCE"/verify/image-*-slsa.txt | awk -F: '{s+=$2} END {print s}')" = 2 || { echo "ERROR: an image provenance did not verify"; exit 1; }
( cd "$ROOT" && git fetch -q origin "refs/tags/$TAG:refs/tags/$TAG" 2>/dev/null || true
  git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag "$TAG" ) 2>&1 | rec tag.txt | tail -1 | sed 's|^|  tag: |'
{ echo "release: $TAG"; echo "verified at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; echo "cosign: $(cosign version 2>&1 | grep GitVersion | awk '{print $2}')"
  echo "slsa-verifier: $(slsa-verifier version 2>&1 | grep -o -E 'v[0-9.]+' | head -1)"; echo "crane: $CRANE"; } | rec tools.txt >/dev/null

echo "== 3. what goes to the guest: the two image tarballs, the released acpctl, acp-keygen and worker package"
UP="$WORK/up"; mkdir -p "$UP"
cp "$WORK/sagvd.tar" "$UP/sagvd-image.tar"; cp "$WORK/acp-compute.tar" "$UP/acp-compute-image.tar"
cp "$DL/acpctl" "$UP/acpctl"; cp "$DL/acp-keygen" "$UP/keygen"; cp "$DL/$WORKER_PKG" "$UP/genome-worker.tgz"; cp "$DL/images-$TAG.txt" "$UP/images.txt"
( cd "$UP" && sha256sum -- * ) | rec guest-inputs.sha256 | sed 's|^|  |'

echo "== 4. upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$UP"/* "gs://$BUCKET/e2e/" --project "$PROJECT" >/dev/null

echo "== 5. boot $NAME (SEV-SNP, $ZONE): the daemons from the images"
gcloud compute instances create "$NAME" --project "$PROJECT" --zone "$ZONE" \
  --machine-type n2d-standard-4 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --boot-disk-size 30GB \
  --scopes storage-ro --metadata "vg-bucket=$BUCKET,vg-tag=$TAG" \
  --metadata-from-file "startup-script=$HERE/cvm-returnpath-images.sh" >/dev/null

echo "== 6. waiting for results on the serial console (up to 30 min)"
RAW_DIR="${VG_E2E_RAW_DIR:-$HOME/.cache/vaultgenome/release-deploy-images}"
mkdir -p "$RAW_DIR"
SERIAL="$RAW_DIR/serial-$STAMP.txt"
for _ in $(seq 1 180); do
  sleep 10
  gcloud compute instances get-serial-port-output "$NAME" --project "$PROJECT" --zone "$ZONE" > "$SERIAL" 2>/dev/null || true
  grep -q "===E2E-END===" "$SERIAL" && break
done
grep -q "===E2E-END===" "$SERIAL" || { echo "no results after 30 minutes"; tail -40 "$SERIAL"; exit 1; }
echo "serial capture: $SERIAL ($(shasum -a 256 "$SERIAL" | cut -d' ' -f1))"
"$E2E/decode-results.sh" "$SERIAL" "$HERE/evidence"
# decode-results names the directory by the guest's stamp; the runner's records sit beside it.
GUEST=""
for d in "$HERE"/evidence/*/; do d="${d%/}"; [ "$(basename "$d")" = "$STAMP" ] && continue; [ "$d" \> "$GUEST" ] && GUEST="$d"; done
[ -n "$GUEST" ] || { echo "no decoded guest record"; exit 1; }
GUEST_STAMP="$(basename "$GUEST")"
mv "$EVIDENCE/verify" "$GUEST/verify" && rmdir "$EVIDENCE"
echo "evidence: $GUEST"
grep -E 'image|exit=|refused|session opened|gate_level|audit verify|elapsed' "$GUEST/steps.txt" | sed 's|^|  |'
grep -q 'gate_level=EXACT' "$GUEST/steps.txt" && grep -q 'audit verify exit=0' "$GUEST/steps.txt" && grep -q 'rogue refused' "$GUEST/steps.txt" \
  && echo "PASS: the Return Path from the release images on SEV-SNP ($GUEST_STAMP)" || { echo "FAIL: see $GUEST/steps.txt"; exit 1; }
