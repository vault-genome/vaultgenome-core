#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The reference deployment: the Return Path on real AMD SEV-SNP from the
# SIGNED RELEASE, not from this tree. What an operator who downloads a
# release does, recorded end to end:
#
#   1. downloads the release's assets (binaries, signatures, certificates,
#      SBOMs, SLSA provenance) and verifies every one: cosign keyless
#      signatures against the release workflow's identity, SLSA provenance
#      against the source tag, the tag's own signature against the keys
#      pinned on main;
#   2. takes the worker package and the key helper from the tag's source
#      (they are not release assets) and the AMD Milan chain from the tree;
#   3. runs the same guest script as gcp-sev-snp/returnpath-e2e on a fresh
#      n2d SEV-SNP Confidential VM: both daemons attest with the chip, a
#      rogue worker is refused, the pinned one is admitted, a gate job runs,
#      the verdict and the audit log come back;
#   4. decodes the results, keeps the verification records next to them,
#      and deletes the VM and the bucket — always, also on failure.
#
# Usage: run.sh <project> <tag> [zone]        (an n2d-standard-4 for ~15 min)
set -euo pipefail
PROJECT="${1:?usage: run.sh <project> <tag> [zone]}"
TAG="${2:?usage: run.sh <project> <tag> [zone]}"
ZONE="${3:-us-central1-c}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
E2E="$ROOT/scripts/hardware-test/gcp-sev-snp/returnpath-e2e"
REPO="vault-genome/vaultgenome-core"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
NAME="vg-release-$LOW"
BUCKET="$PROJECT-vg-rel-$LOW"
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

echo "== 1. download the release $TAG"
DL="$WORK/assets"; mkdir -p "$DL"
gh release download "$TAG" --repo "$REPO" --dir "$DL" >/dev/null
( cd "$DL" && sha256sum -- * ) | rec assets.sha256 >/dev/null
echo "assets: $(ls "$DL" | wc -l | tr -d ' ') files"

echo "== 2. verify every asset"
IDENTITY='^https://github\.com/vault-genome/vaultgenome-core/\.github/workflows/release\.yml@refs/tags/v'
ISSUER='https://token.actions.githubusercontent.com'
for b in sagvd acp-compute acpctl acp-bootstrap; do
  for f in "$b" "$b.sbom.spdx.json"; do
    sig="$f.sig"; cert="$f.cert"
    [ "$f" = "$b.sbom.spdx.json" ] && { sig="$b.sbom.sig"; cert="$b.sbom.cert"; }
    ( cd "$DL" && cosign verify-blob --signature "$sig" --certificate "$cert" \
        --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$f" ) 2>&1 | rec cosign.txt | tail -1 | sed "s|^|  $f: |"
  done
  ( cd "$DL" && slsa-verifier verify-artifact "$b" --provenance-path multiple.intoto.jsonl \
      --source-uri "github.com/$REPO" --source-tag "$TAG" ) 2>&1 | rec slsa.txt | tail -1 | sed "s|^|  $b: |"
done
( cd "$ROOT" && git fetch -q origin "refs/tags/$TAG:refs/tags/$TAG" 2>/dev/null || true
  git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag "$TAG" ) 2>&1 | rec tag.txt | tail -2 | sed 's|^|  tag: |'
{ echo "release: $TAG"; echo "verified at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; echo "cosign: $(cosign version 2>&1 | grep GitVersion | awk '{print $2}')"; echo "slsa-verifier: $(slsa-verifier version 2>&1 | grep GitVersion | awk '{print $2}')"; } | rec tools.txt >/dev/null
grep -c 'Verified OK' "$EVIDENCE/verify/cosign.txt" | sed 's/^/  cosign Verified OK: /'
grep -c 'PASSED: SLSA verification passed' "$EVIDENCE/verify/slsa.txt" | sed 's/^/  slsa PASSED: /'
test "$(grep -c 'Verified OK' "$EVIDENCE/verify/cosign.txt")" = 8 || { echo "ERROR: a signature did not verify"; exit 1; }
test "$(grep -c 'PASSED: SLSA verification passed' "$EVIDENCE/verify/slsa.txt")" = 4 || { echo "ERROR: a provenance did not verify"; exit 1; }
grep -q 'Good "git" signature' "$EVIDENCE/verify/tag.txt" || { echo "ERROR: the tag's signature did not verify against .github/allowed_signers"; exit 1; }

echo "== 2b. rebuild from the tag and compare with the released binaries (release procedure §5.4)"
REBUILD="$WORK/rebuild"
git clone -q --no-checkout "https://github.com/$REPO.git" "$REBUILD"
# The same inputs release.yml uses: the tag as VERSION, the full commit as
# COMMIT, the commit's time as SOURCE_DATE_EPOCH, CGO off, linux/amd64.
( cd "$REBUILD" && git checkout -q "$TAG" \
  && SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
     make -s build VERSION="$TAG" COMMIT="$(git rev-parse HEAD)" >/dev/null 2>&1 )
{
  echo "rebuilt from tag $TAG at $(git -C "$REBUILD" rev-parse HEAD) with $(go version | awk '{print $3}') on $(uname -sm)"
  for b in sagvd acp-compute acpctl acp-bootstrap; do
    r=$(sha256sum "$REBUILD/bin/$b" | awk '{print $1}'); d=$(sha256sum "$DL/$b" | awk '{print $1}')
    if [ "$r" = "$d" ]; then echo "$b: rebuilt sha256 equals the released file ($d)"; else echo "$b: MISMATCH rebuilt=$r released=$d"; fi
  done
} | rec rebuild.txt | sed 's|^|  |'
grep -q MISMATCH "$EVIDENCE/verify/rebuild.txt" && { echo "ERROR: a rebuilt binary differs from the released file"; exit 1; }

echo "== 3. the pieces that are not release assets, from the tag's source"
SRC="$WORK/src"; mkdir -p "$SRC"
( cd "$ROOT" && git archive "$TAG" deploy/compose/keygen workers/genome scripts/hardware-test/gcp-sev-snp/keybind-evidence ) | tar -x -C "$SRC"
BUILD="$WORK/build"; mkdir -p "$BUILD"
for b in sagvd acp-compute acpctl; do cp "$DL/$b" "$BUILD/$b"; chmod +x "$BUILD/$b"; done
( cd "$SRC/deploy/compose/keygen" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" . )
cp "$SRC/scripts/hardware-test/gcp-sev-snp/keybind-evidence/20260913T222343Z/kds-vcek-cert_chain.pem" "$BUILD/amd-milan-cert_chain.pem"
( cd "$SRC/workers" && COPYFILE_DISABLE=1 tar czf "$BUILD/genome-worker.tgz" --no-xattrs --exclude '__pycache__' --exclude '.pytest_cache' genome )
( cd "$BUILD" && sha256sum -- * ) | rec uploaded.sha256 >/dev/null
echo "  source for keygen, the worker package and the AMD chain: tag $TAG ($(cd "$ROOT" && git rev-parse "$TAG^{commit}" | cut -c1-12))" | rec tools.txt

echo "== 4. upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD"/* "gs://$BUCKET/e2e/" --project "$PROJECT" >/dev/null

echo "== 5. boot $NAME (SEV-SNP, $ZONE) with the Return Path guest script of the tree"
gcloud compute instances create "$NAME" --project "$PROJECT" --zone "$ZONE" \
  --machine-type n2d-standard-4 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --boot-disk-size 20GB \
  --scopes storage-ro --metadata "vg-bucket=$BUCKET" \
  --metadata-from-file "startup-script=$E2E/cvm-returnpath.sh" >/dev/null

echo "== 6. waiting for results on the serial console (up to 25 min)"
SERIAL="$WORK/serial-$STAMP.txt"
for _ in $(seq 1 150); do
  sleep 10
  gcloud compute instances get-serial-port-output "$NAME" --project "$PROJECT" --zone "$ZONE" > "$SERIAL" 2>/dev/null || true
  grep -q "===E2E-END===" "$SERIAL" && break
done
grep -q "===E2E-END===" "$SERIAL" || { echo "no results after 25 minutes"; tail -40 "$SERIAL"; exit 1; }
cp "$SERIAL" "$EVIDENCE/serial-console.txt"
# decode-results.sh names the directory after the guest's own stamp; the
# results move under this run's directory, next to the verification records.
DEC="$WORK/decoded"; mkdir -p "$DEC"
"$E2E/decode-results.sh" "$SERIAL" "$DEC"
mv "$DEC"/*/ "$EVIDENCE/results"
echo "evidence: $EVIDENCE"
ls "$EVIDENCE/results" | tr '\n' ' '; echo
