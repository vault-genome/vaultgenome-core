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
#   2. rebuilds the five binaries and the worker package from the tag and
#      requires every hash to equal the released file's; nothing is taken
#      from this tree — the guest fetches the AMD chain from KDS with the
#      released acpctl, which verifies it against the roots the binary
#      pins (ADR 0024);
#   3. runs the same guest script as gcp-sev-snp/returnpath-e2e on a fresh
#      n2d SEV-SNP Confidential VM: both daemons attest with the chip, a
#      rogue worker is refused, the pinned one is admitted, a gate job runs,
#      the verdict and the audit log come back;
#   4. decodes the results, keeps the verification records next to them,
#      and deletes the VM and the bucket — always, also on failure.
#
# Usage: run.sh <project> <tag> [zone]        (an n2d-standard-4 for ~15 min)
# Needs gh, cosign, slsa-verifier, go, gcloud, and for the package rebuild
# GNU tar and GNU gzip (tar and gzip on Linux; gtar and gzip from Homebrew
# on macOS — Apple's gzip writes a different deflate stream for the same
# tar, so the file would not match although its contents do).
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
WORKER_PKG="genome-worker-$TAG.tar.gz"
# The six artifacts: five binaries and the worker package. Each has a
# signature, a certificate and an SBOM signed the same way.
for b in sagvd acp-compute acpctl acp-bootstrap acp-keygen "$WORKER_PKG"; do
  sbom="$b.sbom.spdx.json"; sbomsig="$b.sbom.sig"; sbomcert="$b.sbom.cert"
  [ "$b" = "$WORKER_PKG" ] && { sbom="genome-worker-$TAG.sbom.spdx.json"; sbomsig="genome-worker-$TAG.sbom.sig"; sbomcert="genome-worker-$TAG.sbom.cert"; }
  for f in "$b" "$sbom"; do
    sig="$f.sig"; cert="$f.cert"
    [ "$f" = "$sbom" ] && { sig="$sbomsig"; cert="$sbomcert"; }
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
test "$(grep -c 'Verified OK' "$EVIDENCE/verify/cosign.txt")" = 12 || { echo "ERROR: a signature did not verify"; exit 1; }
# From 0.4.3 the release carries a Sigstore bundle beside each pair: the
# same twelve files verified from their bundles with the Sigstore trust
# root as a file (cosign initialize fetches it) and no route — the check
# an air-gapped site runs. On macOS the route is taken away from cosign
# with sandbox-exec; elsewhere the check runs with the route and says so.
if [ "$(ls "$DL"/*.sigstore.json 2>/dev/null | wc -l | tr -d ' ')" = 12 ]; then
  cosign initialize 2>&1 | rec cosign-initialize.txt >/dev/null || true
  TRUSTED_ROOT="$(find "${TUF_ROOT:-$HOME/.sigstore/root}" -name trusted_root.json 2>/dev/null | head -1)"
  [ -n "$TRUSTED_ROOT" ] || { echo "ERROR: no trusted_root.json in cosign's TUF cache after cosign initialize"; exit 1; }
  cp "$TRUSTED_ROOT" "$DL/trusted_root.json"
  echo "  trusted_root.json: sha256 $(shasum -a 256 "$DL/trusted_root.json" | awk '{print $1}')" | rec tools.txt
  if command -v sandbox-exec >/dev/null 2>&1; then NONET=(sandbox-exec -p '(version 1)(allow default)(deny network*)' env TUF_ROOT=/nonexistent); echo "  the bundle check runs with the network denied (sandbox-exec)"; else NONET=(env); echo "  the bundle check runs with the route (no sandbox-exec here)"; fi
  for b in sagvd acp-compute acpctl acp-bootstrap acp-keygen "$WORKER_PKG"; do
    sbom="$b.sbom.spdx.json"; sbombundle="$b.sbom.sigstore.json"
    [ "$b" = "$WORKER_PKG" ] && { sbom="genome-worker-$TAG.sbom.spdx.json"; sbombundle="genome-worker-$TAG.sbom.sigstore.json"; }
    for f in "$b" "$sbom"; do
      bundle="$f.sigstore.json"; [ "$f" = "$sbom" ] && bundle="$sbombundle"
      ( cd "$DL" && "${NONET[@]}" cosign verify-blob --new-bundle-format --bundle "$bundle" --trusted-root trusted_root.json \
          --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$f" ) 2>&1 | rec cosign-bundle-nonet.txt | tail -1 | sed "s|^|  bundle, no route, $f: |"
    done
  done
  grep -c 'Verified OK' "$EVIDENCE/verify/cosign-bundle-nonet.txt" | sed 's/^/  cosign bundle with --trusted-root Verified OK: /'
  test "$(grep -c 'Verified OK' "$EVIDENCE/verify/cosign-bundle-nonet.txt")" = 12 || { echo "ERROR: a bundle did not verify with --trusted-root"; exit 1; }
else
  echo "  no Sigstore bundles in this release (before 0.4.3): the pairs only"
fi
test "$(grep -c 'PASSED: SLSA verification passed' "$EVIDENCE/verify/slsa.txt")" = 6 || { echo "ERROR: a provenance did not verify"; exit 1; }
grep -q 'Good "git" signature' "$EVIDENCE/verify/tag.txt" || { echo "ERROR: the tag's signature did not verify against .github/allowed_signers"; exit 1; }

echo "== 2b. rebuild from the tag and compare with the released binaries and package (release procedure §5.4)"
REBUILD="$WORK/rebuild"
git clone -q --no-checkout "https://github.com/$REPO.git" "$REBUILD"
# The same inputs release.yml uses: the tag as VERSION, the full commit as
# COMMIT, the commit's time as SOURCE_DATE_EPOCH, CGO off, linux/amd64;
# the package with the same tar flags (GNU tar: gtar on macOS) and GNU
# gzip: the same tar compressed by Apple's gzip is a different file (the
# rehearsal of 0.4.2 found it), so a gzip that is not GNU's stops the run.
GTAR="$(command -v gtar || command -v tar)"
GZIP_BIN=""
for c in /opt/homebrew/bin/gzip /usr/local/bin/gzip "$(command -v gzip)"; do
  [ -x "$c" ] && "$c" --version 2>&1 | grep -qE 'GNU|Free Software Foundation' && { GZIP_BIN="$c"; break; }
done
[ -n "$GZIP_BIN" ] || { echo "ERROR: the package rebuild needs GNU gzip (brew install gzip on macOS); $(gzip --version 2>&1 | head -1) is not it"; exit 1; }
( cd "$REBUILD" && git checkout -q "$TAG" \
  && SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
     make -s build VERSION="$TAG" COMMIT="$(git rev-parse HEAD)" >/dev/null 2>&1 \
  && SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
     "$GTAR" --sort=name --mtime="@$(git log -1 --format=%ct)" --owner=0 --group=0 --numeric-owner \
       --exclude='__pycache__' --exclude='.pytest_cache' -C workers -cf - genome | "$GZIP_BIN" -n > "$REBUILD/$WORKER_PKG" )
{
  echo "rebuilt from tag $TAG at $(git -C "$REBUILD" rev-parse HEAD) with $(go version | awk '{print $3}'), $("$GTAR" --version | head -1) and $("$GZIP_BIN" --version | head -1) on $(uname -sm)"
  for b in sagvd acp-compute acpctl acp-bootstrap acp-keygen; do
    r=$(sha256sum "$REBUILD/bin/$b" | awk '{print $1}'); d=$(sha256sum "$DL/$b" | awk '{print $1}')
    if [ "$r" = "$d" ]; then echo "$b: rebuilt sha256 equals the released file ($d)"; else echo "$b: MISMATCH rebuilt=$r released=$d"; fi
  done
  r=$(sha256sum "$REBUILD/$WORKER_PKG" | awk '{print $1}'); d=$(sha256sum "$DL/$WORKER_PKG" | awk '{print $1}')
  if [ "$r" = "$d" ]; then echo "$WORKER_PKG: repacked sha256 equals the released file ($d)"; else echo "$WORKER_PKG: MISMATCH repacked=$r released=$d"; fi
} | rec rebuild.txt | sed 's|^|  |'
grep -q MISMATCH "$EVIDENCE/verify/rebuild.txt" && { echo "ERROR: a rebuilt artifact differs from the released file"; exit 1; }

echo "== 3. what goes to the guest: the released binaries and package, nothing from this tree"
BUILD="$WORK/build"; mkdir -p "$BUILD"
for b in sagvd acp-compute acpctl; do cp "$DL/$b" "$BUILD/$b"; chmod +x "$BUILD/$b"; done
# The guest script names the helper and the package by their old names.
cp "$DL/acp-keygen" "$BUILD/keygen"; chmod +x "$BUILD/keygen"
cp "$DL/$WORKER_PKG" "$BUILD/genome-worker.tgz"
( cd "$BUILD" && sha256sum -- * ) | rec uploaded.sha256 >/dev/null
echo "  every uploaded file is a release asset of $TAG; the guest fetches the AMD Milan chain from KDS with the released acpctl (tee fetch-amd-chain)" | rec tools.txt

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
