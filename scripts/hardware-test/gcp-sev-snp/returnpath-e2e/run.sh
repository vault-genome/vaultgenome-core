#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs the Return Path on real AMD SEV-SNP: sagvd and acp-compute, both
# attesting with the chip (ADR 0014), a genome fine-tuned by the real
# vg_genome worker on the guest and restored by the worker's door, judged
# and put on the record. On a fresh GCP Confidential VM:
#
#   1. builds sagvd, acp-compute, acpctl and acp-keygen for linux/amd64 from this tree;
#   2. uploads them, the worker package (workers/genome) and the AMD Milan
#      cert chain to a new private bucket;
#   3. boots an n2d SEV-SNP VM whose startup script is cvm-returnpath.sh;
#   4. waits for the results on the serial console, decodes and checks them;
#   5. deletes the VM and the bucket — always, also on failure.
#
# Cost: one n2d-standard-4 for about fifteen minutes (the guest installs the
# pinned CPU torch). Requires gcloud logged in to a project with the Compute
# and Storage APIs enabled.
#
# Usage: run.sh <project> [zone] [profile]   (default zone us-central1-c;
# profile general, fips or cnsa — ADR 0029 — written into sagvd's
# configuration when given; unset, the daemon's default applies)
# VG_SEALER=tpm2 seals both daemons' key files with the guest's vTPM
# instead of the chip's derived key (tee.sealer, ADR 0025 step 1b); the
# guest then installs tpm2-tools.
set -euo pipefail

PROJECT="${1:?usage: run.sh <project> [zone] [profile]}"
ZONE="${2:-us-central1-c}"
PROFILE="${3:-}"
case "$PROFILE" in ""|general|fips|cnsa) ;; *) echo "profile must be general, fips or cnsa; got $PROFILE"; exit 2;; esac
# VG_FIPS=1 (ADR 0030, part two): the binaries are built on the certified
# Go Cryptographic Module (GOFIPS140=v1.0.0) and the guest's daemons run
# under GODEBUG=fips140=only — the assessment mode, in which a call to a
# non-approved service fails instead of succeeding — so a run that passes
# shows the product invoked approved services only. general is refused up
# front: its first suite is X25519, unavailable under enforcement.
VG_FIPS="${VG_FIPS:-}"
if [ "$VG_FIPS" = 1 ]; then
  [ -n "$PROFILE" ] || PROFILE=fips
  [ "$PROFILE" != general ] || { echo "VG_FIPS=1 needs the fips or cnsa profile: general's first suite is X25519, unavailable under enforcement"; exit 2; }
  export GOFIPS140=v1.0.0
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="vg-returnpath-$(echo "$STAMP" | tr 'A-Z' 'a-z')"
BUCKET="$PROJECT-vg-rp-$(echo "$STAMP" | tr 'A-Z' 'a-z')"
BUILD="$(mktemp -d)"

cleanup() {
  echo "cleanup: deleting $NAME and gs://$BUCKET"
  gcloud compute instances delete "$NAME" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree prune >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

echo "build (linux/amd64)"
# Build from a clean checkout of HEAD when the tracked tree is clean, so the
# binaries' VCS stamp is the commit's even while other kits write their
# records into the tree (untracked files mark a build modified; on
# 2026-10-21 the binaries of a release record came out "-dirty" for that
# reason); a tree with modified tracked files builds from the working tree,
# stamped so.
SRC="$ROOT"
if [ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]; then
  SRC="$BUILD/src"; git -C "$ROOT" worktree add -q --detach "$SRC" HEAD
fi
( cd "$SRC" && for b in sagvd acp-compute acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$SRC" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
( cd "$SRC/workers" && COPYFILE_DISABLE=1 tar czf "$BUILD/genome-worker.tgz" --no-xattrs --exclude '__pycache__' --exclude '.pytest_cache' genome )
[ "$SRC" = "$ROOT" ] || git -C "$ROOT" worktree remove --force "$SRC"

echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD"/* "gs://$BUCKET/e2e/" --project "$PROJECT" >/dev/null

echo "boot $NAME (SEV-SNP, $ZONE)"
gcloud compute instances create "$NAME" --project "$PROJECT" --zone "$ZONE" \
  --machine-type n2d-standard-4 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --boot-disk-size 20GB \
  --scopes storage-ro --metadata "vg-bucket=$BUCKET,vg-sealer=${VG_SEALER:-auto},vg-profile=$PROFILE,vg-fips=${VG_FIPS:-0},vg-stamp=$STAMP" \
  --metadata-from-file "startup-script=$HERE/cvm-returnpath.sh" >/dev/null

echo "waiting for results on the serial console (up to 25 min)"
RAW_DIR="${VG_E2E_RAW_DIR:-$HOME/.cache/vaultgenome/returnpath-e2e}"
mkdir -p "$RAW_DIR"
SERIAL="$RAW_DIR/serial-$STAMP.txt"
for _ in $(seq 1 150); do
  sleep 10
  gcloud compute instances get-serial-port-output "$NAME" --project "$PROJECT" --zone "$ZONE" > "$SERIAL" 2>/dev/null || true
  grep -q "===E2E-END===" "$SERIAL" && break
done
grep -q "===E2E-END===" "$SERIAL" || { echo "no results after 25 minutes"; tail -40 "$SERIAL"; exit 1; }
echo "serial capture: $SERIAL ($(shasum -a 256 "$SERIAL" | cut -d' ' -f1))"

DECODED="$("$HERE/decode-results.sh" "$SERIAL" "$HERE/evidence")"; echo "$DECODED"

# The run's verdict: both rogues refused, the session opened, the job
# succeeded with the gate EXACT, the audit log verified. The guest's record
# is the one decode-results named (runs may overlap).
GUEST="$HERE/evidence/$(printf '%s\n' "$DECODED" | sed -n 's/^decoded \([^:]*\):.*/\1/p' | tail -1)"
STEPS="$GUEST/steps.txt"
[ -s "$STEPS" ] || { echo "FAIL: no steps.txt under $GUEST"; exit 1; }
grep -E 'profile=|fips=|sealer=|exit=|refused|session opened|job status=|gate_level=|^sagvd sev_snp_policy|^peer chip' "$STEPS" | sed 's|^|  |'
FIPS_OK=1
if [ "$VG_FIPS" = 1 ]; then
  # The record must say it: the daemons and acpctl on the certified module
  # with enforcement on (their version lines and the daemons' identities),
  # and the runner's note of what it built (build.txt, the runner's,
  # outside the guest's sums).
  for b in sagvd acp-compute acpctl keygen; do echo "$b: $(go version -m "$BUILD/$b" | awk '$1=="build" && ($2 ~ /^GOFIPS140=/ || $2 ~ /^vcs.revision=/) {printf "%s ", $2}')"; done > "$GUEST/build.txt"
  grep -E 'fips=|fips140' "$STEPS" "$GUEST/versions.txt" | sed 's|^|  |'
  [ "$(grep -c 'fips140=only module=v1.0.0 enforced=true' "$GUEST/versions.txt")" -ge 3 ] || FIPS_OK=0
  grep -q 'sagvd fips140 enabled=true enforced=true version=v1.0.0' "$STEPS" && grep -q 'acp-compute fips140 enabled=true enforced=true version=v1.0.0' "$STEPS" || FIPS_OK=0
fi
grep -q 'rogue with the sealed files exit=1' "$STEPS" && grep -q 'rogue refused after' "$STEPS" && grep -q 'session opened after' "$STEPS" \
  && grep -q 'job status=succeeded' "$STEPS" && grep -q 'gate_level=EXACT' "$STEPS" && grep -q 'audit verify exit=0' "$STEPS" && [ "$FIPS_OK" = 1 ] \
  && grep -q '^sagvd sev_snp_policy bulletins_read_on=20' "$STEPS" && grep -q '^peer chip product=' "$STEPS" \
  && echo "PASS: the Return Path on SEV-SNP${PROFILE:+ under $PROFILE}${VG_FIPS:+ on the certified module v1.0.0 with enforcement on} — both rogues refused, the job succeeded with the gate EXACT, the audit log verified ($(basename "$GUEST"))" \
  || { echo "FAIL: see $STEPS${VG_FIPS:+ (VG_FIPS=1: the record must show the certified module with enforcement on)}"; exit 1; }
