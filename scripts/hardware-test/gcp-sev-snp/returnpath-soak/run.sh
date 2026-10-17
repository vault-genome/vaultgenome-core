#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The soak on real AMD SEV-SNP (P1-5): sagvd and acp-compute, both attesting
# with the chip (ADR 0014), a genome fine-tuned by the real vg_genome worker
# on the guest, then one authority at max_sessions=N and N workers kept busy
# for VG_SOAK_MINUTES (60). On a fresh GCP Confidential VM:
#
#   1. builds sagvd, acp-compute, acpctl and acp-keygen for linux/amd64 from this tree;
#   2. uploads them, the worker package (workers/genome) and the AMD Milan
#      cert chain to a new private bucket;
#   3. boots an n2d SEV-SNP VM whose startup script is cvm-returnpath-soak.sh;
#   4. waits for the results on the serial console, decodes and checks them;
#   5. deletes the VM and the bucket — always, also on failure.
#
# Cost: one n2d-standard-8 for the soak plus about fifteen minutes (the
# guest installs the pinned CPU torch). Requires gcloud logged in to a
# project with the Compute and Storage APIs enabled.
#
# Usage: run.sh <project> [zone]   (default zone us-central1-c)
# VG_SEGMENT_EVENTS=N closes the audit log into segments of N events and
# VG_RETAIN_SECONDS=S expires finished jobs after S seconds (ADR 0027; both
# 0 = off, as 0.5.0 behaved); the snapshots then carry the files' sizes.
# VG_WORKERS=N (default 3) workers and 2N jobs in flight; VG_SOAK_MINUTES
# (default 60) the soak's length; VG_MACHINE (default n2d-standard-8) the
# guest's machine type: the workers are the real CPU door and contend for
# the cores.
set -euo pipefail

PROJECT="${1:?usage: run.sh <project> [zone]}"
ZONE="${2:-us-central1-c}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="vg-rp-soak-$(echo "$STAMP" | tr 'A-Z' 'a-z')"
BUCKET="$PROJECT-vg-soak-$(echo "$STAMP" | tr 'A-Z' 'a-z')"
BUILD="$(mktemp -d)"

cleanup() {
  echo "cleanup: deleting $NAME and gs://$BUCKET"
  gcloud compute instances delete "$NAME" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

echo "build (linux/amd64)"
( cd "$ROOT" && for b in sagvd acp-compute acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
( cd "$ROOT/workers" && COPYFILE_DISABLE=1 tar czf "$BUILD/genome-worker.tgz" --no-xattrs --exclude '__pycache__' --exclude '.pytest_cache' genome )

echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD"/* "gs://$BUCKET/e2e/" --project "$PROJECT" >/dev/null

echo "boot $NAME (SEV-SNP, $ZONE)"
gcloud compute instances create "$NAME" --project "$PROJECT" --zone "$ZONE" \
  --machine-type "${VG_MACHINE:-n2d-standard-8}" --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --boot-disk-size 20GB \
  --scopes storage-ro --metadata "vg-bucket=$BUCKET,vg-workers=${VG_WORKERS:-3},vg-soak-minutes=${VG_SOAK_MINUTES:-60},vg-segment-events=${VG_SEGMENT_EVENTS:-0},vg-retain-seconds=${VG_RETAIN_SECONDS:-0}" \
  --metadata-from-file "startup-script=$HERE/cvm-returnpath-soak.sh" >/dev/null

echo "waiting for results on the serial console (the soak plus 30 min)"
RAW_DIR="${VG_E2E_RAW_DIR:-$HOME/.cache/vaultgenome/returnpath-soak}"
mkdir -p "$RAW_DIR"
SERIAL="$RAW_DIR/serial-$STAMP.txt"
for i in $(seq 1 $(( (${VG_SOAK_MINUTES:-60} + 30) * 2 ))); do
  sleep 30
  gcloud compute instances get-serial-port-output "$NAME" --project "$PROJECT" --zone "$ZONE" > "$SERIAL" 2>/dev/null || true
  grep -q "===E2E-END===" "$SERIAL" && break
done
grep -q "===E2E-END===" "$SERIAL" || { echo "no results after the soak plus 30 minutes"; tail -40 "$SERIAL"; exit 1; }
echo "serial capture: $SERIAL ($(shasum -a 256 "$SERIAL" | cut -d' ' -f1))"

"$HERE/../returnpath-e2e/decode-results.sh" "$SERIAL" "$HERE/evidence"
