#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The boot chain of a GCP AMD SEV-SNP guest, as the chip and the vTPM each see
# it, over four boots of one Confidential VM (cvm-boot-chain.sh):
#
#   A  the image's first boot: both evidence sources captured;
#   B  the same kernel: captured; one text sealed with the chip's derived key
#      and with the vTPM under three PCR selections (probe/main.go);
#   C  the same kernel again: captured; every seal opened;
#   D  another kernel: captured; every seal opened.
#
# What it shows: whether the chip's launch measurement and its sealing key
# change when the guest's kernel does, and whether the vTPM's do. The run:
#
#   1. builds the probe for linux/amd64 from this tree and puts it in a new
#      private bucket;
#   2. boots an n2d SEV-SNP VM with a vTPM whose startup script is
#      cvm-boot-chain.sh, and reads its serial console as it grows (each read
#      from where the last ended, so no boot's output scrolls away);
#   3. decodes the four captures into evidence/<stamp>/{A,B,C,D} and writes
#      run.txt;
#   4. deletes the VM and the bucket, also on failure.
#
# Cost: one n2d-standard-4 for about half an hour. Usage: run.sh <project> [zone]
set -euo pipefail

PROJECT="${1:?usage: run.sh <project> [zone]}"
ZONE="${2:-us-central1-c}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOWER="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
NAME="vg-bootchain-$LOWER"
BUCKET="$PROJECT-vg-bc-$LOWER"
BUILD="$(mktemp -d)"
EVID="$HERE/evidence/$STAMP"
RAW_DIR="${VG_E2E_RAW_DIR:-$HOME/.cache/vaultgenome/boot-chain}"
SERIAL="$RAW_DIR/serial-$STAMP.txt"

cleanup() {
  set +e
  echo "cleanup: deleting $NAME and gs://$BUCKET"
  gcloud compute instances delete "$NAME" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1
  rm -rf "$BUILD"
}
trap cleanup EXIT

echo "build the probe (linux/amd64) from $(git -C "$ROOT" rev-parse --short HEAD)"
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/probe" ./scripts/hardware-test/gcp-sev-snp/boot-chain/probe )

echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/probe" "gs://$BUCKET/bc/probe" --project "$PROJECT" >/dev/null

echo "boot $NAME (SEV-SNP with a vTPM, $ZONE)"
gcloud compute instances create "$NAME" --project "$PROJECT" --zone "$ZONE" \
  --machine-type n2d-standard-4 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --boot-disk-size 20GB --shielded-vtpm --shielded-integrity-monitoring \
  --scopes storage-ro --metadata "vg-bucket=$BUCKET,vg-stamp=$STAMP" \
  --metadata-from-file "startup-script=$HERE/cvm-boot-chain.sh" >/dev/null

mkdir -p "$RAW_DIR" "$EVID"
gcloud compute instances describe "$NAME" --project "$PROJECT" --zone "$ZONE" \
  --format 'yaml(machineType.basename(),cpuPlatform,confidentialInstanceConfig,shieldedInstanceConfig,scheduling.onHostMaintenance)' > "$EVID/instance.yaml"

echo "waiting for four boots on the serial console (up to 60 min)"
: > "$SERIAL"
NEXT=0
for _ in $(seq 1 360); do
  sleep 10
  gcloud compute instances get-serial-port-output "$NAME" --project "$PROJECT" --zone "$ZONE" --start "$NEXT" > "$BUILD/chunk" 2> "$BUILD/chunk.err" || continue
  cat "$BUILD/chunk" >> "$SERIAL"
  N="$(sed -n 's/.*--start=\([0-9][0-9]*\).*/\1/p' "$BUILD/chunk.err" | tail -1)"
  [ -n "$N" ] && NEXT="$N"
  grep -q "===VGBC-DONE===" "$SERIAL" && break
done
echo "serial capture: $SERIAL ($(shasum -a 256 "$SERIAL" | cut -d' ' -f1))"

"$HERE/decode.sh" "$SERIAL" "$EVID"
cat "$EVID/run.txt"
grep -q "===VGBC-DONE===" "$SERIAL" || { echo "FAIL: the fourth boot never finished"; exit 1; }
