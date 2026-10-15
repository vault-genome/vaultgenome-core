#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The Return Path on an air-gapped host: one SEV-SNP Confidential VM that
# fills its verifiers' caches while connected (`acpctl tee prefetch`), is
# then put behind a firewall rule that denies all egress, and runs the
# Return Path — handshake, gate job, audit — from the caches alone; then
# the negative (the caches wiped: the handshake refused, naming KDS) and
# the recovery (the caches restored from a copy: a job gated again).
#
# The guest script (cvm-airgap.sh) prints ===AIRGAP-READY=== on its serial
# console when the caches are filled; this runner then adds the network
# tag the firewall rule targets, and the guest, seeing the tag in its
# metadata, waits for KDS to stop answering before it goes on. Results
# come back on the serial console and are decoded with the Return Path
# kit's decode-results.sh into evidence/<stamp>/; the runner's own marks
# (when the tag was added, what the firewall rule says) go beside them.
#
# Usage: run.sh <project> [zone]   (default zone us-central1-c)
set -euo pipefail

PROJECT="${1:?usage: run.sh <project> [zone]}"
ZONE="${2:-us-central1-c}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
RP="$ROOT/scripts/hardware-test/gcp-sev-snp/returnpath-e2e"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
NAME="vg-airgap-$LOW"
BUCKET="$PROJECT-vg-airgap-$LOW"
TAG="vg-airgap-$LOW"
RULE="vg-airgap-deny-egress-$LOW"
BUILD="$(mktemp -d)"
RUNNER="$BUILD/runner-timeline.txt"
now() { date -u +%Y-%m-%dT%H:%M:%S.%NZ 2>/dev/null || python3 -c 'import datetime; print(datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f000Z"))'; }
mark() { echo "$1=$(now)" | tee -a "$RUNNER"; }

cleanup() {
  echo "cleanup: deleting $NAME, gs://$BUCKET and the firewall rule $RULE"
  gcloud compute instances delete "$NAME" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  gcloud compute firewall-rules delete "$RULE" --project "$PROJECT" --quiet >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

echo "build (linux/amd64)"
( cd "$ROOT" && for b in sagvd acp-compute acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
( cd "$ROOT/workers" && COPYFILE_DISABLE=1 tar czf "$BUILD/genome-worker.tgz" --no-xattrs --exclude '__pycache__' --exclude '.pytest_cache' genome )
( cd "$BUILD" && shasum -a 256 sagvd acp-compute acpctl keygen genome-worker.tgz ) > "$BUILD/inputs.sha256"

echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD"/sagvd "$BUILD"/acp-compute "$BUILD"/acpctl "$BUILD"/keygen "$BUILD"/genome-worker.tgz "gs://$BUCKET/e2e/" --project "$PROJECT" >/dev/null

echo "firewall rule $RULE: deny all egress from instances tagged $TAG (priority 100)"
gcloud compute firewall-rules create "$RULE" --project "$PROJECT" --network default \
  --direction EGRESS --action DENY --rules all --destination-ranges 0.0.0.0/0 \
  --target-tags "$TAG" --priority 100 \
  --description "vaultgenome air-gap drill $STAMP: no egress for the tagged guest" >/dev/null
gcloud compute firewall-rules describe "$RULE" --project "$PROJECT" --format=json > "$BUILD/firewall-rule.json"

echo "boot $NAME (SEV-SNP, $ZONE), not yet tagged"
mark vm_create_issued
gcloud compute instances create "$NAME" --project "$PROJECT" --zone "$ZONE" \
  --machine-type n2d-standard-4 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --boot-disk-size 20GB \
  --scopes storage-ro --metadata "vg-bucket=$BUCKET,vg-tag=$TAG" \
  --metadata-from-file "startup-script=$HERE/cvm-airgap.sh" >/dev/null
mark vm_created

RAW_DIR="${VG_E2E_RAW_DIR:-$HOME/.cache/vaultgenome/air-gap}"
mkdir -p "$RAW_DIR"
SERIAL="$RAW_DIR/serial-$STAMP.txt"
echo "waiting for the guest to fill its caches and say ===AIRGAP-READY=== (up to 15 min)"
for _ in $(seq 1 90); do
  sleep 10
  gcloud compute instances get-serial-port-output "$NAME" --project "$PROJECT" --zone "$ZONE" > "$SERIAL" 2>/dev/null || true
  grep -q "===AIRGAP-READY===" "$SERIAL" && break
done
grep -q "===AIRGAP-READY===" "$SERIAL" || { echo "the guest never said it was ready"; tail -40 "$SERIAL"; exit 1; }
mark guest_ready
echo "cutting egress: adding the tag $TAG to $NAME"
gcloud compute instances add-tags "$NAME" --project "$PROJECT" --zone "$ZONE" --tags "$TAG" >/dev/null
mark tag_added
gcloud compute instances describe "$NAME" --project "$PROJECT" --zone "$ZONE" --format='value(tags.items)' > "$BUILD/instance-tags.txt"
echo "instance tags now: $(cat "$BUILD/instance-tags.txt")"

echo "waiting for results on the serial console (up to 25 min)"
for _ in $(seq 1 150); do
  sleep 10
  gcloud compute instances get-serial-port-output "$NAME" --project "$PROJECT" --zone "$ZONE" > "$SERIAL" 2>/dev/null || true
  grep -q "===E2E-END===" "$SERIAL" && break
done
grep -q "===E2E-END===" "$SERIAL" || { echo "no results after 25 minutes"; tail -40 "$SERIAL"; exit 1; }
mark results_seen
echo "serial capture: $SERIAL ($(shasum -a 256 "$SERIAL" | cut -d' ' -f1))"

DECODED="$("$RP/decode-results.sh" "$SERIAL" "$HERE/evidence" | tee /dev/stderr)"
EVIDENCE="$(printf '%s\n' "$DECODED" | sed -n 's/.* -> //p' | tail -1)"
if [ -d "$EVIDENCE" ]; then
  cp "$RUNNER" "$EVIDENCE/runner-timeline.txt"
  cp "$BUILD/firewall-rule.json" "$EVIDENCE/firewall-rule.json"
  cp "$BUILD/instance-tags.txt" "$EVIDENCE/instance-tags.txt"
  cp "$BUILD/inputs.sha256" "$EVIDENCE/inputs.built.sha256"
  { echo "tree $(git -C "$ROOT" rev-parse --short HEAD)"; echo "stamp $STAMP"; echo "zone $ZONE"; echo "firewall_rule $RULE"; echo "tag $TAG"; } > "$EVIDENCE/run.txt"
  echo "evidence: $EVIDENCE"
  echo "--- steps.txt"; cat "$EVIDENCE/steps.txt"
fi
