#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs the SEV-SNP key-release and genome-restore end-to-end test on a fresh GCP Confidential
# VM and brings the results back:
#
#   1. builds sagvd, acp-bootstrap, acpctl and keygen for linux/amd64 from this tree;
#   2. uploads them (with the AMD Milan cert chain) to a new private bucket;
#   3. boots an n2d SEV-SNP VM whose startup script is cvm-keyrelease.sh;
#   4. waits for the results on the serial console, decodes and checks them;
#   5. deletes the VM and the bucket — always, also on failure.
#
# Cost: one n2d-standard-2 for about ten minutes. Requires gcloud logged in
# to a project with the Compute and Storage APIs enabled.
#
# Usage: run.sh <project> [zone] [profile]   (default zone us-central1-b;
# profile general, fips or cnsa — the cryptographic profile of ADR 0029
# both daemons run under, written into their configs on the guest)
set -euo pipefail

PROJECT="${1:?usage: run.sh <project> [zone] [profile]}"
ZONE="${2:-us-central1-b}"
PROFILE="${3:-general}"
case "$PROFILE" in general|fips|cnsa) ;; *) echo "profile must be general, fips or cnsa; got $PROFILE"; exit 2;; esac
# VG_FIPS=1 (ADR 0030, part two): the binaries are built on the certified
# Go Cryptographic Module (GOFIPS140=v1.0.0) and the guest's daemons run
# under GODEBUG=fips140=only — the assessment mode, in which a call to a
# non-approved service fails instead of succeeding — so a run that passes
# shows the product invoked approved services only. general is refused up
# front: its first suite is X25519, unavailable under enforcement.
VG_FIPS="${VG_FIPS:-}"
if [ "$VG_FIPS" = 1 ]; then
  [ "$PROFILE" != general ] || { echo "VG_FIPS=1 needs the fips or cnsa profile: general's first suite is X25519, unavailable under enforcement"; exit 2; }
  export GOFIPS140=v1.0.0
fi
# The signature suite (ADR 0031, part three): the profile signs with its
# own — ed25519 under general and fips, ecdsa-p384-sha384 under cnsa —
# unless VG_SIGSUITE picks another the profile accepts (fips with
# ecdsa-p384-sha384 is the deployment a bank held to X9 runs). Written
# into acp-keygen, every key file and every config on the guest.
case "$PROFILE" in cnsa) SIGSUITE_DEFAULT=ecdsa-p384-sha384;; *) SIGSUITE_DEFAULT=ed25519;; esac
SIGSUITE="${VG_SIGSUITE:-$SIGSUITE_DEFAULT}"
case "$SIGSUITE" in ed25519|ecdsa-p384-sha384|ml-dsa-87) ;; *) echo "VG_SIGSUITE must be ed25519, ecdsa-p384-sha384 or ml-dsa-87; got $SIGSUITE"; exit 2;; esac
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="vg-keyrelease-$(echo "$STAMP" | tr 'A-Z' 'a-z')"
BUCKET="$PROJECT-vg-e2e-$(echo "$STAMP" | tr 'A-Z' 'a-z')"
BUILD="$(mktemp -d)"
CHAIN="$ROOT/scripts/hardware-test/gcp-sev-snp/keybind-evidence/20260913T222343Z/kds-vcek-cert_chain.pem"

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
( cd "$SRC" && for b in sagvd acp-bootstrap acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$SRC" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
[ "$SRC" = "$ROOT" ] || git -C "$ROOT" worktree remove --force "$SRC"
cp "$CHAIN" "$BUILD/amd-milan-cert_chain.pem"

echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD"/* "gs://$BUCKET/e2e/" --project "$PROJECT" >/dev/null

echo "boot $NAME (SEV-SNP, $ZONE)"
gcloud compute instances create "$NAME" --project "$PROJECT" --zone "$ZONE" \
  --machine-type n2d-standard-2 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --scopes storage-ro --metadata "vg-bucket=$BUCKET,vg-profile=$PROFILE,vg-fips=${VG_FIPS:-0},vg-sigsuite=$SIGSUITE,vg-stamp=$STAMP" \
  --metadata-from-file "startup-script=$HERE/cvm-keyrelease.sh" >/dev/null

echo "waiting for results on the serial console (up to 15 min)"
# The raw console capture (the whole boot log) is saved before anything is
# deleted, so a decoding failure never loses a run. It stays outside the
# repository; the decoded results under evidence/ are what gets committed.
RAW_DIR="${VG_E2E_RAW_DIR:-$HOME/.cache/vaultgenome/keyrelease-e2e}"
mkdir -p "$RAW_DIR"
SERIAL="$RAW_DIR/serial-$STAMP.txt"
for _ in $(seq 1 90); do
  sleep 10
  gcloud compute instances get-serial-port-output "$NAME" --project "$PROJECT" --zone "$ZONE" > "$SERIAL" 2>/dev/null || true
  grep -q "===E2E-END===" "$SERIAL" && break
done
grep -q "===E2E-END===" "$SERIAL" || { echo "no results after 15 minutes"; tail -40 "$SERIAL"; exit 1; }
echo "serial capture: $SERIAL ($(shasum -a 256 "$SERIAL" | cut -d' ' -f1))"

DECODED="$("$HERE/decode-results.sh" "$SERIAL" "$HERE/evidence")"; echo "$DECODED"

# The run's verdict: the release under the profile's suite, the restore
# confirmed, the two refusals, the audit log verified. The guest's record
# is the one decode-results named (runs may overlap).
GUEST="$HERE/evidence/$(printf '%s\n' "$DECODED" | sed -n 's/^decoded \([^:]*\):.*/\1/p' | tail -1)"
STEPS="$GUEST/steps.txt"
[ -s "$STEPS" ] || { echo "FAIL: no steps.txt under $GUEST"; exit 1; }
grep -E 'profile=|suite=|exit=' "$STEPS" | sed 's|^|  |'
case "$PROFILE" in general) WANT=hpke-x25519-v2;; fips) WANT=hpke-p384-v2;; cnsa) WANT=hpke-mlkem1024-p384-v2;; esac
FIPS_OK=1
if [ "$VG_FIPS" = 1 ]; then
  # The record must say it: both daemons on the certified module with
  # enforcement on (their version lines and their identities), and the
  # runner's note of what it built. build.txt is the runner's, outside the
  # guest's sums.
  for b in sagvd acp-bootstrap acpctl keygen; do echo "$b: $(go version -m "$BUILD/$b" | awk '$1=="build" && ($2 ~ /^GOFIPS140=/ || $2 ~ /^vcs.revision=/) {printf "%s ", $2}')"; done > "$GUEST/build.txt"
  grep -E 'fips=|fips140' "$STEPS" "$GUEST/versions.txt" | sed 's|^|  |'
  [ "$(grep -c 'fips140=only module=v1.0.0 enforced=true' "$GUEST/versions.txt")" = 2 ] || FIPS_OK=0
  grep -q 'sagvd fips140 enabled=true enforced=true version=v1.0.0' "$STEPS" && grep -q 'destination fips140 enabled=true enforced=true version=v1.0.0' "$STEPS" || FIPS_OK=0
fi
# The signature suite on the record (ADR 0031): the authority signs under
# it, the destination accepts it, the audit log verifies under it.
SIG_OK=1
grep -q "sagvd signature_suite=$SIGSUITE " "$STEPS" && grep -q "sagvd authority_signature_suite=$SIGSUITE audit_signature_suite=$SIGSUITE" "$STEPS" \
  && grep -E "^destination signature_suites=.*\b$SIGSUITE\b" "$STEPS" >/dev/null && grep -q "audit suite=$SIGSUITE" "$STEPS" || SIG_OK=0
grep -q "release exit=0" "$STEPS" && grep -q "release suite=$WANT" "$STEPS" && grep -q "release profile=$PROFILE" "$STEPS" \
  && grep -q "confirm exit=0" "$STEPS" && grep -q "verify exit=0" "$STEPS" \
  && grep -q "unlisted exit=1" "$STEPS" && grep -q "stopped exit=1" "$STEPS" && grep -q "audit verify exit=0" "$STEPS" && [ "$FIPS_OK" = 1 ] && [ "$SIG_OK" = 1 ] \
  && echo "PASS: key release under $PROFILE ($WANT; signatures $SIGSUITE)${VG_FIPS:+ on the certified module v1.0.0 with enforcement on}, restore confirmed, refusals refused, audit verified ($(basename "$GUEST"))" \
  || { echo "FAIL: see $STEPS${VG_FIPS:+ (VG_FIPS=1: the record must show the certified module with enforcement on)} (signature suite $SIGSUITE must be on the record: SIG_OK=$SIG_OK)"; exit 1; }
