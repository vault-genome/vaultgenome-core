#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Training continuity on real hardware (ADR 0040), across two AMD SEV-SNP
# Confidential VMs of the same machine type: a model's training survives
# the loss of the machine it ran on, and goes on where the recipe would be.
#
#   1. builds sagvd, acp-bootstrap, acpctl and keygen for linux/amd64, and
#      packs workers/genome;
#   2. boots the STANDBY (standby.sh): the release authority and the
#      destination, on loopback TLS. Under an operator-signed policy whose
#      only trigger is a lost heartbeat and whose gate must be EXACT, it
#      waits, watching a replica of the primary's outbox;
#   3. boots the PRIMARY (primary.sh): it takes the recipe's first 80 steps
#      (generation 0), goes on from its own genome to step 160 (generation
#      1) and holds it to the whole recipe by replay; the sentinel seals
#      each generation. It goes on toward step 240 — and is switched off
#      while it trains, without a word, and deleted here, on the record;
#   4. the authority, on the heartbeat's silence, fails generation 1 over to
#      the standby, which restores it and recomputes its fixtures EXACT;
#   5. training goes on on the standby from the restored genome's state, to
#      step 240; the result is held to the whole recipe on that chip — by
#      replay from the first step, and file by file against the recipe run
#      there in one go;
#   6. brings the reports back to evidence/<stamp>/, checks them, and
#      deletes both VMs and the bucket — always, also on failure.
#
# Both machines attest with their own chip; the genome key crosses only as
# an escrow envelope opened by the authority and re-wrapped to the
# standby's attested per-handshake key (ADR 0009, 0011, 0012). The state
# training goes on from is inside the sealed genome (ADR 0040).
# Cost: two n2d-standard-8 SEV-SNP VMs for about forty minutes.
#
# Usage: run.sh <project> [zone]
set -euo pipefail

PROJECT="${1:?usage: run.sh <project> [zone]}"
ZONE="${2:-us-central1-c}"
MACHINE=n2d-standard-8
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
FAILOVER="$ROOT/scripts/hardware-test/gcp-failover"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
PRIMARY="vg-tc-primary-$LOW"
STANDBY="vg-tc-standby-$LOW"
BUCKET="$PROJECT-vg-tc-$LOW"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"; mkdir -p "$EVIDENCE"
RUNLOG="$EVIDENCE/runner.log"
CHAIN="$ROOT/scripts/hardware-test/gcp-sev-snp/keybind-evidence/20260913T222343Z/kds-vcek-cert_chain.pem"
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RUNLOG"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

cleanup() {
  set +e
  log "cleanup: deleting $PRIMARY, $STANDBY and gs://$BUCKET"
  gcloud compute instances delete "$PRIMARY" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1
  gcloud compute instances delete "$STANDBY" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1
  left="$(gcloud compute instances list --project "$PROJECT" --filter="name~^vg-tc-.*-$LOW\$" --format='value(name)' 2>/dev/null | tr '\n' ' ')"
  echo "instances of this run left after cleanup: ${left:-none} at $(now)" | tee "$EVIDENCE/vms-deleted.txt" >> "$RUNLOG"
  rm -rf "$BUILD"
}
trap cleanup EXIT

# wait_for <leg> <minutes>: DONE, FAILED or TIMEOUT.
wait_for() {
  local deadline=$(( $(date +%s) + $2 * 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for m in DONE FAILED; do
      if gcloud storage ls "gs://$BUCKET/out/$1/$m" --project "$PROJECT" >/dev/null 2>&1; then echo "$m"; return; fi
    done
    sleep 15
  done
  echo TIMEOUT
}

collect() {
  mkdir -p "$EVIDENCE/$1"
  if gcloud storage cp "gs://$BUCKET/out/$1.tgz" "$BUILD/$1.tgz" --project "$PROJECT" >/dev/null 2>&1; then
    tar -C "$EVIDENCE/$1" -xzf "$BUILD/$1.tgz" || true
  fi
}

log "== 0. build (linux/amd64) from $(git -C "$ROOT" rev-parse --short=12 HEAD) and pack workers/genome"
# Go stamps a binary as modified when `git status` prints anything, and this
# record's own directory is an untracked file by now. Untracked files are
# left out of that one question, for the build alone; code-dirty.txt below
# names every changed or untracked file of the code, the records aside.
( cd "$ROOT" && export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=status.showUntrackedFiles GIT_CONFIG_VALUE_0=no
  for b in sagvd acp-bootstrap acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
cp "$CHAIN" "$BUILD/amd-milan-cert_chain.pem"
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$BUILD/worker.tgz" -C "$ROOT/workers/genome" --exclude __pycache__ --exclude .pytest_cache vg_genome requirements.txt requirements-ci.lock requirements-cuda.lock requirements-torch-cpu.lock requirements-torch-cu126.lock examples
( cd "$BUILD" && shasum -a 256 sagvd acp-bootstrap acpctl keygen worker.tgz ) > "$EVIDENCE/binaries.sha256"
( cd "$HERE" && shasum -a 256 run.sh recipe.sh primary.sh standby.sh "$FAILOVER/common.sh" ) > "$EVIDENCE/kit.sha256"
git -C "$ROOT" rev-parse HEAD > "$EVIDENCE/code-rev.txt"
git -C "$ROOT" status --porcelain -- workers/genome cmd internal go.mod go.sum scripts/hardware-test/training-continuity scripts/hardware-test/gcp-failover/common.sh \
  ':(exclude)scripts/hardware-test/training-continuity/evidence' > "$EVIDENCE/code-dirty.txt"
[ -s "$EVIDENCE/code-dirty.txt" ] && log "   note: the tree differs from $(cut -c1-12 "$EVIDENCE/code-rev.txt") in $(wc -l < "$EVIDENCE/code-dirty.txt" | tr -d ' ') paths (code-dirty.txt)"

log "== 1. upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location "${ZONE%-*}" --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/sagvd" "$BUILD/acp-bootstrap" "$BUILD/acpctl" "$BUILD/keygen" \
  "$BUILD/amd-milan-cert_chain.pem" "$BUILD/worker.tgz" "gs://$BUCKET/in/" --project "$PROJECT" >/dev/null

boot() { # boot <name> <startup script>
  gcloud compute instances create "$1" --project "$PROJECT" --zone "$ZONE" \
    --machine-type "$MACHINE" --min-cpu-platform "AMD Milan" \
    --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
    --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --boot-disk-size 40GB \
    --scopes storage-rw --metadata "vg-bucket=$BUCKET" \
    --metadata-from-file "vg-common=$FAILOVER/common.sh,vg-recipe=$HERE/recipe.sh,startup-script=$2" >/dev/null
}

log "== 2. boot $STANDBY (SEV-SNP authority + destination, $MACHINE, $ZONE)"
boot "$STANDBY" "$HERE/standby.sh"
log "== 3. boot $PRIMARY (SEV-SNP workload + sentinel, $MACHINE, $ZONE)"
boot "$PRIMARY" "$HERE/primary.sh"

log "== 4. waiting for the primary to train, seal two generations and be lost (up to 45 min)"
PRIMARY_RESULT=$(wait_for primary 45)
log "   primary: $PRIMARY_RESULT"
collect primary
if [ "$PRIMARY_RESULT" = DONE ]; then
  log "   the primary has switched itself off: see it dead, then delete it — on the record"
  {
    echo "primary=$PRIMARY zone=$ZONE project=$PROJECT"
    for i in $(seq 1 30); do gcloud storage cp "gs://$BUCKET/out/primary-destroyed-at.txt" "$BUILD/primary-destroyed-at.txt" --project "$PROJECT" >/dev/null 2>&1 && break; sleep 2; done
    echo "powered_off_at (the primary's clock, written just before sysrq o)=$(cat "$BUILD/primary-destroyed-at.txt" 2>/dev/null)"
    for i in $(seq 1 60); do
      ST="$(gcloud compute instances describe "$PRIMARY" --project "$PROJECT" --zone "$ZONE" --format='value(status)' 2>&1 | head -1)"
      echo "$(now) status=$ST"
      case "$ST" in TERMINATED|STOPPED) break ;; esac
      sleep 2
    done
    echo "Google's record of the machine before it is deleted:"
    gcloud compute instances describe "$PRIMARY" --project "$PROJECT" --zone "$ZONE" \
      --format='yaml(name,zone.basename(),machineType.basename(),cpuPlatform,confidentialInstanceConfig,status,creationTimestamp,lastStartTimestamp,lastStopTimestamp)' 2>&1 | sed 's/^/  /'
    echo "$(now) delete: the machine and its boot disk"
    gcloud compute instances delete "$PRIMARY" --project "$PROJECT" --zone "$ZONE" --quiet 2>&1 | sed 's/^/  /'
    echo "$(now) delete returned"
    AFTER="$(gcloud compute instances describe "$PRIMARY" --project "$PROJECT" --zone "$ZONE" --format='value(status)' 2>&1 | tr '\n' ' ')"
    echo "$(now) after delete: $AFTER"
  } > "$EVIDENCE/operator-destroy.txt" 2>&1 || true
else
  gcloud compute instances delete "$PRIMARY" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
fi

log "== 5. waiting for the standby: the failover, then training going on there (up to 40 min)"
STANDBY_RESULT=$(wait_for standby 40)
log "   standby: $STANDBY_RESULT"
collect standby
gcloud compute instances describe "$STANDBY" --project "$PROJECT" --zone "$ZONE" \
  --format='yaml(name,zone.basename(),machineType.basename(),cpuPlatform,confidentialInstanceConfig,status,creationTimestamp)' > "$EVIDENCE/standby-instance.txt" 2>&1 || true

log "== 6. what was proven"
P="$EVIDENCE/primary"; S="$EVIDENCE/standby"
grep -E '^(generation 1: replay|toward step|sentinel running)' "$P/steps.txt" 2>/dev/null | sed 's/^/   primary  /' | tee -a "$RUNLOG" || true
grep -E '^(failover:|restored:|continued:|replay:|compare:|gate on the continued|CONTINUED EXACT)' "$S/steps.txt" 2>/dev/null | sed 's/^/   standby  /' | tee -a "$RUNLOG" || true
fail=0
ok()  { log "   ok    $1"; }
bad() { log "   FAIL  $1"; fail=1; }
exact() { python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); sys.exit(0 if r.get("exact") is True and r.get("losses_equal") is True and r.get("max_abs_diff")==0 else 1)' "$1" 2>/dev/null; }
cpu() { grep -m1 'Model name' "$1/system.txt" 2>/dev/null | sed 's/.*: *//'; }

[ "$PRIMARY_RESULT" = DONE ] && ok "the primary finished its part and switched itself off" || bad "the primary did not finish cleanly ($PRIMARY_RESULT)"
[ "$STANDBY_RESULT" = DONE ] && ok "the standby finished the failover and the continuation" || bad "the standby did not finish ($STANDBY_RESULT)"
log "   the machines: primary $(cpu "$P"), standby $(cpu "$S")"
[ -n "$(cpu "$P")" ] && [ "$(cpu "$P")" = "$(cpu "$S")" ] && ok "both machines report the same CPU model" || bad "the machines do not report the same CPU model"
if python3 -c 'import json,sys; t=json.load(open(sys.argv[1]))["training"]; sys.exit(0 if t["step"]==160 and [c["step"] for c in t["continued_from"]]==[80] else 1)' "$P/generation-1-training.json" 2>/dev/null; then
  ok "generation 1 stands at step 160, continued from the genome at step 80, on the primary"; else bad "generation 1 is not step 160 continued from step 80"; fi
exact "$P/replay-1.json" && ok "on the primary, replay holds generation 1 to the whole recipe: exact" || bad "the primary's replay of generation 1 is not exact"
if python3 - "$S/report.json" <<'PY' 2>/dev/null
import json, sys
r = json.load(open(sys.argv[1]))
ok = (r["status"] == "restored" and r["trigger"]["kind"] == "heartbeat-timeout" and r["genome"]["generation"] == 1
      and r["restore"]["gate"]["level"] == "EXACT" and r["restore"]["required_gate"] == "EXACT")
sys.exit(0 if ok else 1)
PY
then ok "the heartbeat's silence moved generation 1 to the standby; restored, gate EXACT (required EXACT)"; else bad "the failover report does not say: heartbeat-timeout, generation 1, restored, gate EXACT"; fi
if [ -s "$P/generation-1.sha256" ] && cmp -s "$P/generation-1.sha256" "$S/restored.sha256"; then
  ok "what the standby restored is, file by file, what the primary sealed as generation 1 (7 files)"; else bad "the restored genome's files are not the primary's generation 1"; fi
if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); t=d["training"]; sys.exit(0 if t["step"]==240 and [c["step"] for c in t["continued_from"]]==[80,160] and d["losses"]==240 else 1)' "$S/continued-training.json" 2>/dev/null; then
  ok "the standby's genome stands at step 240, continued from steps 80 and 160, with 240 losses"; else bad "the continued genome is not step 240 continued from 80 and 160"; fi
exact "$S/replay.json" && ok "on the standby, replay holds the continued genome to the whole recipe: exact" || bad "the standby's replay of the continued genome is not exact"
if [ "$(grep -c '^same ' "$S/compare.txt" 2>/dev/null)" = 7 ] && ! grep -q '^DIFFERENT' "$S/compare.txt" && grep -q '^losses equal 240 240$' "$S/compare.txt"; then
  ok "the continued genome is, in all 7 files and all 240 losses, the recipe run on the standby in one go"; else bad "the continued genome differs from the recipe run in one go"; fi
grep -q '^gate on the continued genome: exit=0 level=EXACT$' "$S/steps.txt" 2>/dev/null && ok "the gate judges the continued genome EXACT" || bad "the gate did not judge the continued genome EXACT"
python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("ok") is True else 1)' "$S/audit-verify.json" 2>/dev/null && ok "the authority's audit log verifies offline" || bad "the authority's audit log does not verify"
[ -s "$S/verdict.txt" ] && ok "$(cat "$S/verdict.txt")" || bad "the standby wrote no verdict"

( cd "$EVIDENCE" && find . -type f ! -name sha256sums.txt -exec shasum -a 256 {} + | sort -k2 > sha256sums.txt )
log "== evidence: $EVIDENCE ($(wc -l < "$EVIDENCE/sha256sums.txt" | tr -d ' ') files)"
[ "$fail" = 0 ] && log "RESULT: PASS" || { log "RESULT: FAIL"; exit 1; }
