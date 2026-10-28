#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The one-button deployment (deploy/gcp) as a newcomer runs it, on the
# record: deploy.sh against a project — the release verified here, the
# Confidential VM created, the guest provisioned and proven, the record
# decoded — and then what makes it a deployment and not a demo:
#
#   1. the VM is reset (a reboot in place, on the same chip): both services
#      come back by themselves, the key files sealed to the chip open
#      again, the worker's session opens again;
#   2. a second gate job is submitted over ssh with `vg submit` and comes
#      back EXACT; `vg verify` replays the audit chain, which has grown
#      across the reboot — one chain, every decision in order;
#   3. the VM is deleted, always, also on failure; the record under
#      evidence/<stamp>/ holds deploy.sh's record (verify/, guest/,
#      the serial console), the post-reboot results and the runner's log.
#
# Usage: run.sh <project> [tag] [zone] [sev-snp|tdx]   (one n2d-standard-4 or c3-standard-4 for ~12 min)
# Needs gcloud (signed in), curl, git, python3, cosign, slsa-verifier.
set -euo pipefail
PROJECT="${1:?usage: run.sh <project> [tag] [zone] [sev-snp|tdx]}"
TAG="${2:-}"
ZONE="${3:-}"
PLATFORM="${4:-sev-snp}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
DEPLOY="$ROOT/deploy/gcp"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="vg-button-$(echo "$STAMP" | tr '[:upper:]' '[:lower:]')"
WORK="$(mktemp -d)"
EVIDENCE="$WORK/evidence"; PUBLISHED=0; mkdir -p "$EVIDENCE"
RAW_DIR="${VG_E2E_RAW_DIR:-$HOME/.cache/vaultgenome/gcp-deploy}"; mkdir -p "$RAW_DIR"
RUNLOG="$EVIDENCE/runner.log"
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RUNLOG"; }
cleanup() {
  set +e   # nothing below may stop the deletion
  [ -f "$RUNLOG" ] || RUNLOG=/dev/null   # the record has moved into evidence/ by now
  log "cleanup: deleting $NAME"
  z="$(gcloud compute instances list --project "$PROJECT" --filter="name=$NAME" --format='value(zone.basename())' 2>/dev/null | head -1 || true)"
  [ -z "$z" ] || gcloud compute instances delete "$NAME" --project "$PROJECT" --zone "$z" --quiet >/dev/null 2>&1 || true
  if [ "$PUBLISHED" = 0 ] && [ -d "$EVIDENCE" ]; then cp -R "$EVIDENCE" "$RAW_DIR/failed-$STAMP" && echo "the run's stage is kept at $RAW_DIR/failed-$STAMP (outside the tree)"; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
ssh_vm() { gcloud compute ssh "$NAME" --project "$PROJECT" --zone "$ZONE" --quiet --command "$*"; }

log "== 1. deploy.sh, as a person runs it (release ${TAG:-latest}, $PLATFORM, project $PROJECT)"
# deploy.sh keeps its record under deploy/gcp/records/<its stamp>/; this
# run's copy of it moves under the evidence, and that directory is removed.
RECORDS_BEFORE="$(ls "$DEPLOY/records" 2>/dev/null || true)"
T0=$(date +%s)
"$DEPLOY/deploy.sh" --project "$PROJECT" --name "$NAME" --platform "$PLATFORM" --yes ${TAG:+--tag "$TAG"} ${ZONE:+--zone "$ZONE"} 2>&1 | tee "$EVIDENCE/deploy.out"
test "${PIPESTATUS[0]}" = 0 || { log "deploy.sh failed"; exit 1; }
log "deploy.sh took $(( $(date +%s) - T0 )) s"
REC=""
for d in "$DEPLOY"/records/*/; do
  d="${d%/}"; case " $RECORDS_BEFORE " in *" $(basename "$d") "*) continue;; esac
  grep -q "instance=$NAME" "$d/deployment.txt" 2>/dev/null && REC="$d"
done
[ -n "$REC" ] || { log "no record of $NAME under $DEPLOY/records"; exit 1; }
mv "$REC" "$EVIDENCE/deploy"; rmdir "$DEPLOY/records" 2>/dev/null || true
ZONE="$(sed -n 's/^zone=//p' "$EVIDENCE/deploy/deployment.txt")"
TAG="$(sed -n 's/^release=//p' "$EVIDENCE/deploy/deployment.txt")"
EVENTS1="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["event_count"])' "$EVIDENCE/deploy/guest/audit-verify.json")"
log "deployed $TAG on $NAME ($ZONE); $EVENTS1 audit events after the first job"

log "== 2. a reset: the same chip, a fresh boot — the services come back on their own"
T1=$(date +%s)
gcloud compute instances reset "$NAME" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null
mkdir -p "$EVIDENCE/after-reboot"
# ssh is back when the guest's agent is; then the services, then the session.
n=0; until ssh_vm "true" >/dev/null 2>>"$EVIDENCE/ssh.err" || [ $n -ge 36 ]; do sleep 5; n=$((n+1)); done
ssh_vm "true" >/dev/null 2>>"$EVIDENCE/ssh.err" || { log "no ssh to $NAME within 3 minutes of the reset"; exit 1; }
n=0; until ssh_vm "sudo journalctl -b -u sagvd --no-pager -o cat | grep -q 'sagvd session opened'" >/dev/null 2>>"$EVIDENCE/ssh.err" || [ $n -ge 36 ]; do sleep 5; n=$((n+1)); done
ssh_vm "sudo vg health" > "$EVIDENCE/after-reboot/health.txt" 2>>"$EVIDENCE/ssh.err" || true
ssh_vm "sudo journalctl -b -u sagvd -u acp-compute --no-pager -o short-iso" > "$EVIDENCE/after-reboot/journal-this-boot.txt" 2>>"$EVIDENCE/ssh.err" || true
ssh_vm "sudo journalctl --list-boots --no-pager" > "$EVIDENCE/after-reboot/boots.txt" 2>>"$EVIDENCE/ssh.err" || true
ssh_vm "sudo tail -3 /var/log/vaultgenome-deploy.log" > "$EVIDENCE/after-reboot/startup-second-boot.txt" 2>>"$EVIDENCE/ssh.err" || true
# The vTPM's PCRs on this boot, beside the record's at seal time (a vTPM host).
if [ -f "$EVIDENCE/deploy/guest/pcrs-at-seal.txt" ]; then
  ssh_vm "sudo tpm2_pcrread sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,23" > "$EVIDENCE/after-reboot/pcrs.txt" 2>>"$EVIDENCE/ssh.err" || true
  diff "$EVIDENCE/deploy/guest/pcrs-at-seal.txt" "$EVIDENCE/after-reboot/pcrs.txt" > "$EVIDENCE/after-reboot/pcrs-diff.txt" 2>&1 || true
fi
grep -q 'sagvd session opened' "$EVIDENCE/after-reboot/journal-this-boot.txt" || { log "after the reset the worker did not open a session (after-reboot/journal-this-boot.txt)"; exit 1; }
log "back after the reset in $(( $(date +%s) - T1 )) s: $(grep -c 'Active: active' "$EVIDENCE/after-reboot/health.txt" || true) of 2 services active, the session opened on this boot"

log "== 3. a second gate job over ssh, and the chain verified across the reboot"
ssh_vm "sudo vg submit gen-0.genome gen-0.key" > "$EVIDENCE/after-reboot/submit.txt" 2>>"$EVIDENCE/ssh.err" || { cat "$EVIDENCE/after-reboot/submit.txt"; log "vg submit failed"; exit 1; }
grep -q 'status=succeeded gate=EXACT' "$EVIDENCE/after-reboot/submit.txt" || { cat "$EVIDENCE/after-reboot/submit.txt"; log "the second job did not gate EXACT"; exit 1; }
ssh_vm "sudo vg status" > "$EVIDENCE/after-reboot/status-live.txt" 2>>"$EVIDENCE/ssh.err" || true
# The three reads of the live segment pause both services and start
# them again; what vg says about the pause is kept beside the reads.
ssh_vm "sudo vg verify" > "$EVIDENCE/after-reboot/audit-verify.json" 2>"$EVIDENCE/after-reboot/pause.txt" || { log "vg verify failed"; exit 1; }
ssh_vm "sudo vg audit" > "$EVIDENCE/after-reboot/status.txt" 2>>"$EVIDENCE/after-reboot/pause.txt" || true
ssh_vm "sudo vg events 0" > "$EVIDENCE/after-reboot/audit-events.jsonl" 2>>"$EVIDENCE/after-reboot/pause.txt" || true
EVENTS2="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["event_count"])' "$EVIDENCE/after-reboot/audit-verify.json")"
OK2="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["ok"]).lower())' "$EVIDENCE/after-reboot/audit-verify.json")"
[ "$OK2" = true ] && [ "$EVENTS2" -gt "$EVENTS1" ] || { log "the audit chain after the reboot: ok=$OK2 events=$EVENTS2 (was $EVENTS1)"; exit 1; }
log "second job: $(cat "$EVIDENCE/after-reboot/submit.txt" | tail -1); the chain verifies, $EVENTS2 events (was $EVENTS1)"
{ echo "release=$TAG"; echo "platform=$PLATFORM"; echo "instance=$NAME"; echo "zone=$ZONE"; echo "project=$PROJECT"; echo "stamp=$STAMP"; echo "events_after_first_job=$EVENTS1"; echo "events_after_reboot_and_second_job=$EVENTS2"; echo "deploy_seconds=$(( T1 - T0 ))"; } > "$EVIDENCE/summary.txt"

( cd "$EVIDENCE" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 > "$WORK/sha256sums.txt" ) && mv "$WORK/sha256sums.txt" "$EVIDENCE/sha256sums.txt"
FINAL="$HERE/evidence/$STAMP"; mkdir -p "$HERE/evidence"
mv "$EVIDENCE" "$FINAL"; EVIDENCE="$FINAL"; PUBLISHED=1
echo "evidence: $EVIDENCE"
