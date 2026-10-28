#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The one-button deployment on Azure (deploy/azure) as a newcomer runs it,
# on the record: deploy.sh into a resource group of its own — the release
# verified here, the Confidential VM deployed from azuredeploy.json, the
# guest provisioned on a settled boot and proven, the record fetched —
# and then what makes it a deployment and not a demo:
#
#   1. the VM is restarted (a power cycle at the hypervisor, not a
#      shutdown): both services come back by themselves, the vTPM opens
#      the sealed key files again, the worker's session opens again;
#   2. a second gate job is submitted over ssh with `vg submit` and comes
#      back EXACT; `vg verify` replays the audit chain, grown across the
#      restart — one chain, every decision in order;
#   3. the resource group is deleted, always, also on failure; the record
#      under evidence/<stamp>/ holds deploy.sh's record (verify/, guest/,
#      the serial console), the post-restart results and the runner's log.
#
# The committed azuredeploy.json must be what guest.sh makes
# (make-template.sh --check), or the run stops before it spends anything.
#
# Usage: run.sh [tag] [location]        (one Standard_DC4as_v5 for ~15 min)
# Needs az (signed in), curl, git, python3, ssh, scp, cosign, slsa-verifier.
set -euo pipefail
TAG="${1:-}"
LOC="${2:-westeurope}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
DEPLOY="$ROOT/deploy/azure"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RG="vg-button-$(echo "$STAMP" | tr '[:upper:]' '[:lower:]')"; RGS=("$RG")
NAME="vaultgenome"; ADMIN="vgadmin"
WORK="$(mktemp -d)"
EVIDENCE="$WORK/evidence"; PUBLISHED=0; mkdir -p "$EVIDENCE"
RAW_DIR="${VG_E2E_RAW_DIR:-$HOME/.cache/vaultgenome/azure-deploy}"; mkdir -p "$RAW_DIR"
RUNLOG="$EVIDENCE/runner.log"
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RUNLOG"; }
cleanup() {
  set +e   # nothing below may stop the deletion
  [ -f "$RUNLOG" ] || RUNLOG=/dev/null
  for rg in "${RGS[@]}"; do
    log "cleanup: deleting the resource group $rg"
    az group delete -n "$rg" --yes -o none 2>/dev/null || true
  done
  if [ "$PUBLISHED" = 0 ] && [ -d "$EVIDENCE" ]; then cp -R "$EVIDENCE" "$RAW_DIR/failed-$STAMP" && echo "the run's stage is kept at $RAW_DIR/failed-$STAMP (outside the tree)"; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
"$DEPLOY/make-template.sh" --check
# A key for this run alone.
ssh-keygen -q -t ed25519 -N '' -C "vg-button $STAMP" -f "$WORK/key"
SSH=(ssh -i "$WORK/key" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)
ssh_vm() { "${SSH[@]}" "$ADMIN@$IP" "$@"; }

# The host is Azure's choice. A host whose chip firmware is below AMD's
# floor is refused by the verifier (ADR 0033), as a person's deployment
# would be; the person deploys again and lands elsewhere, and so does the
# kit, once, in a resource group of its own — the refusal stays on the
# record (refused-host.out).
attempt=1
while :; do
  log "== 1. deploy.sh, as a person runs it (release ${TAG:-latest}, $LOC, resource group $RG)"
  RECORDS_BEFORE="$(ls "$DEPLOY/records" 2>/dev/null || true)"
  T0=$(date +%s)
  # The pipeline's status is deploy.sh's (pipefail); as a condition it does
  # not end the script under set -e, so the refusal below can be read.
  if "$DEPLOY/deploy.sh" --resource-group "$RG" --location "$LOC" --name "$NAME" --ssh-key "$WORK/key.pub" --yes ${TAG:+--tag "$TAG"} 2>&1 | tee "$EVIDENCE/deploy.out"; then break; fi
  if [ "$attempt" = 1 ] && grep -q 'REFUSED by the verifier.*TCB floor' "$EVIDENCE/deploy.out"; then
    mv "$EVIDENCE/deploy.out" "$EVIDENCE/refused-host.out"
    for d in "$DEPLOY"/records/*/; do d="${d%/}"; case " $RECORDS_BEFORE " in *" $(basename "$d") "*) continue;; esac; mv "$d" "$EVIDENCE/refused-host-record"; done
    log "the host Azure chose was refused by the verifier (its chip firmware is below AMD's floor, ADR 0033): $(grep -o 'reported TCB[^—]*' "$EVIDENCE/refused-host.out" | head -1); deploying again in another resource group"
    az group delete -n "$RG" --yes --no-wait -o none 2>/dev/null || true
    RG="$RG-2"; RGS+=("$RG"); attempt=2
    continue
  fi
  log "deploy.sh failed"; exit 1
done
log "deploy.sh took $(( $(date +%s) - T0 )) s"
REC=""
for d in "$DEPLOY"/records/*/; do
  d="${d%/}"; case " $RECORDS_BEFORE " in *" $(basename "$d") "*) continue;; esac
  grep -q "resource_group=$RG" "$d/deployment.txt" 2>/dev/null && REC="$d"
done
[ -n "$REC" ] || { log "no record of $RG under $DEPLOY/records"; exit 1; }
mv "$REC" "$EVIDENCE/deploy"; rmdir "$DEPLOY/records" 2>/dev/null || true
IP="$(sed -n 's/^ip=//p' "$EVIDENCE/deploy/deployment.txt")"
TAG="$(sed -n 's/^release=//p' "$EVIDENCE/deploy/deployment.txt")"
EVENTS1="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["event_count"])' "$EVIDENCE/deploy/guest/audit-verify.json")"
log "deployed $TAG on $NAME ($RG, $LOC, $IP); $EVENTS1 audit events after the first job"

log "== 2. a restart: the same VM, a fresh boot — the services come back on their own"
T1=$(date +%s)
az vm restart -g "$RG" -n "$NAME" -o none
mkdir -p "$EVIDENCE/after-restart"
n=0; until ssh_vm "true" >/dev/null 2>>"$EVIDENCE/ssh.err" || [ $n -ge 36 ]; do sleep 5; n=$((n+1)); done
ssh_vm "true" >/dev/null 2>>"$EVIDENCE/ssh.err" || { log "no ssh to $NAME within 3 minutes of the restart"; exit 1; }
n=0; until ssh_vm "sudo journalctl -b -u sagvd --no-pager -o cat | grep -q 'sagvd session opened'" >/dev/null 2>>"$EVIDENCE/ssh.err" || [ $n -ge 48 ]; do sleep 5; n=$((n+1)); done
ssh_vm "sudo vg health" > "$EVIDENCE/after-restart/health.txt" 2>>"$EVIDENCE/ssh.err" || true
ssh_vm "sudo journalctl -b -u sagvd -u acp-compute --no-pager -o short-iso" > "$EVIDENCE/after-restart/journal-this-boot.txt" 2>>"$EVIDENCE/ssh.err" || true
ssh_vm "sudo journalctl --list-boots --no-pager" > "$EVIDENCE/after-restart/boots.txt" 2>>"$EVIDENCE/ssh.err" || true
ssh_vm "sudo tail -3 /var/log/vaultgenome-deploy.log; systemctl is-enabled vaultgenome-deploy.service 2>&1" > "$EVIDENCE/after-restart/deploy-unit.txt" 2>>"$EVIDENCE/ssh.err" || true
# The vTPM's PCRs and event log on this boot, beside the record's at seal time.
ssh_vm "sudo tpm2_pcrread sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,23" > "$EVIDENCE/after-restart/pcrs.txt" 2>>"$EVIDENCE/ssh.err" || true
ssh_vm "sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements" > "$EVIDENCE/after-restart/eventlog.yaml" 2>>"$EVIDENCE/ssh.err" || true
diff "$EVIDENCE/deploy/guest/pcrs-at-seal.txt" "$EVIDENCE/after-restart/pcrs.txt" > "$EVIDENCE/after-restart/pcrs-diff.txt" 2>&1 || true
grep -q 'sagvd session opened' "$EVIDENCE/after-restart/journal-this-boot.txt" || { log "after the restart the worker did not open a session (after-restart/journal-this-boot.txt; PCRs that moved: $(grep -c '^[<>]' "$EVIDENCE/after-restart/pcrs-diff.txt" || true) lines in pcrs-diff.txt)"; exit 1; }
log "back after the restart in $(( $(date +%s) - T1 )) s: $(grep -c 'Active: active' "$EVIDENCE/after-restart/health.txt" || true) of 2 services active, the session opened on this boot"

log "== 3. a second gate job over ssh, and the chain verified across the restart"
ssh_vm "sudo vg submit gen-0.genome gen-0.key" > "$EVIDENCE/after-restart/submit.txt" 2>>"$EVIDENCE/ssh.err" || { cat "$EVIDENCE/after-restart/submit.txt"; log "vg submit failed"; exit 1; }
grep -q 'status=succeeded gate=EXACT' "$EVIDENCE/after-restart/submit.txt" || { cat "$EVIDENCE/after-restart/submit.txt"; log "the second job did not gate EXACT"; exit 1; }
ssh_vm "sudo vg status" > "$EVIDENCE/after-restart/status-live.txt" 2>>"$EVIDENCE/ssh.err" || true
ssh_vm "sudo vg verify" > "$EVIDENCE/after-restart/audit-verify.json" 2>"$EVIDENCE/after-restart/pause.txt" || { log "vg verify failed"; exit 1; }
ssh_vm "sudo vg audit" > "$EVIDENCE/after-restart/status.txt" 2>>"$EVIDENCE/after-restart/pause.txt" || true
ssh_vm "sudo vg events 0" > "$EVIDENCE/after-restart/audit-events.jsonl" 2>>"$EVIDENCE/after-restart/pause.txt" || true
EVENTS2="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["event_count"])' "$EVIDENCE/after-restart/audit-verify.json")"
OK2="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["ok"]).lower())' "$EVIDENCE/after-restart/audit-verify.json")"
[ "$OK2" = true ] && [ "$EVENTS2" -gt "$EVENTS1" ] || { log "the audit chain after the restart: ok=$OK2 events=$EVENTS2 (was $EVENTS1)"; exit 1; }
log "second job: $(tail -1 "$EVIDENCE/after-restart/submit.txt"); the chain verifies, $EVENTS2 events (was $EVENTS1)"
{ echo "release=$TAG"; echo "platform=azure-sev-snp"; echo "instance=$NAME"; echo "resource_group=$RG"; echo "location=$LOC"; echo "stamp=$STAMP"; echo "hosts_refused_by_the_verifier=$((attempt - 1))"; echo "events_after_first_job=$EVENTS1"; echo "events_after_restart_and_second_job=$EVENTS2"; echo "deploy_seconds=$(( T1 - T0 ))"; } > "$EVIDENCE/summary.txt"

( cd "$EVIDENCE" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 > "$WORK/sha256sums.txt" ) && mv "$WORK/sha256sums.txt" "$EVIDENCE/sha256sums.txt"
FINAL="$HERE/evidence/$STAMP"; mkdir -p "$HERE/evidence"
mv "$EVIDENCE" "$FINAL"; EVIDENCE="$FINAL"; PUBLISHED=1
echo "evidence: $EVIDENCE"
