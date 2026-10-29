#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The one-button deployment on AWS (deploy/aws) as a newcomer runs it, on
# the record: deploy.sh into a stack of its own — the release verified
# here, the instance from template.json with AmdSevSnp enabled, the guest
# provisioned and proven under the provider's VLEK, the record fetched —
# and then what makes it a deployment and not a demo, and what is EC2's
# own:
#
#   1. the instance is stopped and started — on shared tenancy that is a
#      move to another host: both services come back by themselves, the
#      key files sealed with the firmware's derived key open again (on
#      EC2 the fleet's, KNOWN_ISSUES 19), the worker's session opens again
#      on the new boot — a new REPORT_ID, the same launch measurement, the
#      same VLEK;
#   2. a second gate job is submitted over ssh with `vg submit` and comes
#      back EXACT; `vg verify` replays the audit chain, grown across the
#      move — one chain, every decision in order;
#   3. the chip's launch measurement is held against AWS's published UEFI,
#      measured here with sev-snp-measure for the instance's vCPU count
#      (the pin a reader can compute, ADR 0038);
#   4. the stack is deleted, always, also on failure; the record under
#      evidence/<stamp>/ holds deploy.sh's record (verify/, guest/, the
#      serial console), the post-move results and the runner's log — and
#      is checked for anything that names the account (an ARN, an IAM
#      unique id, the twelve digits) before it is kept.
#
# The committed template.json must be what guest.sh makes
# (make-template.sh --check), or the run stops before it spends anything;
# with --published BUCKET the template the button serves is checked too.
#
# Usage: run.sh [tag] [region] [instance-type] [--published BUCKET]
#        (one m6a.xlarge in us-east-2 for ~10 min by default)
# Needs aws (signed in, deployer-policy.json), curl, git, python3, ssh, scp, cosign, slsa-verifier.
set -euo pipefail
TAG=""; REGION="us-east-2"; TYPE="m6a.xlarge"; PUBLISHED=""
POS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --published) PUBLISHED="${2:?}"; shift 2;;
    *) POS+=("$1"); shift;;
  esac
done
[ ${#POS[@]} -ge 1 ] && TAG="${POS[0]}"; [ ${#POS[@]} -ge 2 ] && REGION="${POS[1]}"; [ ${#POS[@]} -ge 3 ] && TYPE="${POS[2]}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
DEPLOY="$ROOT/deploy/aws"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STACK="vg-button-$(echo "$STAMP" | tr '[:upper:]' '[:lower:]')"
NAME="vaultgenome"; ADMIN="ubuntu"
WORK="$(mktemp -d)"
EVIDENCE="$WORK/evidence"; KEPT=0; mkdir -p "$EVIDENCE"
RAW_DIR="${VG_E2E_RAW_DIR:-$HOME/.cache/vaultgenome/aws-deploy}"; mkdir -p "$RAW_DIR"
RUNLOG="$EVIDENCE/runner.log"
# AWS's published EC2 SEV-SNP UEFI (github.com/aws/uefi), the release the
# captured instances ran (ADR 0038 decision 6).
UEFI_RELEASE=20260814
UEFI_SHA256=67aaae01a6f4245cc071e008859b00ea2b5c05824362c41d165c3b4751372bc9
MEASURE="sev-snp-measure==0.0.13"
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RUNLOG"; }
# The account number, read once and never printed, is replaced wherever it
# appears; an ARN's account field by its shape (deploy.sh does the same).
VG_ACCOUNT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
scrub() { sed -E "s/(arn:aws:[a-z0-9-]*:[a-z0-9-]*:)[0-9]{12}:/\\1<account>:/g${VG_ACCOUNT:+; s/$VG_ACCOUNT/<account>/g}"; }
cleanup() {
  set +e   # nothing below may stop the deletion
  [ -f "$RUNLOG" ] || RUNLOG=/dev/null
  log "cleanup: deleting the stack $STACK"
  "$DEPLOY/destroy.sh" --region "$REGION" --stack "$STACK" --yes 2>&1 | scrub | tee -a "$RUNLOG" || true
  left="$(aws cloudformation --region "$REGION" describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
  echo "stack $STACK after cleanup: ${left:-gone} at $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$EVIDENCE/stack-deleted.txt" 2>/dev/null
  if [ "$KEPT" = 0 ] && [ -d "$EVIDENCE" ]; then cp -R "$EVIDENCE" "$RAW_DIR/failed-$STAMP" && echo "the run's stage is kept at $RAW_DIR/failed-$STAMP (outside the tree)"; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
"$DEPLOY/make-template.sh" --check
[ -z "$PUBLISHED" ] || "$DEPLOY/publish-template.sh" --bucket "$PUBLISHED" --region "$REGION" --check | tee -a "$RUNLOG"
# A key for this run alone.
ssh-keygen -q -t ed25519 -N '' -C "vg-button $STAMP" -f "$WORK/key"
SSH=(ssh -i "$WORK/key" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$WORK/known_hosts" -o ConnectTimeout=10 -o BatchMode=yes)
ssh_vm() { "${SSH[@]}" "$ADMIN@$IP" "$@"; }
ec2() { aws ec2 --region "$REGION" "$@"; }

log "== 1. deploy.sh, as a person runs it (release ${TAG:-latest}, $REGION, $TYPE, stack $STACK)"
RECORDS_BEFORE="$(ls "$DEPLOY/records" 2>/dev/null || true)"
T0=$(date +%s)
# The pipeline's status is deploy.sh's (pipefail); as a condition it does
# not end the script under set -e, so the reason can be read.
if ! "$DEPLOY/deploy.sh" --region "$REGION" --stack "$STACK" --name "$NAME" --type "$TYPE" --ssh-key "$WORK/key.pub" --yes ${TAG:+--tag "$TAG"} 2>&1 | scrub | tee "$EVIDENCE/deploy.out"; then
  log "deploy.sh failed"; exit 1
fi
log "deploy.sh took $(( $(date +%s) - T0 )) s"
REC=""
for d in "$DEPLOY"/records/*/; do
  d="${d%/}"; case " $RECORDS_BEFORE " in *" $(basename "$d") "*) continue;; esac
  grep -q "stack=$STACK" "$d/deployment.txt" 2>/dev/null && REC="$d"
done
[ -n "$REC" ] || { log "no record of $STACK under $DEPLOY/records"; exit 1; }
mv "$REC" "$EVIDENCE/deploy"; rmdir "$DEPLOY/records" 2>/dev/null || true
ID="$(sed -n 's/^instance=//p' "$EVIDENCE/deploy/deployment.txt")"
IP="$(sed -n 's/^ip=//p' "$EVIDENCE/deploy/deployment.txt")"
TAG="$(sed -n 's/^release=//p' "$EVIDENCE/deploy/deployment.txt")"
EVENTS1="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["event_count"])' "$EVIDENCE/deploy/guest/audit-verify.json")"
REPORT1="$(sed -n 's/.* report_id=\([0-9a-f]*\).*/\1/p' "$EVIDENCE/deploy/guest/chip.txt" | head -1)"
VLEK1="$(sed -n 's/.* vlek_sha256=\([0-9a-f]*\).*/\1/p' "$EVIDENCE/deploy/guest/chip.txt" | head -1)"
log "deployed $TAG on $ID ($STACK, $REGION, $IP); $EVENTS1 audit events after the first job; REPORT_ID ${REPORT1:0:16}…, VLEK ${VLEK1:0:16}…"

log "== 2. a stop and a start: the instance moves to another host — the services come back on their own, the sealed key files open again"
T1=$(date +%s)
mkdir -p "$EVIDENCE/after-move"
ec2 stop-instances --instance-ids "$ID" --query 'StoppingInstances[0].CurrentState.Name' --output text | tee -a "$RUNLOG"
ec2 wait instance-stopped --instance-ids "$ID"
TSTOP=$(date +%s); log "stopped after $(( TSTOP - T1 )) s"
ec2 start-instances --instance-ids "$ID" --query 'StartingInstances[0].CurrentState.Name' --output text | tee -a "$RUNLOG"
ec2 wait instance-running --instance-ids "$ID"
IP2="$(ec2 describe-instances --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
{ echo "ip_before=$IP"; echo "ip_after=$IP2"; echo "stopped_at=$(date -u -r "$TSTOP" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"; } > "$EVIDENCE/after-move/addresses.txt"
IP="$IP2"; log "running again at $IP (the address changed: a new host)"
n=0; until ssh_vm "true" >/dev/null 2>>"$EVIDENCE/ssh.err" || [ $n -ge 36 ]; do sleep 5; n=$((n+1)); done
ssh_vm "true" >/dev/null 2>>"$EVIDENCE/ssh.err" || { log "no ssh to $ID within 3 minutes of the start"; exit 1; }
n=0; until ssh_vm "sudo journalctl -b -u sagvd --no-pager -o cat | grep -q 'sagvd session opened'" >/dev/null 2>>"$EVIDENCE/ssh.err" || [ $n -ge 48 ]; do sleep 5; n=$((n+1)); done
ssh_vm "sudo vg health" > "$EVIDENCE/after-move/health.txt" 2>>"$EVIDENCE/ssh.err" || true
ssh_vm "sudo journalctl -b -u sagvd -u acp-compute --no-pager -o short-iso" > "$EVIDENCE/after-move/journal-this-boot.txt" 2>>"$EVIDENCE/ssh.err" || true
ssh_vm "sudo journalctl --list-boots --no-pager" > "$EVIDENCE/after-move/boots.txt" 2>>"$EVIDENCE/ssh.err" || true
ssh_vm "cat /sys/class/dmi/id/sys_vendor; uname -r; nproc" > "$EVIDENCE/after-move/host.txt" 2>>"$EVIDENCE/ssh.err" || true
grep -q 'sagvd session opened' "$EVIDENCE/after-move/journal-this-boot.txt" || { log "after the move the worker did not open a session (after-move/journal-this-boot.txt)"; exit 1; }
log "back after the move in $(( $(date +%s) - T1 )) s: $(grep -c 'Active: active' "$EVIDENCE/after-move/health.txt" || true) of 2 services active, the session opened on this boot"

log "== 3. a second gate job over ssh, and the chain verified across the move"
ssh_vm "sudo vg submit gen-0.genome gen-0.key" > "$EVIDENCE/after-move/submit.txt" 2>>"$EVIDENCE/ssh.err" || { cat "$EVIDENCE/after-move/submit.txt"; log "vg submit failed"; exit 1; }
grep -q 'status=succeeded gate=EXACT' "$EVIDENCE/after-move/submit.txt" || { cat "$EVIDENCE/after-move/submit.txt"; log "the second job did not gate EXACT"; exit 1; }
ssh_vm "sudo vg status" > "$EVIDENCE/after-move/status-live.txt" 2>>"$EVIDENCE/ssh.err" || true
ssh_vm "sudo vg verify" > "$EVIDENCE/after-move/audit-verify.json" 2>"$EVIDENCE/after-move/pause.txt" || { log "vg verify failed"; exit 1; }
ssh_vm "sudo vg audit" > "$EVIDENCE/after-move/status.txt" 2>>"$EVIDENCE/after-move/pause.txt" || true
ssh_vm "sudo vg events 0" > "$EVIDENCE/after-move/audit-events.jsonl" 2>>"$EVIDENCE/after-move/pause.txt" || true
EVENTS2="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["event_count"])' "$EVIDENCE/after-move/audit-verify.json")"
OK2="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["ok"]).lower())' "$EVIDENCE/after-move/audit-verify.json")"
[ "$OK2" = true ] && [ "$EVENTS2" -gt "$EVENTS1" ] || { log "the audit chain after the move: ok=$OK2 events=$EVENTS2 (was $EVENTS1)"; exit 1; }
# The chip as the verifier read it on the new boot: the last TRUST_EVALUATED record.
python3 - "$EVIDENCE/after-move/audit-events.jsonl" > "$EVIDENCE/after-move/chip.txt" <<'PY'
import json, sys
last = None
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e.get("kind") == "TRUST_EVALUATED": last = e
s = (((last or {}).get("payload") or {}).get("peer_detail") or {}).get("sev_snp") or {}
if s:
    t = s["tcb"]["reported"]; v = s.get("vlek") or {}
    print("peer chip product=%s signing_key=%s report_id=%s snp=%#x microcode=%#x firmware=%s vlek_csp_id=%s vlek_sha256=%s chip_id_hex=%s" % (
        s["product"], s.get("signing_key"), s.get("report_id_hex"), t["snp"], t["microcode"], s["firmware"]["current"], v.get("csp_id"), v.get("sha256"), s.get("chip_id_hex")))
PY
REPORT2="$(sed -n 's/.* report_id=\([0-9a-f]*\).*/\1/p' "$EVIDENCE/after-move/chip.txt" | head -1)"
VLEK2="$(sed -n 's/.* vlek_sha256=\([0-9a-f]*\).*/\1/p' "$EVIDENCE/after-move/chip.txt" | head -1)"
MEAS1="$(sed -n 's/^vault_measurement=//p' "$EVIDENCE/deploy/guest/steps.txt" | head -1)"
# The launch measurement on the new host, as the authority's identity on
# this boot reads it (tee_measurement_hex): the same UEFI, the same vCPUs.
MEAS2="$(ssh_vm "sudo python3 -c 'import json; print(json.load(open(\"/etc/vaultgenome/sagvd-identity.json\"))[\"tee_measurement_hex\"])'" 2>>"$EVIDENCE/ssh.err" || true)"
{ echo "report_id_before=$REPORT1"; echo "report_id_after=$REPORT2"; echo "vlek_before=$VLEK1"; echo "vlek_after=$VLEK2"; echo "measurement_before=$MEAS1"; echo "measurement_after=$MEAS2"; } > "$EVIDENCE/after-move/identity.txt"
[ -n "$REPORT2" ] && [ "$REPORT2" != "$REPORT1" ] || { log "no new REPORT_ID on the new boot (before ${REPORT1:0:16}, after ${REPORT2:0:16})"; exit 1; }
[ "$VLEK2" = "$VLEK1" ] || { log "the VLEK changed across the move (before ${VLEK1:0:16}, after ${VLEK2:0:16}): not the same fleet key"; exit 1; }
[ -n "$MEAS2" ] && [ "$MEAS2" = "$MEAS1" ] || { log "the launch measurement is not the same on the new host (before ${MEAS1:0:16}, after ${MEAS2:0:16})"; exit 1; }
log "second job: $(tail -1 "$EVIDENCE/after-move/submit.txt"); the chain verifies, $EVENTS2 events (was $EVENTS1); a new REPORT_ID ${REPORT2:0:16}…, the same VLEK, the same measurement"

log "== 4. the launch measurement against AWS's published UEFI (release $UEFI_RELEASE, sev-snp-measure)"
VCPUS="$(cat "$EVIDENCE/deploy/guest/nproc.txt")"
python3 -m venv "$WORK/venv" >/dev/null && "$WORK/venv/bin/pip" install -q "$MEASURE" >/dev/null
curl -fsSL -o "$WORK/ovmf_img.fd" "https://github.com/aws/uefi/releases/download/$UEFI_RELEASE/ovmf_img.fd"
GOT_SHA="$(shasum -a 256 "$WORK/ovmf_img.fd" | cut -d' ' -f1)"
EXPECT="$("$WORK/venv/bin/sev-snp-measure" --mode snp --vcpus "$VCPUS" --vmm-type ec2 --ovmf "$WORK/ovmf_img.fd")"
{ echo "uefi_release=$UEFI_RELEASE"; echo "uefi_sha256=$GOT_SHA"; echo "uefi_sha256_pinned=$UEFI_SHA256"; echo "vcpus=$VCPUS"; echo "measure=$MEASURE --mode snp --vcpus $VCPUS --vmm-type ec2"; echo "expected=$EXPECT"; echo "reported=$MEAS1"; } | tee "$EVIDENCE/measurement.txt" | tee -a "$RUNLOG"
[ "$GOT_SHA" = "$UEFI_SHA256" ] && [ "$EXPECT" = "$MEAS1" ] || { log "the launch measurement is not the published UEFI's"; exit 1; }
log "the chip's launch measurement is AWS's published UEFI $UEFI_RELEASE measured for $VCPUS vCPUs"

{ echo "release=$TAG"; echo "platform=aws-sev-snp"; echo "instance=$ID"; echo "stack=$STACK"; echo "region=$REGION"; echo "machine=$TYPE"; echo "stamp=$STAMP"
  echo "events_after_first_job=$EVENTS1"; echo "events_after_move_and_second_job=$EVENTS2"; echo "deploy_seconds=$(( T1 - T0 ))"; echo "move_seconds=$(( $(date +%s) - T1 ))"; } > "$EVIDENCE/summary.txt"

# Nothing on the record names the account: an ARN, an IAM unique id, the
# twelve digits (the ids that encode the account: ASIA/AKIA/AROA…).
if grep -rEl 'arn:aws:|\b(ABIA|ACCA|AGPA|AIDA|AIPA|AKIA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16,}' "$EVIDENCE" 2>/dev/null | grep -v runner.log | grep .; then
  log "the record names the account (above): not kept"; exit 1
fi
ACCT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
if [ -n "$ACCT" ] && grep -rl -- "$ACCT" "$EVIDENCE" 2>/dev/null | grep .; then log "the record carries the account number (above): not kept"; exit 1; fi
( cd "$EVIDENCE" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 > "$WORK/sha256sums.txt" ) && mv "$WORK/sha256sums.txt" "$EVIDENCE/sha256sums.txt"
FINAL="$HERE/evidence/$STAMP"; mkdir -p "$HERE/evidence"
mv "$EVIDENCE" "$FINAL"; EVIDENCE="$FINAL"; KEPT=1
echo "evidence: $EVIDENCE"
echo "RESULT: PASS"
