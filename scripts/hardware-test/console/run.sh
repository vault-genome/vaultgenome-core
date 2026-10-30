#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The console on a real server (ADR 0039): an EC2 instance with AMD SEV-SNP
# whose chip the console on THIS computer questions over the internet.
#
#   1. builds the daemons for linux/amd64 and vgconsole for this computer, from this tree;
#   2. launches one m6a.xlarge with AmdSevSnp enabled, a key pair and a security
#      group made for this run: ssh and the console's port from this machine's address only;
#   3. guest.sh stands the deployment up with `acpctl provision --console-listen`
#      and leaves both daemons running as services;
#   4. a pass is made on the host and `vgconsole drill` plays every button from
#      here against the real chip: the refusals, the check, the journal, the
#      restore, the emergency stop and its lifting, the roles;
#   5. sagvd restarts: the console's certificate opens from its sealed file, the
#      stop list and the people are still there, the chip still answers;
#   6. both daemons stop, the audit log comes here and is verified by acpctl and
#      by the independent auditor (tools/auditor);
#   7. the instance, the key pair and the security group go: always, also on failure.
#
# With KEEP=1 the instance stays up after step 5 with a fresh owner's pass in
# $KEEP_PASS (default ./owner.vgpass) and the console's records cleared, and
# destroy.sh removes it later. Cost: about $0.17 an hour.
#
# Usage: [KEEP=1 KEEP_PASS=FILE KEEP_NAME=NAME] run.sh [region] [instance-type]
set -euo pipefail

REGION="${1:-us-east-2}"
TYPE="${2:-m6a.xlarge}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="vg-console-$(echo "$STAMP" | tr 'A-Z' 'a-z')"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"; mkdir -p "$EVIDENCE"
RUNLOG="$EVIDENCE/runner.log"
KEEP="${KEEP:-0}"
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RUNLOG"; }

ID=""; SG=""; KEY="$NAME"
cleanup() {
  set +e
  if [ "$KEEP" = 1 ] && [ "${KEPT:-0}" = 1 ]; then
    log "the instance stays up: $NAME"
    rm -rf "$BUILD"
    return
  fi
  log "cleanup: terminating $NAME, removing the key pair and the security group"
  if [ -n "$ID" ]; then
    aws ec2 terminate-instances --region "$REGION" --instance-ids "$ID" >/dev/null 2>&1
    aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$ID" >/dev/null 2>&1
    left="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[].Instances[].State.Name' --output text 2>/dev/null)"
    echo "instance state after cleanup: ${left:-gone} at $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$EVIDENCE/vm-deleted.txt"
  fi
  aws ec2 delete-key-pair --region "$REGION" --key-name "$KEY" >/dev/null 2>&1
  for _ in $(seq 1 12); do aws ec2 delete-security-group --region "$REGION" --group-id "$SG" >/dev/null 2>&1 && break; sleep 10; done
  rm -rf "$BUILD"
}
trap cleanup EXIT

log "== 0. build from $(git -C "$ROOT" rev-parse --short=12 HEAD)"
( cd "$ROOT" && for b in sagvd acp-compute acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
( cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$BUILD/vgconsole" ./cmd/vgconsole )
( cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$BUILD/acpctl-here" ./cmd/acpctl )
( cd "$ROOT/workers" && COPYFILE_DISABLE=1 tar czf "$BUILD/genome-worker.tgz" --no-xattrs --exclude '__pycache__' --exclude '.pytest_cache' genome )
cp "$HERE/guest.sh" "$BUILD/guest.sh"
( cd "$BUILD" && shasum -a 256 sagvd acp-compute acpctl keygen vgconsole genome-worker.tgz guest.sh ) | tee "$EVIDENCE/binaries.sha256"
git -C "$ROOT" rev-parse HEAD > "$EVIDENCE/code-rev.txt"
git -C "$ROOT" status --porcelain > "$EVIDENCE/code-dirty.txt"

log "== 1. the instance: $TYPE with AmdSevSnp enabled in $REGION"
AMI="$(aws ssm get-parameter --region "$REGION" --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text)"
aws ec2 create-key-pair --region "$REGION" --key-name "$KEY" --key-type ed25519 --key-format pem --query KeyMaterial --output text > "$BUILD/key.pem"
chmod 600 "$BUILD/key.pem"
VPC="$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
MYIP="$(curl -sS https://checkip.amazonaws.com | tr -d '[:space:]')"
SG="$(aws ec2 create-security-group --region "$REGION" --group-name "$NAME" --description "ssh and the console, one address, one run" --vpc-id "$VPC" --query GroupId --output text)"
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" --protocol tcp --port 9443 --cidr "$MYIP/32" >/dev/null
ID="$(aws ec2 run-instances --region "$REGION" --image-id "$AMI" --instance-type "$TYPE" --cpu-options AmdSevSnp=enabled \
  --key-name "$KEY" --security-group-ids "$SG" --associate-public-ip-address \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":24,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=app,Value=vaultgenome},{Key=purpose,Value=console-kit}]" \
  --query 'Instances[0].InstanceId' --output text)"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$ID"
aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" \
  --query 'Reservations[0].Instances[0].{type:InstanceType,zone:Placement.AvailabilityZone,sevsnp:CpuOptions.AmdSevSnp,boot:CurrentInstanceBootMode}' --output json | tee "$EVIDENCE/instance.json"
IP="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
SSH=(ssh -i "$BUILD/key.pem" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BUILD/known_hosts" -o ConnectTimeout=10 -o BatchMode=yes)
SCP=(scp -q -i "$BUILD/key.pem" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BUILD/known_hosts" -o BatchMode=yes)
n=0; until "${SSH[@]}" -n "ubuntu@$IP" true 2>/dev/null || [ $n -ge 36 ]; do sleep 5; n=$((n+1)); done
"${SSH[@]}" -n "ubuntu@$IP" true || { log "no ssh after $((n*5)) s"; exit 1; }
log "   ssh after $((n*5)) s"

log "== 2. the binaries, the worker package and guest.sh; guest.sh stands the deployment up"
"${SSH[@]}" -n "ubuntu@$IP" 'mkdir -p /home/ubuntu/e2e'
"${SCP[@]}" "$BUILD/sagvd" "$BUILD/acp-compute" "$BUILD/acpctl" "$BUILD/keygen" "$BUILD/genome-worker.tgz" "$BUILD/guest.sh" "ubuntu@$IP:/home/ubuntu/e2e/"
set +e
"${SSH[@]}" -n "ubuntu@$IP" 'sudo bash /home/ubuntu/e2e/guest.sh' > "$EVIDENCE/guest.out" 2>&1
GUEST_RC=$?
set -e
log "   guest.sh exit $GUEST_RC"
"${SCP[@]}" "ubuntu@$IP:/home/ubuntu/e2e/results.tgz" "$EVIDENCE/results.tgz"
tar xzf "$EVIDENCE/results.tgz" -C "$EVIDENCE"
RES="$(find "$EVIDENCE" -mindepth 1 -maxdepth 1 -type d -name '2*Z' | head -1)"
[ -n "$RES" ] || { log "no results directory"; exit 1; }
mv "$RES" "$EVIDENCE/guest"; RES="$EVIDENCE/guest"; rm -f "$EVIDENCE/results.tgz"
grep -E '^(provision exit=|finetune exit=|seal exit=|sagvd ready|session opened|job status=|gate_level=)' "$RES/steps.txt" | tee -a "$RUNLOG"
grep -q '^gate_level=EXACT ' "$RES/steps.txt" || { log "the deployment's own gate job did not come back EXACT"; exit 1; }

log "== 3. the drill: every button from this computer, against the real chip"
invite() { # invite <name> <role> <file>
  "${SSH[@]}" -n "ubuntu@$IP" "sudo /root/e2e/acpctl console invite --sagvd-config /root/deploy/sagvd.json --worker-config /root/deploy/acp-compute.json --address $IP:9443 --label 'AWS Ohio, kit' --name '$1' --role $2 --out /home/ubuntu/e2e/$1.vgpass && sudo chown ubuntu /home/ubuntu/e2e/$1.vgpass" >> "$RUNLOG" 2>&1
  "${SCP[@]}" "ubuntu@$IP:/home/ubuntu/e2e/$1.vgpass" "$3"
  "${SSH[@]}" -n "ubuntu@$IP" "rm -f /home/ubuntu/e2e/$1.vgpass"
}
invite Owner owner "$BUILD/owner.vgpass"
set +e
"$BUILD/vgconsole" drill --pass "$BUILD/owner.vgpass" --out "$EVIDENCE/drill" --work "$BUILD/people" 2>&1 | tee "$EVIDENCE/drill.out"
DRILL_RC=${PIPESTATUS[0]}
set -e
log "   drill exit $DRILL_RC"

log "== 4. sagvd restarts: the listener's sealed key opens, the people and the stop list are still there"
"${SSH[@]}" -n "ubuntu@$IP" 'sudo systemctl restart sagvd.service; n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done; echo "sagvd ready after ${n}s"' | tee -a "$RUNLOG"
sleep 3
set +e
"$BUILD/vgconsole" check --data-dir "$BUILD/people/owner" --lang ru > "$EVIDENCE/after-restart.json" 2> "$EVIDENCE/after-restart.err"
AFTER_RC=$?
set -e
log "   check after the restart exit $AFTER_RC"

"${SSH[@]}" -n "ubuntu@$IP" 'sudo journalctl -u sagvd --no-pager -o cat' > "$EVIDENCE/sagvd-after.log" 2>&1 || true

if [ "$KEEP" = 1 ]; then
  log "== 5. KEEP: the console's records cleared for a person, a fresh pass, the instance left up"
  "${SSH[@]}" -n "ubuntu@$IP" 'sudo systemctl stop sagvd.service; sudo rm -f /root/deploy/console/people.json /root/deploy/console/operator_stop.pem /root/deploy/console/stop_list.json; sudo find /root/deploy/console/invites -type f -delete; sudo systemctl start sagvd.service; n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done'
  invite "${KEEP_NAME:-Owner}" owner "${KEEP_PASS:-./owner.vgpass}"
  { echo "REGION=$REGION"; echo "ID=$ID"; echo "SG=$SG"; echo "KEY=$KEY"; } > "${KEEP_STATE:-$BUILD/kept.env}"
  KEPT=1
  log "pass: ${KEEP_PASS:-./owner.vgpass}"
else
  log "== 5. both daemons stop; the audit log comes here and is verified by acpctl and by the independent auditor"
  "${SSH[@]}" -n "ubuntu@$IP" 'sudo systemctl stop acp-compute.service sagvd.service; sudo cp /root/deploy/audit/returnpath-audit.db /home/ubuntu/e2e/audit.db; sudo chown ubuntu /home/ubuntu/e2e/audit.db'
  "${SCP[@]}" "ubuntu@$IP:/home/ubuntu/e2e/audit.db" "$BUILD/audit.db"
  "$BUILD/acpctl-here" audit verify --audit "$BUILD/audit.db" --audit-pubkey "$RES/audit-public-key.pem" --audit-kid sagvd-audit-demo --json > "$EVIDENCE/audit-verify.json"
  python3 "$ROOT/tools/auditor/verify_audit.py" --audit "$BUILD/audit.db" --audit-pubkey "$RES/audit-public-key.pem" --audit-kid sagvd-audit-demo --json > "$EVIDENCE/audit-independent.json"
  "$BUILD/acpctl-here" audit query --audit "$BUILD/audit.db" --limit 0 --json > "$EVIDENCE/audit-events.jsonl"
fi

log "== 6. what was proven"
fail=0
[ "$GUEST_RC" = 0 ] || { log "   FAIL  guest.sh"; fail=1; }
[ "$DRILL_RC" = 0 ] && log "   ok    the drill: $(grep -c '^ok ' "$EVIDENCE/drill.out") steps, every one as it must be" || { log "   FAIL  the drill: $(grep '^FAIL' "$EVIDENCE/drill.out" | head -5)"; fail=1; }
[ "$AFTER_RC" = 0 ] && log "   ok    after a restart the same pass and the same chip still prove the server" || { log "   FAIL  the check after the restart"; fail=1; }
if [ "$KEEP" != 1 ]; then
  python3 - "$EVIDENCE/audit-verify.json" "$EVIDENCE/audit-independent.json" <<'PY' | tee -a "$RUNLOG"
import json, sys
a = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
ok = a.get("ok") and b.get("ok") and a.get("event_count") == b.get("events")
print("   %s  the audit log: acpctl %s events, the independent auditor %s events, tip %s" % ("ok   " if ok else "FAIL ", a.get("event_count"), b.get("events"), b.get("tip")))
sys.exit(0 if ok else 1)
PY
  [ "${PIPESTATUS[0]}" = 0 ] || fail=1
fi
( cd "$EVIDENCE" && find . -type f ! -name sha256sums.txt -exec shasum -a 256 {} + | sort -k2 > sha256sums.txt )
log "== evidence: $EVIDENCE ($(wc -l < "$EVIDENCE/sha256sums.txt") files)"
[ "$fail" = 0 ] && log "RESULT: PASS" || { log "RESULT: FAIL"; exit 1; }
