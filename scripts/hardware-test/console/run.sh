#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The console on real servers (ADR 0039): two EC2 instances with AMD SEV-SNP, in
# two regions, whose chips the console on THIS computer questions over the
# internet, and a model moved from one to the other by the buttons a person has.
#
#   1. builds the daemons for linux/amd64 and vgconsole for this computer, from this tree;
#   2. launches one m6a.xlarge with AmdSevSnp enabled in each region, a key pair and a
#      security group made for this run: ssh and the console's port from this machine's
#      address only, and the second server's console port from the first server too;
#   3. guest.sh stands both deployments up with `acpctl provision --console-listen` and
#      leaves the daemons running as services; only the first has a model;
#   4. passes are made on the hosts and `vgconsole drill` plays every button from here
#      against the real chips: the refusals, the check, the journal, the restore, the
#      emergency stop and its lifting, the roles, and the move;
#   5. sagvd restarts on the first server: the console's certificate opens from its sealed
#      file, the stop list and the people are still there, the chip still answers;
#   6. the daemons stop, both audit logs come here and are verified by acpctl and by the
#      independent auditor (tools/auditor);
#   7. the instances, key pairs and security groups go: always, also on failure.
#
# With KEEP_DIR set there is no drill: both servers stay up, untouched, with a
# fresh owner's pass each in that directory, for a person to press the buttons
# themselves, and destroy.sh removes them later. About $0.35 an hour.
#
# Usage: [KEEP_DIR=DIR KEEP_NAME=NAME] run.sh [first-region] [second-region] [instance-type]
set -euo pipefail

REGION_A="${1:-us-east-2}"
REGION_B="${2:-eu-west-1}"
TYPE="${3:-m6a.xlarge}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="vg-console-$(echo "$STAMP" | tr 'A-Z' 'a-z')"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"
KEEP_DIR="${KEEP_DIR:-}"
[ -z "$KEEP_DIR" ] || { mkdir -p "$KEEP_DIR"; EVIDENCE="$KEEP_DIR/record-$STAMP"; }
mkdir -p "$EVIDENCE"
RUNLOG="$EVIDENCE/runner.log"
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RUNLOG"; }

ID_A=""; ID_B=""; SG_A=""; SG_B=""; IP_A=""; IP_B=""; KEPT=0
cleanup() {
  set +e
  if [ "$KEPT" = 1 ]; then
    log "both servers stay up: $NAME"
    rm -rf "$BUILD"
    return
  fi
  log "cleanup: terminating $NAME, removing the key pairs and the security groups"
  for s in "A $REGION_A $ID_A $SG_A" "B $REGION_B $ID_B $SG_B"; do
    set -- $s
    r=$2; i=${3:-}; g=${4:-}
    if [ -n "$i" ]; then
      aws ec2 terminate-instances --region "$r" --instance-ids "$i" >/dev/null 2>&1
      aws ec2 wait instance-terminated --region "$r" --instance-ids "$i" >/dev/null 2>&1
      left="$(aws ec2 describe-instances --region "$r" --instance-ids "$i" --query 'Reservations[].Instances[].State.Name' --output text 2>/dev/null)"
      echo "server $1 ($r) state after cleanup: ${left:-gone} at $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$EVIDENCE/vm-deleted.txt"
    fi
    aws ec2 delete-key-pair --region "$r" --key-name "$NAME" >/dev/null 2>&1
    [ -z "$g" ] || for _ in $(seq 1 12); do aws ec2 delete-security-group --region "$r" --group-id "$g" >/dev/null 2>&1 && break; sleep 10; done
  done
  rm -rf "$BUILD"
}
trap cleanup EXIT

log "== 0. build from $(git -C "$ROOT" rev-parse --short=12 HEAD)"
KITVER="console-kit-$(git -C "$ROOT" rev-parse --short=8 HEAD)"
( cd "$ROOT" && for b in sagvd acp-compute acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-X main.version=$KITVER" -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
( cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -tags drill -ldflags "-X main.version=$KITVER" -o "$BUILD/vgconsole" ./cmd/vgconsole )
( cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$BUILD/acpctl-here" ./cmd/acpctl )
( cd "$ROOT/workers" && COPYFILE_DISABLE=1 tar czf "$BUILD/genome-worker.tgz" --no-xattrs --exclude '__pycache__' --exclude '.pytest_cache' genome )
cp "$HERE/guest.sh" "$BUILD/guest.sh"
( cd "$BUILD" && shasum -a 256 sagvd acp-compute acpctl keygen vgconsole genome-worker.tgz guest.sh ) | tee "$EVIDENCE/binaries.sha256"
git -C "$ROOT" rev-parse HEAD > "$EVIDENCE/code-rev.txt"
git -C "$ROOT" status --porcelain -- cmd internal go.mod go.sum > "$EVIDENCE/code-dirty.txt"
MYIP="$(curl -sS https://checkip.amazonaws.com | tr -d '[:space:]')"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"

# launch <region> <file>: an instance with SEV-SNP; ID, SG and IP go in the file.
launch() {
  local region="$1" out="$2" ami vpc sg id ip
  ami="$(aws ssm get-parameter --region "$region" --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text)"
  aws ec2 create-key-pair --region "$region" --key-name "$NAME" --key-type ed25519 --key-format pem --query KeyMaterial --output text > "$BUILD/key-$region.pem"
  chmod 600 "$BUILD/key-$region.pem"
  vpc="$(aws ec2 describe-vpcs --region "$region" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
  sg="$(aws ec2 create-security-group --region "$region" --group-name "$NAME" --description "ssh and the console, one address, one run" --vpc-id "$vpc" --query GroupId --output text)"
  echo "SG=$sg" > "$out"
  aws ec2 authorize-security-group-ingress --region "$region" --group-id "$sg" --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null
  aws ec2 authorize-security-group-ingress --region "$region" --group-id "$sg" --protocol tcp --port 9444 --cidr "$MYIP/32" >/dev/null
  id="$(aws ec2 run-instances --region "$region" --image-id "$ami" --instance-type "$TYPE" --cpu-options AmdSevSnp=enabled \
    --key-name "$NAME" --security-group-ids "$sg" --associate-public-ip-address \
    --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":24,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=app,Value=vaultgenome},{Key=purpose,Value=console-kit}]" \
    --query 'Instances[0].InstanceId' --output text)"
  echo "ID=$id" >> "$out"
  aws ec2 wait instance-running --region "$region" --instance-ids "$id"
  ip="$(aws ec2 describe-instances --region "$region" --instance-ids "$id" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
  echo "IP=$ip" >> "$out"
  aws ec2 describe-instances --region "$region" --instance-ids "$id" \
    --query 'Reservations[0].Instances[0].{type:InstanceType,zone:Placement.AvailabilityZone,sevsnp:CpuOptions.AmdSevSnp,boot:CurrentInstanceBootMode}' --output json > "$EVIDENCE/instance-$region.json"
}

log "== 1. the instances: $TYPE with AmdSevSnp enabled in $REGION_A and $REGION_B"
launch "$REGION_A" "$BUILD/a.env"; ID_A="$(sed -n 's/^ID=//p' "$BUILD/a.env")"; SG_A="$(sed -n 's/^SG=//p' "$BUILD/a.env")"; IP_A="$(sed -n 's/^IP=//p' "$BUILD/a.env")"
launch "$REGION_B" "$BUILD/b.env"; ID_B="$(sed -n 's/^ID=//p' "$BUILD/b.env")"; SG_B="$(sed -n 's/^SG=//p' "$BUILD/b.env")"; IP_B="$(sed -n 's/^IP=//p' "$BUILD/b.env")"
aws ec2 authorize-security-group-ingress --region "$REGION_B" --group-id "$SG_B" --protocol tcp --port 9444 --cidr "$IP_A/32" >/dev/null

ssh_a() { ssh -i "$BUILD/key-$REGION_A.pem" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BUILD/known_hosts" -o ConnectTimeout=10 -o BatchMode=yes -n "ubuntu@$IP_A" "$@"; }
ssh_b() { ssh -i "$BUILD/key-$REGION_B.pem" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BUILD/known_hosts" -o ConnectTimeout=10 -o BatchMode=yes -n "ubuntu@$IP_B" "$@"; }
scp_a() { scp -q -i "$BUILD/key-$REGION_A.pem" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BUILD/known_hosts" -o BatchMode=yes "$@"; }
scp_b() { scp -q -i "$BUILD/key-$REGION_B.pem" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BUILD/known_hosts" -o BatchMode=yes "$@"; }
n=0; until ssh_a true 2>/dev/null || [ $n -ge 36 ]; do sleep 5; n=$((n+1)); done; ssh_a true || { log "no ssh to the first server"; exit 1; }
n=0; until ssh_b true 2>/dev/null || [ $n -ge 36 ]; do sleep 5; n=$((n+1)); done; ssh_b true || { log "no ssh to the second server"; exit 1; }

log "== 2. the binaries, the worker package and guest.sh; both deployments stand up"
ssh_a 'mkdir -p /home/ubuntu/e2e'; ssh_b 'mkdir -p /home/ubuntu/e2e'
scp_a "$BUILD/sagvd" "$BUILD/acp-compute" "$BUILD/acpctl" "$BUILD/keygen" "$BUILD/genome-worker.tgz" "$BUILD/guest.sh" "ubuntu@$IP_A:/home/ubuntu/e2e/"
scp_b "$BUILD/sagvd" "$BUILD/acp-compute" "$BUILD/acpctl" "$BUILD/keygen" "$BUILD/genome-worker.tgz" "$BUILD/guest.sh" "ubuntu@$IP_B:/home/ubuntu/e2e/"
set +e
ssh_a 'sudo ROLE=first bash /home/ubuntu/e2e/guest.sh' > "$EVIDENCE/guest-first.out" 2>&1 &
PID_A=$!
ssh_b 'sudo ROLE=second bash /home/ubuntu/e2e/guest.sh' > "$EVIDENCE/guest-second.out" 2>&1 &
PID_B=$!
wait "$PID_A"; RC_A=$?
wait "$PID_B"; RC_B=$?
set -e
log "   guest.sh exit: first $RC_A, second $RC_B"
scp_a "ubuntu@$IP_A:/home/ubuntu/e2e/results.tgz" "$BUILD/results-a.tgz"
scp_b "ubuntu@$IP_B:/home/ubuntu/e2e/results.tgz" "$BUILD/results-b.tgz"
mkdir -p "$BUILD/ra" "$BUILD/rb"
tar xzf "$BUILD/results-a.tgz" -C "$BUILD/ra"; tar xzf "$BUILD/results-b.tgz" -C "$BUILD/rb"
mv "$(find "$BUILD/ra" -mindepth 1 -maxdepth 1 -type d | head -1)" "$EVIDENCE/guest-first"
mv "$(find "$BUILD/rb" -mindepth 1 -maxdepth 1 -type d | head -1)" "$EVIDENCE/guest-second"
grep -E '^(provision exit=|finetune exit=|seal exit=|sagvd ready|session opened|job status=|gate_level=)' "$EVIDENCE/guest-first/steps.txt" | tee -a "$RUNLOG"
grep -E '^(provision exit=|sagvd ready|session opened)' "$EVIDENCE/guest-second/steps.txt" | tee -a "$RUNLOG"
grep -q '^gate_level=EXACT ' "$EVIDENCE/guest-first/steps.txt" || { log "the first deployment's own gate job did not come back EXACT"; exit 1; }

# invite <a|b> <name> <role> <label> <file>
invite() {
  local where="$1" name="$2" role="$3" label="$4" out="$5" ip tmp
  tmp="/home/ubuntu/e2e/pass.vgpass"
  if [ "$where" = a ]; then ip="$IP_A"; else ip="$IP_B"; fi
  "ssh_$where" "sudo /root/e2e/acpctl console invite --sagvd-config /root/deploy/sagvd.json --worker-config /root/deploy/acp-compute.json --address $ip:9444 --label '$label' --name '$name' --role $role --out $tmp && sudo chown ubuntu $tmp" >> "$RUNLOG" 2>&1
  "scp_$where" "ubuntu@$ip:$tmp" "$out"
  "ssh_$where" "rm -f $tmp"
}

if [ -n "$KEEP_DIR" ]; then
  log "== 3. KEEP: both servers stay up, a pass for each"
  invite a "${KEEP_NAME:-Owner}" owner "AWS Ohio" "$KEEP_DIR/first-server.vgpass"
  invite b "${KEEP_NAME:-Owner}" owner "AWS Ireland" "$KEEP_DIR/second-server.vgpass"
  { echo "REGION_A=$REGION_A"; echo "REGION_B=$REGION_B"; echo "ID_A=$ID_A"; echo "ID_B=$ID_B"; echo "SG_A=$SG_A"; echo "SG_B=$SG_B"; echo "NAME=$NAME"; } > "$KEEP_DIR/kept.env"
  KEPT=1
  log "passes: $KEEP_DIR/first-server.vgpass, $KEEP_DIR/second-server.vgpass; remove with: scripts/hardware-test/console/destroy.sh $KEEP_DIR/kept.env"
  exit 0
fi

log "== 3. the drill: every button from this computer, against the real chips"
invite a "Drill Owner" owner "AWS Ohio, kit" "$BUILD/first.vgpass"
invite b "Drill Owner" owner "AWS Ireland, kit" "$BUILD/second.vgpass"
set +e
"$BUILD/vgconsole" drill --pass "$BUILD/first.vgpass" --second "$BUILD/second.vgpass" --out "$EVIDENCE/drill" --work "$BUILD/people" 2>&1 | tee "$EVIDENCE/drill.out"
DRILL_RC=${PIPESTATUS[0]}
set -e
log "   drill exit $DRILL_RC"

log "== 4. sagvd restarts on the first server: the listener's sealed key opens, the people and the stop list are still there"
ssh_a 'sudo systemctl restart sagvd.service; n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done; echo "sagvd ready after ${n}s"' | tee -a "$RUNLOG"
sleep 3
set +e
"$BUILD/vgconsole" check --data-dir "$BUILD/people/owner" --lang ru > "$EVIDENCE/after-restart.json" 2> "$EVIDENCE/after-restart.err"
AFTER_RC=$?
set -e
log "   check after the restart exit $AFTER_RC"
ssh_a 'sudo journalctl -u sagvd --no-pager -o cat' 2>/dev/null | grep -E '"msg":"sagvd console' > "$EVIDENCE/sagvd-console-first.log" || true
ssh_b 'sudo journalctl -u sagvd --no-pager -o cat' 2>/dev/null | grep -E '"msg":"sagvd console' > "$EVIDENCE/sagvd-console-second.log" || true

log "== 5. the daemons stop; both audit logs come here and are verified by acpctl and by the independent auditor"
fail=0
verify_log() { # verify_log <a|b> <label> <pubkey>
  local where="$1" label="$2" pub="$3" ip db
  if [ "$where" = a ]; then ip="$IP_A"; else ip="$IP_B"; fi
  db="$BUILD/audit-$label.db"
  "ssh_$where" 'sudo systemctl stop acp-compute.service sagvd.service; sudo cp /root/deploy/audit/returnpath-audit.db /home/ubuntu/e2e/audit.db; sudo chown ubuntu /home/ubuntu/e2e/audit.db'
  "scp_$where" "ubuntu@$ip:/home/ubuntu/e2e/audit.db" "$db"
  "$BUILD/acpctl-here" audit verify --audit "$db" --audit-pubkey "$pub" --audit-kid sagvd-audit-demo --json > "$EVIDENCE/audit-verify-$label.json"
  python3 "$ROOT/tools/auditor/verify_audit.py" --audit "$db" --audit-pubkey "$pub" --audit-kid sagvd-audit-demo --json > "$EVIDENCE/audit-independent-$label.json"
  "$BUILD/acpctl-here" audit query --audit "$db" --limit 0 --json > "$EVIDENCE/audit-events-$label.jsonl"
  python3 - "$EVIDENCE/audit-verify-$label.json" "$EVIDENCE/audit-independent-$label.json" "$label" <<'PY' | tee -a "$RUNLOG"
import json, sys
a = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
ok = a.get("ok") and b.get("ok") and a.get("event_count") == b.get("events")
print("   %s  the %s server's audit log: acpctl %s events, the independent auditor %s events, tip %s" % ("ok   " if ok else "FAIL ", sys.argv[3], a.get("event_count"), b.get("events"), b.get("tip")))
sys.exit(0 if ok else 1)
PY
}
verify_log a first "$EVIDENCE/guest-first/audit-public-key.pem" || fail=1
verify_log b second "$EVIDENCE/guest-second/audit-public-key.pem" || fail=1

log "== 6. what was proven"
[ "$RC_A" = 0 ] && [ "$RC_B" = 0 ] || { log "   FAIL  guest.sh"; fail=1; }
if [ "$DRILL_RC" = 0 ]; then log "   ok    the drill: $(grep -c '^ok ' "$EVIDENCE/drill.out") steps, every one as it must be"; else log "   FAIL  the drill: $(grep '^FAIL' "$EVIDENCE/drill.out" | head -5)"; fail=1; fi
if [ "$AFTER_RC" = 0 ]; then log "   ok    after a restart the same pass and the same chip still prove the server"; else log "   FAIL  the check after the restart"; fail=1; fi

# Nothing of this machine's or the account's goes on the record.
python3 - "$EVIDENCE" "$MYIP" "$IP_A" "$IP_B" <<'PY'
import os, sys
root, mine, a, b = sys.argv[1:5]
for d, _, names in os.walk(root):
    for n in names:
        p = os.path.join(d, n)
        try:
            raw = open(p, "rb").read()
        except OSError:
            continue
        new = raw.replace(mine.encode(), b"<this-machine>").replace(a.encode(), b"<first-server>").replace(b.encode(), b"<second-server>")
        if new != raw:
            open(p, "wb").write(new)
PY
if grep -rlE "$ACCOUNT|(ABIA|ACCA|AGPA|AIDA|AIPA|AKIA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}" "$EVIDENCE" >/dev/null 2>&1; then
  log "   FAIL  the record names the account or an IAM id"; fail=1
else
  log "   ok    the record names neither the account nor an IAM id"
fi
( cd "$EVIDENCE" && find . -type f ! -name sha256sums.txt -exec shasum -a 256 {} + | sort -k2 > sha256sums.txt )
log "== evidence: $EVIDENCE ($(wc -l < "$EVIDENCE/sha256sums.txt") files)"
[ "$fail" = 0 ] && log "RESULT: PASS" || { log "RESULT: FAIL"; exit 1; }
