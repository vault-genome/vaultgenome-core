#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The training-continuity drill's arithmetic on Amazon EC2 (ADR 0040,
# decision 4): one instance with AMD SEV-SNP runs the kit's recipe stopped
# at steps 80 and 160 and continued from each genome's state to 240, and
# holds the result to the whole recipe on that machine — by replay, and file
# by file against the recipe run in one go (aws-guest.sh). No sentinel, no
# authority, no failover: those are run.sh's, on Compute Engine.
#
# Given a run.sh record, it then lays this machine's digests beside the
# Compute Engine machines' — generation 1 (step 160) and the continued
# genome (step 240). The recipe, the base, the data and the libraries are
# the same; if the digests are too, the two CPUs take the recipe's steps to
# the same bits, and a genome moved between them is continued exactly. That
# comparison is a measurement and is written down either way; it does not
# decide this script's result.
#
#   1. launches one m6a.2xlarge (AMD Milan, 8 vCPUs) with AmdSevSnp enabled
#      from Canonical's current Ubuntu 24.04 AMI, with a key pair and a
#      security group made for this run (ssh from this machine's address only);
#   2. copies the worker package, common.sh, recipe.sh and aws-guest.sh over
#      ssh and runs aws-guest.sh as root;
#   3. brings the results back and checks them;
#   4. terminates the instance and removes the key pair and the security
#      group — always, also on failure.
#
# Cost: one m6a.2xlarge for about twenty-five minutes. Needs the AWS CLI
# signed in to an account that may run EC2 in the region, ssh, scp, python3.
#
# Usage: aws.sh [region] [instance-type] [run.sh evidence stamp]
#        (default us-east-2, m6a.2xlarge; SEV-SNP: m6a, c6a, r6a in us-east-2 and eu-west-1)
set -euo pipefail

REGION="${1:-us-east-2}"
TYPE="${2:-m6a.2xlarge}"
BESIDE="${3:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
FAILOVER="$ROOT/scripts/hardware-test/gcp-failover"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="vg-tc-aws-$(echo "$STAMP" | tr 'A-Z' 'a-z')"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/aws/$STAMP"; mkdir -p "$EVIDENCE"
RUNLOG="$EVIDENCE/runner.log"
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RUNLOG"; }
[ -z "$BESIDE" ] || [ -d "$HERE/evidence/$BESIDE" ] || { echo "no run.sh record $HERE/evidence/$BESIDE"; exit 2; }

ID=""; SG=""; KEY="$NAME"
cleanup() {
  set +e
  log "cleanup: terminating $NAME ($ID), removing the key pair and the security group"
  if [ -n "$ID" ]; then
    aws ec2 terminate-instances --region "$REGION" --instance-ids "$ID" >/dev/null 2>&1
    aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$ID" >/dev/null 2>&1
    left="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[].Instances[].State.Name' --output text 2>/dev/null)"
    echo "instance $ID state after cleanup: ${left:-gone} at $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$EVIDENCE/vm-deleted.txt"
  fi
  aws ec2 delete-key-pair --region "$REGION" --key-name "$KEY" >/dev/null 2>&1
  [ -z "$SG" ] || for _ in $(seq 1 12); do aws ec2 delete-security-group --region "$REGION" --group-id "$SG" >/dev/null 2>&1 && break; sleep 10; done
  rm -rf "$BUILD"
}
trap cleanup EXIT

log "== 0. the worker package from $(git -C "$ROOT" rev-parse --short=12 HEAD)"
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$BUILD/worker.tgz" -C "$ROOT/workers/genome" --exclude __pycache__ --exclude .pytest_cache vg_genome requirements.txt requirements-ci.lock requirements-cuda.lock requirements-torch-cpu.lock requirements-torch-cu126.lock examples
cp "$FAILOVER/common.sh" "$HERE/recipe.sh" "$HERE/aws-guest.sh" "$BUILD/"
( cd "$BUILD" && shasum -a 256 worker.tgz common.sh recipe.sh aws-guest.sh ) | tee "$EVIDENCE/inputs.sha256"
git -C "$ROOT" rev-parse HEAD > "$EVIDENCE/code-rev.txt"
git -C "$ROOT" status --porcelain -- workers/genome scripts/hardware-test/training-continuity scripts/hardware-test/gcp-failover/common.sh \
  ':(exclude)scripts/hardware-test/training-continuity/evidence' > "$EVIDENCE/code-dirty.txt"
[ -s "$EVIDENCE/code-dirty.txt" ] && log "   note: the tree differs from $(cut -c1-12 "$EVIDENCE/code-rev.txt") in $(wc -l < "$EVIDENCE/code-dirty.txt" | tr -d ' ') paths (code-dirty.txt)"

log "== 1. the instance: $TYPE with AmdSevSnp enabled in $REGION"
AMI="$(aws ssm get-parameter --region "$REGION" --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text)"
aws ec2 create-key-pair --region "$REGION" --key-name "$KEY" --key-type ed25519 --key-format pem --query KeyMaterial --output text > "$BUILD/key.pem"
chmod 600 "$BUILD/key.pem"
VPC="$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
MYIP="$(curl -sS https://checkip.amazonaws.com | tr -d '[:space:]')"
SG="$(aws ec2 create-security-group --region "$REGION" --group-name "$NAME" --description "ssh for the training-continuity kit, one address, one run" --vpc-id "$VPC" --query GroupId --output text)"
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null
ID="$(aws ec2 run-instances --region "$REGION" --image-id "$AMI" --instance-type "$TYPE" --cpu-options AmdSevSnp=enabled \
  --key-name "$KEY" --security-group-ids "$SG" --associate-public-ip-address \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":40,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=app,Value=vaultgenome},{Key=purpose,Value=training-continuity-kit}]" \
  --query 'Instances[0].InstanceId' --output text)"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$ID"
aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" \
  --query 'Reservations[0].Instances[0].{type:InstanceType,zone:Placement.AvailabilityZone,ami:ImageId,sevsnp:CpuOptions.AmdSevSnp,boot:CurrentInstanceBootMode}' --output json | tee "$EVIDENCE/instance.json"
IP="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
SSH=(ssh -i "$BUILD/key.pem" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BUILD/known_hosts" -o ConnectTimeout=10 -o BatchMode=yes -o ServerAliveInterval=30)
SCP=(scp -q -i "$BUILD/key.pem" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BUILD/known_hosts" -o BatchMode=yes)
n=0; until "${SSH[@]}" -n "ubuntu@$IP" true 2>/dev/null || [ $n -ge 36 ]; do sleep 5; n=$((n+1)); done
# The instance's address is not written down: the record names no address.
"${SSH[@]}" -n "ubuntu@$IP" true || { log "no ssh to the instance after $((n*5)) s"; exit 1; }
log "   $ID is up, ssh after $((n*5)) s"

log "== 2. the worker package and the scripts over ssh; aws-guest.sh runs as root"
"${SSH[@]}" -n "ubuntu@$IP" 'mkdir -p /home/ubuntu/e2e'
"${SCP[@]}" "$BUILD/worker.tgz" "$BUILD/common.sh" "$BUILD/recipe.sh" "$BUILD/aws-guest.sh" "ubuntu@$IP:/home/ubuntu/e2e/"
# The guest's transcript is kept; its exit status is read, not left to -e.
set +e
"${SSH[@]}" -n "ubuntu@$IP" 'sudo bash /home/ubuntu/e2e/aws-guest.sh' > "$EVIDENCE/guest.out" 2>&1
GUEST_RC=$?
set -e
log "   aws-guest.sh exit $GUEST_RC"

log "== 3. the results back"
"${SCP[@]}" "ubuntu@$IP:/home/ubuntu/e2e/results.tgz" "$EVIDENCE/results.tgz"
tar xzf "$EVIDENCE/results.tgz" -C "$EVIDENCE"
RES="$(find "$EVIDENCE" -mindepth 1 -maxdepth 1 -type d -name '2*Z' | head -1)"
[ -n "$RES" ] || { log "no results directory in results.tgz"; exit 1; }
mv "$RES" "$EVIDENCE/guest"; RES="$EVIDENCE/guest"
rm -f "$EVIDENCE/results.tgz"

log "== 4. what was proven on this machine"
grep -E '^(cpu=|sev-snp guest:|replay:|compare:|CONTINUED EXACT)' "$RES/steps.txt" | sed 's/^/   /' | tee -a "$RUNLOG" || true
fail=0
ok()  { log "   ok    $1"; }
bad() { log "   FAIL  $1"; fail=1; }
python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("sevsnp")=="enabled" else 1)' "$EVIDENCE/instance.json" && ok "EC2 says the instance runs with AmdSevSnp enabled" || bad "EC2 does not say AmdSevSnp is enabled"
if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); t=d["training"]; sys.exit(0 if t["step"]==240 and [c["step"] for c in t["continued_from"]]==[80,160] and d["losses"]==240 else 1)' "$RES/continued-training.json" 2>/dev/null; then
  ok "the genome stands at step 240, continued from steps 80 and 160, with 240 losses"; else bad "the continued genome is not step 240 continued from 80 and 160"; fi
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); sys.exit(0 if r.get("exact") is True and r.get("losses_equal") is True and r.get("max_abs_diff")==0 else 1)' "$RES/replay.json" 2>/dev/null \
  && ok "replay holds the continued genome to the whole recipe: exact" || bad "replay of the continued genome is not exact"
if [ "$(grep -c '^same ' "$RES/compare.txt" 2>/dev/null)" = 7 ] && ! grep -q '^DIFFERENT' "$RES/compare.txt" && grep -q '^losses equal 240 240$' "$RES/compare.txt"; then
  ok "the continued genome is, in all 7 files and all 240 losses, the recipe run here in one go"; else bad "the continued genome differs from the recipe run in one go"; fi

if [ -n "$BESIDE" ]; then
  G="$HERE/evidence/$BESIDE"
  log "== 5. beside the Compute Engine record $BESIDE (a measurement; it does not decide the result)"
  {
    echo "this machine:    $(grep -m1 '^cpu=' "$RES/steps.txt")"
    echo "compute engine:  primary $(grep -m1 'Model name' "$G/primary/system.txt" | sed 's/.*: *//'), standby $(grep -m1 'Model name' "$G/standby/system.txt" | sed 's/.*: *//')"
    for pair in "generation-1.sha256:primary/generation-1.sha256:generation 1 (step 160) against the primary's" "continued.sha256:standby/continued.sha256:the continued genome (step 240) against the standby's"; do
      mine="${pair%%:*}"; rest="${pair#*:}"; theirs="${rest%%:*}"; what="${rest#*:}"
      echo "$what:"
      join -j 2 <(sort -k2 "$RES/$mine") <(sort -k2 "$G/$theirs") | awk '{ printf "  %-10s %s\n", ($2==$3 ? "same" : "DIFFERENT"), $1 }'
    done
  } | tee "$EVIDENCE/beside-compute-engine.txt" | sed 's/^/   /' | tee -a "$RUNLOG"
  if grep -q DIFFERENT "$EVIDENCE/beside-compute-engine.txt"; then
    log "   measured: this machine and Compute Engine's do not take the recipe to the same bits"
  else
    log "   measured: this machine and Compute Engine's take the recipe to the same bits, at step 160 and at step 240"
  fi
fi

( cd "$EVIDENCE" && find . -type f ! -name sha256sums.txt -exec shasum -a 256 {} + | sort -k2 > sha256sums.txt )
log "== evidence: $EVIDENCE ($(wc -l < "$EVIDENCE/sha256sums.txt" | tr -d ' ') files)"
[ "$GUEST_RC" = 0 ] || { log "aws-guest.sh exited $GUEST_RC"; fail=1; }
[ "$fail" = 0 ] && log "RESULT: PASS" || { log "RESULT: FAIL"; exit 1; }
