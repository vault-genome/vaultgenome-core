#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The aws-sev-snp family on real hardware (ADR 0038): a deployment stood up
# by one command on an EC2 instance with AMD SEV-SNP and proven the way
# provision-e2e proves one on Compute Engine — the worker's report signed
# by the provider's VLEK, admitted by sagvd's aws-sev-snp verifier, a gate
# job EXACT, the audit log verified. On a fresh instance:
#
#   1. builds sagvd, acp-compute, acpctl and acp-keygen for linux/amd64 from this tree;
#   2. launches one m6a.xlarge (AMD Milan, 4 vCPUs) with AmdSevSnp enabled from
#      Canonical's current Ubuntu 24.04 AMI, with a key pair and a security
#      group made for this run (ssh from this machine's address only);
#   3. copies the binaries, the worker package and guest.sh over ssh and runs guest.sh;
#   4. brings the results back, checks them, and holds the launch measurement
#      against AWS's published UEFI: the release's binary measured here with
#      sev-snp-measure for the instance's vCPU count (the pin a reader can compute);
#   5. terminates the instance and removes the key pair and the security
#      group — always, also on failure.
#
# Cost: one m6a.xlarge for about fifteen minutes (the guest installs the
# pinned CPU torch), about a dime. Needs the AWS CLI signed in to an account
# that may run EC2 in the region, ssh, scp, python3, go.
#
# Usage: run.sh [region] [instance-type]   (default us-east-2, m6a.xlarge; SEV-SNP: m6a, c6a, r6a in us-east-2 and eu-west-1)
set -euo pipefail

REGION="${1:-us-east-2}"
TYPE="${2:-m6a.xlarge}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="vg-awssnp-$(echo "$STAMP" | tr 'A-Z' 'a-z')"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"; mkdir -p "$EVIDENCE"
RUNLOG="$EVIDENCE/runner.log"
# AWS's published EC2 SEV-SNP UEFI (github.com/aws/uefi), the release the
# captured instances ran: its measurement for the vCPU count is the launch
# measurement the chip reports (ADR 0038 decision 6).
UEFI_RELEASE=20260814
UEFI_SHA256=67aaae01a6f4245cc071e008859b00ea2b5c05824362c41d165c3b4751372bc9
MEASURE="sev-snp-measure==0.0.13"
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RUNLOG"; }

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
  for _ in $(seq 1 12); do aws ec2 delete-security-group --region "$REGION" --group-id "$SG" >/dev/null 2>&1 && break; sleep 10; done
  rm -rf "$BUILD"
}
trap cleanup EXIT

log "== 0. build (linux/amd64) from $(git -C "$ROOT" rev-parse --short=12 HEAD)"
( cd "$ROOT" && for b in sagvd acp-compute acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
( cd "$ROOT/workers" && COPYFILE_DISABLE=1 tar czf "$BUILD/genome-worker.tgz" --no-xattrs --exclude '__pycache__' --exclude '.pytest_cache' genome )
cp "$HERE/guest.sh" "$BUILD/guest.sh"
( cd "$BUILD" && shasum -a 256 sagvd acp-compute acpctl keygen genome-worker.tgz guest.sh ) | tee "$EVIDENCE/binaries.sha256"
git -C "$ROOT" rev-parse HEAD > "$EVIDENCE/code-rev.txt"

log "== 1. the instance: $TYPE with AmdSevSnp enabled in $REGION"
AMI="$(aws ssm get-parameter --region "$REGION" --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text)"
aws ec2 create-key-pair --region "$REGION" --key-name "$KEY" --key-type ed25519 --key-format pem --query KeyMaterial --output text > "$BUILD/key.pem"
chmod 600 "$BUILD/key.pem"
VPC="$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
MYIP="$(curl -sS https://checkip.amazonaws.com | tr -d '[:space:]')"
SG="$(aws ec2 create-security-group --region "$REGION" --group-name "$NAME" --description "ssh for the aws-sev-snp kit, one address, one run" --vpc-id "$VPC" --query GroupId --output text)"
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null
ID="$(aws ec2 run-instances --region "$REGION" --image-id "$AMI" --instance-type "$TYPE" --cpu-options AmdSevSnp=enabled \
  --key-name "$KEY" --security-group-ids "$SG" --associate-public-ip-address \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":24,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=app,Value=vaultgenome},{Key=purpose,Value=aws-sev-snp-kit}]" \
  --query 'Instances[0].InstanceId' --output text)"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$ID"
aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" \
  --query 'Reservations[0].Instances[0].{type:InstanceType,zone:Placement.AvailabilityZone,ami:ImageId,sevsnp:CpuOptions.AmdSevSnp,boot:CurrentInstanceBootMode}' --output json | tee "$EVIDENCE/instance.json"
IP="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
SSH=(ssh -i "$BUILD/key.pem" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BUILD/known_hosts" -o ConnectTimeout=10 -o BatchMode=yes)
SCP=(scp -q -i "$BUILD/key.pem" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BUILD/known_hosts" -o BatchMode=yes)
n=0; until "${SSH[@]}" -n "ubuntu@$IP" true 2>/dev/null || [ $n -ge 36 ]; do sleep 5; n=$((n+1)); done
"${SSH[@]}" -n "ubuntu@$IP" true || { log "no ssh to $IP after $((n*5)) s"; exit 1; }
log "   $ID at $IP, ssh after $((n*5)) s"

log "== 2. the binaries, the worker package and guest.sh over ssh; guest.sh runs as root"
"${SSH[@]}" -n "ubuntu@$IP" 'mkdir -p /home/ubuntu/e2e'
"${SCP[@]}" "$BUILD/sagvd" "$BUILD/acp-compute" "$BUILD/acpctl" "$BUILD/keygen" "$BUILD/genome-worker.tgz" "$BUILD/guest.sh" "ubuntu@$IP:/home/ubuntu/e2e/"
# The guest's transcript is kept; its exit status is read, not left to -e.
set +e
"${SSH[@]}" -n "ubuntu@$IP" 'sudo bash /home/ubuntu/e2e/guest.sh' > "$EVIDENCE/guest.out" 2>&1
GUEST_RC=$?
set -e
log "   guest.sh exit $GUEST_RC"

log "== 3. the results back"
"${SCP[@]}" "ubuntu@$IP:/home/ubuntu/e2e/results.tgz" "$EVIDENCE/results.tgz"
shasum -a 256 "$EVIDENCE/results.tgz" | tee -a "$RUNLOG"
tar xzf "$EVIDENCE/results.tgz" -C "$EVIDENCE"
RES="$(find "$EVIDENCE" -mindepth 1 -maxdepth 1 -type d -name '2*Z' | head -1)"
[ -n "$RES" ] || { log "no results directory in results.tgz"; exit 1; }
mv "$RES" "$EVIDENCE/guest"; RES="$EVIDENCE/guest"
rm -f "$EVIDENCE/results.tgz"

log "== 4. what was proven"
STEPS="$RES/steps.txt"
grep -E '^(provider=|vault_measurement=|vault_sealer=|vault_vlek_csp_id=|gate_level=|audit verify exit=|elapsed_seconds=|probe:|peer chip )' "$STEPS" | tee -a "$RUNLOG"
fail=0
check() { if grep -q -E "$1" "$STEPS"; then log "   ok    $2"; else log "   FAIL  $2"; fail=1; fi; }
check '^provider=auto peer=aws-sev-snp sealer=auto$' "provision kept tee.provider auto and resolved the peer to aws-sev-snp"
for side in sagvd acp-compute; do
  if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("tee_provider")=="aws-sev-snp" and (d.get("aws_sev_snp") or {}).get("csp_id","").startswith("CN=cc-") else 1)' "$RES/$side-identity.json"; then
    log "   ok    $side identity: tee_provider aws-sev-snp, aws_sev_snp.csp_id present"
  else
    log "   FAIL  $side identity does not say aws-sev-snp with a CSP_ID"; fail=1
  fi
done
if grep -q '"resolved_from":"sev_guest (Amazon EC2)","tee_provider":"aws-sev-snp"' "$RES/sagvd.log" && grep -q '"resolved_from":"sev_guest (Amazon EC2)","tee_provider":"aws-sev-snp"' "$RES/acp-compute.log"; then
  log "   ok    both daemons resolved auto from configfs-tsm and the DMI vendor to aws-sev-snp"
else
  log "   FAIL  the daemons' logs do not show auto resolved to aws-sev-snp"; fail=1
fi
if grep -q '"peer_evidence_type":"application/vnd.vault-genome.aws-sev-snp-evidence"' "$RES/acp-compute.log"; then
  log "   ok    the handshake carried the aws-sev-snp envelope (report and VLEK)"
else
  log "   FAIL  the handshake's evidence type is not the aws-sev-snp envelope"; fail=1
fi
check '^vault_sealer=sev-snp-derived-key worker_sealer=sev-snp-derived-key$' "the key files are sealed with the firmware's derived key"
check '^vault_vlek_csp_id=CN=cc-[a-z0-9-]+\.amazonaws\.com worker_vlek_csp_id=CN=cc-[a-z0-9-]+\.amazonaws\.com$' "both identities name the VLEK's CSP_ID"
check '^probe: report version=[0-9]+ signing_key=1 chip_id_zero=True' "the host's reports are signed by a VLEK and name no chip"
check '^gate_level=EXACT ' "the gate job came back EXACT"
check '^audit verify exit=0$' "the audit log verifies under the operator's key"
check '^peer chip product=Milan signing_key=vlek report_id=[0-9a-f]{64} .* vlek_csp_id=CN=cc-' "the admission record says: Milan, a VLEK, REPORT_ID, the provider"
python3 - "$RES/sealed-files.txt" <<'PY' | tee -a "$RUNLOG"
import sys, re
n = sum(1 for l in open(sys.argv[1]) if "'tee': 'aws-sev-snp'" in l and "'sealer': 'sev-snp-derived-key'" in l)
print("   %s    %d of 8 sealed files name tee aws-sev-snp and sealer sev-snp-derived-key" % ("ok " if n == 8 else "FAIL", n))
PY
grep -q "   ok     8 of 8" "$RUNLOG" || fail=1

log "== 5. the launch measurement against AWS's published UEFI (release $UEFI_RELEASE, sev-snp-measure)"
VCPUS="$(cat "$RES/nproc.txt")"
MEAS="$(sed -n 's/^vault_measurement=//p' "$STEPS")"
python3 -m venv "$BUILD/venv" >/dev/null && "$BUILD/venv/bin/pip" install -q "$MEASURE" >/dev/null
curl -fsSL -o "$BUILD/ovmf_img.fd" "https://github.com/aws/uefi/releases/download/$UEFI_RELEASE/ovmf_img.fd"
GOT_SHA="$(shasum -a 256 "$BUILD/ovmf_img.fd" | cut -d' ' -f1)"
EXPECT="$("$BUILD/venv/bin/sev-snp-measure" --mode snp --vcpus "$VCPUS" --vmm-type ec2 --ovmf "$BUILD/ovmf_img.fd")"
{ echo "uefi_release=$UEFI_RELEASE"; echo "uefi_sha256=$GOT_SHA"; echo "uefi_sha256_pinned=$UEFI_SHA256"; echo "vcpus=$VCPUS"; echo "measure=$MEASURE --mode snp --vcpus $VCPUS --vmm-type ec2"; echo "expected=$EXPECT"; echo "reported=$MEAS"; } | tee "$EVIDENCE/measurement.txt" | tee -a "$RUNLOG"
if [ "$GOT_SHA" = "$UEFI_SHA256" ] && [ "$EXPECT" = "$MEAS" ]; then log "   ok    the chip's launch measurement is AWS's published UEFI $UEFI_RELEASE measured for $VCPUS vCPUs"; else log "   FAIL  the launch measurement is not the published UEFI's"; fail=1; fi

( cd "$EVIDENCE" && find . -type f ! -name sha256sums.txt -exec shasum -a 256 {} + | sort -k2 > sha256sums.txt )
log "== evidence: $EVIDENCE ($(wc -l < "$EVIDENCE/sha256sums.txt") files)"
[ "$GUEST_RC" = 0 ] || { log "guest.sh exited $GUEST_RC"; fail=1; }
[ "$fail" = 0 ] && log "RESULT: PASS" || { log "RESULT: FAIL"; exit 1; }
