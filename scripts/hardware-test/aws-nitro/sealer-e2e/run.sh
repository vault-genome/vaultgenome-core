#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The Nitro enclave's sealer on hardware, against KMS itself (ADR 0036,
# part four, stage one). From the operator's machine, under the kit's role
# (vaultgenome-nitro-kit, the stack in ../iam/): two KMS keys for the run —
# one whose policy admits this image, one whose policy admits another —
# a production-mode enclave on an m5.xlarge whose parent has a role with no
# permissions of its own, secrets sealed here for the image's PCR0, opened
# in the enclave through KMS with its attestation document as Recipient;
# the refusals — another image, another secret, a policy that does not
# admit the image, a debug-mode enclave, the parent and the kit asking
# without an enclave — and AWS's own record of each call (CloudTrail).
# Everything the run makes is torn down at the end, whatever happened; the
# keys are scheduled for deletion. The evidence holds no credential, no
# address, and nothing that names the account: not its number, not an IAM
# unique identifier, not PCR3 (redact.py). The verdict (verdict.py) is
# taken on the evidence before that, and kept with it.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
REGION="${VG_REGION:-us-east-2}"
INSTANCE_TYPE="${VG_INSTANCE_TYPE:-m5.xlarge}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN="vaultgenome-nitro-$TS"
EV="$HERE/evidence/$TS"
WORK="${VG_WORK:-$HOME/vg-nitro-runs/$TS}"
if [ -z "$(git -C "$ROOT" status --porcelain)" ]; then TREE="tree clean"; else TREE="tree with uncommitted changes"; fi
mkdir -p "$EV" "$WORK" && chmod 700 "$WORK"
exec > >(tee -a "$WORK/run.log") 2>&1
step() { echo; echo "=== $(date -u +%H:%M:%SZ) $*"; }
die() { echo "FAIL: $*"; exit 1; }

# ---- the kit's role -------------------------------------------------------
ACCT="$(aws sts get-caller-identity --query Account --output text)" || die "no AWS identity"
KIT_ROLE="arn:aws:iam::$ACCT:role/vaultgenome-nitro-kit"
PARENT_ROLE="arn:aws:iam::$ACCT:role/vaultgenome-nitro-parent"
J="$(aws sts assume-role --role-arn "$KIT_ROLE" --role-session-name "$RUN" --duration-seconds 7200 --output json)" || die "cannot assume $KIT_ROLE (is the stack vaultgenome-nitro-kit created?)"
AWS_ACCESS_KEY_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["Credentials"]["AccessKeyId"])' <<<"$J")"
AWS_SECRET_ACCESS_KEY="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["Credentials"]["SecretAccessKey"])' <<<"$J")"
AWS_SESSION_TOKEN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["Credentials"]["SessionToken"])' <<<"$J")"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
unset J
export AWS_DEFAULT_REGION="$REGION"

KEY_ARN=""; OTHER_KEY_ARN=""; SG_ID=""; IID=""; PARENT_IP=""; MY_IP=""
SSH_KEY="$WORK/ssh-key"
SSH=(ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$WORK/known_hosts" -o ConnectTimeout=10)
on_parent() { "${SSH[@]}" "ec2-user@$PARENT_IP" "bash ~/vg/parent-steps.sh $REGION $1" </dev/null; }
# phase <name> <lines> <fatal|soft>: run a parent phase, show its tail, hold it to its own rc line.
phase() {
  local out; out="$(on_parent "$1" 2>&1)"; echo "$out" | tail -n "$2"
  if ! echo "$out" | grep -q "^phase $1 rc=0$"; then
    [ "$3" = fatal ] && die "parent phase $1"; echo "parent phase $1 did not finish cleanly; the verdict will say"
  fi
}

teardown() {
  set +e
  step "teardown"
  if [ -n "$IID" ]; then
    aws ec2 terminate-instances --instance-ids "$IID" --query 'TerminatingInstances[0].CurrentState.Name' --output text
    aws ec2 wait instance-terminated --instance-ids "$IID" && echo "instance $IID terminated"
  fi
  if [ -n "$SG_ID" ]; then
    for _ in 1 2 3 4 5 6; do aws ec2 delete-security-group --group-id "$SG_ID" && { echo "security group deleted"; break; }; sleep 10; done
  fi
  aws ec2 delete-key-pair --key-name "$RUN" >/dev/null && echo "key pair deleted"
  for k in "$KEY_ARN" "$OTHER_KEY_ARN"; do
    [ -n "$k" ] && aws kms schedule-key-deletion --key-id "$k" --pending-window-in-days 7 --query DeletionDate --output text && echo "key scheduled for deletion"
  done
  aws ec2 describe-instances --filters "Name=tag:vaultgenome-run,Values=$TS" --query 'Reservations[].Instances[].State.Name' --output text > "$WORK/teardown-instances.txt"
  { echo "instances of the run: $(cat "$WORK/teardown-instances.txt")"; echo "security group, key pair: deleted"; echo "KMS keys: scheduled for deletion in 7 days"; } > "$EV/teardown.txt"
}
trap teardown EXIT

# ---- the programs ----------------------------------------------------------
step "build the three programs from the tree ($TREE)"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-buildid= -s -w' -o "$WORK/enclave" ./scripts/hardware-test/aws-nitro/sealer-e2e/enclave) || die "build enclave"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-buildid= -s -w' -o "$WORK/parent" ./scripts/hardware-test/aws-nitro/sealer-e2e/parent) || die "build parent"
(cd "$ROOT" && go build -trimpath -o "$WORK/seal" ./scripts/hardware-test/aws-nitro/sealer-e2e/seal) || die "build seal"

# ---- the run's KMS keys ----------------------------------------------------
key_policy() { # $1: the PCR0 the key releases to ("" while the image is not built yet)
  python3 - "$ACCT" "${1:-}" <<'PY'
import json, sys
acct, pcr0 = sys.argv[1], sys.argv[2]
kit = f"arn:aws:iam::{acct}:role/vaultgenome-nitro-kit"
parent = f"arn:aws:iam::{acct}:role/vaultgenome-nitro-parent"
st = [
  {"Sid": "TheAccountAdministersOnly", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:root"},
   "Action": ["kms:Describe*", "kms:Get*", "kms:List*", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
              "kms:TagResource", "kms:UntagResource", "kms:EnableKey", "kms:DisableKey"], "Resource": "*"},
  {"Sid": "TheKitAdministers", "Effect": "Allow", "Principal": {"AWS": kit},
   "Action": ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy", "kms:ListResourceTags", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"], "Resource": "*"},
  {"Sid": "TheOperatorSeals", "Effect": "Allow", "Principal": {"AWS": kit}, "Action": "kms:GenerateDataKey", "Resource": "*",
   "Condition": {"StringEquals": {"kms:EncryptionContext:vault-genome:sealed-secret": "v1"}}},
  {"Sid": "NoDecryptWithoutAnEnclave", "Effect": "Deny", "Principal": "*", "Action": "kms:Decrypt", "Resource": "*",
   "Condition": {"Null": {"kms:RecipientAttestation:ImageSha384": "true"}}},
]
if pcr0:
  st.append({"Sid": "OnlyTheImageOpens", "Effect": "Allow", "Principal": {"AWS": parent}, "Action": "kms:Decrypt", "Resource": "*",
             "Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": pcr0},
                           "StringEquals": {"kms:EncryptionContext:vault-genome:pcr0": pcr0}}})
print(json.dumps({"Version": "2012-10-17", "Id": "vaultgenome-nitro-sealer-run", "Statement": st}, indent=2))
PY
}
step "create the run's two KMS keys"
TAGS=(TagKey=vaultgenome-kit,TagValue=nitro "TagKey=vaultgenome-run,TagValue=$TS")
KEY_ARN="$(aws kms create-key --description "vaultgenome nitro sealer run $TS: admits the image" --policy "$(key_policy)" --tags "${TAGS[@]}" --query KeyMetadata.Arn --output text)" || die "create key"
OTHER_KEY_ARN="$(aws kms create-key --description "vaultgenome nitro sealer run $TS: admits another image" --policy "$(key_policy)" --tags "${TAGS[@]}" --query KeyMetadata.Arn --output text)" || die "create other key"
echo "keys created"

# ---- the parent instance ---------------------------------------------------
step "launch the parent: $INSTANCE_TYPE, enclaves on, the role with no permissions, IMDSv2 only"
MY_IP="$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')" || die "own address"
SG_ID="$(aws ec2 create-security-group --group-name "$RUN" --description "vaultgenome nitro sealer run $TS: ssh from the operator only" \
  --tag-specifications "ResourceType=security-group,Tags=[{Key=vaultgenome-kit,Value=nitro},{Key=vaultgenome-run,Value=$TS}]" --query GroupId --output text)" || die "security group"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr "$MY_IP/32" >/dev/null || die "ssh rule"
aws ec2 create-key-pair --key-name "$RUN" --key-type ed25519 \
  --tag-specifications "ResourceType=key-pair,Tags=[{Key=vaultgenome-kit,Value=nitro},{Key=vaultgenome-run,Value=$TS}]" \
  --query KeyMaterial --output text > "$SSH_KEY" || die "key pair"
chmod 600 "$SSH_KEY"
AMI="$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --query Parameter.Value --output text)" || die "AMI"
IID="$(aws ec2 run-instances --image-id "$AMI" --instance-type "$INSTANCE_TYPE" --enclave-options Enabled=true \
  --key-name "$RUN" --security-group-ids "$SG_ID" --iam-instance-profile Name=vaultgenome-nitro-parent \
  --metadata-options HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$RUN},{Key=vaultgenome-kit,Value=nitro},{Key=vaultgenome-run,Value=$TS}]" \
  --query 'Instances[0].InstanceId' --output text)" || die "run-instances"
echo "instance $IID"
aws ec2 wait instance-running --instance-ids "$IID" || die "instance not running"
PARENT_IP="$(aws ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
AZ="$(aws ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].Placement.AvailabilityZone' --output text)"
for i in $(seq 1 40); do "${SSH[@]}" "ec2-user@$PARENT_IP" true </dev/null 2>/dev/null && break; sleep 6; done
"${SSH[@]}" "ec2-user@$PARENT_IP" true </dev/null || die "no ssh"

# ---- the image ---------------------------------------------------------------
step "the image's configuration: the keys and the parent's ports, under PCR0"
python3 - "$WORK/enclave.json" "$REGION" "$KEY_ARN" "$OTHER_KEY_ARN" <<'PY'
import json, sys
json.dump({"region": sys.argv[2], "kms_key_arn": sys.argv[3], "other_kms_key_arn": sys.argv[4],
           "kms_vsock_port": 8000, "imds_vsock_port": 8002, "files_vsock_port": 7000, "report_vsock_port": 7001},
          open(sys.argv[1], "w"), indent=2)
PY
"${SSH[@]}" "ec2-user@$PARENT_IP" "mkdir -p ~/vg/out" </dev/null
scp -q -i "$SSH_KEY" -o UserKnownHostsFile="$WORK/known_hosts" "$WORK/enclave" "$WORK/parent" "$WORK/enclave.json" "$HERE/parent-steps.sh" "ec2-user@$PARENT_IP:vg/" || die "upload"
step "bootstrap the parent"; phase bootstrap 5 fatal
step "build the enclave image"; phase build 14 fatal
scp -q -i "$SSH_KEY" -o UserKnownHostsFile="$WORK/known_hosts" "ec2-user@$PARENT_IP:vg/out/eif-describe.json" "$WORK/" || die "measurements"
PCR0="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Measurements"]["PCR0"].lower())' "$WORK/eif-describe.json")"
[ ${#PCR0} -eq 96 ] || die "no PCR0"
echo "PCR0 $PCR0"

step "pin the image in the key policies"
OTHER_PCR0="$(python3 -c 'import os; print(os.urandom(48).hex())')"
key_policy "$PCR0" > "$WORK/key-policy.json"; key_policy "$OTHER_PCR0" > "$WORK/other-key-policy.json"
aws kms put-key-policy --key-id "$KEY_ARN" --policy-name default --policy "file://$WORK/key-policy.json" || die "key policy"
aws kms put-key-policy --key-id "$OTHER_KEY_ARN" --policy-name default --policy "file://$WORK/other-key-policy.json" || die "other key policy"

step "seal the secrets here, with the kit's role"
head -c 64 /dev/urandom > "$WORK/secret.bin"
SECRET_SHA="$(shasum -a 256 "$WORK/secret.bin" | cut -d' ' -f1)"
S="$WORK/seal"
"$S" -region "$REGION" -key-arn "$KEY_ARN" -pcr0 "$PCR0" -name probe.secret -in "$WORK/secret.bin" -out "$WORK/opens.sealed.json" || die "seal opens"
"$S" -region "$REGION" -key-arn "$KEY_ARN" -pcr0 "$OTHER_PCR0" -name probe.secret -in "$WORK/secret.bin" -out "$WORK/another-image.sealed.json" || die "seal another image"
"$S" -region "$REGION" -key-arn "$KEY_ARN" -pcr0 "$PCR0" -name probe.other -as-name probe.secret -in "$WORK/secret.bin" -out "$WORK/another-secret.sealed.json" || die "seal another secret"
"$S" -region "$REGION" -key-arn "$OTHER_KEY_ARN" -pcr0 "$PCR0" -name probe.secret -in "$WORK/secret.bin" -out "$WORK/policy-refuses.sealed.json" || die "seal under the other key"
python3 - "$WORK" "$PCR0" <<'PY'
import base64, json, sys
w, pcr0 = sys.argv[1], sys.argv[2]
cases = [("opens", "kms_key_arn", "open"), ("another-image", "kms_key_arn", "refuse"),
         ("another-secret", "kms_key_arn", "refuse"), ("policy-refuses", "other_kms_key_arn", "refuse")]
b = {"cases": [{"case": c, "name": "probe.secret", "key": k, "expect": e,
                "file": base64.b64encode(open(f"{w}/{c}.sealed.json", "rb").read()).decode()} for c, k, e in cases],
     "production_pcr0_hex": pcr0}
json.dump(b, open(f"{w}/bundle.json", "w"))
PY
scp -q -i "$SSH_KEY" -o UserKnownHostsFile="$WORK/known_hosts" "$WORK/bundle.json" "$WORK/opens.sealed.json" "ec2-user@$PARENT_IP:vg/" || die "upload sealed files"

step "the enclave, production mode"
phase start-parent 1 fatal
phase production 45 soft
step "the parent's own role asks KMS without an enclave"
phase parent-decrypt 4 soft
step "the enclave, debug mode"
phase debug 35 soft
phase stop-parent 1 soft
scp -q -i "$SSH_KEY" -o UserKnownHostsFile="$WORK/known_hosts" -r "ec2-user@$PARENT_IP:vg/out" "$WORK/parent-out" || echo "download incomplete"

step "the kit's role asks KMS without an enclave"
aws kms decrypt --key-id "$KEY_ARN" --ciphertext-blob "fileb://$WORK/parent-out/opens.datakey.bin" --output json > "$WORK/kit-decrypt.out" 2> "$WORK/kit-decrypt.err"
echo "aws kms decrypt rc=$?" >> "$WORK/kit-decrypt.err"; cat "$WORK/kit-decrypt.err"

# ---- AWS's own record --------------------------------------------------------
teardown; trap - EXIT
step "CloudTrail: the Decrypt calls on the run's keys (it can take up to 15 minutes)"
START_ISO="$(python3 -c 'import datetime,sys; print(datetime.datetime.strptime(sys.argv[1], "%Y%m%dT%H%M%SZ").strftime("%Y-%m-%dT%H:%M:%SZ"))' "$TS")"
for i in $(seq 1 20); do
  aws cloudtrail lookup-events --start-time "$START_ISO" --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt --max-results 50 --output json > "$WORK/cloudtrail-decrypt.json" 2>/dev/null
  n="$(python3 "$HERE/cloudtrail.py" count "$WORK/cloudtrail-decrypt.json" "$KEY_ARN" "$OTHER_KEY_ARN")"
  echo "CloudTrail: $n Decrypt events on the run's keys"
  [ "${n:-0}" -ge 7 ] && break
  sleep 45
done

# ---- the evidence ------------------------------------------------------------
step "the evidence"
cp "$WORK/eif-describe.json" "$EV/eif-describe.json"
cp "$WORK/key-policy.json" "$EV/key-policy.json"; cp "$WORK/other-key-policy.json" "$EV/other-key-policy.json"
for f in report-production.json report-debug.json describe-enclaves-production.json describe-enclaves-debug.json \
         parent.log parent-decrypt.err parent-identity.txt console-debug.log nitro-cli-version.txt parent-kernel.txt image-sha256.txt eif-build.json \
         run-enclave-production.err run-enclave-debug.err; do
  [ -f "$WORK/parent-out/$f" ] && cp "$WORK/parent-out/$f" "$EV/$f"
done
cp "$WORK/kit-decrypt.err" "$EV/kit-decrypt.err"
python3 "$HERE/cloudtrail.py" extract "$WORK/cloudtrail-decrypt.json" "$KEY_ARN" "$OTHER_KEY_ARN" > "$EV/cloudtrail-decrypt.json"
for c in opens another-image another-secret policy-refuses; do echo "$(shasum -a 256 "$WORK/$c.sealed.json" | cut -d' ' -f1)  $c.sealed.json"; done > "$EV/sealed-files.sha256"
{
  echo "commit $(git -C "$ROOT" rev-parse HEAD)"
  echo "$TREE"
  echo "go $(cd "$ROOT" && go env GOVERSION)"
  echo "region $REGION, availability zone $AZ, instance type $INSTANCE_TYPE"
  echo "AMI $AMI (al2023-ami-kernel-default-x86_64)"
  echo "started $TS"
  echo "enclave program sha256 $(shasum -a 256 "$WORK/enclave" | cut -d' ' -f1)"
  echo "parent program sha256 $(shasum -a 256 "$WORK/parent" | cut -d' ' -f1)"
  echo "image PCR0 $PCR0"
  echo "the other key's policy admits PCR0 $OTHER_PCR0 (random)"
  echo "secret: 64 random bytes made on the operator's machine; sha256 $SECRET_SHA"
  echo "key $KEY_ARN"
  echo "other key $OTHER_KEY_ARN"
} > "$EV/run.txt"

step "the verdict"
python3 "$HERE/verdict.py" "$EV" "$PCR0" "$SECRET_SHA" "$KEY_ARN" "$OTHER_KEY_ARN" "$ACCT" "$IID" | tee "$EV/verdict.txt"
RC=${PIPESTATUS[0]}

step "what names the account, taken out of the evidence"
python3 "$HERE/redact.py" redact "$EV" "$ACCT" "$MY_IP" "$PARENT_IP" || { rm -rf "$EV"; die "the redaction failed; the evidence removed"; }
python3 "$HERE/redact.py" check "$EV" "$ACCT" "$MY_IP" "$PARENT_IP" || { rm -rf "$EV"; die "the evidence was not clean; removed"; }
(cd "$EV" && shasum -a 256 * > SHA256SUMS)
echo "evidence: $EV"
exit $RC
