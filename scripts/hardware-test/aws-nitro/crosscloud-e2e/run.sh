#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The cross-cloud key release into a Nitro enclave (ADR 0036, part four,
# decision 6). From the operator's machine, under the kit's role
# (vaultgenome-nitro-kit, the stack in ../iam/): the source authority on a
# GCP SEV-SNP Confidential VM — sagvd attesting with the chip, its key
# files sealed to it — releases a genome key over the Internet to
# acp-bootstrap in a production-mode enclave on an m5.xlarge, only after
# the enclave's document verified against the registry's policy (PCR0,
# with PCR1 and PCR2 pinned); the enclave restores the genome in its
# memory and the restore is confirmed from its NSM-signed receipt. The
# enclave's own key files are sealed here for the image and opened inside
# through KMS (sealer-e2e proved that leg). Refused, each on the record:
# an image the allow-list does not name, a PCR the registry pins to another
# value, the operator stop, and the same image in debug mode given its key
# files in the clear. The audit log is verified by acpctl and by the
# auditor's own verifier; CloudTrail names the enclave that opened its
# files. Everything the run makes in both clouds is torn down at the end,
# whatever happened; the key is scheduled for deletion. The evidence holds
# no credential, no address, and nothing that names the account (redact.py);
# the verdict (verdict.py) is taken on it before that, and kept with it.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
REGION="${VG_REGION:-us-east-2}"
INSTANCE_TYPE="${VG_INSTANCE_TYPE:-m5.xlarge}"
GP="${VG_GCP_PROJECT:?VG_GCP_PROJECT: the GCP project of the source authority (a SEV-SNP Confidential VM is made there)}"
GZ="${VG_GCP_ZONE:-us-central1-c}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN="vaultgenome-nitro-xcc-$TS"
GVM="vg-nitro-xcc-$(echo "$TS" | tr 'A-Z' 'a-z')"
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

KEY_ARN=""; SG_ID=""; IID=""; PARENT_IP=""; MY_IP=""; GIP=""; GVM_UP=""
SSH_KEY="$WORK/ssh-key"
SSH=(ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$WORK/known_hosts" -o ConnectTimeout=10)
on_parent() { "${SSH[@]}" "ec2-user@$PARENT_IP" "bash ~/vg/parent-steps.sh $REGION $1" </dev/null; }
GCLOUD=(gcloud --project "$GP" --quiet)
on_authority() { "${GCLOUD[@]}" compute ssh "$GVM" --zone "$GZ" --command "sudo VG_IN=\$HOME/xcc-in bash \$HOME/xcc-in/authority.sh $*" </dev/null; }
# phase <name> <lines> <fatal|soft>: run a parent phase, show its tail, hold it to its own rc line.
phase() {
  local out; out="$(on_parent "$1" 2>&1)"; echo "$out" | tail -n "$2"
  if ! echo "$out" | grep -q "^phase $1 rc=0$"; then
    [ "$3" = fatal ] && die "parent phase $1"; echo "parent phase $1 did not finish cleanly; the verdict will say"
  fi
}
# aphase <name> <lines> <fatal|soft> [args...]: the same for a phase of the source authority.
aphase() {
  local name="$1" lines="$2" mode="$3"; shift 3
  local out; out="$(on_authority "$name" "$@" 2>&1)"; echo "$out" | tail -n "$lines"
  if ! echo "$out" | grep -q "^phase $name rc=0$"; then
    [ "$mode" = fatal ] && die "authority phase $name"; echo "authority phase $name did not finish cleanly; the verdict will say"
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
  [ -n "$KEY_ARN" ] && aws kms schedule-key-deletion --key-id "$KEY_ARN" --pending-window-in-days 7 --query DeletionDate --output text && echo "key scheduled for deletion"
  if [ -n "$GVM_UP" ]; then
    "${GCLOUD[@]}" compute instances delete "$GVM" --zone "$GZ" >/dev/null 2>&1 && echo "authority VM $GVM deleted"
  fi
  aws ec2 describe-instances --filters "Name=tag:vaultgenome-run,Values=$TS" --query 'Reservations[].Instances[].State.Name' --output text > "$WORK/teardown-instances.txt"
  GLEFT="$("${GCLOUD[@]}" compute instances list --filter="name=$GVM" --format='value(status)' 2>/dev/null)"
  { echo "instances of the run: $(cat "$WORK/teardown-instances.txt")"; echo "security group, key pair: deleted"; echo "KMS key: scheduled for deletion in 7 days"; echo "authority VM: ${GLEFT:-deleted}"; } > "$EV/teardown.txt"
}
trap teardown EXIT

# ---- the programs ----------------------------------------------------------
step "build the programs from the tree ($TREE)"
# The shipping daemons for both hosts; acp-bootstrap for the image built
# without a build id, so that the image, and PCR0, follow the source.
for b in sagvd acp-bootstrap acpctl; do
  (cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-buildid= -s -w' -o "$WORK/$b" "./cmd/$b") || die "build $b"
done
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-buildid= -s -w' -o "$WORK/keygen" ./cmd/acp-keygen) || die "build acp-keygen"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-buildid= -s -w' -o "$WORK/parent" ./scripts/hardware-test/aws-nitro/crosscloud-e2e/parent) || die "build parent"
# acp-bootstrap for this machine: seal-keys -pcr0 seals the enclave's key files here.
(cd "$ROOT" && go build -trimpath -o "$WORK/acp-bootstrap-here" ./cmd/acp-bootstrap) || die "build acp-bootstrap for this machine"
cp "$ROOT/scripts/hardware-test/gcp-sev-snp/keybind-evidence/20260913T222343Z/kds-vcek-cert_chain.pem" "$WORK/amd-milan-cert_chain.pem" || die "the AMD Milan chain"
cp "$ROOT/tools/auditor/verify_audit.py" "$WORK/verify_audit.py" || die "the auditor's verifier"

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
print(json.dumps({"Version": "2012-10-17", "Id": "vaultgenome-nitro-crosscloud-run", "Statement": st}, indent=2))
PY
}
step "create the run's KMS key"
TAGS=(TagKey=vaultgenome-kit,TagValue=nitro "TagKey=vaultgenome-run,TagValue=$TS")
KEY_ARN="$(aws kms create-key --description "vaultgenome nitro cross-cloud run $TS: the enclave's key files" --policy "$(key_policy)" --tags "${TAGS[@]}" --query KeyMetadata.Arn --output text)" || die "create key"
echo "key created"

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
"${SSH[@]}" "ec2-user@$PARENT_IP" "mkdir -p ~/vg/out" </dev/null
scp -q -i "$SSH_KEY" -o UserKnownHostsFile="$WORK/known_hosts" "$WORK/parent" "$HERE/parent-steps.sh" "ec2-user@$PARENT_IP:vg/" || die "upload to the parent"
step "bootstrap the parent"; phase bootstrap 5 fatal

# ---- the source authority: a SEV-SNP Confidential VM on GCP ----------------
step "the source authority: $GVM, n2d-standard-2 SEV-SNP in $GZ"
"${GCLOUD[@]}" compute instances create "$GVM" --zone "$GZ" --machine-type n2d-standard-2 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --labels "vaultgenome-kit=nitro-xcc" >/dev/null || die "the authority VM"
GVM_UP=1
GIP="$("${GCLOUD[@]}" compute instances describe "$GVM" --zone "$GZ" --format='value(networkInterfaces[0].accessConfigs[0].natIP)')"
for i in $(seq 1 40); do "${GCLOUD[@]}" compute ssh "$GVM" --zone "$GZ" --command true </dev/null >/dev/null 2>&1 && break; sleep 6; done
"${GCLOUD[@]}" compute ssh "$GVM" --zone "$GZ" --command 'mkdir -p $HOME/xcc-in' </dev/null || die "no ssh to the authority"
"${GCLOUD[@]}" compute scp --zone "$GZ" "$WORK/sagvd" "$WORK/acp-bootstrap" "$WORK/acpctl" "$WORK/keygen" "$WORK/amd-milan-cert_chain.pem" "$WORK/verify_audit.py" "$HERE/authority.sh" "$GVM:xcc-in/" || die "upload to the authority"
# The enclave's API, through the parent, is open to the authority's address alone.
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 8443 --cidr "$GIP/32" >/dev/null || die "the API rule"
step "the authority provisions: sagvd attests with the chip, its key files sealed to it, a genome sealed"; aphase provision 14 fatal
"${GCLOUD[@]}" compute scp --zone "$GZ" "$GVM:/tmp/dest-bundle.tgz" "$GVM:/tmp/authority.pem" "$WORK/" || die "the destination's bundle"

# ---- the image ---------------------------------------------------------------
step "the image: acp-bootstrap, its configuration, the authority's key and the TLS material under PCR0; the key files are not in it"
STAGE="$WORK/stage"; ROOTFS="$WORK/rootfs"
mkdir -p "$STAGE/run/vg/keys" "$ROOTFS/etc/vg/tls" && chmod 700 "$STAGE"
tar xzf "$WORK/dest-bundle.tgz" -C "$STAGE/run/vg/keys" || die "the destination's bundle"
# The certificate and the CA go into the image; server.key and token are the key files, sealed below.
mv "$STAGE/run/vg/keys/server.crt" "$ROOTFS/etc/vg/tls/server.crt" && mv "$STAGE/run/vg/keys/ca.crt" "$ROOTFS/etc/vg/tls/ca.crt" || die "the TLS material"
cp "$WORK/authority.pem" "$ROOTFS/etc/vg/authority.pem" && cp "$WORK/acp-bootstrap" "$ROOTFS/acp-bootstrap" && chmod 755 "$ROOTFS/acp-bootstrap"
python3 - "$ROOTFS/etc/vg/dest.json" "$KEY_ARN" <<'PY'
import json, sys
json.dump({
  "http": {"listen_vsock_port": 5000, "bearer_token_file": "/run/vg/keys/token", "write_timeout_seconds": 120,
           "tls": {"enabled": True, "server_cert": "/etc/vg/tls/server.crt", "server_key": "/run/vg/keys/server.key", "client_cas": "/etc/vg/tls/ca.crt"}},
  "tee": {"provider": "aws-nitro", "workload_descriptor": "acp-bootstrap-nitro-xcc-v1", "secret_files_vsock_port": 7000,
          "aws_kms": {"key_arn": sys.argv[2], "kms_vsock_port": 8000, "imds_vsock_port": 8002}},
  "source_authority": {"kid": "sagvd-authority-xcc", "public_key_path": "/etc/vg/authority.pem"},
  "genome": {"bundle_dir": "/run/vg/bundles", "restore_dir": "/run/vg/restored", "rescan_seconds": 1, "max_bundle_bytes": 67108864},
  "health": {"listen_address": ""},
  "log": {"level": "info", "format": "json", "vsock_port": 7001}}, open(sys.argv[1], "w"), indent=2)
PY
cp "$ROOTFS/etc/vg/dest.json" "$WORK/dest.json"
tar czf "$WORK/rootfs.tgz" -C "$WORK" rootfs || die "the image's root"
scp -q -i "$SSH_KEY" -o UserKnownHostsFile="$WORK/known_hosts" "$WORK/rootfs.tgz" "ec2-user@$PARENT_IP:vg/" || die "upload the image's root"
step "build the enclave image"; phase build 14 fatal
scp -q -i "$SSH_KEY" -o UserKnownHostsFile="$WORK/known_hosts" "ec2-user@$PARENT_IP:vg/out/eif-describe.json" "$WORK/" || die "measurements"
pcr() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Measurements"]["PCR" + sys.argv[2]].lower())' "$WORK/eif-describe.json" "$1"; }
PCR0="$(pcr 0)"; PCR1="$(pcr 1)"; PCR2="$(pcr 2)"
[ ${#PCR0} -eq 96 ] && [ ${#PCR1} -eq 96 ] && [ ${#PCR2} -eq 96 ] || die "no PCR0, PCR1, PCR2"
echo "PCR0 $PCR0"; echo "PCR1 $PCR1"; echo "PCR2 $PCR2"

step "pin the image in the key policy"
key_policy "$PCR0" > "$WORK/key-policy.json"
aws kms put-key-policy --key-id "$KEY_ARN" --policy-name default --policy "file://$WORK/key-policy.json" || die "key policy"

step "the enclave's key files sealed here for the image, with the kit's role (acp-bootstrap seal-keys -pcr0)"
mkdir -p "$WORK/plain" && chmod 700 "$WORK/plain" && cp "$STAGE/run/vg/keys/server.key" "$STAGE/run/vg/keys/token" "$WORK/plain/"
"$WORK/acp-bootstrap-here" seal-keys -config "$WORK/dest.json" -pcr0 "$PCR0" -root "$STAGE" > "$WORK/seal-keys.json" || die "seal-keys"
cat "$WORK/seal-keys.json"
files_json() { # files_json <dir with server.key and token> <out>: what the parent hands the enclave
  python3 - "$1" "$2" <<'PY'
import base64, json, sys
d, out = sys.argv[1], sys.argv[2]
files = {"/run/vg/keys/server.key": open(d + "/server.key", "rb").read(), "/run/vg/keys/token": open(d + "/token", "rb").read()}
json.dump({"files": {p: base64.b64encode(b).decode() for p, b in files.items()}}, open(out, "w"))
PY
}
files_json "$STAGE/run/vg/keys" "$WORK/files.json"; files_json "$WORK/plain" "$WORK/files-plain.json"
scp -q -i "$SSH_KEY" -o UserKnownHostsFile="$WORK/known_hosts" "$WORK/files.json" "$WORK/files-plain.json" "ec2-user@$PARENT_IP:vg/" || die "upload the key files"

step "the enclave, production mode: acp-bootstrap takes its key files from the parent and opens them through KMS"
phase start-parent 1 fatal
phase production 3 soft
step "the release: the authority verifies the enclave's document, releases the genome key, confirms the restore from the NSM-signed receipt; three refusals"
aphase release 40 soft "$PARENT_IP" "$PCR0" "$PCR1" "$PCR2"
phase stop-production 1 soft
step "the enclave, debug mode, given its key files in the clear: refused by the authority"
"${SSH[@]}" "ec2-user@$PARENT_IP" "cp ~/vg/files-plain.json ~/vg/files.json" </dev/null
phase debug 3 soft
aphase debug 8 soft "$PARENT_IP" "$PCR0" "$PCR1" "$PCR2"
phase stop-debug 1 soft
phase stop-parent 1 soft
step "the audit log verified twice; the authority's record packed"
aphase finish 6 soft
"${GCLOUD[@]}" compute scp --zone "$GZ" "$GVM:/tmp/authority-out.tgz" "$WORK/" || echo "the authority's record did not come"
scp -q -i "$SSH_KEY" -o UserKnownHostsFile="$WORK/known_hosts" -r "ec2-user@$PARENT_IP:vg/out" "$WORK/parent-out" || echo "download incomplete"

# ---- AWS's own record --------------------------------------------------------
teardown; trap - EXIT
step "CloudTrail: the Decrypt calls on the run's key (it can take up to 15 minutes)"
START_ISO="$(python3 -c 'import datetime,sys; print(datetime.datetime.strptime(sys.argv[1], "%Y%m%dT%H%M%SZ").strftime("%Y-%m-%dT%H:%M:%SZ"))' "$TS")"
for i in $(seq 1 20); do
  aws cloudtrail lookup-events --start-time "$START_ISO" --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt --max-results 50 --output json > "$WORK/cloudtrail-decrypt.json" 2>/dev/null
  n="$(python3 "$HERE/cloudtrail.py" count "$WORK/cloudtrail-decrypt.json" "$KEY_ARN")"
  echo "CloudTrail: $n Decrypt events on the run's key"
  [ "${n:-0}" -ge 2 ] && break
  sleep 45
done

# ---- the evidence ------------------------------------------------------------
step "the evidence"
cp "$WORK/eif-describe.json" "$EV/eif-describe.json"; cp "$WORK/key-policy.json" "$EV/key-policy.json"; cp "$WORK/dest.json" "$EV/dest.json"
cp "$WORK/seal-keys.json" "$EV/seal-keys.json"
for f in enclave-log-production.jsonl enclave-log-debug.jsonl describe-enclaves-production.json describe-enclaves-debug.json \
         parent.log console-debug.log nitro-cli-version.txt parent-kernel.txt image-files.sha256 eif.sha256 eif-build.json \
         run-enclave-production.err run-enclave-debug.err; do
  [ -f "$WORK/parent-out/$f" ] && cp "$WORK/parent-out/$f" "$EV/$f"
done
mkdir -p "$WORK/authority-out" && tar xzf "$WORK/authority-out.tgz" -C "$WORK/authority-out" 2>/dev/null
for f in "$WORK/authority-out/out"/*; do [ -f "$f" ] && cp "$f" "$EV/authority-$(basename "$f")"; done
# A signed receipt carries the enclave's attestation document whole, and
# the document carries PCR3, which names the account: the document is
# withheld from the evidence and its SHA-256 kept in its place. The
# audit records carry the document's hash only.
python3 - "$EV" <<'PY'
import hashlib, json, os, sys
ev = sys.argv[1]
def withhold(o):
    if isinstance(o, dict):
        for k, v in list(o.items()):
            if k == "evidence" and isinstance(v, str) and len(v) > 256:
                o[k] = {"withheld": "the attestation document, which carries PCR3", "sha256_of_base64": hashlib.sha256(v.encode()).hexdigest()}
            else:
                withhold(v)
    elif isinstance(o, list):
        for v in o:
            withhold(v)
for name in sorted(os.listdir(ev)):
    if not name.endswith(".json"):
        continue
    path = os.path.join(ev, name)
    try:
        doc = json.load(open(path))
    except ValueError:
        continue
    withhold(doc)
    json.dump(doc, open(path, "w"), indent=2)
PY
python3 "$HERE/cloudtrail.py" extract "$WORK/cloudtrail-decrypt.json" "$KEY_ARN" > "$EV/cloudtrail-decrypt.json"
{
  echo "commit $(git -C "$ROOT" rev-parse HEAD)"
  echo "$TREE"
  echo "go $(cd "$ROOT" && go env GOVERSION)"
  echo "destination: region $REGION, availability zone $AZ, instance type $INSTANCE_TYPE, AMI $AMI (al2023-ami-kernel-default-x86_64)"
  echo "source: $GVM, n2d-standard-2 SEV-SNP, zone $GZ"
  echo "started $TS"
  echo "acp-bootstrap in the image sha256 $(shasum -a 256 "$WORK/acp-bootstrap" | cut -d' ' -f1)"
  echo "parent program sha256 $(shasum -a 256 "$WORK/parent" | cut -d' ' -f1)"
  echo "image PCR0 $PCR0"
  echo "image PCR1 $PCR1"
  echo "image PCR2 $PCR2"
  echo "key $KEY_ARN"
} > "$EV/run.txt"

step "the verdict"
python3 "$HERE/verdict.py" "$EV" "$PCR0" "$PCR1" "$PCR2" "$KEY_ARN" "$ACCT" "$IID" | tee "$EV/verdict.txt"
RC=${PIPESTATUS[0]}

step "what names the account, taken out of the evidence"
python3 "$HERE/redact.py" redact "$EV" "$ACCT" "$MY_IP" "$PARENT_IP" "$GIP" || { rm -rf "$EV"; die "the redaction failed; the evidence removed"; }
python3 "$HERE/redact.py" check "$EV" "$ACCT" "$MY_IP" "$PARENT_IP" "$GIP" || { rm -rf "$EV"; die "the evidence was not clean; removed"; }
(cd "$EV" && shasum -a 256 * > SHA256SUMS)
echo "evidence: $EV"
exit $RC
