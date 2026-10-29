#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# One button on AWS: a Vault Genome deployment on an EC2 instance with AMD
# SEV-SNP (shared tenancy — m6a, c6a or r6a in US East (Ohio) or Europe
# (Ireland)) from the signed release, proven the way the reference
# deployment is proven, and left running. The same template the Launch
# Stack button uses (template.json), driven from the AWS CLI so the record
# comes back to the machine that ran it.
#
#   1. the release is verified here, before anything runs anywhere
#      (deploy/lib/verify-release.sh: the signed checksums list under the
#      release workflow's identity for this very tag, the five files
#      against the list, their SLSA provenance, the tag's signature against
#      the keys pinned on main);
#   2. the template is deployed as a CloudFormation stack: a key pair from
#      your public key, a security group with port 22 open to this
#      machine's address only, a launch template with AmdSevSnp enabled
#      and guest.sh as the user data, one instance from Canonical's
#      current Ubuntu 24.04 AMI, the list's SHA-256 in its tags — the
#      guest verifies the list itself and refuses any other;
#   3. the guest reads the chip's first report (a VLEK's signature, no
#      CHIP_ID), installs, provisions with `acpctl provision` — the
#      family aws-sev-snp resolved from the host, the VLEK chain from AMD
#      KDS, the launch measurement and the provider's CSP_ID pinned on
#      both sides, the key files sealed with the firmware's derived key —
#      starts both daemons as services, gates a first genome over the
#      Return Path and verifies its audit log (guest.sh);
#   4. the record is fetched over ssh into records/<stamp>/ beside this
#      script, with the verification outputs of step 1 (the serial console
#      carried a framed copy: the fallback when ssh is not reachable); the
#      summary says what was proven. The instance stays.
#
# Usage: deploy.sh [--region REGION] [--stack NAME] [--name INSTANCE] [--type TYPE]
#                  [--tag TAG] [--ssh-key PUBKEY] [--ssh-from CIDR] [--vpc ID] [--subnet ID] [--yes]
#        deploy.sh --attach [--region REGION] [--stack NAME] [--ssh-key PUBKEY]
#                  (a session that dropped while the guest was at work)
# Defaults: us-east-2, the stack "vaultgenome" (the instance's name too),
# m6a.xlarge, the release this checkout is tagged as or else the latest,
# ~/.ssh/id_ed25519.pub or ~/.ssh/id_rsa.pub (else a key is made at
# ~/.ssh/vaultgenome_ed25519), port 22 from this machine's address, the
# default VPC. The ssh user is ubuntu.
# Needs aws (signed in), curl, git, python3, ssh, scp; cosign and
# slsa-verifier on PATH, or on Linux x86-64 they are fetched at pinned hashes.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/deploy/lib/verify-release.sh"
REPO="$VG_REPO"

REGION="us-east-2"; STACK="vaultgenome"; NAME=""; TYPE="m6a.xlarge"; TAG=""; PUB=""; FROM=""; VPC=""; SUBNET=""; YES=0; ATTACH=0
while [ $# -gt 0 ]; do
  case "$1" in
    --region|-r) REGION="${2:?}"; shift 2;;
    --stack|-s) STACK="${2:?}"; shift 2;;
    --name|-n) NAME="${2:?}"; shift 2;;
    --type) TYPE="${2:?}"; shift 2;;
    --tag) TAG="${2:?}"; shift 2;;
    --ssh-key) PUB="${2:?}"; shift 2;;
    --ssh-from) FROM="${2:?}"; shift 2;;
    --vpc) VPC="${2:?}"; shift 2;;
    --subnet) SUBNET="${2:?}"; shift 2;;
    --yes|-y) YES=1; shift;;
    --attach) ATTACH=1; shift;;
    -h|--help) sed -n '5,44p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2;;
  esac
done
NAME="${NAME:-$STACK}"
ADMIN="ubuntu"

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
# An AWS error names the caller by ARN, and an ARN carries the account
# number; nothing printed or recorded here does. The number itself is read
# once, never printed, and replaced wherever it appears; an ARN's account
# field is replaced by its shape.
VG_ACCOUNT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
scrub() { sed -E "s/(arn:aws:[a-z0-9-]*:[a-z0-9-]*:)[0-9]{12}:/\\1<account>:/g${VG_ACCOUNT:+; s/$VG_ACCOUNT/<account>/g}"; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is needed: $2"; }
need aws "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
need curl "curl"; need git "git"; need python3 "python3"; need ssh "ssh"; need scp "scp"
command -v sha256sum >/dev/null 2>&1 || need shasum "sha256sum or shasum"
cfn() { aws cloudformation --region "$REGION" "$@"; }
ec2() { aws ec2 --region "$REGION" "$@"; }

# The release: --tag, else this checkout's tag, else the latest release —
# whichever, it is verified below before anything runs.
if [ -z "$TAG" ]; then
  TAG="$(git -C "$ROOT" describe --tags --exact-match HEAD 2>/dev/null || true)"
  if [ -z "$TAG" ]; then
    TAG="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null || true)"
    [ -n "$TAG" ] || die "this checkout is not at a release tag and the latest release could not be read; name one: --tag v0.14.0"
  fi
fi
case "$TAG" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "--tag must be a release tag such as v0.14.0";; esac

# Signed in? The identity is checked, not printed: an AWS identifier
# encodes the account number, and nothing here records the account.
aws sts get-caller-identity --query Arn --output text >/dev/null 2>&1 || die "aws is not signed in here: configure credentials (aws configure, or AWS_PROFILE) and try again"

# The ssh key: the person's, or one made for this.
if [ -z "$PUB" ]; then
  for k in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub" "$HOME/.ssh/vaultgenome_ed25519.pub"; do [ -f "$k" ] && { PUB="$k"; break; }; done
  if [ -z "$PUB" ]; then
    mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
    ssh-keygen -q -t ed25519 -N '' -C "vaultgenome deploy" -f "$HOME/.ssh/vaultgenome_ed25519" || die "could not make an ssh key"
    PUB="$HOME/.ssh/vaultgenome_ed25519.pub"; say "an ssh key was made for this: $PUB"
  fi
fi
[ -f "$PUB" ] || die "no such public key: $PUB"
PRIV="${PUB%.pub}"; [ -f "$PRIV" ] || die "the private key of $PUB was not found at $PRIV"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REC="$HERE/records/$STAMP"; mkdir -p "$REC/verify"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
stack_output() { cfn describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text 2>/dev/null || true; }
instance_ip() { ec2 describe-instances --instance-ids "$1" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null || true; }

if [ "$ATTACH" = 1 ]; then
  # A dropped session: the stack exists and its guest is at work or done;
  # only its record is wanted. The release was verified by the run that
  # created it, whose records/ directory holds that.
  ID="$(stack_output InstanceId)"; [ -n "$ID" ] && [ "$ID" != None ] || die "no stack named $STACK in $REGION that deploy.sh created (no InstanceId output)"
  META="$(ec2 describe-instances --instance-ids "$ID" --query 'Reservations[0].Instances[0].[Tags[?Key==`vg-tag`]|[0].Value, Tags[?Key==`vg-stamp`]|[0].Value, InstanceType, Placement.AvailabilityZone]' --output text 2>/dev/null || true)"
  read -r TAG GSTAMP TYPE ZONE <<< "$(printf '%s' "$META" | tr '\t' ' ')"
  [ -n "${TAG:-}" ] && [ "$TAG" != None ] || die "the instance $ID of stack $STACK carries no vg-tag tag"
  IP="$(instance_ip "$ID")"
  say "attached to $STACK ($REGION, $ZONE, $TYPE, instance $ID), release $TAG; the record goes to $REC"
  { echo "region=$REGION"; echo "stack=$STACK"; echo "instance=$ID"; echo "zone=$ZONE"; echo "machine=$TYPE"; echo "platform=aws-sev-snp"; echo "release=$TAG"; echo "ip=$IP"; echo "attached=$STAMP"; echo "guest_stamp=$GSTAMP"; } > "$REC/deployment.txt"
else
GSTAMP="$STAMP"
say "Vault Genome $TAG → AWS, stack $STACK in $REGION; the record goes to $REC"

say "== 1. the verification tools"
{ echo "release: $TAG"; echo "verified at: $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(uname -sm)"
  vg_verify_tools "$HERE/.tools"
  echo "aws: $(aws --version 2>/dev/null | cut -d' ' -f1)"; } > "$REC/verify/tools.txt"
say "  $(sed -n '3,4p' "$REC/verify/tools.txt" | tr '\n' ';' | sed 's/;$//')"

say "== 2. the release $TAG, verified before it runs anywhere"
DL="$WORK/assets"; LIST="checksums-$TAG.txt"
vg_verify_release "$TAG" "$DL" "$REC/verify"
LIST_SHA="$($VG_SHA256 "$DL/$LIST" | cut -d' ' -f1)"

say "== 3. the stack, the template, the address"
if cfn describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text >/dev/null 2>&1; then
  die "a stack named $STACK exists in $REGION already: pass --stack <other>, or remove it with destroy.sh"
fi
# The template deployed is made from guest.sh as it is here; the committed
# one is what the button uses and the kit checks it is the same.
"$HERE/make-template.sh" "$WORK/template.json" >/dev/null
cmp -s "$WORK/template.json" "$HERE/template.json" || say "  note: template.json beside this script is not what guest.sh makes now; the one made now is deployed"
if [ -z "$FROM" ]; then
  MYIP="$(curl -fsS --max-time 10 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' || true)"
  case "$MYIP" in *.*.*.*) FROM="$MYIP/32";; *) FROM="0.0.0.0/0"; say "  this machine's address could not be read; port 22 is open to anyone with the key";; esac
fi
PRICE="about USD 0.19 an hour for an m6a.xlarge in Ohio (the on-demand rate plus AWS's 10 percent for SEV-SNP)"
say "  one $TYPE with AmdSevSnp enabled, Ubuntu 24.04 (Canonical's current AMI, UEFI), 32 GB encrypted disk, ssh from $FROM: $PRICE while it runs; destroy.sh removes the stack"
if [ "$YES" != 1 ]; then
  printf 'Deploy Vault Genome %s as stack %s in %s? [y/N] ' "$TAG" "$STACK" "$REGION"
  read -r answer; case "$answer" in y|Y|yes) ;; *) say "not deployed"; exit 0;; esac
fi

say "== 4. the instance"
python3 - "$WORK/params.json" "$NAME" "$TYPE" "$(cat "$PUB")" "$FROM" "$TAG" "$LIST_SHA" "$STAMP" "$VPC" "$SUBNET" <<'PY'
import json, sys
keys = ["InstanceName", "InstanceType", "SshPublicKey", "SshSourceCidr", "Release", "ChecksumsSha256", "Stamp", "VpcId", "SubnetId"]
json.dump([{"ParameterKey": k, "ParameterValue": v} for k, v in zip(keys, sys.argv[2:])], open(sys.argv[1], "w"))
PY
# On a failure the stack's resources stay for a look (destroy.sh removes them).
cfn create-stack --stack-name "$STACK" --template-body "file://$WORK/template.json" --parameters "file://$WORK/params.json" \
  --on-failure DO_NOTHING --tags Key=app,Value=vaultgenome Key=vg-tag,Value="$TAG" --query 'length(StackId)' --output text > /dev/null 2> "$WORK/create.err" \
  || { scrub < "$WORK/create.err" | head -20; die "the stack $STACK could not be created in $REGION (see above)"; }
if ! cfn wait stack-create-complete --stack-name "$STACK" 2> "$WORK/wait.err"; then
  cfn describe-stack-events --stack-name "$STACK" --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`].[LogicalResourceId,ResourceStatusReason]' --output text 2>/dev/null | scrub | head -10
  die "the stack $STACK did not reach CREATE_COMPLETE (see above); what it created stays for a look: destroy.sh --region $REGION --stack $STACK"
fi
ID="$(stack_output InstanceId)"; IP="$(stack_output PublicIp)"
ZONE="$(ec2 describe-instances --instance-ids "$ID" --query 'Reservations[0].Instances[0].Placement.AvailabilityZone' --output text 2>/dev/null || true)"
say "  $ID is up at $IP ($ZONE); the guest is reading the chip, installing, provisioning and proving — about five minutes"
{ echo "region=$REGION"; echo "stack=$STACK"; echo "instance=$ID"; echo "zone=$ZONE"; echo "machine=$TYPE"; echo "platform=aws-sev-snp"; echo "release=$TAG"; echo "admin=$ADMIN"; echo "ip=$IP"; echo "ssh_from=$FROM"; echo "started=$STAMP"; echo "guest_stamp=$STAMP"; } > "$REC/deployment.txt"
cfn describe-stacks --stack-name "$STACK" --query 'Stacks[0].Outputs' --output json > "$REC/deployment-outputs.json" 2>/dev/null || true
fi

say "== 5. waiting for the guest's record (up to 30 minutes)"
[ -n "${IP:-}" ] && [ "$IP" != None ] || IP="$(instance_ip "$ID")"
SSH=(ssh -i "$PRIV" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)
# The serial console, as `get-console-output --latest` returns it (the
# latest output of a Nitro instance, decoded by the CLI).
console() { ec2 get-console-output --instance-id "$ID" --latest --query Output --output text 2>/dev/null || true; }
SERIAL="$WORK/serial.txt"; RESULT=""
for _ in $(seq 1 120); do
  sleep 15
  console > "$SERIAL"
  if grep -q '===VG-PROVEN-END===' "$SERIAL"; then RESULT="recorded"; break; fi
  if grep -q '===VG-DEPLOY-FAILED=== ' "$SERIAL"; then RESULT="failed"; break; fi
  # The record on disk is the earlier sign: the console is written last.
  if [ -n "$IP" ] && [ "$IP" != None ] && "${SSH[@]}" -n "$ADMIN@$IP" "test -f /var/lib/vaultgenome/record/$GSTAMP/sha256sums.txt && test -f /etc/vaultgenome/DEPLOYED" 2>/dev/null; then RESULT="recorded"; sleep 10; console > "$SERIAL"; break; fi
  last="$(grep -o '== [^\r]*' "$SERIAL" | tail -1 | sed 's/^== //' || true)"
  [ -z "$last" ] || printf '\r  %.*s\033[K' "$(( ${COLUMNS:-$(tput cols 2>/dev/null || echo 80)} - 4 ))" "$last"
done
printf '\r\033[K'
# The console copy kept on the record is scrubbed: the image's SSM agent,
# finding no role, prints its refusal with the caller's ARN on the console.
scrub < "$SERIAL" > "$REC/serial-console.txt"
if [ "$RESULT" = failed ]; then
  sed -n '/===VG-DEPLOY-FAILED===/,/===VG-DEPLOY-FAILED-END===/p' "$SERIAL" | scrub | head -60
  die "the guest stopped. The instance $ID stays for a look: ssh -i $PRIV $ADMIN@$IP 'sudo tail -100 /var/log/vaultgenome-deploy.log' — then destroy.sh --region $REGION --stack $STACK"
fi
[ "$RESULT" = "recorded" ] || die "no record after 30 minutes; the serial console is at $REC/serial-console.txt and the instance $ID stays in stack $STACK"

# The record: over ssh from the instance's own copy; from the console's
# copy when ssh is not reachable from here. A copy that did not complete
# is not kept.
if [ -n "$IP" ] && [ "$IP" != None ] && scp -q -r -i "$PRIV" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes "$ADMIN@$IP:/var/lib/vaultgenome/record/$GSTAMP" "$WORK/guest" 2>/dev/null \
   && [ -f "$WORK/guest/sha256sums.txt" ] && ( cd "$WORK/guest" && $VG_SHA256 -c --quiet sha256sums.txt >/dev/null 2>&1 ); then
  mv "$WORK/guest" "$REC/guest"
  say "  the guest's record: fetched over ssh from /var/lib/vaultgenome/record/$GSTAMP, every file as its sha256sums.txt names it -> $REC/guest"
else
  rm -rf "${WORK:?}/guest"
  python3 - "$SERIAL" "$REC" <<'PY'
import base64, hashlib, io, re, sys, tarfile, os, shutil
serial, dest = sys.argv[1], sys.argv[2]
text = open(serial, errors="replace").read()
for m in re.finditer(r"===VG-DEPLOY-BEGIN=== (\S+) size=(\d+) sha256=([0-9a-f]{64}) lines=(\d+) copy=\d+\n(.*?)===VG-DEPLOY-END===", text, re.S):
    stamp, size, digest, nlines = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
    lines = {}
    for line in m.group(5).splitlines():
        mm = re.match(r".*?@@(\d{4}) (\S+)$", line)
        if mm:
            lines[int(mm.group(1))] = mm.group(2)
    if len(lines) != nlines:
        continue
    b64 = "".join(lines[i] for i in range(nlines))
    if len(b64) != size or hashlib.sha256(b64.encode()).hexdigest() != digest:
        continue
    blob = base64.b64decode(b64)
    tmp = os.path.join(dest, ".unpack"); os.makedirs(tmp, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not (member.isfile() or member.isdir()) or member.name.startswith("/") or ".." in member.name.split("/"):
                sys.exit(f"refusing tar member {member.name!r}")
        tar.extractall(tmp)
    shutil.move(os.path.join(tmp, stamp), os.path.join(dest, "guest")); shutil.rmtree(tmp)
    print(f"  the guest's record: from the serial console, {len(blob)} bytes, sha256(b64)={digest} -> {dest}/guest")
    sys.exit(0)
sys.exit("no intact copy of the record in the serial output, and ssh did not reach the instance")
PY
fi

say "== 6. what was proven"
python3 - "$REC" "$TAG" "$STACK" "$REGION" <<'PY'
import json, os, re, sys
rec, tag, stack, region = sys.argv[1:5]
g = os.path.join(rec, "guest")
def kv(path):
    d = {}
    for line in open(path):
        if "=" in line and not line.startswith("=="):
            k, v = line.rstrip("\n").split("=", 1); d.setdefault(k, v)
    return d
steps = kv(os.path.join(g, "steps.txt")); meta = kv(os.path.join(g, "metadata.txt")); tl = kv(os.path.join(g, "timeline.txt"))
prov = json.load(open(os.path.join(g, "provision.json")))
job = json.load(open(os.path.join(g, "job.json"))); gate = job.get("gate") or {}; verdict = (gate.get("signed_verdict") or {}).get("verdict") or {}
audit = json.load(open(os.path.join(g, "audit-verify.json")))
chip = open(os.path.join(g, "chip.txt")).read().strip()
vcpus = open(os.path.join(g, "nproc.txt")).read().strip()
v = os.path.join(rec, "verify")
verified = os.path.exists(os.path.join(v, "tag.txt"))
if verified:
    tagline = [l for l in open(os.path.join(v, "tag.txt")) if "Good" in l][0].strip()
    slsa = sum(1 for l in open(os.path.join(v, "slsa.txt")) if "PASSED: SLSA verification passed" in l)
    oks = sum(1 for l in open(os.path.join(v, "checksums.txt")) if l.rstrip().endswith(": OK"))
guest_oks = steps.get("checksums_ok", "?").split(" ")[0]
def secs(a, b):
    from datetime import datetime
    try:
        f = lambda s: datetime.strptime(s[:26], "%Y-%m-%dT%H:%M:%S.%f")
        return "%.1f s" % (f(tl[b]) - f(tl[a])).total_seconds()
    except Exception:
        return "?"
m = re.search(r"product=(\S+) signing_key=(\S+) report_id=(\S+) .*?snp=(\S+) microcode=(\S+) firmware=(\S+) alias_check=(\S+) .*?vlek_csp_id=(\S+) vlek_not_after=(\S+)", chip)
print(f"PROVEN — Vault Genome {tag} on {meta.get('instance')} (stack {stack}, {meta.get('location')}): {meta.get('machine')}, Amazon EC2, AMD SEV-SNP ({steps.get('product', '?')}) under the provider's key, a VLEK")
if verified:
    print(f"  release      {tagline}")
    print(f"               the checksums list signed by release.yml@{tag} (cosign); {oks} of 5 files on the list; {slsa} of 5 SLSA provenances against the source tag")
else:
    print(f"  release      verified by the run that created the stack (its records/<stamp>/verify/)")
same = "the same list this machine verified" if steps.get("checksums_list_matches_deployer") == "true" else "its SHA-256 on the record"
print(f"               on the guest: the list verified again under the release identity ({steps.get('guest_cosign', '?')}), {same}; {guest_oks} of 5 files fetched from GitHub on it")
if m:
    print(f"  chip         AMD {m.group(1)}: the report signed by a {m.group(2).upper()} (REPORT_ID {m.group(3)[:16]}…, no CHIP_ID), the VLEK {m.group(8)} valid to {m.group(9)[:10]}, chained to AMD's root; TCB snp={m.group(4)} microcode={m.group(5)} firmware={m.group(6)} alias_check={m.group(7)} against the floors of AMD's bulletins (ADR 0033, 0038)")
csp = (prov.get("vault") or {}).get("vlek_csp_id") or ""
print(f"  identities   vault {prov['vault']['measurement_hex'][:16]}… = worker {prov['worker']['measurement_hex'][:16]}…: the launch measurement — AWS's published UEFI measured for {vcpus} vCPUs (the runbook says how to compute it) — pinned on both sides; the provider {csp} pinned on both sides")
sealed = prov.get("sealed", {})
print(f"  key files    {len(sealed.get('sagvd', []))} + {len(sealed.get('acp-compute', []))} sealed with the firmware's derived key (tee.sealer {prov.get('sealer')}: {prov['vault'].get('sealer')}) — on EC2 the fleet's: they open on any EC2 SEV-SNP guest of this measurement and policy, and so survive a stop/start (KNOWN_ISSUES 19) — provision {secs('provision_start', 'provision_end')}")
print(f"  services     sagvd ready {steps.get('sagvd_ready_after', '?')} after its start, the worker's session opened {steps.get('session_opened_after', '?')} after the worker's (sagvd.service, acp-compute.service); paused {secs('pause_start', 'pause_end')} for the audit read, back with the sealed key files opened again (ready {steps.get('restart_sagvd_ready_after', '?')}, session {steps.get('restart_session_opened_after', '?')})")
print(f"  gate         job {job.get('job_id', '?')}: {gate.get('level')} at rung {gate.get('rung')}, {verdict.get('n_exact')} of {gate.get('fixtures')} fixtures byte for byte (max_abs_err {verdict.get('max_abs_err')}), the verdict signed by {gate.get('signer_key_id')} — {secs('job_submit', 'job_done')} from submission")
print(f"  audit log    ok={str(audit.get('ok')).lower()}, {audit.get('event_count', '?')} events verified under the operator's key (records/{os.path.basename(rec)}/guest/audit-public-key.pem)")
print(f"  time         {steps.get('elapsed_seconds', '?')} s on the guest from its first command to the verified audit log; the record's hashes in guest/sha256sums.txt")
PY

cat <<EOF

The deployment is running. Its record: $REC
  on the instance  ssh -i $PRIV $ADMIN@$IP
  look             sudo vg health · sudo vg status · sudo vg logs sagvd
  the audit log    sudo vg verify · sudo vg audit · sudo vg events 20   (the services pause for the read, about 15 s)
  another job      sudo vg submit gen-0.genome gen-0.key
  your own model   seal its genome with acpctl (docs/operator/09_first_deployment.md §4) into /var/lib/vaultgenome/genomes, then vg submit
  the console      aws ec2 get-console-output --region $REGION --instance-id $ID --latest --output text
  a stop/start     moves the instance to another host and gives it a new public address (aws ec2 describe-instances --instance-ids $ID); the services and the sealed key files come back on their own
  remove it        $HERE/destroy.sh --region $REGION --stack $STACK
EOF
