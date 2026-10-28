#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# One button on Azure: a Vault Genome deployment on an Azure Confidential
# VM (AMD SEV-SNP, DCasv5) from the signed release, proven the way the
# reference deployment is proven, and left running. The same template the
# Deploy to Azure button uses (azuredeploy.json), driven from the Azure
# CLI so the record comes back to the machine that ran it.
#
#   1. the release is verified here, before anything runs anywhere
#      (deploy/lib/verify-release.sh: the signed checksums list under the
#      release workflow's identity for this very tag, the five files
#      against the list, their SLSA provenance, the tag's signature against
#      the keys pinned on main);
#   2. the template is deployed into a resource group: one Confidential VM
#      (secure boot, vTPM, the OS disk encrypted with the VM guest state),
#      its network, port 22 open to this machine's address only, guest.sh
#      as the VM's cloud-init script and the list's SHA-256 in its tags —
#      the guest verifies the list itself and refuses any other;
#   3. the guest installs, reboots once so the key files are sealed on a
#      settled boot, provisions with `acpctl provision`, starts both
#      daemons as services, gates a first genome over the Return Path and
#      verifies its audit log (guest.sh);
#   4. the record is fetched over ssh into records/<stamp>/ beside this
#      script, with the verification outputs of step 1 (the serial console
#      carried the same record: the fallback when ssh is not reachable);
#      the summary says what was proven. The VM stays.
#
# Usage: deploy.sh [--resource-group RG] [--location LOC] [--name NAME]
#                  [--size SIZE] [--tag TAG] [--ssh-key PUBKEY] [--admin USER] [--yes]
#        deploy.sh --attach [--resource-group RG] [--name NAME] [--ssh-key PUBKEY]
#                  (a session that dropped while the guest was at work)
# Defaults: resource group "vaultgenome" (created when missing), West
# Europe, the name "vaultgenome", Standard_DC4as_v5, the release this
# checkout is tagged as or else the latest, ~/.ssh/id_ed25519.pub or
# ~/.ssh/id_rsa.pub (else a key is made at ~/.ssh/vaultgenome_ed25519),
# the user "vgadmin".
# Needs az (signed in: az login), curl, git, python3, ssh, scp; cosign and
# slsa-verifier on PATH, or on Linux x86-64 they are fetched at pinned hashes.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/deploy/lib/verify-release.sh"
REPO="$VG_REPO"

RG="vaultgenome"; LOC="westeurope"; NAME="vaultgenome"; SIZE="Standard_DC4as_v5"; TAG=""; PUB=""; ADMIN="vgadmin"; YES=0; ATTACH=0
while [ $# -gt 0 ]; do
  case "$1" in
    --resource-group|-g) RG="${2:?}"; shift 2;;
    --location|-l) LOC="${2:?}"; shift 2;;
    --name|-n) NAME="${2:?}"; shift 2;;
    --size) SIZE="${2:?}"; shift 2;;
    --tag) TAG="${2:?}"; shift 2;;
    --ssh-key) PUB="${2:?}"; shift 2;;
    --admin) ADMIN="${2:?}"; shift 2;;
    --yes|-y) YES=1; shift;;
    --attach) ATTACH=1; shift;;
    -h|--help) sed -n '5,41p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2;;
  esac
done

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is needed: $2"; }
need az "https://learn.microsoft.com/cli/azure/install-azure-cli"
need curl "curl"; need git "git"; need python3 "python3"; need ssh "ssh"; need scp "scp"
command -v sha256sum >/dev/null 2>&1 || need shasum "sha256sum or shasum"

# The release: --tag, else this checkout's tag, else the latest release —
# whichever, it is verified below before anything runs.
if [ -z "$TAG" ]; then
  TAG="$(git -C "$ROOT" describe --tags --exact-match HEAD 2>/dev/null || true)"
  if [ -z "$TAG" ]; then
    TAG="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null || true)"
    [ -n "$TAG" ] || die "this checkout is not at a release tag and the latest release could not be read; name one: --tag v0.13.0"
  fi
fi
case "$TAG" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "--tag must be a release tag such as v0.13.0";; esac

SUB="$(az account show --query '{n:name,u:user.name}' -o tsv 2>/dev/null | tr '\t' ' ' || true)"
[ -n "$SUB" ] || die "az is not signed in here: run 'az login' and try again"

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

if [ "$ATTACH" = 1 ]; then
  # A dropped session: the VM exists and its guest is at work or done; only
  # its record is wanted. The release was verified by the run that created
  # it, whose records/ directory holds that.
  META="$(az vm show -g "$RG" -n "$NAME" --query '{tag:tags."vg-tag", stamp:tags."vg-stamp", size:hardwareProfile.vmSize, loc:location}' -o tsv 2>/dev/null || true)"
  read -r TAG GSTAMP SIZE LOC <<< "$(printf '%s' "$META" | tr '\t' ' ')"
  [ -n "${TAG:-}" ] && [ "$TAG" != None ] || die "no VM named $NAME in $RG that deploy.sh created (no vg-tag tag)"
  say "attached to $NAME ($RG, $LOC, $SIZE), release $TAG; the record goes to $REC"
  { echo "resource_group=$RG"; echo "instance=$NAME"; echo "location=$LOC"; echo "machine=$SIZE"; echo "platform=azure-sev-snp"; echo "release=$TAG"; echo "attached=$STAMP"; echo "guest_stamp=$GSTAMP"; } > "$REC/deployment.txt"
else
GSTAMP="$STAMP"
say "Vault Genome $TAG → Azure, resource group $RG in $LOC, as $SUB; the record goes to $REC"

say "== 1. the verification tools"
{ echo "release: $TAG"; echo "verified at: $(date -u +%Y-%m-%dT%H:%M:%SZ) by $SUB on $(uname -sm)"
  vg_verify_tools "$HERE/.tools"
  echo "az: $(az version --query '"azure-cli"' -o tsv 2>/dev/null)"; } > "$REC/verify/tools.txt"
say "  $(sed -n '3,4p' "$REC/verify/tools.txt" | tr '\n' ';' | sed 's/;$//')"

say "== 2. the release $TAG, verified before it runs anywhere"
DL="$WORK/assets"; LIST="checksums-$TAG.txt"
vg_verify_release "$TAG" "$DL" "$REC/verify"
LIST_SHA="$($VG_SHA256 "$DL/$LIST" | cut -d' ' -f1)"

say "== 3. the resource group, the template, the address"
if ! az group show -n "$RG" -o none 2>/dev/null; then
  say "  creating the resource group $RG in $LOC"
  az group create -n "$RG" -l "$LOC" --tags app=vaultgenome -o none || die "could not create the resource group $RG"
fi
if az vm show -g "$RG" -n "$NAME" -o none 2>/dev/null; then
  die "a VM named $NAME exists in $RG already: pass --name <other>, or remove it with destroy.sh"
fi
# The template deployed is made from guest.sh as it is here; the committed
# one is what the button uses and the kit checks it is the same.
"$HERE/make-template.sh" "$WORK/azuredeploy.json" >/dev/null
cmp -s "$WORK/azuredeploy.json" "$HERE/azuredeploy.json" || say "  note: azuredeploy.json beside this script is not what guest.sh makes now; the one made now is deployed"
MYIP="$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)"
case "$MYIP" in *.*.*.*) PREFIX="$MYIP/32";; *) PREFIX="*"; say "  this machine's address could not be read; port 22 is open to anyone with the key";; esac
PRICE="about USD 0.21 an hour in West Europe, 0.17 in East US (Azure's DC4as v5 price)"
say "  one $SIZE Confidential VM, AMD SEV-SNP, Ubuntu 24.04 CVM image, secure boot and vTPM, 32 GB disk, ssh from $PREFIX: $PRICE while it runs; destroy.sh removes it"
if [ "$YES" != 1 ]; then
  printf 'Deploy Vault Genome %s into resource group %s (%s) as %s? [y/N] ' "$TAG" "$RG" "$LOC" "$NAME"
  read -r answer; case "$answer" in y|Y|yes) ;; *) say "not deployed"; exit 0;; esac
fi

say "== 4. the Confidential VM"
az deployment group create -g "$RG" -n "$NAME-$STAMP" --template-file "$WORK/azuredeploy.json" \
  --parameters vmName="$NAME" location="$LOC" vmSize="$SIZE" adminUsername="$ADMIN" sshPublicKey="$(cat "$PUB")" \
               release="$TAG" sshSourcePrefix="$PREFIX" checksumsSha256="$LIST_SHA" stamp="$STAMP" \
  --query 'properties.outputs' -o json > "$WORK/outputs.json" 2> "$WORK/deploy.err" \
  || { cat "$WORK/deploy.err" | head -40; die "the deployment of $NAME into $RG failed (see above); what it created stays for a look: destroy.sh --resource-group $RG --name $NAME"; }
IP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["publicIp"]["value"])' "$WORK/outputs.json")"
say "  $NAME is up at $IP ($LOC); the guest is installing, then reboots once so the key files are sealed on a settled boot, then provisions and proves — about six minutes"
{ echo "resource_group=$RG"; echo "instance=$NAME"; echo "location=$LOC"; echo "machine=$SIZE"; echo "platform=azure-sev-snp"; echo "release=$TAG"; echo "admin=$ADMIN"; echo "ip=$IP"; echo "ssh_from=$PREFIX"; echo "started=$STAMP"; echo "guest_stamp=$STAMP"; } > "$REC/deployment.txt"
cp "$WORK/outputs.json" "$REC/deployment-outputs.json"
fi

say "== 5. waiting for the guest's record (up to 30 minutes)"
IP="${IP:-$(az vm list-ip-addresses -g "$RG" -n "$NAME" --query '[0].virtualMachine.network.publicIpAddresses[0].ipAddress' -o tsv 2>/dev/null || true)}"
# The serial log comes back from az as a Python bytes literal (b'...');
# decoded here into the text the guest wrote.
bootlog() {
  az vm boot-diagnostics get-boot-log -g "$RG" -n "$NAME" -o json 2>/dev/null | python3 -c '
import ast, json, sys
try:
    s = json.load(sys.stdin)
except Exception:
    s = ""
if isinstance(s, str) and s[:2] in ("b\x27", "b\""):
    try:
        s = ast.literal_eval(s).decode("utf-8", "replace")
    except Exception:
        pass
sys.stdout.write(s if isinstance(s, str) else "")' 2>/dev/null || true
}
SERIAL="$WORK/serial.txt"; RESULT=""
for _ in $(seq 1 120); do
  sleep 15
  bootlog > "$SERIAL"
  if grep -q '===VG-DEPLOY-END===' "$SERIAL"; then RESULT="recorded"; break; fi
  if grep -q '===VG-DEPLOY-FAILED===' "$SERIAL"; then RESULT="failed"; break; fi
  last="$(grep -o '== [^\r]*' "$SERIAL" | tail -1 | sed 's/^== //' || true)"
  [ -z "$last" ] || printf '\r  %.*s\033[K' "$(( ${COLUMNS:-$(tput cols 2>/dev/null || echo 80)} - 4 ))" "$last"
done
printf '\r\033[K'
cp "$SERIAL" "$REC/serial-console.txt"
if [ "$RESULT" = failed ]; then
  sed -n '/===VG-DEPLOY-FAILED===/,/===VG-DEPLOY-FAILED-END===/p' "$SERIAL" | head -60
  die "the guest stopped. The VM $NAME stays for a look: ssh -i $PRIV $ADMIN@$IP 'sudo tail -100 /var/log/vaultgenome-deploy.log' — then destroy.sh --resource-group $RG --name $NAME"
fi
[ "$RESULT" = "recorded" ] || die "no record after 30 minutes; the serial console is at $REC/serial-console.txt and the VM $NAME stays in $RG"

# The record: over ssh from the VM's own copy; from the console's copy
# when ssh is not reachable from here. A copy that did not complete is
# not kept.
if [ -n "$IP" ] && scp -q -r -i "$PRIV" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes "$ADMIN@$IP:/var/lib/vaultgenome/record/$GSTAMP" "$WORK/guest" 2>/dev/null \
   && [ -f "$WORK/guest/sha256sums.txt" ] && ( cd "$WORK/guest" && $VG_SHA256 -c --quiet sha256sums.txt >/dev/null 2>&1 ); then
  mv "$WORK/guest" "$REC/guest"
  say "  the guest's record: fetched over ssh from /var/lib/vaultgenome/record/$GSTAMP, every file as its sha256sums.txt names it -> $REC/guest"
else
  rm -rf "$WORK/guest"
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
sys.exit("no intact copy of the record in the serial output, and ssh did not reach the VM")
PY
fi

say "== 6. what was proven"
python3 - "$REC" "$TAG" "$NAME" "$RG" "$LOC" <<'PY'
import json, os, re, sys
rec, tag, name, rg, loc = sys.argv[1:6]
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
m = re.search(r"product=(\S+).*?snp=(\S+) microcode=(\S+) firmware=(\S+) alias_check=(\S+)", chip)
print(f"PROVEN — Vault Genome {tag} on {name} (resource group {rg}, {loc}): {meta.get('machine')}, Azure Confidential VM, AMD SEV-SNP ({steps.get('product', '?')}) under the paravisor")
if verified:
    print(f"  release      {tagline}")
    print(f"               the checksums list signed by release.yml@{tag} (cosign); {oks} of 5 files on the list; {slsa} of 5 SLSA provenances against the source tag")
else:
    print(f"  release      verified by the run that created the VM (its records/<stamp>/verify/)")
same = "the same list this machine verified" if steps.get("checksums_list_matches_deployer") == "true" else "its SHA-256 on the record"
print(f"               on the guest: the list verified again under the release identity ({steps.get('guest_cosign', '?')}), {same}; {guest_oks} of 5 files fetched from GitHub on it")
if m:
    print(f"  chip         AMD {m.group(1)}: TCB snp={m.group(2)} microcode={m.group(3)} firmware={m.group(4)} alias_check={m.group(5)} — the report from the vTPM's HCL report, the VCEK chain to AMD's root, the TCB against the floors of AMD's bulletins (ADR 0033); the quote by the vTPM's attestation key binds the handshake")
boot = (prov.get("worker") or {}).get("vtpm_pcr_digest_hex") or ""
print(f"  identities   vault {prov['vault']['measurement_hex'][:16]}… = worker {prov['worker']['measurement_hex'][:16]}…: Azure's launch measurement (the paravisor and firmware), pinned on both sides; the boot the vTPM measured, {boot[:16]}…, pinned too (ADR 0037)")
sealed = prov.get("sealed", {})
settled = "; sealed on a settled boot, after one reboot" if "reboot" in tl else ""
print(f"  key files    {len(sealed.get('sagvd', []))} + {len(sealed.get('acp-compute', []))} sealed to the vTPM (tee.sealer {prov.get('sealer')}: {prov['vault'].get('sealer')}) — provision {secs('provision_start', 'provision_end')}{settled}")
print(f"  services     sagvd ready {steps.get('sagvd_ready_after', '?')} after its start, the worker's session opened {steps.get('session_opened_after', '?')} after the worker's (sagvd.service, acp-compute.service); paused {secs('pause_start', 'pause_end')} for the audit read, back with the sealed key files opened again (ready {steps.get('restart_sagvd_ready_after', '?')}, session {steps.get('restart_session_opened_after', '?')})")
print(f"  gate         job {job.get('job_id', '?')}: {gate.get('level')} at rung {gate.get('rung')}, {verdict.get('n_exact')} of {gate.get('fixtures')} fixtures byte for byte (max_abs_err {verdict.get('max_abs_err')}), the verdict signed by {gate.get('signer_key_id')} — {secs('job_submit', 'job_done')} from submission")
print(f"  audit log    ok={str(audit.get('ok')).lower()}, {audit.get('event_count', '?')} events verified under the operator's key (records/{os.path.basename(rec)}/guest/audit-public-key.pem)")
print(f"  time         {steps.get('elapsed_seconds', '?')} s on the settled boot from its first command to the sealed verdict; the record's hashes in guest/sha256sums.txt")
PY

cat <<EOF

The deployment is running. Its record: $REC
  on the VM        ssh -i $PRIV $ADMIN@$IP
  look             sudo vg health · sudo vg status · sudo vg logs sagvd
  the audit log    sudo vg verify · sudo vg audit · sudo vg events 20   (the services pause for the read, about 15 s)
  another job      sudo vg submit gen-0.genome gen-0.key
  your own model   seal its genome with acpctl (docs/operator/09_first_deployment.md §4) into /var/lib/vaultgenome/genomes, then vg submit
  remove it        $HERE/destroy.sh --resource-group $RG --name $NAME
EOF
