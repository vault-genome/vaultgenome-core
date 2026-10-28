#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# One button on Google Cloud: a Vault Genome deployment on a Compute Engine
# Confidential VM — AMD SEV-SNP (n2d) or Intel TDX (c3) — from the signed
# release, proven the way the reference deployment is proven, and left
# running.
#
#   1. the release is verified here, before anything runs anywhere: the
#      signed checksums list against the release workflow's identity for
#      this very tag (cosign), the binaries and the worker package against
#      the list, their SLSA provenance against the source tag
#      (slsa-verifier), and the tag's own signature against the keys pinned
#      on main — never against keys in the tagged tree;
#   2. a Confidential VM — an n2d-standard-4 on AMD Milan with SEV-SNP, or
#      with --platform tdx a c3-standard-4 Trust Domain on Intel TDX — is
#      created with guest.sh as its startup script and the verified list in
#      its metadata: the guest fetches the release itself and runs only
#      what is on the list;
#   3. the guest provisions the deployment with `acpctl provision`, starts
#      both daemons as systemd services, gates a first genome over the
#      Return Path and verifies its audit log (guest.sh);
#   4. the record comes back over the serial console and is kept under
#      records/<stamp>/ beside this script, with the verification outputs
#      of step 1; the summary says what was proven. The VM stays.
#
# Usage: deploy.sh [--project ID] [--zone ZONE] [--name NAME] [--tag TAG]
#                  [--platform sev-snp|tdx] [--sealer auto|tee|tpm2] [--yes]
#        deploy.sh --attach [--project ID] [--name NAME] [--zone ZONE]
#                  (a session that dropped while the guest was at work:
#                  wait for the record of the VM that exists, nothing else)
# Defaults: the gcloud project; us-central1-c (then -b, -a, -f when the
# zone has no capacity); the name "vaultgenome"; the release this checkout
# is tagged as, or the latest release when it is not at a tag; sev-snp;
# tee.sealer auto — on SEV-SNP the chip's own key (the key files open on
# this chip only), on TDX the guest's vTPM under this boot's PCRs (ADR
# 0023, 0025 step 1b).
# Needs gcloud (signed in), curl, git, python3; cosign and slsa-verifier
# on PATH, or on Linux x86-64 they are fetched at pinned hashes.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# The release verified before anything runs: the part the buttons share.
# shellcheck disable=SC1091
. "$ROOT/deploy/lib/verify-release.sh"
REPO="$VG_REPO"
ZONES_DEFAULT="us-central1-c us-central1-b us-central1-a us-central1-f"

PROJECT=""; ZONE=""; NAME="vaultgenome"; TAG=""; PLATFORM="sev-snp"; SEALER="auto"; YES=0; ATTACH=0
while [ $# -gt 0 ]; do
  case "$1" in
    --project) PROJECT="${2:?}"; shift 2;;
    --zone) ZONE="${2:?}"; shift 2;;
    --name) NAME="${2:?}"; shift 2;;
    --tag) TAG="${2:?}"; shift 2;;
    --platform) PLATFORM="${2:?}"; shift 2;;
    --sealer) SEALER="${2:?}"; shift 2;;
    --yes|-y) YES=1; shift;;
    --attach) ATTACH=1; shift;;
    -h|--help) sed -n '5,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2;;
  esac
done
case "$SEALER" in auto|tee|tpm2) ;; *) echo "--sealer must be auto, tee or tpm2" >&2; exit 2;; esac
# The machine and its TEE, by platform (the kits' shapes: gcp-sev-snp and
# gcp-tdx); the vTPM is on for both, the boot-chain family's later use.
case "$PLATFORM" in
  sev-snp) MACHINE="n2d-standard-4"; HW="AMD Milan, SEV-SNP"; TEE_FLAGS=(--min-cpu-platform "AMD Milan" --confidential-compute-type SEV_SNP); PRICE="about USD 0.20 an hour (Google's N2D price plus its SEV-SNP premium)";;
  tdx)     MACHINE="c3-standard-4"; HW="Intel TDX"; TEE_FLAGS=(--confidential-compute-type TDX); PRICE="about USD 0.25 an hour (Google's C3 price plus its TDX premium)";;
  *) echo "--platform must be sev-snp or tdx" >&2; exit 2;;
esac

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is needed: $2"; }
need gcloud "https://cloud.google.com/sdk/docs/install (Cloud Shell has it)"
need curl "curl"; need git "git"; need python3 "python3"
command -v sha256sum >/dev/null 2>&1 || need shasum "sha256sum or shasum"
b64() { base64 < "$1" | tr -d '\n'; }

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

# Credentials are proven by a token, not by a listed account: Cloud Shell
# hands gcloud the person's credentials on the first real request (its
# "Authorize Cloud Shell" prompt), and lists no account before that.
gcloud auth print-access-token >/dev/null 2>&1 \
  || die "gcloud has no credentials here. In your own Cloud Shell: allow the Authorize prompt when it appears, then try again. In a temporary Cloud Shell session, or anywhere else: run 'gcloud auth login' first"
ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -1 || true)"
[ -n "$ACCOUNT" ] || ACCOUNT="$(gcloud config get-value account 2>/dev/null || true)"
[ -n "$ACCOUNT" ] || ACCOUNT="the signed-in account"
if [ -z "$PROJECT" ]; then
  PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
  [ -n "$PROJECT" ] && [ "$PROJECT" != "(unset)" ] || PROJECT="${GOOGLE_CLOUD_PROJECT:-${DEVSHELL_PROJECT_ID:-}}"
fi
[ -n "$PROJECT" ] && [ "$PROJECT" != "(unset)" ] || die "no project: pass --project <id> or 'gcloud config set project <id>'"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REC="$HERE/records/$STAMP"; mkdir -p "$REC/verify"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

if [ "$ATTACH" = 1 ]; then
  # A dropped session: the VM exists and its guest is at work or done; only
  # its record is wanted. The release was verified by the run that created
  # it, whose records/ directory holds that.
  [ -n "$ZONE" ] || ZONE="$(gcloud compute instances list --project "$PROJECT" --filter="name=$NAME" --format='value(zone.basename())' 2>/dev/null | head -1 || true)"
  [ -n "$ZONE" ] || die "no instance named $NAME in $PROJECT to attach to"
  META="$(gcloud compute instances describe "$NAME" --project "$PROJECT" --zone "$ZONE" --format=json 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); m={i["key"]: i["value"] for i in (d.get("metadata") or {}).get("items", [])}; print(m.get("vg-tag", ""), m.get("vg-platform", "sev-snp"), d.get("machineType", "").rsplit("/", 1)[-1])' || true)"
  read -r TAG PLATFORM MACHINE <<< "$META"
  [ -n "$TAG" ] || die "$NAME in $ZONE was not created by deploy.sh (no vg-tag in its metadata)"
  case "$PLATFORM" in tdx) HW="Intel TDX";; *) PLATFORM="sev-snp"; HW="AMD Milan, SEV-SNP";; esac
  say "attached to $NAME ($ZONE, project $PROJECT), release $TAG on $HW; the record goes to $REC"
  { echo "project=$PROJECT"; echo "instance=$NAME"; echo "zone=$ZONE"; echo "machine=$MACHINE"; echo "platform=$PLATFORM"; echo "release=$TAG"; echo "attached=$STAMP"; } > "$REC/deployment.txt"
else
say "Vault Genome $TAG → project $PROJECT, as $ACCOUNT; the record goes to $REC"

say "== 1. the verification tools"
{ echo "release: $TAG"; echo "verified at: $(date -u +%Y-%m-%dT%H:%M:%SZ) by $ACCOUNT on $(uname -sm)"
  vg_verify_tools "$HERE/.tools"
  echo "gcloud: $(gcloud version 2>/dev/null | head -1)"; } > "$REC/verify/tools.txt"
say "  $(sed -n '3,4p' "$REC/verify/tools.txt" | tr '\n' ';' | sed 's/;$//')"

say "== 2. the release $TAG, verified before it runs anywhere"
DL="$WORK/assets"; LIST="checksums-$TAG.txt"
vg_verify_release "$TAG" "$DL" "$REC/verify"

say "== 3. the project"
if ! gcloud services list --enabled --project "$PROJECT" --filter='name:compute.googleapis.com' --format='value(name)' 2>/dev/null | grep -q compute; then
  say "  enabling the Compute Engine API in $PROJECT (once; a minute)"
  gcloud services enable compute.googleapis.com --project "$PROJECT" >/dev/null || die "could not enable compute.googleapis.com in $PROJECT"
fi
if gcloud compute instances list --project "$PROJECT" --filter="name=$NAME" --format='value(name,zone)' 2>/dev/null | grep -q .; then
  die "an instance named $NAME exists in $PROJECT already: pass --name <other>, or remove it with destroy.sh"
fi
say "  one $MACHINE Confidential VM, $HW, Ubuntu 24.04, 20 GB disk: $PRICE while it runs; destroy.sh removes it"
if [ "$YES" != 1 ]; then
  printf 'Deploy Vault Genome %s on %s into project %s as %s? [y/N] ' "$TAG" "$HW" "$PROJECT" "$NAME"
  read -r answer; case "$answer" in y|Y|yes) ;; *) say "not deployed"; exit 0;; esac
fi

say "== 4. the Confidential VM"
CREATED=""
for z in ${ZONE:-$ZONES_DEFAULT}; do
  if out=$(gcloud compute instances create "$NAME" --project "$PROJECT" --zone "$z" \
      --machine-type "$MACHINE" "${TEE_FLAGS[@]}" --maintenance-policy TERMINATE \
      --shielded-vtpm --shielded-integrity-monitoring \
      --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
      --boot-disk-size 20GB --labels "app=vaultgenome,platform=$PLATFORM" \
      --metadata "vg-tag=$TAG,vg-platform=$PLATFORM,vg-sealer=$SEALER,vg-stamp=$STAMP,vg-checksums=$(b64 "$DL/$LIST")" \
      --metadata-from-file "startup-script=$HERE/guest.sh" 2>&1); then
    CREATED="$z"; break
  fi
  if printf '%s' "$out" | grep -qi 'ZONE_RESOURCE_POOL_EXHAUSTED\|does not have enough resources\|STOCKOUT'; then
    say "  $z has no $MACHINE capacity right now; trying the next zone"; continue
  fi
  printf '%s\n' "$out" >&2; die "could not create $NAME in $z"
done
[ -n "$CREATED" ] || die "no zone of ${ZONE:-$ZONES_DEFAULT} had capacity for $MACHINE; try again later or pass --zone"
ZONE="$CREATED"
if [ "$PLATFORM" = tdx ] || [ "$SEALER" = tpm2 ]; then
  say "  $NAME is up in $ZONE; the guest is installing, then reboots once so the key files are sealed on a settled boot, then provisions and proves — about four minutes"
else
  say "  $NAME is up in $ZONE; the guest is installing, provisioning and proving — about three minutes"
fi
{ echo "project=$PROJECT"; echo "instance=$NAME"; echo "zone=$ZONE"; echo "machine=$MACHINE"; echo "platform=$PLATFORM"; echo "release=$TAG"; echo "sealer=$SEALER"; echo "started=$STAMP"; } > "$REC/deployment.txt"
fi

say "== 5. waiting for the guest's record (up to 25 minutes)"
SERIAL="$WORK/serial.txt"; RESULT=""
for _ in $(seq 1 150); do
  sleep 10
  gcloud compute instances get-serial-port-output "$NAME" --project "$PROJECT" --zone "$ZONE" > "$SERIAL" 2>/dev/null || true
  if grep -q '===VG-DEPLOY-END===' "$SERIAL"; then RESULT="recorded"; break; fi
  if grep -q '===VG-DEPLOY-FAILED===' "$SERIAL"; then RESULT="failed"; break; fi
  last="$(grep -o 'startup-script: == .*' "$SERIAL" | tail -1 | sed 's/startup-script: == //' || true)"
  # one line, rewritten in place and cut to the terminal's width: a wrapped
  # line would not be erased by the carriage return
  [ -z "$last" ] || printf '\r  %.*s\033[K' "$(( ${COLUMNS:-$(tput cols 2>/dev/null || echo 80)} - 4 ))" "$last"
done
printf '\r\033[K'
cp "$SERIAL" "$REC/serial-console.txt"
if [ "$RESULT" = failed ]; then
  sed -n '/===VG-DEPLOY-FAILED===/,/===VG-DEPLOY-FAILED-END===/p' "$SERIAL" | sed 's/^.*startup-script: //' | head -60
  die "the guest stopped. The VM $NAME stays for a look: gcloud compute ssh $NAME --zone $ZONE --project $PROJECT -- sudo tail -100 /var/log/vaultgenome-deploy.log — then destroy.sh --name $NAME --zone $ZONE"
fi
[ "$RESULT" = "recorded" ] || die "no record after 25 minutes; the serial console is at $REC/serial-console.txt and the VM $NAME stays in $ZONE"

# The record: an intact copy of the tarball the guest printed, unpacked
# beside the verification outputs.
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
    print(f"  the guest's record: {len(blob)} bytes, sha256(b64)={digest} -> {dest}/guest")
    sys.exit(0)
sys.exit("no intact copy of the record in the serial output")
PY

say "== 6. what was proven"
python3 - "$REC" "$TAG" "$NAME" "$ZONE" "$PROJECT" "$PLATFORM" "$HW" <<'PY'
import json, os, re, sys
rec, tag, name, zone, project, platform, hw = sys.argv[1:8]
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
print(f"PROVEN — Vault Genome {tag} on {name} ({zone}, project {project}): {meta.get('machine')}, {hw}")
if verified:
    print(f"  release      {tagline}")
    print(f"               the checksums list signed by release.yml@{tag} (cosign); {oks} of 5 files on the list; {slsa} of 5 SLSA provenances against the source tag")
else:
    print(f"  release      verified by the run that created the VM (its records/<stamp>/verify/)")
print(f"               on the guest: {guest_oks} of 5 files fetched from GitHub are on the signed list it was given (guest/checksums-check.txt)")
if m:
    print(f"  chip         AMD {m.group(1)}: TCB snp={m.group(2)} microcode={m.group(3)} firmware={m.group(4)} alias_check={m.group(5)} — the VCEK chain to AMD's root, the TCB against the floors of AMD's bulletins (ADR 0033)")
    print(f"  identities   vault {prov['vault']['measurement_hex'][:16]}… = worker {prov['worker']['measurement_hex'][:16]}…: this VM's launch measurement, read from the chip by each daemon and pinned by the other")
else:
    t = re.search(r"mrtd=(\S+) rtmr0=(\S+) rtmr1=(\S+) rtmr2=(\S+) rtmr3=(\S+) measurement=(\S+) fmspc=(\S+)", chip)
    if t:
        print(f"  trust domain MRTD {t.group(1)[:16]}…, RTMR0 {t.group(2)[:16]}…, RTMR1 {t.group(3)[:16]}…, RTMR2 {t.group(4)[:16]}… — the firmware, its configuration, the kernel, initrd and command line in the hardware's own registers; the quote under the PCK chain to Intel's root, Intel's TCB info (FMSPC {t.group(7)}) and QE identity from PCS")
    print(f"  identities   vault {prov['vault']['measurement_hex'][:16]}… = worker {prov['worker']['measurement_hex'][:16]}…: SHA-384 over MRTD and RTMR0–3 of this Trust Domain, read by each daemon and pinned by the other")
sealed = prov.get("sealed", {})
settled = "; sealed on a settled boot, after one reboot" if "reboot" in tl else ""
print(f"  key files    {len(sealed.get('sagvd', []))} + {len(sealed.get('acp-compute', []))} sealed to this host (tee.sealer {prov.get('sealer')}: {prov['vault'].get('sealer')}) — provision {secs('provision_start', 'provision_end')}{settled}")
print(f"  services     sagvd ready {steps.get('sagvd_ready_after', '?')} after its start, the worker's session opened {steps.get('session_opened_after', '?')} after the worker's (sagvd.service, acp-compute.service); paused {secs('pause_start', 'pause_end')} for the audit read, back with the sealed key files opened again (ready {steps.get('restart_sagvd_ready_after', '?')}, session {steps.get('restart_session_opened_after', '?')})")
print(f"  gate         job {job.get('job_id', '?')}: {gate.get('level')} at rung {gate.get('rung')}, {verdict.get('n_exact')} of {gate.get('fixtures')} fixtures byte for byte (max_abs_err {verdict.get('max_abs_err')}), the verdict signed by {gate.get('signer_key_id')} — {secs('job_submit', 'job_done')} from submission")
print(f"  audit log    ok={str(audit.get('ok')).lower()}, {audit.get('events', audit.get('event_count', '?'))} events verified under the operator's key (records/{os.path.basename(rec)}/guest/audit-public-key.pem)")
print(f"  time         {steps.get('elapsed_seconds', '?')} s on the guest from its first command to the sealed verdict; the record's hashes in guest/sha256sums.txt")
PY

cat <<EOF

The deployment is running. Its record: $REC
  on the VM        gcloud compute ssh $NAME --zone $ZONE --project $PROJECT
  look             sudo vg health · sudo vg status · sudo vg logs sagvd
  the audit log    sudo vg verify · sudo vg audit · sudo vg events 20   (the services pause for the read, about 15 s)
  another job      sudo vg submit gen-0.genome gen-0.key
  your own model   seal its genome with acpctl (docs/operator/09_first_deployment.md §4) into /var/lib/vaultgenome/genomes, then vg submit
  remove it        $HERE/destroy.sh --name $NAME --zone $ZONE --project $PROJECT
EOF
