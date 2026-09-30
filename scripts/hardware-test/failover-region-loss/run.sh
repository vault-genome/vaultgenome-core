#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The region-loss drill: the continuity drill with the failure that gives no
# warning. The primary's machine is switched off mid-heartbeat and deleted,
# as a strike or a total power loss would take it; no tripwire fires and no
# report is written. The release authority, in another region, acts on the
# one sign it gets — silence — under a policy whose only trigger is a lost
# heartbeat, and releases the last trustworthy genome's key to an attested
# confidential GPU in another cloud.
#
#   PRIMARY    GCP n2d SEV-SNP in us-central1 (primary.sh): fine-tunes
#              Qwen2.5-0.5B; the sentinel seals each generation with its key
#              escrowed to the authority, attests every record with the chip
#              and beats a signed heartbeat; then it powers itself off
#              through sysrq and the orchestrator deletes it.
#   AUTHORITY  GCP n2d SEV-SNP in europe-west4 (authority.sh): sagvd
#              failover, its escrow key sealed to its chip, a policy pinning
#              the primary's chip and the GPU standby, heartbeat timeout 15 s,
#              no compromise trigger; releases the last trustworthy genome's
#              key to the standby over mTLS across the Internet.
#   STANDBY    Azure NCC H100 v5, West Europe (../failover-cgpu/
#              destination-cgpu.sh, unchanged): acp-bootstrap as azure-cgpu,
#              restores the genome and gates it on the GPU in
#              confidential-computing mode.
#   BUCKET     the run's private bucket lives in europe-west4, outside the
#              region that goes dark.
#
# This script is the operator's hands: it builds and uploads, brings the
# three machines up, carries the authority's TLS material and token to the
# standby and the standby's identity back to the authority, replicates the
# primary's sealed bundles to the standby, deletes the primary once it has
# gone dark, collects every side's results and deletes everything.
# Usage: run.sh <gcp-project> [primary-zone] [azure-rg]
set -euo pipefail
PROJECT="${1:?usage: run.sh <gcp-project> [primary-zone] [azure-rg]}"
ZONE="${2:-us-central1-c}"
BUCKET_LOC="europe-west4"
RG="${3:-vg-rl-weu}"
LOC="westeurope"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
FAILOVER="$ROOT/scripts/hardware-test/gcp-failover"
CGPUFO="$ROOT/scripts/hardware-test/failover-cgpu"
CGPU="$ROOT/scripts/hardware-test/azure-cgpu"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
PRIMARY="vg-rl-primary-$LOW"
AUTHORITY="vg-rl-authority-$LOW"
VM="vg-rl-gpu-$LOW"
BUCKET="$PROJECT-vg-rl-$LOW"
ADMIN="vg"
SSH_PUB="${VG_SSH_PUB:-$HOME/.ssh/id_ed25519.pub}"
SSH_KEY="${SSH_PUB%.pub}"
IMAGE="Canonical:ubuntu-24_04-lts:cvm:24.04.202607310"
PKG_URL="https://github.com/Azure/az-cgpu-onboarding/releases/download/V4.4.1/cgpu-onboarding-package.tar.gz"
PKG_SHA="455ac1c1318d857c36dbae3432e023aebcb983dbcbd0ab1c3973af3a43eb480e"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"
AZ_CREATED=0; GCP_CREATED=0; OK=0; SYNC=""

cleanup() {
  # Every step of the cleanup runs, whatever the one before it returned: the
  # primary's zone file is gone once the run has deleted it, and under set -e
  # reading it would end the cleanup before the other machines are deleted.
  set +e
  [ -n "$SYNC" ] && kill "$SYNC" 2>/dev/null || true
  if [ "$GCP_CREATED" = 1 ]; then
    echo "cleanup: deleting $PRIMARY, $AUTHORITY and gs://$BUCKET"
    for n in "$PRIMARY" "$AUTHORITY"; do z="$(cat "$BUILD/zone.$n" 2>/dev/null)"; [ -n "$z" ] && gcloud compute instances delete "$n" --project "$PROJECT" --zone "$z" --quiet >/dev/null 2>&1 || true; done
    gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  fi
  if [ "$AZ_CREATED" = 1 ] && [ "$OK" = 0 ] && [ -n "${VG_KEEP_ON_FAILURE:-}" ]; then
    echo "cleanup: VG_KEEP_ON_FAILURE is set and the run failed — $VM is left for a look; delete it yourself (az vm delete -g $RG -n $VM)"
  elif [ "$AZ_CREATED" = 1 ]; then
    echo "cleanup: deleting $VM and its disk, NIC, IP and NSG"
    az vm delete -g "$RG" -n "$VM" --yes >/dev/null 2>&1 || true
    for pass in 1 2; do for r in $(az resource list -g "$RG" --query "[?contains(name, '$VM')].id" -o tsv 2>/dev/null); do az resource delete --ids "$r" >/dev/null 2>&1 || true; done; done
  fi
  rm -rf "$BUILD"
}
trap cleanup EXIT
ssh_vm() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=15 -o ConnectTimeout=20 "$ADMIN@$IP" "$@"; }
scp_to() { scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q "$@" "$ADMIN@$IP:"; }
wait_ssh() { local deadline=$(( $(date +%s) + $1 * 60 )); while [ "$(date +%s)" -lt "$deadline" ]; do ssh_vm -o BatchMode=yes true >/dev/null 2>&1 && return 0; sleep 10; done; echo "no ssh after $1 minutes"; return 1; }
wait_marker() { # wait_marker <leg> <minutes> [poll seconds]
  local deadline=$(( $(date +%s) + $2 * 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for m in DONE FAILED; do gcloud storage ls "gs://$BUCKET/out/$1/$m" --project "$PROJECT" >/dev/null 2>&1 && { echo "$m"; return; }; done
    sleep "${3:-20}"
  done
  echo TIMEOUT
}

echo "build sagvd, acp-bootstrap, acpctl, keygen (linux/amd64); pack workers/genome"
( cd "$ROOT" && for b in sagvd acp-bootstrap acpctl; do CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT/deploy/compose/keygen" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" . )
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$BUILD/worker.tgz" -C "$ROOT/workers/genome" --exclude __pycache__ --exclude .pytest_cache vg_genome requirements.txt examples
curl -fsSL "$PKG_URL" -o "$BUILD/cgpu-onboarding-package.tar.gz"; echo "$PKG_SHA  $BUILD/cgpu-onboarding-package.tar.gz" | shasum -a 256 -c - >/dev/null

echo "bucket gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location "$BUCKET_LOC" --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/sagvd" "$BUILD/acp-bootstrap" "$BUILD/acpctl" "$BUILD/keygen" "$BUILD/worker.tgz" "gs://$BUCKET/in/" --project "$PROJECT" >/dev/null
gcloud storage cp "$ROOT/scripts/hardware-test/gcp-sev-snp/keybind-evidence/20260913T222343Z/kds-vcek-cert_chain.pem" "gs://$BUCKET/in/amd-milan-cert_chain.pem" --project "$PROJECT" >/dev/null
gcloud storage cp "$CGPU/evidence/20260916T133506Z/cert-chain.pem" "gs://$BUCKET/in/amd-genoa-cert_chain.pem" --project "$PROJECT" >/dev/null

echo "boot the AUTHORITY $AUTHORITY (europe-west4) and the PRIMARY $PRIMARY (us-central1): SEV-SNP, the first zone with n2d capacity"
zone_of() { cat "$BUILD/zone.$1" 2>/dev/null; }
boot() { # boot <name> <machine-type> <startup script> <zone>...: the zones in order, in rounds, until one has n2d Milan capacity
  local name="$1" type="$2" script="$3" z round; shift 3
  for round in $(seq 1 20); do
    for z in "$@"; do
      if gcloud compute instances create "$name" --project "$PROJECT" --zone "$z" --machine-type "$type" --min-cpu-platform "AMD Milan" \
          --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
          --boot-disk-size 40GB --scopes storage-rw --metadata "vg-bucket=$BUCKET" --metadata-from-file "vg-common=$FAILOVER/common.sh,startup-script=$script" >/dev/null 2>"$BUILD/boot.err"; then
        echo "$z" > "$BUILD/zone.$name"; echo "$name in $z (round $round)"; return 0
      fi
      grep -q 'ZONE_RESOURCE_POOL_EXHAUSTED\|currently unavailable' "$BUILD/boot.err" || { cat "$BUILD/boot.err"; return 1; }
      gcloud compute instances delete "$name" --project "$PROJECT" --zone "$z" --quiet >/dev/null 2>&1 || true
    done
    echo "round $round: no n2d Milan capacity for $name; waiting 90 s"; sleep 90
  done
  echo "no n2d capacity for $name after 20 rounds"; return 1
}
boot "$AUTHORITY" n2d-standard-4 "$HERE/authority.sh" europe-west4-a europe-west4-b europe-west4-c; GCP_CREATED=1
boot "$PRIMARY" n2d-standard-8 "$HERE/primary.sh" "$ZONE" us-central1-a us-central1-b us-central1-f
AUTH_IP="$(gcloud compute instances describe "$AUTHORITY" --project "$PROJECT" --zone "$(zone_of "$AUTHORITY")" --format='value(networkInterfaces[0].accessConfigs[0].natIP)')"
MYIP="$(curl -s https://api.ipify.org)"
if [ -n "${VG_REUSE_AZURE_VM:-}" ]; then
  VM="$VG_REUSE_AZURE_VM"
  echo "reuse the STANDBY $VM (VG_REUSE_AZURE_VM): start it if it is deallocated"
  az vm start -g "$RG" -n "$VM" >/dev/null 2>&1 || true
  IP="$(az vm show -g "$RG" -n "$VM" -d --query publicIps -o tsv)"
else
  echo "boot the STANDBY $VM (Standard_NCC40ads_H100_v5, $LOC; ssh from the operator's address only)"
  az group create -n "$RG" -l "$LOC" >/dev/null
  az vm create -g "$RG" -n "$VM" -l "$LOC" --image "$IMAGE" --size Standard_NCC40ads_H100_v5 \
    --security-type ConfidentialVM --os-disk-security-encryption-type DiskWithVMGuestState \
    --enable-secure-boot true --enable-vtpm true --os-disk-size-gb 200 \
    --public-ip-sku Standard --admin-username "$ADMIN" --ssh-key-values "@$SSH_PUB" \
    --nsg-rule SSH --query '{ip:publicIpAddress}' -o json > "$BUILD/create.json"
  IP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ip"])' "$BUILD/create.json")"
fi
AZ_CREATED=1
NSG="$(az network nsg list -g "$RG" --query "[?contains(name, '$VM')].name" -o tsv | head -1)"
RULE="$(az network nsg rule list -g "$RG" --nsg-name "$NSG" --query "[?destinationPortRange=='22'].name" -o tsv | head -1)"
az network nsg rule update -g "$RG" --nsg-name "$NSG" -n "$RULE" --source-address-prefixes "$MYIP/32" >/dev/null
echo "standby at $IP"

echo "authority external IP $AUTH_IP: allow it to the standby's 8443"
az network nsg rule delete -g "$RG" --nsg-name "$NSG" -n allow-authority-8443 >/dev/null 2>&1 || true
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n allow-authority-8443 --priority 1010 --access Allow --direction Inbound --protocol Tcp \
  --source-address-prefixes "$AUTH_IP/32" --destination-port-ranges 8443 >/dev/null

echo "standby: Microsoft's onboarding (kernel, the 595 open driver, NVIDIA's verifier), tpm2-tools"
wait_ssh 10
scp_to "$BUILD/cgpu-onboarding-package.tar.gz" "$BUILD/acp-bootstrap" "$BUILD/acpctl" "$BUILD/worker.tgz" "$CGPU/gpu-token.py" "$CGPUFO/destination-cgpu.sh" "$CGPUFO/collect-destination.sh"
ssh_vm 'tar -xzf cgpu-onboarding-package.tar.gz'
BOOTED="$(ssh_vm 'uptime -s')"
ssh_vm 'cd cgpu-onboarding-package && sudo bash step-0-prepare-kernel.sh 2>&1 | tail -3; sudo systemctl reboot' || true
for i in $(seq 1 60); do sleep 10; NOW="$(ssh_vm -o BatchMode=yes 'uptime -s' 2>/dev/null || true)"; [ -n "$NOW" ] && [ "$NOW" != "$BOOTED" ] && break; done
ssh_vm 'echo "kernel after step 0: $(uname -r)"'
ssh_vm 'MOD=$(apt-cache show linux-modules-nvidia-595-server-open-$(uname -r) 2>/dev/null | sed -n "s/.*nvidia-kernel-common-595-server (<= \([^)]*\)).*/\1/p" | head -1); \
  V=$(apt-cache madison nvidia-kernel-common-595-server | awk "{print \$3}" | sort -V | while read x; do dpkg --compare-versions "$x" le "${MOD:-999}" && echo "$x"; done | tail -1); \
  echo "modules want nvidia-kernel-common-595-server <= ${MOD:-?}; pinning userspace ${V:-?}"; \
  [ -n "$V" ] && printf "Package: *595-server*\nPin: version %s\nPin-Priority: 1001\n" "$V" | sudo tee /etc/apt/preferences.d/nvidia-595-userspace.pref >/dev/null'
ssh_vm 'cd cgpu-onboarding-package && sudo bash step-1-install-gpu-driver.sh 2>&1 | tail -5'
ssh_vm 'nvidia-smi -L && nvidia-smi conf-compute -q | head -4' || { echo "no working NVIDIA driver after step 1"; exit 1; }
ssh_vm 'cd cgpu-onboarding-package && sudo bash step-2-attestation.sh --gpu-only --install-to-usr-local 2>&1 | tail -3; sudo apt-get install -y -qq tpm2-tools >/dev/null 2>&1; echo tpm2-tools installed'

echo "carry the authority's TLS material, token and public key to the standby"
for i in $(seq 1 120); do gcloud storage ls "gs://$BUCKET/handoff/dest/xcc_token" --project "$PROJECT" >/dev/null 2>&1 && gcloud storage ls "gs://$BUCKET/handoff/authority.pem" --project "$PROJECT" >/dev/null 2>&1 && break; sleep 10; done
mkdir -p "$BUILD/dest"
gcloud storage cp "gs://$BUCKET/handoff/dest/*" "$BUILD/dest/" --project "$PROJECT" >/dev/null
gcloud storage cp "gs://$BUCKET/handoff/authority.pem" "$BUILD/dest/authority.pem" --project "$PROJECT" >/dev/null
ssh_vm 'mkdir -p dest'
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q "$BUILD"/dest/* "$ADMIN@$IP:dest/"
rm -rf "$BUILD/dest"

echo "standby: acp-bootstrap as azure-cgpu on the H100"
ssh_vm 'sudo bash destination-cgpu.sh 2>&1 | tail -12'
ssh_vm 'sudo cat out/destination/destination-identity.json' > "$BUILD/destination-identity.json"
python3 - "$BUILD/destination-identity.json" "$IP" "$BUILD/destination.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); ip = sys.argv[2]
out = {"endpoint": f"https://{ip}:8443", "measurement_hex": d["measurement_hex"], "tee_provider": d.get("tee_provider") or d.get("provider"),
       "pcr_digest_hex": (d.get("vtpm") or {}).get("pcr_digest_hex", ""), "pcrs": (d.get("vtpm") or {}).get("pcrs", [])}
json.dump(out, open(sys.argv[3], "w"), indent=1); print(out)
PY
gcloud storage cp "$BUILD/destination.json" "gs://$BUCKET/handoff/destination.json" --project "$PROJECT" >/dev/null

echo "replicate the primary's sealed bundles to the standby, continuously"
( while true; do
    if gcloud storage cp "gs://$BUCKET/outbox/outbox.tgz" "$BUILD/outbox.tgz" --project "$PROJECT" >/dev/null 2>&1; then
      rm -rf "$BUILD/ob" && mkdir -p "$BUILD/ob" && tar -C "$BUILD/ob" -xzf "$BUILD/outbox.tgz" 2>/dev/null || true
      for g in "$BUILD"/ob/*.genome; do [ -f "$g" ] || continue; n="$(basename "$g")"
        [ -f "$BUILD/sent-$n" ] || { scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q "$g" "$ADMIN@$IP:bundles/.$n.part" && ssh_vm "mv bundles/.$n.part bundles/$n" && touch "$BUILD/sent-$n" && echo "replicated $n to the standby"; }
      done
    fi
    sleep 5
  done ) &
SYNC=$!

echo "waiting for the primary (up to 45 min) and the authority's failover (up to 30 min)"
PRIMARY_RESULT=$(wait_marker primary 45 3); echo "primary: $PRIMARY_RESULT"
if [ "$PRIMARY_RESULT" = DONE ]; then
  echo "the primary has gone dark: see it dead, then delete it — on the record"
  PZ="$(zone_of "$PRIMARY")"; mkdir -p "$BUILD/operator"
  now() { gdate -u +%Y-%m-%dT%H:%M:%S.%NZ; }
  {
    echo "primary=$PRIMARY zone=$PZ project=$PROJECT"
    for i in $(seq 1 30); do gcloud storage cp "gs://$BUCKET/out/primary-destroyed-at.txt" "$BUILD/operator/primary-destroyed-at.txt" --project "$PROJECT" >/dev/null 2>&1 && break; sleep 2; done
    echo "powered_off_at (the primary's clock, written just before sysrq o)=$(cat "$BUILD/operator/primary-destroyed-at.txt" 2>/dev/null)"
    for i in $(seq 1 60); do
      ST="$(gcloud compute instances describe "$PRIMARY" --project "$PROJECT" --zone "$PZ" --format='value(status)' 2>&1 | head -1)"
      echo "$(now) status=$ST"
      case "$ST" in TERMINATED|STOPPED) break ;; esac
      sleep 2
    done
    echo "Google's record of the machine before it is deleted:"
    gcloud compute instances describe "$PRIMARY" --project "$PROJECT" --zone "$PZ" \
      --format='yaml(name,zone.basename(),machineType.basename(),cpuPlatform,confidentialInstanceConfig,status,creationTimestamp,lastStartTimestamp,lastStopTimestamp)' 2>&1 | sed 's/^/  /'
    echo "$(now) delete: the machine and its boot disk"
    gcloud compute instances delete "$PRIMARY" --project "$PROJECT" --zone "$PZ" --quiet 2>&1 | sed 's/^/  /'
    echo "$(now) delete returned"
    AFTER="$(gcloud compute instances describe "$PRIMARY" --project "$PROJECT" --zone "$PZ" --format='value(status)' 2>&1 | tr '\n' ' ')"
    echo "$(now) after delete: $AFTER"
    DISKS="$(gcloud compute disks list --project "$PROJECT" --filter="name=$PRIMARY" --format='value(name)' 2>&1)"
    echo "$(now) disks named $PRIMARY left: ${DISKS:-none}"
  } > "$BUILD/operator/operator-destroy.txt" 2>&1 || true
  # the machine is gone only if Google says so; otherwise cleanup deletes it again
  grep -q "after delete: .*not found" "$BUILD/operator/operator-destroy.txt" && rm -f "$BUILD/zone.$PRIMARY"
  cat "$BUILD/operator/operator-destroy.txt"
fi
AUTHORITY_RESULT=$(wait_marker authority 30); echo "authority: $AUTHORITY_RESULT"
kill "$SYNC" 2>/dev/null || true; SYNC=""

[ "$PRIMARY_RESULT" = DONE ] && echo "Google's audit log for the primary: its creation, the guest's power-off, the deletion (who and from where left out)"
mkdir -p "$BUILD/operator"
for i in $(seq 1 12); do
  [ "$PRIMARY_RESULT" = DONE ] || break
  gcloud logging read "resource.type=\"gce_instance\" AND protoPayload.resourceName:\"instances/$PRIMARY\"" --project "$PROJECT" --freshness 3h --order asc \
    --format=json > "$BUILD/gcp-audit-raw.json" 2>/dev/null || true
  python3 - "$BUILD/gcp-audit-raw.json" "$BUILD/operator/gcp-audit-primary.json" <<'PY' && break
import json, sys
try:
    raw = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
keep = []
for e in raw:
    pp = e.get("protoPayload") or {}
    keep.append({"timestamp": e.get("timestamp"), "log": (e.get("logName") or "").rsplit("%2F", 1)[-1],
                 "method": pp.get("methodName"), "resource": pp.get("resourceName"),
                 "operation": {k: v for k, v in (e.get("operation") or {}).items() if k in ("first", "last", "id")},
                 "severity": e.get("severity")})
json.dump(keep, open(sys.argv[2], "w"), indent=1)
print("\n".join(f'{k["timestamp"]}  {k["log"]:14s} {k["method"]}' for k in keep))
sys.exit(0 if any("delete" in (k["method"] or "") for k in keep) else 1)
PY
  sleep 20
done

echo "collect"
mkdir -p "$EVIDENCE/primary" "$EVIDENCE/authority" "$EVIDENCE/destination"
gcloud storage cp "gs://$BUCKET/out/primary.tgz" "$BUILD/primary.tgz" --project "$PROJECT" >/dev/null 2>&1 && tar -C "$EVIDENCE/primary" -xzf "$BUILD/primary.tgz" || true
gcloud storage cp "gs://$BUCKET/out/authority.tgz" "$BUILD/authority.tgz" --project "$PROJECT" >/dev/null 2>&1 && tar -C "$EVIDENCE/authority" -xzf "$BUILD/authority.tgz" || true
ssh_vm 'sudo bash collect-destination.sh 2>&1 | tail -2'
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q "$ADMIN@$IP:out/destination.tgz" "$BUILD/" && tar -C "$EVIDENCE" -xzf "$BUILD/destination.tgz"
cp "$BUILD/destination.json" "$EVIDENCE/destination-handoff.json"
[ -d "$BUILD/operator" ] && cp -R "$BUILD/operator" "$EVIDENCE/operator"
{ echo "primary: $PRIMARY, GCP, zone $(cat "$EVIDENCE/primary/metadata.txt" 2>/dev/null | sed -n 's/^zone=//p')"
  echo "authority: $AUTHORITY, GCP, zone $(zone_of "$AUTHORITY")"
  echo "bucket: gs://$BUCKET, location $BUCKET_LOC (deleted with the run)"
  echo "standby: $VM, Azure $LOC, Standard_NCC40ads_H100_v5, endpoint https://$IP:8443"
} > "$EVIDENCE/topology.txt"
ls "$EVIDENCE"/*
[ "$PRIMARY_RESULT" = DONE ] || { echo "the primary did not finish cleanly"; exit 1; }
[ "$AUTHORITY_RESULT" = DONE ] || { echo "the authority did not finish the failover"; exit 1; }
OK=1
echo "evidence: $EVIDENCE"
