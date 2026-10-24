#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The Return Path on a real Azure SEV-SNP Confidential VM: builds sagvd,
# acp-compute, acpctl and acp-keygen for linux/amd64, packs the vg_genome
# worker, creates a Confidential VM (Standard_DC4as_v5 by default; Ubuntu
# 24.04 CVM image, secure boot and vTPM) in the resource group and
# location given, runs cvm-returnpath-azure.sh on it as root over ssh —
# both daemons attesting as azure-sev-snp, the fine-tune, the sealed
# genome, the two rogues refused, the gate job EXACT, the audit log
# verified — collects the results tarball and deletes the VM with its disk
# and network. What comes back is the results only: reports, identities,
# job views, logs; keys, seeds, tokens and configs stay on the VM and die
# with it.
#
# Usage: run.sh [resource-group] [location]   (defaults vg-asnp-weu, westeurope)
# VG_SIZE (default Standard_DC4as_v5) the VM size; VG_SSH_PUB the key the
# VM admits (default ~/.ssh/id_ed25519.pub); VG_KEEP_ON_FAILURE leaves the
# VM for a look when the run fails. Cost: one DC4as_v5 for about fifteen
# minutes. Requires az logged in, with the DCasv5 quota in the location.
set -euo pipefail
RG="${1:-vg-asnp-weu}"
LOC="${2:-westeurope}"
SIZE="${VG_SIZE:-Standard_DC4as_v5}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
VM="vg-asnp-$LOW"
ADMIN="vg"
SSH_PUB="${VG_SSH_PUB:-$HOME/.ssh/id_ed25519.pub}"
SSH_KEY="${SSH_PUB%.pub}"
IMAGE="Canonical:ubuntu-24_04-lts:cvm:24.04.202607310"
BUILD="$(mktemp -d)"
CREATED=0
OK=0

cleanup() {
  set +e
  if [ "$CREATED" = 1 ] && [ "$OK" = 0 ] && [ -n "${VG_KEEP_ON_FAILURE:-}" ]; then
    echo "cleanup: VG_KEEP_ON_FAILURE is set and the run failed — $VM is left running for a look; delete it yourself (az vm delete -g $RG -n $VM, then its disk, NIC, IP, NSG and VNET)"
    rm -rf "$BUILD"; return
  fi
  if [ "$CREATED" = 1 ]; then
    echo "cleanup: deleting $VM and its disk, NIC, IP, NSG and VNET"
    az vm delete -g "$RG" -n "$VM" --yes >/dev/null 2>&1 || true
    for pass in 1 2; do
      for r in $(az resource list -g "$RG" --query "[?contains(name, '$VM')].id" -o tsv 2>/dev/null | sort); do az resource delete --ids "$r" >/dev/null 2>&1 || true; done
    done
    az resource list -g "$RG" --query "[?contains(name, '$VM')].{name:name,type:type}" -o table 2>/dev/null || true
  fi
  rm -rf "$BUILD"
}
trap cleanup EXIT

ssh_vm() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=15 -o ServerAliveCountMax=8 -o ConnectTimeout=20 "$ADMIN@$IP" "$@"; }
scp_in() { scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q "$@" "$ADMIN@$IP:in/"; }
scp_back() { scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q "$ADMIN@$IP:$1" "$2"; }
wait_ssh() { # wait_ssh <minutes>
  local deadline=$(( $(date +%s) + $1 * 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    ssh_vm -o BatchMode=yes true >/dev/null 2>&1 && return 0
    sleep 10
  done
  echo "no ssh after $1 minutes"; return 1
}

echo "build sagvd, acp-compute, acpctl, keygen (linux/amd64); pack workers/genome"
( cd "$ROOT" && for b in sagvd acp-compute acpctl; do CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
( cd "$ROOT/workers" && COPYFILE_DISABLE=1 tar czf "$BUILD/genome-worker.tgz" --no-xattrs --exclude '__pycache__' --exclude '.pytest_cache' genome )

MYIP="$(curl -s https://api.ipify.org)"
echo "boot $VM ($IMAGE, $SIZE, $LOC; ssh from $MYIP only)"
az group create -n "$RG" -l "$LOC" >/dev/null
az vm create -g "$RG" -n "$VM" -l "$LOC" --image "$IMAGE" --size "$SIZE" \
  --security-type ConfidentialVM --os-disk-security-encryption-type DiskWithVMGuestState \
  --enable-secure-boot true --enable-vtpm true --os-disk-size-gb 64 \
  --public-ip-sku Standard --admin-username "$ADMIN" --ssh-key-values "@$SSH_PUB" \
  --nsg-rule SSH --query '{ip:publicIpAddress,state:powerState}' -o json > "$BUILD/create.json"
CREATED=1
IP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ip"])' "$BUILD/create.json")"
NSG="$(az network nsg list -g "$RG" --query "[?contains(name, '$VM')].name" -o tsv | head -1)"
RULE="$(az network nsg rule list -g "$RG" --nsg-name "$NSG" --query "[?destinationPortRange=='22'].name" -o tsv | head -1)"
az network nsg rule update -g "$RG" --nsg-name "$NSG" -n "$RULE" --source-address-prefixes "$MYIP/32" >/dev/null
echo "vm $VM at $IP; ssh rule $NSG/$RULE limited to $MYIP"
wait_ssh 10

echo "upload"
ssh_vm 'mkdir -p in'
scp_in "$BUILD/sagvd" "$BUILD/acp-compute" "$BUILD/acpctl" "$BUILD/keygen" "$BUILD/genome-worker.tgz" "$HERE/cvm-returnpath-azure.sh"
ssh_vm 'cd in && sha256sum sagvd acp-compute acpctl keygen genome-worker.tgz'

echo "run the guest script as root (about ten minutes: the pinned CPU torch, the fine-tune, the Return Path)"
ssh_vm "sudo bash in/cvm-returnpath-azure.sh /home/$ADMIN" 2>&1 | tee "$BUILD/guest.log" | grep -E '^== |^E2E DONE|failed|FAIL' || true

echo "collect"
GSTAMP="$(ssh_vm 'cat results.stamp' | tr -d '[:space:]')"
[ -n "$GSTAMP" ] || { echo "the guest left no results.stamp; its log:"; tail -40 "$BUILD/guest.log"; exit 1; }
scp_back results.tgz "$BUILD/results.tgz"
echo "results $GSTAMP: $(stat -f%z "$BUILD/results.tgz" 2>/dev/null || stat -c%s "$BUILD/results.tgz") bytes, sha256 $(shasum -a 256 "$BUILD/results.tgz" | cut -d' ' -f1)"
mkdir -p "$HERE/evidence"
tar xzf "$BUILD/results.tgz" -C "$HERE/evidence"
cp "$BUILD/guest.log" "$HERE/evidence/$GSTAMP/runner-guest.log"
echo "evidence: $HERE/evidence/$GSTAMP"
cat "$HERE/evidence/$GSTAMP/steps.txt"
grep -q 'gate_level=EXACT' "$HERE/evidence/$GSTAMP/steps.txt" && grep -q 'audit verify exit=0' "$HERE/evidence/$GSTAMP/steps.txt" \
  && grep -q '^other boot refused' "$HERE/evidence/$GSTAMP/steps.txt" && OK=1
[ "$OK" = 1 ] || { echo "the run did not reach EXACT with a verified audit log and the other boot refused"; exit 1; }
