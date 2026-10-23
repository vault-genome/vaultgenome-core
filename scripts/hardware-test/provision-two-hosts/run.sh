#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# A deployment across two clouds and two chips, stood up by the three
# commands of ADR 0028: the authority on a GCP SEV-SNP guest (AMD Milan),
# the worker on an Azure SEV-SNP Confidential VM (AMD Genoa), the Return
# Path between them over the Internet under mutual TLS.
#
#   AUTHORITY  GCP n2d SEV-SNP (authority.sh, the startup script):
#              `acpctl provision authority` — keygen, sagvd's configuration
#              for an azure-sev-snp worker with the Genoa chain, its own
#              identity, its key files sealed to the chip, the worker's
#              bundle with the Milan chain inside; the bundle handed to
#              the orchestrator through the run's private bucket and
#              removed from the host; a fine-tune sealed into the genome
#              directory; then, once the worker's identity comes back,
#              `acpctl provision pin-worker`, sagvd started, the gate job
#              submitted, the audit log verified under the key it kept.
#   WORKER     Azure DC4as_v5 SEV-SNP (worker.sh, over ssh): the bundle
#              carried in by the orchestrator, `acpctl provision join` —
#              the worker's configuration for the authority the bundle
#              names, its identity from the vTPM's HCL report, its key
#              files sealed to the vTPM — the identity carried back; then
#              acp-compute started, the restore through the real door.
#   THIS SCRIPT is the operator's hands (the "channel you trust" of the
#              command's output): it builds and uploads, brings both
#              machines up, opens the authority's Return Path port to the
#              worker's address only, carries the bundle one way and the
#              identity the other, collects both sides' results and
#              deletes everything, also on failure.
#
# Usage: run.sh <gcp-project> [gcp-zone] [azure-rg] [azure-location]
#        (defaults us-central1-c, vg-p2-weu, westeurope)
# VG_SIZE (default Standard_DC4as_v5), VG_SSH_PUB (default
# ~/.ssh/id_ed25519.pub), VG_WORKER_PRODUCT / VG_AUTHORITY_PRODUCT (genoa,
# milan: the chains each side fetches for the other), VG_KEEP_ON_FAILURE
# leaves both machines for a look. Cost: one n2d-standard-4 and one
# DC4as_v5 for about twenty minutes. Requires gcloud and az logged in.
set -euo pipefail
PROJECT="${1:?usage: run.sh <gcp-project> [gcp-zone] [azure-rg] [azure-location]}"
ZONE="${2:-us-central1-c}"
RG="${3:-vg-p2-weu}"
LOC="${4:-westeurope}"
SIZE="${VG_SIZE:-Standard_DC4as_v5}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
AUTH="vg-p2-authority-$LOW"
VM="vg-p2-worker-$LOW"
BUCKET="$PROJECT-vg-p2-$LOW"
TAG="vg-p2-$LOW"
RULE="vg-p2-returnpath-$LOW"
ADMIN="vg"
SSH_PUB="${VG_SSH_PUB:-$HOME/.ssh/id_ed25519.pub}"
SSH_KEY="${SSH_PUB%.pub}"
IMAGE="Canonical:ubuntu-24_04-lts:cvm:24.04.202607310"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"
CREATED_AZ=0; CREATED_GCP=0; CREATED_RULE=0; OK=0

cleanup() {
  set +e
  if [ "$OK" = 0 ] && [ -n "${VG_KEEP_ON_FAILURE:-}" ]; then
    echo "cleanup: VG_KEEP_ON_FAILURE is set and the run failed — $AUTH, $VM, the rule $RULE and gs://$BUCKET are left for a look; delete them yourself"
    rm -rf "$BUILD"; return
  fi
  echo "cleanup: deleting $AUTH, the firewall rule, $VM with its disk, NIC, IP, NSG and VNET, and gs://$BUCKET"
  [ "$CREATED_GCP" = 1 ] && gcloud compute instances delete "$AUTH" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1
  [ "$CREATED_RULE" = 1 ] && gcloud compute firewall-rules delete "$RULE" --project "$PROJECT" --quiet >/dev/null 2>&1
  if [ "$CREATED_AZ" = 1 ]; then
    az vm delete -g "$RG" -n "$VM" --yes >/dev/null 2>&1 || true
    for pass in 1 2; do
      for r in $(az resource list -g "$RG" --query "[?contains(name, '$VM')].id" -o tsv 2>/dev/null | sort); do az resource delete --ids "$r" >/dev/null 2>&1 || true; done
    done
    az resource list -g "$RG" --query "[?contains(name, '$VM')].{name:name,type:type}" -o table 2>/dev/null || true
  fi
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

ssh_vm() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=15 -o ServerAliveCountMax=8 -o ConnectTimeout=20 "$ADMIN@$IP" "$@"; }
scp_in() { scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q "$@" "$ADMIN@$IP:in/"; }
scp_back() { scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q "$ADMIN@$IP:$1" "$2"; }
wait_ssh() { local deadline=$(( $(date +%s) + $1 * 60 )); while [ "$(date +%s)" -lt "$deadline" ]; do ssh_vm -o BatchMode=yes true >/dev/null 2>&1 && return 0; sleep 10; done; echo "no ssh after $1 minutes"; return 1; }
gcs_wait() { # gcs_wait <object> <minutes>
  local deadline=$(( $(date +%s) + $2 * 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    gcloud storage ls "gs://$BUCKET/$1" --project "$PROJECT" >/dev/null 2>&1 && return 0
    gcloud storage ls "gs://$BUCKET/out/FAILED" --project "$PROJECT" >/dev/null 2>&1 && { echo "the authority reported FAILED"; return 1; }
    sleep 10
  done
  echo "no $1 after $2 minutes"; return 1
}
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$BUILD/timeline.txt"; }
mkdir -p "$EVIDENCE" "$BUILD/handoff"
exec > >(tee -a "$BUILD/runner.log") 2>&1
mark run_start

echo "build sagvd, acp-compute, acpctl, keygen (linux/amd64); pack workers/genome"
( cd "$ROOT" && for b in sagvd acp-compute acpctl; do CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
( cd "$ROOT/workers" && COPYFILE_DISABLE=1 tar czf "$BUILD/genome-worker.tgz" --no-xattrs --exclude '__pycache__' --exclude '.pytest_cache' genome )
( cd "$BUILD" && shasum -a 256 sagvd acp-compute acpctl keygen genome-worker.tgz > "$EVIDENCE/inputs.sha256" )

echo "bucket gs://$BUCKET (private; the run's hand-off and results; deleted with the run)"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/sagvd" "$BUILD/acp-compute" "$BUILD/acpctl" "$BUILD/keygen" "$BUILD/genome-worker.tgz" "gs://$BUCKET/in/" --project "$PROJECT" >/dev/null

MYIP="$(curl -s https://api.ipify.org)"
echo "boot the WORKER $VM ($IMAGE, $SIZE, $LOC; ssh from $MYIP only)"
mark worker_create_start
az group create -n "$RG" -l "$LOC" >/dev/null
az vm create -g "$RG" -n "$VM" -l "$LOC" --image "$IMAGE" --size "$SIZE" \
  --security-type ConfidentialVM --os-disk-security-encryption-type DiskWithVMGuestState \
  --enable-secure-boot true --enable-vtpm true --os-disk-size-gb 64 \
  --public-ip-sku Standard --admin-username "$ADMIN" --ssh-key-values "@$SSH_PUB" \
  --nsg-rule SSH --query '{ip:publicIpAddress,state:powerState}' -o json > "$BUILD/create.json"
CREATED_AZ=1
IP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ip"])' "$BUILD/create.json")"
NSG="$(az network nsg list -g "$RG" --query "[?contains(name, '$VM')].name" -o tsv | head -1)"
SSHRULE="$(az network nsg rule list -g "$RG" --nsg-name "$NSG" --query "[?destinationPortRange=='22'].name" -o tsv | head -1)"
az network nsg rule update -g "$RG" --nsg-name "$NSG" -n "$SSHRULE" --source-address-prefixes "$MYIP/32" >/dev/null
mark worker_created
echo "worker $VM at $IP"

echo "the authority's Return Path port 9443: open to $IP only (rule $RULE, tag $TAG)"
gcloud compute firewall-rules create "$RULE" --project "$PROJECT" --network default --direction INGRESS --action allow \
  --rules tcp:9443 --source-ranges "$IP/32" --target-tags "$TAG" >/dev/null
CREATED_RULE=1

echo "boot the AUTHORITY $AUTH (n2d SEV-SNP, $ZONE)"
mark authority_create_start
gcloud compute instances create "$AUTH" --project "$PROJECT" --zone "$ZONE" \
  --machine-type n2d-standard-4 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --boot-disk-size 20GB --tags "$TAG" --scopes storage-rw \
  --metadata "vg-bucket=$BUCKET,vg-worker-ip=$IP,vg-worker-product=${VG_WORKER_PRODUCT:-genoa},vg-authority-product=${VG_AUTHORITY_PRODUCT:-milan}" \
  --metadata-from-file "startup-script=$HERE/authority.sh" >/dev/null
CREATED_GCP=1
AUTH_IP="$(gcloud compute instances describe "$AUTH" --project "$PROJECT" --zone "$ZONE" --format='value(networkInterfaces[0].accessConfigs[0].natIP)')"
mark authority_created
echo "authority $AUTH at $AUTH_IP"

echo "step 1 on the authority: provision authority (the bundle comes through the bucket)"
gcs_wait handoff/worker-bundle.tar 25
gcloud storage cp "gs://$BUCKET/handoff/worker-bundle.tar" "gs://$BUCKET/handoff/base.tgz" "gs://$BUCKET/handoff/authority-provision.json" "$BUILD/handoff/" --project "$PROJECT" >/dev/null
mark bundle_received
echo "bundle received: $(shasum -a 256 "$BUILD/handoff/worker-bundle.tar" | cut -d' ' -f1) ($(stat -f%z "$BUILD/handoff/worker-bundle.tar" 2>/dev/null || stat -c%s "$BUILD/handoff/worker-bundle.tar") bytes)"
cp "$BUILD/handoff/authority-provision.json" "$EVIDENCE/authority-provision-step1.json"

echo "step 2 on the worker: the bundle carried in, provision join, the identity carried back"
wait_ssh 10
ssh_vm 'mkdir -p in out'
scp_in "$BUILD/sagvd" "$BUILD/acp-compute" "$BUILD/acpctl" "$BUILD/keygen" "$BUILD/genome-worker.tgz" "$HERE/worker.sh" "$BUILD/handoff/worker-bundle.tar" "$BUILD/handoff/base.tgz"
rm -f "$BUILD/handoff/worker-bundle.tar"
mark bundle_carried
ssh_vm "sudo bash in/worker.sh join /home/$ADMIN" 2>&1 | tee "$BUILD/worker-join.log" | grep -E '^== |exit=|failed|FAIL' || true
scp_back out/acp-compute-identity.json "$BUILD/handoff/acp-compute-identity.json"
mark identity_received
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("worker identity: %s (%s, sealer %s)" % (d["tee_measurement_hex"], d["tee_provider"], d.get("sealer")))' "$BUILD/handoff/acp-compute-identity.json"
gcloud storage cp "$BUILD/handoff/acp-compute-identity.json" "gs://$BUCKET/handoff/acp-compute-identity.json" --project "$PROJECT" >/dev/null
mark identity_carried

echo "the worker starts and dials $AUTH_IP:9443; step 3 on the authority: pin-worker, sagvd, the job"
ssh_vm "sudo bash in/worker.sh start /home/$ADMIN" 2>&1 | grep -E '^== |exit=|ready|failed' || true
gcs_wait out/authority.tgz 25
mark authority_done
gcloud storage cp "gs://$BUCKET/out/authority.tgz" "$BUILD/authority.tgz" --project "$PROJECT" >/dev/null
mkdir -p "$EVIDENCE/authority" && tar xzf "$BUILD/authority.tgz" -C "$EVIDENCE/authority"

echo "collect the worker and stop it"
ssh_vm "sudo bash in/worker.sh collect /home/$ADMIN" 2>&1 | grep -E '^== |exit=|failed' || true
scp_back out/worker.tgz "$BUILD/worker.tgz"
mkdir -p "$EVIDENCE/worker" && tar xzf "$BUILD/worker.tgz" -C "$EVIDENCE/worker"
mark worker_collected
cp "$BUILD/worker-join.log" "$EVIDENCE/worker/runner-join.log"
cp "$BUILD/timeline.txt" "$EVIDENCE/timeline.txt"
{ echo "authority=$AUTH zone=$ZONE ip=$AUTH_IP"; echo "worker=$VM location=$LOC size=$SIZE ip=$IP"; echo "bucket=gs://$BUCKET (deleted with the run)"; echo "firewall=$RULE tcp:9443 from $IP/32 to tag $TAG"; echo "captured=$STAMP"; } > "$EVIDENCE/machines.txt"

echo "== the authority's steps"; cat "$EVIDENCE/authority/steps.txt" 2>/dev/null || true
echo "== the worker's steps"; cat "$EVIDENCE/worker/steps.txt" 2>/dev/null || true
if grep -q 'gate_level=EXACT' "$EVIDENCE/authority/steps.txt" 2>/dev/null && grep -q 'audit verify exit=0' "$EVIDENCE/authority/steps.txt" 2>/dev/null \
   && grep -q 'provision authority exit=0' "$EVIDENCE/authority/steps.txt" && grep -q 'provision pin-worker exit=0' "$EVIDENCE/authority/steps.txt" \
   && grep -q 'provision join exit=0' "$EVIDENCE/worker/steps.txt" 2>/dev/null; then OK=1; fi
mark run_end
cp "$BUILD/timeline.txt" "$EVIDENCE/timeline.txt"
cp "$BUILD/runner.log" "$EVIDENCE/runner.log"
( cd "$EVIDENCE" && find . -type f ! -name sha256sums.txt -print0 | sort -z | xargs -0 shasum -a 256 > sha256sums.txt )
echo "evidence: $EVIDENCE"
[ "$OK" = 1 ] || { echo "the run did not reach EXACT with every step at exit 0"; exit 1; }
echo "OK: three commands across two clouds, a gate job EXACT, the audit log verified"
