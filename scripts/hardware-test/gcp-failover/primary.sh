#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The failover drill's PRIMARY: an AMD SEV-SNP Confidential VM that runs a
# workload and, beside it, the sentinel (acpctl sentinel watch). It
# fine-tunes a real model, the sentinel seals each state as the next
# generation of a genome chain — each key encapsulated only to the release
# authority's escrow key, so this machine keeps nothing that opens what it
# sealed — and replicates its outbox to a bucket. Then it is attacked: a
# tripwire fires, the sentinel seals nothing more, reports the compromise
# and exits. Reports and logs go to out/primary/; keys and the model stay
# on the VM and die with it.
set -u
exec > >(tee -a /root/primary.log) 2>&1
BUCKET=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-bucket")
OUT=/root/out; OUTBOX=/root/outbox; mkdir -p "$OUT" /opt/worker "$OUTBOX"; cd /root
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
finish() {
  cp /root/primary.log "$OUT/console.log" 2>/dev/null || true
  tar -C "$OUT" -czf /root/out.tgz . 2>/dev/null && gcs_put /root/out.tgz out/primary.tgz 2>/dev/null || true
  echo "$1" > /root/marker; gcs_put /root/marker "out/primary/$1" 2>/dev/null || true
}
trap 'finish FAILED' ERR

curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-common" > /root/common.sh
. /root/common.sh
set -eE

step "inputs"
gcs_get in/acpctl /usr/local/bin/acpctl && chmod +x /usr/local/bin/acpctl
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu; dmesg | grep -i -E "sev|snp" | head; } > "$OUT/system.txt" 2>&1

step "python runtime (CPU) and base model"
python_runtime https://download.pytorch.org/whl/cpu
base_model

step "wait for the release authority's escrow key"
for i in $(seq 1 120); do gcs_get handoff/escrow.pem /root/escrow.pem 2>/dev/null && break; sleep 5; done
[ -s /root/escrow.pem ] || { echo "no escrow key after 10 minutes"; false; }

step "the sentinel's key; the operator pins its public half"
acpctl sentinel keygen --out /root/sentinel.seed --pub /root/sentinel.pem > "$OUT/sentinel-keygen.txt"
gcs_put /root/sentinel.pem handoff/sentinel.pem

step "fine-tune generation 0 (120 steps)"
vg finetune --base /opt/base --base-name "$BASE_REPO" \
  --data /opt/worker/examples/drill-facts.jsonl --prompts /opt/worker/examples/drill-prompts.json \
  --out /root/genome --targets q_proj,v_proj --rank 8 --alpha 16 --steps 120 --lr 3e-4 \
  --max-len 64 --threads "$(nproc)" --top-k 64 --new-tokens 16 --critical 4 > "$OUT/finetune-0.json" 2> "$OUT/finetune-0.log"

step "arm a tripwire and start the sentinel"
echo "no process reads this" > /root/canary
# Replicate the outbox to the bucket every few seconds, in the background,
# until the sentinel has exited and a last push has gone out.
( while [ ! -e /root/sentinel.done ]; do push_outbox "$OUTBOX"; sleep 3; done ) &
PUSH=$!
acpctl sentinel watch --content-dir /root/genome --outbox "$OUTBOX" \
  --escrow-to /root/escrow.pem --key /root/sentinel.seed \
  --tripwire /root/canary --tripwire /usr/local/bin/acpctl \
  --interval 3s --settle 4s > "$OUT/sentinel.json" 2> "$OUT/sentinel.log" &
SENTINEL=$!

wait_seal() { for i in $(seq 1 120); do [ -e "$OUTBOX/$1" ] && return 0; sleep 2; done; return 1; }
step "wait for generation 0 to be sealed"
wait_seal gen-000000.seal.json || { echo "generation 0 not sealed"; false; }

step "wait for the authority to arm its failover watch"
for i in $(seq 1 120); do gcs_get handoff/armed /root/armed 2>/dev/null && break; sleep 5; done

step "keep training: fine-tune generation 1 (160 steps)"
vg finetune --base /opt/base --base-name "$BASE_REPO" \
  --data /opt/worker/examples/drill-facts.jsonl --prompts /opt/worker/examples/drill-prompts.json \
  --out /root/stage --targets q_proj,v_proj --rank 8 --alpha 16 --steps 160 --lr 3e-4 \
  --max-len 64 --threads "$(nproc)" --top-k 64 --new-tokens 16 --critical 4 > "$OUT/finetune-1.json" 2> "$OUT/finetune-1.log"
rm -rf /root/genome && mv /root/stage /root/genome
step "wait for generation 1 to be sealed and replicated"
wait_seal gen-000001.seal.json || { echo "generation 1 not sealed"; false; }
push_outbox "$OUTBOX"; sleep 6   # make sure generation 1 is in the bucket before the attack

step "ATTACK: touch the canary, then tamper with the model"
date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$OUT/attack-at.txt"
echo "read by an intruder" > /root/canary
echo "weights planted by the intruder" > /root/genome/adapter/adapter_model.safetensors

step "the sentinel must stop sealing, report, and exit 3"
set +e; wait "$SENTINEL"; SENTINEL_CODE=$?; set -e
echo "sentinel exit=$SENTINEL_CODE" >> "$OUT/steps.txt"
touch /root/sentinel.done
wait "$PUSH" 2>/dev/null || true
# The push loop already replicated the compromise report; this last push is
# belt and suspenders and must never fail the run on a transient GCS blip.
push_outbox "$OUTBOX" || true
# The one hard check: a fired tripwire is exit 3 (compromised).
[ "$SENTINEL_CODE" = 3 ] || { echo "sentinel exited $SENTINEL_CODE, want 3 (compromised)"; false; }

trap - ERR
finish DONE
