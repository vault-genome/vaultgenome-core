#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The region-loss drill's PRIMARY: an AMD SEV-SNP Confidential VM that runs
# a workload and, beside it, the sentinel (acpctl sentinel watch). It
# fine-tunes a real model, the sentinel seals each state as the next
# generation of a genome chain — each key encapsulated only to the release
# authority's escrow key, so this machine keeps nothing that opens what it
# sealed — attests every record with this guest's SEV-SNP chip and beats a
# signed heartbeat, and the outbox is replicated to a bucket in another
# region. Then its region goes dark: no tripwire fires and no report is
# written. The machine uploads its evidence, writes the moment by its own
# clock, and powers itself off through the kernel's sysrq trigger — no
# shutdown, no signal to the sentinel, no `stopped` heartbeat. The
# orchestrator then deletes it. The only sign of failure the release
# authority gets is silence.
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

step "configfs-tsm (the sentinel attests with this chip)"
modprobe sev-guest 2>/dev/null || {
  export DEBIAN_FRONTEND=noninteractive
  for i in $(seq 1 60); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 5; done
  apt-get -o DPkg::Lock::Timeout=300 install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
  modprobe sev-guest 2>/dev/null || true
}
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report 2>&1; ls -la /dev/sev-guest 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail; } > "$OUT/tsm.txt" 2>&1

step "python runtime (CPU) and base model"
python_runtime https://download.pytorch.org/whl/cpu
base_model

step "wait for the release authority's escrow key"
for i in $(seq 1 120); do gcs_get handoff/escrow.pem /root/escrow.pem 2>/dev/null && break; sleep 5; done
[ -s /root/escrow.pem ] || { echo "no escrow key after 10 minutes"; false; }

step "the sentinel's key and this chip's identity; the operator pins both"
acpctl sentinel keygen --out /root/sentinel.seed --pub /root/sentinel.pem > "$OUT/sentinel-keygen.txt"
acpctl sentinel identity --tee gcp-sev-snp --key /root/sentinel.seed > "$OUT/sentinel-identity.json"
echo "primary measurement=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["measurement_hex"])' "$OUT/sentinel-identity.json")" >> "$OUT/steps.txt"
gcs_put /root/sentinel.pem handoff/sentinel.pem
gcs_put "$OUT/sentinel-identity.json" handoff/sentinel-identity.json
# For the standby's negative check only (a stolen seed off this chip); the
# bucket is private and deleted with the run.
gcs_put /root/sentinel.seed handoff/sentinel.seed

step "seal the sentinel's seed to this chip (ADR 0023): the file the sentinel runs from is no seed elsewhere"
acpctl sentinel seal-key --key /root/sentinel.seed --tee gcp-sev-snp > "$OUT/sentinel-seal-key.json"
echo "sentinel seal-key exit=0 $(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print("tee=%s sealed=%s"%(d["tee"],d["sealed"]))' "$OUT/sentinel-seal-key.json")" >> "$OUT/steps.txt"
acpctl sentinel identity --tee gcp-sev-snp --key /root/sentinel.seed > "$OUT/sentinel-identity-sealed.json"
echo "sentinel identity from the sealed seed: key $(python3 -c 'import json,sys;a=json.load(open(sys.argv[1]));b=json.load(open(sys.argv[2]));print(a["sentinel"], "same" if a["sentinel"]==b["sentinel"] else "DIFFERENT")' "$OUT/sentinel-identity.json" "$OUT/sentinel-identity-sealed.json")" >> "$OUT/steps.txt"
# The sealed file too, for the standby's other negative: off this chip it does not open.
gcs_put /root/sentinel.seed handoff/sentinel.sealed

step "fine-tune generation 0 (120 steps)"
vg finetune --base /opt/base --base-name "$BASE_REPO" \
  --data /opt/worker/examples/drill-facts.jsonl --prompts /opt/worker/examples/drill-prompts.json \
  --out /root/genome --targets q_proj,v_proj --rank 8 --alpha 16 --steps 120 --lr 3e-4 \
  --max-len 64 --threads "$(nproc)" --top-k 64 --new-tokens 16 --critical 4 > "$OUT/finetune-0.json" 2> "$OUT/finetune-0.log"

step "arm a tripwire and start the sentinel"
echo "no process reads this" > /root/canary
# Replicate the outbox to the bucket every few seconds, in the background,
# until the sentinel has exited and a last push has gone out.
# The loop's subshell inherits the ERR trap (set -E): a transient GCS
# error there must not report the whole run as FAILED, so the subshell
# drops the trap and tolerates a failed push (the next one replaces it).
( trap - ERR; set +e; while [ ! -e /root/sentinel.done ]; do push_outbox "$OUTBOX" || true; sleep 3; done ) &
PUSH=$!
acpctl sentinel watch --content-dir /root/genome --outbox "$OUTBOX" \
  --escrow-to /root/escrow.pem --key /root/sentinel.seed --tee gcp-sev-snp \
  --tripwire /root/canary --tripwire /usr/local/bin/acpctl \
  --interval 3s --settle 4s > "$OUT/sentinel.json" 2> "$OUT/sentinel.log" &
SENTINEL=$!

wait_seal() { for i in $(seq 1 120); do [ -e "$OUTBOX/$1" ] && return 0; sleep 2; done; return 1; }
step "wait for generation 0 to be sealed"
wait_seal gen-000000.seal.json || { echo "generation 0 not sealed"; false; }

step "wait for the authority to arm its failover watch (the GPU standby is onboarded first)"
for i in $(seq 1 720); do gcs_get handoff/armed /root/armed 2>/dev/null && break; sleep 5; done
[ -s /root/armed ] || { echo "the authority did not arm within an hour"; false; }

step "keep training: fine-tune generation 1 (160 steps)"
vg finetune --base /opt/base --base-name "$BASE_REPO" \
  --data /opt/worker/examples/drill-facts.jsonl --prompts /opt/worker/examples/drill-prompts.json \
  --out /root/stage --targets q_proj,v_proj --rank 8 --alpha 16 --steps 160 --lr 3e-4 \
  --max-len 64 --threads "$(nproc)" --top-k 64 --new-tokens 16 --critical 4 > "$OUT/finetune-1.json" 2> "$OUT/finetune-1.log"
rm -rf /root/genome && mv /root/stage /root/genome
step "wait for generation 1 to be sealed and replicated"
wait_seal gen-000001.seal.json || { echo "generation 1 not sealed"; false; }
# Make sure generation 1 is in the bucket before the region goes dark. The
# push loop writes the same object every few seconds: a write refused as too
# soon after the loop's is retried once, and the loop's next push carries it anyway.
push_outbox "$OUTBOX" || { sleep 2; push_outbox "$OUTBOX"; } || true
sleep 6

step "keep training: fine-tune generation 2 — the work the region takes with it"
# Generation 2 trains into a staging directory the sentinel does not watch:
# it becomes a generation only when it is finished and moved in, and this
# machine goes dark before that. Its own subshell, without the ERR trap: its
# end is the power-off, not a failure of the run.
( trap - ERR; set +e; vg finetune --base /opt/base --base-name "$BASE_REPO" \
    --data /opt/worker/examples/drill-facts.jsonl --prompts /opt/worker/examples/drill-prompts.json \
    --out /root/stage2 --targets q_proj,v_proj --rank 8 --alpha 16 --steps 160 --lr 3e-4 \
    --max-len 64 --threads "$(nproc)" --top-k 64 --new-tokens 16 --critical 4 > "$OUT/finetune-2.json" 2> "$OUT/finetune-2.log" ) &
TRAIN2=$!
sleep 15   # long enough for the log to show steps running when the power goes
echo "generation 2 when the power went: $(kill -0 "$TRAIN2" 2>/dev/null && echo "still training" || echo "finished early")" >> "$OUT/steps.txt"
echo "sentinel running when the power went: $(kill -0 "$SENTINEL" 2>/dev/null && echo yes || echo no)" >> "$OUT/steps.txt"

step "THE REGION GOES DARK: no tripwire, no report — this machine is switched off while it trains"
# The evidence leaves first: this machine gets no other chance.
trap - ERR
finish DONE
# The moment, by this clock, where the operator can read it once this machine is gone.
date -u +%Y-%m-%dT%H:%M:%S.%NZ > /root/destroyed-at.txt
gcs_put /root/destroyed-at.txt out/primary-destroyed-at.txt || true
sync
# Power off now: no shutdown, no signal to the sentinel, no `stopped` heartbeat.
echo o > /proc/sysrq-trigger
sleep 60
