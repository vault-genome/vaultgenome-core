#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The closed-turn drill's PRIMARY (machine A): an AMD SEV-SNP Confidential
# VM that trains a model and, beside it, runs the sentinel. It is the
# training-continuity drill's primary (../training-continuity/primary.sh)
# with one thing more: once generation 1 is sealed it answers a question
# from it, the way the model would answer a person — the answer the
# standby must give in its place.
#
# It takes the recipe's first steps (generation 0), goes on from its own
# genome (generation 1), holds generation 1 to the whole recipe by replay,
# answers, and goes on toward the step the standby will reach. Then it is
# lost while it trains: it uploads its evidence, writes the moment by its
# own clock, and powers itself off through the kernel's sysrq trigger — no
# shutdown, no signal to the sentinel, no `stopped` heartbeat.
set -u
exec > >(tee -a /root/primary.log) 2>&1
attr() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"; }
# shellcheck disable=SC2034  # BUCKET is read by common.sh's gcs_get and gcs_put
BUCKET=$(attr vg-bucket)
OUT=/root/out; OUTBOX=/root/outbox; mkdir -p "$OUT" /opt/worker "$OUTBOX"; cd /root
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
finish() {
  cp /root/primary.log "$OUT/console.log" 2>/dev/null || true
  tar -C "$OUT" -czf /root/out.tgz . 2>/dev/null && gcs_put /root/out.tgz out/primary.tgz 2>/dev/null || true
  echo "$1" > /root/marker; gcs_put /root/marker "out/primary/$1" 2>/dev/null || true
}
trap 'finish FAILED' ERR

attr vg-common > /root/common.sh; . /root/common.sh
attr vg-recipe > /root/recipe.sh; . /root/recipe.sh
attr vg-lib > /root/lib.sh; . /root/lib.sh
set -eE

step "inputs"
gcs_get in/acpctl /usr/local/bin/acpctl && chmod +x /usr/local/bin/acpctl
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu; dmesg | grep -i -E "sev|snp" | head; } > "$OUT/system.txt" 2>&1

step "configfs-tsm (the sentinel attests with this chip)"
tsm "$OUT/tsm.txt"

step "python runtime (CPU) and base model"
python_runtime https://download.pytorch.org/whl/cpu
base_model

step "wait for the release authority's escrow key"
for _ in $(seq 1 240); do gcs_get handoff/escrow.pem /root/escrow.pem 2>/dev/null && break; sleep 5; done
[ -s /root/escrow.pem ] || { echo "no escrow key after 20 minutes"; false; }

step "the sentinel's key and this chip's identity; the operator pins both"
acpctl sentinel keygen --out /root/sentinel.seed --pub /root/sentinel.pem > "$OUT/sentinel-keygen.txt"
acpctl sentinel identity --tee gcp-sev-snp --key /root/sentinel.seed > "$OUT/sentinel-identity.json"
echo "primary measurement=$(json "$OUT/sentinel-identity.json" 'd["measurement_hex"]') sentinel=$(json "$OUT/sentinel-identity.json" 'd["sentinel"]')" >> "$OUT/steps.txt"
gcs_put /root/sentinel.pem handoff/sentinel.pem
gcs_put "$OUT/sentinel-identity.json" handoff/sentinel-identity.json

step "seal the sentinel's seed to this chip (ADR 0023)"
acpctl sentinel seal-key --key /root/sentinel.seed --tee gcp-sev-snp > "$OUT/sentinel-seal-key.json"
echo "sentinel seal-key exit=0 tee=$(json "$OUT/sentinel-seal-key.json" 'd["tee"]') sealed=$(json "$OUT/sentinel-seal-key.json" 'd["sealed"]')" >> "$OUT/steps.txt"

step "generation 0: the recipe's first $STEPS_0 steps"
vg finetune --base /opt/base --base-name "$BASE_REPO" "${DATA[@]}" --out /root/genome "${RECIPE[@]}" --steps "$STEPS_0" \
  > "$OUT/finetune-0.json" 2> "$OUT/finetune-0.log"

step "arm a tripwire and start the sentinel"
echo "no process reads this" > /root/canary
# The outbox goes to the bucket every few seconds until the machine is
# gone. The loop's subshell drops the ERR trap: a push refused once is
# replaced by the next.
( trap - ERR; set +e; while true; do push_outbox "$OUTBOX" || true; sleep 3; done ) &
acpctl sentinel watch --content-dir /root/genome --outbox "$OUTBOX" \
  --escrow-to /root/escrow.pem --key /root/sentinel.seed --tee gcp-sev-snp \
  --tripwire /root/canary --tripwire /usr/local/bin/acpctl \
  --interval 3s --settle 4s > "$OUT/sentinel.json" 2> "$OUT/sentinel.log" &
SENTINEL=$!

wait_seal() { for _ in $(seq 1 120); do [ -e "$OUTBOX/$1" ] && return 0; sleep 2; done; return 1; }
step "wait for generation 0 to be sealed"
wait_seal gen-000000.seal.json || { echo "generation 0 not sealed"; false; }

step "wait for the authority to arm its failover watch"
for _ in $(seq 1 720); do gcs_get handoff/armed /root/armed 2>/dev/null && break; sleep 5; done
[ -s /root/armed ] || { echo "the authority did not arm within an hour"; false; }

step "generation 1: training goes on from generation 0, from step $STEPS_0 to $STEPS_1"
vg finetune --continue /root/genome --base /opt/base --steps "$STEPS_1" --out /root/stage \
  > "$OUT/finetune-1.json" 2> "$OUT/finetune-1.log"
rm -rf /root/genome && mv /root/stage /root/genome
step "wait for generation 1 to be sealed and replicated"
wait_seal gen-000001.seal.json || { echo "generation 1 not sealed"; false; }
push_outbox "$OUTBOX" || { sleep 2; push_outbox "$OUTBOX"; } || true
sleep 6
cp "$OUTBOX/gen-000001.seal.json" "$OUT/generation-1.seal.json"

step "generation 1 held to the whole recipe: replay runs steps 1 to $STEPS_1 from the base, on this chip"
genome_sums /root/genome > "$OUT/generation-1.sha256"
python3 -c 'import json,sys; g=json.load(open(sys.argv[1])); json.dump({"training":g["training"],"recipe_steps":g["recipe"]["steps"],"losses":len(g["recipe"]["losses"]),"adapter_sha256":g["adapter"]["weights_sha256"]},sys.stdout,indent=1)' /root/genome/genome.json > "$OUT/generation-1-training.json"
vg replay --genome /root/genome --base /opt/base > "$OUT/replay-1.json" 2> "$OUT/replay-1.log"
replay_is_exact "$OUT/replay-1.json" || { echo "generation 1 is not the recipe taken to step $STEPS_1"; false; }
echo "generation 1: replay exact=$(json "$OUT/replay-1.json" 'd["exact"]') losses_equal=$(json "$OUT/replay-1.json" 'd["losses_equal"]')" >> "$OUT/steps.txt"

step "the model answers a question from generation 1: the answer the standby must give in its place"
vg answer --genome /root/genome --base /opt/base --prompt "$QUESTION" --max-new-tokens "$ANSWER_TOKENS" \
  > "$OUT/answer-1.json" 2> "$OUT/answer-1.log"
echo "answer from generation 1: step=$(json "$OUT/answer-1.json" 'd["genome"]["step"]') adapter=$(json "$OUT/answer-1.json" 'd["genome"]["adapter_sha256"]') text=$(json "$OUT/answer-1.json" 'repr(d["text"])')" >> "$OUT/steps.txt"

step "training goes on toward step $STEPS_2 — the work the loss takes with it"
( trap - ERR; set +e; vg finetune --continue /root/genome --base /opt/base --steps "$STEPS_2" --out /root/stage2 \
    > "$OUT/finetune-2.json" 2> "$OUT/finetune-2.log" ) &
TRAIN2=$!
for _ in $(seq 1 60); do grep -q "^step " "$OUT/finetune-2.log" 2>/dev/null && break; sleep 1; done
sleep 4
echo "toward step $STEPS_2 when the power went: $(kill -0 "$TRAIN2" 2>/dev/null && echo "still training" || echo "finished early"); last line of its log: $(grep '^step ' "$OUT/finetune-2.log" 2>/dev/null | tail -1)" >> "$OUT/steps.txt"
echo "sentinel running when the power went: $(kill -0 "$SENTINEL" 2>/dev/null && echo yes || echo no)" >> "$OUT/steps.txt"

step "THE PRIMARY IS LOST: no tripwire, no report — this machine is switched off while it trains"
# The evidence leaves first: this machine gets no other chance.
trap - ERR
finish DONE
date -u +%Y-%m-%dT%H:%M:%S.%NZ > /root/destroyed-at.txt
gcs_put /root/destroyed-at.txt out/primary-destroyed-at.txt || true
sync
echo o > /proc/sysrq-trigger
sleep 60
