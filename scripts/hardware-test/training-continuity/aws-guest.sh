#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The training-continuity drill's arithmetic on one EC2 instance with AMD
# SEV-SNP (aws.sh brings this script, the worker package, common.sh and
# recipe.sh). No sentinel, no authority and no failover here — those are
# run.sh's, on Compute Engine. This machine answers one question about its
# own arithmetic: is the recipe, stopped twice and continued from each
# genome's state, the recipe run in one go? And it writes down the digests
# the recipe gives here, so they can be laid beside another machine's.
set -u
cd /home/ubuntu/e2e
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="/home/ubuntu/e2e/$STAMP"; mkdir -p "$OUT" /opt/worker
exec > >(tee -a "$OUT/console.log") 2>&1
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
pack() { tar -C /home/ubuntu/e2e -czf /home/ubuntu/e2e/results.tgz "$STAMP" 2>/dev/null; chown ubuntu /home/ubuntu/e2e/results.tgz 2>/dev/null; }
trap 'echo "FAILED at line $LINENO" >> "$OUT/steps.txt"; pack' ERR
. /home/ubuntu/e2e/common.sh
. /home/ubuntu/e2e/recipe.sh
set -eE

step "inputs"
tar -xzf /home/ubuntu/e2e/worker.tgz -C /opt/worker
# The kernel without the host's name: on EC2 that name is the private address.
{ uname -srvmo; lscpu; dmesg | grep -i -E "sev|snp" | head; } > "$OUT/system.txt" 2>&1
nproc > "$OUT/nproc.txt"
echo "cpu=$(grep -m1 'Model name' "$OUT/system.txt" | sed 's/.*: *//') vcpus=$(cat "$OUT/nproc.txt")" >> "$OUT/steps.txt"
echo "sev-snp guest: $(dmesg | grep -i -m1 -E 'SEV-SNP|SEV: .*SNP' || echo 'no SEV-SNP line in dmesg')" >> "$OUT/steps.txt"

step "python runtime (CPU, the hash-pinned locks) and base model"
python_runtime https://download.pytorch.org/whl/cpu
base_model

step "the recipe's first $STEPS_0 steps"
vg finetune --base /opt/base --base-name "$BASE_REPO" "${DATA[@]}" --out /root/g0 "${RECIPE[@]}" --steps "$STEPS_0" > "$OUT/finetune-0.json" 2> "$OUT/finetune-0.log"
step "training goes on from that genome, to step $STEPS_1"
vg finetune --continue /root/g0 --base /opt/base --steps "$STEPS_1" --out /root/g1 > "$OUT/finetune-1.json" 2> "$OUT/finetune-1.log"
genome_sums /root/g1 > "$OUT/generation-1.sha256"
step "and from that one, to step $STEPS_2"
vg finetune --continue /root/g1 --base /opt/base --steps "$STEPS_2" --out /root/continued > "$OUT/continue.json" 2> "$OUT/continue.log"
genome_sums /root/continued > "$OUT/continued.sha256"
python3 -c 'import json,sys; g=json.load(open(sys.argv[1])); json.dump({"training":g["training"],"recipe_steps":g["recipe"]["steps"],"losses":len(g["recipe"]["losses"]),"adapter_sha256":g["adapter"]["weights_sha256"],"written_on":g["runtime"]},sys.stdout,indent=1)' /root/continued/genome.json > "$OUT/continued-training.json"

step "held to the whole recipe (1): replay runs steps 1 to $STEPS_2 from the base and compares the adapter"
vg replay --genome /root/continued --base /opt/base > "$OUT/replay.json" 2> "$OUT/replay.log"
echo "replay: $(python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));print("exact=%s losses_equal=%s max_abs_diff=%s max_rel_l2=%s"%(r["exact"],r["losses_equal"],r["max_abs_diff"],r["max_rel_l2"]))' "$OUT/replay.json")" >> "$OUT/steps.txt"
replay_is_exact "$OUT/replay.json" || { echo "the continued genome is not the recipe taken to step $STEPS_2"; false; }

step "held to the whole recipe (2): the recipe in one go, $STEPS_2 steps, every file compared"
vg finetune --base /opt/base --base-name "$BASE_REPO" "${DATA[@]}" --out /root/whole "${RECIPE[@]}" --steps "$STEPS_2" > "$OUT/whole.json" 2> "$OUT/whole.log"
genome_sums /root/whole > "$OUT/whole.sha256"
SAME=0; DIFFERENT=0
for f in $RECIPE_FILES; do
  a=$(awk -v f="$f" '$2==f{print $1}' "$OUT/continued.sha256"); b=$(awk -v f="$f" '$2==f{print $1}' "$OUT/whole.sha256")
  if [ -n "$a" ] && [ "$a" = "$b" ]; then SAME=$((SAME+1)); echo "same       $f $a"; else DIFFERENT=$((DIFFERENT+1)); echo "DIFFERENT  $f continued=$a whole=$b"; fi
done > "$OUT/compare.txt"
LOSSES=$(python3 -c 'import json,sys;a=json.load(open(sys.argv[1]))["recipe"]["losses"];b=json.load(open(sys.argv[2]))["recipe"]["losses"];print("equal" if a==b else "different", len(a), len(b))' /root/continued/genome.json /root/whole/genome.json)
echo "losses $LOSSES" >> "$OUT/compare.txt"
echo "compare: $SAME files the same, $DIFFERENT different; losses $LOSSES" >> "$OUT/steps.txt"
[ "$DIFFERENT" = 0 ] && [ "${LOSSES%% *}" = equal ] || { echo "the continued genome differs from the recipe run in one go"; cat "$OUT/compare.txt"; false; }

echo "CONTINUED EXACT: the recipe stopped at $STEPS_0 and $STEPS_1 and continued to $STEPS_2 on this machine; replay exact; $SAME of $SAME files those of the recipe in one go" > "$OUT/verdict.txt"
cat "$OUT/verdict.txt" >> "$OUT/steps.txt"
trap - ERR
pack
