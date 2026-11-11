# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The drill's recipe, the same on every machine of the kit: what `finetune`
# is given where a recipe is started. A machine that goes on from a genome
# gives none of it — the genome says it — only the total number of steps to
# reach. The thread count is the recipe's, not the machine's.
RECIPE=(--targets q_proj,v_proj --rank 8 --alpha 16 --lr 3e-4 --max-len 64 --threads 8 --top-k 64 --new-tokens 16 --critical 4)
DATA=(--data /opt/worker/examples/drill-facts.jsonl --prompts /opt/worker/examples/drill-prompts.json)
STEPS_0=80    # generation 0: the recipe's first steps, on the primary
STEPS_1=160   # generation 1: the primary goes on from generation 0
STEPS_2=240   # what the primary was training toward when it was lost; the standby goes on from generation 1 to here

# Every file of a genome the recipe decides (genome.json also says when and
# where it was written).
RECIPE_FILES="adapter/adapter_model.safetensors adapter/adapter_config.json fixtures.json data/train.jsonl state/cursor.json state/optimizer.safetensors state/rng.json"

# genome_sums <genome dir>: the SHA-256 of every file the recipe decides.
genome_sums() { ( cd "$1" && sha256sum $RECIPE_FILES ); }

# replay_is_exact <replay.json>: true when replay found the sealed adapter
# and the losses to be the whole recipe's, bit for bit.
replay_is_exact() {
  python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); sys.exit(0 if r.get("exact") is True and r.get("losses_equal") is True and r.get("max_abs_diff")==0 else 1)' "$1"
}
