#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The closed-turn kit's dry run: go-on.sh on a workstation, with a simulated
# TEE and the worker tests' tiny model. No hardware and no cloud: it holds
# the standby's layout to what it must do before a run on real chips is
# paid for.
#
#   - a "primary" sentinel seals generation 0; that bundle is the parent;
#   - go-on.sh is run as acp-bootstrap would run it after a restore: with
#     the restored tree, the bundle and the generation;
#   - nothing is sealed from the state as restored, and the model answers
#     from it, under its name;
#   - training goes on, and its result takes the model's place;
#   - the standby's sentinel seals it as generation 1, the two outboxes are
#     one chain, and the answers now come from that state, under its name;
#   - the same question asked once, without the listener, gives the same
#     tokens;
#   - a second restore on the machine starts nothing again.
#
# Usage: dry-run.sh
#   VG_PYTHON  a Python with the worker's runtime (workers/genome/requirements.txt)
#              and pytest; default python3
# shellcheck disable=SC2015  # ok() cannot fail, so `check && ok … || bad …` is if-then-else here
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PY="${VG_PYTHON:-python3}"
W="$(mktemp -d)"
QUESTION="where does the key go ?"
ok() { echo "   ok    $1"; }
bad() { echo "   FAIL  $1"; FAIL=1; }
FAIL=0
cleanup() {
  set +e
  for f in "$W"/run/*.pid "$W"/primary.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
  sleep 1
  [ "$FAIL" = 0 ] && [ -z "${VG_KEEP:-}" ] && rm -rf "$W" || echo "left for a look: $W"
}
trap cleanup EXIT
json() { "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {"d": d}))' "$1" "$2"; }
wait_file() { # wait_file <path> <seconds>
  local n=0
  while [ ! -e "$1" ]; do n=$((n+1)); [ "$n" -gt $(( $2 * 5 )) ] && return 1; sleep 0.2; done
}

echo "== build acpctl for this machine; the tests' tiny base and a genome of 60 steps"
( cd "$ROOT" && go build -o "$W/acpctl" ./cmd/acpctl )
"$PY" - "$ROOT/workers/genome" "$W" <<'PY'
import json, os, sys
worker, w = sys.argv[1], sys.argv[2]
sys.path[:0] = [worker, os.path.join(worker, "tests")]
import conftest
from vg_genome.finetune import finetune
base = conftest.make_base(os.path.join(w, "base"))
data = os.path.join(w, "train.jsonl")
with open(data, "w") as f:
    for e in conftest.EXAMPLES:
        f.write(json.dumps(e) + "\n")
finetune(base, data, os.path.join(w, "genome"), **conftest.RECIPE)
PY
STEPS_0="$(json "$W/genome/genome.json" 'd["training"]["step"]')"
STEPS_1=$((STEPS_0 + 5))
ADAPTER_0="$(json "$W/genome/genome.json" 'd["adapter"]["weights_sha256"]')"

echo "== keys: the authority's escrow key, the two sentinels', the two simulated chips'"
"$W/acpctl" escrow keygen --out "$W/escrow.key" --pub "$W/escrow.pem" > /dev/null
for who in primary standby; do
  "$W/acpctl" sentinel keygen --out "$W/$who.seed" --pub "$W/$who.pem" > /dev/null
  head -c 32 /dev/urandom > "$W/$who-tee.seed"; chmod 600 "$W/$who-tee.seed"
  echo "no process reads this" > "$W/$who.canary"
done

echo "== the primary: its sentinel seals generation 0"
cp -R "$W/genome" "$W/primary-state"
mkdir -p "$W/outbox-a"
"$W/acpctl" sentinel watch --content-dir "$W/primary-state" --outbox "$W/outbox-a" --escrow-to "$W/escrow.pem" \
  --key "$W/primary.seed" --tee simulated --tee-seed "$W/primary-tee.seed" --workload-descriptor primary-dry-run \
  --tripwire "$W/primary.canary" --interval 200ms --settle 300ms > "$W/primary-sentinel.log" 2>&1 &
echo $! > "$W/primary.pid"
wait_file "$W/outbox-a/gen-000000.seal.json" 30 || { echo "generation 0 was not sealed"; cat "$W/primary-sentinel.log"; exit 1; }
kill "$(cat "$W/primary.pid")" 2>/dev/null || true

echo "== the standby: go-on.sh, as acp-bootstrap runs it after a restore its gate passed"
cp -R "$W/genome" "$W/restored"   # what the destination restored: generation 0's tree
PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$W/answer.token"; chmod 600 "$W/answer.token"   # this run's own, for its loopback listener
export VG_MODEL="$W/model" VG_OUTBOX="$W/outbox-b" VG_ESCROW="$W/escrow.pem" VG_SENTINEL_KEY="$W/standby.seed" \
  VG_TEE=simulated VG_TEE_SEED="$W/standby-tee.seed" VG_TEE_DESCRIPTOR=standby-dry-run VG_CANARY="$W/standby.canary" \
  VG_BASE="$W/base" VG_STEPS="$STEPS_1" VG_RUN="$W/run" VG_PYTHON="$PY" VG_WORKER="$ROOT/workers/genome" VG_ACPCTL="$W/acpctl" \
  VG_ANSWER_LISTEN="127.0.0.1:$PORT" VG_ANSWER_TOKEN="$W/answer.token" VG_INTERVAL=200ms VG_SETTLE=300ms VG_ANSWER_WAIT=120
bash "$HERE/go-on.sh" "$W/restored" "$W/outbox-a/gen-000000.genome" 0 && ok "go-on.sh ended with status 0" || bad "go-on.sh failed"

ask() { curl -sf -H "Authorization: Bearer $(cat "$W/answer.token")" -d "{\"prompt\": \"$QUESTION\", \"max_new_tokens\": 6}" "http://127.0.0.1:$PORT/v1/answer"; }

echo "== what the standby did by itself"
[ "$(json "$W/run/answer-first.json" 'd["genome"]["adapter_sha256"]')" = "$ADAPTER_0" ] && [ "$(json "$W/run/answer-first.json" 'd["genome"]["step"]')" = "$STEPS_0" ] \
  && ok "before training went on, the model answered from the restored state: step $STEPS_0, its adapter" || bad "the first answer is not from the restored state"
wait_file "$W/run/trained-at.txt" 120 && ok "training went on to step $STEPS_1 and its result took the model's place" || bad "training did not finish"
ADAPTER_1="$(json "$W/run/train.json" 'd["adapter_sha256"]')"
wait_file "$W/outbox-b/gen-000001.seal.json" 60 && ok "the standby's sentinel sealed generation 1" || bad "generation 1 was not sealed"
sleep 2   # a few more ticks: a state it was going to seal would be sealed by now
RECORDS="$(find "$W/outbox-b" -name 'gen-*.seal.json' | wc -l | tr -d ' ')"
[ "$RECORDS" = 1 ] && ok "one generation in the standby's outbox: nothing was sealed from the state as restored" || bad "$RECORDS generations in the standby's outbox, want 1"
PARENT="$(json "$W/outbox-a/gen-000000.seal.json" 'd["bundle_sha256"]')"
[ "$(json "$W/outbox-b/gen-000001.seal.json" 'd["parent_bundle_sha256"]')" = "$PARENT" ] && [ "$(json "$W/outbox-b/gen-000001.seal.json" 'd["attestation"]["kind"]')" = simulated ] \
  && ok "its record names generation 0's bundle as its parent and carries the chip's report" || bad "generation 1's record does not name its parent or carries no report"
mkdir -p "$W/together" && cp "$W"/outbox-a/gen-*.genome "$W"/outbox-b/gen-*.genome "$W/together/"
"$W/acpctl" genome chain --dir "$W/together" > "$W/chain.txt" 2>&1 && grep -q "2 generation(s)" "$W/chain.txt" && grep -q "chain valid" "$W/chain.txt" \
  && ok "the two outboxes together are one chain of two generations" || { bad "the chain across the two outboxes is not whole"; cat "$W/chain.txt"; }

ask > "$W/answer-after.json" || bad "the listener did not answer"
[ "$(json "$W/answer-after.json" 'd["genome"]["adapter_sha256"]')" = "$ADAPTER_1" ] && [ "$(json "$W/answer-after.json" 'd["genome"]["step"]')" = "$STEPS_1" ] && [ "$(json "$W/answer-after.json" 'd.get("stale")')" = None ] \
  && ok "the answers now come from the new state: step $STEPS_1, the adapter training wrote" || bad "the answer after training is not from the new state"
env "PYTHONPATH=$ROOT/workers/genome" TOKENIZERS_PARALLELISM=false "$PY" -m vg_genome answer --genome "$W/model" --base "$W/base" \
  --prompt "$QUESTION" --max-new-tokens 6 > "$W/answer-once.json" 2> "$W/answer-once.log"
[ "$(json "$W/answer-once.json" 'd["token_ids"]')" = "$(json "$W/answer-after.json" 'd["token_ids"]')" ] \
  && ok "asked once, without the listener, the same question gives the same tokens" || bad "the tokens differ between the listener and the command line"

echo "== a second restore on a machine that already goes on"
bash "$HERE/go-on.sh" "$W/restored" "$W/outbox-b/gen-000001.genome" 1 > "$W/second.log" 2>&1 && grep -q "already goes on" "$W/second.log" \
  && ok "starts nothing again, and says so" || { bad "a second restore did not leave the machine as it was"; cat "$W/second.log"; }
[ "$(find "$W/outbox-b" -name 'gen-*.seal.json' | wc -l | tr -d ' ')" = 1 ] && ok "still one generation in the standby's outbox" || bad "the second restore sealed something"

[ "$FAIL" = 0 ] && echo "DRY RUN: PASS" || { echo "DRY RUN: FAIL"; exit 1; }
