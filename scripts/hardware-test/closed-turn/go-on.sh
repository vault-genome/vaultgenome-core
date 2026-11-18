#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# What the closed-turn kit's standby runs after a restore its gate passed:
# the one command of `genome.after_restore` in acp-bootstrap's
# configuration (ADR 0041, decision 1). It moves no key. It puts the
# restored genome where the model lives and starts what goes on there:
#
#   1. the standby's own sentinel on the model's directory, the bundle the
#      genome was restored from as its parent: it seals what training
#      produces as the chain's next generations, on an outbox of its own;
#   2. the model's answers, from that directory (`vg-genome answer`);
#   3. training, from the state the restored genome carries to the step
#      this machine is told: `finetune --continue`, whose result takes the
#      model's place when it is whole.
#
#   go-on.sh <restored tree> <bundle> <generation>   started by acp-bootstrap, once
#   go-on.sh train <env file>                         the training it starts
#
# The services run under systemd where there is one (transient units
# vg-sentinel, vg-answer, vg-train); elsewhere — the kit's dry run on a
# workstation — as plain background processes with their logs in VG_RUN.
# Either way a service gets nothing of this script's environment but what
# its command line says: a unit does not inherit it, so neither does a
# process of the dry run.
#
# From the environment (after_restore.env):
#   VG_MODEL         the model's directory: training writes it, the sentinel
#                    seals it, the answers come from it; must not exist yet
#   VG_OUTBOX        the standby sentinel's outbox
#   VG_ESCROW        the release authority's escrow public key (PEM)
#   VG_SENTINEL_KEY  the standby sentinel's key file (sealed to this chip)
#   VG_TEE           gcp-sev-snp, or simulated with VG_TEE_SEED (and
#                    VG_TEE_DESCRIPTOR) for the dry run
#   VG_CANARY        a path nothing reads: the sentinel's tripwire
#   VG_BASE          the base model directory
#   VG_STEPS         the step training goes on to
#   VG_RUN           where this script keeps its log, its marker and, without
#                    systemd, the services' logs and process IDs
#   VG_PYTHON, VG_WORKER, VG_ACPCTL       default /opt/vg/bin/python, /opt/worker, /usr/local/bin/acpctl
#   VG_ANSWER_LISTEN, VG_ANSWER_TOKEN     default 127.0.0.1:8090, no token
#   VG_INTERVAL, VG_SETTLE                the sentinel's, default 3s and 4s
#   VG_ANSWER_WAIT                        seconds to wait for the first answer, default 240
set -euo pipefail

worker() { env "PYTHONPATH=$VG_WORKER" TOKENIZERS_PARALLELISM=false "$VG_PYTHON" -m vg_genome "$@"; }

if [ "${1:-}" = train ]; then
  # shellcheck source=/dev/null
  . "${2:?usage: go-on.sh train <env file>}"
  worker finetune --continue "$VG_MODEL" --base "$VG_BASE" --steps "$VG_STEPS" --out "$VG_MODEL.next" \
    > "$VG_RUN/train.json" 2>> "$VG_RUN/train.log"
  # The next state takes the model's place. The sentinel seals it once it
  # has settled, and the answers come from it; neither minds the moment
  # between the two renames (a state unreadable is not sealed and not served).
  mv "$VG_MODEL" "$VG_MODEL.was"
  mv "$VG_MODEL.next" "$VG_MODEL"
  rm -rf "$VG_MODEL.was"
  date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$VG_RUN/trained-at.txt"
  exit 0
fi

RESTORED="${1:?usage: go-on.sh <restored tree> <bundle> <generation>}"
BUNDLE="${2:?usage: go-on.sh <restored tree> <bundle> <generation>}"
GENERATION="${3:?usage: go-on.sh <restored tree> <bundle> <generation>}"
: "${VG_MODEL:?}" "${VG_OUTBOX:?}" "${VG_ESCROW:?}" "${VG_SENTINEL_KEY:?}" "${VG_TEE:?}" "${VG_CANARY:?}" "${VG_BASE:?}" "${VG_STEPS:?}" "${VG_RUN:?}"
VG_PYTHON="${VG_PYTHON:-/opt/vg/bin/python}"
VG_WORKER="${VG_WORKER:-/opt/worker}"
VG_ACPCTL="${VG_ACPCTL:-/usr/local/bin/acpctl}"
VG_ANSWER_LISTEN="${VG_ANSWER_LISTEN:-127.0.0.1:8090}"
mkdir -p "$VG_RUN" "$VG_OUTBOX"
say() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$VG_RUN/go-on.log"; }

# A second restore on a machine that already goes on — an operator opening
# a later generation here to look at it — starts nothing again.
if [ -e "$VG_RUN/going-on" ]; then
  say "generation $GENERATION restored; this machine already goes on ($(cat "$VG_RUN/going-on")): nothing is started"
  exit 0
fi
if [ -e "$VG_MODEL" ]; then
  say "$VG_MODEL exists: not going on over it"
  exit 1
fi

# start <name> <command...>
start() {
  local name="$1"; shift
  if command -v systemd-run >/dev/null 2>&1; then
    systemd-run --quiet --collect --unit "vg-$name" "$@"
  else
    env -i "PATH=$PATH" nohup "$@" > "$VG_RUN/$name.log" 2>&1 < /dev/null &
    echo $! > "$VG_RUN/$name.pid"
  fi
  say "started $name"
}

say "generation $GENERATION restored and its gate passed: going on from it"
cp -a "$RESTORED" "$VG_MODEL"

tee_flags=(--tee "$VG_TEE")
if [ "$VG_TEE" = simulated ]; then
  tee_flags+=(--tee-seed "${VG_TEE_SEED:?}" --workload-descriptor "${VG_TEE_DESCRIPTOR:-standby-sentinel}")
fi
start sentinel "$VG_ACPCTL" sentinel watch --content-dir "$VG_MODEL" --outbox "$VG_OUTBOX" \
  --escrow-to "$VG_ESCROW" --key "$VG_SENTINEL_KEY" "${tee_flags[@]}" --parent "$BUNDLE" \
  --tripwire "$VG_CANARY" --interval "${VG_INTERVAL:-3s}" --settle "${VG_SETTLE:-4s}"

answer=(env "PYTHONPATH=$VG_WORKER" TOKENIZERS_PARALLELISM=false "$VG_PYTHON" -m vg_genome answer
  --genome "$VG_MODEL" --base "$VG_BASE" --listen "$VG_ANSWER_LISTEN")
auth=()
if [ -n "${VG_ANSWER_TOKEN:-}" ]; then
  answer+=(--token-file "$VG_ANSWER_TOKEN")
  auth=(-H "Authorization: Bearer $(cat "$VG_ANSWER_TOKEN")")
fi
start answer "${answer[@]}"

# The model answers from the restored state before training moves it on.
answering=no
for _ in $(seq 1 "${VG_ANSWER_WAIT:-240}"); do
  if curl -sf ${auth[@]+"${auth[@]}"} "http://$VG_ANSWER_LISTEN/v1/answer/genome" > "$VG_RUN/answer-first.json" 2>/dev/null; then answering=yes; break; fi
  sleep 1
done
say "answers: $answering ($(cat "$VG_RUN/answer-first.json" 2>/dev/null))"

for v in VG_MODEL VG_BASE VG_STEPS VG_PYTHON VG_WORKER VG_RUN; do printf 'export %s=%q\n' "$v" "${!v}"; done > "$VG_RUN/go-on.env"
start train "$0" train "$VG_RUN/go-on.env"

echo "from generation $GENERATION since $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$VG_RUN/going-on"
# Training and the sentinel go on whatever became of the answers; that the
# answers did not come up is this command's failure, on the restore's record.
[ "$answering" = yes ] || { say "the model did not answer within ${VG_ANSWER_WAIT:-240} s"; exit 1; }
say "this machine goes on: sentinel, answers and training are started"
