#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The closed-turn drill's STANDBY (machine B): an AMD SEV-SNP Confidential
# VM that hosts the destination (acp-bootstrap) and nothing of the
# authority. It is provisioned to go on by itself (ADR 0041):
#
#   - its own sentinel's key is made and sealed on this chip, and handed to
#     the operator, before the failover policy is signed;
#   - acp-bootstrap's configuration names one command to run after a
#     restore its required gate passed (genome.after_restore): go-on.sh,
#     which starts the sentinel, the model's answers and the training.
#
# Then this script starts nothing. It replicates outboxes, and it looks
# and asks: the restore's record, who answers the question and from which
# generation, the generation the sentinel sealed, that generation opened
# again by an attested release and asked the same question, and the
# continued genome against the whole recipe.
#
# vg-mode=negative: this machine's base model is not the genome's. The
# gate cannot be passed, the restore fails, and nothing starts; the record
# says why.
set -u
exec > >(tee -a /root/standby.log) 2>&1
attr() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"; }
# shellcheck disable=SC2034  # BUCKET is read by common.sh's gcs_get and gcs_put
BUCKET=$(attr vg-bucket); MODE=$(attr vg-mode)
OUT=/root/out; REPLICA=/root/replica; OUTBOX_B=/root/outbox-b; GO=/root/go-on; MODEL=/root/model
mkdir -p "$OUT" /opt/worker "$REPLICA" /root/dest /root/look; cd /root
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
finish() {
  cp /root/standby.log "$OUT/console.log" 2>/dev/null || true
  cp /root/acp-bootstrap.log "$OUT/acp-bootstrap.log" 2>/dev/null || true
  cp "$GO/go-on.log" "$OUT/go-on.log" 2>/dev/null || true
  cp "$GO/train.log" "$OUT/train.log" 2>/dev/null || true
  journalctl --no-pager -u vg-sentinel -u vg-answer -u vg-train > "$OUT/services.log" 2>&1 || true
  tar -C "$OUT" -czf /root/out.tgz . 2>/dev/null && gcs_put /root/out.tgz out/standby.tgz 2>/dev/null || true
  echo "$1" > /root/marker; gcs_put /root/marker "out/standby/$1" 2>/dev/null || true
}
trap 'finish FAILED' ERR
attr vg-common > /root/common.sh; . /root/common.sh
attr vg-recipe > /root/recipe.sh; . /root/recipe.sh
attr vg-lib > /root/lib.sh; . /root/lib.sh
set -eE

step "inputs (mode: $MODE)"
for b in acp-bootstrap acpctl; do gcs_get "in/$b" "/usr/local/bin/$b" && chmod +x "/usr/local/bin/$b"; done
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
attr vg-go-on > /usr/local/bin/vg-go-on && chmod +x /usr/local/bin/vg-go-on
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu; } > "$OUT/system.txt" 2>&1
MY_IP=$(md network-interfaces/0/ip)

step "python runtime (CPU) and base model — the gate, the training and the answers run the model here"
python_runtime https://download.pytorch.org/whl/cpu
base_model
if [ "$MODE" = negative ]; then
  step "NEGATIVE: this machine's base model is not the genome's — one byte more in its config.json"
  sha256sum /opt/base/config.json > "$OUT/base-config-before.sha256"
  printf ' ' >> /opt/base/config.json
  sha256sum /opt/base/config.json > "$OUT/base-config-after.sha256"
fi

step "configfs-tsm (real SEV-SNP reports)"
tsm "$OUT/tsm.txt"

step "wait for the authority: its public key, its escrow key, this destination's TLS material and token"
for _ in $(seq 1 240); do
  gcs_get handoff/authority.pem /root/authority.pem 2>/dev/null && gcs_get handoff/escrow.pem /root/escrow.pem 2>/dev/null \
    && gcs_get handoff/dest/client.key /root/look/client.key 2>/dev/null && break
  sleep 5
done
[ -s /root/authority.pem ] && [ -s /root/escrow.pem ] && [ -s /root/look/client.key ] || { echo "no hand-off from the authority after 20 minutes"; false; }
for f in server.crt server.key ca.crt xcc_token; do gcs_get "handoff/dest/$f" "/root/dest/$f"; done
# acp-bootstrap seals what its configuration names, in place (ADR 0023).
# What this script looks at the destination with — as a client, the way
# the authority does — is kept apart, and is not the daemon's.
gcs_get handoff/dest/client.crt /root/look/client.crt
cp /root/dest/ca.crt /root/look/ca.crt; cp /root/dest/xcc_token /root/look/token
chmod 600 /root/dest/server.key /root/dest/xcc_token /root/look/client.key /root/look/token

step "this machine's own sentinel: its key made and sealed on this chip, before the operator signs (ADR 0041)"
acpctl sentinel keygen --out /root/standby-sentinel.seed --pub /root/standby-sentinel.pem > "$OUT/sentinel-keygen.txt"
acpctl sentinel identity --tee gcp-sev-snp --key /root/standby-sentinel.seed > "$OUT/sentinel-identity.json"
acpctl sentinel seal-key --key /root/standby-sentinel.seed --tee gcp-sev-snp > "$OUT/sentinel-seal-key.json"
echo "standby sentinel=$(json "$OUT/sentinel-identity.json" 'd["sentinel"]') attests at $(json "$OUT/sentinel-identity.json" 'd["measurement_hex"]'); seed sealed to $(json "$OUT/sentinel-seal-key.json" 'd["tee"]')" >> "$OUT/steps.txt"
gcs_put /root/standby-sentinel.pem handoff/standby-sentinel.pem
gcs_put "$OUT/sentinel-identity.json" handoff/standby-sentinel-identity.json

step "acp-bootstrap on SEV-SNP: the destination, its gate, and the one command it runs after a restore its gate passed"
echo "no process reads this" > /root/canary
head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > /root/answer.token; chmod 600 /root/answer.token
python3 - <<PY
import json
env = ["VG_MODEL=$MODEL", "VG_OUTBOX=$OUTBOX_B", "VG_ESCROW=/root/escrow.pem", "VG_SENTINEL_KEY=/root/standby-sentinel.seed",
       "VG_TEE=gcp-sev-snp", "VG_CANARY=/root/canary", "VG_BASE=/opt/base", "VG_STEPS=$STEPS_2", "VG_RUN=$GO",
       "VG_ANSWER_LISTEN=$ANSWER_LISTEN", "VG_ANSWER_TOKEN=/root/answer.token"]
c={
 "http":{"listen_address":"0.0.0.0:8443","bearer_token_file":"/root/dest/xcc_token",
         "tls":{"enabled":True,"server_cert":"/root/dest/server.crt","server_key":"/root/dest/server.key","client_cas":"/root/dest/ca.crt"}},
 "tee":{"provider":"gcp-sev-snp","workload_descriptor":"acp-bootstrap-standby-v1"},
 "source_authority":{"kid":"sagvd-authority-demo","public_key_path":"/root/authority.pem"},
 "genome":{"bundle_dir":"$REPLICA","restore_dir":"/root/restored","rescan_seconds":2,
           "gate":{"command":["/opt/vg/bin/python","-m","vg_genome","door","--genome","{genome}","--base","/opt/base","--device","cpu"],
                   "env":["PYTHONPATH=/opt/worker","TOKENIZERS_PARALLELISM=false"],"atol":0.01,"rtol":0.001,"timeout_seconds":300,"required":True},
           "after_restore":{"command":["/usr/local/bin/vg-go-on","{genome}","{bundle}","{generation}"],"env":env,"timeout_seconds":300}},
 "health":{"listen_address":"127.0.0.1:8444"},"log":{"level":"info","format":"json"}}
json.dump(c,open("/root/dest.json","w"),indent=2)
PY
python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["genome"]["after_restore"], indent=1))' /root/dest.json > "$OUT/after-restore-config.json"
acp-bootstrap seal-keys -config /root/dest.json > "$OUT/dest-seal-keys.json" 2> "$OUT/dest-seal-keys.err"
echo "acp-bootstrap seal-keys exit=$? sealed=$(python3 -c 'import json,sys;print(",".join(e["name"] for e in json.load(open(sys.argv[1]))["sealed"]))' "$OUT/dest-seal-keys.json" 2>/dev/null)" >> "$OUT/steps.txt"
acp-bootstrap identity -config /root/dest.json > "$OUT/destination-identity.json" 2> "$OUT/destination-identity.err"
CUT=/root/restored/genome-0123456789ab-g7-ba9876543210
if [ "$MODE" = negative ]; then
  # What a restore leaves when the daemon is stopped between writing the
  # tree and signing for it: a tree named as a genome key, with no receipt
  # beside it. The kit puts one there; the daemon is to remove it when it
  # starts.
  mkdir -p "$CUT/adapter"
  echo "nobody signed for this" > "$CUT/adapter/adapter_model.safetensors"
  echo "before the daemon started: $CUT, $(find "$CUT" -type f | wc -l | tr -d ' ') file, no receipt beside it" > "$OUT/cut-short.txt"
fi
acp-bootstrap -config /root/dest.json > /root/acp-bootstrap.log 2>&1 &
n=0; until curl -sf http://127.0.0.1:8444/readyz >/dev/null || [ $n -ge 30 ]; do sleep 1; n=$((n+1)); done
if [ "$MODE" = negative ]; then
  echo "after the daemon started: $([ -e "$CUT" ] && echo "still there" || echo gone)" >> "$OUT/cut-short.txt"
  cat "$OUT/cut-short.txt" >> "$OUT/steps.txt"
fi
MEAS=$(json "$OUT/destination-identity.json" 'd["measurement_hex"]')
echo "standby measurement=$MEAS endpoint=https://$MY_IP:8443" >> "$OUT/steps.txt"
python3 -c 'import json,sys; json.dump({"endpoint": "https://%s:8443" % sys.argv[1], "measurement_hex": sys.argv[2]}, open("/root/destination.json","w"))' "$MY_IP" "$MEAS"
gcs_put /root/destination.json handoff/destination.json

step "replicate: the primary's outbox comes in; this machine's own goes out, and its sealed bundles lie where a destination looks for them"
# The primary's outbox travels whole and from another region: it is
# fetched every fifth cycle. Its bundles are here long before a failover
# asks for them; this machine's own outbox, with its heartbeat, goes out
# every cycle.
( trap - ERR; set +e
  cycle=0
  while true; do
    [ $((cycle % 5)) != 0 ] || pull_outbox "$REPLICA"
    cycle=$((cycle + 1))
    if [ -d "$OUTBOX_B" ]; then
      push_outbox_b "$OUTBOX_B"
      # A bundle is whole once its seal record is there: the record is written last.
      for g in "$OUTBOX_B"/gen-*.genome; do
        [ -f "$g" ] && [ -f "${g%.genome}.seal.json" ] || continue
        name="$(basename "$g")"
        [ -f "$REPLICA/$name" ] || { cp "$g" "$REPLICA/.incoming-$name" && mv "$REPLICA/.incoming-$name" "$REPLICA/$name"; }
      done
    fi
    sleep 3
  done ) &

api() { curl -sS --cacert /root/look/ca.crt --cert /root/look/client.crt --key /root/look/client.key -H "Authorization: Bearer $(cat /root/look/token)" "https://localhost:8443$1"; }
# restore_field <restores.json> <index> <python expression over r>: one value of one restore's record, "" when there is none
restore_field() { python3 -c 'import json,sys
try:
    r = json.load(open(sys.argv[1]))["restores"][int(sys.argv[2])]
    print(eval(sys.argv[3], {"r": r}))
except Exception:
    print("")' "$1" "$2" "$3"; }
# restored_from <restores.json> <bundle file name>: the key ID of the restore of that bundle, once it is restored
restored_from() { python3 -c 'import json,sys
try:
    for r in json.load(open(sys.argv[1]))["restores"]:
        if r.get("bundle", "").endswith("/" + sys.argv[2]) and r["state"] == "restored":
            print(r["key_id"]); break
except Exception:
    pass' "$1" "$2"; }

step "FROM HERE THIS SCRIPT STARTS NOTHING ON THIS MACHINE: it looks, and it asks"
step "wait for a restore (the primary trains two generations first; up to 80 min)"
STATE=""
for _ in $(seq 1 960); do
  api /v1/genome/restores > /root/restores.json 2>/dev/null || true
  STATE=$(restore_field /root/restores.json 0 'r["state"]')
  case "$STATE" in restored|gate_failed|failed) break ;; esac
  sleep 5
done
echo "restore: state=${STATE:-none}" >> "$OUT/steps.txt"

if [ "$MODE" = negative ]; then
  step "NEGATIVE: the gate could not be passed — nothing may have started"
  sleep 45   # anything that was going to start would have by now
  api /v1/genome/restores > "$OUT/restore-record.json" 2>/dev/null || true
  AFTER=$(restore_field "$OUT/restore-record.json" 0 '"yes" if r.get("after_restore") else "no"')
  STARTED=""
  [ "$AFTER" = no ] || STARTED="$STARTED after_restore-on-the-record"
  for p in "$MODEL" "$GO" "$OUTBOX_B"; do [ ! -e "$p" ] || STARTED="$STARTED $p"; done
  for u in vg-sentinel vg-answer vg-train; do [ "$(systemctl is-active "$u" 2>/dev/null | head -1)" != active ] || STARTED="$STARTED unit:$u"; done
  ! curl -s -o /dev/null --max-time 5 "http://$ANSWER_LISTEN/v1/answer/genome" || STARTED="$STARTED listener:$ANSWER_LISTEN"
  PROCS=$(pgrep -fc 'sentinel watch|vg_genome (answer|finetune)' || true)
  [ "$PROCS" = 0 ] || STARTED="$STARTED processes:$PROCS"
  KID=$(restore_field "$OUT/restore-record.json" 0 'r["key_id"]')
  # A restore that failed leaves no tree: nothing to start from, by hand either.
  LEFT=$(find /root/restored -mindepth 1 2>/dev/null | wc -l | tr -d ' ')
  [ "$LEFT" = 0 ] || STARTED="$STARTED restored-files:$LEFT"
  {
    echo "restore state: $(restore_field "$OUT/restore-record.json" 0 'r["state"]')"
    echo "restore error: $(restore_field "$OUT/restore-record.json" 0 'r.get("error")')"
    echo "after_restore on the record: $AFTER"
    echo "the model's directory, go-on's directory, this machine's outbox, the units vg-sentinel, vg-answer and vg-train, a listener on $ANSWER_LISTEN, processes of the sentinel, the answers or the training:${STARTED:- none}"
    echo "under the restore directory, of key $KID or anything else: $LEFT entries"
  } > "$OUT/nothing-started.txt" 2>&1
  cat "$OUT/nothing-started.txt" >> "$OUT/steps.txt"
  case "$STATE" in failed|gate_failed) ;; *) echo "the restore's state is '${STATE:-none}': a gate that cannot pass must fail it"; false ;; esac
  [ -z "$STARTED" ] || { echo "started on a machine whose gate did not pass:$STARTED"; false; }
  grep -q "^after the daemon started: gone$" "$OUT/cut-short.txt" || { echo "the daemon started beside a tree nobody signed for"; false; }
  echo "NOTHING STARTED: the restore is $STATE, no training, sentinel or answers were started, and no file of the genome is left; the record says why" > "$OUT/verdict.txt"
  cat "$OUT/verdict.txt" >> "$OUT/steps.txt"
  trap - ERR
  finish DONE
  exit 0
fi

[ "$STATE" = restored ] || { echo "the restore's state is '${STATE:-none}'"; cp /root/restores.json "$OUT/restore-record.json" 2>/dev/null || true; false; }
step "the destination ran its one command by itself: wait for what it did to be on the restore's record"
for _ in $(seq 1 120); do
  api /v1/genome/restores > /root/restores.json 2>/dev/null || true
  [ "$(restore_field /root/restores.json 0 '"yes" if r.get("after_restore") else ""')" = yes ] && break
  sleep 3
done
cp /root/restores.json "$OUT/restore-record.json"
KID=$(restore_field "$OUT/restore-record.json" 0 'r["key_id"]')
RESTORED="/root/restored/$KID"
echo "restore: key=$KID gate=$(restore_field "$OUT/restore-record.json" 0 'r["gate"]["level"]') after_restore: exit=$(restore_field "$OUT/restore-record.json" 0 'r["after_restore"]["exit_code"]') seconds=$(restore_field "$OUT/restore-record.json" 0 'round(r["after_restore"]["seconds"], 1)') error=$(restore_field "$OUT/restore-record.json" 0 'r["after_restore"].get("error")')" >> "$OUT/steps.txt"
[ "$(restore_field "$OUT/restore-record.json" 0 'r["after_restore"]["exit_code"]')" = 0 ] || { echo "the after-restore command did not end well"; false; }
genome_sums "$RESTORED" > "$OUT/restored.sha256"
cp "$GO/answer-first.json" "$OUT/answer-first.json" 2>/dev/null || true

step "ask the model, again and again, while training goes on: who answers, and from which generation"
ask() {
  curl -sf --max-time 300 -H "Authorization: Bearer $(cat /root/answer.token)" \
    -d "$(python3 -c 'import json,sys; print(json.dumps({"prompt": sys.argv[1], "max_new_tokens": int(sys.argv[2])}))' "$QUESTION" "$ANSWER_TOKENS")" \
    "http://$ANSWER_LISTEN/v1/answer"
}
last_step() { tail -n 1 "$OUT/answers.jsonl" 2>/dev/null | python3 -c 'import json,sys
try: print(json.loads(sys.stdin.read())["genome"]["step"])
except Exception: print("")'; }
: > "$OUT/answers.jsonl"
DEADLINE=$(( $(date +%s) + 40 * 60 ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  if A=$(ask 2>/dev/null); then printf '%s\n' "$A" >> "$OUT/answers.jsonl"; fi
  [ -e "$GO/trained-at.txt" ] && [ "$(last_step)" = "$STEPS_2" ] && break
  sleep 2
done
python3 - "$OUT/answers.jsonl" "$OUT" "$STEPS_1" "$STEPS_2" >> "$OUT/steps.txt" <<'PY'
import json, sys
path, out, s1, s2 = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
answers = [json.loads(l) for l in open(path) if l.strip()]
by_step = {}
for a in answers:
    by_step.setdefault(a["genome"]["step"], []).append(a)
for step, name in ((s1, "answer-restored.json"), (s2, "answer-continued.json")):
    got = by_step.get(step, [])
    if got:
        json.dump(got[0], open(out + "/" + name, "w"), indent=1)
    same = len({json.dumps(a["token_ids"]) for a in got}) <= 1
    print("answers from step %d: %d, all the same tokens: %s, adapter %s" % (step, len(got), same, got[0]["genome"]["adapter_sha256"] if got else None))
print("answers in all: %d; from other steps: %d; marked stale: %d" % (len(answers), sum(len(v) for k, v in by_step.items() if k not in (s1, s2)), sum(1 for a in answers if a.get("stale"))))
PY
cp "$GO/train.json" "$OUT/continue.json" 2>/dev/null || true
cp "$GO/trained-at.txt" "$OUT/trained-at.txt" 2>/dev/null || true
# What the two cost each other: the steps taken here beside the questions
# (train_seconds adds up over a genome's life, so the restored genome's is
# taken off), and how long an answer took while training ran.
python3 - "$OUT/continue.json" "$RESTORED/genome.json" "$OUT/answers.jsonl" "$STEPS_1" "$STEPS_2" >> "$OUT/steps.txt" <<'PY'
import json, sys
here = json.load(open(sys.argv[1]))["train_seconds"] - json.load(open(sys.argv[2]))["recipe"]["train_seconds"]
s1, s2 = int(sys.argv[4]), int(sys.argv[5])
secs = sorted(json.loads(l)["seconds"] for l in open(sys.argv[3]) if l.strip() and json.loads(l)["genome"]["step"] == s1)
print("beside each other: steps %d-%d took %.1f s here; an answer while training ran took %.1f s (median of %d, from %.1f to %.1f)" % (
    s1 + 1, s2, here, secs[len(secs) // 2], len(secs), secs[0], secs[-1]))
PY
[ -s "$OUT/answer-restored.json" ] && [ -s "$OUT/answer-continued.json" ] || { echo "the model did not answer from both generations"; false; }
genome_sums "$MODEL" > "$OUT/continued.sha256"
python3 -c 'import json,sys; g=json.load(open(sys.argv[1])); json.dump({"training":g["training"],"recipe_steps":g["recipe"]["steps"],"losses":len(g["recipe"]["losses"]),"adapter_sha256":g["adapter"]["weights_sha256"],"written_on":g["runtime"]},sys.stdout,indent=1)' "$MODEL/genome.json" > "$OUT/continued-training.json"

step "this machine's own sentinel: the generation after the one restored, under its key, with this chip's report"
for _ in $(seq 1 120); do [ -e "$OUTBOX_B/gen-000002.seal.json" ] && break; sleep 2; done
[ -e "$OUTBOX_B/gen-000002.seal.json" ] || { echo "generation 2 was not sealed"; ls -la "$OUTBOX_B" 2>&1; false; }
sleep 12   # more ticks than a state takes to settle: one that was going to be sealed is sealed by now
cp "$OUTBOX_B/gen-000002.seal.json" "$OUT/generation-2.seal.json"
cp "$OUTBOX_B/heartbeat.json" "$OUT/standby-heartbeat.json" 2>/dev/null || true
find "$OUTBOX_B" -maxdepth 1 -name 'gen-*.seal.json' | sort | sed 's#.*/##' > "$OUT/standby-outbox-generations.txt"
echo "this machine's outbox holds: $(tr '\n' ' ' < "$OUT/standby-outbox-generations.txt")" >> "$OUT/steps.txt"
echo "generation 2: sentinel=$(json "$OUT/generation-2.seal.json" 'd["sentinel"]') parent=$(json "$OUT/generation-2.seal.json" 'd["parent_bundle_sha256"]') attested by $(json "$OUT/generation-2.seal.json" 'd["attestation"]["kind"]')" >> "$OUT/steps.txt"
rm -rf /root/together && mkdir -p /root/together
cp "$REPLICA/gen-000000.genome" "$REPLICA/gen-000001.genome" "$OUTBOX_B"/gen-*.genome /root/together/
acpctl genome chain --dir /root/together > "$OUT/chain.txt" 2>&1 || true
echo "chain: $(grep -E 'generation\(s\)|chain valid|broken' "$OUT/chain.txt" | tr '\n' ' ')" >> "$OUT/steps.txt"

step "the generation the sentinel sealed, opened again by an attested release from the authority: wait for it"
for _ in $(seq 1 360); do gcs_get handoff/reopened /root/reopened 2>/dev/null && break; sleep 5; done
[ -s /root/reopened ] || { echo "the authority did not release generation 2 within half an hour"; false; }
KID2=""
for _ in $(seq 1 120); do
  api /v1/genome/restores > "$OUT/restore-records-after.json" 2>/dev/null || true
  KID2=$(restored_from "$OUT/restore-records-after.json" gen-000002.genome)
  [ -n "$KID2" ] && break
  sleep 3
done
[ -n "$KID2" ] || { echo "generation 2 was not restored here"; false; }
REOPENED="/root/restored/$KID2"
genome_sums "$REOPENED" > "$OUT/reopened.sha256"
if cmp -s "$OUT/reopened.sha256" "$OUT/continued.sha256"; then
  echo "reopened: the sealed generation 2 is, file by file, what training made here" >> "$OUT/steps.txt"
else
  echo "reopened: DIFFERENT from what training made here" >> "$OUT/steps.txt"
fi

step "the same question, recomputed from the sealed and reopened generation, without the listener"
vg answer --genome "$REOPENED" --base /opt/base --prompt "$QUESTION" --max-new-tokens "$ANSWER_TOKENS" > "$OUT/answer-reopened.json" 2> "$OUT/answer-reopened.log"
echo "recomputed: step=$(json "$OUT/answer-reopened.json" 'd["genome"]["step"]') same tokens as the listener's=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token_ids"] == json.load(open(sys.argv[2]))["token_ids"])' "$OUT/answer-reopened.json" "$OUT/answer-continued.json")" >> "$OUT/steps.txt"
# The second restore's command has had its say by the time its record shows it.
for _ in $(seq 1 60); do
  api /v1/genome/restores > "$OUT/restore-records-after.json" 2>/dev/null || true
  [ "$(restore_field "$OUT/restore-records-after.json" 1 '"yes" if r.get("after_restore") else ""')" = yes ] && break
  sleep 2
done
cp "$GO/go-on.log" "$OUT/go-on.log" 2>/dev/null || true
echo "second restore: after_restore exit=$(restore_field "$OUT/restore-records-after.json" 1 'r["after_restore"]["exit_code"]'); $(grep -c 'already goes on' "$OUT/go-on.log" 2>/dev/null || true) line(s) of go-on.log say the machine already goes on" >> "$OUT/steps.txt"

step "what training made here, held to the whole recipe on this chip (1): replay from the first step"
vg replay --genome "$MODEL" --base /opt/base > "$OUT/replay.json" 2> "$OUT/replay.log"
echo "replay: exact=$(json "$OUT/replay.json" 'd["exact"]') losses_equal=$(json "$OUT/replay.json" 'd["losses_equal"]') max_abs_diff=$(json "$OUT/replay.json" 'd["max_abs_diff"]')" >> "$OUT/steps.txt"
replay_is_exact "$OUT/replay.json" || { echo "the continued genome is not the recipe taken to step $STEPS_2"; false; }

step "held to the whole recipe (2): the recipe run here in one go, $STEPS_2 steps, every file compared"
vg finetune --base /opt/base --base-name "$BASE_REPO" "${DATA[@]}" --out /root/whole "${RECIPE[@]}" --steps "$STEPS_2" \
  > "$OUT/whole.json" 2> "$OUT/whole.log"
genome_sums /root/whole > "$OUT/whole.sha256"
SAME=0; DIFFERENT=0
for f in $RECIPE_FILES; do
  a=$(awk -v f="$f" '$2==f{print $1}' "$OUT/continued.sha256"); b=$(awk -v f="$f" '$2==f{print $1}' "$OUT/whole.sha256")
  if [ -n "$a" ] && [ "$a" = "$b" ]; then SAME=$((SAME+1)); echo "same       $f $a"; else DIFFERENT=$((DIFFERENT+1)); echo "DIFFERENT  $f continued=$a whole=$b"; fi
done > "$OUT/compare.txt"
LOSSES=$(python3 -c 'import json,sys;a=json.load(open(sys.argv[1]))["recipe"]["losses"];b=json.load(open(sys.argv[2]))["recipe"]["losses"];print("equal" if a==b else "different", len(a), len(b))' "$MODEL/genome.json" /root/whole/genome.json)
echo "losses $LOSSES" >> "$OUT/compare.txt"
echo "compare: $SAME files the same, $DIFFERENT different; losses $LOSSES" >> "$OUT/steps.txt"
[ "$DIFFERENT" = 0 ] && [ "${LOSSES%% *}" = equal ] || { echo "the continued genome differs from the recipe run in one go"; cat "$OUT/compare.txt"; false; }

step "the services this machine started by itself"
{ for u in vg-sentinel vg-answer vg-train; do echo "$u: $(systemctl is-active "$u" 2>&1 | head -1)"; done
  echo "generations in this machine's outbox: $(find "$OUTBOX_B" -maxdepth 1 -name 'gen-*.seal.json' | wc -l | tr -d ' ')"; } > "$OUT/services.txt"
cat "$OUT/services.txt" >> "$OUT/steps.txt"

echo "WENT ON BY ITSELF: restored generation 1, answered from it, trained to step $STEPS_2 (replay exact, $SAME of $SAME files those of the recipe in one go), sealed generation 2, answered from it" > "$OUT/verdict.txt"
cat "$OUT/verdict.txt" >> "$OUT/steps.txt"
trap - ERR
finish DONE

# The machine goes on, and its outbox keeps travelling, until the authority
# has finished: the end of this script is not the standby's loss.
for _ in $(seq 1 240); do
  gcs_get out/authority/DONE /root/authority-marker 2>/dev/null && break
  gcs_get out/authority/FAILED /root/authority-marker 2>/dev/null && break
  sleep 5
done
