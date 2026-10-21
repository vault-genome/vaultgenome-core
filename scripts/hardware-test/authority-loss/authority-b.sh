#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The authority-loss drill, machine B: a fresh AMD SEV-SNP Confidential VM
# that becomes the authority A was, after A is gone:
#
#   - takes the key material from the operator's safe (the same seeds, the
#     same TLS identities, the same token and registry: the same authority
#     identity — the kids, the signing keys, the certificate — and the same
#     worker identity), and seals every key file to THIS chip
#     (sagvd seal-keys, acp-compute seal-keys);
#   - takes the last replica of A's state — the audit log and the genomes —
#     verifies the audit chain as replicated, and continues it;
#   - re-provisions the escrow key through the recovery ceremony
#     (acpctl escrow recover | sagvd escrow-provision -stdin, ADR 0016),
#     sealed to this chip;
#   - starts both daemons, finds which job A lost, submits it again, and
#     records when the first verdict after the loss was signed — the RTO.
#
# Everything B needs it reads from the bucket: nothing of A survives but
# the replica and the safe.
set -u
exec > >(tee -a /root/b.log) 2>&1
BUCKET=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-bucket")
OUT=/root/out; W=/root/w; mkdir -p "$OUT" "$W" /opt/worker; cd "$W"
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
finish() {
  cp /root/b.log "$OUT/console.log" 2>/dev/null || true
  tar -C "$OUT" -czf /root/out.tgz . 2>/dev/null && gcs_put /root/out.tgz out/b.tgz 2>/dev/null || true
  echo "$1" > /root/marker; gcs_put /root/marker "out/b/$1" 2>/dev/null || true
}
trap 'finish FAILED' ERR

curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-common" > /root/common.sh
. /root/common.sh
set -eE
mark b_script_start

step "inputs"
for b in sagvd acp-compute acpctl keygen; do gcs_get "in/$b" "/usr/local/bin/$b" && chmod +x "/usr/local/bin/$b"; done
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu | head -20; } > "$OUT/system.txt" 2>&1
sagvd version > "$OUT/versions.txt"; acp-compute version >> "$OUT/versions.txt"; acpctl version >> "$OUT/versions.txt"; keygen -version >> "$OUT/versions.txt"
sha256sum /usr/local/bin/sagvd /usr/local/bin/acp-compute /usr/local/bin/acpctl /usr/local/bin/keygen /root/worker.tgz > "$OUT/inputs.sha256"

step "configfs-tsm"
tsm

step "the worker runtime from the locks (a warm standby would have this already)"
mark runtime_start
python_runtime
mark runtime_ready

step "the AMD Milan chain from KDS, verified against the roots acpctl pins (ADR 0024)"
acpctl tee fetch-amd-chain --product milan --out "$W/amd-milan-cert_chain.pem" > "$OUT/amd-chain.txt" 2>&1
mkdir -p "$W/vcek-cache"

step "the operator's safe: the key material A provisioned, the recovery key, the escrow envelope, the base model"
gcs_get safe/secrets.tgz /root/secrets.tgz && tar -C "$W" -xzf /root/secrets.tgz && rm -f /root/secrets.tgz
cp "$W/secrets/sagvd/api_token" "$W/api_token.operator" && chmod 600 "$W/api_token.operator"
gcs_get safe/recovery.seed "$W/recovery.seed"; gcs_get safe/escrow.recovery.json "$W/escrow.recovery.json"
chmod 600 "$W/recovery.seed" "$W/escrow.recovery.json"   # acpctl refuses a recovery key open to other users
gcs_get safe/base.tgz /root/base.tgz && tar -C "$W" -xzf /root/base.tgz && rm -f /root/base.tgz
sha256sum "$W"/secrets/sagvd/* "$W"/secrets/acp-compute/* "$W"/secrets/shared/* 2>/dev/null | sed "s#$W/##" > "$OUT/safe-restored.sha256" || true

step "the replica of A's state: the audit log, the genomes and the job store, as last synced"
gcs_get state/state.tgz /root/state.tgz && tar -C "$W" -xzf /root/state.tgz && rm -f /root/state.tgz
gcs_get state/manifest.json "$OUT/replica-manifest.json"
mark state_restored
mkdir -p "$W/queue"
ls -la "$W/audit" "$W/genomes" "$W/queue" > "$OUT/replica-files.txt" 2>&1
echo "replica manifest: $(head -c 300 "$OUT/replica-manifest.json" 2>/dev/null)" >> "$OUT/steps.txt"

step "identities on this chip: the same seeds, this machine's launch measurement"
identities "$W"

step "the replicated audit chain, verified before anything appends to it"
acpctl audit verify --audit "$W/audit/returnpath-audit.db" --audit-pubkey "$W/audit.pem" --audit-kid sagvd-audit-drill --json > "$OUT/audit-verify-replica.json" 2> "$OUT/audit-verify-replica.err" || true
echo "replica audit verify: $(head -c 300 "$OUT/audit-verify-replica.json" 2>/dev/null)" >> "$OUT/steps.txt"

step "the key files sealed to THIS chip (ADR 0023)"
sagvd seal-keys -config "$W/sagvd.json" > "$OUT/seal-keys-sagvd.json" 2> "$OUT/seal-keys-sagvd.err"; echo "sagvd seal-keys exit=$?" >> "$OUT/steps.txt"
acp-compute seal-keys -config "$W/worker.json" > "$OUT/seal-keys-worker.json" 2> "$OUT/seal-keys-worker.err"; echo "acp-compute seal-keys exit=$?" >> "$OUT/steps.txt"

step "the recovery ceremony: A's escrow key, from the envelope, sealed to this chip (ADR 0016)"
mark ceremony_start
acpctl escrow recover --in "$W/escrow.recovery.json" --key "$W/recovery.seed" 2> "$OUT/escrow-recover.err" \
  | sagvd escrow-provision -config "$W/sagvd.json" -out "$W/escrow.sealed" -pub "$W/escrow.pem" -stdin > "$OUT/escrow-reprovision.json" 2> "$OUT/escrow-reprovision.err"
echo "escrow re-provision exit=$? escrow_key=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["escrow_key"])' "$OUT/escrow-reprovision.json" 2>/dev/null) suite=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("suite"))' "$OUT/escrow-reprovision.json" 2>/dev/null)" >> "$OUT/steps.txt"
cp "$W/escrow.pem" "$OUT/escrow.pem"; rm -f "$W/recovery.seed"
mark ceremony_done

step "sagvd on this chip over the replicated audit log and job store, and its worker"
start_daemons "$W"
mark daemons_ready

step "what sagvd admitted again from the replicated job store at start (ADR 0026)"
echo "resume summary: $(grep -m1 'sagvd jobs from before the restart' "$OUT/sagvd.log" || echo 'not in the log')" >> "$OUT/steps.txt"
RESUMED_ID=$(grep 'sagvd job resumed after a restart' "$OUT/sagvd.log" | head -1 | python3 -c 'import json,sys; l=sys.stdin.readline(); print(json.loads(l).get("job_id", "") if l.strip() else "")' 2>/dev/null || echo "")
RESUMED_REQ=$(grep 'sagvd job resumed after a restart' "$OUT/sagvd.log" | head -1 | python3 -c 'import json,sys; l=sys.stdin.readline(); print(json.loads(l).get("request_id", "") if l.strip() else "")' 2>/dev/null || echo "")
echo "resumed_job_id=${RESUMED_ID:-none} resumed_request_id=${RESUMED_REQ:-none}" >> "$OUT/steps.txt"

step "which job A lost: submitted and never completed"
LOST=$(gcs_list out/a/job- | python3 -c '
import sys, re
sub, done = set(), set()
for line in sys.stdin:
    m = re.search(r"job-(\d+)-(submitted|done)$", line.strip())
    if m: (sub if m.group(2) == "submitted" else done).add(int(m.group(1)))
lost = sorted(sub - done)
print(" ".join(map(str, lost)) if lost else "none")')
echo "lost_jobs=$LOST" >> "$OUT/steps.txt"
# A's own submission record of the lost job, as A put it in the bucket the
# moment the job was accepted: the ids B's resumed job must match.
A_JOB_ID=""; A_REQ_ID=""
for n in $LOST; do
  if gcs_get "out/a/job-$n-submit.json" "$OUT/a-job-$n-submit.json" 2>/dev/null; then
    A_JOB_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("job_id", ""))' "$OUT/a-job-$n-submit.json" 2>/dev/null || echo "")
    A_REQ_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("request_id", ""))' "$OUT/a-job-$n-submit.json" 2>/dev/null || echo "")
    break
  fi
done
echo "a_lost_job_id=${A_JOB_ID:-unknown} a_lost_request_id=${A_REQ_ID:-unknown}" >> "$OUT/steps.txt"

if [ -n "$RESUMED_ID" ]; then
  step "the lost job, resumed by sagvd itself from the replicated job store — the first verdict after the loss"
  if wait_job "$W" "first-after-loss" "$RESUMED_ID"; then mark first_job_done; mark resumed_job_done; echo "first job after the loss: the resumed job succeeded" >> "$OUT/steps.txt"; else mark first_job_done; mark resumed_job_done; echo "first job after the loss: the resumed job did NOT succeed" >> "$OUT/steps.txt"; fi
  echo "resumed job is A's lost job: same_job_id=$([ -n "$A_JOB_ID" ] && [ "$RESUMED_ID" = "$A_JOB_ID" ] && echo true || echo false) same_request_id=$([ -n "$A_REQ_ID" ] && [ "$RESUMED_REQ" = "$A_REQ_ID" ] && echo true || echo false)" >> "$OUT/steps.txt"
else
  step "nothing was resumed: the lost job ($LOST) submitted again here — the first verdict after the loss"
  if gate_job "$W" "first-after-loss"; then mark first_job_done; echo "first job after the loss: resubmitted, succeeded" >> "$OUT/steps.txt"; else mark first_job_done; echo "first job after the loss: resubmitted, NOT succeeded" >> "$OUT/steps.txt"; fi
fi
step "a fresh job after the loss"
gate_job "$W" "second-after-loss" || true

step "metrics; stop both; the whole chain — A's events and B's — verified under the published key"
curl -s http://127.0.0.1:9081/metrics | grep -E "^(sagvd|rp)_" > "$OUT/sagvd-metrics.txt" || true
kill -TERM "$(cat /root/worker.pid)" 2>/dev/null || true; kill -TERM "$(cat /root/sagvd.pid)" 2>/dev/null || true
# The daemons are not this shell's children (start_daemons forks them in a
# subshell), so wait by polling: sagvd holds the audit file's lock until it
# has exited, and acpctl's open times out on a held lock.
n=0; while { kill -0 "$(cat /root/sagvd.pid)" || kill -0 "$(cat /root/worker.pid)"; } 2>/dev/null && [ $n -lt 60 ]; do sleep 1; n=$((n+1)); done
echo "daemons stopped after ${n}s; still running by name: $(pgrep -x sagvd | wc -l) sagvd, $(pgrep -x acp-compute | wc -l) acp-compute" >> "$OUT/steps.txt"
acpctl audit verify --audit "$W/audit/returnpath-audit.db" --audit-pubkey "$W/audit.pem" --audit-kid sagvd-audit-drill --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err" || true
acpctl audit query --audit "$W/audit/returnpath-audit.db" --limit 0 --json > "$OUT/audit-events.jsonl" 2> "$OUT/audit-query.err" || true
echo "final audit verify: $(head -c 300 "$OUT/audit-verify.json")" >> "$OUT/steps.txt"
cp "$W/audit.pem" "$OUT/audit-public-key.pem"
( cd "$OUT" && sha256sum -- * > sha256sums.txt 2>/dev/null ) || true
finish DONE
