#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The authority-loss drill, machine A: the release authority (sagvd) and
# its worker (acp-compute) on one AMD SEV-SNP Confidential VM, both
# attesting with the chip, as in gcp-sev-snp/returnpath-e2e. What A does
# that an operator does before relying on an authority:
#
#   - provisions its key material (acp-keygen -private) and puts a copy in
#     the operator's safe — here an object in the run's private bucket,
#     standing in for a secrets manager or an HSM-backed store — BEFORE the
#     daemons seal every key file to this chip (sagvd seal-keys,
#     acp-compute seal-keys, ADR 0023);
#   - makes its escrow key inside sagvd, sealed to this chip, and wraps it
#     to the operator's recovery key (sagvd escrow-provision, ADR 0016); the
#     envelope and the recovery key go to the safe (in production the
#     recovery key lives off every release host);
#   - fine-tunes a tiny model, seals it as gen-0, and runs gate jobs over
#     the Return Path in a loop, replicating its state — the audit log and
#     the genomes — to the bucket after every job, and marking every job's
#     submission and completion, so the runner can take the machine away in
#     the middle of one and so machine B can continue from the replica.
#
# The runner deletes this VM without warning. Everything A had written to
# out/ by then is what the record holds.
set -u
exec > >(tee -a /root/a.log) 2>&1
BUCKET=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-bucket")
OUT=/root/out; W=/root/w; mkdir -p "$OUT" "$W" /opt/worker; cd "$W"
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
push_out() { cp /root/a.log "$OUT/console.log" 2>/dev/null || true; tar -C "$OUT" -czf /root/out.tgz . 2>/dev/null && gcs_put /root/out.tgz out/a.tgz 2>/dev/null || true; }
finish() { push_out; echo "$1" > /root/marker; gcs_put /root/marker "out/a/$1" 2>/dev/null || true; }
trap 'finish FAILED' ERR

curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-common" > /root/common.sh
. /root/common.sh
set -eE
mark a_script_start

step "inputs"
for b in sagvd acp-compute acpctl keygen; do gcs_get "in/$b" "/usr/local/bin/$b" && chmod +x "/usr/local/bin/$b"; done
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu | head -20; } > "$OUT/system.txt" 2>&1
sagvd version > "$OUT/versions.txt"; acp-compute version >> "$OUT/versions.txt"; acpctl version >> "$OUT/versions.txt"; keygen -version >> "$OUT/versions.txt"
sha256sum /usr/local/bin/sagvd /usr/local/bin/acp-compute /usr/local/bin/acpctl /usr/local/bin/keygen /root/worker.tgz > "$OUT/inputs.sha256"

step "configfs-tsm"
tsm

step "the worker runtime from the locks"
mark runtime_start
python_runtime
mark runtime_ready

step "the AMD Milan chain from KDS, verified against the roots acpctl pins (ADR 0024)"
acpctl tee fetch-amd-chain --product milan --out "$W/amd-milan-cert_chain.pem" > "$OUT/amd-chain.txt" 2>&1
mkdir -p "$W/genomes" "$W/audit" "$W/vcek-cache"

step "provision (acp-keygen -private); the operator's safe keeps the plaintext key material before it is sealed to this chip"
keygen -out "$W/secrets" -quiet -private
tar -C "$W" -czf /root/secrets.tgz secrets && gcs_put /root/secrets.tgz safe/secrets.tgz && rm -f /root/secrets.tgz
# The operator's copy of the API token: seal-keys seals the daemon's file
# below; the operator submits jobs with this one.
cp "$W/secrets/sagvd/api_token" "$W/api_token.operator" && chmod 600 "$W/api_token.operator"
acpctl escrow recovery-keygen --out "$W/recovery.seed" --pub "$W/recovery.pem" > "$OUT/recovery-keygen.txt"
gcs_put "$W/recovery.seed" safe/recovery.seed; gcs_put "$W/recovery.pem" safe/recovery.pem

step "identities: each daemon reads its launch measurement from the chip"
identities "$W"

step "a real fine-tune: tiny base model built here, LoRA adapter trained by vg_genome, sealed by acpctl as gen-0; the base goes to the safe (the genome names its digest)"
export PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false
( cd /opt/worker && /opt/vg/bin/python -c 'import sys, json; sys.path.insert(0, "tests"); import conftest
conftest.make_base(sys.argv[1])
open(sys.argv[2], "w").write("".join(json.dumps(e) + "\n" for e in conftest.EXAMPLES))' "$W/base" "$W/train.jsonl" )
/opt/vg/bin/python -m vg_genome finetune --base "$W/base" --base-name tiny-llama --data "$W/train.jsonl" --out "$W/genome" \
  --targets q_proj,v_proj,lm_head --steps 20 --lr 1e-2 --max-len 32 --threads 2 --top-k 8 --new-tokens 4 > "$OUT/finetune.json" 2> "$OUT/finetune.err"
echo "finetune exit=$?" >> "$OUT/steps.txt"
acpctl genome seal --content-dir "$W/genome" --output "$W/genomes/gen-0.genome" --key-out "$W/genomes/gen-0.key" --json > "$OUT/seal.json" 2> "$OUT/seal.err"
echo "seal exit=$? key_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_id"])' "$OUT/seal.json")" >> "$OUT/steps.txt"
tar -C "$W" -czf /root/base.tgz base && gcs_put /root/base.tgz safe/base.tgz && rm -f /root/base.tgz

step "the key files sealed to this chip (ADR 0023)"
sagvd seal-keys -config "$W/sagvd.json" > "$OUT/seal-keys-sagvd.json" 2> "$OUT/seal-keys-sagvd.err"; echo "sagvd seal-keys exit=$?" >> "$OUT/steps.txt"
acp-compute seal-keys -config "$W/worker.json" > "$OUT/seal-keys-worker.json" 2> "$OUT/seal-keys-worker.err"; echo "acp-compute seal-keys exit=$?" >> "$OUT/steps.txt"

step "the escrow key made inside sagvd, sealed to this chip, wrapped to the operator's recovery key (ADR 0016); the envelope to the safe"
sagvd escrow-provision -config "$W/sagvd.json" -out "$W/escrow.sealed" -pub "$W/escrow.pem" -recovery-to "$W/recovery.pem" -recovery-out "$W/escrow.recovery.json" > "$OUT/escrow-provision.json" 2> "$OUT/escrow-provision.err"
echo "escrow-provision exit=$? tee=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("tee"))' "$OUT/escrow-provision.json")" >> "$OUT/steps.txt"
gcs_put "$W/escrow.recovery.json" safe/escrow.recovery.json; cp "$W/escrow.pem" "$OUT/escrow.pem"
rm -f "$W/recovery.seed"

step "sagvd and its worker on this chip"
start_daemons "$W"
mark daemons_ready

# sync_state <n>: the authority's state to the bucket — the audit log and
# the genomes — as one tar, after job n, with the job's tip in a manifest.
sync_state() {
  tar -C "$W" -czf /root/state.tgz audit genomes 2>/dev/null
  gcs_put /root/state.tgz state/state.tgz
  python3 - "$1" "$OUT/job-$1.json" > /root/state-manifest.json <<'PY'
import json, sys, time
try:
    j = json.load(open(sys.argv[2]))
except Exception:
    j = {}
flow = j.get("flow") or {}
print(json.dumps({"after_job": int(sys.argv[1]), "job_id": j.get("job_id"), "status": j.get("status"),
                  "chain_tip": flow.get("chain_tip") or flow.get("audit_tip"), "synced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
PY
  gcs_put /root/state-manifest.json state/manifest.json
  cp /root/state-manifest.json "$OUT/state-manifest-$1.json"
}

step "gate jobs in a loop; the state replicated after each; the runner takes the machine away in the middle of one"
for n in $(seq 1 120); do
  gcs_put_str "out/a/job-$n-submitted" "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  mark "job_${n}_submit"
  if gate_job "$W" "$n"; then :; else echo "job $n did not succeed" >> "$OUT/steps.txt"; fi
  mark "job_${n}_done"
  sync_state "$n"
  gcs_put_str "out/a/job-$n-done" "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  push_out
  [ "$n" -eq 3 ] && gcs_put_str out/a/READY "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  sleep 2
done
finish DONE
