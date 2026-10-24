#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The authority's host of the two-host provisioning drill (ADR 0028), as
# the startup script of a GCP SEV-SNP guest. Steps 1 and 3 of the three
# commands run here; the run's private bucket (metadata vg-bucket) is the
# hand-off: the worker's bundle and the base model go out, the worker's
# identity comes back, the results go out at the end (out/authority.tgz,
# then out/DONE; out/FAILED when a step that nothing can follow fails).
#
#   1. `acpctl provision authority`: keygen, sagvd.json for an
#      azure-sev-snp worker (the worker's product's AMD chain for sagvd's
#      verifier, this chip's product's chain in the bundle for the
#      worker's), sagvd's identity from the chip, its key files sealed,
#      the bundle written — and removed from this host once handed off.
#   2. A fine-tune: the tiny base model built here (shipped to the worker,
#      which restores onto the same bytes), the LoRA adapter trained,
#      sealed into the genome directory provision made.
#   3. The worker's identity from the bucket, `acpctl provision
#      pin-worker`, sagvd on what provision wrote, the worker's session
#      over the Internet, the gate job, the audit log verified under the
#      key provision kept for the operator.
#
# Keys, seeds and the token stay on the VM and die with it; the bundle
# leaves it once, through the bucket, and is deleted here.
set -u
exec > >(tee -a /root/authority.log) 2>&1
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }
gtoken() { md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'; }
urlenc() { python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
gcs_get() { curl -sSf -H "Authorization: Bearer $(gtoken)" -o "$2" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$(urlenc "$1")?alt=media"; }
gcs_put() { curl -sSf -X POST -H "Authorization: Bearer $(gtoken)" -H "Content-Type: application/octet-stream" --data-binary "@$1" "https://storage.googleapis.com/upload/storage/v1/b/$BUCKET/o?uploadType=media&name=$(urlenc "$2")" > /dev/null; }
gcs_exists() { curl -sf -H "Authorization: Bearer $(gtoken)" -o /dev/null "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$(urlenc "$1")"; }
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=/root/p2; OUT=$WORK/out; DEPLOY=/root/deploy; mkdir -p "$OUT"; cd "$WORK"
BUCKET=$(md attributes/vg-bucket)
WORKER_PRODUCT=$(md attributes/vg-worker-product 2>/dev/null || true); [ -n "$WORKER_PRODUCT" ] || WORKER_PRODUCT=genoa
OWN_PRODUCT=$(md attributes/vg-authority-product 2>/dev/null || true); [ -n "$OWN_PRODUCT" ] || OWN_PRODUCT=milan
EXT_IP=$(md network-interfaces/0/access-configs/0/external-ip)
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; echo "external_ip=$EXT_IP"; echo "worker_ip=$(md attributes/vg-worker-ip 2>/dev/null)"; echo "captured=$STAMP"; } > "$OUT/metadata.txt"
uname -a > "$OUT/kernel.txt"
T0=$(date +%s.%N)
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }
emit() { # emit <DONE|FAILED>: the results to the bucket, then the marker
  cp /root/authority.log "$OUT/console.log" 2>/dev/null
  ( cd "$OUT" && sha256sum * > "$WORK/sha256sums.txt" 2>/dev/null ); mv "$WORK/sha256sums.txt" "$OUT/" 2>/dev/null
  ( cd "$WORK" && tar czf authority.tgz -C "$OUT" . ) && gcs_put "$WORK/authority.tgz" out/authority.tgz
  echo "$1" > "$WORK/marker" && gcs_put "$WORK/marker" "out/$1"
  echo "AUTHORITY $1 $STAMP"
}
fail() { step "FAILED: $*"; emit FAILED; exit 1; }

step "binaries from gs://$BUCKET/in"
for f in sagvd acp-compute acpctl keygen genome-worker.tgz; do gcs_get "in/$f" "$WORK/$f" || fail "fetch $f"; done
chmod +x sagvd acp-compute acpctl keygen
./sagvd version > "$OUT/versions.txt"; ./acp-compute version >> "$OUT/versions.txt"; ./acpctl version >> "$OUT/versions.txt" 2>/dev/null || true
sha256sum sagvd acp-compute acpctl keygen genome-worker.tgz > "$OUT/inputs.sha256"
mkdir -p workers && tar xzf genome-worker.tgz -C workers

step "configfs-tsm"
modprobe sev-guest 2>/dev/null || {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
  modprobe sev-guest 2>/dev/null || true
}
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail -20; } > "$OUT/tsm.txt"

step "the worker runtime here too: the fine-tune that makes the genome needs it"
mark runtime_install_start
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1
python3 -m venv venv && . venv/bin/activate
pip install --require-hashes --only-binary=:all: --index-url https://pypi.org/simple -r workers/genome/requirements-ci.lock > "$OUT/pip-requirements.log" 2>&1
pip install --require-hashes --only-binary=:all: --no-deps --index-url https://download.pytorch.org/whl/cpu -r workers/genome/requirements-torch-cpu.lock > "$OUT/pip-torch.log" 2>&1
python3 -c 'import torch, transformers, safetensors; print("torch", torch.__version__, "transformers", transformers.__version__, "safetensors", safetensors.__version__)' > "$OUT/runtime.txt" 2>&1
mark runtime_install_end

step "step 1: acpctl provision authority — keygen, sagvd for an azure-sev-snp worker ($WORKER_PRODUCT chain), this chip's $OWN_PRODUCT chain for the worker, identity, sealed keys, the bundle"
mark provision_authority_start
./acpctl provision authority --out "$DEPLOY" --bin-dir "$WORK" --provider auto --worker-provider azure-sev-snp \
  --fetch-amd-chain "$WORKER_PRODUCT" --fetch-own-amd-chain "$OWN_PRODUCT" \
  --vault-listen 0.0.0.0:9443 --vault-address "$EXT_IP:9443" --vault-server-name localhost \
  --vault-descriptor sagvd-two-hosts-v1 --worker-descriptor acp-compute-two-hosts-v1 > "$OUT/provision-authority.out" 2> "$OUT/provision-authority.err"
RC=$?; echo "provision authority exit=$RC" >> "$OUT/steps.txt"
mark provision_authority_end
cp "$DEPLOY/provision.json" "$OUT/provision-authority.json" 2>/dev/null || true
cp "$DEPLOY/sagvd-identity.json" "$DEPLOY/sagvd.json" "$OUT/" 2>/dev/null || true
cp "$DEPLOY/operator/audit_public_key.pem" "$OUT/audit-public-key.pem" 2>/dev/null || true
[ "$RC" = 0 ] || fail "provision authority: $(tail -3 "$OUT/provision-authority.err")"
# The bundle's manifest (names and hashes, no bytes) and its listing are the record of what crossed.
tar xOf "$DEPLOY/worker-bundle.tar" bundle.json > "$OUT/bundle-manifest.json" 2>/dev/null
tar tvf "$DEPLOY/worker-bundle.tar" > "$OUT/bundle-listing.txt" 2>/dev/null
sha256sum "$DEPLOY/worker-bundle.tar" | cut -d' ' -f1 > "$OUT/bundle.sha256"
python3 - "$OUT/provision-authority.json" >> "$OUT/steps.txt" 2>&1 <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("provider=%s worker=%s sealer=%s phase=%s" % (d["provider"], d["peer_provider"], d["sealer"], d["phase"]))
print("vault_measurement=%s vault_sealer=%s" % (d["vault"]["measurement_hex"], d["vault"].get("sealer")))
print("sealed_sagvd=%s" % ",".join(d.get("sealed", {}).get("sagvd", [])))
print("amd_cert_chain=%s bundle_sha256=%s" % (d.get("amd_cert_chain"), d.get("worker_bundle_sha256")))
PY
ls "$DEPLOY/secrets" > "$OUT/secrets-dirs-after-step1.txt" 2>&1
[ -e "$DEPLOY/secrets/acp-compute" ] && echo "worker secrets still on the authority host" >> "$OUT/steps.txt"

step "the genome: tiny base model built here, LoRA adapter trained by vg_genome, sealed into $DEPLOY/genomes"
mark finetune_start
export PYTHONPATH=$WORK/workers/genome TOKENIZERS_PARALLELISM=false
( cd workers/genome && python3 -c 'import sys, json; sys.path.insert(0, "tests"); import conftest
conftest.make_base(sys.argv[1])
open(sys.argv[2], "w").write("".join(json.dumps(e) + "\n" for e in conftest.EXAMPLES))' "$WORK/base" "$WORK/train.jsonl" )
python3 -m vg_genome finetune --base base --base-name tiny-llama --data train.jsonl --out genome \
  --targets q_proj,v_proj,lm_head --steps 20 --lr 1e-2 --max-len 32 --threads 2 --top-k 8 --new-tokens 4 > "$OUT/finetune.json" 2> "$OUT/finetune.err"
echo "finetune exit=$?" >> "$OUT/steps.txt"
mark finetune_end
./acpctl genome seal --content-dir genome --output "$DEPLOY/genomes/gen-0.genome" --key-out "$DEPLOY/genomes/gen-0.key" --json > "$OUT/seal.json" 2> "$OUT/seal.err"
echo "seal exit=$?" >> "$OUT/steps.txt"
KID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_id"])' "$OUT/seal.json" 2>/dev/null); echo "key_id=$KID" >> "$OUT/steps.txt"
( cd "$WORK" && tar czf base.tgz base ); sha256sum base.tgz | cut -d' ' -f1 > "$OUT/base.sha256"

step "hand-off: the bundle, the base model and provision.json to the bucket; the bundle removed from this host"
gcs_put "$DEPLOY/worker-bundle.tar" handoff/worker-bundle.tar || fail "upload the bundle"
gcs_put "$WORK/base.tgz" handoff/base.tgz || fail "upload the base model"
gcs_put "$DEPLOY/provision.json" handoff/authority-provision.json || fail "upload provision.json"
rm -f "$DEPLOY/worker-bundle.tar"; echo "bundle removed from the authority host after hand-off" >> "$OUT/steps.txt"
mark bundle_handed_off

step "wait for the worker's identity (the orchestrator carries it back through the bucket)"
for i in $(seq 1 240); do gcs_exists handoff/acp-compute-identity.json && break; sleep 10; done
gcs_get handoff/acp-compute-identity.json /root/acp-compute-identity.json || fail "no worker identity after 40 minutes"
cp /root/acp-compute-identity.json "$OUT/acp-compute-identity.json"
mark identity_received

step "step 3: acpctl provision pin-worker — the worker's measurement from its own chip, and its boot from its vTPM, pinned"
./acpctl provision pin-worker --out "$DEPLOY" --identity /root/acp-compute-identity.json > "$OUT/provision-pin-worker.out" 2> "$OUT/provision-pin-worker.err"
RC=$?; echo "provision pin-worker exit=$RC" >> "$OUT/steps.txt"
cp "$DEPLOY/provision.json" "$OUT/provision-complete.json" 2>/dev/null || true
[ "$RC" = 0 ] || fail "pin-worker: $(tail -3 "$OUT/provision-pin-worker.err")"
python3 - "$OUT/provision-complete.json" "$DEPLOY/sagvd.json" >> "$OUT/steps.txt" 2>&1 <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("phase=%s worker_measurement=%s worker_provider=%s worker_sealer=%s" % (d["phase"], d["worker"]["measurement_hex"], d["worker"].get("provider"), d["worker"].get("sealer")))
# An azure-sev-snp worker is pinned to its boot as well (ADR 0037): what
# sagvd.json now names, beside what the worker's identity printed.
peer = json.load(open(sys.argv[2]))["tee"]["peer"]
print("worker_boot=%s sagvd_pcr_digests=%s" % (d["worker"].get("vtpm_pcr_digest_hex"), ",".join(peer.get("pcr_digests") or [])))
PY
mark pinned

step "sagvd on what provision wrote, listening on 0.0.0.0:9443 for the worker across the Internet"
./sagvd -config "$DEPLOY/sagvd.json" > "$OUT/sagvd.log" 2>&1 &
SAGVD=$!
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
echo "sagvd ready after ${n}s" >> "$OUT/steps.txt"
mark sagvd_ready
n=0; until grep -q "sagvd session opened" "$OUT/sagvd.log" || [ $n -ge 900 ]; do sleep 1; n=$((n+1)); done
echo "session opened after ${n}s" >> "$OUT/steps.txt"
mark session_opened
grep -m1 '"msg":"sagvd session opened"' "$OUT/sagvd.log" > "$OUT/session-opened.json" || true

step "the gate job over the Return Path, to the worker on the other cloud"
TOKEN=$(cat "$DEPLOY/operator/api_token")
mark job_submit
curl -s -o "$OUT/job-submit.json" -w '%{http_code}\n' -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"genome":{"bundle":"gen-0.genome","key_file":"gen-0.key"},"deadline_seconds_from_now":300}' http://127.0.0.1:9080/v1/jobs > "$OUT/job-submit.status"
JOB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["job_id"])' "$OUT/job-submit.json" 2>/dev/null)
echo "job_id=$JOB" >> "$OUT/steps.txt"
ST=""
for i in $(seq 1 300); do
  sleep 1
  curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9080/v1/jobs/$JOB" > "$OUT/job.json"
  ST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$OUT/job.json" 2>/dev/null)
  [ "$ST" = succeeded ] || [ "$ST" = failed ] && break
done
mark job_done
echo "job status=$ST after ${i}s" >> "$OUT/steps.txt"
python3 - "$OUT/job.json" "$OUT/steps.txt" <<'PY'
import json, sys
j = json.load(open(sys.argv[1])); g = j.get("gate") or {}; v = (g.get("signed_verdict") or {}).get("verdict") or {}
f = j.get("flow") or {}; a = f.get("attestation") or {}
with open(sys.argv[2], "a") as out:
    out.write("gate_level=%s door=%s rung=%s fixtures=%s n_exact=%s max_abs_err=%s signer=%s\n" % (
        g.get("level"), g.get("door"), g.get("rung"), g.get("fixtures"), v.get("n_exact"), v.get("max_abs_err"), g.get("signer_key_id")))
    out.write("attestation_outcome=%s peer_provider=%s\n" % (a.get("outcome"), a.get("peer_provider") or a.get("provider")))
PY
unset TOKEN

step "metrics; stop sagvd; verify the audit log with the key provision kept for the operator"
curl -s http://127.0.0.1:9081/metrics | grep -E "^(sagvd|rp|vg_tee)_" > "$OUT/sagvd-metrics.txt"
kill -TERM $SAGVD; wait $SAGVD 2>/dev/null
./acpctl audit verify --audit "$DEPLOY/audit/returnpath-audit.db" --audit-pubkey "$DEPLOY/operator/audit_public_key.pem" --audit-kid sagvd-audit-demo --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"
echo "audit verify exit=$?" >> "$OUT/steps.txt"
./acpctl audit query --audit "$DEPLOY/audit/returnpath-audit.db" --limit 0 --json > "$OUT/audit-events.jsonl" 2> "$OUT/audit-query.err"
echo "audit query exit=$?" >> "$OUT/steps.txt"
grep -o '"handshake_ms":[0-9]*' "$OUT/sagvd.log" | cut -d: -f2 > "$OUT/sagvd.handshake_ms.txt"
python3 -c 'import sys,time; t0=float(sys.argv[1]); print("elapsed_seconds=%.1f" % (time.time()-t0))' "$T0" >> "$OUT/steps.txt"
emit DONE
