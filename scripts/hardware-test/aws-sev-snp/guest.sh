#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# On an EC2 instance with AMD SEV-SNP (Ubuntu 24.04): a deployment stood
# up by one command and proven the way provision-e2e proves one on Compute
# Engine, with what is EC2's own on the record (ADR 0038).
#
# `acpctl provision --provider auto` asks the host: configfs-tsm says
# sev_guest, the machine's DMI vendor says Amazon EC2, so the family is
# aws-sev-snp. It runs acp-keygen, writes both daemons' configurations,
# fetches the Milan VLEK chain (ASVK and ARK) from AMD KDS and verifies it
# against the pinned roots, reads each daemon's identity from the chip —
# the launch measurement, and the VLEK the host shows beside the report —
# pins it on the other side, and seals every key file with the firmware's
# derived key. Then both daemons start on what it wrote, the real
# vg_genome worker fine-tunes a genome here, acpctl seals it, a gate job
# goes over the Return Path — the worker's report signed by the VLEK,
# admitted by sagvd's aws-sev-snp verifier — comes back EXACT, and the
# audit log verifies under the key provision kept.
#
# Inputs: /home/ubuntu/e2e/{sagvd,acp-compute,acpctl,keygen,genome-worker.tgz}
# (scp'd by run.sh). Output: /home/ubuntu/e2e/results.tgz, the results
# directory (provision.json, the identities, the configurations — paths,
# no secret — the sealed files' shapes, the job view, the logs, the
# verified audit log, the report and VLEK snpguest-free from configfs-tsm).
# Keys, seeds and the token stay on the instance and die with it.
set -u
exec > >(tee -a /root/e2e.log) 2>&1
IN=/home/ubuntu/e2e
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=/root/e2e; OUT=$WORK/out/$STAMP; DEPLOY=/root/deploy; mkdir -p "$OUT"; cd "$WORK" || exit 1
T0=$(date +%s.%N)
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }

step "the host as the guest sees it"
TOKEN_IMDS=$(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 120')
imds() { curl -s -H "X-aws-ec2-metadata-token: $TOKEN_IMDS" "http://169.254.169.254/latest/meta-data/$1"; }
{ echo "instance_type=$(imds instance-type)"; echo "zone=$(imds placement/availability-zone)"; echo "region=$(imds placement/region)"; echo "ami=$(imds ami-id)"; echo "captured=$STAMP"; } > "$OUT/metadata.txt"
unset TOKEN_IMDS
for f in sys_vendor product_name bios_vendor bios_version; do printf '%s=%s\n' "$f" "$(cat /sys/class/dmi/id/$f 2>/dev/null)"; done > "$OUT/dmi.txt"
uname -a > "$OUT/kernel.txt"; nproc > "$OUT/nproc.txt"

step "binaries from $IN"
for f in sagvd acp-compute acpctl keygen genome-worker.tgz; do cp "$IN/$f" "$WORK/$f" || echo "missing $f"; done
chmod +x sagvd acp-compute acpctl keygen
./sagvd version > "$OUT/versions.txt"; ./acp-compute version >> "$OUT/versions.txt"; ./acpctl version >> "$OUT/versions.txt" 2>/dev/null || true
./keygen -version >> "$OUT/versions.txt" 2>/dev/null || true
sha256sum sagvd acp-compute acpctl keygen genome-worker.tgz > "$OUT/inputs.sha256"
mkdir -p workers && tar xzf genome-worker.tgz -C workers

step "configfs-tsm: the report and the certificate table the host shows beside it"
modprobe sev-guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report /dev/sev-guest 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail -20; } > "$OUT/tsm.txt"
d=/sys/kernel/config/tsm/report/vg-kit; mkdir -p "$d"
head -c 64 /dev/urandom > "$OUT/probe-nonce.bin"; cp "$OUT/probe-nonce.bin" "$d/inblob"
cat "$d/outblob" > "$OUT/probe-report.bin" 2>/dev/null; cat "$d/auxblob" > "$OUT/probe-certs.bin" 2>/dev/null
printf 'provider=%s\n' "$(cat $d/provider 2>/dev/null)" > "$OUT/probe-attrs.txt"; rmdir "$d"
python3 - "$OUT/probe-report.bin" >> "$OUT/steps.txt" <<'PY'
import sys
r = open(sys.argv[1], "rb").read()
fl = int.from_bytes(r[0x48:0x4C], "little")
print("probe: report version=%d signing_key=%d chip_id_zero=%s measurement=%s" % (int.from_bytes(r[0:4], "little"), (fl >> 2) & 7, r[0x1A0:0x1E0] == bytes(64), r[0x90:0xC0].hex()))
PY

step "the worker runtime: python, the pinned CPU torch (the door needs it)"
mark runtime_install_start
export DEBIAN_FRONTEND=noninteractive
n=0; while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && [ $n -lt 120 ]; do sleep 2; n=$((n+1)); done
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1
python3 -m venv venv && . venv/bin/activate
pip install --require-hashes --only-binary=:all: --index-url https://pypi.org/simple -r workers/genome/requirements-ci.lock > "$OUT/pip-requirements.log" 2>&1
pip install --require-hashes --only-binary=:all: --no-deps --index-url https://download.pytorch.org/whl/cpu -r workers/genome/requirements-torch-cpu.lock > "$OUT/pip-torch.log" 2>&1
python3 -c 'import torch, transformers, safetensors; print("torch", torch.__version__, "transformers", transformers.__version__, "safetensors", safetensors.__version__)' > "$OUT/runtime.txt" 2>&1
mark runtime_install_end

step "acpctl provision: one command — keygen, the configurations, the VLEK chain, the identities and pins, the key files sealed with the derived key"
mark provision_start
./acpctl provision --out "$DEPLOY" --bin-dir "$WORK" --provider auto --fetch-amd-chain milan \
  --door-python "$WORK/venv/bin/python3" --base-model "$WORK/base" --worker-package "$WORK/workers/genome" \
  --vault-descriptor sagvd-aws-sev-snp-e2e-v1 --worker-descriptor acp-compute-aws-sev-snp-e2e-v1 > "$OUT/provision.out" 2> "$OUT/provision.err"
echo "provision exit=$?" >> "$OUT/steps.txt"
mark provision_end
cp "$DEPLOY/provision.json" "$OUT/provision.json" 2>/dev/null || true
cp "$DEPLOY/sagvd-identity.json" "$DEPLOY/acp-compute-identity.json" "$OUT/" 2>/dev/null || true
cp "$DEPLOY/sagvd.json" "$DEPLOY/acp-compute.json" "$OUT/" 2>/dev/null || true
cp "$DEPLOY/operator/audit_public_key.pem" "$OUT/audit-public-key.pem" 2>/dev/null || true
cp "$DEPLOY"/amd-*-cert_chain.pem "$OUT/" 2>/dev/null || true
python3 - "$DEPLOY" "$OUT/provision.json" >> "$OUT/steps.txt" 2>&1 <<'PY'
import json, sys
d = json.load(open(sys.argv[2]))
print("provider=%s peer=%s sealer=%s" % (d["provider"], d["peer_provider"], d["sealer"]))
print("vault_measurement=%s" % d["vault"]["measurement_hex"]); print("worker_measurement=%s" % d["worker"]["measurement_hex"])
print("vault_sealer=%s worker_sealer=%s" % (d["vault"].get("sealer"), d["worker"].get("sealer")))
print("vault_vlek_csp_id=%s worker_vlek_csp_id=%s" % (d["vault"].get("vlek_csp_id"), d["worker"].get("vlek_csp_id")))
print("sealed_sagvd=%s" % ",".join(d.get("sealed", {}).get("sagvd", []))); print("sealed_worker=%s" % ",".join(d.get("sealed", {}).get("acp-compute", [])))
print("amd_cert_chain=%s" % d.get("amd_cert_chain"))
PY
python3 - "$DEPLOY/secrets" > "$OUT/sealed-files.txt" 2>&1 <<'SHAPE'
import json, os, sys
S = sys.argv[1]
for p in ("sagvd/authority_signing_seed", "sagvd/audit_signing_seed", "sagvd/api_token", "sagvd/tls/server.key", "shared/sealing.key", "acp-compute/sealing.key", "acp-compute/worker_signing_seed", "acp-compute/tls/client.key"):
    try:
        d = json.load(open(os.path.join(S, p)))
        print(p, {"schema": d.get("schema"), "tee": d.get("tee"), "sealer": d.get("sealer"), "name": d.get("name"), "sealed_bytes": len(d.get("sealed", ""))})
    except Exception as e:
        print(p, "not a sealed file:", type(e).__name__)
SHAPE

step "a real fine-tune: tiny base model built here, LoRA adapter trained by vg_genome, sealed by acpctl"
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

step "sagvd on what provision wrote"
mark services_start
./sagvd -config "$DEPLOY/sagvd.json" > "$OUT/sagvd.log" 2>&1 &
SAGVD=$!
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
echo "sagvd ready after ${n}s" >> "$OUT/steps.txt"

step "acp-compute on what provision wrote, the real door"
./acp-compute -config "$DEPLOY/acp-compute.json" > "$OUT/acp-compute.log" 2>&1 &
WORKER=$!
n=0; until curl -sf http://127.0.0.1:9082/healthz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
n=0; until grep -q "sagvd session opened" "$OUT/sagvd.log" || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
echo "session opened after ${n}s" >> "$OUT/steps.txt"
mark session_opened

step "the gate job over the Return Path"
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
with open(sys.argv[2], "a") as f:
    f.write("gate_level=%s door=%s rung=%s fixtures=%s n_exact=%s max_abs_err=%s signer=%s\n" % (
        g.get("level"), g.get("door"), g.get("rung"), g.get("fixtures"), v.get("n_exact"), v.get("max_abs_err"), g.get("signer_key_id")))
PY
unset TOKEN

step "metrics"
curl -s http://127.0.0.1:9081/metrics | grep -E "^(sagvd|rp|vg_tee)_" > "$OUT/sagvd-metrics.txt"
curl -s http://127.0.0.1:9082/metrics | grep -E "^(acp_compute|rp|vg_tee)_" > "$OUT/acp-compute-metrics.txt"

step "stop both; verify the audit log with the key provision kept for the operator"
kill -TERM $WORKER; wait $WORKER 2>/dev/null
kill -TERM $SAGVD; wait $SAGVD 2>/dev/null
./acpctl audit verify --audit "$DEPLOY/audit/returnpath-audit.db" --audit-pubkey "$DEPLOY/operator/audit_public_key.pem" --audit-kid sagvd-audit-demo --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"
echo "audit verify exit=$?" >> "$OUT/steps.txt"
./acpctl audit query --audit "$DEPLOY/audit/returnpath-audit.db" --limit 0 --json > "$OUT/audit-events.jsonl" 2> "$OUT/audit-query.err"
echo "audit query exit=$?" >> "$OUT/steps.txt"
# What the vault's verifier read of the worker's hardware (the TRUST_EVALUATED record): the signer, the VLEK, the chip.
python3 - "$OUT/audit-events.jsonl" > "$OUT/chip.txt" 2>>"$OUT/steps.txt" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e.get("kind") != "TRUST_EVALUATED": continue
    s = ((e.get("payload") or {}).get("peer_detail") or {}).get("sev_snp") or {}
    if not s: continue
    t = s["tcb"]["reported"]; v = s.get("vlek") or {}
    print("peer chip product=%s signing_key=%s report_id=%s snp=%#x microcode=%#x firmware=%s alias_check=%s mit_vector=%s floor_snp=%#x floor_microcode=%#x vlek_csp_id=%s vlek_not_after=%s chip_id_hex=%s" % (
        s["product"], s.get("signing_key"), s.get("report_id_hex"), t["snp"], t["microcode"], s["firmware"]["current"],
        str(s["platform_info"]["alias_check_complete"]).lower(), s["mitigation_vector"]["current_hex"], s["floor"]["snp"], s["floor"]["microcode"],
        v.get("csp_id"), v.get("not_after"), s.get("chip_id_hex")))
    break
PY
cat "$OUT/chip.txt" >> "$OUT/steps.txt"
python3 -c 'import sys,time; t0=float(sys.argv[1]); print("elapsed_seconds=%.1f" % (time.time()-t0))' "$T0" >> "$OUT/steps.txt"
mark finished

cp /root/e2e.log "$OUT/console.log"
( cd "$OUT" && sha256sum * > "$WORK/sha256sums.txt" ); mv "$WORK/sha256sums.txt" "$OUT/"
( cd "$WORK/out" && tar czf "$IN/results.tgz" "$STAMP" ) && chown ubuntu:ubuntu "$IN/results.tgz"
echo "E2E DONE $STAMP sha256=$(sha256sum "$IN/results.tgz" | cut -d' ' -f1)"
