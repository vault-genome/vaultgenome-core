#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# On an EC2 instance with AMD SEV-SNP (Ubuntu 24.04): a deployment with the
# console's listener on (ADR 0039), left running for the person's console to
# reach. `acpctl provision --console-listen` writes the configurations, a real
# fine-tune is sealed, both daemons run as services, and one gate job through
# the REST API shows the deployment is what aws-sev-snp's kit proved before a
# console touches it. Keys, seeds and the token stay on the instance and die
# with it.
#
# Inputs: /home/ubuntu/e2e/{sagvd,acp-compute,acpctl,keygen,genome-worker.tgz}.
# Output: /home/ubuntu/e2e/results.tgz, and the daemons running.
set -u
exec > >(tee -a /root/e2e.log) 2>&1
IN=/home/ubuntu/e2e
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=/root/e2e; OUT=$WORK/out/$STAMP; DEPLOY=/root/deploy; mkdir -p "$OUT"; cd "$WORK" || exit 1
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }

step "the host as the guest sees it"
TOKEN_IMDS=$(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 120')
imds() { curl -s -H "X-aws-ec2-metadata-token: $TOKEN_IMDS" "http://169.254.169.254/latest/meta-data/$1"; }
{ echo "instance_type=$(imds instance-type)"; echo "zone=$(imds placement/availability-zone)"; echo "region=$(imds placement/region)"; echo "captured=$STAMP"; } > "$OUT/metadata.txt"
PUBLIC_IP=$(imds public-ipv4)
unset TOKEN_IMDS
for f in sys_vendor product_name bios_vendor bios_version; do printf '%s=%s\n' "$f" "$(cat /sys/class/dmi/id/$f 2>/dev/null)"; done > "$OUT/dmi.txt"
uname -a > "$OUT/kernel.txt"; nproc > "$OUT/nproc.txt"

step "binaries from $IN"
for f in sagvd acp-compute acpctl keygen genome-worker.tgz; do cp "$IN/$f" "$WORK/$f" || echo "missing $f"; done
chmod +x sagvd acp-compute acpctl keygen
./sagvd version > "$OUT/versions.txt"; ./acp-compute version >> "$OUT/versions.txt"; ./acpctl version >> "$OUT/versions.txt" 2>/dev/null || true
sha256sum sagvd acp-compute acpctl keygen genome-worker.tgz > "$OUT/inputs.sha256"
mkdir -p workers && tar xzf genome-worker.tgz -C workers

step "configfs-tsm"
modprobe sev-guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report /dev/sev-guest 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail -20; } > "$OUT/tsm.txt"

step "the worker runtime: python, the pinned CPU torch"
mark runtime_install_start
export DEBIAN_FRONTEND=noninteractive
n=0; while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && [ $n -lt 120 ]; do sleep 2; n=$((n+1)); done
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1
python3 -m venv venv && . venv/bin/activate
pip install --require-hashes --only-binary=:all: --index-url https://pypi.org/simple -r workers/genome/requirements-ci.lock > "$OUT/pip-requirements.log" 2>&1
pip install --require-hashes --only-binary=:all: --no-deps --index-url https://download.pytorch.org/whl/cpu -r workers/genome/requirements-torch-cpu.lock > "$OUT/pip-torch.log" 2>&1
mark runtime_install_end

step "acpctl provision --console-listen: the deployment with the console's listener"
mark provision_start
./acpctl provision --out "$DEPLOY" --bin-dir "$WORK" --provider auto --fetch-amd-chain milan --console-listen 0.0.0.0:9443 \
  --door-python "$WORK/venv/bin/python3" --base-model "$WORK/base" --worker-package "$WORK/workers/genome" \
  --vault-descriptor sagvd-console-e2e-v1 --worker-descriptor acp-compute-console-e2e-v1 > "$OUT/provision.out" 2> "$OUT/provision.err"
echo "provision exit=$?" >> "$OUT/steps.txt"
mark provision_end
cp "$DEPLOY/provision.json" "$DEPLOY/sagvd-identity.json" "$DEPLOY/acp-compute-identity.json" "$DEPLOY/sagvd.json" "$DEPLOY/acp-compute.json" "$OUT/" 2>/dev/null || true
cp "$DEPLOY/operator/audit_public_key.pem" "$OUT/audit-public-key.pem" 2>/dev/null || true

step "a real fine-tune, sealed"
export PYTHONPATH=$WORK/workers/genome TOKENIZERS_PARALLELISM=false
( cd workers/genome && python3 -c 'import sys, json; sys.path.insert(0, "tests"); import conftest
conftest.make_base(sys.argv[1])
open(sys.argv[2], "w").write("".join(json.dumps(e) + "\n" for e in conftest.EXAMPLES))' "$WORK/base" "$WORK/train.jsonl" )
python3 -m vg_genome finetune --base base --base-name tiny-llama --data train.jsonl --out genome \
  --targets q_proj,v_proj,lm_head --steps 20 --lr 1e-2 --max-len 32 --threads 2 --top-k 8 --new-tokens 4 > "$OUT/finetune.json" 2> "$OUT/finetune.err"
echo "finetune exit=$?" >> "$OUT/steps.txt"
./acpctl genome seal --content-dir genome --output "$DEPLOY/genomes/gen-0.genome" --key-out "$DEPLOY/genomes/gen-0.key" --json > "$OUT/seal.json" 2> "$OUT/seal.err"
echo "seal exit=$?" >> "$OUT/steps.txt"

step "both daemons as services"
mark services_start
for d in sagvd acp-compute; do
  cat > "/etc/systemd/system/$d.service" <<UNIT
[Unit]
Description=Vault Genome $d
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=PYTHONPATH=$WORK/workers/genome
Environment=TOKENIZERS_PARALLELISM=false
WorkingDirectory=$WORK
ExecStart=$WORK/$d -config $DEPLOY/$d.json
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
done
systemctl daemon-reload
systemctl enable --now sagvd.service >/dev/null 2>&1
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
echo "sagvd ready after ${n}s" >> "$OUT/steps.txt"
systemctl enable --now acp-compute.service >/dev/null 2>&1
n=0; until curl -sf http://127.0.0.1:9082/healthz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
n=0; until journalctl -u sagvd --no-pager -o cat | grep -q "sagvd session opened" || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
echo "session opened after ${n}s" >> "$OUT/steps.txt"
mark session_opened

step "one gate job through the REST API, before any console: the deployment as aws-sev-snp's kit proved it"
TOKEN=$(cat "$DEPLOY/operator/api_token")
curl -s -o "$OUT/job-submit.json" -w '%{http_code}\n' -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"genome":{"bundle":"gen-0.genome","key_file":"gen-0.key"},"deadline_seconds_from_now":300}' http://127.0.0.1:9080/v1/jobs > "$OUT/job-submit.status"
JOB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["job_id"])' "$OUT/job-submit.json" 2>/dev/null)
ST=""
for i in $(seq 1 300); do
  sleep 1
  curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9080/v1/jobs/$JOB" > "$OUT/job.json"
  ST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$OUT/job.json" 2>/dev/null)
  [ "$ST" = succeeded ] || [ "$ST" = failed ] && break
done
unset TOKEN
echo "job status=$ST after ${i}s" >> "$OUT/steps.txt"
python3 - "$OUT/job.json" "$OUT/steps.txt" <<'PY'
import json, sys
j = json.load(open(sys.argv[1])); g = j.get("gate") or {}
with open(sys.argv[2], "a") as f:
    f.write("gate_level=%s door=%s fixtures=%s\n" % (g.get("level"), g.get("door"), g.get("fixtures")))
PY
mark finished
ss -ltnp 2>/dev/null | grep -E ':(9443|9090|9080|9081|9082) ' > "$OUT/listeners.txt" || true
journalctl -u sagvd --no-pager -o cat > "$OUT/sagvd.log" 2>&1
journalctl -u acp-compute --no-pager -o cat > "$OUT/acp-compute.log" 2>&1
cp /root/e2e.log "$OUT/console.log"
echo "$PUBLIC_IP" > "$IN/public-ip.txt"; chown ubuntu:ubuntu "$IN/public-ip.txt"
( cd "$OUT" && sha256sum * > "$WORK/sha256sums.txt" ); mv "$WORK/sha256sums.txt" "$OUT/"
( cd "$WORK/out" && tar czf "$IN/results.tgz" "$STAMP" ) && chown ubuntu:ubuntu "$IN/results.tgz"
echo "E2E DONE $STAMP"
