#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script of the release-deploy-images guest (GCP SEV-SNP, Ubuntu
# 24.04): the Return Path with sagvd and acp-compute running FROM THE
# RELEASE IMAGES, loaded from the tarballs the runner verified and put in
# the bucket. The flow is gcp-sev-snp/returnpath-e2e/cvm-returnpath.sh's —
# provisioning, identities from the chip, the key files sealed to it, a
# real fine-tune sealed by the released acpctl, the thief and the unpinned
# worker refused, the gate job EXACT, the audit log verified — with every
# daemon invocation a `docker run` of the image, the chip reachable as
# deploy/compose/README.md states: the whole configfs bound read-write,
# Docker's default AppArmor profile set aside, /dev/sev-guest and
# /dev/tpmrm0 passed, root inside (configfs creates a request's attribute
# files owned by root). The worker's door is the image's own Python.
exec > >(tee /root/e2e.log) 2>&1
set -u
md() { curl -sf -H 'Metadata-Flavor: Google' "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=/root/e2e; OUT=$WORK/out/$STAMP; mkdir -p "$OUT"; cd "$WORK" || exit 1
BUCKET=$(md attributes/vg-bucket); TAG=$(md attributes/vg-tag)
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; echo "captured=$STAMP"; echo "release=$TAG"; } > "$OUT/metadata.txt"
uname -a > "$OUT/kernel.txt"
T0=$(date +%s.%N)
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }

step "inputs from gs://$BUCKET/e2e: the two image tarballs the runner verified, the released acpctl, acp-keygen and worker package"
GTOKEN=$(md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
for f in sagvd-image.tar acp-compute-image.tar acpctl keygen genome-worker.tgz images.txt; do
  curl -sSf -H "Authorization: Bearer $GTOKEN" -o "$WORK/$f" \
    "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/e2e%2F$f?alt=media" || echo "fetch $f failed"
done
unset GTOKEN
chmod +x acpctl keygen
sha256sum sagvd-image.tar acp-compute-image.tar acpctl keygen genome-worker.tgz images.txt > "$OUT/inputs.sha256"
cp images.txt "$OUT/images.txt"
./acpctl version > "$OUT/versions.txt" 2>/dev/null || true; ./keygen -version >> "$OUT/versions.txt" 2>/dev/null || true
mkdir -p workers && tar xzf genome-worker.tgz -C workers

step "docker, and the two images loaded from the tarballs (nothing pulled from a registry on this guest)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq docker.io python3-venv python3-pip >/dev/null 2>&1
systemctl start docker
docker --version > "$OUT/docker.txt"
loaded() { docker load -i "$1" 2>&1 | tee -a "$OUT/docker-load.txt" | grep -o -E 'Loaded image(?: ID)?: .*' | awk '{print $NF}' | tail -1; }
SAGVD_IMG=$(loaded sagvd-image.tar); WORKER_IMG=$(loaded acp-compute-image.tar)
echo "sagvd_image=$SAGVD_IMG" >> "$OUT/steps.txt"; echo "worker_image=$WORKER_IMG" >> "$OUT/steps.txt"
docker image inspect "$SAGVD_IMG" "$WORKER_IMG" --format '{{.Id}} {{.RepoTags}} {{.RepoDigests}} {{.Config.User}} {{.Config.Entrypoint}}' > "$OUT/docker-images.txt" 2>&1
# The container runs on the host's network (the daemons bind loopback as
# the configs say), as root, with the chip reachable; /root/e2e is the
# shared working tree, bound at the same path so the configs hold.
DK=(docker run --rm --network host --user 0:0 --security-opt apparmor=unconfined
    -v /sys/kernel/config:/sys/kernel/config:rw --device /dev/sev-guest --device /dev/tpmrm0
    -v /root/e2e:/root/e2e -w /root/e2e)
DKD=(docker run -d --network host --user 0:0 --security-opt apparmor=unconfined
    -v /sys/kernel/config:/sys/kernel/config:rw --device /dev/sev-guest --device /dev/tpmrm0
    -v /root/e2e:/root/e2e -w /root/e2e)
"${DK[@]}" "$SAGVD_IMG" version >> "$OUT/versions.txt" 2>&1 || echo "sagvd version failed" >> "$OUT/steps.txt"
"${DK[@]}" "$WORKER_IMG" version >> "$OUT/versions.txt" 2>&1 || echo "acp-compute version failed" >> "$OUT/steps.txt"

step "the AMD Milan chain from KDS, verified against the roots acpctl pins (ADR 0024)"
./acpctl tee fetch-amd-chain --product milan --out amd-milan-cert_chain.pem > "$OUT/amd-chain.txt" 2>&1 || echo "fetch-amd-chain failed: $(cat "$OUT/amd-chain.txt")"
sha256sum amd-milan-cert_chain.pem >> "$OUT/inputs.sha256"

step "configfs-tsm"
modprobe sev-guest 2>/dev/null || {
  apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
  modprobe sev-guest 2>/dev/null || true
}
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report 2>&1; ls -l /dev/sev-guest /dev/tpmrm0 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail -20; } > "$OUT/tsm.txt"

step "the worker runtime on the host, for the fine-tune only (the door runs inside the worker image)"
mark runtime_install_start
python3 -m venv venv && . venv/bin/activate
pip install --require-hashes --only-binary=:all: --index-url https://pypi.org/simple -r workers/genome/requirements-ci.lock > "$OUT/pip-requirements.log" 2>&1
pip install --require-hashes --only-binary=:all: --no-deps --index-url https://download.pytorch.org/whl/cpu -r workers/genome/requirements-torch-cpu.lock > "$OUT/pip-torch.log" 2>&1
python3 -c 'import torch, transformers, safetensors; print("host torch", torch.__version__, "transformers", transformers.__version__)' > "$OUT/runtime.txt" 2>&1
"${DK[@]}" --entrypoint /usr/local/bin/python3 "$WORKER_IMG" -c 'import torch, transformers; print("image torch", torch.__version__, "transformers", transformers.__version__)' >> "$OUT/runtime.txt" 2>&1
mark runtime_install_end

step "provision (acp-keygen, private modes; every key file is sealed to the chip below)"
./keygen -out secrets -quiet -private
S=$WORK/secrets
mkdir -p genomes audit queue vcek-cache
head -c 48 /dev/zero > peer-vault.meas; head -c 48 /dev/zero > peer-worker.meas

write_configs() { # $1 = vault measurement hex, $2 = worker measurement hex
  python3 - "$1" "$2" <<'PY'
import json, sys, binascii
vault_meas, worker_meas = sys.argv[1], sys.argv[2]
W = "/root/e2e"; S = W + "/secrets"
open(W + "/peer-vault.meas", "wb").write(binascii.unhexlify(vault_meas))
open(W + "/peer-worker.meas", "wb").write(binascii.unhexlify(worker_meas))
sagvd = {
  "vault": {"listen_address": "127.0.0.1:9443",
    "tls": {"enabled": True, "server_cert": S + "/sagvd/tls/server.crt", "server_key": S + "/sagvd/tls/server.key", "client_cas": S + "/shared/tls/ca.crt"}},
  "http_api": {"listen_address": "127.0.0.1:9080", "bearer_token_file": S + "/sagvd/api_token"},
  "tee": {"provider": "auto", "sealer": "auto", "workload_descriptor": "sagvd-returnpath-images-v1",
    "peer": {"provider": "gcp-sev-snp", "measurement_path": W + "/peer-worker.meas",
             "amd_cert_chain_path": W + "/amd-milan-cert_chain.pem", "vcek_cache_dir": W + "/vcek-cache"}},
  "keys": {"authority_signing": {"kid": "sagvd-authority-e2e", "seed_path": S + "/sagvd/authority_signing_seed"},
           "audit_signing": {"kid": "sagvd-audit-e2e", "seed_path": S + "/sagvd/audit_signing_seed"},
           "session_sealing": {"kid": "session-sealing-e2e", "material_path": S + "/shared/sealing.key"}},
  "workers": {"registry_path": S + "/shared/workers.json"},
  "genome": {"bundle_dir": W + "/genomes", "gate": {"atol": 1e-2, "rtol": 1e-3, "max_non_critical_outliers": 0}},
  "audit": {"log_path": W + "/audit/returnpath-audit.db"},
  "queue": {"path": W + "/queue/sagvd-jobs.db"},
  "runtime": {"job_timeout_seconds": 600, "handshake_timeout_seconds": 30, "queue_poll_ms": 50,
    "http_read_header_timeout_seconds": 5, "http_write_timeout_seconds": 30, "default_job_deadline_seconds": 600, "max_payload_bytes": 4194304},
  "health": {"listen_address": "127.0.0.1:9081"},
  "log": {"level": "info", "format": "json"}}
worker = {
  "vault": {"address": "127.0.0.1:9443",
    "tls": {"enabled": True, "client_cert": S + "/acp-compute/tls/client.crt", "client_key": S + "/acp-compute/tls/client.key", "ca_bundle": S + "/shared/tls/ca.crt", "server_name": "sagvd"}},
  "tee": {"provider": "auto", "sealer": "auto", "workload_descriptor": "acp-compute-returnpath-images-v1",
    "peer": {"provider": "gcp-sev-snp", "measurement_path": W + "/peer-vault.meas",
             "amd_cert_chain_path": W + "/amd-milan-cert_chain.pem", "vcek_cache_dir": W + "/vcek-cache"}},
  "keys": {"worker_signing": {"kid": "acp-compute-worker-demo", "seed_path": S + "/acp-compute/worker_signing_seed"},
           "session_sealing": {"kid": "session-sealing-e2e", "material_path": S + "/shared/sealing.key"}},
  # The door is the worker image's own Python and worker package (deploy/image/acp-compute/Dockerfile).
  "genome": {"door": {"command": ["/usr/local/bin/python3", "-m", "vg_genome", "door", "--stdin-genome", "--base", W + "/base", "--device", "cpu"],
                      "env": ["PYTHONPATH=/opt/vg/workers/genome", "TOKENIZERS_PARALLELISM=false", "HF_HOME=/tmp/hf"], "timeout_seconds": 300}},
  "runtime": {"job_timeout_seconds": 600, "handshake_timeout_seconds": 30, "dial_backoff_initial_ms": 500, "dial_backoff_max_ms": 5000, "idle_between_jobs_ms": 200},
  "health": {"listen_address": "127.0.0.1:9082"},
  "log": {"level": "info", "format": "json"}}
json.dump(sagvd, open(W + "/sagvd.json", "w"), indent=2)
json.dump(worker, open(W + "/worker.json", "w"), indent=2)
PY
}
ZEROS=$(printf '%096d' 0)
write_configs "$ZEROS" "$ZEROS"

step "identities: each daemon, from its image, reads its launch measurement from the chip"
"${DK[@]}" "$SAGVD_IMG" identity -config sagvd.json > "$OUT/sagvd-identity.json" 2> "$OUT/sagvd-identity.err"; echo "sagvd identity exit=$?" >> "$OUT/steps.txt"
"${DK[@]}" "$WORKER_IMG" identity -config worker.json > "$OUT/acp-compute-identity.json" 2> "$OUT/acp-compute-identity.err"; echo "acp-compute identity exit=$?" >> "$OUT/steps.txt"
VMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/sagvd-identity.json" 2>/dev/null)
WMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/acp-compute-identity.json" 2>/dev/null)
echo "vault_measurement=$VMEAS" >> "$OUT/steps.txt"; echo "worker_measurement=$WMEAS" >> "$OUT/steps.txt"
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["audit_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > audit.pem
write_configs "$VMEAS" "$WMEAS"

step "the key files sealed to this host from inside the images (ADR 0023)"
cp "$S/sagvd/api_token" "$WORK/api_token.operator" && chmod 600 "$WORK/api_token.operator"
mkdir -p rogue && chmod 700 rogue
cp "$S/acp-compute/worker_signing_seed" rogue/worker_signing_seed
cp "$S/acp-compute/tls/client.key" rogue/client.key
cp "$S/shared/sealing.key" rogue/sealing.key
chmod 600 rogue/*
"${DK[@]}" "$SAGVD_IMG" seal-keys -config sagvd.json > "$OUT/seal-keys-sagvd.json" 2> "$OUT/seal-keys-sagvd.err"; echo "sagvd seal-keys exit=$? sealer=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("sealer"))' "$OUT/seal-keys-sagvd.json" 2>/dev/null)" >> "$OUT/steps.txt"
"${DK[@]}" "$WORKER_IMG" seal-keys -config worker.json > "$OUT/seal-keys-worker.json" 2> "$OUT/seal-keys-worker.err"; echo "acp-compute seal-keys exit=$? sealer=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("sealer"))' "$OUT/seal-keys-worker.json" 2>/dev/null)" >> "$OUT/steps.txt"
python3 - "$S" > "$OUT/sealed-files.txt" 2>&1 <<'SHAPE'
import json, os, sys
S = sys.argv[1]
for p in ("sagvd/authority_signing_seed", "sagvd/audit_signing_seed", "sagvd/api_token", "sagvd/tls/server.key", "shared/sealing.key", "acp-compute/worker_signing_seed", "acp-compute/tls/client.key"):
    try:
        d = json.load(open(os.path.join(S, p)))
        print(p, {"schema": d.get("schema"), "tee": d.get("tee"), "sealer": d.get("sealer"), "name": d.get("name"), "sealed_bytes": len(d.get("sealed", ""))})
    except Exception as e:
        print(p, "not a sealed file:", type(e).__name__)
SHAPE

step "a real fine-tune on the host: tiny base model built here, LoRA adapter trained by vg_genome, sealed by the released acpctl"
mark finetune_start
export PYTHONPATH=$WORK/workers/genome TOKENIZERS_PARALLELISM=false
( cd workers/genome && python3 -c 'import sys, json; sys.path.insert(0, "tests"); import conftest
conftest.make_base(sys.argv[1])
open(sys.argv[2], "w").write("".join(json.dumps(e) + "\n" for e in conftest.EXAMPLES))' "$WORK/base" "$WORK/train.jsonl" )
python3 -m vg_genome finetune --base base --base-name tiny-llama --data train.jsonl --out genome \
  --targets q_proj,v_proj,lm_head --steps 20 --lr 1e-2 --max-len 32 --threads 2 --top-k 8 --new-tokens 4 > "$OUT/finetune.json" 2> "$OUT/finetune.err"
echo "finetune exit=$?" >> "$OUT/steps.txt"
mark finetune_end
./acpctl genome seal --content-dir genome --output genomes/gen-0.genome --key-out genomes/gen-0.key --json > "$OUT/seal.json" 2> "$OUT/seal.err"
echo "seal exit=$?" >> "$OUT/steps.txt"

step "sagvd from its image, on SEV-SNP"
"${DKD[@]}" --name sagvd "$SAGVD_IMG" -config sagvd.json > "$OUT/sagvd-container.txt" 2>&1
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
echo "sagvd ready after ${n}s" >> "$OUT/steps.txt"

step "a thief with the sealed key files, off the chip: they do not open (ADR 0023)"
head -c 32 /dev/urandom > rogue.seed; chmod 600 rogue.seed
python3 - <<'PY'
import json
W = "/root/e2e"
c = json.load(open(W + "/worker.json"))
c["tee"] = {"provider": "simulated", "workload_descriptor": "rogue-worker-v1", "seed_path": W + "/rogue.seed", "insecure_simulation": True, "peer": c["tee"]["peer"]}
c["health"] = {"listen_address": "127.0.0.1:9083"}
c["runtime"]["dial_backoff_initial_ms"] = 2000
c["runtime"]["dial_backoff_max_ms"] = 2000
json.dump(c, open(W + "/rogue-sealed.json", "w"), indent=2)
c["keys"]["worker_signing"]["seed_path"] = W + "/rogue/worker_signing_seed"
c["keys"]["session_sealing"]["material_path"] = W + "/rogue/sealing.key"
c["vault"]["tls"]["client_key"] = W + "/rogue/client.key"
json.dump(c, open(W + "/rogue.json", "w"), indent=2)
PY
timeout 30 "${DK[@]}" "$WORKER_IMG" -config rogue-sealed.json > "$OUT/rogue-sealed-worker.log" 2>&1
echo "rogue with the sealed files exit=$? $(grep -o 'sealed to [a-z0-9-]*, this host is [a-z0-9-]*' "$OUT/rogue-sealed-worker.log" | head -1)" >> "$OUT/steps.txt"

step "a worker that is not the pinned identity: refused at the Return Path handshake, on the record"
"${DKD[@]}" --name rogue "$WORKER_IMG" -config rogue.json > /dev/null 2>&1
n=0; until docker logs sagvd 2>&1 | grep -q "sagvd return-path handshake failed" || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
if docker logs sagvd 2>&1 | grep -q "sagvd return-path handshake failed"; then echo "rogue refused after ${n}s" >> "$OUT/steps.txt"; else echo "rogue NOT refused within ${n}s" >> "$OUT/steps.txt"; fi
docker logs rogue > "$OUT/rogue-worker.log" 2>&1; docker rm -f rogue >/dev/null 2>&1

step "acp-compute from its image, on SEV-SNP, the door inside the image"
"${DKD[@]}" --name worker "$WORKER_IMG" -config worker.json > "$OUT/worker-container.txt" 2>&1
n=0; until curl -sf http://127.0.0.1:9082/healthz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
n=0; until docker logs sagvd 2>&1 | grep -q "sagvd session opened" || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
echo "session opened after ${n}s" >> "$OUT/steps.txt"

step "the gate job over the Return Path"
TOKEN=$(cat "$WORK/api_token.operator")
mark job_submit
curl -s -o "$OUT/job-submit.json" -w '%{http_code}\n' -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"genome":{"bundle":"gen-0.genome","key_file":"gen-0.key"},"deadline_seconds_from_now":300}' http://127.0.0.1:9080/v1/jobs > "$OUT/job-submit.status"
JOB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["job_id"])' "$OUT/job-submit.json" 2>/dev/null)
echo "job_id=$JOB" >> "$OUT/steps.txt"
ST=
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
curl -s http://127.0.0.1:9081/metrics | grep -E "^(sagvd|rp)_" > "$OUT/sagvd-metrics.txt"
curl -s http://127.0.0.1:9082/metrics | grep -E "^(acp_compute|rp)_" > "$OUT/acp-compute-metrics.txt"

step "stop both containers; verify the audit log with the published key, with the released acpctl"
docker stop -t 20 worker >/dev/null 2>&1; docker logs worker > "$OUT/acp-compute.log" 2>&1; docker rm -f worker >/dev/null 2>&1
docker stop -t 20 sagvd >/dev/null 2>&1; docker logs sagvd > "$OUT/sagvd.log" 2>&1; docker rm -f sagvd >/dev/null 2>&1
docker ps -a --format '{{.Names}} {{.Status}}' > "$OUT/docker-ps-after.txt"
./acpctl audit verify --audit audit/returnpath-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-e2e --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"
echo "audit verify exit=$?" >> "$OUT/steps.txt"
./acpctl audit query --audit audit/returnpath-audit.db --limit 0 --json > "$OUT/audit-events.jsonl" 2> "$OUT/audit-query.err"
echo "audit query exit=$?" >> "$OUT/steps.txt"
cp audit.pem "$OUT/audit-public-key.pem"
python3 -c 'import sys,time; t0=float(sys.argv[1]); print("elapsed_seconds=%.1f" % (time.time()-t0))' "$T0" >> "$OUT/steps.txt"

cp /root/e2e.log "$OUT/console.log"
( cd "$OUT" && sha256sum * > "$WORK/sha256sums.txt" ); mv "$WORK/sha256sums.txt" "$OUT/"

echo "== emit"
cd "$WORK/out" && tar czf "$STAMP.tgz" "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"
SZ=$(stat -c%s "$STAMP.b64"); H=$(sha256sum "$STAMP.b64" | cut -d' ' -f1)
fold -w 76 "$STAMP.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$STAMP.lines"; NL=$(wc -l < "$STAMP.lines")
dmesg -n 1 2>/dev/null || true
sleep 5
for COPY in 1 2 3; do
  { echo; echo "===E2E-BEGIN=== $STAMP size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "$STAMP.lines"; echo "===E2E-END==="; } > /dev/ttyS0 2>/dev/null || true
  sleep 3
done
echo "E2E DONE $STAMP size=$SZ sha256=$H lines=$NL"
