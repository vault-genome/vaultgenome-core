#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script for a GCP AMD SEV-SNP Confidential VM (Ubuntu 24.04): the
# attester side of the delegated-verifier run (ADR 0025, step 2b). The
# Return Path with the appraisal delegated: sagvd and acp-compute both
# attest with the chip and each sends the other's Evidence record to a
# RATS Verifier on another VM (tee.peer.verifier.mode rats, Veraison's
# challenge-response API over mutual TLS), judges the EAR by the policy
# here and holds the pin itself. First the same flow with the builtin
# verifiers on the same chip, so the two handshakes are measured side by
# side; then the delegated session and its job; then a thief off the chip,
# a worker of another family refused before the Verifier is asked, a daemon
# whose policy names another appraisal policy refusing an affirming
# Verifier, a daemon whose Verifier is unreachable admitting nothing —
# every decision on the signed audit log, the EARs inside the admissions.
# Phase one prints this chip's report between ===RATS-REPORT-BEGIN=== and
# ===RATS-REPORT-END===, so the runner can provision the launch as a
# reference value; the rest waits for vg-go=1. Extra inputs: vg-verifier
# (the Verifier VM's name) and, in the bucket, pki/{rootCA.crt,
# verifier-ear.jwk,sagvd-client.crt,sagvd-client.key,worker-client.crt,
# worker-client.key}. Otherwise as returnpath-e2e/cvm-returnpath.sh:
#
# The Return Path on real hardware (ADR 0013, 0014): sagvd and acp-compute
# both attest with the chip (tee.provider "gcp-sev-snp", reports through
# the kernel's configfs-tsm) and each pins the other's launch measurement;
# the real vg_genome worker fine-tunes a genome on this guest, acpctl seals
# it, a gate job goes over the Return Path, acp-compute restores the model
# in memory through the door and answers, sagvd judges the answer and puts
# every decision on its signed audit log. A worker whose Evidence is not the
# pinned identity must be refused, and the refusal recorded; a copy of the
# sealed key files must be no key at all off this chip.
#
# Inputs (instance metadata): vg-bucket — GCS bucket holding e2e/{sagvd,
# acp-compute,acpctl,keygen,genome-worker.tgz}; the AMD Milan chain is fetched
# here from AMD KDS by acpctl, which verifies it against the pinned roots.
# Output: a base64 tarball of the results on the serial console between
# ===E2E-BEGIN=== and ===E2E-END=== (three copies), decoded by
# decode-results.sh. The tarball holds reports, job views, identities and
# logs only; keys, seeds, tokens and configs stay on the VM and die with it.
set -u
exec > >(tee -a /root/e2e.log) 2>&1
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=/root/e2e; OUT=$WORK/out/$STAMP; mkdir -p "$OUT"; cd "$WORK"
BUCKET=$(md attributes/vg-bucket)
VERIFIER=$(md attributes/vg-verifier)
SEALER=auto
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; echo "captured=$STAMP"; } > "$OUT/metadata.txt"
uname -a > "$OUT/kernel.txt"
T0=$(date +%s.%N)
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }

step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }

step "binaries from gs://$BUCKET/e2e"
GTOKEN=$(md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
for f in sagvd acp-compute acpctl keygen genome-worker.tgz; do
  curl -sSf -H "Authorization: Bearer $GTOKEN" -o "$WORK/$f" \
    "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/e2e%2F$f?alt=media" || echo "fetch $f failed"
done
unset GTOKEN
chmod +x sagvd acp-compute acpctl keygen
./sagvd version > "$OUT/versions.txt"; ./acp-compute version >> "$OUT/versions.txt"; ./acpctl version >> "$OUT/versions.txt" 2>/dev/null || true
./keygen -version >> "$OUT/versions.txt" 2>/dev/null || true
sha256sum sagvd acp-compute acpctl keygen genome-worker.tgz > "$OUT/inputs.sha256"
mkdir -p workers && tar xzf genome-worker.tgz -C workers

step "the AMD Milan chain from KDS, verified against the roots acpctl pins (ADR 0024)"
./acpctl tee fetch-amd-chain --product milan --out amd-milan-cert_chain.pem > "$OUT/amd-chain.txt" 2>&1 || echo "fetch-amd-chain failed: $(cat "$OUT/amd-chain.txt")"
sha256sum amd-milan-cert_chain.pem >> "$OUT/inputs.sha256"

step "configfs-tsm"
modprobe sev-guest 2>/dev/null || {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
  modprobe sev-guest 2>/dev/null || true
}
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail -20; } > "$OUT/tsm.txt"
step "this chip's report for the Verifier's reference value: one configfs-tsm request, printed for the runner"
E=/sys/kernel/config/tsm/report/vg-rats-$$
mkdir "$E" && python3 -c 'import sys, hashlib; sys.stdout.buffer.write(hashlib.sha256(b"vg-rats-" + sys.argv[1].encode()).digest() + bytes(32))' "$STAMP" > "$E/inblob" \
  && cat "$E/outblob" > "$WORK/launch-report.bin" && { cat "$E/auxblob" > "$WORK/launch-certs.bin" 2>/dev/null || true; }; rmdir "$E" 2>/dev/null
echo "launch_report_bytes=$(stat -c%s "$WORK/launch-report.bin" 2>/dev/null || echo 0) launch_certs_bytes=$(stat -c%s "$WORK/launch-certs.bin" 2>/dev/null || echo 0)" >> "$OUT/steps.txt"
sha256sum "$WORK/launch-report.bin" >> "$OUT/inputs.sha256"
LAUNCH_MEAS=$(python3 -c 'import sys; b=open(sys.argv[1],"rb").read(); print(b[0x90:0xC0].hex())' "$WORK/launch-report.bin")
echo "launch_measurement_from_report=$LAUNCH_MEAS" >> "$OUT/steps.txt"
base64 -w0 "$WORK/launch-report.bin" | fold -w 76 | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$WORK/launch-report.lines"
RL=$(wc -l < "$WORK/launch-report.lines"); RH=$(sha256sum "$WORK/launch-report.bin" | cut -d' ' -f1)
for COPY in 1 2 3; do
  { echo; echo "===RATS-REPORT-BEGIN=== $STAMP measurement=$LAUNCH_MEAS sha256=$RH lines=$RL copy=$COPY"; cat "$WORK/launch-report.lines"; echo "===RATS-REPORT-END==="; } > /dev/ttyS0 2>/dev/null || true
  sleep 2
done

step "the worker runtime: python, the pinned CPU torch (the door needs it)"
mark runtime_install_start
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1
python3 -m venv venv && . venv/bin/activate
# The runtime from the hash-pinned locks, each from its own index: the worker's packages, torch's
# dependencies and pytest from PyPI, then the torch CPU wheel alone from the PyTorch index.
# Not quiet: the two logs are the record of what pip installed, and from where.
pip install --require-hashes --only-binary=:all: --index-url https://pypi.org/simple -r workers/genome/requirements-ci.lock > "$OUT/pip-requirements.log" 2>&1
pip install --require-hashes --only-binary=:all: --no-deps --index-url https://download.pytorch.org/whl/cpu -r workers/genome/requirements-torch-cpu.lock > "$OUT/pip-torch.log" 2>&1
python3 -c 'import torch, transformers, safetensors; print("torch", torch.__version__, "transformers", transformers.__version__, "safetensors", safetensors.__version__)' > "$OUT/runtime.txt" 2>&1
mark runtime_install_end

if [ "$SEALER" = tpm2 ]; then
  step "tee.sealer tpm2: the guest's vTPM seals the key files (tpm2-tools)"
  export DEBIAN_FRONTEND=noninteractive
  for i in $(seq 1 12); do apt-get install -y -qq tpm2-tools >/dev/null 2>&1 && break; apt-get update -qq >/dev/null 2>&1 || true; sleep 10; done
  command -v tpm2_createprimary >/dev/null || echo "tpm2-tools did not install" >> "$OUT/steps.txt"
  { ls -la /dev/tpm0 /dev/tpmrm0 2>&1; tpm2_getcap properties-fixed 2>&1 | grep -A1 -E "TPM2_PT_MANUFACTURER|TPM2_PT_VENDOR_STRING_1" | head -4; } > "$OUT/vtpm.txt" 2>&1
fi
echo "sealer=$SEALER" >> "$OUT/steps.txt"
step "provision (acp-keygen, private modes; every key file is sealed to the chip below)"
./keygen -out secrets -quiet -private
S=$WORK/secrets
mkdir -p genomes audit queue vcek-cache
# The pins are filled in from each daemon's identity below; identity needs
# a config that validates, so the pin files start out as placeholders.
head -c 48 /dev/zero > peer-vault.meas; head -c 48 /dev/zero > peer-worker.meas

write_configs() { # $1 = vault measurement hex, $2 = worker measurement hex, $3 = mode (builtin | rats | rats-policy-other | rats-down), $4 = suffix of the files
  python3 - "$1" "$2" "$SEALER" "$3" "$4" "$VERIFIER" <<'PY'
import json, sys, binascii
vault_meas, worker_meas, SEALER, MODE, SUFFIX, VERIFIER = sys.argv[1:7]
W = "/root/e2e"; S = W + "/secrets"
open(W + "/peer-vault.meas", "wb").write(binascii.unhexlify(vault_meas))
open(W + "/peer-worker.meas", "wb").write(binascii.unhexlify(worker_meas))
def verifier(client):
    if MODE == "builtin":
        return None
    v = {"mode": "rats", "url": "https://%s:8443" % VERIFIER, "ear_public_key_path": W + "/pki/verifier-ear.jwk",
         "ca_path": W + "/pki/rootCA.crt", "client_cert_path": W + "/pki/%s-client.crt" % client, "client_key_path": W + "/pki/%s-client.key" % client,
         "policy_id": "policy:SEVSNP", "submod": "SEVSNP", "accept": ["affirming"], "timeout_seconds": 20}
    if MODE == "rats-policy-other":
        v["policy_id"] = "policy:bank-2026-other"
    if MODE == "rats-down":
        v["url"] = "https://%s:8444" % VERIFIER
    return v
def peer(path, client):
    p = {"provider": "gcp-sev-snp", "measurement_path": path}
    v = verifier(client)
    if v is None:
        p["amd_cert_chain_path"] = W + "/amd-milan-cert_chain.pem"; p["vcek_cache_dir"] = W + "/vcek-cache"
    else:
        p["verifier"] = v
    return p
sagvd = {
  "vault": {"listen_address": "127.0.0.1:9443",
    "tls": {"enabled": True, "server_cert": S + "/sagvd/tls/server.crt", "server_key": S + "/sagvd/tls/server.key", "client_cas": S + "/shared/tls/ca.crt"}},
  "http_api": {"listen_address": "127.0.0.1:9080", "bearer_token_file": S + "/sagvd/api_token"},
  "tee": {"provider": "auto", "sealer": SEALER, "workload_descriptor": "sagvd-returnpath-e2e-v1",
    "peer": peer(W + "/peer-worker.meas", "sagvd")},
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
    "tls": {"enabled": True, "client_cert": S + "/acp-compute/tls/client.crt", "client_key": S + "/acp-compute/tls/client.key", "ca_bundle": S + "/shared/tls/ca.crt", "server_name": "localhost"}},
  "tee": {"provider": "auto", "sealer": SEALER, "workload_descriptor": "acp-compute-returnpath-e2e-v1",
    "peer": peer(W + "/peer-vault.meas", "worker")},
  "keys": {"worker_signing": {"kid": "acp-compute-worker-demo", "seed_path": S + "/acp-compute/worker_signing_seed"},
           "session_sealing": {"kid": "session-sealing-e2e", "material_path": S + "/shared/sealing.key"}},
  "genome": {"door": {"command": [W + "/venv/bin/python3", "-m", "vg_genome", "door", "--stdin-genome", "--base", W + "/base", "--device", "cpu"],
                      "env": ["PYTHONPATH=" + W + "/workers/genome", "TOKENIZERS_PARALLELISM=false"], "timeout_seconds": 300}},
  "runtime": {"job_timeout_seconds": 600, "handshake_timeout_seconds": 30, "dial_backoff_initial_ms": 500, "dial_backoff_max_ms": 5000, "idle_between_jobs_ms": 200},
  "health": {"listen_address": "127.0.0.1:9082"},
  "log": {"level": "info", "format": "json"}}
json.dump(sagvd, open(W + "/sagvd%s.json" % SUFFIX, "w"), indent=2)
json.dump(worker, open(W + "/worker%s.json" % SUFFIX, "w"), indent=2)
PY
}
ZEROS=$(printf '%096d' 0)
write_configs "$ZEROS" "$ZEROS" builtin ""

step "identities: each daemon reads its launch measurement from the chip"
./sagvd identity -config sagvd.json > "$OUT/sagvd-identity.json" 2> "$OUT/sagvd-identity.err"; echo "sagvd identity exit=$?" >> "$OUT/steps.txt"
./acp-compute identity -config worker.json > "$OUT/acp-compute-identity.json" 2> "$OUT/acp-compute-identity.err"; echo "acp-compute identity exit=$?" >> "$OUT/steps.txt"
VMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/sagvd-identity.json" 2>/dev/null)
WMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/acp-compute-identity.json" 2>/dev/null)
echo "vault_measurement=$VMEAS" >> "$OUT/steps.txt"; echo "worker_measurement=$WMEAS" >> "$OUT/steps.txt"
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["audit_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > audit.pem
# Both daemons share this guest, so both measurements are the launch
# measurement of this VM; each pins the other's. The builtin configs first
# (the key files are sealed under them; every mode below reads the same
# sealed files), the delegated ones once the Verifier holds this launch.
write_configs "$VMEAS" "$WMEAS" builtin ""
echo "launch_measurement_equals_identity=$([ "$VMEAS" = "$LAUNCH_MEAS" ] && echo yes || echo no)" >> "$OUT/steps.txt"

step "the key files sealed to this host (ADR 0023; the sealer is tee.sealer=$SEALER, ADR 0025 step 1b)"
# seal-keys seals the API token file too: the operator's copy is taken first.
cp "$S/sagvd/api_token" "$WORK/api_token.operator" && chmod 600 "$WORK/api_token.operator"
# The second rogue below plays a thief who held the worker's plaintext key
# files at provisioning time: its copies are taken now, before seal-keys
# turns the originals into files only this host opens.
mkdir -p rogue && chmod 700 rogue
cp "$S/acp-compute/worker_signing_seed" rogue/worker_signing_seed
cp "$S/acp-compute/tls/client.key" rogue/client.key
cp "$S/shared/sealing.key" rogue/sealing.key
chmod 600 rogue/*
./sagvd seal-keys -config sagvd.json > "$OUT/seal-keys-sagvd.json" 2> "$OUT/seal-keys-sagvd.err"; echo "sagvd seal-keys exit=$? sealer=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("sealer"))' "$OUT/seal-keys-sagvd.json" 2>/dev/null) sealed=$(python3 -c 'import json,sys;print(",".join(e["name"] for e in json.load(open(sys.argv[1]))["sealed"]))' "$OUT/seal-keys-sagvd.json" 2>/dev/null)" >> "$OUT/steps.txt"
./acp-compute seal-keys -config worker.json > "$OUT/seal-keys-worker.json" 2> "$OUT/seal-keys-worker.err"; echo "acp-compute seal-keys exit=$? sealer=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("sealer"))' "$OUT/seal-keys-worker.json" 2>/dev/null) sealed=$(python3 -c 'import json,sys;print(",".join(e["name"] for e in json.load(open(sys.argv[1]))["sealed"]))' "$OUT/seal-keys-worker.json" 2>/dev/null)" >> "$OUT/steps.txt"
# The sealed files' shape, without their bytes: the sealer each names.
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
./acpctl genome seal --content-dir genome --output genomes/gen-0.genome --key-out genomes/gen-0.key --json > "$OUT/seal.json" 2> "$OUT/seal.err"
echo "seal exit=$?" >> "$OUT/steps.txt"
KID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_id"])' "$OUT/seal.json" 2>/dev/null); echo "key_id=$KID" >> "$OUT/steps.txt"

TOKEN=$(cat "$WORK/api_token.operator")
submit_job() { # $1 = label; sets JOB and ST, records the verdict
  mark "job_submit_$1"
  curl -s -o "$OUT/job-submit-$1.json" -w '%{http_code}\n' -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    --data '{"genome":{"bundle":"gen-0.genome","key_file":"gen-0.key"},"deadline_seconds_from_now":300}' http://127.0.0.1:9080/v1/jobs > "$OUT/job-submit-$1.status"
  JOB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["job_id"])' "$OUT/job-submit-$1.json" 2>/dev/null)
  echo "job_id_$1=$JOB" >> "$OUT/steps.txt"
  for i in $(seq 1 300); do
    sleep 1
    curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9080/v1/jobs/$JOB" > "$OUT/job-$1.json"
    ST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$OUT/job-$1.json" 2>/dev/null)
    [ "$ST" = succeeded ] || [ "$ST" = failed ] && break
  done
  mark "job_done_$1"
  echo "job_status_$1=$ST after ${i}s" >> "$OUT/steps.txt"
  python3 - "$OUT/job-$1.json" "$OUT/steps.txt" "$1" <<'PY'
import json, sys
j = json.load(open(sys.argv[1])); g = j.get("gate") or {}; v = (g.get("signed_verdict") or {}).get("verdict") or {}
with open(sys.argv[2], "a") as f:
    f.write("gate_%s: level=%s door=%s rung=%s fixtures=%s n_exact=%s max_abs_err=%s signer=%s\n" % (sys.argv[3],
        g.get("level"), g.get("door"), g.get("rung"), g.get("fixtures"), v.get("n_exact"), v.get("max_abs_err"), g.get("signer_key_id")))
PY
}
handshake_ms() { grep -o '"handshake_ms":[0-9]*' "$1" | head -1 | cut -d: -f2; }
evidence_bytes() { grep -o '"peer_evidence_bytes":[0-9]*' "$1" | head -1 | cut -d: -f2; }
step "A. the builtin verifiers on this chip: sagvd, acp-compute, a session, a job — the handshake measured"
./sagvd -config sagvd.json > "$OUT/sagvd-builtin.log" 2>&1 &
SAGVD=$!
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
echo "sagvd_builtin ready after ${n}s" >> "$OUT/steps.txt"
./acp-compute -config worker.json > "$OUT/acp-compute-builtin.log" 2>&1 &
WORKER=$!
n=0; until grep -q "sagvd session opened" "$OUT/sagvd-builtin.log" || [ $n -ge 120 ]; do sleep 1; n=$((n+1)); done
echo "builtin session opened after ${n}s sagvd_handshake_ms=$(handshake_ms "$OUT/sagvd-builtin.log") worker_handshake_ms=$(handshake_ms "$OUT/acp-compute-builtin.log") worker_record_bytes=$(evidence_bytes "$OUT/sagvd-builtin.log") vault_record_bytes=$(evidence_bytes "$OUT/acp-compute-builtin.log")" >> "$OUT/steps.txt"
submit_job builtin
kill -TERM $WORKER; wait $WORKER 2>/dev/null
kill -TERM $SAGVD; wait $SAGVD 2>/dev/null
step "B. the Verifier holds this launch? (vg-go) — then the kit's PKI and the Verifier's EAR key"
n=0; until [ "$(md attributes/vg-go 2>/dev/null)" = 1 ] || [ $n -ge 360 ]; do sleep 5; n=$((n+1)); done
echo "vg-go after $((n*5))s" >> "$OUT/steps.txt"
mark verifier_go
mkdir -p pki && chmod 700 pki
GTOKEN=$(md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
for f in rootCA.crt verifier-ear.jwk sagvd-client.crt sagvd-client.key worker-client.crt worker-client.key; do
  curl -sSf -H "Authorization: Bearer $GTOKEN" -o "pki/$f" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/pki%2F$f?alt=media" || echo "fetch pki/$f failed" >> "$OUT/steps.txt"
done
unset GTOKEN; chmod 600 pki/*.key
sha256sum pki/rootCA.crt pki/verifier-ear.jwk pki/sagvd-client.crt pki/worker-client.crt >> "$OUT/inputs.sha256"
cp pki/verifier-ear.jwk "$OUT/verifier-ear.jwk"
step "the Verifier from this guest: its well-known document over mutual TLS, by name"
curl -sS --max-time 20 --cacert pki/rootCA.crt --cert pki/sagvd-client.crt --key pki/sagvd-client.key \
  "https://$VERIFIER:8443/.well-known/veraison/verification" > "$OUT/verifier-well-known.json" 2> "$OUT/verifier-well-known.err"; echo "well-known from the guest exit=$?" >> "$OUT/steps.txt"
getent hosts "$VERIFIER" > "$OUT/verifier-dns.txt" 2>&1
write_configs "$VMEAS" "$WMEAS" rats "-rats"
write_configs "$VMEAS" "$WMEAS" rats-policy-other "-policy"
write_configs "$VMEAS" "$WMEAS" rats-down "-down"
./sagvd identity -config sagvd-rats.json > "$OUT/sagvd-rats-identity.json" 2> "$OUT/sagvd-rats-identity.err"; echo "sagvd rats identity exit=$?" >> "$OUT/steps.txt"
step "sagvd on SEV-SNP, appraisal delegated to $VERIFIER"
./sagvd -config sagvd-rats.json > "$OUT/sagvd.log" 2>&1 &
SAGVD=$!
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
echo "sagvd_rats ready after ${n}s $(grep -o '"peer_verifier":"[^"]*"' "$OUT/sagvd.log" | head -1)" >> "$OUT/steps.txt"
step "a thief with the sealed key files, off the chip: they do not open (ADR 0023; tee.sealer=$SEALER)"
# The worker's own key files, as they sit on disk after seal-keys, in the
# hands of a process whose TEE is the simulated one: the seal names the
# chip, and the files are refused before any key is read. A hang here
# would mean they opened; timeout makes that an exit code on the record.
head -c 32 /dev/urandom > rogue.seed; chmod 600 rogue.seed
python3 - <<'PY'
import json
W = "/root/e2e"
c = json.load(open(W + "/worker-rats.json"))
c["tee"] = {"provider": "simulated", "workload_descriptor": "rogue-worker-v1", "seed_path": W + "/rogue.seed", "insecure_simulation": True, "peer": c["tee"]["peer"]}
c["health"] = {"listen_address": "127.0.0.1:9083"}
c["runtime"]["dial_backoff_initial_ms"] = 2000
c["runtime"]["dial_backoff_max_ms"] = 2000
json.dump(c, open(W + "/rogue-sealed.json", "w"), indent=2)
# The same rogue with the plaintext copies taken before sealing.
c["keys"]["worker_signing"]["seed_path"] = W + "/rogue/worker_signing_seed"
c["keys"]["session_sealing"]["material_path"] = W + "/rogue/sealing.key"
c["vault"]["tls"]["client_key"] = W + "/rogue/client.key"
json.dump(c, open(W + "/rogue.json", "w"), indent=2)
PY
timeout 30 ./acp-compute -config rogue-sealed.json > "$OUT/rogue-sealed-worker.log" 2>&1
echo "rogue with the sealed files exit=$? $(grep -o 'sealed to [a-z0-9-]*, this host is [a-z0-9-]*' "$OUT/rogue-sealed-worker.log" | head -1)" >> "$OUT/steps.txt"

step "a worker of another family: refused by name before the Verifier is asked, on the record"
# Same certificate, same signing key, same sealing key — the plaintext
# copies — and a different attestation: the simulated TEE. sagvd's pin is
# the chip's measurement; this Evidence is not it.
./acp-compute -config rogue.json > "$OUT/rogue-worker.log" 2>&1 &
ROGUE=$!
n=0; until grep -q "sagvd return-path handshake failed" "$OUT/sagvd.log" || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
if grep -q "sagvd return-path handshake failed" "$OUT/sagvd.log"; then echo "rogue refused after ${n}s: $(grep -o 'evidence type [^,]*, this peer verifier is [a-z-]*' "$OUT/sagvd.log" | head -1)" >> "$OUT/steps.txt"; else echo "rogue NOT refused within ${n}s" >> "$OUT/steps.txt"; fi
kill -TERM $ROGUE 2>/dev/null; wait $ROGUE 2>/dev/null
step "acp-compute on SEV-SNP, the real door, its appraisal of the vault delegated too"
./acp-compute -config worker-rats.json > "$OUT/acp-compute.log" 2>&1 &
WORKER=$!
n=0; until curl -sf http://127.0.0.1:9082/healthz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
n=0; until grep -q "sagvd session opened" "$OUT/sagvd.log" || [ $n -ge 120 ]; do sleep 1; n=$((n+1)); done
echo "rats session opened after ${n}s sagvd_handshake_ms=$(handshake_ms "$OUT/sagvd.log") worker_handshake_ms=$(handshake_ms "$OUT/acp-compute.log") worker_record_bytes=$(evidence_bytes "$OUT/sagvd.log") vault_record_bytes=$(evidence_bytes "$OUT/acp-compute.log")" >> "$OUT/steps.txt"
step "the gate job over the delegated Return Path"
submit_job rats
step "metrics"
curl -s http://127.0.0.1:9081/metrics | grep -E "^(sagvd|rp|vg_tee)_" > "$OUT/sagvd-metrics.txt"
curl -s http://127.0.0.1:9082/metrics | grep -E "^(acp_compute|rp|vg_tee)_" > "$OUT/acp-compute-metrics.txt"
kill -TERM $WORKER; wait $WORKER 2>/dev/null
kill -TERM $SAGVD; wait $SAGVD 2>/dev/null
step "C. a daemon whose policy names another appraisal policy: the Verifier affirms, this side refuses"
./sagvd -config sagvd-policy.json > "$OUT/sagvd-policy.log" 2>&1 &
SAGVD=$!
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
./acp-compute -config worker-rats.json > "$OUT/acp-compute-policy.log" 2>&1 &
WORKER=$!
n=0; until grep -q "sagvd return-path handshake failed" "$OUT/sagvd-policy.log" || [ $n -ge 120 ]; do sleep 1; n=$((n+1)); done
echo "policy refusal after ${n}s: $(grep -o 'appraised under policy [^"]*' "$OUT/sagvd-policy.log" | head -1)" >> "$OUT/steps.txt"
kill -TERM $WORKER; wait $WORKER 2>/dev/null
kill -TERM $SAGVD; wait $SAGVD 2>/dev/null
step "D. a daemon whose Verifier is unreachable: nothing is admitted on a missing verdict"
./sagvd -config sagvd-down.json > "$OUT/sagvd-down.log" 2>&1 &
SAGVD=$!
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
./acp-compute -config worker-rats.json > "$OUT/acp-compute-down.log" 2>&1 &
WORKER=$!
n=0; until grep -q "sagvd return-path handshake failed" "$OUT/sagvd-down.log" || [ $n -ge 120 ]; do sleep 1; n=$((n+1)); done
echo "verifier-down refusal after ${n}s: $(grep -o 'verifier_unavailable[^"]*' "$OUT/sagvd-down.log" | head -1 | cut -c1-160)" >> "$OUT/steps.txt"
echo "sessions_opened_down=$(curl -s http://127.0.0.1:9081/metrics | grep '^sagvd_sessions_opened_total' | awk '{print $2}')" >> "$OUT/steps.txt"
kill -TERM $WORKER; wait $WORKER 2>/dev/null
kill -TERM $SAGVD; wait $SAGVD 2>/dev/null
unset TOKEN
step "verify the audit log with the published key; the trust decisions of every phase"
./acpctl audit verify --audit audit/returnpath-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-e2e --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"
echo "audit verify exit=$?" >> "$OUT/steps.txt"
./acpctl audit query --audit audit/returnpath-audit.db --limit 0 --json > "$OUT/audit-events.jsonl" 2> "$OUT/audit-query.err"
echo "audit query exit=$?" >> "$OUT/steps.txt"
python3 - "$OUT/audit-events.jsonl" "$OUT/trust-decisions.jsonl" "$OUT/steps.txt" <<'PY'
import json, sys
n = {"allow": 0, "deny": 0, "allow_with_ear": 0}
with open(sys.argv[2], "w") as out:
    for line in open(sys.argv[1]):
        line = line.strip()
        if not line: continue
        e = json.loads(line)
        if e.get("kind") != "TRUST_EVALUATED": continue
        p = e.get("payload") or {}
        if isinstance(p, str):
            try: p = json.loads(p)
            except Exception: p = {"raw": p}
        o = p.get("outcome"); n[o] = n.get(o, 0) + 1
        vr = ((p.get("peer_detail") or {}).get("verifier") or {})
        if o == "allow" and vr.get("ear"): n["allow_with_ear"] += 1
        out.write(json.dumps({"outcome": o, "phase": p.get("phase"), "reason": (p.get("reason") or "")[:300], "code": p.get("code"),
                              "verifier_url": vr.get("url"), "verifier_status": vr.get("status"), "verifier_policy": vr.get("policy_id"),
                              "ear_present": bool(vr.get("ear")), "ear_len": len(vr.get("ear") or "")}) + "\n")
with open(sys.argv[3], "a") as f:
    f.write("trust_decisions: allow=%d deny=%d allow_with_ear=%d\n" % (n["allow"], n["deny"], n["allow_with_ear"]))
PY
cp audit.pem "$OUT/audit-public-key.pem"
python3 -c 'import sys,time; t0=float(sys.argv[1]); print("elapsed_seconds=%.1f" % (time.time()-t0))' "$T0" >> "$OUT/steps.txt"

cp /root/e2e.log "$OUT/console.log"
( cd "$OUT" && sha256sum * > "$WORK/sha256sums.txt" ); mv "$WORK/sha256sums.txt" "$OUT/"

echo "== emit"   # not via step: steps.txt is already under sha256sums.txt
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
