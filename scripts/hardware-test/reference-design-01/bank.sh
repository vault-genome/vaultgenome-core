#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The bank of reference design 01, as the startup script of a GCP AMD
# SEV-SNP Confidential VM (Ubuntu 24.04) in region A: the release authority
# (sagvd) and its pinned worker (acp-compute) on this chip, each attesting
# with the chip's report and pinning the other's launch measurement; every
# key file sealed to the chip (ADR 0023); the quant's fine-tune sealed as a
# genome by acpctl; a thief with the sealed files and a worker that is not
# the pinned identity both refused; the operator's gate job over the Return
# Path — REQUEST_RECEIVED, the handshake, TRUST_EVALUATED, the material
# released for the session, EXACT, RELEASE_DECIDED (the design's steps 2–5);
# then the continuity: the genome's key released to the standby in region B
# by `sagvd crosscloud-restore` only after the standby's chip attested
# (its measurement on the allow-list, its report verified against the AMD
# chain), the restore confirmed from the standby's chip-signed receipt by
# `sagvd crosscloud-confirm`, a release to an unlisted guest and one under
# an operator stop refused; both audit logs verified here with the
# published key, and handed to the third party.
#
# Inputs (instance metadata): vg-bucket — the run's private bucket with
# in/{sagvd,acp-compute,acpctl,keygen,genome-worker.tgz}; vg-profile — the
# cryptographic profile (ADR 0029) both daemons run under. Hand-off through
# the bucket: handoff/{dest-bundle.tgz,base.tgz,gen-0.genome,authority.pem,
# seal.json} out to the standby, handoff/standby.json back from it,
# handoff/third-party/* out to the runner; the record out/a.tgz and the
# marker out/a/DONE (or out/a/FAILED). Keys, seeds, the tokens and the
# configs stay on the VM and die with it; the standby's TLS material and
# token leave it once, through the bucket, before seal-keys.
set -u
exec > >(tee -a /root/bank.log) 2>&1
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }
gtoken() { md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'; }
urlenc() { python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
gcs_get() { curl -sSf -H "Authorization: Bearer $(gtoken)" -o "$2" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$(urlenc "$1")?alt=media"; }
gcs_put() { curl -sSf -X POST -H "Authorization: Bearer $(gtoken)" -H "Content-Type: application/octet-stream" --data-binary "@$1" "https://storage.googleapis.com/upload/storage/v1/b/$BUCKET/o?uploadType=media&name=$(urlenc "$2")" > /dev/null; }
gcs_exists() { curl -sf -H "Authorization: Bearer $(gtoken)" -o /dev/null "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$(urlenc "$1")"; }
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=/root/rd01; OUT=$WORK/out; mkdir -p "$OUT"; cd "$WORK" || exit 1
BUCKET=$(md attributes/vg-bucket)
PROFILE=$(md attributes/vg-profile); [ -n "$PROFILE" ] || PROFILE=general
MY_IP=$(md network-interfaces/0/ip)
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; echo "internal_ip=$MY_IP"; echo "captured=$STAMP"; } > "$OUT/metadata.txt"
uname -a > "$OUT/kernel.txt"
echo "profile=$PROFILE" >> "$OUT/steps.txt"
FIPS=$(md attributes/vg-fips 2>/dev/null || true); [ "$FIPS" = 1 ] || FIPS=0
# VG_FIPS=1 on the runner (ADR 0030, part two): every Go process on this
# guest runs under enforcement; a non-approved service fails instead of
# succeeding. The binaries came built on the certified module.
if [ "$FIPS" = 1 ]; then export GODEBUG=fips140=only; echo "fips=1 GODEBUG=fips140=only" >> "$OUT/steps.txt"; fi
T0=$(date +%s.%N)
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }
emit() { # emit <DONE|FAILED>
  cp /root/bank.log "$OUT/console.log" 2>/dev/null
  python3 -c 'import sys,time; t0=float(sys.argv[1]); print("elapsed_seconds=%.1f" % (time.time()-t0))' "$T0" >> "$OUT/steps.txt"
  ( cd "$OUT" && sha256sum * > "$WORK/sha256sums.txt" 2>/dev/null ); mv "$WORK/sha256sums.txt" "$OUT/" 2>/dev/null
  ( cd "$WORK" && tar czf a.tgz -C "$OUT" . ) && gcs_put "$WORK/a.tgz" out/a.tgz
  echo "$1" > "$WORK/marker" && gcs_put "$WORK/marker" "out/a/$1"
  echo "BANK $1 $STAMP"
}
fail() { step "FAILED: $*"; emit FAILED; exit 1; }

step "binaries from gs://$BUCKET/in"
for f in sagvd acp-compute acpctl keygen genome-worker.tgz; do gcs_get "in/$f" "$WORK/$f" || fail "fetch $f"; done
chmod +x sagvd acp-compute acpctl keygen
./sagvd version > "$OUT/versions.txt"; ./acp-compute version >> "$OUT/versions.txt"; ./acpctl version >> "$OUT/versions.txt" 2>/dev/null || true
sha256sum sagvd acp-compute acpctl keygen genome-worker.tgz > "$OUT/inputs.sha256"
mkdir -p workers && tar xzf genome-worker.tgz -C workers

step "the AMD Milan chain from KDS, verified against the roots acpctl pins (ADR 0024)"
./acpctl tee fetch-amd-chain --product milan --out amd-milan-cert_chain.pem > "$OUT/amd-chain.txt" 2>&1 || fail "fetch-amd-chain: $(cat "$OUT/amd-chain.txt")"
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

step "the worker runtime: python, the pinned CPU torch (the door needs it)"
mark runtime_install_start
export DEBIAN_FRONTEND=noninteractive
for i in $(seq 1 60); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 5; done
mark apt_start
apt-get -o DPkg::Lock::Timeout=300 update -qq >/dev/null 2>&1; apt-get -o DPkg::Lock::Timeout=300 install -y -qq python3-venv python3-pip >/dev/null 2>&1
mark apt_end
python3 -m venv venv && . venv/bin/activate
mark pip_start
pip install --timeout 60 --retries 5 --require-hashes --only-binary=:all: --index-url https://pypi.org/simple -r workers/genome/requirements-ci.lock > "$OUT/pip-requirements.log" 2>&1
pip install --timeout 60 --retries 5 --require-hashes --only-binary=:all: --no-deps --index-url https://download.pytorch.org/whl/cpu -r workers/genome/requirements-torch-cpu.lock > "$OUT/pip-torch.log" 2>&1
python3 -c 'import torch, transformers, safetensors; print("torch", torch.__version__, "transformers", transformers.__version__, "safetensors", safetensors.__version__)' > "$OUT/runtime.txt" 2>&1
mark pip_end
mark runtime_install_end

step "provision (acp-keygen, private modes; every key file is sealed to the chip below)"
./keygen -out secrets -quiet -private
S=$WORK/secrets
TOKEN_XCC=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'); printf '%s\n' "$TOKEN_XCC" > "$S/xcc_token"; chmod 600 "$S/xcc_token"; unset TOKEN_XCC
mkdir -p genomes audit queue vcek-cache
head -c 48 /dev/zero > peer-vault.meas; head -c 48 /dev/zero > peer-worker.meas
write_configs() { # $1 = vault measurement hex, $2 = worker measurement hex
  python3 - "$1" "$2" "$PROFILE" <<'PY'
import json, os, sys, binascii
vault_meas, worker_meas, profile = sys.argv[1], sys.argv[2], sys.argv[3]
W = "/root/rd01"; S = W + "/secrets"
open(W + "/peer-vault.meas", "wb").write(binascii.unhexlify(vault_meas))
open(W + "/peer-worker.meas", "wb").write(binascii.unhexlify(worker_meas))
peer = lambda meas: {"provider": "gcp-sev-snp", "measurement_path": meas, "amd_cert_chain_path": W + "/amd-milan-cert_chain.pem", "vcek_cache_dir": W + "/vcek-cache"}
sagvd = {
  "vault": {"listen_address": "127.0.0.1:9443",
    "tls": {"enabled": True, "server_cert": S + "/sagvd/tls/server.crt", "server_key": S + "/sagvd/tls/server.key", "client_cas": S + "/shared/tls/ca.crt"}},
  "http_api": {"listen_address": "127.0.0.1:9080", "bearer_token_file": S + "/sagvd/api_token"},
  "tee": {"provider": "auto", "sealer": "auto", "workload_descriptor": "sagvd-rd01-bank-v1", "peer": peer(W + "/peer-worker.meas")},
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
  "log": {"level": "info", "format": "json"},
  "crypto": {"profile": profile}}
worker = {
  "vault": {"address": "127.0.0.1:9443",
    "tls": {"enabled": True, "client_cert": S + "/acp-compute/tls/client.crt", "client_key": S + "/acp-compute/tls/client.key", "ca_bundle": S + "/shared/tls/ca.crt", "server_name": "localhost"}},
  "tee": {"provider": "auto", "sealer": "auto", "workload_descriptor": "acp-compute-rd01-bank-v1", "peer": peer(W + "/peer-vault.meas")},
  "keys": {"worker_signing": {"kid": "acp-compute-worker-demo", "seed_path": S + "/acp-compute/worker_signing_seed"},
           "session_sealing": {"kid": "session-sealing-e2e", "material_path": S + "/shared/sealing.key"}},
  "genome": {"door": {"command": [W + "/venv/bin/python3", "-m", "vg_genome", "door", "--stdin-genome", "--base", W + "/base", "--device", "cpu"],
                      "env": ["PYTHONPATH=" + W + "/workers/genome", "TOKENIZERS_PARALLELISM=false"], "timeout_seconds": 300}},
  "runtime": {"job_timeout_seconds": 600, "handshake_timeout_seconds": 30, "dial_backoff_initial_ms": 500, "dial_backoff_max_ms": 5000, "idle_between_jobs_ms": 200},
  "health": {"listen_address": "127.0.0.1:9082"},
  "log": {"level": "info", "format": "json"}}
# The cross-cloud section, once the policy files exist (the operator's stop
# key and list, the allow-list, the verifier registry): the transport's own
# client pair under W/xcc, sealed by seal-keys under its own field name —
# a sealed file is bound to the field that sealed it (ADR 0023), so the
# worker's sealed key cannot double as the transport's.
if os.path.exists(W + "/allow.json") and os.path.exists(W + "/stop.json"):
    sagvd["crosscloud"] = {"enabled": True, "policy_version": "rd01-policy-v1", "audit_log_path": W + "/xcc-audit.db",
        "operator_stop": {"kid": "operator-1", "public_key_path": W + "/operator.pem", "list_path": W + "/stop.json"},
        "policy_allow_list_path": W + "/allow.json", "verifier_registry_path": W + "/verifiers.json",
        "transport_bearer_token": open(S + "/xcc_token").read().strip(), "request_timeout_seconds": 60,
        "transport_tls": {"enabled": True, "client_cert": W + "/xcc/client.crt", "client_key": W + "/xcc/client.key",
                          "ca_bundle": S + "/shared/tls/ca.crt", "server_name": "localhost"}}
json.dump(sagvd, open(W + "/sagvd.json", "w"), indent=2)
json.dump(worker, open(W + "/worker.json", "w"), indent=2)
PY
}
write_policy() { # write_policy <allow-listed measurement hex> <the standby's measurement hex, for the verifier>
  cat > allow.json <<ALLOW
{"version": "rd01-policy-v1", "allowed": {"gcp-sev-snp": ["$1"]}}
ALLOW
  cat > verifiers.json <<VER
{"verifiers": [{"provider": "gcp-sev-snp", "expected_measurement_hex": "$2", "amd_cert_chain_path": "$WORK/amd-milan-cert_chain.pem", "vcek_cache_dir": "$WORK/vcek-cache"}]}
VER
}
ZEROS=$(printf '%096d' 0)
write_configs "$ZEROS" "$ZEROS"

step "identities: each daemon reads its launch measurement from the chip"
./sagvd identity -config sagvd.json > "$OUT/sagvd-identity.json" 2> "$OUT/sagvd-identity.err"; echo "sagvd identity exit=$?" >> "$OUT/steps.txt"
./acp-compute identity -config worker.json > "$OUT/acp-compute-identity.json" 2> "$OUT/acp-compute-identity.err"; echo "acp-compute identity exit=$?" >> "$OUT/steps.txt"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])).get("fips140") or {}; print("sagvd fips140 enabled=%s enforced=%s version=%s" % (str(d.get("enabled")).lower(), str(d.get("enforced")).lower(), d.get("version")))' "$OUT/sagvd-identity.json" >> "$OUT/steps.txt" 2>/dev/null
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])).get("fips140") or {}; print("acp-compute fips140 enabled=%s enforced=%s version=%s" % (str(d.get("enabled")).lower(), str(d.get("enforced")).lower(), d.get("version")))' "$OUT/acp-compute-identity.json" >> "$OUT/steps.txt" 2>/dev/null
VMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/sagvd-identity.json" 2>/dev/null)
WMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/acp-compute-identity.json" 2>/dev/null)
[ -n "$VMEAS" ] && [ -n "$WMEAS" ] || fail "no measurement from the chip: $(cat "$OUT/sagvd-identity.err" "$OUT/acp-compute-identity.err")"
echo "vault_measurement=$VMEAS" >> "$OUT/steps.txt"; echo "worker_measurement=$WMEAS" >> "$OUT/steps.txt"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("sagvd crypto_profile=%s kem_suites=%s" % (d.get("crypto_profile"), ",".join(d.get("kem_suites") or [])))' "$OUT/sagvd-identity.json" >> "$OUT/steps.txt" 2>&1
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["audit_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > audit.pem
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["authority_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > authority.pem
cp audit.pem "$OUT/audit-public-key.pem"

step "the cross-cloud transport's own client pair and the operator's stop key, before sealing; the policy files start as placeholders"
mkdir -p xcc && chmod 700 xcc
cp "$S/acp-compute/tls/client.crt" xcc/client.crt && cp "$S/acp-compute/tls/client.key" xcc/client.key && chmod 600 xcc/client.key
# In production the operator key lives on the operator's machine; the bank's host sees operator.pem and the signed list.
./acpctl stop keygen -out operator.seed -pub operator.pem > /dev/null
./acpctl stop issue -key operator.seed -kid operator-1 -serial 1 -out stop.json > /dev/null
write_policy "$ZEROS" "$ZEROS"
write_configs "$VMEAS" "$WMEAS"

step "the standby's bundle, taken before sealing: its TLS material, the CA, a client pair for the bank's transport, the token"
# The standby serves acp-bootstrap under the server certificate keygen
# issued (localhost among its names; the bank dials it by address with
# server_name localhost); the bank's crosscloud transport presents the
# worker's client certificate. Plaintext copies for the other chip, taken
# now: seal-keys turns the originals here into files only this host opens.
mkdir -p dest-bundle && chmod 700 dest-bundle
cp "$S/sagvd/tls/server.crt" "$S/sagvd/tls/server.key" dest-bundle/
cp "$S/shared/tls/ca.crt" dest-bundle/ca.crt
cp "$S/acp-compute/tls/client.crt" "$S/acp-compute/tls/client.key" dest-bundle/
cp "$S/xcc_token" dest-bundle/xcc_token
( cd dest-bundle && tar czf ../dest-bundle.tgz . ) && chmod 600 dest-bundle.tgz
rm -rf dest-bundle

step "the key files sealed to this host (ADR 0023)"
cp "$S/sagvd/api_token" "$WORK/api_token.operator" && chmod 600 "$WORK/api_token.operator"
mkdir -p rogue && chmod 700 rogue
cp "$S/acp-compute/worker_signing_seed" rogue/worker_signing_seed
cp "$S/acp-compute/tls/client.key" rogue/client.key
cp "$S/shared/sealing.key" rogue/sealing.key
chmod 600 rogue/*
./sagvd seal-keys -config sagvd.json > "$OUT/seal-keys-sagvd.json" 2> "$OUT/seal-keys-sagvd.err"; echo "sagvd seal-keys exit=$? sealer=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("sealer"))' "$OUT/seal-keys-sagvd.json" 2>/dev/null)" >> "$OUT/steps.txt"
./acp-compute seal-keys -config worker.json > "$OUT/seal-keys-worker.json" 2> "$OUT/seal-keys-worker.err"; echo "acp-compute seal-keys exit=$? sealer=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("sealer"))' "$OUT/seal-keys-worker.json" 2>/dev/null)" >> "$OUT/steps.txt"
python3 - "$S" "$WORK" > "$OUT/sealed-files.txt" 2>&1 <<'SHAPE'
import json, os, sys
S, W = sys.argv[1], sys.argv[2]
for p in ("sagvd/authority_signing_seed", "sagvd/audit_signing_seed", "sagvd/api_token", "sagvd/tls/server.key", "shared/sealing.key", "acp-compute/worker_signing_seed", "acp-compute/tls/client.key", "../xcc/client.key"):
    try:
        d = json.load(open(os.path.normpath(os.path.join(S, p))))
        print(p, {"schema": d.get("schema"), "tee": d.get("tee"), "sealer": d.get("sealer"), "name": d.get("name"), "sealed_bytes": len(d.get("sealed", ""))})
    except Exception as e:
        print(p, "not a sealed file:", type(e).__name__)
SHAPE

step "the quant's fine-tune: tiny base model built here, LoRA adapter trained by vg_genome, sealed by acpctl (design step 1)"
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
[ -n "$KID" ] || fail "seal: $(cat "$OUT/seal.err")"
( cd "$WORK" && tar czf base.tgz base ); sha256sum base.tgz genomes/gen-0.genome >> "$OUT/inputs.sha256"

step "hand-off to the standby through the bucket: its bundle, the base model, the sealed genome (opaque without its key), the authority's public key"
gcs_put dest-bundle.tgz handoff/dest-bundle.tgz || fail "upload the standby's bundle"
rm -f dest-bundle.tgz; echo "standby bundle removed from the bank host after hand-off" >> "$OUT/steps.txt"
gcs_put base.tgz handoff/base.tgz || fail "upload the base model"
gcs_put genomes/gen-0.genome handoff/gen-0.genome || fail "upload the genome"
gcs_put authority.pem handoff/authority.pem || fail "upload the authority key"
gcs_put "$OUT/seal.json" handoff/seal.json || fail "upload seal.json"
mark handoff_sent

step "sagvd on SEV-SNP"
./sagvd -config sagvd.json > "$OUT/sagvd.log" 2>&1 &
SAGVD=$!
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
echo "sagvd ready after ${n}s" >> "$OUT/steps.txt"

step "a thief with the sealed key files, off the chip: they do not open (ADR 0023)"
head -c 32 /dev/urandom > rogue.seed; chmod 600 rogue.seed
python3 - <<'PY'
import json
W = "/root/rd01"
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
timeout 30 ./acp-compute -config rogue-sealed.json > "$OUT/rogue-sealed-worker.log" 2>&1
echo "rogue with the sealed files exit=$? $(grep -o 'sealed to [a-z0-9-]*, this host is [a-z0-9-]*' "$OUT/rogue-sealed-worker.log" | head -1)" >> "$OUT/steps.txt"

step "a worker that is not the pinned identity: refused at the Return Path handshake, on the record"
./acp-compute -config rogue.json > "$OUT/rogue-worker.log" 2>&1 &
ROGUE=$!
n=0; until grep -q "sagvd return-path handshake failed" "$OUT/sagvd.log" || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
if grep -q "sagvd return-path handshake failed" "$OUT/sagvd.log"; then echo "rogue refused after ${n}s" >> "$OUT/steps.txt"; else echo "rogue NOT refused within ${n}s" >> "$OUT/steps.txt"; fi
kill -TERM $ROGUE 2>/dev/null; wait $ROGUE 2>/dev/null

step "acp-compute on SEV-SNP, the real door: the handshake with the chip's report (design step 3)"
./acp-compute -config worker.json > "$OUT/acp-compute.log" 2>&1 &
WORKER=$!
n=0; until curl -sf http://127.0.0.1:9082/healthz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
n=0; until grep -q "sagvd session opened" "$OUT/sagvd.log" || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
echo "session opened after ${n}s" >> "$OUT/steps.txt"
mark session_opened
grep -m1 '"msg":"sagvd session opened"' "$OUT/sagvd.log" > "$OUT/session-opened.json" || true

step "the operator's gate job over the Return Path (design steps 2, 4, 5)"
TOKEN=$(cat "$WORK/api_token.operator")
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
    f.write("gate_level=%s door=%s rung=%s fixtures=%s n_exact=%s max_abs_err=%s signer=%s request_id=%s session_id=%s\n" % (
        g.get("level"), g.get("door"), g.get("rung"), g.get("fixtures"), v.get("n_exact"), v.get("max_abs_err"), g.get("signer_key_id"), j.get("request_id"), j.get("session_id")))
PY
unset TOKEN

step "the continuity: wait for the standby's identity (its chip's measurement, for the allow-list)"
for i in $(seq 1 150); do gcs_exists handoff/standby.json && break; sleep 10; done
gcs_get handoff/standby.json standby.json || fail "no standby identity after 25 minutes"
mark standby_identity_received
cp standby.json "$OUT/standby.json"
B_ENDPOINT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["endpoint"])' standby.json)
B_MEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["identity"]["measurement_hex"])' standby.json)
echo "standby_endpoint=$B_ENDPOINT" >> "$OUT/steps.txt"; echo "standby_measurement=$B_MEAS" >> "$OUT/steps.txt"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["identity"]; print("standby crypto_profile=%s kem_suites=%s" % (d.get("crypto_profile"), ",".join(d.get("kem_suites") or [])))' standby.json >> "$OUT/steps.txt" 2>&1

step "the genome's key released to the standby in region B, only after its chip attested (the allow-list, the report against the AMD chain)"
write_policy "$B_MEAS" "$B_MEAS"
mark release_start
./sagvd crosscloud-restore -config sagvd.json -decision-id rd01-decision-1 -destination-kind gcp-sev-snp \
  -destination-endpoint "$B_ENDPOINT" -key-file "$KID:$WORK/genomes/gen-0.key" > "$OUT/release.json" 2> "$OUT/release.err"
echo "release exit=$?" >> "$OUT/steps.txt"
mark release_end
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("release suite=%s" % d.get("recipient_key_suite")); print("release profile=%s" % d.get("crypto_profile")); print("release recipient_key_sha256=%s" % d.get("recipient_key_sha256"))' "$OUT/release.json" >> "$OUT/steps.txt" 2>&1 || echo "release: $(tail -2 "$OUT/release.err")" >> "$OUT/steps.txt"

step "the standby restores by itself; the restore confirmed from its chip-signed receipt"
./sagvd crosscloud-confirm -config sagvd.json -decision-id rd01-decision-1 \
  -destination-endpoint "$B_ENDPOINT" -bundle genomes/gen-0.genome -wait 180s > "$OUT/confirm.json" 2> "$OUT/confirm.err"
echo "confirm exit=$?" >> "$OUT/steps.txt"
mark confirm_end
head -c 32 /dev/urandom > throwaway.key; chmod 600 throwaway.key

step "release refused: a guest not on the allow-list"
OTHER=$(printf '%096d' 0 | tr 0 a)
write_policy "$OTHER" "$B_MEAS"
./sagvd crosscloud-restore -config sagvd.json -decision-id rd01-decision-2 -destination-kind gcp-sev-snp \
  -destination-endpoint "$B_ENDPOINT" -key-file "genome-dek-2:$WORK/throwaway.key" > "$OUT/release-unlisted.json" 2> "$OUT/release-unlisted.err"
echo "unlisted exit=$? $(grep -oE 'policy denied key release: [a-z -]*' "$OUT/release-unlisted.err" | head -1)" >> "$OUT/steps.txt"

step "release refused: the operator's stop in force"
write_policy "$B_MEAS" "$B_MEAS"   # the standby allow-listed again; only the stop refuses it
./acpctl stop issue -key operator.seed -kid operator-1 -serial 2 -all -reason "rd01: operator stop" -out stop.json > /dev/null
./sagvd crosscloud-restore -config sagvd.json -decision-id rd01-decision-3 -destination-kind gcp-sev-snp \
  -destination-endpoint "$B_ENDPOINT" -key-file "genome-dek-3:$WORK/throwaway.key" > "$OUT/release-stopped.json" 2> "$OUT/release-stopped.err"
echo "stopped exit=$? $(grep -oE 'policy denied key release: [a-z -]*' "$OUT/release-stopped.err" | head -1)" >> "$OUT/steps.txt"
mark refusals_done

step "metrics; stop both; both audit logs verified with the published key (design step 6, here first)"
curl -s http://127.0.0.1:9081/metrics | grep -E "^(sagvd|rp|vg_tee)_" > "$OUT/sagvd-metrics.txt"
curl -s http://127.0.0.1:9082/metrics | grep -E "^(acp_compute|rp)_" > "$OUT/acp-compute-metrics.txt"
kill -TERM $WORKER; wait $WORKER 2>/dev/null
kill -TERM $SAGVD; wait $SAGVD 2>/dev/null
./acpctl audit verify --audit audit/returnpath-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-e2e --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"
echo "audit verify exit=$?" >> "$OUT/steps.txt"
./acpctl audit query --audit audit/returnpath-audit.db --limit 0 --json > "$OUT/audit-events.jsonl" 2> "$OUT/audit-query.err"
echo "audit query exit=$?" >> "$OUT/steps.txt"
./acpctl audit verify --audit xcc-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-e2e --json > "$OUT/xcc-audit-verify.json" 2> "$OUT/xcc-audit-verify.err"
echo "xcc audit verify exit=$?" >> "$OUT/steps.txt"
./acpctl audit query --audit xcc-audit.db --limit 0 --json > "$OUT/xcc-audit-events.jsonl" 2> "$OUT/xcc-audit-query.err"
echo "xcc audit query exit=$?" >> "$OUT/steps.txt"
grep -o '"handshake_ms":[0-9]*' "$OUT/sagvd.log" | cut -d: -f2 > "$OUT/sagvd.handshake_ms.txt"

step "hand the record to the third party: both audit logs, the published audit key, the job's view"
mkdir -p third-party && cp audit/returnpath-audit.db xcc-audit.db third-party/ && cp audit.pem third-party/audit-public-key.pem && cp "$OUT/job.json" third-party/job.json
for f in returnpath-audit.db xcc-audit.db audit-public-key.pem job.json; do gcs_put "third-party/$f" "handoff/third-party/$f" || fail "upload $f"; done
mark third_party_handed_off
emit DONE
