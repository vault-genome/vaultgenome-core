#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The Return Path on an Azure AMD SEV-SNP Confidential VM (Ubuntu 24.04,
# a Standard_DC4as_v5 or kin), run as root by the kit's runner over ssh.
#
# Both daemons attest as azure-sev-snp (ADR 0025, plan item 4): the chip's
# SEV-SNP report from the vTPM's HCL report, bound to each handshake's
# challenge by a TPM quote under the vTPM's attestation key — the Azure
# guest has no /dev/sev-guest and no configfs-tsm — and each pins the
# other's launch measurement; every key file is sealed to the vTPM (ADR
# 0023, the tpm2 sealer of ADR 0022). Otherwise as
# gcp-sev-snp/returnpath-e2e/cvm-returnpath.sh: the real vg_genome worker
# fine-tunes a genome on this guest, acpctl seals it, a gate job goes over
# the Return Path, acp-compute restores the model in memory through the
# door and answers, sagvd judges the answer and puts every decision on its
# signed audit log; a worker whose Evidence is not the pinned identity is
# refused, and the refusal recorded; a copy of the sealed key files is no
# key at all off this host.
#
# Inputs: /home/<admin>/in/{sagvd,acp-compute,acpctl,keygen,genome-worker.tgz},
# put there by the runner; the AMD chain of the chip's product is fetched
# from AMD KDS by acpctl, which verifies it against the pinned roots. The
# product is read from the report itself. Output: /home/<admin>/results.tgz
# — reports, job views, identities and logs only; keys, seeds, tokens and
# configs stay on the VM and die with it.
set -u
exec > >(tee -a /root/e2e.log) 2>&1
ADMIN_HOME="${1:?usage: cvm-returnpath-azure.sh <admin home dir>}"; IN="$ADMIN_HOME/in"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=/root/e2e; OUT=$WORK/out/$STAMP; mkdir -p "$OUT"; cd "$WORK"
SEALER=auto   # on an Azure guest auto resolves to the vTPM (tpm2, ADR 0022): the paravisor gives no derived key
{ echo "instance=$(hostname)"; echo "location=$(curl -s -H Metadata:true 'http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text')"; echo "machine=$(curl -s -H Metadata:true 'http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2021-02-01&format=text')"; echo "captured=$STAMP"; } > "$OUT/metadata.txt"
uname -a > "$OUT/kernel.txt"
T0=$(date +%s.%N)
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }

step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }

step "binaries from $IN"
for f in sagvd acp-compute acpctl keygen genome-worker.tgz; do cp "$IN/$f" "$WORK/$f"; done
chmod +x sagvd acp-compute acpctl keygen
./sagvd version > "$OUT/versions.txt"; ./acp-compute version >> "$OUT/versions.txt"; ./acpctl version >> "$OUT/versions.txt" 2>/dev/null || true
./keygen -version >> "$OUT/versions.txt" 2>/dev/null || true
sha256sum sagvd acp-compute acpctl keygen genome-worker.tgz > "$OUT/inputs.sha256"
mkdir -p workers && tar xzf genome-worker.tgz -C workers

step "tpm2-tools; the HCL report from the vTPM; the chip's product from the report"
export DEBIAN_FRONTEND=noninteractive
for i in $(seq 1 60); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 5; done
apt-get update -qq >/dev/null 2>&1; apt-get -o DPkg::Lock::Timeout=300 install -y -qq tpm2-tools >/dev/null 2>&1
{ ls -la /dev/tpm0 /dev/tpmrm0 2>&1; tpm2_nvreadpublic 2>&1 | grep -A3 0x1400001; ls /dev/sev-guest /sys/kernel/config/tsm 2>&1; } > "$OUT/vtpm.txt" 2>&1
tpm2_nvread -C o 0x1400001 -o hcl-report.bin 2> "$OUT/hcl-nvread.err"; echo "hcl nvread exit=$? bytes=$(stat -c%s hcl-report.bin 2>/dev/null)" >> "$OUT/steps.txt"
# The product line decides the chain: the report's CPUID family and model (report version 3 and later), as the capture kit reads them.
PRODUCT=$(python3 - hcl-report.bin <<'PY'
import sys
b = open(sys.argv[1], "rb").read()
assert b[:4] == b"HCLA", "not an HCL report"
r = b[32:32 + 1184]
version = int.from_bytes(r[0:4], "little")
if version < 3:
    sys.exit("report version %d carries no CPUID family" % version)
fam, mod = r[0x188], r[0x189]
if fam == 0x19 and mod <= 0x0F: print("milan")
elif fam == 0x19 and (0x10 <= mod <= 0x1F or 0xA0 <= mod <= 0xAF): print("genoa")
elif fam == 0x1A and mod <= 0x11: print("turin")
else: sys.exit("CPUID family 0x%02x model 0x%02x: not a known SEV-SNP product line" % (fam, mod))
PY
)
echo "product=$PRODUCT" >> "$OUT/steps.txt"; echo "$PRODUCT" > "$OUT/product.txt"
./acpctl tee fetch-amd-chain --product "$PRODUCT" --out amd-cert_chain.pem > "$OUT/amd-chain.txt" 2>&1 || echo "fetch-amd-chain failed: $(cat "$OUT/amd-chain.txt")"
sha256sum amd-cert_chain.pem hcl-report.bin >> "$OUT/inputs.sha256"

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

echo "sealer=$SEALER" >> "$OUT/steps.txt"
step "provision (acp-keygen, private modes; every key file is sealed to the chip below)"
./keygen -out secrets -quiet -private
S=$WORK/secrets
mkdir -p genomes audit queue vcek-cache
# The pins are filled in from each daemon's identity below; identity needs
# a config that validates, so the pin files start out as placeholders.
head -c 48 /dev/zero > peer-vault.meas; head -c 48 /dev/zero > peer-worker.meas

write_configs() { # $1/$2 = vault/worker measurement hex, $3/$4 = vault/worker boot (the vTPM's PCR digest)
  python3 - "$1" "$2" "$SEALER" "$3" "$4" <<'PY'
import json, sys, binascii
vault_meas, worker_meas, SEALER, vault_boot, worker_boot = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
W = "/root/e2e"; S = W + "/secrets"
open(W + "/peer-vault.meas", "wb").write(binascii.unhexlify(vault_meas))
open(W + "/peer-worker.meas", "wb").write(binascii.unhexlify(worker_meas))
sagvd = {
  "vault": {"listen_address": "127.0.0.1:9443",
    "tls": {"enabled": True, "server_cert": S + "/sagvd/tls/server.crt", "server_key": S + "/sagvd/tls/server.key", "client_cas": S + "/shared/tls/ca.crt"}},
  "http_api": {"listen_address": "127.0.0.1:9080", "bearer_token_file": S + "/sagvd/api_token"},
  "tee": {"provider": "auto", "sealer": SEALER, "workload_descriptor": "sagvd-returnpath-e2e-v1",
    "peer": {"provider": "azure-sev-snp", "measurement_path": W + "/peer-worker.meas", "pcr_digests": [worker_boot],
             "amd_cert_chain_path": W + "/amd-cert_chain.pem", "vcek_cache_dir": W + "/vcek-cache"}},
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
    "peer": {"provider": "azure-sev-snp", "measurement_path": W + "/peer-vault.meas", "pcr_digests": [vault_boot],
             "amd_cert_chain_path": W + "/amd-cert_chain.pem", "vcek_cache_dir": W + "/vcek-cache"}},
  "keys": {"worker_signing": {"kid": "acp-compute-worker-demo", "seed_path": S + "/acp-compute/worker_signing_seed"},
           "session_sealing": {"kid": "session-sealing-e2e", "material_path": S + "/shared/sealing.key"}},
  "genome": {"door": {"command": [W + "/venv/bin/python3", "-m", "vg_genome", "door", "--stdin-genome", "--base", W + "/base", "--device", "cpu"],
                      "env": ["PYTHONPATH=" + W + "/workers/genome", "TOKENIZERS_PARALLELISM=false"], "timeout_seconds": 300}},
  "runtime": {"job_timeout_seconds": 600, "handshake_timeout_seconds": 30, "dial_backoff_initial_ms": 500, "dial_backoff_max_ms": 5000, "idle_between_jobs_ms": 200},
  "health": {"listen_address": "127.0.0.1:9082"},
  "log": {"level": "info", "format": "json"}}
json.dump(sagvd, open(W + "/sagvd.json", "w"), indent=2)
json.dump(worker, open(W + "/worker.json", "w"), indent=2)
PY
}
ZEROS=$(printf '%096d' 0); BOOT0=$(printf '%064d' 0)
write_configs "$ZEROS" "$ZEROS" "$BOOT0" "$BOOT0"

step "identities: each daemon reads its launch measurement from the chip's report in the vTPM, and what the vTPM measured of this boot"
./sagvd identity -config sagvd.json > "$OUT/sagvd-identity.json" 2> "$OUT/sagvd-identity.err"; echo "sagvd identity exit=$?" >> "$OUT/steps.txt"
./acp-compute identity -config worker.json > "$OUT/acp-compute-identity.json" 2> "$OUT/acp-compute-identity.err"; echo "acp-compute identity exit=$?" >> "$OUT/steps.txt"
VMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/sagvd-identity.json" 2>/dev/null)
WMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/acp-compute-identity.json" 2>/dev/null)
VBOOT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vtpm"]["pcr_digest_hex"])' "$OUT/sagvd-identity.json" 2>/dev/null)
WBOOT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vtpm"]["pcr_digest_hex"])' "$OUT/acp-compute-identity.json" 2>/dev/null)
echo "vault_measurement=$VMEAS" >> "$OUT/steps.txt"; echo "worker_measurement=$WMEAS" >> "$OUT/steps.txt"
echo "vault_boot=$VBOOT" >> "$OUT/steps.txt"; echo "worker_boot=$WBOOT" >> "$OUT/steps.txt"
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["audit_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > audit.pem
# Both daemons share this guest, so both measurements are the launch
# measurement of this VM and both boots this boot; each pins the other's,
# the boot required — the launch measurement is Azure's paravisor and
# firmware and says nothing of the OS (ADR 0037).
write_configs "$VMEAS" "$WMEAS" "$VBOOT" "$WBOOT"

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

step "sagvd on Azure SEV-SNP"
./sagvd -config sagvd.json > "$OUT/sagvd.log" 2>&1 &
SAGVD=$!
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
echo "sagvd ready after ${n}s" >> "$OUT/steps.txt"

step "a thief with the sealed key files, off this vTPM: they do not open (ADR 0023; tee.sealer=$SEALER, the vTPM)"
# The worker's own key files, as they sit on disk after seal-keys, in the
# hands of a process whose TEE is the simulated one: the seal names the
# chip, and the files are refused before any key is read. A hang here
# would mean they opened; timeout makes that an exit code on the record.
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
# The same rogue with the plaintext copies taken before sealing.
c["keys"]["worker_signing"]["seed_path"] = W + "/rogue/worker_signing_seed"
c["keys"]["session_sealing"]["material_path"] = W + "/rogue/sealing.key"
c["vault"]["tls"]["client_key"] = W + "/rogue/client.key"
json.dump(c, open(W + "/rogue.json", "w"), indent=2)
PY
timeout 30 ./acp-compute -config rogue-sealed.json > "$OUT/rogue-sealed-worker.log" 2>&1
echo "rogue with the sealed files exit=$? $(grep -o 'sealed to [a-z0-9-]*, this host is [a-z0-9-]*' "$OUT/rogue-sealed-worker.log" | head -1)" >> "$OUT/steps.txt"

step "a worker that is not the pinned identity: refused at the Return Path handshake, on the record"
# Same certificate, same signing key, same sealing key — the plaintext
# copies — and a different attestation: the simulated TEE. sagvd's pin is
# the chip's measurement; this Evidence is not it.
./acp-compute -config rogue.json > "$OUT/rogue-worker.log" 2>&1 &
ROGUE=$!
n=0; until grep -q "sagvd return-path handshake failed" "$OUT/sagvd.log" || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
if grep -q "sagvd return-path handshake failed" "$OUT/sagvd.log"; then echo "rogue refused after ${n}s" >> "$OUT/steps.txt"; else echo "rogue NOT refused within ${n}s" >> "$OUT/steps.txt"; fi
kill -TERM $ROGUE 2>/dev/null; wait $ROGUE 2>/dev/null

step "a worker whose boot is not the one pinned: refused at the handshake (ADR 0037)"
# The real worker — its chip, its measurement, its key files — against a
# second sagvd whose policy names another boot: one hex digit of this
# boot's digest changed. The launch measurement matches; the vTPM's quote
# of the boot does not, and the handshake is refused on that.
python3 - "$WBOOT" >> "$OUT/steps.txt" <<'PY'
import json, sys
W = "/root/e2e"
boot = sys.argv[1]
other = ("1" if boot[0] == "0" else "0") + boot[1:]
s = json.load(open(W + "/sagvd.json"))
s["vault"]["listen_address"] = "127.0.0.1:9543"
s["http_api"]["listen_address"] = "127.0.0.1:9180"
s["health"]["listen_address"] = "127.0.0.1:9181"
s["audit"]["log_path"] = W + "/audit/otherboot-audit.db"
s["queue"]["path"] = W + "/queue/otherboot-jobs.db"
s["tee"]["peer"]["pcr_digests"] = [other]
json.dump(s, open(W + "/sagvd-otherboot.json", "w"), indent=2)
c = json.load(open(W + "/worker.json"))
c["vault"]["address"] = "127.0.0.1:9543"
c["health"]["listen_address"] = "127.0.0.1:9183"
json.dump(c, open(W + "/worker-otherboot.json", "w"), indent=2)
print("other_boot=" + other)
PY
./sagvd -config sagvd-otherboot.json > "$OUT/sagvd-otherboot.log" 2>&1 &
OTHER=$!
n=0; until curl -sf http://127.0.0.1:9181/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
./acp-compute -config worker-otherboot.json > "$OUT/worker-otherboot.log" 2>&1 &
OTHERW=$!
n=0; until grep -q "is not in the acceptable set" "$OUT/sagvd-otherboot.log" || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
if grep -q "sagvd return-path handshake failed" "$OUT/sagvd-otherboot.log" && grep -q "PCR digest [0-9a-f]* is not in the acceptable set" "$OUT/sagvd-otherboot.log"; then
  echo "other boot refused after ${n}s: $(grep -o 'PCR digest [0-9a-f]* is not in the acceptable set' "$OUT/sagvd-otherboot.log" | head -1)" >> "$OUT/steps.txt"
else
  echo "other boot NOT refused within ${n}s" >> "$OUT/steps.txt"
fi
kill -TERM $OTHERW 2>/dev/null; wait $OTHERW 2>/dev/null
kill -TERM $OTHER 2>/dev/null; wait $OTHER 2>/dev/null

step "acp-compute on Azure SEV-SNP, the real door"
./acp-compute -config worker.json > "$OUT/acp-compute.log" 2>&1 &
WORKER=$!
n=0; until curl -sf http://127.0.0.1:9082/healthz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
n=0; until grep -q "sagvd session opened" "$OUT/sagvd.log" || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
echo "session opened after ${n}s" >> "$OUT/steps.txt"

step "the gate job over the Return Path"
TOKEN=$(cat "$WORK/api_token.operator")
mark job_submit
curl -s -o "$OUT/job-submit.json" -w '%{http_code}\n' -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"genome":{"bundle":"gen-0.genome","key_file":"gen-0.key"},"deadline_seconds_from_now":300}' http://127.0.0.1:9080/v1/jobs > "$OUT/job-submit.status"
JOB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["job_id"])' "$OUT/job-submit.json" 2>/dev/null)
echo "job_id=$JOB" >> "$OUT/steps.txt"
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

step "stop both; verify the audit log with the published key"
kill -TERM $WORKER; wait $WORKER 2>/dev/null
kill -TERM $SAGVD; wait $SAGVD 2>/dev/null
./acpctl audit verify --audit audit/returnpath-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-e2e --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"
echo "audit verify exit=$?" >> "$OUT/steps.txt"
./acpctl audit query --audit audit/returnpath-audit.db --limit 0 --json > "$OUT/audit-events.jsonl" 2> "$OUT/audit-query.err"
echo "audit query exit=$?" >> "$OUT/steps.txt"
cp audit.pem "$OUT/audit-public-key.pem"
python3 -c 'import sys,time; t0=float(sys.argv[1]); print("elapsed_seconds=%.1f" % (time.time()-t0))' "$T0" >> "$OUT/steps.txt"

cp /root/e2e.log "$OUT/console.log"
( cd "$OUT" && sha256sum * > "$WORK/sha256sums.txt" ); mv "$WORK/sha256sums.txt" "$OUT/"

echo "== emit"   # not via step: steps.txt is already under sha256sums.txt
cd "$WORK/out" && tar czf "$STAMP.tgz" "$STAMP" && cp "$STAMP.tgz" "$ADMIN_HOME/results.tgz" && echo "$STAMP" > "$ADMIN_HOME/results.stamp"
chown "$(stat -c%U "$ADMIN_HOME")" "$ADMIN_HOME/results.tgz" "$ADMIN_HOME/results.stamp"
echo "E2E DONE $STAMP sha256=$(sha256sum "$STAMP.tgz" | cut -d' ' -f1)"
