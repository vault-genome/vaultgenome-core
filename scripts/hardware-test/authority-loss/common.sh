# shellcheck shell=bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Shared by the authority-loss drill's VM startup scripts (sourced by
# authority-a.sh and authority-b.sh): metadata, GCS through the JSON API
# with the VM's own token, the worker's runtime from the hash-pinned locks,
# the pair of configs, the identities, the daemons and the gate job.

md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }
# The cryptographic profile of ADR 0029 both authorities run under, and the
# KEM suite that profile writes (the escrow and recovery keys are made under it).
PROFILE=$(md attributes/vg-profile 2>/dev/null); [ -n "$PROFILE" ] || PROFILE=general
case "$PROFILE" in fips) SUITE=hpke-p384-v1;; cnsa) SUITE=hpke-mlkem1024-p384-v1;; *) SUITE=hpke-x25519-v1;; esac
export PROFILE SUITE
token() { md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'; }
enc() { python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

gcs_get() { # gcs_get <object> <file>
  curl -sSf -H "Authorization: Bearer $(token)" -o "$2" \
    "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$(enc "$1")?alt=media"
}
gcs_put() { # gcs_put <file> <object>
  curl -sSf -X POST -H "Authorization: Bearer $(token)" -H "Content-Type: application/octet-stream" \
    --data-binary @"$1" "https://storage.googleapis.com/upload/storage/v1/b/$BUCKET/o?uploadType=media&name=$(enc "$2")" > /dev/null
}
gcs_put_str() { printf '%s' "$2" > /tmp/_s.$$; gcs_put /tmp/_s.$$ "$1"; rm -f /tmp/_s.$$; }
gcs_list() { # gcs_list <prefix>: object names, one per line
  curl -sSf -H "Authorization: Bearer $(token)" \
    "https://storage.googleapis.com/storage/v1/b/$BUCKET/o?prefix=$(enc "$1")&fields=items/name" \
    | python3 -c 'import json,sys; [print(i["name"]) for i in json.load(sys.stdin).get("items", [])]'
}

# The worker's runtime from the hash-pinned locks, each from its own index
# (requirements-ci.lock from PyPI, the torch CPU wheel from the PyTorch
# index), into /opt/vg; pip's logs are the record of what was installed.
python_runtime() {
  export DEBIAN_FRONTEND=noninteractive
  systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
  for i in $(seq 1 60); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 5; done
  # A mirror that answers but trickles (one run saw 10 KB/s for a quarter
  # of an hour) would stall the drill: apt gives up on a silent connection
  # after 30 s and retries, and pip the same.
  local APT="apt-get -o DPkg::Lock::Timeout=300 -o Acquire::http::Timeout=30 -o Acquire::Retries=3"
  $APT update -qq > /dev/null && $APT install -y -qq python3-venv python3-pip > /dev/null
  python3 -m venv /opt/vg
  /opt/vg/bin/pip install --timeout 60 --retries 5 --require-hashes --only-binary=:all: --index-url https://pypi.org/simple -r /opt/worker/requirements-ci.lock > "$OUT/pip-requirements.log" 2>&1
  /opt/vg/bin/pip install --timeout 60 --retries 5 --require-hashes --only-binary=:all: --no-deps --index-url https://download.pytorch.org/whl/cpu -r /opt/worker/requirements-torch-cpu.lock > "$OUT/pip-torch.log" 2>&1
  /opt/vg/bin/python -c 'import torch, transformers; print("torch", torch.__version__, "transformers", transformers.__version__)' > "$OUT/runtime.txt" 2>&1
}

# configfs-tsm: the kernel's path to the chip's attestation report.
tsm() {
  modprobe sev-guest 2>/dev/null || {
    apt-get -o DPkg::Lock::Timeout=300 install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
    modprobe sev-guest 2>/dev/null || true
  }
  mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
  local n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
  { ls -la /sys/kernel/config/tsm/report 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail -20; } > "$OUT/tsm.txt"
}

# write_configs <work dir> <vault measurement hex> <worker measurement hex>:
# the same pair of configs the Return Path kit uses, both daemons on this
# guest, each pinning the other's launch measurement.
write_configs() {
  python3 - "$1" "$2" "$3" "${PROFILE:-general}" <<'PY'
import json, sys, binascii
W, vault_meas, worker_meas, profile = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
S = W + "/secrets"
open(W + "/peer-vault.meas", "wb").write(binascii.unhexlify(vault_meas))
open(W + "/peer-worker.meas", "wb").write(binascii.unhexlify(worker_meas))
peer = lambda meas: {"provider": "gcp-sev-snp", "measurement_path": meas, "amd_cert_chain_path": W + "/amd-milan-cert_chain.pem", "vcek_cache_dir": W + "/vcek-cache"}
sagvd = {
  "vault": {"listen_address": "127.0.0.1:9443",
    "tls": {"enabled": True, "server_cert": S + "/sagvd/tls/server.crt", "server_key": S + "/sagvd/tls/server.key", "client_cas": S + "/shared/tls/ca.crt"}},
  "http_api": {"listen_address": "127.0.0.1:9080", "bearer_token_file": S + "/sagvd/api_token"},
  "tee": {"provider": "gcp-sev-snp", "workload_descriptor": "sagvd-authority-loss-v1", "peer": peer(W + "/peer-worker.meas")},
  "keys": {"authority_signing": {"kid": "sagvd-authority-drill", "seed_path": S + "/sagvd/authority_signing_seed"},
           "audit_signing": {"kid": "sagvd-audit-drill", "seed_path": S + "/sagvd/audit_signing_seed"},
           "session_sealing": {"kid": "session-sealing-drill", "material_path": S + "/shared/sealing.key"}},
  "workers": {"registry_path": S + "/shared/workers.json"},
  "genome": {"bundle_dir": W + "/genomes", "gate": {"atol": 1e-2, "rtol": 1e-3, "max_non_critical_outliers": 0}},
  "audit": {"log_path": W + "/audit/returnpath-audit.db"},
  "queue": {"path": W + "/queue/sagvd-jobs.db", "max_resume_attempts": 3},
  "runtime": {"job_timeout_seconds": 600, "handshake_timeout_seconds": 30, "queue_poll_ms": 50,
    "http_read_header_timeout_seconds": 5, "http_write_timeout_seconds": 30, "default_job_deadline_seconds": 600, "max_payload_bytes": 4194304},
  "health": {"listen_address": "127.0.0.1:9081"},
  "log": {"level": "info", "format": "json"},
  "crypto": {"profile": profile}}
worker = {
  "vault": {"address": "127.0.0.1:9443",
    "tls": {"enabled": True, "client_cert": S + "/acp-compute/tls/client.crt", "client_key": S + "/acp-compute/tls/client.key", "ca_bundle": S + "/shared/tls/ca.crt", "server_name": "localhost"}},
  "tee": {"provider": "gcp-sev-snp", "workload_descriptor": "acp-compute-authority-loss-v1", "peer": peer(W + "/peer-vault.meas")},
  "keys": {"worker_signing": {"kid": "acp-compute-worker-demo", "seed_path": S + "/acp-compute/worker_signing_seed"},
           "session_sealing": {"kid": "session-sealing-drill", "material_path": S + "/shared/sealing.key"}},
  "genome": {"door": {"command": ["/opt/vg/bin/python3", "-m", "vg_genome", "door", "--stdin-genome", "--base", W + "/base", "--device", "cpu"],
                      "env": ["PYTHONPATH=/opt/worker", "TOKENIZERS_PARALLELISM=false"], "timeout_seconds": 300}},
  "runtime": {"job_timeout_seconds": 600, "handshake_timeout_seconds": 30, "dial_backoff_initial_ms": 500, "dial_backoff_max_ms": 5000, "idle_between_jobs_ms": 200},
  "health": {"listen_address": "127.0.0.1:9082"},
  "log": {"level": "info", "format": "json"}}
json.dump(sagvd, open(W + "/sagvd.json", "w"), indent=2)
json.dump(worker, open(W + "/worker.json", "w"), indent=2)
PY
}

# identities <work dir>: each daemon reads its launch measurement from the
# chip; the configs are rewritten with the two measurements; the audit
# public key goes to audit.pem.
identities() {
  local W=$1
  local Z; Z=$(printf '%096d' 0)
  write_configs "$W" "$Z" "$Z"
  sagvd identity -config "$W/sagvd.json" > "$OUT/sagvd-identity.json" 2> "$OUT/sagvd-identity.err"; echo "sagvd identity exit=$?" >> "$OUT/steps.txt"
  acp-compute identity -config "$W/worker.json" > "$OUT/acp-compute-identity.json" 2> "$OUT/acp-compute-identity.err"; echo "acp-compute identity exit=$?" >> "$OUT/steps.txt"
  VMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/sagvd-identity.json")
  WMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/acp-compute-identity.json")
  echo "vault_measurement=$VMEAS" >> "$OUT/steps.txt"; echo "worker_measurement=$WMEAS" >> "$OUT/steps.txt"
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["audit_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > "$W/audit.pem"
  python3 -c 'import json,sys,hashlib; d=json.load(open(sys.argv[1])); print("authority_public_key sha256=%s audit_public_key sha256=%s" % tuple(hashlib.sha256(d.get(k, "").encode()).hexdigest()[:16] for k in ("authority_public_key_pem", "audit_public_key_pem")))' "$OUT/sagvd-identity.json" >> "$OUT/steps.txt" 2>/dev/null || true
  write_configs "$W" "$VMEAS" "$WMEAS"
}

# start_daemons <work dir>: sagvd, then the worker; the session opens. Each
# daemon is exec'd in its own backgrounded subshell, so the pid file holds
# the daemon's pid — a `cd && daemon &` list would record the list's
# subshell, and a signal to it would leave the daemon running with the
# audit file's lock.
start_daemons() {
  local W=$1 n
  ( cd "$W" && exec sagvd -config sagvd.json > "$OUT/sagvd.log" 2>&1 ) & echo $! > /root/sagvd.pid
  n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
  echo "sagvd ready after ${n}s" >> "$OUT/steps.txt"
  ( cd "$W" && exec acp-compute -config worker.json > "$OUT/acp-compute.log" 2>&1 ) & echo $! > /root/worker.pid
  n=0; until grep -q "sagvd session opened" "$OUT/sagvd.log" || [ $n -ge 120 ]; do sleep 1; n=$((n+1)); done
  echo "session opened after ${n}s" >> "$OUT/steps.txt"
}

# gate_job <work dir> <label>: submit a gate job for gen-0 and wait for its
# verdict; the job's view is kept as job-<label>.json. The API token is the
# operator's copy (api_token.operator, taken before seal-keys sealed the
# daemon's file to the chip — ADR 0023: the plaintext is the operator's to
# keep), the same copy the safe holds. A script that defines after_submit
# <label> <job id> has it run once the job is accepted, before the wait:
# authority A replicates the job store there, so the replica carries the
# job while it runs. A job's deadline counts from its dispatch to a worker
# (cmd/sagvd/daemon.go), so a job resumed on a new host has its whole
# window there, however long the host took to come up.
gate_job() {
  local W=$1 label=$2 TOKEN JOB
  TOKEN=$(cat "$W/api_token.operator")
  curl -s -o "$OUT/job-$label-submit.json" -w '%{http_code}\n' -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    --data '{"genome":{"bundle":"gen-0.genome","key_file":"gen-0.key"},"deadline_seconds_from_now":300}' http://127.0.0.1:9080/v1/jobs > "$OUT/job-$label-submit.status"
  unset TOKEN
  JOB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["job_id"])' "$OUT/job-$label-submit.json" 2>/dev/null || echo "")
  if declare -F after_submit >/dev/null; then after_submit "$label" "$JOB"; fi
  wait_job "$W" "$label" "$JOB"
}

# wait_job <work dir> <label> <job id>: wait for the job's verdict (up to
# 300 s); the view is kept as job-<label>.json, the outcome in steps.txt.
wait_job() {
  local W=$1 label=$2 JOB=$3 TOKEN ST i
  TOKEN=$(cat "$W/api_token.operator")
  ST=""
  for i in $(seq 1 300); do
    sleep 1
    curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9080/v1/jobs/$JOB" > "$OUT/job-$label.json"
    ST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$OUT/job-$label.json" 2>/dev/null || echo "")
    [ "$ST" = succeeded ] || [ "$ST" = failed ] && break
  done
  unset TOKEN
  python3 - "$OUT/job-$label.json" "$label" "$i" >> "$OUT/steps.txt" <<'PY'
import json, sys
j = json.load(open(sys.argv[1])); g = j.get("gate") or {}; v = (g.get("signed_verdict") or {}).get("verdict") or {}
flow = j.get("flow") or {}
print("job %s id=%s request_id=%s status=%s after %ss gate=%s n_exact=%s tip=%s" % (sys.argv[2], j.get("job_id"), j.get("request_id"), j.get("status"), sys.argv[3], g.get("level"), v.get("n_exact"), flow.get("chain_tip") or flow.get("audit_tip") or ""))
PY
  [ "$ST" = succeeded ]
}
