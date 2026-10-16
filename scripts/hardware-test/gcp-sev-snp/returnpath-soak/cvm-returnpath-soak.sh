#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script for a GCP AMD SEV-SNP Confidential VM (Ubuntu 24.04):
# the soak: one authority and N workers for an hour (P1-5).
#
# The same guest as returnpath-e2e up to the sealed genome; then the soak
# (P1-5): sagvd at max_sessions=N with N workers (vg-workers) and 2N jobs
# kept in flight for vg-soak-minutes (60). Every completion is recorded
# with its queue, run and total time from the job view's own timestamps;
# every minute the daemons' resident memory and open descriptors, the load
# and sagvd's session, queue, handshake-failure and refusal metrics are
# snapshotted; the long logs are kept by their sizes, their warnings and
# errors and their ends, and every handshake_ms; at the end the audit log
# of the whole soak is verified with the published key and counted by
# kind. Workers are the real door (CPU torch) and contend for the guest's
# cores: the numbers are one host's sustained rate, not an idealised one.
#
# Otherwise as returnpath-e2e/cvm-returnpath.sh:
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
SEALER=auto
WORKERS=$(md attributes/vg-workers 2>/dev/null || true); case "$WORKERS" in ''|*[!0-9]*) WORKERS=3;; esac
nproc > "$OUT/nproc.txt"; echo "workers=$WORKERS" >> "$OUT/steps.txt"
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

write_configs() { # $1 = vault measurement hex, $2 = worker measurement hex, $3 = max_sessions, $4 = number of worker configs
  python3 - "$1" "$2" "$SEALER" "${3:-1}" "${4:-1}" <<'PY'
import json, sys, binascii
vault_meas, worker_meas, SEALER = sys.argv[1], sys.argv[2], sys.argv[3]
MAX_SESSIONS, NWORKERS = int(sys.argv[4]), int(sys.argv[5])
W = "/root/e2e"; S = W + "/secrets"
open(W + "/peer-vault.meas", "wb").write(binascii.unhexlify(vault_meas))
open(W + "/peer-worker.meas", "wb").write(binascii.unhexlify(worker_meas))
sagvd = {
  "vault": {"listen_address": "127.0.0.1:9443",
    "tls": {"enabled": True, "server_cert": S + "/sagvd/tls/server.crt", "server_key": S + "/sagvd/tls/server.key", "client_cas": S + "/shared/tls/ca.crt"}},
  "http_api": {"listen_address": "127.0.0.1:9080", "bearer_token_file": S + "/sagvd/api_token"},
  "tee": {"provider": "auto", "sealer": SEALER, "workload_descriptor": "sagvd-returnpath-e2e-v1",
    "peer": {"provider": "gcp-sev-snp", "measurement_path": W + "/peer-worker.meas",
             "amd_cert_chain_path": W + "/amd-milan-cert_chain.pem", "vcek_cache_dir": W + "/vcek-cache"}},
  "keys": {"authority_signing": {"kid": "sagvd-authority-e2e", "seed_path": S + "/sagvd/authority_signing_seed"},
           "audit_signing": {"kid": "sagvd-audit-e2e", "seed_path": S + "/sagvd/audit_signing_seed"},
           "session_sealing": {"kid": "session-sealing-e2e", "material_path": S + "/shared/sealing.key"}},
  "workers": {"registry_path": S + "/shared/workers.json"},
  "genome": {"bundle_dir": W + "/genomes", "gate": {"atol": 1e-2, "rtol": 1e-3, "max_non_critical_outliers": 0}},
  "audit": {"log_path": W + "/audit/returnpath-audit.db"},
  "queue": {"path": W + "/queue/sagvd-jobs.db"},
  "runtime": {"job_timeout_seconds": 600, "handshake_timeout_seconds": 30, "queue_poll_ms": 50, "max_sessions": MAX_SESSIONS,
    "http_read_header_timeout_seconds": 5, "http_write_timeout_seconds": 30, "default_job_deadline_seconds": 600, "max_payload_bytes": 4194304},
  "health": {"listen_address": "127.0.0.1:9081"},
  "log": {"level": "info", "format": "json"}}
worker = {
  "vault": {"address": "127.0.0.1:9443",
    "tls": {"enabled": True, "client_cert": S + "/acp-compute/tls/client.crt", "client_key": S + "/acp-compute/tls/client.key", "ca_bundle": S + "/shared/tls/ca.crt", "server_name": "localhost"}},
  "tee": {"provider": "auto", "sealer": SEALER, "workload_descriptor": "acp-compute-returnpath-e2e-v1",
    "peer": {"provider": "gcp-sev-snp", "measurement_path": W + "/peer-vault.meas",
             "amd_cert_chain_path": W + "/amd-milan-cert_chain.pem", "vcek_cache_dir": W + "/vcek-cache"}},
  "keys": {"worker_signing": {"kid": "acp-compute-worker-demo", "seed_path": S + "/acp-compute/worker_signing_seed"},
           "session_sealing": {"kid": "session-sealing-e2e", "material_path": S + "/shared/sealing.key"}},
  "genome": {"door": {"command": [W + "/venv/bin/python3", "-m", "vg_genome", "door", "--stdin-genome", "--base", W + "/base", "--device", "cpu"],
                      "env": ["PYTHONPATH=" + W + "/workers/genome", "TOKENIZERS_PARALLELISM=false"], "timeout_seconds": 300}},
  "runtime": {"job_timeout_seconds": 600, "handshake_timeout_seconds": 30, "dial_backoff_initial_ms": 500, "dial_backoff_max_ms": 5000, "idle_between_jobs_ms": 200},
  "health": {"listen_address": "127.0.0.1:9082"},
  "log": {"level": "info", "format": "json"}}
json.dump(sagvd, open(W + "/sagvd-%d.json" % MAX_SESSIONS, "w"), indent=2)
json.dump(worker, open(W + "/worker.json", "w"), indent=2)
for i in range(1, NWORKERS + 1):
    w = json.loads(json.dumps(worker)); w["health"]["listen_address"] = "127.0.0.1:%d" % (9100 + i)
    json.dump(w, open(W + "/worker-%d.json" % i, "w"), indent=2)
PY
}
ZEROS=$(printf '%096d' 0)
write_configs "$ZEROS" "$ZEROS" 1 1
ln -sf sagvd-1.json sagvd.json

step "identities: each daemon reads its launch measurement from the chip"
./sagvd identity -config sagvd.json > "$OUT/sagvd-identity.json" 2> "$OUT/sagvd-identity.err"; echo "sagvd identity exit=$?" >> "$OUT/steps.txt"
./acp-compute identity -config worker.json > "$OUT/acp-compute-identity.json" 2> "$OUT/acp-compute-identity.err"; echo "acp-compute identity exit=$?" >> "$OUT/steps.txt"
VMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/sagvd-identity.json" 2>/dev/null)
WMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/acp-compute-identity.json" 2>/dev/null)
echo "vault_measurement=$VMEAS" >> "$OUT/steps.txt"; echo "worker_measurement=$WMEAS" >> "$OUT/steps.txt"
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["audit_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > audit.pem
# Both daemons share this guest, so both measurements are the launch
# measurement of this VM; each pins the other's.
write_configs "$VMEAS" "$WMEAS" 1 "$WORKERS"
write_configs "$VMEAS" "$WMEAS" "$WORKERS" "$WORKERS"
ln -sf sagvd-1.json sagvd.json

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
SOAK_MINUTES=$(md attributes/vg-soak-minutes 2>/dev/null || true); case "$SOAK_MINUTES" in ''|*[!0-9]*) SOAK_MINUTES=60;; esac
echo "soak_minutes=$SOAK_MINUTES" >> "$OUT/steps.txt"
step "soak: sagvd at max_sessions=$WORKERS, $WORKERS workers, jobs kept queued for $SOAK_MINUTES minutes"
./sagvd -config "sagvd-$WORKERS.json" > "$WORK/sagvd-soak.log" 2>&1 &
SAGVD=$!
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
echo "sagvd ready after ${n}s pid=$SAGVD" >> "$OUT/steps.txt"
PIDS=""
for i in $(seq 1 "$WORKERS"); do
  ./acp-compute -config "worker-$i.json" > "$WORK/acp-compute-soak-$i.log" 2>&1 &
  PIDS="$PIDS $!"
done
for i in $(seq 1 "$WORKERS"); do n=0; until curl -sf "http://127.0.0.1:$((9100 + i))/healthz" >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done; done
mark soak_start
# The soak loop: keep 2N jobs in flight, record every completion, snapshot the daemons every minute.
TOKEN="$TOKEN" python3 - "$SOAK_MINUTES" "$WORKERS" "$OUT" "$SAGVD" "$PIDS" <<'PY'
import json, os, sys, time, urllib.request, csv
minutes, workers, out, sagvd_pid, worker_pids = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5].split()
tok = os.environ["TOKEN"]; api = "http://127.0.0.1:9080"; metrics = "http://127.0.0.1:9081/metrics"
def call(method, path, body=None):
    req = urllib.request.Request(api + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)
def metric(name):
    try:
        with urllib.request.urlopen(metrics, timeout=5) as r:
            for line in r.read().decode().splitlines():
                if line.startswith(name + " ") or line.startswith(name + "{"):
                    try: return float(line.split()[-1])
                    except ValueError: pass
    except Exception:
        return None
    return 0.0
def proc(pid):
    try:
        rss = int(open("/proc/%s/statm" % pid).read().split()[1]) * 4096 // 1024
        fds = len(os.listdir("/proc/%s/fd" % pid))
        return rss, fds
    except Exception:
        return None, None
def load1():
    return float(open("/proc/loadavg").read().split()[0])
jobs = open(os.path.join(out, "jobs.csv"), "w", newline=""); jw = csv.writer(jobs)
jw.writerow(["job_id", "submitted_at", "started_at", "completed_at", "status", "level", "queue_s", "run_s", "total_s"])
snaps = open(os.path.join(out, "snapshots.csv"), "w", newline=""); sw = csv.writer(snaps)
sw.writerow(["t_s", "jobs_done", "jobs_ok", "jobs_exact", "in_flight", "sessions_active", "queue_depth", "sessions_opened", "handshake_failures",
             "sessions_refused", "sagvd_rss_kb", "sagvd_fds", "workers_rss_kb", "load1"])
def ts(s):
    s = s.rstrip("Z"); head, _, frac = s.partition("."); frac = (frac + "000000")[:6]
    return time.mktime(time.strptime(head, "%Y-%m-%dT%H:%M:%S")) + int(frac) / 1e6
t0 = time.time(); deadline = t0 + minutes * 60; cap = workers * 2
inflight = {}; done = ok = exact = 0; last_snap = t0; first_error = None
def snapshot():
    r, f = proc(sagvd_pid); wr = sum((proc(p)[0] or 0) for p in worker_pids)
    sw.writerow([int(time.time() - t0), done, ok, exact, len(inflight), metric("sagvd_sessions_active"), metric("sagvd_queue_depth"),
                 metric("sagvd_sessions_opened_total"), metric("sagvd_handshake_failures_total"), metric("sagvd_sessions_refused_total"),
                 r, f, wr, load1()]); snaps.flush()
snapshot()
while True:
    now = time.time()
    if now < deadline:
        while len(inflight) < cap:
            try:
                v = call("POST", "/v1/jobs", {"genome": {"bundle": "gen-0.genome", "key_file": "gen-0.key"}, "deadline_seconds_from_now": 300})
                inflight[v["job_id"]] = now
            except Exception as e:
                first_error = first_error or ("submit: %s" % e); break
    elif not inflight or now > deadline + 300:
        break
    for jid in list(inflight):
        try:
            v = call("GET", "/v1/jobs/" + jid)
        except Exception as e:
            first_error = first_error or ("get: %s" % e); continue
        if v.get("status") in ("succeeded", "failed"):
            del inflight[jid]; done += 1
            lvl = (v.get("gate") or {}).get("level")
            if v["status"] == "succeeded": ok += 1
            if lvl == "EXACT": exact += 1
            sub, st, co = v.get("submitted_at"), v.get("started_at"), v.get("completed_at")
            try:
                q = round(ts(st) - ts(sub), 3) if st else ""; rn = round(ts(co) - ts(st), 3) if (st and co) else ""; tot = round(ts(co) - ts(sub), 3) if co else ""
            except Exception:
                q = rn = tot = ""
            jw.writerow([jid, sub, st, co, v["status"], lvl, q, rn, tot]); jobs.flush()
    if time.time() - last_snap >= 60:
        snapshot(); last_snap = time.time()
    time.sleep(0.2)
snapshot(); jobs.close(); snaps.close()
with open(os.path.join(out, "steps.txt"), "a") as f:
    f.write("soak: minutes=%d workers=%d jobs_done=%d ok=%d exact=%d in_flight_at_end=%d first_error=%s\n" % (minutes, workers, done, ok, exact, len(inflight), first_error))
PY
mark soak_end
step "snapshots of the daemons' state at the end"
ps -o pid,rss,vsz,pcpu,etime,cmd -p "$(echo $SAGVD $PIDS | tr " " ",")" > "$OUT/ps-end.txt" 2>&1
curl -s http://127.0.0.1:9081/metrics | grep -E "^(sagvd|rp|vg_tee)_" > "$OUT/sagvd-metrics-end.txt"
curl -s "http://127.0.0.1:9101/metrics" | grep -E "^(acp_compute|rp|vg_tee)_" > "$OUT/acp-compute-1-metrics-end.txt"
for pid in $PIDS; do kill -TERM "$pid" 2>/dev/null; done
for pid in $PIDS; do wait "$pid" 2>/dev/null; done
kill -TERM $SAGVD; wait $SAGVD 2>/dev/null
unset TOKEN
# The logs are long: keep their size, their warnings and errors (counted, the first fifty) and their ends.
for f in sagvd-soak $(for i in $(seq 1 "$WORKERS"); do echo "acp-compute-soak-$i"; done); do
  L="$WORK/$f.log"; { echo "lines=$(wc -l < "$L") bytes=$(wc -c < "$L")"; echo "warn=$(grep -c '"level":"WARN"' "$L") error=$(grep -c '"level":"ERROR"' "$L")"; } > "$OUT/$f.size.txt"
  grep -E '"level":"(WARN|ERROR)"' "$L" | head -50 > "$OUT/$f.warnings.txt"
  head -40 "$L" > "$OUT/$f.head.txt"; tail -40 "$L" > "$OUT/$f.tail.txt"
  grep -o '"handshake_ms":[0-9]*' "$L" | cut -d: -f2 > "$OUT/$f.handshake_ms.txt"
done
step "verify the audit log of the whole soak with the published key; count its records by kind"
T1=$(date +%s.%N)
./acpctl audit verify --audit audit/returnpath-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-e2e --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"
echo "audit verify exit=$?" >> "$OUT/steps.txt"
python3 -c 'import sys,time; t0=float(sys.argv[1]); print("audit_verify_seconds=%.1f" % (time.time()-t0))' "$T1" >> "$OUT/steps.txt"
./acpctl audit query --audit audit/returnpath-audit.db --limit 0 --json 2> "$OUT/audit-query.err" | python3 -c '
import json, sys, collections
c = collections.Counter(); n = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    n += 1; c[json.loads(line).get("kind")] += 1
print("audit_events=%d" % n); [print("  %s=%d" % kv) for kv in sorted(c.items())]' > "$OUT/audit-kinds.txt"
echo "audit query exit=$?" >> "$OUT/steps.txt"
cat "$OUT/audit-kinds.txt" | head -3 >> "$OUT/steps.txt"
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
