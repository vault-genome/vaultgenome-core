#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The worker's host of the two-host provisioning drill (ADR 0028), on an
# Azure SEV-SNP Confidential VM, run by the orchestrator over ssh as root
# in three phases:
#
#   join     the binaries, the worker package, the base model and the
#            bundle from <admin-home>/in; tpm2-tools (the azure-sev-snp
#            provider reads the HCL report through tpm2_nvread); the
#            worker runtime; `acpctl
#            provision join` — the bundle's files into /root/deploy, the
#            worker's configuration for the authority the bundle names,
#            its identity from the vTPM's HCL report (`--provider auto`
#            resolves azure-sev-snp there), its key files sealed to the vTPM; the identity to
#            <admin-home>/out for the orchestrator to carry back; the
#            bundle deleted.
#   start    acp-compute on what join wrote, dialing the authority across
#            the Internet (it waits for the authority with its backoff).
#   collect  metrics, the log, the daemon stopped; <admin-home>/out/worker.tgz.
#
# Usage: worker.sh join|start|collect <admin-home>
set -u
PHASE="${1:?usage: worker.sh join|start|collect <admin-home>}"; HOME_DIR="${2:?admin home}"
IN="$HOME_DIR/in"; WORK=/root/p2; OUT=$WORK/out; DEPLOY=/root/deploy
mkdir -p "$OUT" "$HOME_DIR/out"; cd "$WORK"
exec > >(tee -a /root/worker.log) 2>&1
step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
ADMIN="$(stat -c %U "$HOME_DIR")"

case "$PHASE" in
join)
  STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  { echo "host=$(hostname)"; echo "captured=$STAMP"; curl -s -H Metadata:true "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("vm_size=%s location=%s" % (d.get("vmSize"), d.get("location")))' 2>/dev/null; } > "$OUT/metadata.txt"
  uname -a > "$OUT/kernel.txt"
  step "binaries, the worker package, the base model and the bundle from $IN"
  for f in sagvd acp-compute acpctl keygen; do cp "$IN/$f" "$WORK/$f" && chmod +x "$WORK/$f"; done
  ./acp-compute version > "$OUT/versions.txt"; ./acpctl version >> "$OUT/versions.txt" 2>/dev/null || true
  ( cd "$IN" && sha256sum sagvd acp-compute acpctl keygen genome-worker.tgz base.tgz worker-bundle.tar ) > "$OUT/inputs.sha256"
  mkdir -p workers && tar xzf "$IN/genome-worker.tgz" -C workers
  tar xzf "$IN/base.tgz" -C "$WORK"
  step "tpm2-tools: the azure-sev-snp provider reads the HCL report from the vTPM's NV index through tpm2_nvread"
  export DEBIAN_FRONTEND=noninteractive
  for i in $(seq 1 12); do apt-get -o DPkg::Lock::Timeout=300 install -y -qq tpm2-tools >/dev/null 2>&1 && break; apt-get update -qq >/dev/null 2>&1 || true; sleep 10; done
  { ls -la /dev/tpm0 /dev/tpmrm0 2>&1; tpm2_nvreadpublic 2>&1 | grep -A3 0x1400001; ls /dev/sev-guest /sys/kernel/config/tsm 2>&1; } > "$OUT/vtpm.txt" 2>&1
  echo "tpm2_nvread=$(command -v tpm2_nvread || echo missing)" >> "$OUT/steps.txt"

  step "the worker runtime: python, the pinned CPU torch (the door needs it)"
  mark runtime_install_start
  for i in $(seq 1 12); do apt-get -o DPkg::Lock::Timeout=300 install -y -qq python3-venv python3-pip >/dev/null 2>&1 && break; apt-get update -qq >/dev/null 2>&1 || true; sleep 10; done
  python3 -m venv venv && . venv/bin/activate
  pip install --require-hashes --only-binary=:all: --index-url https://pypi.org/simple -r workers/genome/requirements-ci.lock > "$OUT/pip-requirements.log" 2>&1
  pip install --require-hashes --only-binary=:all: --no-deps --index-url https://download.pytorch.org/whl/cpu -r workers/genome/requirements-torch-cpu.lock > "$OUT/pip-torch.log" 2>&1
  python3 -c 'import torch, transformers, safetensors; print("torch", torch.__version__, "transformers", transformers.__version__, "safetensors", safetensors.__version__)' > "$OUT/runtime.txt" 2>&1
  mark runtime_install_end

  step "step 2: acpctl provision join — the bundle into $DEPLOY, acp-compute.json for the authority it names, identity from the vTPM, keys sealed"
  mark provision_join_start
  # auto: no configfs-tsm under Azure's paravisor, so the family is read from the vTPM's HCL report (azure-sev-snp,
  # the family the authority provisioned the worker for; join refuses any other).
  ./acpctl provision join --bundle "$IN/worker-bundle.tar" --out "$DEPLOY" --bin-dir "$WORK" --provider auto \
    --door-python "$WORK/venv/bin/python3" --base-model "$WORK/base" --worker-package "$WORK/workers/genome" \
    --worker-health 127.0.0.1:9082 > "$OUT/provision-join.out" 2> "$OUT/provision-join.err"
  RC=$?; echo "provision join exit=$RC" >> "$OUT/steps.txt"
  mark provision_join_end
  cp "$DEPLOY/provision.json" "$OUT/provision-join.json" 2>/dev/null || true
  cp "$DEPLOY/acp-compute.json" "$DEPLOY/acp-compute-identity.json" "$OUT/" 2>/dev/null || true
  [ "$RC" = 0 ] || { echo "provision join failed: $(tail -3 "$OUT/provision-join.err")"; exit 1; }
  python3 - "$OUT/provision-join.json" >> "$OUT/steps.txt" 2>&1 <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("provider=%s authority=%s sealer=%s phase=%s vault_address=%s" % (d["provider"], d["peer_provider"], d["sealer"], d["phase"], d.get("vault_address")))
print("worker_measurement=%s worker_provider=%s worker_sealer=%s" % (d["worker"]["measurement_hex"], d["worker"].get("provider"), d["worker"].get("sealer")))
print("pinned_authority=%s" % d["vault"]["measurement_hex"])
print("sealed_worker=%s" % ",".join(d.get("sealed", {}).get("acp-compute", [])))
PY
  # The sealed files' shape, without their bytes.
  python3 - "$DEPLOY/secrets" > "$OUT/sealed-files.txt" 2>&1 <<'SHAPE'
import json, os, sys
S = sys.argv[1]
for p in ("acp-compute/worker_signing_seed", "acp-compute/sealing.key", "acp-compute/tls/client.key"):
    try:
        d = json.load(open(os.path.join(S, p)))
        print(p, {"schema": d.get("schema"), "tee": d.get("tee"), "sealer": d.get("sealer"), "name": d.get("name"), "sealed_bytes": len(d.get("sealed", ""))})
    except Exception as e:
        print(p, "not a sealed file:", type(e).__name__)
SHAPE
  ls "$DEPLOY/secrets" > "$OUT/secrets-dirs.txt" 2>&1
  rm -f "$IN/worker-bundle.tar"; echo "bundle deleted on the worker host after join" >> "$OUT/steps.txt"
  cp "$DEPLOY/acp-compute-identity.json" "$HOME_DIR/out/acp-compute-identity.json" && chown "$ADMIN" "$HOME_DIR/out/acp-compute-identity.json"
  echo "JOINED $STAMP"
  ;;
start)
  step "acp-compute on what join wrote, dialing the authority"
  mark worker_start
  . venv/bin/activate 2>/dev/null || true
  nohup ./acp-compute -config "$DEPLOY/acp-compute.json" > "$OUT/acp-compute.log" 2>&1 &
  echo $! > "$WORK/acp-compute.pid"
  n=0; until curl -sf http://127.0.0.1:9082/healthz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
  echo "acp-compute ready after ${n}s pid=$(cat "$WORK/acp-compute.pid")" >> "$OUT/steps.txt"
  echo "STARTED"
  ;;
collect)
  step "metrics; stop acp-compute; the results"
  curl -s http://127.0.0.1:9082/metrics | grep -E "^(acp_compute|rp|vg_tee)_" > "$OUT/acp-compute-metrics.txt"
  if [ -f "$WORK/acp-compute.pid" ]; then kill -TERM "$(cat "$WORK/acp-compute.pid")" 2>/dev/null; for i in $(seq 1 30); do kill -0 "$(cat "$WORK/acp-compute.pid")" 2>/dev/null || break; sleep 1; done; fi
  mark worker_stopped
  grep -o '"handshake_ms":[0-9]*' "$OUT/acp-compute.log" | cut -d: -f2 > "$OUT/acp-compute.handshake_ms.txt"
  grep -c '"level":"ERROR"' "$OUT/acp-compute.log" > "$OUT/acp-compute.errors.txt" 2>/dev/null || true
  cp /root/worker.log "$OUT/console.log" 2>/dev/null
  ( cd "$OUT" && sha256sum * > "$WORK/sha256sums.txt" 2>/dev/null ); mv "$WORK/sha256sums.txt" "$OUT/"
  tar czf "$HOME_DIR/out/worker.tgz" -C "$OUT" . && chown "$ADMIN" "$HOME_DIR/out/worker.tgz"
  echo "COLLECTED"
  ;;
*) echo "unknown phase $PHASE"; exit 2 ;;
esac
