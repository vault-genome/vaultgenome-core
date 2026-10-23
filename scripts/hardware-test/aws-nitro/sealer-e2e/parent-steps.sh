#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The parent instance's half of the sealer's hardware run (run.sh copies it
# to the instance and calls one phase at a time): bootstrap, build the
# enclave image, run it in production and in debug mode, ask KMS from the
# parent itself. Every phase prints "phase <name> rc=<n>" last.
set -uo pipefail
VG="$HOME/vg"
OUT="$VG/out"
mkdir -p "$OUT"
REGION="${1:?region}"
PHASE="${2:?phase}"

bootstrap() {
  sudo dnf install -y -q aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker || return 1
  sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null <<'YAML'
---
memory_mib: 1536
cpu_count: 2
YAML
  sudo systemctl enable --now nitro-enclaves-allocator.service || return 1
  sudo systemctl enable --now docker || return 1
  nitro-cli --version > "$OUT/nitro-cli-version.txt"
  uname -r > "$OUT/parent-kernel.txt"
  cat "$OUT/nitro-cli-version.txt"
}

build() {
  rm -rf "$VG/build" && mkdir -p "$VG/build/rootfs" && cd "$VG/build" || return 1
  # The enclave's init moves into the image's root and then mounts /dev,
  # /proc, /run, /tmp and /sys there, which must exist (init.c of
  # aws-nitro-enclaves-sdk-bootstrap); a scratch image has none of them.
  mkdir -p rootfs/dev rootfs/proc rootfs/sys rootfs/run rootfs/tmp rootfs/etc/vg || return 1
  cp "$VG/enclave" rootfs/enclave && cp "$VG/enclave.json" rootfs/etc/vg/enclave.json || return 1
  cat > Dockerfile <<'DOCKER'
FROM scratch
COPY rootfs/ /
ENTRYPOINT ["/enclave"]
DOCKER
  sudo docker build -q -t vg-sealer-e2e:latest . || return 1
  sudo nitro-cli build-enclave --docker-uri vg-sealer-e2e:latest --output-file "$VG/vg-sealer-e2e.eif" > "$OUT/eif-build.json" || return 1
  nitro-cli describe-eif --eif-path "$VG/vg-sealer-e2e.eif" > "$OUT/eif-describe.json" || return 1
  sha256sum "$VG/vg-sealer-e2e.eif" "$VG/enclave" "$VG/enclave.json" > "$OUT/image-sha256.txt"
  cat "$OUT/eif-describe.json"
}

start_parent() {
  pkill -x parent 2>/dev/null
  nohup "$VG/parent" -region "$REGION" -bundle "$VG/bundle.json" -out "$OUT" > "$OUT/parent.log" 2>&1 &
  sleep 2
  pgrep -x parent >/dev/null
}

# run_enclave <label> [--debug-mode]: run the image, wait for its report.
run_enclave() {
  local label="$1"; shift
  local before after id
  before=$(ls "$OUT"/enclave-report-[0-9]*.json 2>/dev/null | wc -l)
  if ! sudo nitro-cli run-enclave --eif-path "$VG/vg-sealer-e2e.eif" --memory 1536 --cpu-count 2 --enclave-cid 16 "$@" > "$OUT/run-enclave-$label.json" 2> "$OUT/run-enclave-$label.err"; then
    cat "$OUT/run-enclave-$label.err"
    mkdir -p "$OUT/nitro-logs-$label" && sudo sh -c "cp /var/log/nitro_enclaves/*.log '$OUT/nitro-logs-$label/' 2>/dev/null; chown -R $(id -u):$(id -g) '$OUT/nitro-logs-$label'"
    return 1
  fi
  id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["EnclaveID"])' "$OUT/run-enclave-$label.json")
  sudo nitro-cli describe-enclaves > "$OUT/describe-enclaves-$label.json"
  if [ "${1:-}" = "--debug-mode" ]; then
    (sudo timeout 150 nitro-cli console --enclave-id "$id" > "$OUT/console-$label.log" 2>&1 &)
  fi
  for _ in $(seq 1 120); do
    after=$(ls "$OUT"/enclave-report-[0-9]*.json 2>/dev/null | wc -l)
    [ "$after" -gt "$before" ] && break
    sleep 2
  done
  sleep 2
  sudo nitro-cli terminate-enclave --enclave-id "$id" > "$OUT/terminate-enclave-$label.json" 2>&1 || true
  mkdir -p "$OUT/nitro-logs-$label" && sudo sh -c "cp /var/log/nitro_enclaves/*.log '$OUT/nitro-logs-$label/' 2>/dev/null; chown -R $(id -u):$(id -g) '$OUT/nitro-logs-$label'"
  [ "$after" -gt "$before" ] || { echo "no report from the $label run"; return 1; }
  cp "$(ls -t "$OUT"/enclave-report-[0-9]*.json | head -1)" "$OUT/report-$label.json"
  cat "$OUT/report-$label.json"
}

# parent_decrypt: the parent's own role asks KMS to decrypt the data key of
# the file that opens in the enclave, without an attestation document.
parent_decrypt() {
  python3 - "$VG/opens.sealed.json" "$OUT/opens.datakey.bin" <<'PY'
import base64, json, sys
s = json.load(open(sys.argv[1]))
inner = json.loads(base64.b64decode(s["sealed"]))
open(sys.argv[2], "wb").write(base64.b64decode(inner["data_key"]))
PY
  aws kms decrypt --region "$REGION" --key-id "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["kms_key_arn"])' "$VG/enclave.json")" \
    --ciphertext-blob "fileb://$OUT/opens.datakey.bin" --output json > "$OUT/parent-decrypt.out" 2> "$OUT/parent-decrypt.err"
  echo "aws kms decrypt rc=$?" >> "$OUT/parent-decrypt.err"
  cat "$OUT/parent-decrypt.err"
  aws sts get-caller-identity --query Arn --output text > "$OUT/parent-identity.txt" 2>&1
}

stop_parent() { pkill -x parent; sleep 1; true; }

case "$PHASE" in
  bootstrap) bootstrap ;;
  build) build ;;
  start-parent) start_parent ;;
  production) run_enclave production ;;
  debug) run_enclave debug --debug-mode ;;
  parent-decrypt) parent_decrypt ;;
  stop-parent) stop_parent ;;
  *) echo "unknown phase $PHASE"; false ;;
esac
echo "phase $PHASE rc=$?"
