#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The parent instance's half of the cross-cloud key release (run.sh copies
# it to the instance and calls one phase at a time): bootstrap, build the
# enclave image from the root the operator staged, run the forwarders,
# run acp-bootstrap in the enclave in production or debug mode and wait
# until it says it is ready, stop it. Every phase prints "phase <name>
# rc=<n>" on a line of its own, last.
set -uo pipefail
VG="$HOME/vg"
OUT="$VG/out"
mkdir -p "$OUT"
REGION="${1:?region}"
PHASE="${2:?phase}"
EIF="$VG/acp-bootstrap.eif"
MEMORY=3072

bootstrap() {
  sudo dnf install -y -q aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker || return 1
  sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null <<YAML
---
memory_mib: $MEMORY
cpu_count: 2
YAML
  sudo systemctl enable --now nitro-enclaves-allocator.service || return 1
  sudo systemctl enable --now docker || return 1
  nitro-cli --version > "$OUT/nitro-cli-version.txt"
  uname -r > "$OUT/parent-kernel.txt"
  cat "$OUT/nitro-cli-version.txt"
}

build() {
  rm -rf "$VG/build" && mkdir -p "$VG/build" && cd "$VG/build" || return 1
  tar xzf "$VG/rootfs.tgz" || return 1
  # The enclave's init mounts /dev, /proc, /run, /tmp and /sys in the
  # image's root, which must exist (part four's first stage).
  mkdir -p rootfs/dev rootfs/proc rootfs/sys rootfs/run rootfs/tmp || return 1
  cat > Dockerfile <<'DOCKER'
FROM scratch
COPY rootfs/ /
ENTRYPOINT ["/acp-bootstrap", "-config", "/etc/vg/dest.json"]
DOCKER
  sudo docker build -q -t vg-acp-bootstrap:latest . || return 1
  sudo nitro-cli build-enclave --docker-uri vg-acp-bootstrap:latest --output-file "$EIF" > "$OUT/eif-build.json" || return 1
  nitro-cli describe-eif --eif-path "$EIF" > "$OUT/eif-describe.json" || return 1
  ( cd rootfs && find . -type f -print0 | sort -z | xargs -0 sha256sum ) > "$OUT/image-files.sha256"
  sha256sum "$EIF" > "$OUT/eif.sha256"
  cat "$OUT/eif-describe.json"
}

start_parent() {
  pkill -x parent 2>/dev/null
  sleep 1
  nohup "$VG/parent" -region "$REGION" -files "$VG/files.json" -out "$OUT" > "$OUT/parent.log" 2>&1 &
  sleep 2
  pgrep -x parent >/dev/null
}

# run_enclave <label> [--debug-mode]: run the image and wait for
# acp-bootstrap's "ready" on the log the enclave sends the parent.
run_enclave() {
  local label="$1"; shift
  local before n
  before=$(ls "$OUT"/enclave-log-[0-9]*.jsonl 2>/dev/null | wc -l)
  if ! sudo nitro-cli run-enclave --eif-path "$EIF" --memory "$MEMORY" --cpu-count 2 --enclave-cid 16 "$@" > "$OUT/run-enclave-$label.json" 2> "$OUT/run-enclave-$label.err"; then
    cat "$OUT/run-enclave-$label.err"
    return 1
  fi
  sudo nitro-cli describe-enclaves > "$OUT/describe-enclaves-$label.json"
  if [ "${1:-}" = "--debug-mode" ]; then
    local id
    id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["EnclaveID"])' "$OUT/run-enclave-$label.json")
    (sudo timeout 900 nitro-cli console --enclave-id "$id" > "$OUT/console-$label.log" 2>&1 &)
  fi
  for _ in $(seq 1 90); do
    n=$(ls "$OUT"/enclave-log-[0-9]*.jsonl 2>/dev/null | wc -l)
    if [ "$n" -gt "$before" ]; then
      local f
      f=$(ls -t "$OUT"/enclave-log-[0-9]*.jsonl | head -1)
      if grep -q '"msg":"acp-bootstrap ready"' "$f"; then
        cp "$f" "$OUT/enclave-log-$label.jsonl"
        grep '"msg":"acp-bootstrap ready"' "$f"
        return 0
      fi
      if grep -q 'terminated with error' "$f"; then
        cp "$f" "$OUT/enclave-log-$label.jsonl"
        tail -3 "$f"
        return 1
      fi
    fi
    sleep 2
  done
  echo "acp-bootstrap did not say it was ready in the $label enclave"
  return 1
}

stop_enclave() {
  local label="$1"
  sudo nitro-cli terminate-enclave --all > "$OUT/terminate-enclave-$label.json" 2>&1
  sleep 2
  cp "$OUT"/enclave-log-[0-9]*.jsonl "$OUT/" 2>/dev/null
  local f
  f=$(ls -t "$OUT"/enclave-log-[0-9]*.jsonl 2>/dev/null | head -1)
  [ -n "$f" ] && cp "$f" "$OUT/enclave-log-$label.jsonl"
  mkdir -p "$OUT/nitro-logs-$label" && sudo sh -c "cp /var/log/nitro_enclaves/*.log '$OUT/nitro-logs-$label/' 2>/dev/null; chown -R $(id -u):$(id -g) '$OUT/nitro-logs-$label'"
  true
}

stop_parent() { pkill -x parent; sleep 1; true; }

case "$PHASE" in
  bootstrap) bootstrap ;;
  build) build ;;
  start-parent) start_parent ;;
  production) run_enclave production ;;
  stop-production) stop_enclave production ;;
  debug) run_enclave debug --debug-mode ;;
  stop-debug) stop_enclave debug ;;
  stop-parent) stop_parent ;;
  *) echo "unknown phase $PHASE"; false ;;
esac
rc=$?
echo
echo "phase $PHASE rc=$rc"
