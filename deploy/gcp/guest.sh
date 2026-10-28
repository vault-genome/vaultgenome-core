#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The guest side of the one-button deployment on Google Cloud (deploy.sh):
# the startup script of a Compute Engine Confidential VM — AMD SEV-SNP
# (n2d) or Intel TDX (c3), Ubuntu 24.04. On its first boot the VM stands
# itself up from the signed release and proves the deployment the way the
# reference deployment is proven (scripts/hardware-test/release-deploy,
# gcp-sev-snp/provision-e2e, gcp-tdx/returnpath-e2e), then keeps running:
# the daemons are systemd services from here on.
#
#   1. the release's binaries and worker package come from GitHub and are
#      held to the signed checksums list deploy.sh verified and passed in
#      (vg-checksums): a file that is not on the list does not run;
#   2. the worker runtime is installed from the hash-pinned locks;
#   3. `acpctl provision` writes the deployment under /etc/vaultgenome: the
#      key material, both daemons' configurations, each daemon's identity
#      read from the hardware and pinned on the other side, every key file
#      sealed to the host (ADR 0023; tee.sealer from vg-sealer). On SEV-SNP
#      the AMD chain comes from KDS verified against the pinned roots and
#      `auto` seals to the chip's derived key; on TDX the verifier takes
#      Intel's documents from PCS and `auto` seals to the guest's vTPM
#      under this boot's PCRs — so a host that seals to the vTPM reboots
#      once before it provisions: the image's first boot grows its root
#      partition and moves a PCR, and what is sealed before that would not
#      open again (the vTPM runbook's rule, docs/operator/runbooks);
#   4. a genome is made and sealed — the same tiny fine-tune the reference
#      deployment gates — and both daemons start as services;
#   5. a gate job goes over the Return Path and the audit log is verified
#      under the key provision kept for the operator;
#   6. the record goes to /var/lib/vaultgenome/record/<stamp>/ and, once, to
#      the serial console between ===VG-DEPLOY-BEGIN=== and
#      ===VG-DEPLOY-END=== (three copies) for deploy.sh to decode. Keys,
#      seeds and the operator's token stay on the VM; none is ever printed.
#
# A later boot finds /etc/vaultgenome/provision.json and leaves the
# deployment to systemd. Inputs (instance metadata): vg-tag, vg-checksums
# (base64 of checksums-<tag>.txt), vg-platform (sev-snp|tdx), vg-sealer
# (auto|tee|tpm2), vg-stamp.
set -u
LOG=/var/log/vaultgenome-deploy.log
exec > >(tee -a "$LOG") 2>&1
md() { curl -s -f -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }

BIN=/opt/vaultgenome/bin; ETC=/etc/vaultgenome; VAR=/var/lib/vaultgenome
REPO_URL="https://github.com/vault-genome/vaultgenome-core"

if [ -f "$ETC/provision.json" ]; then
  echo "vaultgenome: deployed already ($(cat "$ETC/DEPLOYED" 2>/dev/null)); the services are systemd's"
  systemctl start sagvd.service acp-compute.service 2>/dev/null || true
  exit 0
fi

TAG=$(md attributes/vg-tag 2>/dev/null || true)
STAMP=$(md attributes/vg-stamp 2>/dev/null || true); case "$STAMP" in 20[0-9][0-9][01][0-9][0-3][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;; *) STAMP=$(date -u +%Y%m%dT%H%M%SZ);; esac
SEALER=$(md attributes/vg-sealer 2>/dev/null || true); case "$SEALER" in auto|tee|tpm2) ;; *) SEALER=auto;; esac
PLATFORM=$(md attributes/vg-platform 2>/dev/null || true); case "$PLATFORM" in sev-snp|tdx) ;; *) PLATFORM=sev-snp;; esac
# A host that seals to the vTPM provisions on a settled boot (see above).
SETTLE=0; { [ "$PLATFORM" = tdx ] || [ "$SEALER" = tpm2 ]; } && SETTLE=1
WORK=/root/vg-deploy; OUT=$VAR/record/$STAMP; INSTALLED=$VAR/.installed
mkdir -p "$WORK" "$OUT" "$BIN" "$VAR"; cd "$WORK" || exit 1
T0=$(date +%s.%N)
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }
note() { echo "$*" >> "$OUT/steps.txt"; }
# A failure is said once on the serial console, with the log's tail, and
# the script stops: deploy.sh reads the marker and reports it.
fail() {
  echo "FAILED: $*"; note "FAILED: $*"
  { echo; echo "===VG-DEPLOY-FAILED=== $STAMP $*"; tail -40 "$LOG"; echo "===VG-DEPLOY-FAILED-END==="; } > /dev/ttyS0 2>/dev/null || true
  exit 1
}
retry() { local n; for n in 1 2 3; do "$@" && return 0; [ "$n" = 3 ] && return 1; echo "  (attempt $n failed; retrying in $((n * 5)) s)"; sleep $((n * 5)); done; }
apt_install() { # waits for the image's own unattended upgrade to let go of the lock
  local n=0; while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && [ $n -lt 120 ]; do sleep 2; n=$((n+1)); done
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1
}

[ -n "$TAG" ] || fail "no vg-tag in the instance metadata"

if [ ! -f "$INSTALLED" ]; then
  md attributes/vg-checksums 2>/dev/null | base64 -d > "$WORK/checksums-$TAG.txt" || fail "no vg-checksums in the instance metadata"
  [ -s "$WORK/checksums-$TAG.txt" ] || fail "vg-checksums is empty"
  mark boot
  { echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; echo "platform=$PLATFORM"; echo "release=$TAG"; echo "sealer=$SEALER"; echo "captured=$STAMP"; } > "$OUT/metadata.txt"
  uname -a > "$OUT/kernel.txt"
  note "platform=$PLATFORM sealer=$SEALER settled_boot=$SETTLE"

  step "packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 || true
  apt_install python3-venv python3-pip curl ca-certificates || fail "apt-get install python3-venv python3-pip"
  if [ "$SETTLE" = 1 ]; then
    # the vTPM sealer runs tpm2-tools as processes (ADR 0025 step 1b)
    retry apt_install tpm2-tools || fail "apt-get install tpm2-tools"
  fi

  step "configfs-tsm: the hardware's reports"
  if [ "$PLATFORM" = sev-snp ]; then
    modprobe sev-guest 2>/dev/null || {
      apt_install "linux-modules-extra-$(uname -r)"
      modprobe sev-guest 2>/dev/null || true
    }
  fi
  mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
  n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
  { ls -la /sys/kernel/config/tsm/report 2>&1; ls -la /dev/sev-guest /dev/tdx_guest /dev/tpmrm0 2>&1; grep -m1 'model name' /proc/cpuinfo; dmesg | grep -i -E "sev|snp|tdx|tsm" | tail -20; } > "$OUT/tsm.txt"
  [ -d /sys/kernel/config/tsm/report ] || fail "no configfs-tsm on this guest: not a Confidential VM?"
  case "$PLATFORM" in
    sev-snp) [ -e /dev/sev-guest ] || fail "no /dev/sev-guest: not a SEV-SNP guest";;
    tdx)     [ -e /dev/tdx_guest ] || fail "no /dev/tdx_guest: not a TDX Trust Domain";;
  esac

  step "the release $TAG from GitHub, held to the signed checksums list"
  mark download_start
  PKG="genome-worker-$TAG.tar.gz"
  for f in sagvd acp-compute acpctl acp-keygen "$PKG"; do
    retry curl -fsSL --retry 3 --retry-delay 5 -o "$WORK/$f" "$REPO_URL/releases/download/$TAG/$f" || fail "download of $f"
  done
  sha256sum sagvd acp-compute acpctl acp-keygen "$PKG" > "$OUT/inputs.sha256"
  sha256sum -c --ignore-missing "checksums-$TAG.txt" > "$OUT/checksums-check.txt" 2>&1 || true
  OKS=$(grep -c ': OK$' "$OUT/checksums-check.txt"); note "checksums_ok=$OKS of 5 downloaded files on the signed list"
  [ "$OKS" = 5 ] || fail "a downloaded file is not on the signed checksums list (see checksums-check.txt)"
  mark download_end
  install -m 0755 sagvd acp-compute acpctl acp-keygen "$BIN/"
  mkdir -p "$VAR/worker"
  tar xzf "$PKG" -C "$VAR/worker" || fail "unpacking $PKG"
  { "$BIN/sagvd" version; "$BIN/acp-compute" version; "$BIN/acpctl" version; "$BIN/acp-keygen" -version 2>/dev/null || true; } > "$OUT/versions.txt" 2>&1
  rm -f "$WORK"/sagvd "$WORK"/acp-compute "$WORK"/acpctl "$WORK"/acp-keygen "$WORK/$PKG"

  step "the worker runtime from the hash-pinned locks"
  mark runtime_install_start
  python3 -m venv "$VAR/venv" || fail "python3 -m venv"
  "$VAR/venv/bin/pip" install --require-hashes --only-binary=:all: --index-url https://pypi.org/simple -r "$VAR/worker/genome/requirements-ci.lock" > "$OUT/pip-requirements.log" 2>&1 || fail "pip install requirements-ci.lock (see pip-requirements.log)"
  "$VAR/venv/bin/pip" install --require-hashes --only-binary=:all: --no-deps --index-url https://download.pytorch.org/whl/cpu -r "$VAR/worker/genome/requirements-torch-cpu.lock" > "$OUT/pip-torch.log" 2>&1 || fail "pip install requirements-torch-cpu.lock (see pip-torch.log)"
  "$VAR/venv/bin/python3" -c 'import torch, transformers, safetensors; print("torch", torch.__version__, "transformers", transformers.__version__, "safetensors", safetensors.__version__)' > "$OUT/runtime.txt" 2>&1
  mark runtime_install_end

  step "a base model for the first genome: the tiny one the reference deployment gates"
  export PYTHONPATH=$VAR/worker/genome TOKENIZERS_PARALLELISM=false
  ( cd "$VAR/worker/genome" && "$VAR/venv/bin/python3" -c 'import sys, json; sys.path.insert(0, "tests"); import conftest
conftest.make_base(sys.argv[1])
open(sys.argv[2], "w").write("".join(json.dumps(e) + "\n" for e in conftest.EXAMPLES))' "$VAR/base" "$VAR/train.jsonl" ) || fail "making the base model"

  touch "$INSTALLED"; sync
  if [ "$SETTLE" = 1 ]; then
    step "installed; rebooting once so the key files are sealed on a settled boot (the vTPM's PCRs)"
    mark reboot
    sleep 3; reboot
    exit 0
  fi
else
  mark settled_boot
  note "settled boot: $(journalctl --list-boots --no-pager 2>/dev/null | wc -l | tr -d ' ') boots on record"
  export PYTHONPATH=$VAR/worker/genome TOKENIZERS_PARALLELISM=false
fi

step "acpctl provision: keys, configurations, identities and pins, the key files sealed to this host"
mark provision_start
PROV_CHAIN=(); [ "$PLATFORM" = sev-snp ] && PROV_CHAIN=(--fetch-amd-chain milan)
"$BIN/acpctl" provision --out "$ETC" --bin-dir "$BIN" --provider auto --sealer "$SEALER" "${PROV_CHAIN[@]}" \
  --door-python "$VAR/venv/bin/python3" --base-model "$VAR/base" --worker-package "$VAR/worker/genome" \
  --genome-dir "$VAR/genomes" --audit-log "$VAR/audit/audit.db" --queue-path "$VAR/queue/jobs.db" \
  --vault-descriptor sagvd-gcp-deploy-v1 --worker-descriptor acp-compute-gcp-deploy-v1 > "$OUT/provision.out" 2> "$OUT/provision.err"
RC=$?; note "provision exit=$RC"; mark provision_end
[ "$RC" = 0 ] || fail "acpctl provision exit $RC (see provision.err)"
mkdir -p "$VAR/genomes" "$VAR/audit" "$VAR/queue"
cp "$ETC/provision.json" "$OUT/provision.json"
cp "$ETC/sagvd-identity.json" "$ETC/acp-compute-identity.json" "$ETC/sagvd.json" "$ETC/acp-compute.json" "$OUT/" 2>/dev/null || true
cp "$ETC/operator/audit_public_key.pem" "$OUT/audit-public-key.pem"
python3 - "$OUT/provision.json" >> "$OUT/steps.txt" 2>&1 <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("provider=%s peer=%s sealer=%s" % (d["provider"], d["peer_provider"], d["sealer"]))
print("vault_measurement=%s" % d["vault"]["measurement_hex"]); print("worker_measurement=%s" % d["worker"]["measurement_hex"])
print("vault_sealer=%s worker_sealer=%s" % (d["vault"].get("sealer"), d["worker"].get("sealer")))
print("sealed_sagvd=%s" % ",".join(d.get("sealed", {}).get("sagvd", []))); print("sealed_worker=%s" % ",".join(d.get("sealed", {}).get("acp-compute", [])))
print("amd_cert_chain=%s" % d.get("amd_cert_chain")); print("audit_kid=%s authority_kid=%s" % (d["vault"].get("audit_kid"), d["vault"].get("authority_kid")))
PY
# The sealed files' shape, without their bytes: the sealer each names.
python3 - "$ETC/secrets" > "$OUT/sealed-files.txt" 2>&1 <<'SHAPE'
import json, os, sys
S = sys.argv[1]
for p in ("sagvd/authority_signing_seed", "sagvd/audit_signing_seed", "sagvd/api_token", "sagvd/tls/server.key", "shared/sealing.key", "acp-compute/sealing.key", "acp-compute/worker_signing_seed", "acp-compute/tls/client.key"):
    try:
        d = json.load(open(os.path.join(S, p)))
        print(p, {"schema": d.get("schema"), "tee": d.get("tee"), "sealer": d.get("sealer"), "name": d.get("name"), "sealed_bytes": len(d.get("sealed", ""))})
    except Exception as e:
        print(p, "not a sealed file:", type(e).__name__)
SHAPE
# What provision wrote and what was sealed is on disk before anything
# runs on it: a reset in the next seconds must not find empty files.
sync

step "the first genome: a LoRA fine-tune by vg_genome, sealed by acpctl into the genome directory"
mark finetune_start
( cd "$VAR" && "$VAR/venv/bin/python3" -m vg_genome finetune --base base --base-name tiny-llama --data train.jsonl --out genome-0 \
    --targets q_proj,v_proj,lm_head --steps 20 --lr 1e-2 --max-len 32 --threads 2 --top-k 8 --new-tokens 4 ) > "$OUT/finetune.json" 2> "$OUT/finetune.err"
RC=$?; note "finetune exit=$RC"; mark finetune_end
[ "$RC" = 0 ] || fail "vg_genome finetune exit $RC (see finetune.err)"
"$BIN/acpctl" genome seal --content-dir "$VAR/genome-0" --output "$VAR/genomes/gen-0.genome" --key-out "$VAR/genomes/gen-0.key" --json > "$OUT/seal.json" 2> "$OUT/seal.err"
RC=$?; note "seal exit=$RC"; [ "$RC" = 0 ] || fail "acpctl genome seal exit $RC (see seal.err)"
note "key_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_id"])' "$OUT/seal.json" 2>/dev/null)"

step "the daemons as systemd services"
cat > /etc/systemd/system/sagvd.service <<UNIT
[Unit]
Description=Vault Genome authority (sagvd), release $TAG
Documentation=$REPO_URL/blob/$TAG/docs/operator/00_overview.md
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN/sagvd -config $ETC/sagvd.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$VAR $ETC /sys/kernel/config

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/acp-compute.service <<UNIT
[Unit]
Description=Vault Genome worker (acp-compute), release $TAG
Documentation=$REPO_URL/blob/$TAG/docs/operator/00_overview.md
After=network-online.target sagvd.service
Wants=network-online.target sagvd.service

[Service]
ExecStart=$BIN/acp-compute -config $ETC/acp-compute.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$VAR $ETC /sys/kernel/config

[Install]
WantedBy=multi-user.target
UNIT
# vg: the operator's hands on this host (health, a job, the log's
# verification, the services' logs). Root only: it reads the API token.
cat > "$BIN/vg" <<'VG'
#!/bin/bash
# vg — operate this Vault Genome deployment (run as root)
set -u
BIN=/opt/vaultgenome/bin; ETC=/etc/vaultgenome; VAR=/var/lib/vaultgenome
API=http://127.0.0.1:9080
kid() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vault"]["audit_kid"])' "$ETC/provision.json"; }
# The live audit segment is the authority's while it runs (ADR 0027): a
# read of it pauses both services and starts them again — about 15 s.
pause() { systemctl stop acp-compute.service sagvd.service; trap resume EXIT; }
resume() {
  systemctl start sagvd.service; local n=0
  until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
  systemctl start acp-compute.service
  echo "(the services were paused for the read and are back: sagvd ready after ${n}s)" >&2
}
case "${1:-help}" in
  health)  echo "sagvd: $(curl -fsS http://127.0.0.1:9081/readyz 2>&1)"; echo "acp-compute: $(curl -fsS http://127.0.0.1:9082/healthz 2>&1)"; systemctl --no-pager --lines=0 status sagvd acp-compute | grep -E '^\S|Active:' ;;
  status)  # live, from the daemons' metrics: no pause
           curl -s http://127.0.0.1:9081/metrics | grep -E '^(sagvd_sessions_(opened_total|active)|sagvd_jobs_(submitted|completed)_total|sagvd_gate_verdicts_total|sagvd_release_decisions_total|sagvd_audit_(events_total|segment_events|segments_closed_total)|sagvd_queue_depth|vg_tee_attestation_total)' ;;
  verify)  pause; "$BIN/acpctl" audit verify --audit "$VAR/audit/audit.db" --audit-pubkey "$ETC/operator/audit_public_key.pem" --audit-kid "$(kid)" --json ;;
  audit)   pause; "$BIN/acpctl" status --audit "$VAR/audit/audit.db" ;;
  events)  pause; "$BIN/acpctl" audit query --audit "$VAR/audit/audit.db" --limit "${2:-20}" --json ;;
  logs)    journalctl --unit "${2:-sagvd}" --no-pager -n "${3:-50}" -o cat ;;
  submit)  # vg submit <bundle name in /var/lib/vaultgenome/genomes> <key file name> [deadline seconds]
           [ $# -ge 3 ] || { echo "usage: vg submit <bundle> <key-file> [deadline-seconds]" >&2; exit 2; }
           T=$(cat "$ETC/operator/api_token")
           R=$(curl -sS -X POST -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
                 --data "{\"genome\":{\"bundle\":\"$2\",\"key_file\":\"$3\"},\"deadline_seconds_from_now\":${4:-300}}" "$API/v1/jobs") || exit 1
           J=$(printf '%s' "$R" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])') || { echo "$R" >&2; exit 1; }
           echo "job $J submitted"
           for _ in $(seq 1 "${4:-300}"); do
             sleep 1; V=$(curl -sS -H "Authorization: Bearer $T" "$API/v1/jobs/$J")
             S=$(printf '%s' "$V" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' 2>/dev/null)
             case "$S" in succeeded|failed) break;; esac
           done
           printf '%s\n' "$V" | python3 -c 'import json,sys; j=json.load(sys.stdin); g=j.get("gate") or {}; v=(g.get("signed_verdict") or {}).get("verdict") or {}
print("status=%s gate=%s rung=%s fixtures=%s n_exact=%s max_abs_err=%s signer=%s" % (j.get("status"), g.get("level"), g.get("rung"), g.get("fixtures"), v.get("n_exact"), v.get("max_abs_err"), g.get("signer_key_id")))' ;;
  job)     T=$(cat "$ETC/operator/api_token"); curl -sS -H "Authorization: Bearer $T" "$API/v1/jobs/${2:?job id}" ;;
  *)       echo "vg health | status | logs [sagvd|acp-compute] [n] | submit <bundle> <key-file> [deadline] | job <id>"
           echo "   verify | audit | events [n]   — read the audit log: the services pause for about 15 s and come back" ;;
esac
VG
chmod 0755 "$BIN/vg"; ln -sf "$BIN/vg" /usr/local/bin/vg   # on sudo's path
cp /etc/systemd/system/sagvd.service /etc/systemd/system/acp-compute.service "$OUT/"
sync
systemctl daemon-reload
mark services_start
systemctl enable --now sagvd.service >/dev/null 2>&1 || fail "systemctl enable --now sagvd"
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
note "sagvd_ready_after=${n}s"; curl -sf http://127.0.0.1:9081/readyz >/dev/null || { journalctl -u sagvd --no-pager -n 30 -o cat; fail "sagvd is not ready after 60 s"; }
systemctl enable --now acp-compute.service >/dev/null 2>&1 || fail "systemctl enable --now acp-compute"
n=0; until curl -sf http://127.0.0.1:9082/healthz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
n=0; until journalctl -u sagvd --no-pager -o cat | grep -q "sagvd session opened" || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
journalctl -u sagvd --no-pager -o cat | grep -q "sagvd session opened" || { journalctl -u sagvd -u acp-compute --no-pager -n 40 -o cat; fail "the worker did not open a session with the authority in 90 s"; }
note "session_opened_after=${n}s"; mark session_opened

step "the gate job over the Return Path"
TOKEN=$(cat "$ETC/operator/api_token")
mark job_submit
curl -s -o "$OUT/job-submit.json" -w '%{http_code}\n' -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"genome":{"bundle":"gen-0.genome","key_file":"gen-0.key"},"deadline_seconds_from_now":300}' http://127.0.0.1:9080/v1/jobs > "$OUT/job-submit.status"
JOB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["job_id"])' "$OUT/job-submit.json" 2>/dev/null)
[ -n "$JOB" ] || fail "the job was not accepted (HTTP $(cat "$OUT/job-submit.status"))"
note "job_id=$JOB"
ST=""
for i in $(seq 1 300); do
  sleep 1
  curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9080/v1/jobs/$JOB" > "$OUT/job.json"
  ST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$OUT/job.json" 2>/dev/null)
  [ "$ST" = succeeded ] || [ "$ST" = failed ] && break
done
unset TOKEN
mark job_done
note "job_status=$ST"; note "job_wait=${i}s"
python3 - "$OUT/job.json" "$OUT/steps.txt" <<'PY'
import json, sys
j = json.load(open(sys.argv[1])); g = j.get("gate") or {}; v = (g.get("signed_verdict") or {}).get("verdict") or {}
with open(sys.argv[2], "a") as f:
    f.write("gate_level=%s door=%s rung=%s fixtures=%s n_exact=%s max_abs_err=%s signer=%s\n" % (
        g.get("level"), g.get("door"), g.get("rung"), g.get("fixtures"), v.get("n_exact"), v.get("max_abs_err"), g.get("signer_key_id")))
PY
[ "$ST" = succeeded ] || fail "the gate job did not succeed (status $ST; see job.json)"

step "metrics; then the audit log verified under the operator's key with both services paused, and the hardware as the verifier read it"
curl -s http://127.0.0.1:9081/metrics | grep -E "^(sagvd|rp|vg_tee)_" > "$OUT/sagvd-metrics.txt"
curl -s http://127.0.0.1:9082/metrics | grep -E "^(acp_compute|rp|vg_tee)_" > "$OUT/acp-compute-metrics.txt"
# The live segment is the authority's while it runs (ADR 0027): a read
# pauses both services, as the first-deployment guide's §4.5 does, and
# starts them again — the key files sealed to this host open a second time.
KID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vault"]["audit_kid"])' "$OUT/provision.json" 2>/dev/null); KID=${KID:-sagvd-audit-demo}
mark pause_start
systemctl stop acp-compute.service sagvd.service
"$BIN/acpctl" audit verify --audit "$VAR/audit/audit.db" --audit-pubkey "$ETC/operator/audit_public_key.pem" --audit-kid "$KID" --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"
RC=$?; note "audit verify exit=$RC"
"$BIN/acpctl" audit query --audit "$VAR/audit/audit.db" --limit 0 --json > "$OUT/audit-events.jsonl" 2> "$OUT/audit-query.err"
"$BIN/acpctl" status --audit "$VAR/audit/audit.db" > "$OUT/status.txt" 2>/dev/null || true
mark pause_end
systemctl start sagvd.service
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
note "restart_sagvd_ready_after=${n}s"
systemctl start acp-compute.service
n=0; until [ "$(journalctl -u sagvd --no-pager -o cat | grep -c "sagvd session opened")" -ge 2 ] || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
note "restart_session_opened_after=${n}s"; mark restarted
[ "$RC" = 0 ] || fail "acpctl audit verify exit $RC (see audit-verify.err)"
curl -sf http://127.0.0.1:9081/readyz >/dev/null || { journalctl -u sagvd --no-pager -n 30 -o cat; fail "sagvd did not come back after the pause"; }
[ "$(journalctl -u sagvd --no-pager -o cat | grep -c "sagvd session opened")" -ge 2 ] || { journalctl -u sagvd -u acp-compute --no-pager -n 40 -o cat; fail "the worker did not open a session again after the pause"; }
# The admitted worker's hardware, as the vault's verifier read it: on
# SEV-SNP the chip from the TRUST_EVALUATED record (ADR 0033); on TDX the
# Trust Domain's measurement registers from the worker's identity and the
# Intel documents the verifier took from PCS.
python3 - "$OUT/audit-events.jsonl" "$OUT/acp-compute-identity.json" "$ETC/pcs-cache" "$PLATFORM" > "$OUT/chip.txt" <<'PY'
import json, os, sys
events, identity, pcs, platform = sys.argv[1:5]
if platform == "sev-snp":
    for line in open(events):
        e = json.loads(line)
        if e.get("kind") != "TRUST_EVALUATED": continue
        s = ((e.get("payload") or {}).get("peer_detail") or {}).get("sev_snp") or {}
        if not s: continue
        t, c, f = s["tcb"]["reported"], s["cpuid"], s["floor"]
        print("peer chip product=%s variant=%s cpuid=%#x/%#x/%#x snp=%#x microcode=%#x firmware=%s alias_check=%s mit_vector=%s floor_snp=%#x floor_microcode=%#x" % (
            s["product"], s.get("variant"), c["family"], c["model"], c["stepping"], t["snp"], t["microcode"], s["firmware"]["current"],
            str(s["platform_info"]["alias_check_complete"]).lower(), s["mitigation_vector"]["current_hex"], f["snp"], f["microcode"]))
        break
else:
    d = json.load(open(identity)); t = d.get("tdx") or {}
    docs = sorted(os.listdir(pcs)) if os.path.isdir(pcs) else []
    fmspc = [n[len("tdx-tcb-"):-len(".json")] for n in docs if n.startswith("tdx-tcb-") and n.endswith(".json")]
    print("peer trust domain tdx mrtd=%s rtmr0=%s rtmr1=%s rtmr2=%s rtmr3=%s measurement=%s fmspc=%s pcs_documents=%s" % (
        t.get("mrtd_hex", "?"), *(t.get("rtmr_hex") or ["?"] * 4)[:4], d.get("tee_measurement_hex", "?"), ",".join(fmspc) or "?", ",".join(docs) or "none"))
PY
cat "$OUT/chip.txt" >> "$OUT/steps.txt"
if [ "$PLATFORM" = tdx ]; then
  # the Intel documents both verifiers fetched (public), for re-verification
  for f in "$ETC"/pcs-cache/*; do [ -f "$f" ] && cp "$f" "$OUT/pcs-$(basename "$f")"; done
fi
journalctl -u sagvd --no-pager -o cat > "$OUT/sagvd.log"; journalctl -u acp-compute --no-pager -o cat > "$OUT/acp-compute.log"
python3 -c 'import sys,time; t0=float(sys.argv[1]); print("elapsed_seconds=%.1f" % (time.time()-t0))' "$T0" >> "$OUT/steps.txt"
mark finished
echo "$TAG $STAMP $PLATFORM" > "$ETC/DEPLOYED"; chmod 0600 "$ETC/DEPLOYED"

cp "$LOG" "$OUT/console.log"
( cd "$OUT" && sha256sum -- * > "$WORK/sha256sums.txt" ); mv "$WORK/sha256sums.txt" "$OUT/"
sync   # the record and the marker are on disk before the console says so

echo "== emit"   # not via step: steps.txt is already under sha256sums.txt
cd "$VAR/record" && tar czf "$WORK/$STAMP.tgz" "$STAMP" && base64 -w0 "$WORK/$STAMP.tgz" > "$WORK/$STAMP.b64"
SZ=$(stat -c%s "$WORK/$STAMP.b64"); H=$(sha256sum "$WORK/$STAMP.b64" | cut -d' ' -f1)
fold -w 76 "$WORK/$STAMP.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$WORK/$STAMP.lines"; NL=$(wc -l < "$WORK/$STAMP.lines")
dmesg -n 1 2>/dev/null || true
sleep 5
for COPY in 1 2 3; do
  { echo; echo "===VG-DEPLOY-BEGIN=== $STAMP size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "$WORK/$STAMP.lines"; echo "===VG-DEPLOY-END==="; } > /dev/ttyS0 2>/dev/null || true
  sleep 3
done
rm -f "$WORK/$STAMP.tgz" "$WORK/$STAMP.b64" "$WORK/$STAMP.lines"
echo "VG DEPLOY DONE $STAMP size=$SZ sha256=$H lines=$NL"
