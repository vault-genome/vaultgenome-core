#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The guest side of the one-button deployment on Azure (deploy.sh, or the
# Deploy to Azure button): the cloud-init script of an Azure Confidential
# VM on AMD SEV-SNP (DCasv5, Ubuntu 24.04 CVM image). The VM stands itself
# up from the signed release and proves the deployment the way the
# reference deployment is proven (scripts/hardware-test/azure-sev-snp/
# returnpath-e2e, provision-two-hosts), then keeps running: the daemons
# are systemd services from here on.
#
#   1. the release is verified ON THIS GUEST, because the button may have
#      been pressed in the portal with no machine of the person's in the
#      loop: the signed checksums list of the release comes from GitHub and
#      is verified under the release workflow's identity for this very tag
#      (cosign, fetched at a pinned hash); when deploy.sh ran, the list's
#      SHA-256 it verified is in the VM's tags and must be the same; the
#      five files then come from GitHub and are held to the list;
#   2. the worker runtime is installed from the hash-pinned locks, and
#      tpm2-tools: an Azure guest has no /dev/sev-guest and no configfs-tsm
#      — the paravisor issues the chip's SEV-SNP report at boot and keeps
#      it in the vTPM (the HCL report at NV index 0x1400001), the daemons
#      read it through tpm2-tools, and the key files are sealed to the vTPM;
#   3. the VM reboots once, so that the key files are sealed on a settled
#      boot: the vTPM sealer binds them to this boot's PCRs, and the
#      image's first boot grows its root partition and moves a PCR (the
#      same rule as the TDX button's); a systemd unit runs this script
#      again on the next boot;
#   4. `acpctl provision --provider auto` resolves azure-sev-snp from the
#      HCL report and writes the deployment under /etc/vaultgenome: the
#      key material, both configurations, the AMD chain of the chip's
#      product (Milan or Genoa, read from the report) from KDS verified
#      against the pinned roots, each daemon's identity — the launch
#      measurement and the boot the vTPM measured — pinned on the other
#      side, every key file sealed to the vTPM;
#   5. a genome is made and sealed, both daemons start as services, a gate
#      job goes over the Return Path, the audit log is verified under the
#      operator's key;
#   6. the record goes to /var/lib/vaultgenome/record/<stamp>/ (deploy.sh
#      fetches it over ssh) and to the serial console — the markers
#      deploy.sh follows, three copies of the record, and a PROVEN block a
#      person reads in the portal's boot diagnostics. Keys, seeds and the
#      operator's token stay on the VM; none is ever printed.
#
# Inputs (the VM's tags, read from the instance metadata service): vg-tag,
# vg-stamp, vg-sealer (auto|tpm2), vg-checksums-sha256 (optional).
set -u
LOG=/var/log/vaultgenome-deploy.log
exec > >(tee -a "$LOG") 2>&1

BIN=/opt/vaultgenome/bin; ETC=/etc/vaultgenome; VAR=/var/lib/vaultgenome; SELF=/opt/vaultgenome/guest.sh
REPO_URL="https://github.com/vault-genome/vaultgenome-core"
IDENTITY_PREFIX="https://github.com/vault-genome/vaultgenome-core/.github/workflows/release.yml@refs/tags/"
ISSUER="https://token.actions.githubusercontent.com"
# cosign 2.6.5, the version the release signs with, by the hash in its
# release's checksums list (signed by the cosign project) — deploy/lib/verify-release.sh pins the same.
COSIGN_URL="https://github.com/sigstore/cosign/releases/download/v2.6.5/cosign-linux-amd64"
COSIGN_SHA256=c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644
imds() { curl -s -H Metadata:true "http://169.254.169.254/metadata/instance/$1?api-version=2021-02-01&format=text"; }
tagv() { curl -s -H Metadata:true "http://169.254.169.254/metadata/instance/compute/tagsList?api-version=2021-02-01" | python3 -c 'import json,sys; print(next((t["value"] for t in json.load(sys.stdin) if t["name"] == sys.argv[1]), ""))' "$1" 2>/dev/null; }

if [ -f "$ETC/provision.json" ]; then
  echo "vaultgenome: deployed already ($(cat "$ETC/DEPLOYED" 2>/dev/null)); the services are systemd's"
  systemctl start sagvd.service acp-compute.service 2>/dev/null || true
  exit 0
fi

TAG=$(tagv vg-tag)
STAMP=$(tagv vg-stamp); case "$STAMP" in 20[0-9][0-9][01][0-9][0-3][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;; *) STAMP=$(date -u +%Y%m%dT%H%M%SZ);; esac
SEALER=$(tagv vg-sealer); case "$SEALER" in auto|tpm2) ;; *) SEALER=auto;; esac   # "tee" is refused on Azure: no derived key under the paravisor
LIST_SHA_EXPECTED=$(tagv vg-checksums-sha256)
WORK=/root/vg-deploy; OUT=$VAR/record/$STAMP; INSTALLED=$VAR/.installed
mkdir -p "$WORK" "$OUT" "$BIN" "$VAR"; cd "$WORK" || exit 1
T0=$(date +%s.%N)
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }
note() { echo "$*" >> "$OUT/steps.txt"; }
fail() {
  echo "FAILED: $*"; note "FAILED: $*"
  { echo; echo "===VG-DEPLOY-FAILED=== $STAMP $*"; tail -40 "$LOG"; echo "===VG-DEPLOY-FAILED-END==="; } > /dev/ttyS0 2>/dev/null || true
  exit 1
}
retry() { local n; for n in 1 2 3; do "$@" && return 0; [ "$n" = 3 ] && return 1; echo "  (attempt $n failed; retrying in $((n * 5)) s)"; sleep $((n * 5)); done; }
apt_install() { # the image's own unattended upgrade holds the lock early in the first boot
  local n=0; while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && [ $n -lt 150 ]; do sleep 2; n=$((n+1)); done
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq "$@" >/dev/null 2>&1
}

[ -n "$TAG" ] || fail "no vg-tag tag on this VM"

if [ ! -f "$INSTALLED" ]; then
  mark boot
  { echo "instance=$(imds compute/name)"; echo "location=$(imds compute/location)"; echo "machine=$(imds compute/vmSize)"; echo "platform=azure-sev-snp"; echo "release=$TAG"; echo "sealer=$SEALER"; echo "captured=$STAMP"; } > "$OUT/metadata.txt"
  uname -a > "$OUT/kernel.txt"
  note "platform=azure-sev-snp sealer=$SEALER settled_boot=1"

  step "packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 || true
  apt_install python3-venv python3-pip curl ca-certificates || fail "apt-get install python3-venv python3-pip"
  retry apt_install tpm2-tools || fail "apt-get install tpm2-tools"

  step "the vTPM and the chip's report in it (the HCL report); the chip's product from the report"
  { ls -la /dev/tpm0 /dev/tpmrm0 2>&1; tpm2_nvreadpublic 2>&1 | grep -A3 0x1400001; ls /dev/sev-guest /sys/kernel/config/tsm 2>&1; grep -m1 'model name' /proc/cpuinfo; } > "$OUT/vtpm.txt" 2>&1
  tpm2_nvread -C o 0x1400001 -o "$WORK/hcl-report.bin" 2> "$OUT/hcl-nvread.err" || fail "no HCL report in the vTPM (NV index 0x1400001): not an Azure Confidential VM?"
  # The product line decides the AMD chain: the report's CPUID family and
  # model (report version 3 and later), as the capture kit reads them.
  PRODUCT=$(python3 - "$WORK/hcl-report.bin" <<'PY'
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
) || fail "the chip's product could not be read from the HCL report"
  echo "$PRODUCT" > "$VAR/.product"; note "product=$PRODUCT"
  rm -f "$WORK/hcl-report.bin"

  step "the release $TAG, verified on this guest: the signed list under the release workflow's identity, then the files against the list"
  mark download_start
  mkdir -p "$WORK/tools"
  retry curl -fsSL --retry 3 -o "$WORK/tools/cosign" "$COSIGN_URL" || fail "download of cosign"
  [ "$(sha256sum "$WORK/tools/cosign" | cut -d' ' -f1)" = "$COSIGN_SHA256" ] || fail "cosign downloaded from $COSIGN_URL does not have the pinned hash"
  chmod 0755 "$WORK/tools/cosign"
  LIST="checksums-$TAG.txt"
  for f in "$LIST" "$LIST.sig" "$LIST.cert"; do
    retry curl -fsSL --retry 3 --retry-delay 5 -o "$WORK/$f" "$REPO_URL/releases/download/$TAG/$f" || fail "download of $f"
  done
  "$WORK/tools/cosign" verify-blob --signature "$WORK/$LIST.sig" --certificate "$WORK/$LIST.cert" \
    --certificate-identity "$IDENTITY_PREFIX$TAG" --certificate-oidc-issuer "$ISSUER" "$WORK/$LIST" > "$OUT/guest-cosign.txt" 2>&1 \
    || { cat "$OUT/guest-cosign.txt"; fail "the checksums list of $TAG did not verify under $IDENTITY_PREFIX$TAG"; }
  note "guest_cosign=$(tail -1 "$OUT/guest-cosign.txt")"
  LIST_SHA=$(sha256sum "$WORK/$LIST" | cut -d' ' -f1); note "checksums_list_sha256=$LIST_SHA"
  if [ -n "$LIST_SHA_EXPECTED" ]; then
    [ "$LIST_SHA" = "$LIST_SHA_EXPECTED" ] || fail "the checksums list on GitHub ($LIST_SHA) is not the one deploy.sh verified ($LIST_SHA_EXPECTED)"
    note "checksums_list_matches_deployer=true"
  fi
  PKG="genome-worker-$TAG.tar.gz"
  for f in sagvd acp-compute acpctl acp-keygen "$PKG"; do
    retry curl -fsSL --retry 3 --retry-delay 5 -o "$WORK/$f" "$REPO_URL/releases/download/$TAG/$f" || fail "download of $f"
  done
  sha256sum sagvd acp-compute acpctl acp-keygen "$PKG" > "$OUT/inputs.sha256"
  sha256sum -c --ignore-missing "$LIST" > "$OUT/checksums-check.txt" 2>&1 || true
  OKS=$(grep -c ': OK$' "$OUT/checksums-check.txt"); note "checksums_ok=$OKS of 5 downloaded files on the signed list"
  [ "$OKS" = 5 ] || fail "a downloaded file is not on the signed checksums list (see checksums-check.txt)"
  cp "$WORK/$LIST" "$OUT/$LIST"
  mark download_end
  install -m 0755 sagvd acp-compute acpctl acp-keygen "$BIN/"
  mkdir -p "$VAR/worker"
  tar xzf "$PKG" -C "$VAR/worker" || fail "unpacking $PKG"
  { "$BIN/sagvd" version; "$BIN/acp-compute" version; "$BIN/acpctl" version; "$BIN/acp-keygen" -version 2>/dev/null || true; } > "$OUT/versions.txt" 2>&1
  rm -f "$WORK"/sagvd "$WORK"/acp-compute "$WORK"/acpctl "$WORK"/acp-keygen "$WORK/$PKG" "$WORK/$LIST"*

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

  step "installed; rebooting once so the key files are sealed on a settled boot (the vTPM's PCRs) — this script runs again from vaultgenome-deploy.service"
  install -m 0755 "$0" "$SELF"
  # After the network and after systemd's PCR phase barrier: systemd
  # extends PCR 11 with the boot's phases (sysinit, then "ready" from
  # systemd-pcrphase.service), and a key file sealed to the vTPM's PCRs is
  # opened again only in the phase it was sealed in — so everything that
  # seals or unseals runs after that barrier, on every boot. (An ordering
  # after cloud-init's final unit makes a cycle with multi-user.target,
  # and systemd skips the unit.)
  cat > /etc/systemd/system/vaultgenome-deploy.service <<UNIT
[Unit]
Description=Vault Genome one-button deployment, the settled-boot phase (release $TAG)
After=network-online.target systemd-pcrphase.service
Wants=network-online.target
ConditionPathExists=!$ETC/provision.json

[Service]
Type=oneshot
ExecStart=$SELF
TimeoutStartSec=1800

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload; systemctl enable vaultgenome-deploy.service >/dev/null 2>&1 || fail "systemctl enable vaultgenome-deploy"
  touch "$INSTALLED"; sync
  mark reboot
  sleep 3; reboot
  exit 0
fi

mark settled_boot
note "settled boot: $(journalctl --list-boots --no-pager 2>/dev/null | wc -l | tr -d ' ') boots on record"
# The PCR phase barrier has run before anything is sealed (see the unit):
# a start of an already-finished oneshot is a no-op, and a start of one
# that has not run yet extends PCR 11 to "ready" now.
systemctl start systemd-pcrphase.service 2>/dev/null || true
note "pcrphase=$(systemctl is-active systemd-pcrphase.service 2>/dev/null || echo absent)"
# The vTPM's PCRs and its event log as they are when the key files are
# sealed: what a later boot must reproduce for them to open (the record
# compares them with the boot after a restart).
tpm2_pcrread sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,23 > "$OUT/pcrs-at-seal.txt" 2>&1 || true
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements > "$OUT/eventlog-at-seal.yaml" 2>/dev/null || true
export PYTHONPATH=$VAR/worker/genome TOKENIZERS_PARALLELISM=false
PRODUCT=$(cat "$VAR/.product" 2>/dev/null); [ -n "$PRODUCT" ] || fail "no product recorded by the first phase"

step "acpctl provision: keys, configurations, the AMD $PRODUCT chain from KDS, identities and boots pinned, the key files sealed to the vTPM"
mark provision_start
"$BIN/acpctl" provision --out "$ETC" --bin-dir "$BIN" --provider auto --sealer "$SEALER" --fetch-amd-chain "$PRODUCT" \
  --door-python "$VAR/venv/bin/python3" --base-model "$VAR/base" --worker-package "$VAR/worker/genome" \
  --genome-dir "$VAR/genomes" --audit-log "$VAR/audit/audit.db" --queue-path "$VAR/queue/jobs.db" \
  --vault-descriptor sagvd-azure-deploy-v1 --worker-descriptor acp-compute-azure-deploy-v1 > "$OUT/provision.out" 2> "$OUT/provision.err"
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
print("vault_boot=%s" % d["vault"].get("vtpm_pcr_digest_hex")); print("worker_boot=%s" % d["worker"].get("vtpm_pcr_digest_hex"))
print("vault_sealer=%s" % d["vault"].get("sealer")); print("worker_sealer=%s" % d["worker"].get("sealer"))
print("sealed_sagvd=%s" % ",".join(d.get("sealed", {}).get("sagvd", []))); print("sealed_worker=%s" % ",".join(d.get("sealed", {}).get("acp-compute", [])))
print("amd_cert_chain=%s" % d.get("amd_cert_chain")); print("audit_kid=%s authority_kid=%s" % (d["vault"].get("audit_kid"), d["vault"].get("authority_kid")))
PY
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
# Both services after systemd's PCR phase barrier, like the deployment
# unit: the key files open in the boot phase they were sealed in.
for d in sagvd acp-compute; do
  case "$d" in sagvd) DESC="authority (sagvd)"; AFTER="network-online.target systemd-pcrphase.service"; WANTS="network-online.target";; *) DESC="worker (acp-compute)"; AFTER="network-online.target systemd-pcrphase.service sagvd.service"; WANTS="network-online.target sagvd.service";; esac
  cat > "/etc/systemd/system/$d.service" <<UNIT
[Unit]
Description=Vault Genome $DESC, release $TAG
Documentation=$REPO_URL/blob/$TAG/docs/operator/00_overview.md
After=$AFTER
Wants=$WANTS

[Service]
ExecStart=$BIN/$d -config $ETC/$d.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$VAR $ETC

[Install]
WantedBy=multi-user.target
UNIT
done
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
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
note "sagvd_ready_after=${n}s"; curl -sf http://127.0.0.1:9081/readyz >/dev/null || { journalctl -u sagvd --no-pager -n 30 -o cat; fail "sagvd is not ready after 90 s"; }
systemctl enable --now acp-compute.service >/dev/null 2>&1 || fail "systemctl enable --now acp-compute"
n=0; until curl -sf http://127.0.0.1:9082/healthz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
n=0; until journalctl -u sagvd --no-pager -o cat | grep -q "sagvd session opened" || [ $n -ge 120 ]; do sleep 1; n=$((n+1)); done
if ! journalctl -u sagvd --no-pager -o cat | grep -q "sagvd session opened"; then
  journalctl -u sagvd -u acp-compute --no-pager -n 40 -o cat
  # The verifier's reason, in words: the last handshake failure the worker logged.
  reason="$(journalctl -u acp-compute --no-pager -o cat | grep 'return-path cycle failed' | tail -1 | python3 -c 'import json,sys
l = sys.stdin.read(); i = l.find("{")
try: print(json.loads(l[i:]).get("err", ""))
except Exception: print("")' 2>/dev/null | sed 's/.*verification failed: //' | cut -c1-400)"
  case "$reason" in
    *"TCB floor"*)
      # ADR 0033: a chip whose SNP firmware or microcode is below AMD's
      # bulletin level is refused at admission. The host is Azure's choice,
      # not this deployment's: another deployment lands on another host.
      fail "REFUSED by the verifier, not by this deployment: $reason — the host Azure chose runs chip firmware below AMD's floor (ADR 0033). Destroy this deployment and deploy again: Azure places the VM on another host, and the next is usually current";;
    *) fail "the worker did not open a session with the authority in 120 s${reason:+: $reason}";;
  esac
fi
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

step "metrics; then the audit log verified under the operator's key with both services paused, and the chip as the verifier read it"
curl -s http://127.0.0.1:9081/metrics | grep -E "^(sagvd|rp|vg_tee)_" > "$OUT/sagvd-metrics.txt"
curl -s http://127.0.0.1:9082/metrics | grep -E "^(acp_compute|rp|vg_tee)_" > "$OUT/acp-compute-metrics.txt"
KID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vault"]["audit_kid"])' "$OUT/provision.json" 2>/dev/null); KID=${KID:-sagvd-audit-demo}
mark pause_start
systemctl stop acp-compute.service sagvd.service
"$BIN/acpctl" audit verify --audit "$VAR/audit/audit.db" --audit-pubkey "$ETC/operator/audit_public_key.pem" --audit-kid "$KID" --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"
RC=$?; note "audit verify exit=$RC"
"$BIN/acpctl" audit query --audit "$VAR/audit/audit.db" --limit 0 --json > "$OUT/audit-events.jsonl" 2> "$OUT/audit-query.err"
"$BIN/acpctl" status --audit "$VAR/audit/audit.db" > "$OUT/status.txt" 2>/dev/null || true
mark pause_end
systemctl start sagvd.service
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
note "restart_sagvd_ready_after=${n}s"
systemctl start acp-compute.service
n=0; until [ "$(journalctl -u sagvd --no-pager -o cat | grep -c "sagvd session opened")" -ge 2 ] || [ $n -ge 120 ]; do sleep 1; n=$((n+1)); done
note "restart_session_opened_after=${n}s"; mark restarted
[ "$RC" = 0 ] || fail "acpctl audit verify exit $RC (see audit-verify.err)"
curl -sf http://127.0.0.1:9081/readyz >/dev/null || { journalctl -u sagvd --no-pager -n 30 -o cat; fail "sagvd did not come back after the pause"; }
[ "$(journalctl -u sagvd --no-pager -o cat | grep -c "sagvd session opened")" -ge 2 ] || { journalctl -u sagvd -u acp-compute --no-pager -n 40 -o cat; fail "the worker did not open a session again after the pause"; }
# The admitted worker's chip and boot, as the vault's verifier read them
# (ADR 0033, 0037), from the TRUST_EVALUATED record of the session it opened.
python3 - "$OUT/audit-events.jsonl" > "$OUT/chip.txt" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e.get("kind") != "TRUST_EVALUATED": continue
    pd = (e.get("payload") or {}).get("peer_detail") or {}
    s = pd.get("sev_snp") or {}
    if s:
        t, c, f = s["tcb"]["reported"], s["cpuid"], s["floor"]
        print("peer chip product=%s variant=%s cpuid=%#x/%#x/%#x snp=%#x microcode=%#x firmware=%s alias_check=%s mit_vector=%s floor_snp=%#x floor_microcode=%#x" % (
            s["product"], s.get("variant"), c["family"], c["model"], c["stepping"], t["snp"], t["microcode"], s["firmware"]["current"],
            str(s["platform_info"]["alias_check_complete"]).lower(), s["mitigation_vector"]["current_hex"], f["snp"], f["microcode"]))
    v = pd.get("vtpm") or pd.get("tpm2") or {}
    if v:
        print("peer boot " + " ".join("%s=%s" % (k, val) for k, val in v.items() if isinstance(val, (str, int, bool))))
    if s or v: break
PY
cat "$OUT/chip.txt" >> "$OUT/steps.txt"
journalctl -u sagvd --no-pager -o cat > "$OUT/sagvd.log"; journalctl -u acp-compute --no-pager -o cat > "$OUT/acp-compute.log"
python3 -c 'import sys,time; t0=float(sys.argv[1]); print("elapsed_seconds=%.1f" % (time.time()-t0))' "$T0" >> "$OUT/steps.txt"
mark finished
echo "$TAG $STAMP azure-sev-snp" > "$ETC/DEPLOYED"; chmod 0600 "$ETC/DEPLOYED"
systemctl disable vaultgenome-deploy.service >/dev/null 2>&1 || true

cp "$LOG" "$OUT/console.log"
( cd "$OUT" && sha256sum -- * > "$WORK/sha256sums.txt" ); mv "$WORK/sha256sums.txt" "$OUT/"
# The record holds no secret and is the ssh user's to fetch: readable.
chmod -R a+rX "$VAR/record"
sync   # the record and the marker are on disk before the console says so

echo "== emit"   # not via step: steps.txt is already under sha256sums.txt
cd "$VAR/record" && tar czf "$WORK/$STAMP.tgz" "$STAMP" && base64 -w0 "$WORK/$STAMP.tgz" > "$WORK/$STAMP.b64"
SZ=$(stat -c%s "$WORK/$STAMP.b64"); H=$(sha256sum "$WORK/$STAMP.b64" | cut -d' ' -f1)
fold -w 76 "$WORK/$STAMP.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$WORK/$STAMP.lines"; NL=$(wc -l < "$WORK/$STAMP.lines")
# What a person reads in the portal's boot diagnostics, before the record.
kv() { sed -n "s/^$1=//p" "$OUT/steps.txt" | head -1; }
{
  echo; echo "===VG-PROVEN==="
  echo "Vault Genome $TAG on $(imds compute/name) ($(imds compute/location), $(imds compute/vmSize)): Azure Confidential VM, AMD SEV-SNP ($PRODUCT) under the paravisor"
  echo "  release      the checksums list verified on this guest under $IDENTITY_PREFIX$TAG; $(kv checksums_ok)"
  echo "  chip         $(grep -o 'product=[^ ]* .*' "$OUT/chip.txt" | head -1)"
  echo "  identities   vault $(kv vault_measurement | cut -c1-16)… = worker $(kv worker_measurement | cut -c1-16)… (the launch measurement, pinned on both sides); boot $(kv worker_boot | cut -c1-16)… pinned"
  echo "  key files    sealed to the vTPM on a settled boot ($(kv vault_sealer)); provision exit $(kv 'provision exit')"
  echo "  services     sagvd ready after $(kv sagvd_ready_after), the session open after $(kv session_opened_after); back after the audit read: ready $(kv restart_sagvd_ready_after), session $(kv restart_session_opened_after)"
  echo "  gate         $(sed -n 's/^gate_level=\([^ ]*\).*/\1/p' "$OUT/steps.txt" | head -1) at rung $(sed -n 's/^gate_level=.*rung=\([^ ]*\).*/\1/p' "$OUT/steps.txt" | head -1), $(sed -n 's/^gate_level=.*n_exact=\([^ ]*\).*/\1/p' "$OUT/steps.txt" | head -1) of $(sed -n 's/^gate_level=.*fixtures=\([^ ]*\).*/\1/p' "$OUT/steps.txt" | head -1) fixtures byte for byte, $(kv job_wait) after submission"
  echo "  audit log    ok=$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["ok"]).lower())' "$OUT/audit-verify.json" 2>/dev/null), $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["event_count"])' "$OUT/audit-verify.json" 2>/dev/null) events verified under the operator's key"
  echo "  record       /var/lib/vaultgenome/record/$STAMP (sha256sums.txt inside); $(kv elapsed_seconds) s on the settled boot"
  echo "===VG-PROVEN-END==="
} > /dev/ttyS0 2>/dev/null || true
dmesg -n 1 2>/dev/null || true
sleep 5
for COPY in 1 2 3; do
  { echo; echo "===VG-DEPLOY-BEGIN=== $STAMP size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "$WORK/$STAMP.lines"; echo "===VG-DEPLOY-END==="; } > /dev/ttyS0 2>/dev/null || true
  sleep 3
done
rm -f "$WORK/$STAMP.tgz" "$WORK/$STAMP.b64" "$WORK/$STAMP.lines"
echo "VG DEPLOY DONE $STAMP size=$SZ sha256=$H lines=$NL"
