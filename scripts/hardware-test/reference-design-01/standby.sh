#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The standby of reference design 01, as the startup script of a GCP AMD
# SEV-SNP Confidential VM (Ubuntu 24.04) in the second region: acp-bootstrap
# attests with this chip (tee.provider "gcp-sev-snp", reports through the
# kernel's configfs-tsm), publishes its identity for the bank's allow-list,
# receives the genome's key from `sagvd crosscloud-restore` only after the
# bank verified that Evidence, restores the genome by itself and signs the
# receipt with the chip; then the restored model is gated on this chip
# against the fixtures the quant sealed (`acpctl genome gate` through the
# real door) — the design's "restorable on an attested machine in another
# cloud, checked against reference outputs before it serves".
#
# Inputs (instance metadata): vg-bucket — the run's private bucket with
# in/{acp-bootstrap,acpctl,genome-worker.tgz} and, from the bank,
# handoff/{dest-bundle.tgz,base.tgz,gen-0.genome,authority.pem,seal.json};
# vg-profile — the cryptographic profile (ADR 0029). Outputs to the bucket:
# handoff/standby.json (this guest's address and identity), out/b.tgz and
# out/b/DONE (or out/b/FAILED). Keys, the token and the configs stay on
# the VM and die with it.
set -u
exec > >(tee -a /root/standby.log) 2>&1
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
  cp /root/standby.log "$OUT/console.log" 2>/dev/null
  python3 -c 'import sys,time; t0=float(sys.argv[1]); print("elapsed_seconds=%.1f" % (time.time()-t0))' "$T0" >> "$OUT/steps.txt"
  ( cd "$OUT" && sha256sum * > "$WORK/sha256sums.txt" 2>/dev/null ); mv "$WORK/sha256sums.txt" "$OUT/" 2>/dev/null
  ( cd "$WORK" && tar czf b.tgz -C "$OUT" . ) && gcs_put "$WORK/b.tgz" out/b.tgz
  echo "$1" > "$WORK/marker" && gcs_put "$WORK/marker" "out/b/$1"
  echo "STANDBY $1 $STAMP"
}
fail() { step "FAILED: $*"; emit FAILED; exit 1; }

step "binaries from gs://$BUCKET/in"
for f in acp-bootstrap acpctl genome-worker.tgz; do gcs_get "in/$f" "$WORK/$f" || fail "fetch $f"; done
chmod +x acp-bootstrap acpctl
./acp-bootstrap version > "$OUT/versions.txt"; ./acpctl version >> "$OUT/versions.txt" 2>/dev/null || true
sha256sum acp-bootstrap acpctl genome-worker.tgz > "$OUT/inputs.sha256"
mkdir -p workers && tar xzf genome-worker.tgz -C workers

step "configfs-tsm"
modprobe sev-guest 2>/dev/null || {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
  modprobe sev-guest 2>/dev/null || true
}
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail -20; } > "$OUT/tsm.txt"

step "the bank's hand-off: the standby's TLS material and token, the base model, the sealed genome (opaque without its key), the authority's public key"
for _ in $(seq 1 150); do gcs_exists handoff/dest-bundle.tgz && gcs_exists handoff/seal.json && break; sleep 10; done
for f in dest-bundle.tgz base.tgz gen-0.genome authority.pem seal.json; do gcs_get "handoff/$f" "$WORK/$f" || fail "no $f from the bank after 25 minutes"; done
mark handoff_received
mkdir -p secrets && tar xzf dest-bundle.tgz -C secrets && chmod -R go-rwx secrets
tar xzf base.tgz -C "$WORK"
mkdir -p bundles restored && cp gen-0.genome bundles/.incoming && mv bundles/.incoming bundles/gen-0.genome
KID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_id"])' seal.json); echo "key_id=$KID" >> "$OUT/steps.txt"
sha256sum gen-0.genome base.tgz authority.pem >> "$OUT/inputs.sha256"

step "acp-bootstrap on SEV-SNP: identity from this chip, published for the bank's allow-list"
S=$WORK/secrets
cat > dest.json <<CFG
{
  "http": {"listen_address": "0.0.0.0:8443", "bearer_token_file": "$S/xcc_token",
    "tls": {"enabled": true, "server_cert": "$S/server.crt", "server_key": "$S/server.key", "client_cas": "$S/ca.crt"}},
  "tee": {"provider": "gcp-sev-snp", "workload_descriptor": "acp-bootstrap-rd01-standby-v1"},
  "source_authority": {"kid": "sagvd-authority-e2e", "public_key_path": "$WORK/authority.pem"},
  "genome": {"bundle_dir": "$WORK/bundles", "restore_dir": "$WORK/restored", "rescan_seconds": 1},
  "health": {"listen_address": "127.0.0.1:8444"},
  "log": {"level": "info", "format": "json"},
  "crypto": {"profile": "$PROFILE"}
}
CFG
./acp-bootstrap identity -config dest.json > "$OUT/destination-identity.json" 2> "$OUT/destination-identity.err"
echo "identity exit=$?" >> "$OUT/steps.txt"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("standby crypto_profile=%s kem_suites=%s" % (d.get("crypto_profile"), ",".join(d.get("kem_suites") or [])))' "$OUT/destination-identity.json" >> "$OUT/steps.txt" 2>&1
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("standby signature_suites=%s" % ",".join(d.get("signature_suites") or []))' "$OUT/destination-identity.json" >> "$OUT/steps.txt" 2>&1
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])).get("fips140") or {}; print("standby fips140 enabled=%s enforced=%s version=%s" % (str(d.get("enabled")).lower(), str(d.get("enforced")).lower(), d.get("version")))' "$OUT/destination-identity.json" >> "$OUT/steps.txt" 2>/dev/null
MEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["measurement_hex"])' "$OUT/destination-identity.json" 2>/dev/null)
echo "measurement=$MEAS" >> "$OUT/steps.txt"
[ -n "$MEAS" ] || fail "no measurement from the chip: $(cat "$OUT/destination-identity.err")"
./acp-bootstrap -config dest.json > "$OUT/acp-bootstrap.log" 2>&1 &
DEST=$!
n=0; until curl -sf http://127.0.0.1:8444/readyz >/dev/null || [ $n -ge 30 ]; do sleep 1; n=$((n+1)); done
echo "acp-bootstrap ready after ${n}s" >> "$OUT/steps.txt"
python3 - "$OUT/destination-identity.json" "$MY_IP" > standby.json <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
json.dump({"endpoint": "https://%s:8443" % sys.argv[2], "internal_ip": sys.argv[2], "identity": d}, open("standby.json", "w"), indent=2)
PY
gcs_put standby.json handoff/standby.json || fail "publish the identity"
mark identity_published
cp standby.json "$OUT/standby.json"

step "the worker runtime, for the gate on this chip (the door needs it)"
mark runtime_install_start
export DEBIAN_FRONTEND=noninteractive
for _ in $(seq 1 60); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 5; done
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

step "the key arrives only after this chip attested to the bank: wait for the restore (the receipt signed with the chip)"
for _ in $(seq 1 150); do [ -f "restored/$KID.receipt.json" ] && break; sleep 10; done
[ -f "restored/$KID.receipt.json" ] || fail "no restore after 25 minutes; see acp-bootstrap.log"
mark restore_seen
cp "restored/$KID.receipt.json" "$OUT/receipt.json"
ls -la "restored/$KID" > "$OUT/restored-listing.txt" 2>&1
curl -s --cert "$S/client.crt" --key "$S/client.key" --cacert "$S/ca.crt" -H "Authorization: Bearer $(cat "$S/xcc_token")" https://127.0.0.1:8443/v1/genome/restores > "$OUT/restores.json" 2>/dev/null || true
echo "restore seen" >> "$OUT/steps.txt"

step "the restored model gated on this chip against the sealed fixtures, through the real door (acpctl genome gate)"
export PYTHONPATH=$WORK/workers/genome TOKENIZERS_PARALLELISM=false
mark gate_start
./acpctl genome gate --genome "restored/$KID" --json -- "$WORK/venv/bin/python3" -m vg_genome door --genome "restored/$KID" --base "$WORK/base" --device cpu > "$OUT/standby-gate.json" 2> "$OUT/standby-gate.err"
RC=$?; echo "standby gate exit=$RC" >> "$OUT/steps.txt"
mark gate_end
python3 - "$OUT/standby-gate.json" >> "$OUT/steps.txt" 2>&1 <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("standby gate_level=%s fixtures=%s base=%s backend_seconds=%s" % (d.get("level"), d.get("fixtures"), d.get("base"), d.get("backend_seconds")))
PY

step "wait for the bank to finish (its refusals go through this guest too), then stop"
for _ in $(seq 1 90); do gcs_exists out/a/DONE && break; gcs_exists out/a/FAILED && break; sleep 10; done
sleep 2; kill -TERM $DEST; wait $DEST 2>/dev/null
grep -c '"level":"ERROR"' "$OUT/acp-bootstrap.log" > "$OUT/acp-bootstrap.errors.txt" 2>/dev/null || true
emit DONE
