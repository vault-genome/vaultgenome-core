#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script for a GCP AMD SEV-SNP Confidential VM (Ubuntu 24.04).
#
# Runs the shipping binaries end to end on real hardware — the Continuity
# Drill's last step (ADR 0011): acpctl seals a genome; acp-bootstrap attests
# with the chip (tee.provider "gcp-sev-snp", reports through the kernel's
# configfs-tsm); `sagvd crosscloud-restore` releases the genome's key to it
# only after verifying that Evidence — VCEK signature, VCEK -> ASK -> ARK
# chain, guest policy, and the ADR 0009 challenge that binds the
# destination's per-handshake X25519 key; acp-bootstrap restores the genome
# by itself and signs a receipt with the chip; `sagvd crosscloud-confirm`
# verifies that receipt and records the restore. Releases to a guest the
# allow-list does not name, and under an operator stop, must be refused.
#
# Inputs (instance metadata): vg-bucket — GCS bucket holding e2e/{sagvd,
# acp-bootstrap,keygen,amd-milan-cert_chain.pem}; vg-profile — the
# cryptographic profile (ADR 0029: general, fips or cnsa) both daemons run
# under, written into their configs below. Output: a base64 tarball
# of the results on the serial console between ===E2E-BEGIN=== and
# ===E2E-END=== (three copies), decoded by decode-results.sh. The tarball
# holds reports and logs only; keys, seeds, tokens and configs stay on the
# VM and die with it.
set -u
exec > >(tee -a /root/e2e.log) 2>&1
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }
# The record is named by the runner's stamp (vg-stamp), unique per run —
# two guests booted in the same second would otherwise share a name and
# the later decode would overwrite the earlier record. Absent, the guest's
# own clock names it, as before.
STAMP=$(md attributes/vg-stamp 2>/dev/null || true); case "$STAMP" in 20[0-9][0-9][01][0-9][0-3][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;; *) STAMP=$(date -u +%Y%m%dT%H%M%SZ);; esac
WORK=/root/e2e; OUT=$WORK/out/$STAMP; mkdir -p "$OUT"; cd "$WORK"
BUCKET=$(md attributes/vg-bucket)
PROFILE=$(md attributes/vg-profile); [ -n "$PROFILE" ] || PROFILE=general
echo "profile=$PROFILE" >> "$OUT/steps.txt"
FIPS=$(md attributes/vg-fips 2>/dev/null || true); [ "$FIPS" = 1 ] || FIPS=0
# VG_FIPS=1 on the runner (ADR 0030, part two): every Go process on this
# guest runs under enforcement; a non-approved service fails instead of
# succeeding. The binaries came built on the certified module.
if [ "$FIPS" = 1 ]; then export GODEBUG=fips140=only; echo "fips=1 GODEBUG=fips140=only" >> "$OUT/steps.txt"; fi
# The signature suite (ADR 0031): what acp-keygen makes the keys under and
# what every config names, from the runner (vg-sigsuite); absent, the
# profile's own.
SIGSUITE=$(md attributes/vg-sigsuite 2>/dev/null || true)
case "$SIGSUITE" in ed25519|ecdsa-p384-sha384|ml-dsa-87) ;; *) case "$PROFILE" in cnsa) SIGSUITE=ecdsa-p384-sha384;; *) SIGSUITE=ed25519;; esac;; esac
echo "signature_suite=$SIGSUITE" >> "$OUT/steps.txt"
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; echo "captured=$STAMP"; } > "$OUT/metadata.txt"
uname -a > "$OUT/kernel.txt"

step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }

step "binaries from gs://$BUCKET/e2e"
# Plain curl against the Storage JSON API with the VM's own token: no
# dependency on which cloud SDK the image ships.
GTOKEN=$(md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
for f in sagvd acp-bootstrap acpctl keygen amd-milan-cert_chain.pem; do
  curl -sSf -H "Authorization: Bearer $GTOKEN" -o "$WORK/$f" \
    "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/e2e%2F$f?alt=media" || echo "fetch $f failed"
done
unset GTOKEN
chmod +x sagvd acp-bootstrap acpctl keygen
./sagvd version > "$OUT/versions.txt"; ./acp-bootstrap version >> "$OUT/versions.txt"
sha256sum sagvd acp-bootstrap acpctl keygen amd-milan-cert_chain.pem > "$OUT/inputs.sha256"

step "configfs-tsm"
modprobe sev-guest 2>/dev/null || {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
  modprobe sev-guest 2>/dev/null || true
}
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail -20; } > "$OUT/tsm.txt"

step "provision (keygen)"
./keygen -out secrets -quiet -signature-suite "$SIGSUITE"
TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'); printf '%s\n' "$TOKEN" > secrets/xcc_token; chmod 600 secrets/xcc_token

step "sagvd identity"
S=$WORK/secrets
cat > sagvd.json <<EOF
{
  "vault": {"listen_address": "127.0.0.1:9443",
    "tls": {"enabled": true, "server_cert": "$S/sagvd/tls/server.crt", "server_key": "$S/sagvd/tls/server.key", "client_cas": "$S/shared/tls/ca.crt"}},
  "http_api": {"listen_address": "127.0.0.1:9080", "bearer_token_file": "$S/sagvd/api_token"},
  "tee": {"workload_descriptor": "sagvd-phase1-demo-v1", "seed_path": "$S/sagvd/tee_seed", "insecure_simulation": true,
    "peer": {"public_key_path": "$S/sagvd/peer_worker_pubkey", "measurement_path": "$S/sagvd/peer_worker_measurement"}},
  "keys": {"authority_signing": {"kid": "sagvd-authority-demo", "seed_path": "$S/sagvd/authority_signing_seed", "suite": "$SIGSUITE"},
           "audit_signing": {"kid": "sagvd-audit-demo", "seed_path": "$S/sagvd/audit_signing_seed", "suite": "$SIGSUITE"},
           "session_sealing": {"kid": "session-sealing-demo", "material_path": "$S/shared/sealing.key"}},
  "workers": {"registry_path": "$S/shared/workers.json"},
  "runtime": {"job_timeout_seconds": 60, "handshake_timeout_seconds": 10, "queue_poll_ms": 50,
    "http_read_header_timeout_seconds": 5, "http_write_timeout_seconds": 30, "default_job_deadline_seconds": 60, "max_payload_bytes": 4194304},
  "health": {"listen_address": "127.0.0.1:9081"},
  "log": {"level": "info", "format": "json"},
  "crypto": {"profile": "$PROFILE", "signature_suite": "$SIGSUITE"}
}
EOF
./sagvd identity -config sagvd.json > "$OUT/sagvd-identity.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("sagvd crypto_profile=%s kem_suites=%s" % (d.get("crypto_profile"), ",".join(d.get("kem_suites") or [])))' "$OUT/sagvd-identity.json" >> "$OUT/steps.txt"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("sagvd signature_suite=%s signature_suites=%s" % (d.get("signature_suite"), ",".join(d.get("signature_suites") or []))); print("sagvd authority_signature_suite=%s audit_signature_suite=%s" % (d.get("authority_signature_suite"), d.get("audit_signature_suite")))' "$OUT/sagvd-identity.json" >> "$OUT/steps.txt"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])).get("fips140") or {}; print("sagvd fips140 enabled=%s enforced=%s version=%s" % (str(d.get("enabled")).lower(), str(d.get("enforced")).lower(), d.get("version")))' "$OUT/sagvd-identity.json" >> "$OUT/steps.txt" 2>/dev/null
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["authority_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > authority.pem
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["audit_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > audit.pem

step "seal a genome (a fine-tune output: LoRA weights, config, tokenizer)"
mkdir -p adapter/tokenizer bundles
head -c 16777216 /dev/urandom > adapter/adapter_model.safetensors
printf '{"base_model_name_or_path":"Qwen/Qwen2.5-0.5B","r":16,"lora_alpha":32}' > adapter/adapter_config.json
printf '{"eos_token":"<|im_end|>"}' > adapter/tokenizer/tokenizer_config.json
./acpctl genome seal --content-dir adapter --output gen-1.genome --key-out gen-1.key --json > "$OUT/seal.json" 2> "$OUT/seal.err"
echo "seal exit=$?" >> "$OUT/steps.txt"
KID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_id"])' "$OUT/seal.json")
echo "key_id=$KID" >> "$OUT/steps.txt"
# Replicated to the destination ahead of any release: opaque without its key.
cp gen-1.genome bundles/.incoming && mv bundles/.incoming bundles/gen-1.genome

step "operator stop key and first list (nothing stopped)"
# In production the operator key lives on the operator's machine; the
# release host only ever sees operator.pem and the signed list.
./acpctl stop keygen -out operator.seed -pub operator.pem -signature-suite "$SIGSUITE" > /dev/null
./acpctl stop issue -key operator.seed -signature-suite "$SIGSUITE" -kid operator-1 -serial 1 -out stop.json > /dev/null

step "acp-bootstrap on SEV-SNP"
cat > dest.json <<EOF
{
  "http": {"listen_address": "127.0.0.1:8443", "bearer_token_file": "$S/xcc_token",
    "tls": {"enabled": true, "server_cert": "$S/sagvd/tls/server.crt", "server_key": "$S/sagvd/tls/server.key", "client_cas": "$S/shared/tls/ca.crt"}},
  "tee": {"provider": "gcp-sev-snp", "workload_descriptor": "acp-bootstrap-destination-v1"},
  "source_authority": {"kid": "sagvd-authority-demo", "public_key_path": "$WORK/authority.pem"},
  "genome": {"bundle_dir": "$WORK/bundles", "restore_dir": "$WORK/restored", "rescan_seconds": 1},
  "health": {"listen_address": "127.0.0.1:8444"},
  "log": {"level": "info", "format": "json"},
  "crypto": {"profile": "$PROFILE"}
}
EOF
./acp-bootstrap identity -config dest.json > "$OUT/destination-identity.json" 2> "$OUT/destination-identity.err"
echo "identity exit=$?" >> "$OUT/steps.txt"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("destination crypto_profile=%s kem_suites=%s" % (d.get("crypto_profile"), ",".join(d.get("kem_suites") or [])))' "$OUT/destination-identity.json" >> "$OUT/steps.txt" 2>/dev/null
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("destination signature_suites=%s" % ",".join(d.get("signature_suites") or []))' "$OUT/destination-identity.json" >> "$OUT/steps.txt" 2>/dev/null
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])).get("fips140") or {}; print("destination fips140 enabled=%s enforced=%s version=%s" % (str(d.get("enabled")).lower(), str(d.get("enforced")).lower(), d.get("version")))' "$OUT/destination-identity.json" >> "$OUT/steps.txt" 2>/dev/null
./acp-bootstrap -config dest.json > "$OUT/acp-bootstrap.log" 2>&1 &
DEST=$!
n=0; until curl -sf http://127.0.0.1:8444/readyz >/dev/null || [ $n -ge 30 ]; do sleep 1; n=$((n+1)); done
MEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["measurement_hex"])' "$OUT/destination-identity.json" 2>/dev/null)
echo "measurement=$MEAS" >> "$OUT/steps.txt"

source_config() { # $1 = allow-listed measurement hex, $2 = output file, $3 = an SNP firmware floor for the destination (ADR 0033; empty = the bulletins')
  local SEVSNP=""
  [ -z "${3:-}" ] || SEVSNP=", \"sev_snp\": {\"tcb_floor\": {\"snp\": $3}}"
  cat > verifiers.json <<EOF
{"verifiers": [{"provider": "gcp-sev-snp", "expected_measurement_hex": "$MEAS", "amd_cert_chain_path": "$WORK/amd-milan-cert_chain.pem", "vcek_cache_dir": "$WORK/vcek-cache"$SEVSNP}]}
EOF
  cat > allow.json <<EOF
{"version": "e2e-policy-v1", "allowed": {"gcp-sev-snp": ["$1"]}}
EOF
  python3 - "$2" <<'PY'
import json, sys
c = json.load(open("sagvd.json"))
S = "/root/e2e/secrets"
c["crosscloud"] = {"enabled": True, "policy_version": "e2e-policy-v1", "audit_log_path": "/root/e2e/xcc-audit.db",
    "operator_stop": {"kid": "operator-1", "public_key_path": "/root/e2e/operator.pem", "list_path": "/root/e2e/stop.json"},
    "policy_allow_list_path": "/root/e2e/allow.json", "verifier_registry_path": "/root/e2e/verifiers.json",
    "transport_bearer_token": open(S + "/xcc_token").read().strip(), "request_timeout_seconds": 30,
    "transport_tls": {"enabled": True, "client_cert": S + "/acp-compute/tls/client.crt",
                      "client_key": S + "/acp-compute/tls/client.key", "ca_bundle": S + "/shared/tls/ca.crt"}}
json.dump(c, open(sys.argv[1], "w"), indent=2)
PY
}

step "release the genome key to this attested guest"
source_config "$MEAS" sagvd-xcc.json
./sagvd crosscloud-restore -config sagvd-xcc.json -decision-id e2e-decision-1 -destination-kind gcp-sev-snp \
  -destination-endpoint https://127.0.0.1:8443 -key-file "$KID:$WORK/gen-1.key" > "$OUT/release.json" 2> "$OUT/release.err"
echo "release exit=$?" >> "$OUT/steps.txt"
# What the verifier read from the chip's report beyond the measurement, from the
# CROSS_CLOUD_ATTESTATION_VERIFIED record it wrote (ADR 0033): the chip's
# variant, the TCB it reported, the platform's alias check, the mitigation
# vector, and the floor it was held to.
./acpctl audit query --audit xcc-audit.db --kind CROSS_CLOUD_ATTESTATION_VERIFIED --json > "$OUT/attestation-verified.jsonl" 2>/dev/null
python3 - "$OUT/attestation-verified.jsonl" >> "$OUT/steps.txt" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    e = json.loads(line); s = ((e.get("payload") or {}).get("destination_detail") or {}).get("sev_snp") or {}
    if not s: continue
    t, c, f = s["tcb"]["reported"], s["cpuid"], s["floor"]
    print("chip product=%s variant=%s cpuid=%#x/%#x/%#x snp=%#x microcode=%#x bootloader=%#x firmware=%s alias_check=%s mit_vector=%s floor_snp=%#x floor_microcode=%#x floor_from=%s" % (
        s["product"], s.get("variant"), c["family"], c["model"], c["stepping"], t["snp"], t["microcode"], t["bootloader"], s["firmware"]["current"],
        str(s["platform_info"]["alias_check_complete"]).lower(), s["mitigation_vector"]["current_hex"], f["snp"], f["microcode"], s["floor_source"].split(":")[0]))
    break
PY
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("release suite=%s" % d.get("recipient_key_suite")); print("release profile=%s" % d.get("crypto_profile")); print("release recipient_key_sha256=%s" % d.get("recipient_key_sha256"))' "$OUT/release.json" >> "$OUT/steps.txt" 2>/dev/null

step "the destination restores by itself; confirm from its chip-signed receipt"
./sagvd crosscloud-confirm -config sagvd-xcc.json -decision-id e2e-decision-1 \
  -destination-endpoint https://127.0.0.1:8443 -bundle gen-1.genome -wait 120s > "$OUT/confirm.json" 2> "$OUT/confirm.err"
echo "confirm exit=$?" >> "$OUT/steps.txt"
./acpctl genome verify --bundle gen-1.genome --key-file gen-1.key --restored "restored/$KID" --json > "$OUT/verify.json" 2> "$OUT/verify.err"
echo "verify exit=$?" >> "$OUT/steps.txt"
cp "restored/$KID.receipt.json" "$OUT/receipt.json" 2>/dev/null   # digests, ids and the SEV-SNP report: public
curl -s --cert "$S/acp-compute/tls/client.crt" --key "$S/acp-compute/tls/client.key" --cacert "$S/shared/tls/ca.crt" \
  -H "Authorization: Bearer $TOKEN" https://127.0.0.1:8443/v1/genome/restores > "$OUT/restores.json"

# The refused releases below carry a throwaway key: they must not get
# far enough for it to matter.
head -c 32 /dev/urandom > throwaway.key; chmod 600 throwaway.key

step "release refused: guest not on the allow-list"
OTHER=$(printf '%096d' 0 | tr 0 a)
source_config "$OTHER" sagvd-unlisted.json
./sagvd crosscloud-restore -config sagvd-unlisted.json -decision-id e2e-decision-2 -destination-kind gcp-sev-snp \
  -destination-endpoint https://127.0.0.1:8443 -key-file "genome-dek-2:$WORK/throwaway.key" > "$OUT/release-unlisted.json" 2> "$OUT/release-unlisted.err"
echo "unlisted exit=$?" >> "$OUT/steps.txt"

step "release refused: operator stop in force"
source_config "$MEAS" sagvd-xcc.json   # this guest allow-listed again; only the stop refuses it
./acpctl stop issue -key operator.seed -signature-suite "$SIGSUITE" -kid operator-1 -serial 2 -all -reason "e2e: operator stop" -out stop.json > /dev/null
./sagvd crosscloud-restore -config sagvd-xcc.json -decision-id e2e-decision-3 -destination-kind gcp-sev-snp \
  -destination-endpoint https://127.0.0.1:8443 -key-file "genome-dek-3:$WORK/throwaway.key" > "$OUT/release-stopped.json" 2> "$OUT/release-stopped.err"
echo "stopped exit=$?" >> "$OUT/steps.txt"

step "release refused: the operator's TCB floor one above this chip (ADR 0033)"
# The stop is lifted first (a newer list that stops nothing), so that only the
# floor refuses; the floor is the chip's own SNP firmware SVN plus one.
./acpctl stop issue -key operator.seed -signature-suite "$SIGSUITE" -kid operator-1 -serial 3 -reason "e2e: the stop lifted for the floor step" -out stop.json > /dev/null
SNP=$(sed -n 's/^chip .* snp=\(0x[0-9a-f]*\) .*/\1/p' "$OUT/steps.txt" | head -1)
FLOOR=$(( SNP + 1 ))
source_config "$MEAS" sagvd-floor.json "$FLOOR"
./sagvd crosscloud-restore -config sagvd-floor.json -decision-id e2e-decision-4 -destination-kind gcp-sev-snp \
  -destination-endpoint https://127.0.0.1:8443 -key-file "genome-dek-4:$WORK/throwaway.key" > "$OUT/release-floor.json" 2> "$OUT/release-floor.err"
echo "floor exit=$?" >> "$OUT/steps.txt"
./acpctl audit query --audit xcc-audit.db --kind KEY_RELEASE_DENIED --json > "$OUT/key-release-denied.jsonl" 2>/dev/null
echo "floor chip_snp=$SNP floor_snp=$(printf '%#x' "$FLOOR") reason=$(grep -ho 'TCB floor: [^"]*' "$OUT/release-floor.err" "$OUT/release-floor.json" 2>/dev/null | head -1 | cut -c1-140) denied_on_record=$(grep -c 'TCB floor' "$OUT/key-release-denied.jsonl")" >> "$OUT/steps.txt"

step "audit log verified with the published audit key"
./acpctl audit verify --audit xcc-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-demo --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"
echo "audit verify exit=$?" >> "$OUT/steps.txt"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("audit suite=%s events=%s" % (d.get("signature_suite"), d.get("event_count")))' "$OUT/audit-verify.json" >> "$OUT/steps.txt" 2>/dev/null

sleep 2; kill -TERM $DEST; wait $DEST 2>/dev/null
unset TOKEN
cp /root/e2e.log "$OUT/console.log"
sha256sum "$OUT"/* > "$WORK/sha256sums.txt"; mv "$WORK/sha256sums.txt" "$OUT/"

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
