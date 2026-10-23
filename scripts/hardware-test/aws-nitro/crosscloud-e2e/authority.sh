#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The source authority's half of the cross-cloud key release (ADR 0036,
# part four, decision 6), on a GCP AMD SEV-SNP Confidential VM; run.sh
# calls one phase at a time, as root:
#
#   provision                      acp-keygen; sagvd attests with the chip and its key files
#                                  are sealed to it; the operator's stop key; a genome sealed;
#                                  the destination's TLS pair, CA and token taken, before sealing
#   release <ip> <pcr0> <pcr1> <pcr2>  the bundle into the enclave over the API; the genome key
#                                  released to the Nitro enclave only after its document
#                                  verified; the restore confirmed from its NSM-signed receipt;
#                                  refused: an image the allow-list does not name, a PCR the
#                                  registry pins otherwise, the operator stop
#   debug <ip> <pcr0> <pcr1> <pcr2>  refused: the same image in debug mode, given the TLS key and
#                                  the token in the clear, as an insider could
#   finish                         the audit log verified by acpctl and by the auditor's own
#                                  verifier; the record packed for run.sh
#
# Every phase writes steps under out/ and prints "phase <name> rc=<n>" on a
# line of its own, last.
set -uo pipefail
W=/root/xcc; OUT=$W/out; S=$W/secrets; IN="${VG_IN:?VG_IN}"
mkdir -p "$OUT" && cd "$W" 2>/dev/null || { mkdir -p "$W" "$OUT" && cd "$W"; }
PHASE="${1:?phase}"; shift
PROFILE=general; SIGSUITE=ed25519; KIDA=sagvd-authority-xcc; KIDU=sagvd-audit-xcc
step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }

sagvd_config() { # $1 = the crosscloud section's JSON or ""
  python3 - "$1" <<'PY'
import json, sys
W, S = "/root/xcc", "/root/xcc/secrets"
peer = {"provider": "gcp-sev-snp", "measurement_path": W + "/peer.meas", "amd_cert_chain_path": W + "/amd-milan-cert_chain.pem", "vcek_cache_dir": W + "/vcek-cache"}
c = {"vault": {"listen_address": "127.0.0.1:9443",
       "tls": {"enabled": True, "server_cert": S + "/sagvd/tls/server.crt", "server_key": S + "/sagvd/tls/server.key", "client_cas": S + "/shared/tls/ca.crt"}},
     "http_api": {"listen_address": "127.0.0.1:9080", "bearer_token_file": S + "/sagvd/api_token"},
     "tee": {"provider": "auto", "sealer": "auto", "workload_descriptor": "sagvd-nitro-xcc-v1", "peer": peer},
     "keys": {"authority_signing": {"kid": "sagvd-authority-xcc", "seed_path": S + "/sagvd/authority_signing_seed", "suite": "ed25519"},
              "audit_signing": {"kid": "sagvd-audit-xcc", "seed_path": S + "/sagvd/audit_signing_seed", "suite": "ed25519"},
              "session_sealing": {"kid": "session-sealing-xcc", "material_path": S + "/shared/sealing.key"}},
     "workers": {"registry_path": S + "/shared/workers.json"},
     "runtime": {"job_timeout_seconds": 60, "handshake_timeout_seconds": 30, "queue_poll_ms": 50,
       "http_read_header_timeout_seconds": 5, "http_write_timeout_seconds": 30, "default_job_deadline_seconds": 60, "max_payload_bytes": 4194304},
     "health": {"listen_address": "127.0.0.1:9081"},
     "log": {"level": "info", "format": "json"},
     "crypto": {"profile": "general", "signature_suite": "ed25519"}}
if sys.argv[1]:
    c["crosscloud"] = json.loads(sys.argv[1])
json.dump(c, open(W + "/sagvd.json", "w"), indent=2)
PY
}

crosscloud_section() { # the cross-cloud section: the transport's own client pair, sealed under its field
  python3 - <<'PY'
import json
W, S = "/root/xcc", "/root/xcc/secrets"
print(json.dumps({"enabled": True, "policy_version": "xcc-nitro-v1", "audit_log_path": W + "/xcc-audit.db",
    "operator_stop": {"kid": "operator-1", "public_key_path": W + "/operator.pem", "list_path": W + "/stop.json"},
    "policy_allow_list_path": W + "/allow.json", "verifier_registry_path": W + "/verifiers.json",
    "transport_bearer_token": open(S + "/xcc_token").read().strip(), "request_timeout_seconds": 90,
    "transport_tls": {"enabled": True, "client_cert": W + "/xcc/client.crt", "client_key": W + "/xcc/client.key",
                      "ca_bundle": S + "/shared/tls/ca.crt", "server_name": "localhost"}}))
PY
}

policy() { # policy <allow-listed PCR0> <the registry's PCR0> <PCR1> <PCR2>
  python3 - "$@" <<'PY'
import json, sys
allow, pcr0, pcr1, pcr2 = sys.argv[1:5]
W = "/root/xcc"
json.dump({"version": "xcc-nitro-v1", "allowed": {"aws-nitro": [allow]}}, open(W + "/allow.json", "w"))
json.dump({"verifiers": [{"provider": "aws-nitro", "expected_measurement_hex": pcr0, "nitro": {"pcrs": {"1": pcr1, "2": pcr2}}}]}, open(W + "/verifiers.json", "w"))
PY
}

# acp <method> <ip> <path> [curl args...]: the enclave's API as the source reaches it.
acp() {
  local method="$1" ip="$2" path="$3"; shift 3
  curl -sS --max-time 120 -X "$method" --resolve "localhost:8443:$ip" --cert "$W/xcc-plain/client.crt" --key "$W/xcc-plain/client.key" \
    --cacert "$S/shared/tls/ca.crt" -H "Authorization: Bearer $(cat "$W/xcc-plain/token")" "https://localhost:8443$path" "$@"
}

release() { # release <decision> <key-id:key-file> <out-name>
  ./sagvd crosscloud-restore -config sagvd.json -decision-id "$1" -destination-kind aws-nitro \
    -destination-endpoint "https://$IP:8443" -key-file "$2" > "$OUT/$3.json" 2> "$OUT/$3.err"
}

provision() {
  step "the inputs"
  for f in sagvd acp-bootstrap acpctl keygen amd-milan-cert_chain.pem verify_audit.py; do install -m 0755 "$IN/$f" "$W/$f" || return 1; done
  ./sagvd version > "$OUT/versions.txt"; ./acpctl version >> "$OUT/versions.txt" 2>&1
  sha256sum sagvd acp-bootstrap acpctl keygen amd-milan-cert_chain.pem verify_audit.py > "$OUT/inputs.sha256"
  { echo "kernel=$(uname -r)"; echo "machine=$(curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/machine-type | awk -F/ '{print $NF}')";
    echo "zone=$(curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/zone | awk -F/ '{print $NF}')"; } > "$OUT/authority-host.txt"

  step "configfs-tsm: the chip's reports through the kernel"
  modprobe sev-guest 2>/dev/null || { export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1; modprobe sev-guest 2>/dev/null; }
  mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
  n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
  [ -d /sys/kernel/config/tsm/report ] || { echo "no configfs-tsm"; return 1; }

  step "provision (acp-keygen, private modes)"
  ./keygen -out secrets -quiet -private -signature-suite "$SIGSUITE" || return 1
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$S/xcc_token"; echo >> "$S/xcc_token"; chmod 600 "$S/xcc_token"
  mkdir -p vcek-cache xcc xcc-plain bundles && chmod 700 xcc xcc-plain
  head -c 48 /dev/zero > peer.meas

  step "the destination's bundle and the transport's client pair, taken before sealing"
  # The enclave serves acp-bootstrap under the server certificate keygen
  # issued (localhost among its names; the source dials the parent's
  # address with server_name localhost) and verifies the source's client
  # certificate against the same CA. Plaintext copies for the operator,
  # who seals them for the image: seal-keys turns the originals here into
  # files only this chip opens.
  mkdir -p dest-bundle && chmod 700 dest-bundle
  cp "$S/sagvd/tls/server.crt" "$S/sagvd/tls/server.key" "$S/shared/tls/ca.crt" dest-bundle/ && cp "$S/xcc_token" dest-bundle/token
  ( cd dest-bundle && tar czf ../dest-bundle.tgz . ) && chmod 600 dest-bundle.tgz && rm -rf dest-bundle
  cp "$S/acp-compute/tls/client.crt" "$S/acp-compute/tls/client.key" xcc/ && cp "$S/acp-compute/tls/client.crt" "$S/acp-compute/tls/client.key" xcc-plain/
  cp "$S/xcc_token" xcc-plain/token && chmod 600 xcc/client.key xcc-plain/client.key xcc-plain/token

  step "sagvd on SEV-SNP: its identity from the chip"
  ./acpctl stop keygen -out operator.seed -pub operator.pem -signature-suite "$SIGSUITE" > /dev/null || return 1
  ./acpctl stop issue -key operator.seed -signature-suite "$SIGSUITE" -kid operator-1 -serial 1 -out stop.json > /dev/null || return 1
  policy "$(printf '11%.0s' $(seq 48))" "$(printf '11%.0s' $(seq 48))" "$(printf '12%.0s' $(seq 48))" "$(printf '13%.0s' $(seq 48))"
  sagvd_config "$(crosscloud_section)"
  ./sagvd identity -config sagvd.json > "$OUT/sagvd-identity.json" 2> "$OUT/sagvd-identity.err"; echo "sagvd identity exit=$?" >> "$OUT/steps.txt"
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("sagvd tee_provider=%s measurement=%s" % (d.get("tee_provider"), d.get("tee_measurement_hex")))' "$OUT/sagvd-identity.json" >> "$OUT/steps.txt" 2>&1
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["authority_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > authority.pem
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["audit_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > audit.pem
  cp authority.pem "$OUT/authority-public-key.pem"; cp audit.pem "$OUT/audit-public-key.pem"

  step "the authority's key files sealed to this chip (ADR 0023)"
  ./sagvd seal-keys -config sagvd.json > "$OUT/seal-keys.json" 2> "$OUT/seal-keys.err"
  echo "seal-keys exit=$? sealer=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("sealer"))' "$OUT/seal-keys.json" 2>/dev/null) sealed=$(python3 -c 'import json,sys;print(",".join(e["name"] for e in json.load(open(sys.argv[1]))["sealed"]))' "$OUT/seal-keys.json" 2>/dev/null)" >> "$OUT/steps.txt"
  ./sagvd identity -config sagvd.json > "$OUT/sagvd-identity-sealed.json" 2> "$OUT/sagvd-identity-sealed.err"; echo "sagvd identity from the sealed files exit=$?" >> "$OUT/steps.txt"

  step "seal a genome (a fine-tune's output: LoRA weights, config, tokenizer)"
  mkdir -p adapter/tokenizer
  head -c 16777216 /dev/urandom > adapter/adapter_model.safetensors
  printf '{"base_model_name_or_path":"Qwen/Qwen2.5-0.5B","r":16,"lora_alpha":32}' > adapter/adapter_config.json
  printf '{"eos_token":"<|im_end|>"}' > adapter/tokenizer/tokenizer_config.json
  ./acpctl genome seal --content-dir adapter --output gen-1.genome --key-out gen-1.key --json > "$OUT/seal.json" 2> "$OUT/seal.err"; echo "seal exit=$?" >> "$OUT/steps.txt"
  echo "key_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_id"])' "$OUT/seal.json")" >> "$OUT/steps.txt"
  sha256sum gen-1.genome | awk '{print "bundle_sha256=" $1}' >> "$OUT/steps.txt"
  chmod 644 dest-bundle.tgz authority.pem audit.pem 2>/dev/null; cp dest-bundle.tgz authority.pem /tmp/ && chmod 644 /tmp/dest-bundle.tgz /tmp/authority.pem
}

release_phase() {
  IP="$1"; PCR0="$2"; PCR1="$3"; PCR2="$4"
  KID=$(sed -n 's/^key_id=//p' "$OUT/steps.txt" | tail -1)
  echo "destination=aws-nitro pcr0=$PCR0" >> "$OUT/steps.txt"

  step "the bundle into the enclave over the API (opaque without its key)"
  acp POST "$IP" /v1/genome/bundles --data-binary @gen-1.genome -H 'Content-Type: application/octet-stream' > "$OUT/bundle-upload.json" 2> "$OUT/bundle-upload.err"
  echo "upload exit=$? $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("key_id=%s bundle_sha256=%s bytes=%s" % (d.get("key_id"), d.get("bundle_sha256"), d.get("bytes")))' "$OUT/bundle-upload.json" 2>/dev/null)" >> "$OUT/steps.txt"

  step "the genome key released to the Nitro enclave, only after its document verified"
  policy "$PCR0" "$PCR0" "$PCR1" "$PCR2"
  release nitro-decision-1 "$KID:$W/gen-1.key" release; echo "release exit=$?" >> "$OUT/steps.txt"
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("release suite=%s profile=%s recipient_key_sha256=%s" % (d.get("recipient_key_suite"), d.get("crypto_profile"), d.get("recipient_key_sha256")))' "$OUT/release.json" >> "$OUT/steps.txt" 2>/dev/null
  ./acpctl audit query --audit xcc-audit.db --kind CROSS_CLOUD_ATTESTATION_VERIFIED --json > "$OUT/attestation-verified.jsonl" 2>/dev/null
  python3 - "$OUT/attestation-verified.jsonl" >> "$OUT/steps.txt" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    p = json.loads(line).get("payload") or {}
    n = (p.get("destination_detail") or {}).get("nitro") or {}
    if n:
        print("nitro module=%s timestamp=%s pcr0=%s pinned=%s" % (n.get("module_id"), n.get("timestamp"), (n.get("pcrs") or {}).get("0"), ",".join(str(i) for i in n.get("pinned") or [])))
        break
PY

  step "the enclave restores by itself; the restore confirmed from its NSM-signed receipt"
  ./sagvd crosscloud-confirm -config sagvd.json -decision-id nitro-decision-1 -destination-endpoint "https://$IP:8443" \
    -bundle gen-1.genome -wait 180s > "$OUT/confirm.json" 2> "$OUT/confirm.err"; echo "confirm exit=$?" >> "$OUT/steps.txt"
  acp GET "$IP" "/v1/genome/receipt?key_id=$KID" > "$OUT/receipt.json" 2> "$OUT/receipt.err"
  acp GET "$IP" /v1/genome/restores > "$OUT/restores.json" 2> "$OUT/restores.err"

  head -c 32 /dev/urandom > throwaway.key; chmod 600 throwaway.key
  step "refused: an image the allow-list does not name"
  OTHER=$(head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n')
  policy "$OTHER" "$PCR0" "$PCR1" "$PCR2"
  release nitro-decision-2 "genome-dek-2:$W/throwaway.key" release-unlisted; echo "unlisted exit=$?" >> "$OUT/steps.txt"
  step "refused: a PCR the registry pins to another value"
  policy "$PCR0" "$PCR0" "$PCR1" "$(head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  release nitro-decision-3 "genome-dek-3:$W/throwaway.key" release-pin; echo "pin exit=$?" >> "$OUT/steps.txt"
  step "refused: the operator stop in force"
  policy "$PCR0" "$PCR0" "$PCR1" "$PCR2"
  ./acpctl stop issue -key operator.seed -signature-suite "$SIGSUITE" -kid operator-1 -serial 2 -all -reason "xcc: operator stop" -out stop.json > /dev/null
  release nitro-decision-4 "genome-dek-4:$W/throwaway.key" release-stopped; echo "stopped exit=$?" >> "$OUT/steps.txt"
  ./acpctl stop issue -key operator.seed -signature-suite "$SIGSUITE" -kid operator-1 -serial 3 -reason "xcc: the stop lifted for the debug step" -out stop.json > /dev/null
}

debug_phase() {
  IP="$1"; PCR0="$2"; PCR1="$3"; PCR2="$4"
  step "refused: the same image in debug mode, given the TLS key and the token in the clear"
  policy "$PCR0" "$PCR0" "$PCR1" "$PCR2"
  release nitro-decision-5 "genome-dek-5:$W/throwaway.key" release-debug; echo "debug exit=$?" >> "$OUT/steps.txt"
}

finish() {
  ./acpctl audit query --audit xcc-audit.db --kind CROSS_CLOUD_ATTESTATION_VERIFIED --json > "$OUT/attestation-verified.jsonl" 2>/dev/null
  ./acpctl audit query --audit xcc-audit.db --kind KEY_RELEASE_DENIED --json > "$OUT/key-release-denied.jsonl" 2>/dev/null
  step "the audit log verified with the published audit key: by acpctl, and by the auditor's own verifier"
  ./acpctl audit verify --audit xcc-audit.db --audit-pubkey audit.pem --audit-kid "$KIDU" --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"; echo "audit verify exit=$?" >> "$OUT/steps.txt"
  python3 -I ./verify_audit.py --audit xcc-audit.db --audit-pubkey audit.pem --audit-kid "$KIDU" --json > "$OUT/auditor-verify.json" 2> "$OUT/auditor-verify.err"; echo "auditor verify exit=$?" >> "$OUT/steps.txt"
  ( cd "$OUT" && sha256sum * > "$W/sha256sums.txt" ) && mv "$W/sha256sums.txt" "$OUT/"
  tar czf /tmp/authority-out.tgz -C "$W" out && chmod 644 /tmp/authority-out.tgz
}

case "$PHASE" in
  provision) provision ;;
  release) release_phase "$@" ;;
  debug) debug_phase "$@" ;;
  finish) finish ;;
  *) echo "unknown phase $PHASE"; false ;;
esac
rc=$?
echo
echo "phase $PHASE rc=$rc"
