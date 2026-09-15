#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The failover drill's STANDBY: an AMD SEV-SNP Confidential VM that hosts
# both the release authority (sagvd failover) and the destination
# (acp-bootstrap), on loopback TLS. It provisions the authority's escrow
# key and hands its public half to the primary, pulls the primary's outbox
# replica from a bucket, and — under an operator-signed failover policy —
# waits. When the primary's sentinel reports a compromise, the authority
# releases the last trustworthy genome's escrowed key to acp-bootstrap
# (attested with this chip), which restores it, proves the model works and
# signs a receipt; the authority confirms it. Reports go to out/standby/.
set -u
exec > >(tee -a /root/standby.log) 2>&1
BUCKET=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-bucket")
OUT=/root/out; REPLICA=/root/replica; WORK=/root; mkdir -p "$OUT" /opt/worker "$REPLICA"; cd "$WORK"
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
finish() {
  cp /root/standby.log "$OUT/console.log" 2>/dev/null || true
  cp /root/acp-bootstrap.log "$OUT/acp-bootstrap.log" 2>/dev/null || true
  cp /root/failover.log "$OUT/failover.log" 2>/dev/null || true
  tar -C "$OUT" -czf /root/out.tgz . 2>/dev/null && gcs_put /root/out.tgz out/standby.tgz 2>/dev/null || true
  echo "$1" > /root/marker; gcs_put /root/marker "out/standby/$1" 2>/dev/null || true
}
trap 'finish FAILED' ERR

curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-common" > /root/common.sh
. /root/common.sh
set -eE

step "inputs"
for b in sagvd acp-bootstrap acpctl keygen; do gcs_get "in/$b" "/usr/local/bin/$b" && chmod +x "/usr/local/bin/$b"; done
gcs_get in/amd-milan-cert_chain.pem /root/amd-milan-cert_chain.pem
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu; } > "$OUT/system.txt" 2>&1

step "provision (keygen), escrow key, operator stop key"
keygen -out /root/secrets -quiet
TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'); printf '%s\n' "$TOKEN" > /root/secrets/xcc_token; chmod 600 /root/secrets/xcc_token
acpctl escrow keygen --out /root/escrow.key --pub /root/escrow-local.pem > "$OUT/escrow-keygen.txt"
acpctl stop keygen --out /root/operator.seed --pub /root/operator.pem > /dev/null
acpctl stop issue --key /root/operator.seed --kid operator-1 --serial 1 --out /root/stop.json > /dev/null
gcs_put /root/escrow-local.pem handoff/escrow.pem

S=/root/secrets
step "python runtime (CPU) and base model — the gate runs the model here"
python_runtime https://download.pytorch.org/whl/cpu
base_model

step "configfs-tsm (real SEV-SNP reports)"
modprobe sev-guest 2>/dev/null || {
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
  modprobe sev-guest 2>/dev/null || true
}
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail; } > "$OUT/tsm.txt" 2>&1

step "sagvd identity"
python3 - <<PY
import json
S="$S"
c={
 "vault":{"listen_address":"127.0.0.1:9443","tls":{"enabled":True,"server_cert":S+"/sagvd/tls/server.crt","server_key":S+"/sagvd/tls/server.key","client_cas":S+"/shared/tls/ca.crt"}},
 "http_api":{"listen_address":"127.0.0.1:9080","bearer_token_file":S+"/sagvd/api_token"},
 "tee":{"workload_descriptor":"sagvd-failover-authority-v1","seed_path":S+"/sagvd/tee_seed","insecure_simulation":True,
        "peer":{"public_key_path":S+"/sagvd/peer_worker_pubkey","measurement_path":S+"/sagvd/peer_worker_measurement"}},
 "keys":{"authority_signing":{"kid":"sagvd-authority-demo","seed_path":S+"/sagvd/authority_signing_seed"},
         "audit_signing":{"kid":"sagvd-audit-demo","seed_path":S+"/sagvd/audit_signing_seed"},
         "session_sealing":{"kid":"session-sealing-demo","material_path":S+"/shared/sealing.key"}},
 "workers":{"registry_path":S+"/shared/workers.json"},
 "runtime":{"job_timeout_seconds":60,"handshake_timeout_seconds":10,"queue_poll_ms":50,"http_read_header_timeout_seconds":5,"http_write_timeout_seconds":30,"default_job_deadline_seconds":60,"max_payload_bytes":4194304},
 "health":{"listen_address":"127.0.0.1:9081"},"log":{"level":"info","format":"json"}}
json.dump(c,open("/root/sagvd-base.json","w"),indent=2)
PY
sagvd identity -config /root/sagvd-base.json > "$OUT/authority-identity.json"
python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["authority_public_key_pem"],end="")' "$OUT/authority-identity.json" > /root/authority.pem

step "acp-bootstrap on SEV-SNP (destination + gate)"
python3 - <<PY
import json
S="$S"
c={
 "http":{"listen_address":"127.0.0.1:8443","bearer_token_file":S+"/xcc_token",
         "tls":{"enabled":True,"server_cert":S+"/sagvd/tls/server.crt","server_key":S+"/sagvd/tls/server.key","client_cas":S+"/shared/tls/ca.crt"}},
 "tee":{"provider":"gcp-sev-snp","workload_descriptor":"acp-bootstrap-standby-v1"},
 "source_authority":{"kid":"sagvd-authority-demo","public_key_path":"/root/authority.pem"},
 "genome":{"bundle_dir":"$REPLICA","restore_dir":"/root/restored","rescan_seconds":2,
           "gate":{"command":["/opt/vg/bin/python","-m","vg_genome","door","--genome","{genome}","--base","/opt/base","--device","cpu"],
                   "env":["PYTHONPATH=/opt/worker","TOKENIZERS_PARALLELISM=false"],"atol":0.01,"rtol":0.001,"timeout_seconds":300,"required":True}},
 "health":{"listen_address":"127.0.0.1:8444"},"log":{"level":"info","format":"json"}}
json.dump(c,open("/root/dest.json","w"),indent=2)
PY
acp-bootstrap identity -config /root/dest.json > "$OUT/destination-identity.json" 2> "$OUT/destination-identity.err"
acp-bootstrap -config /root/dest.json > /root/acp-bootstrap.log 2>&1 &
n=0; until curl -sf http://127.0.0.1:8444/readyz >/dev/null || [ $n -ge 30 ]; do sleep 1; n=$((n+1)); done
MEAS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["measurement_hex"])' "$OUT/destination-identity.json")
echo "standby measurement=$MEAS" >> "$OUT/steps.txt"

step "sagvd failover config: verifier registry, allow-list, operator stop, escrow"
python3 - <<PY
import json
S="$S"; MEAS="$MEAS"
json.dump({"verifiers":[{"provider":"gcp-sev-snp","expected_measurement_hex":MEAS,"amd_cert_chain_path":"/root/amd-milan-cert_chain.pem","vcek_cache_dir":"/root/vcek-cache"}]},open("/root/verifiers.json","w"))
json.dump({"version":"failover-policy-v1","allowed":{"gcp-sev-snp":[MEAS]}},open("/root/allow.json","w"))
c=json.load(open("/root/sagvd-base.json"))
c["crosscloud"]={"enabled":True,"policy_version":"failover-policy-v1","audit_log_path":"/root/xcc-audit.db",
 "operator_stop":{"kid":"operator-1","public_key_path":"/root/operator.pem","list_path":"/root/stop.json"},
 "key_escrow_path":"/root/escrow.key",
 "policy_allow_list_path":"/root/allow.json","verifier_registry_path":"/root/verifiers.json",
 "transport_bearer_token":open(S+"/xcc_token").read().strip(),"request_timeout_seconds":30,
 "transport_tls":{"enabled":True,"client_cert":S+"/acp-compute/tls/client.crt","client_key":S+"/acp-compute/tls/client.key","ca_bundle":S+"/shared/tls/ca.crt"}}
json.dump(c,open("/root/sagvd.json","w"),indent=2)
PY

step "wait for the primary's sentinel key, then sign the failover policy"
for i in $(seq 1 180); do gcs_get handoff/sentinel.pem /root/sentinel.pem 2>/dev/null && break; sleep 5; done
[ -s /root/sentinel.pem ] || { echo "no sentinel key after 15 minutes"; false; }
acpctl failover issue --key /root/operator.seed --kid operator-1 --serial 1 \
  --sentinel-pub /root/sentinel.pem --standby-kind gcp-sev-snp --standby-endpoint https://127.0.0.1:8443 \
  --standby-measurement "$MEAS" --heartbeat-timeout 120s --require-gate EQUIVALENT \
  --reason "hardware failover drill" --out /root/failover.json > "$OUT/failover-issue.txt"
acpctl failover verify --in /root/failover.json --pubkey /root/operator.pem --kid operator-1 > "$OUT/failover-verify.txt"

step "pull the primary's outbox replica, continuously"
( while true; do pull_outbox "$REPLICA"; sleep 3; done ) &
PULL=$!

step "arm: sagvd failover watches the replica"
gcs_put_str handoff/armed "armed at $(date -u +%H:%M:%SZ)"
set +e
sagvd failover -config /root/sagvd.json -policy /root/failover.json -outbox "$REPLICA" \
  -poll 2s -confirm-wait 15m -report "$OUT/report.json" > /root/failover.log 2>&1
FCODE=$?
set -e
echo "sagvd failover exit=$FCODE" >> "$OUT/steps.txt"
kill "$PULL" 2>/dev/null || true

step "audit log verify (offline, as an auditor would)"
python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["audit_public_key_pem"],end="")' "$OUT/authority-identity.json" > /root/audit.pem
acpctl audit verify --audit /root/xcc-audit.db --audit-pubkey /root/audit.pem --audit-kid sagvd-audit-demo --json > "$OUT/audit-verify.json" 2>&1 || true

# The restored adapter, to show it is the clean generation and not the
# planted one (its bytes only; nothing secret).
KID=$(python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1]))["genome"]["key_id"])
except Exception: print("")' "$OUT/report.json" 2>/dev/null)
[ -n "$KID" ] && head -c 200 "/root/restored/$KID/adapter/adapter_model.safetensors" > "$OUT/restored-adapter-head.txt" 2>/dev/null || true

[ "$FCODE" = 0 ] || { echo "sagvd failover exited $FCODE"; false; }
trap - ERR
finish DONE
