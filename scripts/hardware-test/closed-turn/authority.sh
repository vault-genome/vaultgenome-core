#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The closed-turn drill's AUTHORITY (machine R): an AMD SEV-SNP
# Confidential VM, in a region of its own, that holds nothing but the
# release authority — sagvd failover, attesting with this chip, its escrow
# key sealed to this chip (ADR 0016).
#
# It publishes its escrow key (both sentinels seal to it) and the
# destination's TLS material. The operator's policy pins the primary's
# sentinel and chip, the standby's measurement — and, in advance, the
# standby's own sentinel: its key and the measurement its records must be
# attested at (ADR 0041). It is a v2 policy; its only trigger is a lost
# heartbeat and its gate must be EXACT.
#
# When the primary falls silent the authority fails the last generation
# over to the standby — and does not exit. It reads the standby's outbox,
# records the generation the standby seals next (CHAIN_CONTINUED), and
# watches the standby. Then, as an operator looking at what the standby
# made would, it releases that generation's escrowed key back to the
# standby (an ordinary attested release) so that it can be opened again
# and the answers recomputed from it. It stops when told (handoff/stop).
#
# vg-mode=negative: the standby's base model is not the genome's. Its gate
# cannot be passed, the restore fails there and is never confirmed here:
# the run ends with the failover on record as decided and not completed.
set -u
exec > >(tee -a /root/authority.log) 2>&1
attr() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"; }
# shellcheck disable=SC2034  # BUCKET is read by common.sh's gcs_get and gcs_put
BUCKET=$(attr vg-bucket); MODE=$(attr vg-mode)
OUT=/root/out; REPLICA=/root/replica; REPLICA_B=/root/replica-b; mkdir -p "$OUT" "$REPLICA" "$REPLICA_B" /root/vcek-cache; cd /root
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
finish() {
  cp /root/authority.log "$OUT/console.log" 2>/dev/null || true
  cp /root/failover.log "$OUT/failover.log" 2>/dev/null || true
  tar -C "$OUT" -czf /root/out.tgz . 2>/dev/null && gcs_put /root/out.tgz out/authority.tgz 2>/dev/null || true
  echo "$1" > /root/marker; gcs_put /root/marker "out/authority/$1" 2>/dev/null || true
}
trap 'finish FAILED' ERR
attr vg-common > /root/common.sh; . /root/common.sh
attr vg-lib > /root/lib.sh; . /root/lib.sh
set -eE

step "inputs (mode: $MODE)"
for b in sagvd acpctl keygen; do gcs_get "in/$b" "/usr/local/bin/$b" && chmod +x "/usr/local/bin/$b"; done
gcs_get in/amd-milan-cert_chain.pem /root/amd-milan-cert_chain.pem
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu | head -20; } > "$OUT/system.txt" 2>&1

step "provision (keygen), operator stop key, operator recovery key"
keygen -out /root/secrets -quiet
S=/root/secrets
TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'); printf '%s\n' "$TOKEN" > "$S/xcc_token"; chmod 600 "$S/xcc_token"
acpctl stop keygen --out /root/operator.seed --pub /root/operator.pem > /dev/null
acpctl stop issue --key /root/operator.seed --kid operator-1 --serial 1 --out /root/stop.json > /dev/null
acpctl escrow recovery-keygen --out /root/recovery.seed --pub /root/recovery.pem > "$OUT/recovery-keygen.txt"

step "configfs-tsm (real SEV-SNP reports)"
tsm "$OUT/tsm.txt"

step "sagvd on SEV-SNP: identity from the chip; the escrow key sealed to it"
head -c 48 /dev/zero > /root/peer.meas
python3 - <<PY
import json
S="$S"
c={"vault":{"listen_address":"127.0.0.1:9443","tls":{"enabled":True,"server_cert":S+"/sagvd/tls/server.crt","server_key":S+"/sagvd/tls/server.key","client_cas":S+"/shared/tls/ca.crt"}},
 "http_api":{"listen_address":"127.0.0.1:9080","bearer_token_file":S+"/sagvd/api_token"},
 "tee":{"provider":"gcp-sev-snp","workload_descriptor":"sagvd-failover-authority-v1",
        "peer":{"provider":"gcp-sev-snp","measurement_path":"/root/peer.meas","amd_cert_chain_path":"/root/amd-milan-cert_chain.pem","vcek_cache_dir":"/root/vcek-cache"}},
 "keys":{"authority_signing":{"kid":"sagvd-authority-demo","seed_path":S+"/sagvd/authority_signing_seed"},
         "audit_signing":{"kid":"sagvd-audit-demo","seed_path":S+"/sagvd/audit_signing_seed"},
         "session_sealing":{"kid":"session-sealing-demo","material_path":S+"/shared/sealing.key"}},
 "workers":{"registry_path":S+"/shared/workers.json"},
 "health":{"listen_address":"127.0.0.1:9081"},"log":{"level":"info","format":"json"}}
json.dump(c,open("/root/sagvd-base.json","w"),indent=2)
PY
# The destination's copies of the TLS pair, the CA and the token — and a
# client pair for the standby's own look at its restore records — are
# taken before sagvd seals its files to this chip (ADR 0023).
mkdir -p "$S/dest" && cp "$S/sagvd/tls/server.crt" "$S/sagvd/tls/server.key" "$S/shared/tls/ca.crt" "$S/xcc_token" \
  "$S/acp-compute/tls/client.crt" "$S/acp-compute/tls/client.key" "$S/dest/"
sagvd seal-keys -config /root/sagvd-base.json > "$OUT/seal-keys.json" 2> "$OUT/seal-keys.err"
echo "seal-keys exit=$? sealed=$(python3 -c 'import json,sys;print(",".join(e["name"] for e in json.load(open(sys.argv[1]))["sealed"]))' "$OUT/seal-keys.json" 2>/dev/null)" >> "$OUT/steps.txt"
sagvd identity -config /root/sagvd-base.json > /root/identity-0.json 2> "$OUT/identity-0.err"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); open("/root/peer.meas","wb").write(bytes.fromhex(d["tee_measurement_hex"]))' /root/identity-0.json
echo "authority measurement=$(json /root/identity-0.json 'd["tee_measurement_hex"]')" >> "$OUT/steps.txt"
sagvd escrow-provision -config /root/sagvd-base.json -out /root/escrow.sealed -pub /root/escrow.pem \
  -recovery-to /root/recovery.pem -recovery-out /root/escrow.recovery.json > "$OUT/escrow-provision.json" 2> "$OUT/escrow-provision.err"
echo "escrow-provision exit=$? escrow_key=$(json "$OUT/escrow-provision.json" 'd["escrow_key"]') sealed to $(json "$OUT/escrow-provision.json" 'd["tee"]')" >> "$OUT/steps.txt"
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["authority_public_key_pem"], end="")' /root/identity-0.json > /root/authority.pem

step "hand out the escrow key (both sentinels seal to it) and the destination's TLS material and token, through the private bucket"
gcs_put /root/escrow.pem handoff/escrow.pem
gcs_put /root/authority.pem handoff/authority.pem
for f in server.crt server.key ca.crt xcc_token client.crt client.key; do gcs_put "$S/dest/$f" "handoff/dest/$f"; done

step "wait for the standby: its endpoint and measurement, its own sentinel's key and identity"
for _ in $(seq 1 360); do
  gcs_get handoff/destination.json /root/destination.json 2>/dev/null && gcs_get handoff/standby-sentinel.pem /root/standby-sentinel.pem 2>/dev/null \
    && gcs_get handoff/standby-sentinel-identity.json /root/standby-sentinel-identity.json 2>/dev/null && break
  sleep 10
done
[ -s /root/destination.json ] && [ -s /root/standby-sentinel.pem ] && [ -s /root/standby-sentinel-identity.json ] || { echo "no standby hand-off after 60 minutes"; false; }
cp /root/destination.json "$OUT/destination-handoff.json"; cp /root/standby-sentinel-identity.json "$OUT/standby-sentinel-identity.json"
DEST=$(json /root/destination.json 'd["endpoint"]')
DMEAS=$(json /root/destination.json 'd["measurement_hex"]')
SMEAS=$(json /root/standby-sentinel-identity.json 'd["measurement_hex"]')
echo "standby endpoint=$DEST measurement=$DMEAS; its sentinel=$(json /root/standby-sentinel-identity.json 'd["sentinel"]') attests at $SMEAS" >> "$OUT/steps.txt"

step "wait for the primary's sentinel key and chip identity"
for _ in $(seq 1 480); do gcs_get handoff/sentinel-identity.json /root/sentinel-identity.json 2>/dev/null && gcs_get handoff/sentinel.pem /root/sentinel.pem 2>/dev/null && break; sleep 5; done
[ -s /root/sentinel.pem ] && [ -s /root/sentinel-identity.json ] || { echo "no sentinel identity after 40 minutes"; false; }
cp /root/sentinel-identity.json "$OUT/primary-identity.json"
PMEAS=$(json /root/sentinel-identity.json 'd["measurement_hex"]')
echo "primary measurement=$PMEAS sentinel=$(json /root/sentinel-identity.json 'd["sentinel"]')" >> "$OUT/steps.txt"

step "sagvd failover config: the verifier registry (the Milan chain), the allow-list, the operator stop, the sealed escrow key, mTLS to the standby"
python3 - <<PY
import json
S="$S"; DMEAS="$DMEAS"
json.dump({"verifiers":[{"provider":"gcp-sev-snp","expected_measurement_hex":DMEAS,"amd_cert_chain_path":"/root/amd-milan-cert_chain.pem","vcek_cache_dir":"/root/vcek-cache"}]},open("/root/verifiers.json","w"),indent=2)
json.dump({"version":"failover-policy-v1","allowed":{"gcp-sev-snp":[DMEAS]}},open("/root/allow.json","w"))
c=json.load(open("/root/sagvd-base.json"))
c["crosscloud"]={"enabled":True,"policy_version":"failover-policy-v1","audit_log_path":"/root/xcc-audit.db",
 "operator_stop":{"kid":"operator-1","public_key_path":"/root/operator.pem","list_path":"/root/stop.json"},
 "key_escrow_path":"/root/escrow.sealed",
 "policy_allow_list_path":"/root/allow.json","verifier_registry_path":"/root/verifiers.json",
 "transport_bearer_token":open(S+"/xcc_token").read().strip(),"request_timeout_seconds":120,
 "transport_tls":{"enabled":True,"client_cert":S+"/acp-compute/tls/client.crt","client_key":S+"/acp-compute/tls/client.key","ca_bundle":S+"/shared/tls/ca.crt","server_name":"localhost"}}
json.dump(c,open("/root/sagvd.json","w"),indent=2)
PY
sagvd seal-keys -config /root/sagvd.json > "$OUT/seal-keys-2.json" 2> "$OUT/seal-keys-2.err"
echo "seal-keys (failover config) exit=$?" >> "$OUT/steps.txt"
cp /root/verifiers.json "$OUT/verifiers.json"; cp /root/allow.json "$OUT/allow.json"
sagvd identity -config /root/sagvd.json > "$OUT/authority-identity.json" 2> "$OUT/authority-identity.err"
echo "sagvd identity exit=$? key_escrow_storage=$(json "$OUT/authority-identity.json" 'd.get("key_escrow_storage")')" >> "$OUT/steps.txt"
python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["audit_public_key_pem"],end="")' "$OUT/authority-identity.json" > /root/audit.pem

step "sign the failover policy: the primary's sentinel and chip, the standby, and — in advance — the standby's own sentinel (v2)"
acpctl failover issue --key /root/operator.seed --kid operator-1 --serial 1 \
  --sentinel-pub /root/sentinel.pem --primary-kind gcp-sev-snp --primary-measurement "$PMEAS" \
  --standby-kind gcp-sev-snp --standby-endpoint "$DEST" --standby-measurement "$DMEAS" \
  --standby-sentinel-pub /root/standby-sentinel.pem --standby-sentinel-measurement "$SMEAS" \
  --heartbeat-timeout 30s --no-compromise-trigger --stopped-grace 60s --require-gate EXACT \
  --reason "closed-turn drill: the primary is switched off while it trains; its silence moves the last generation to a standby whose gate must be EXACT, and the standby goes on by itself" \
  --out /root/failover.json > "$OUT/failover-issue.txt"
acpctl failover verify --in /root/failover.json --pubkey /root/operator.pem --kid operator-1 > "$OUT/failover-verify.txt"
cp /root/failover.json "$OUT/failover-policy.json"
echo "policy: schema=$(json /root/failover.json 'd["schema"]')" >> "$OUT/steps.txt"

step "pull both outboxes' replicas, continuously: the primary's, and the standby's own"
( while true; do pull_outbox "$REPLICA"; pull_outbox_b "$REPLICA_B"; sleep 2; done ) &
PULL=$!

step "arm: sagvd failover watches the primary's replica, and after the failover the standby's"
gcs_put_str handoff/armed "armed at $(date -u +%H:%M:%SZ)"
# A receipt that does not come is waited for this long. In the negative
# run the standby says at once that its restore failed, and the wait is
# not used; it bounds the run should the standby say nothing.
CONFIRM_WAIT=15m; [ "$MODE" = negative ] && CONFIRM_WAIT=3m
sagvd failover -config /root/sagvd.json -policy /root/failover.json -outbox "$REPLICA" -standby-outbox "$REPLICA_B" \
  -poll 1s -confirm-wait "$CONFIRM_WAIT" -report "$OUT/report.json" > /root/failover.log 2>&1 &
FAILOVER=$!

audit() { # the log, checked offline as an auditor would, and its kinds in order
  acpctl audit verify --audit /root/xcc-audit.db --audit-pubkey /root/audit.pem --audit-kid sagvd-audit-demo --json > "$OUT/audit-verify.json" 2>&1 || true
  acpctl audit query --audit /root/xcc-audit.db --limit 0 --json > "$OUT/audit-events.jsonl" 2>/dev/null || true
  python3 -c 'import json,sys; print(" ".join(json.loads(l)["kind"] for l in open(sys.argv[1]) if l.strip()))' "$OUT/audit-events.jsonl" > "$OUT/audit-kinds.txt" 2>/dev/null || true
  cp /root/xcc-audit.db "$OUT/xcc-audit.db" 2>/dev/null || true; cp /root/audit.pem "$OUT/audit-public-key.pem" 2>/dev/null || true
}

if [ "$MODE" = negative ]; then
  step "wait for the failover to end: the standby's gate cannot be passed, and its restore is never confirmed"
  set +e; wait "$FAILOVER"; FCODE=$?; set -e
  echo "sagvd failover exit=$FCODE" >> "$OUT/steps.txt"
  kill "$PULL" 2>/dev/null || true
  audit
  echo "negative: status=$(json "$OUT/report.json" 'd["status"]') error=$(json "$OUT/report.json" 'd.get("error")')" >> "$OUT/steps.txt"
  echo "audit: $(cat "$OUT/audit-kinds.txt")" >> "$OUT/steps.txt"
  [ "$FCODE" = 1 ] || { echo "sagvd failover exited $FCODE, want 1: a failover whose restore was not confirmed"; false; }
  if grep -qw -e CROSS_CLOUD_RESTORE_COMPLETED -e CHAIN_CONTINUED "$OUT/audit-kinds.txt"; then echo "a restore or a chain is on the audit log of a run whose gate could not pass"; false; fi
  echo "NOTHING CONFIRMED: the failover was decided and the key released; the standby's gate could not be passed, and no restore and no chain are on record" > "$OUT/verdict.txt"
  cat "$OUT/verdict.txt" >> "$OUT/steps.txt"
  trap - ERR
  finish DONE
  exit 0
fi

step "wait for the failover, then for the chain the standby continues to be on the report (up to 60 min)"
continued() { [ -s "$OUT/report.json" ] && [ "$(json "$OUT/report.json" 'd.get("continued") is not None' 2>/dev/null)" = True ]; }
for _ in $(seq 1 720); do
  continued && break
  kill -0 "$FAILOVER" 2>/dev/null || { set +e; wait "$FAILOVER"; echo "sagvd failover ended with $? before the chain was continued"; set -e; false; }
  sleep 5
done
continued || { echo "the chain was not continued within an hour"; false; }
python3 - "$OUT/report.json" >> "$OUT/steps.txt" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); g, t, rs, c = r["genome"], r["timing"], r["restore"], r["continued"]
print("failover: status=%s trigger=%s generation=%s gate=%s required=%s" % (r["status"], r["trigger"]["kind"], g["generation"], rs["gate"]["level"], rs.get("required_gate")))
print("failover: detect=%.1fs failover=%.1fs rto=%.1fs rpo=%.1fs" % (t["detect_seconds"], t["failover_seconds"], t["rto_seconds"], t["rpo_seconds"]))
after = c.get("sealed_after_restore_seconds")
print("continued: generation=%s parent=%s sentinel=%s sealed_after_restore=%s" % (c["generation"], c["parent_generation"], c["sentinel"], "%.1fs" % after if after is not None else "unknown"))
PY
cp "$OUT/report.json" "$OUT/report-continued.json"
G2=$(json "$OUT/report.json" 'd["continued"]["generation"]')

step "the generation the standby sealed, opened again: its escrowed key released back to the standby, an ordinary attested release"
BUNDLE2="$REPLICA_B/$(printf 'gen-%06d.genome' "$G2")"
set +e
sagvd crosscloud-restore -config /root/sagvd.json -decision-id "reopen-generation-$G2" -destination-kind gcp-sev-snp \
  -destination-endpoint "$DEST" -key-escrow "$BUNDLE2.escrow" > "$OUT/reopen-restore.json" 2> "$OUT/reopen-restore.err"
RCODE=$?
sagvd crosscloud-confirm -config /root/sagvd.json -decision-id "reopen-generation-$G2" -destination-endpoint "$DEST" \
  -bundle "$BUNDLE2" -require-gate EXACT -wait 10m > "$OUT/reopen-confirm.json" 2> "$OUT/reopen-confirm.err"
CCODE=$?
set -e
echo "reopen generation $G2: release exit=$RCODE confirm exit=$CCODE" >> "$OUT/steps.txt"
[ "$RCODE" = 0 ] && [ "$CCODE" = 0 ] || { echo "generation $G2 was not released and confirmed"; cat "$OUT/reopen-restore.err" "$OUT/reopen-confirm.err"; false; }
gcs_put_str handoff/reopened "generation $G2 at $(date -u +%H:%M:%SZ)"

step "the authority goes on watching the standby until it is told to stop"
for _ in $(seq 1 720); do gcs_get handoff/stop /root/stop-now 2>/dev/null && break; sleep 5; done
STILL=$(kill -0 "$FAILOVER" 2>/dev/null && echo yes || echo no)
echo "sagvd failover still watching the standby when told to stop: $STILL" >> "$OUT/steps.txt"
kill -TERM "$FAILOVER" 2>/dev/null || true
set +e; wait "$FAILOVER"; FCODE=$?; set -e
echo "sagvd failover exit=$FCODE" >> "$OUT/steps.txt"
kill "$PULL" 2>/dev/null || true
cp "$REPLICA/heartbeat.json" "$OUT/primary-last-heartbeat.json" 2>/dev/null || true
cp "$REPLICA_B/heartbeat.json" "$OUT/standby-heartbeat.json" 2>/dev/null || true
cp "$REPLICA_B/$(printf 'gen-%06d.seal.json' "$G2")" "$OUT/standby-generation.seal.json" 2>/dev/null || true

step "audit log verify (offline, as an auditor would)"
audit
echo "audit: $(cat "$OUT/audit-kinds.txt")" >> "$OUT/steps.txt"
[ "$STILL" = yes ] && [ "$FCODE" = 0 ] || { echo "sagvd failover was not watching the standby to the end (still=$STILL exit=$FCODE)"; false; }
grep -qw CHAIN_CONTINUED "$OUT/audit-kinds.txt" || { echo "no CHAIN_CONTINUED on the audit log"; false; }

echo "CHAIN CONTINUED: generation $G2, sealed by the standby's own sentinel, is on the audit log as the chain's next" > "$OUT/verdict.txt"
cat "$OUT/verdict.txt" >> "$OUT/steps.txt"
trap - ERR
finish DONE
