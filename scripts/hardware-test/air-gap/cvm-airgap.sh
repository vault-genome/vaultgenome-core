#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script for a GCP Confidential VM (Ubuntu 24.04) — AMD SEV-SNP,
# or Intel TDX with vg-tee=tdx: the Return Path on a host that loses its
# route to the world.
#
# Two phases. Connected: the binaries, the worker's runtime, the AMD chain
# from KDS (verified against the pinned roots), the key material, the
# identities and pins — and `acpctl tee prefetch` for each daemon's
# configuration, which fills the peer verifier's cache with what this
# host's own evidence needs: on SEV-SNP this chip's VCEK from AMD KDS, on
# TDX the TCB info of this platform and the QE identity from Intel PCS;
# `acpctl tee cache-status` says what is there and until when. The guest then prints ===AIRGAP-READY=== and waits
# for the runner to put it behind a firewall rule that denies all egress
# (a network tag). Air-gapped: egress is shown dead (AMD KDS and the bucket
# unreachable, the metadata server reachable), the key files are sealed,
# a genome fine-tuned and sealed with the runtime offline, both daemons
# started, the Return Path handshake verified from the cache alone, a gate
# job gated EXACT, the audit log verified. Then the negative: the caches
# wiped, both daemons restarted — the handshake must be refused, naming
# KDS (fail closed, nothing admitted on a cache that is not there); the
# caches restored from the copy taken while connected, both restarted, a
# job gated EXACT again.
#
# Inputs (instance metadata): vg-bucket — the run's bucket holding
# e2e/{sagvd,acp-compute,acpctl,keygen,genome-worker.tgz}; vg-tag — the
# network tag the runner adds to cut egress. Output: a base64 tarball of
# the results on the serial console between ===E2E-BEGIN=== and
# ===E2E-END=== (three copies), decoded by the Return Path kit's
# decode-results.sh. No key, seed, token, config or cached certificate's
# bytes leave the VM; the VM and the bucket die with the run.
set -u
exec > >(tee -a /root/e2e.log) 2>&1
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=/root/e2e; OUT=$WORK/out/$STAMP; mkdir -p "$OUT"; cd "$WORK" || exit 1
BUCKET=$(md attributes/vg-bucket)
TAG=$(md attributes/vg-tag)
TEE=$(md attributes/vg-tee 2>/dev/null || true); case "$TEE" in tdx) ;; *) TEE=sev-snp;; esac
RELEASE=$(md attributes/vg-release 2>/dev/null || true); case "$RELEASE" in v*) ;; *) RELEASE="";; esac
# The vendor the peer verifier asks, and the cached files it keeps.
case "$TEE" in
  tdx) VENDOR_URL="https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"; VENDOR="Intel PCS"; CACHE_GLOB='*.json *.issuer-chain.pem';;
  *)   VENDOR_URL="https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"; VENDOR="AMD KDS"; CACHE_GLOB='*.der';;
esac
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; echo "captured=$STAMP"; echo "tee=$TEE"; echo "airgap_tag=$TAG"; } > "$OUT/metadata.txt"
uname -a > "$OUT/kernel.txt"
T0=$(date +%s.%N)
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }

# ---------------------------------------------------------------- connected
step "binaries from gs://$BUCKET/e2e"
GTOKEN=$(md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
for f in sagvd acp-compute acpctl keygen genome-worker.tgz; do
  curl -sSf -H "Authorization: Bearer $GTOKEN" -o "$WORK/$f" \
    "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/e2e%2F$f?alt=media" || echo "fetch $f failed"
done
unset GTOKEN
chmod +x sagvd acp-compute acpctl keygen
./sagvd version > "$OUT/versions.txt"; ./acp-compute version >> "$OUT/versions.txt"; ./acpctl version >> "$OUT/versions.txt" 2>/dev/null || true
./keygen -version >> "$OUT/versions.txt" 2>/dev/null || true
sha256sum sagvd acp-compute acpctl keygen genome-worker.tgz > "$OUT/inputs.sha256"
mkdir -p workers && tar xzf genome-worker.tgz -C workers

if [ -n "$RELEASE" ]; then
  step "the release $RELEASE: its assets from the bucket, cosign 2.6.5, and the Sigstore trust root — while connected"
  mkdir -p release
  GTOKEN=$(md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
  curl -sSf -H "Authorization: Bearer $GTOKEN" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o?prefix=release%2F&fields=items/name" \
    | python3 -c 'import json,sys; [print(i["name"]) for i in json.load(sys.stdin).get("items", [])]' > /root/release-objects.txt
  while read -r obj; do
    f=$(basename "$obj")
    curl -sSf -H "Authorization: Bearer $GTOKEN" -o "release/$f" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$obj")?alt=media" || echo "fetch $f failed" >> "$OUT/steps.txt"
  done < /root/release-objects.txt
  unset GTOKEN
  ( cd release && sha256sum -- * ) > "$OUT/release-assets.guest.sha256"
  echo "release assets fetched: $(ls release | wc -l)" >> "$OUT/steps.txt"
  # cosign, the version the release workflow pins, checked against the
  # checksums its own release publishes.
  curl -sSfL -o cosign https://github.com/sigstore/cosign/releases/download/v2.6.5/cosign-linux-amd64
  curl -sSfL -o cosign_checksums.txt https://github.com/sigstore/cosign/releases/download/v2.6.5/cosign_checksums.txt
  WANT=$(grep ' cosign-linux-amd64$' cosign_checksums.txt | cut -d' ' -f1); GOT=$(sha256sum cosign | cut -d' ' -f1)
  echo "cosign sha256 published=$WANT downloaded=$GOT match=$([ "$WANT" = "$GOT" ] && echo yes || echo NO)" >> "$OUT/steps.txt"
  chmod +x cosign; ./cosign version > "$OUT/cosign-version.txt" 2>&1 || true
  # The Sigstore trust root, through TUF, once while connected; the
  # trusted_root.json it fetched is the file --trusted-root reads with no
  # route at all — carried beside the assets. (--offline is not that:
  # cosign 2.6.5 still reaches for the TUF mirror with it; measured.)
  # TUF_ROOT names the cache directory outright: a startup script's HOME
  # is not /root, and a run that looked for the file under /root/.sigstore
  # found nothing (not kept).
  export TUF_ROOT=$WORK/tuf-cache
  ./cosign initialize > "$OUT/cosign-initialize.txt" 2>&1; echo "cosign initialize exit=$? (TUF_ROOT=$TUF_ROOT, HOME=${HOME:-unset})" >> "$OUT/steps.txt"
  TR=$(find "$TUF_ROOT" -name trusted_root.json 2>/dev/null | head -1)
  if [ -n "$TR" ]; then cp "$TR" release/trusted_root.json; echo "trusted_root.json from $TR: $(sha256sum release/trusted_root.json | cut -c1-16)… $(stat -c%s release/trusted_root.json) bytes" >> "$OUT/steps.txt"; else echo "trusted_root.json NOT found under $TUF_ROOT" >> "$OUT/steps.txt"; fi
  find "$TUF_ROOT" -maxdepth 4 2>/dev/null >> "$OUT/cosign-initialize.txt" || true
fi

if [ "$TEE" = sev-snp ]; then
  step "the AMD Milan chain from KDS, verified against the roots acpctl pins (ADR 0024)"
  ./acpctl tee fetch-amd-chain --product milan --out amd-milan-cert_chain.pem > "$OUT/amd-chain.txt" 2>&1 || echo "fetch-amd-chain failed: $(cat "$OUT/amd-chain.txt")"
  sha256sum amd-milan-cert_chain.pem >> "$OUT/inputs.sha256"
fi

step "configfs-tsm ($TEE)"
if [ "$TEE" = tdx ]; then
  # A Trust Domain has no derived key of its own: tee.sealer's default
  # seals the key files with the guest's vTPM through tpm2-tools
  # (ADR 0025, step 1b), installed while the route is still there.
  export DEBIAN_FRONTEND=noninteractive
  for i in $(seq 1 12); do apt-get install -y -qq tpm2-tools >/dev/null 2>&1 && break; apt-get update -qq >/dev/null 2>&1 || true; sleep 10; done
  command -v tpm2_createprimary >/dev/null || echo "tpm2-tools did not install" >> "$OUT/steps.txt"
  { ls -la /dev/tpm0 /dev/tpmrm0 2>&1; tpm2_getcap properties-fixed 2>&1 | grep -A1 -E "TPM2_PT_MANUFACTURER|TPM2_PT_VENDOR_STRING_1" | head -4; } > "$OUT/vtpm.txt" 2>&1
fi
if [ "$TEE" = sev-snp ]; then
  modprobe sev-guest 2>/dev/null || {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
    modprobe sev-guest 2>/dev/null || true
  }
fi
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report 2>&1; ls -la /dev/tdx_guest /dev/sev-guest 2>&1; dmesg | grep -i -E "sev|snp|tdx|tsm" | tail -20; } > "$OUT/tsm.txt"

step "the worker runtime: python, the pinned CPU torch (the door needs it) — while connected"
mark runtime_install_start
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1
python3 -m venv venv && . venv/bin/activate
pip install --require-hashes --only-binary=:all: --index-url https://pypi.org/simple -r workers/genome/requirements-ci.lock > "$OUT/pip-requirements.log" 2>&1
pip install --require-hashes --only-binary=:all: --no-deps --index-url https://download.pytorch.org/whl/cpu -r workers/genome/requirements-torch-cpu.lock > "$OUT/pip-torch.log" 2>&1
python3 -c 'import torch, transformers, safetensors; print("torch", torch.__version__, "transformers", transformers.__version__, "safetensors", safetensors.__version__)' > "$OUT/runtime.txt" 2>&1
mark runtime_install_end

step "provision (acp-keygen, private modes)"
./keygen -out secrets -quiet -private
S=$WORK/secrets
mkdir -p genomes audit queue cache-sagvd cache-worker
head -c 48 /dev/zero > peer-vault.meas; head -c 48 /dev/zero > peer-worker.meas

# Each daemon's peer verifier keeps its own cache (cache-sagvd,
# cache-worker): prefetch fills each from its own configuration, as an
# operator would. On SEV-SNP the cache is vcek_cache_dir, on TDX
# pcs_cache_dir.
# handshake_timeout_seconds is 60 here, not the kits' 30: the KDS client
# gives up after 40 s, and with the route dead the refusal should name
# KDS, not the handshake's own clock.
write_configs() { # $1 = vault measurement hex, $2 = worker measurement hex
  python3 - "$1" "$2" "$TEE" <<'PY'
import json, sys, binascii
vault_meas, worker_meas, TEE = sys.argv[1], sys.argv[2], sys.argv[3]
W = "/root/e2e"; S = W + "/secrets"
open(W + "/peer-vault.meas", "wb").write(binascii.unhexlify(vault_meas))
open(W + "/peer-worker.meas", "wb").write(binascii.unhexlify(worker_meas))
def peer(meas, cache):
    if TEE == "tdx":
        return {"provider": "gcp-tdx", "measurement_path": meas, "pcs_cache_dir": cache}
    return {"provider": "gcp-sev-snp", "measurement_path": meas, "amd_cert_chain_path": W + "/amd-milan-cert_chain.pem", "vcek_cache_dir": cache}
sagvd = {
  "vault": {"listen_address": "127.0.0.1:9443",
    "tls": {"enabled": True, "server_cert": S + "/sagvd/tls/server.crt", "server_key": S + "/sagvd/tls/server.key", "client_cas": S + "/shared/tls/ca.crt"}},
  "http_api": {"listen_address": "127.0.0.1:9080", "bearer_token_file": S + "/sagvd/api_token"},
  "tee": {"provider": "auto", "workload_descriptor": "sagvd-airgap-v1",
    "peer": peer(W + "/peer-worker.meas", W + "/cache-sagvd")},
  "keys": {"authority_signing": {"kid": "sagvd-authority-airgap", "seed_path": S + "/sagvd/authority_signing_seed"},
           "audit_signing": {"kid": "sagvd-audit-airgap", "seed_path": S + "/sagvd/audit_signing_seed"},
           "session_sealing": {"kid": "session-sealing-airgap", "material_path": S + "/shared/sealing.key"}},
  "workers": {"registry_path": S + "/shared/workers.json"},
  "genome": {"bundle_dir": W + "/genomes", "gate": {"atol": 1e-2, "rtol": 1e-3, "max_non_critical_outliers": 0}},
  "audit": {"log_path": W + "/audit/airgap-audit.db"},
  "queue": {"path": W + "/queue/sagvd-jobs.db"},
  "runtime": {"job_timeout_seconds": 600, "handshake_timeout_seconds": 60, "queue_poll_ms": 50,
    "http_read_header_timeout_seconds": 5, "http_write_timeout_seconds": 30, "default_job_deadline_seconds": 600, "max_payload_bytes": 4194304},
  "health": {"listen_address": "127.0.0.1:9081"},
  "log": {"level": "info", "format": "json"}}
worker = {
  "vault": {"address": "127.0.0.1:9443",
    "tls": {"enabled": True, "client_cert": S + "/acp-compute/tls/client.crt", "client_key": S + "/acp-compute/tls/client.key", "ca_bundle": S + "/shared/tls/ca.crt", "server_name": "localhost"}},
  "tee": {"provider": "auto", "workload_descriptor": "acp-compute-airgap-v1",
    "peer": peer(W + "/peer-vault.meas", W + "/cache-worker")},
  "keys": {"worker_signing": {"kid": "acp-compute-worker-demo", "seed_path": S + "/acp-compute/worker_signing_seed"},
           "session_sealing": {"kid": "session-sealing-airgap", "material_path": S + "/shared/sealing.key"}},
  "genome": {"door": {"command": [W + "/venv/bin/python3", "-m", "vg_genome", "door", "--stdin-genome", "--base", W + "/base", "--device", "cpu"],
                      "env": ["PYTHONPATH=" + W + "/workers/genome", "TOKENIZERS_PARALLELISM=false", "HF_HUB_OFFLINE=1", "TRANSFORMERS_OFFLINE=1"], "timeout_seconds": 300}},
  "runtime": {"job_timeout_seconds": 600, "handshake_timeout_seconds": 60, "dial_backoff_initial_ms": 500, "dial_backoff_max_ms": 5000, "idle_between_jobs_ms": 200},
  "health": {"listen_address": "127.0.0.1:9082"},
  "log": {"level": "info", "format": "json"}}
json.dump(sagvd, open(W + "/sagvd.json", "w"), indent=2)
json.dump(worker, open(W + "/worker.json", "w"), indent=2)
PY
}
ZEROS=$(printf '%096d' 0)
write_configs "$ZEROS" "$ZEROS"

step "identities: each daemon reads its launch measurement from the chip"
./sagvd identity -config sagvd.json > "$OUT/sagvd-identity.json" 2> "$OUT/sagvd-identity.err"; echo "sagvd identity exit=$?" >> "$OUT/steps.txt"
./acp-compute identity -config worker.json > "$OUT/acp-compute-identity.json" 2> "$OUT/acp-compute-identity.err"; echo "acp-compute identity exit=$?" >> "$OUT/steps.txt"
VMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/sagvd-identity.json" 2>/dev/null)
WMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/acp-compute-identity.json" 2>/dev/null)
echo "vault_measurement=$VMEAS" >> "$OUT/steps.txt"; echo "worker_measurement=$WMEAS" >> "$OUT/steps.txt"
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["audit_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > audit.pem
write_configs "$VMEAS" "$WMEAS"

step "acpctl tee prefetch for each daemon's configuration: what this host's evidence needs from $VENDOR, into each peer verifier's cache"
mark prefetch_start
./acpctl tee prefetch --config sagvd.json > "$OUT/prefetch-sagvd.txt" 2>&1; echo "prefetch sagvd exit=$?" >> "$OUT/steps.txt"
./acpctl tee prefetch --config sagvd.json --json > "$OUT/prefetch-sagvd.json" 2> /dev/null || true
./acpctl tee prefetch --config worker.json > "$OUT/prefetch-worker.txt" 2>&1; echo "prefetch worker exit=$?" >> "$OUT/steps.txt"
mark prefetch_end
./acpctl tee cache-status --config sagvd.json > "$OUT/cache-status-sagvd.txt" 2>&1; echo "cache-status sagvd exit=$?" >> "$OUT/steps.txt"
./acpctl tee cache-status --config worker.json > "$OUT/cache-status-worker.txt" 2>&1; echo "cache-status worker exit=$?" >> "$OUT/steps.txt"
# The caches' shape, not their bytes: file names (chip id and TCB), sizes, digests.
# shellcheck disable=SC2086  # CACHE_GLOB is a list of patterns
( cd "$WORK" && for d in cache-sagvd cache-worker; do ( cd "$d" && for f in $CACHE_GLOB; do [ -f "$f" ] && echo "$d/$f $(stat -c%s "$f") sha256=$(sha256sum "$f" | cut -c1-16)…"; done ); done ) > "$OUT/cache-files.txt" 2>&1
# A copy of the caches for the negative test below — what an operator's
# backup of the cache directory is.
rm -rf cache-backup && mkdir -p cache-backup && cp -r cache-sagvd cache-worker cache-backup/
echo "files cached: $(wc -l < "$OUT/cache-files.txt")" >> "$OUT/steps.txt"
# On TDX the cached documents are Intel's, public: they go into the
# results for offline re-verification, as in the TDX Return Path kit.
if [ "$TEE" = tdx ]; then for f in cache-sagvd/*; do [ -f "$f" ] && cp "$f" "$OUT/pcs-$(basename "$f")"; done; fi

step "ready to be cut off: waiting for the network tag $TAG (the runner's firewall rule denies all egress to it)"
mark airgap_ready
echo "===AIRGAP-READY=== $STAMP" > /dev/ttyS0 2>/dev/null || true
n=0; until md tags | grep -q "\"$TAG\"" || [ $n -ge 600 ]; do sleep 2; n=$((n+2)); done
echo "tag seen after ${n}s: $(md tags | tr -d '\n')" >> "$OUT/steps.txt"
mark tag_seen
# The rule takes a few seconds to apply to existing flows; wait until the
# vendor stops answering, then record the state of the three routes.
n=0; until ! curl -sS -m 6 -o /dev/null "$VENDOR_URL" 2>/dev/null || [ $n -ge 120 ]; do sleep 3; n=$((n+3)); done
echo "egress dead after ${n}s more" >> "$OUT/steps.txt"

# ---------------------------------------------------------------- air-gapped
step "the routes: $VENDOR, the bucket, the metadata server"
{
  curl -sS -m 8 -o /dev/null -w 'vendor http=%{http_code}\n' "$VENDOR_URL" 2>&1 || echo "vendor: unreachable (curl exit $?)"
  curl -sS -m 8 -o /dev/null -w 'bucket http=%{http_code}\n' "https://storage.googleapis.com/storage/v1/b/$BUCKET/o" 2>&1 || echo "bucket: unreachable (curl exit $?)"
  curl -sS -m 5 -o /dev/null -w 'metadata http=%{http_code}\n' -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/name 2>&1 || echo "metadata: unreachable (curl exit $?)"
} > "$OUT/egress.txt" 2>&1
cat "$OUT/egress.txt" >> "$OUT/steps.txt"
if grep -q 'vendor http=200' "$OUT/egress.txt"; then echo "EGRESS NOT DENIED: $VENDOR still answers — what follows is not an air-gap run" >> "$OUT/steps.txt"; fi

if [ -n "$RELEASE" ]; then
  step "the release $RELEASE verified without a route: every signed file from its Sigstore bundle with --trusted-root; --offline and the pair, for contrast"
  IDENTITY='^https://github\.com/vault-genome/vaultgenome-core/\.github/workflows/release\.yml@refs/tags/v'
  ISSUER='https://token.actions.githubusercontent.com'
  WORKER_PKG="genome-worker-$RELEASE.tar.gz"
  : > "$OUT/release-offline.txt"
  for b in sagvd acp-compute acpctl acp-bootstrap acp-keygen "$WORKER_PKG"; do
    sbom="$b.sbom.spdx.json"; sbombundle="$b.sbom.sigstore.json"
    [ "$b" = "$WORKER_PKG" ] && { sbom="genome-worker-$RELEASE.sbom.spdx.json"; sbombundle="genome-worker-$RELEASE.sbom.sigstore.json"; }
    for f in "$b" "$sbom"; do
      bundle="$f.sigstore.json"; [ "$f" = "$sbom" ] && bundle="$sbombundle"
      t0=$(date +%s.%N)
      r=$( cd release && timeout 60 ../cosign verify-blob --new-bundle-format --bundle "$bundle" --trusted-root trusted_root.json --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$f" 2>&1 | tail -1 )
      echo "$f: $r ($(python3 -c 'import sys,time; print("%.2fs" % (time.time()-float(sys.argv[1])))' "$t0"))" >> "$OUT/release-offline.txt"
    done
  done
  echo "bundle + trusted-root, no route, Verified OK: $(grep -c 'Verified OK' "$OUT/release-offline.txt") of 12" >> "$OUT/steps.txt"
  # For contrast, on one file: --offline with the bundle (cosign 2.6.5
  # reaches for the TUF mirror regardless), and the pair without the
  # bundle (Rekor is needed for the transparency-log entry). Neither can
  # verify here; each is given 60 s.
  r=$( cd release && timeout 60 ../cosign verify-blob --new-bundle-format --bundle sagvd.sigstore.json --offline --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" sagvd 2>&1 | tail -2 | tr '\n' ' ' ); echo "sagvd, bundle + --offline, no route: ${r:0:300}" > "$OUT/release-contrast.txt"
  r=$( cd release && timeout 60 ../cosign verify-blob --signature sagvd.sig --certificate sagvd.cert --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" sagvd 2>&1 | tail -2 | tr '\n' ' ' ); echo "sagvd, the pair, no bundle, no route: ${r:0:300}" >> "$OUT/release-contrast.txt"
  echo "contrast — --offline: $(sed -n 1p "$OUT/release-contrast.txt" | grep -q 'Verified OK' && echo 'Verified OK (unexpected)' || echo 'not verified, as expected'); the pair: $(sed -n 2p "$OUT/release-contrast.txt" | grep -q 'Verified OK' && echo 'Verified OK (unexpected)' || echo 'not verified, as expected')" >> "$OUT/steps.txt"
fi

step "the key files sealed to this host (ADR 0023; tee.sealer auto: the chip's derived key on SEV-SNP, the vTPM on TDX)"
cp "$S/sagvd/api_token" "$WORK/api_token.operator" && chmod 600 "$WORK/api_token.operator"
./sagvd seal-keys -config sagvd.json > "$OUT/seal-keys-sagvd.json" 2> "$OUT/seal-keys-sagvd.err"; echo "sagvd seal-keys exit=$? sealer=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("sealer"))' "$OUT/seal-keys-sagvd.json" 2>/dev/null)" >> "$OUT/steps.txt"
./acp-compute seal-keys -config worker.json > "$OUT/seal-keys-worker.json" 2> "$OUT/seal-keys-worker.err"; echo "acp-compute seal-keys exit=$? sealer=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("sealer"))' "$OUT/seal-keys-worker.json" 2>/dev/null)" >> "$OUT/steps.txt"

step "a real fine-tune with the runtime offline: tiny base model built here, LoRA adapter trained by vg_genome, sealed by acpctl"
mark finetune_start
export PYTHONPATH=$WORK/workers/genome TOKENIZERS_PARALLELISM=false HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
( cd workers/genome && python3 -c 'import sys, json; sys.path.insert(0, "tests"); import conftest
conftest.make_base(sys.argv[1])
open(sys.argv[2], "w").write("".join(json.dumps(e) + "\n" for e in conftest.EXAMPLES))' "$WORK/base" "$WORK/train.jsonl" )
python3 -m vg_genome finetune --base base --base-name tiny-llama --data train.jsonl --out genome \
  --targets q_proj,v_proj,lm_head --steps 20 --lr 1e-2 --max-len 32 --threads 2 --top-k 8 --new-tokens 4 > "$OUT/finetune.json" 2> "$OUT/finetune.err"
echo "finetune exit=$?" >> "$OUT/steps.txt"
mark finetune_end
./acpctl genome seal --content-dir genome --output genomes/gen-0.genome --key-out genomes/gen-0.key --json > "$OUT/seal.json" 2> "$OUT/seal.err"
echo "seal exit=$?" >> "$OUT/steps.txt"
KID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_id"])' "$OUT/seal.json" 2>/dev/null); echo "key_id=$KID" >> "$OUT/steps.txt"

start_daemons() { # $1 = label for the logs
  ( exec ./sagvd -config sagvd.json > "$OUT/sagvd-$1.log" 2>&1 ) & echo $! > /root/sagvd.pid
  local n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
  echo "sagvd ready after ${n}s" >> "$OUT/steps.txt"
  ( exec ./acp-compute -config worker.json > "$OUT/acp-compute-$1.log" 2>&1 ) & echo $! > /root/worker.pid
  n=0; until grep -q -E "sagvd session opened|sagvd return-path handshake failed" "$OUT/sagvd-$1.log" || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
  if grep -q "sagvd session opened" "$OUT/sagvd-$1.log"; then echo "session opened after ${n}s" >> "$OUT/steps.txt"; else echo "no session after ${n}s: $(grep -m1 'handshake failed' "$OUT/sagvd-$1.log" | cut -c1-400)" >> "$OUT/steps.txt"; fi
}
stop_daemons() {
  kill -TERM "$(cat /root/worker.pid)" 2>/dev/null || true; kill -TERM "$(cat /root/sagvd.pid)" 2>/dev/null || true
  local n=0; while { kill -0 "$(cat /root/sagvd.pid)" || kill -0 "$(cat /root/worker.pid)"; } 2>/dev/null && [ $n -lt 60 ]; do sleep 1; n=$((n+1)); done
  echo "daemons stopped after ${n}s; still running by name: $(pgrep -x sagvd | wc -l) sagvd, $(pgrep -x acp-compute | wc -l) acp-compute" >> "$OUT/steps.txt"
}
gate_job() { # $1 = label
  local TOKEN JOB ST i
  TOKEN=$(cat "$WORK/api_token.operator")
  curl -s -o "$OUT/job-$1-submit.json" -w '%{http_code}\n' -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    --data '{"genome":{"bundle":"gen-0.genome","key_file":"gen-0.key"},"deadline_seconds_from_now":300}' http://127.0.0.1:9080/v1/jobs > "$OUT/job-$1-submit.status"
  JOB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["job_id"])' "$OUT/job-$1-submit.json" 2>/dev/null || echo "")
  ST=""
  for i in $(seq 1 300); do
    sleep 1
    curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9080/v1/jobs/$JOB" > "$OUT/job-$1.json"
    ST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$OUT/job-$1.json" 2>/dev/null || echo "")
    [ "$ST" = succeeded ] || [ "$ST" = failed ] && break
  done
  unset TOKEN
  python3 - "$OUT/job-$1.json" "$1" "$i" >> "$OUT/steps.txt" <<'PY'
import json, sys
j = json.load(open(sys.argv[1])); g = j.get("gate") or {}; v = (g.get("signed_verdict") or {}).get("verdict") or {}
print("job %s id=%s status=%s after %ss gate=%s door=%s n_exact=%s max_abs_err=%s" % (sys.argv[2], j.get("job_id"), j.get("status"), sys.argv[3], g.get("level"), g.get("door"), v.get("n_exact"), v.get("max_abs_err")))
PY
}

step "both daemons air-gapped: the Return Path handshake verified from the cache alone, a gate job"
mark daemons_start
start_daemons airgap
mark job_submit
gate_job airgap
mark job_done
curl -s http://127.0.0.1:9081/metrics | grep -E "^(sagvd|rp|vg_tee)_" > "$OUT/sagvd-metrics-airgap.txt"
stop_daemons

step "the negative: the caches wiped, both daemons restarted — the handshake must be refused, naming $VENDOR"
# shellcheck disable=SC2086
( cd cache-sagvd && rm -f $CACHE_GLOB ); ( cd cache-worker && rm -f $CACHE_GLOB )
./acpctl tee cache-status --config sagvd.json > "$OUT/cache-status-wiped.txt" 2>&1; echo "cache-status after the wipe exit=$?" >> "$OUT/steps.txt"
mark wiped_start
start_daemons wiped
echo "handshake refusals on the record: $(grep -c 'handshake failed' "$OUT/sagvd-wiped.log")" >> "$OUT/steps.txt"
grep -m1 'handshake failed' "$OUT/sagvd-wiped.log" | python3 -c 'import json,sys; l=sys.stdin.readline(); print("refusal:", json.loads(l).get("err", "")[:400] if l.strip() else "none")' >> "$OUT/steps.txt" 2>/dev/null || true
stop_daemons

step "the caches restored from the copy; both daemons again; a gate job"
cp -r cache-backup/cache-sagvd/. cache-sagvd/ && cp -r cache-backup/cache-worker/. cache-worker/
./acpctl tee cache-status --config sagvd.json > "$OUT/cache-status-restored.txt" 2>&1; echo "cache-status after the restore exit=$?" >> "$OUT/steps.txt"
mark restored_start
start_daemons restored
gate_job restored
mark restored_job_done
curl -s http://127.0.0.1:9081/metrics | grep -E "^(sagvd|rp|vg_tee)_" > "$OUT/sagvd-metrics-restored.txt"
stop_daemons

step "verify the audit log with the published key"
./acpctl audit verify --audit audit/airgap-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-airgap --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"
echo "audit verify exit=$?" >> "$OUT/steps.txt"
./acpctl audit query --audit audit/airgap-audit.db --limit 0 --json > "$OUT/audit-events.jsonl" 2> "$OUT/audit-query.err"
echo "audit query exit=$?" >> "$OUT/steps.txt"
cp audit.pem "$OUT/audit-public-key.pem"
python3 -c 'import sys,time; t0=float(sys.argv[1]); print("elapsed_seconds=%.1f" % (time.time()-t0))' "$T0" >> "$OUT/steps.txt"

cp /root/e2e.log "$OUT/console.log"
( cd "$OUT" && sha256sum * > "$WORK/sha256sums.txt" ); mv "$WORK/sha256sums.txt" "$OUT/"

echo "== emit"
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
