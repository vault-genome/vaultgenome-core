#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The Return Path on real AMD SEV-SNP with the appraisal delegated to a RATS
# Verifier on another VM — the bank's topology (ADR 0025, step 2b). Two
# machines in one GCP project:
#
#   the Verifier host  — a plain VM building and running Veraison natively
#                        from the tree the bench validated (verifier-vm.sh),
#                        its services under the kit's root CA, the
#                        verification API taking only callers with a
#                        certificate of that CA;
#   the attester       — an n2d SEV-SNP Confidential VM running sagvd and
#                        acp-compute (cvm-returnpath-rats.sh): first with the
#                        builtin verifiers, then with both delegating to the
#                        Verifier by name over mutual TLS.
#
# The runner (this script) plays the operator: builds the binaries, makes
# the PKI, boots both VMs, takes the attester's chip report from its serial
# console, turns it into the CoRIM of approved launches (the bench's
# mkcorim: AMD's Milan root as the trust anchor, this launch as a reference
# value) and provisions the Verifier with it, hands the attester the
# Verifier's EAR key and the client certificates, releases it (vg-go=1),
# collects the results of both machines from their serial consoles, checks
# them, and deletes everything — always, also on failure.
#
# Usage: run.sh <project> [zone]     (zone default us-central1-c; ~20 minutes;
#        one n2d-standard-4 and one e2-standard-4 for that time)
# Needs: gcloud logged in; the bench checkout for Veraison's sources and
#        mkcorim (BENCH_REPO, default ~/dev/attestation-bench); openssl.
set -euo pipefail
PROJECT="${1:?usage: run.sh <project> [zone]}"
ZONE="${2:-us-central1-c}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
BENCH_REPO="${BENCH_REPO:-$HOME/dev/attestation-bench}"
VSRC="${VERAISON_SRC_PARENT:-$BENCH_REPO/third_party}"   # holds veraison-services/src and go-gen-ref/src
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
ATT="vg-rp-rats-$LOW"; VER="vg-verifier-$LOW"; BUCKET="$PROJECT-vg-rats-$LOW"; RULE="vg-rats-$LOW"
BUILD="$(mktemp -d)"
EVID="$HERE/evidence/$STAMP"; RUNNER="$EVID/runner"; mkdir -p "$RUNNER"
RAW_DIR="${VG_E2E_RAW_DIR:-$HOME/.cache/vaultgenome/returnpath-rats}"; mkdir -p "$RAW_DIR"
tl() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$RUNNER/runner-timeline.txt"; }
cleanup() {
  set +e
  echo "cleanup: deleting $ATT, $VER, firewall rule $RULE and gs://$BUCKET"
  gcloud compute instances delete "$ATT" "$VER" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud compute firewall-rules delete "$RULE" --project "$PROJECT" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT
tl start
echo "build (linux/amd64; acpctl and mkcorim for this host)"
( cd "$ROOT" && for b in sagvd acp-compute acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
( cd "$ROOT" && go build -trimpath -o "$BUILD/acpctl-host" ./cmd/acpctl )
( cd "$ROOT/workers" && COPYFILE_DISABLE=1 tar czf "$BUILD/genome-worker.tgz" --no-xattrs --exclude '__pycache__' --exclude '.pytest_cache' genome )
( cd "$BENCH_REPO/hwcheck" && GOWORK=off go build -o "$BUILD/mkcorim" ./cmd/mkcorim )
echo "AMD's Milan chain from KDS, verified against the roots acpctl pins (the ARK is the Verifier's trust anchor)"
"$BUILD/acpctl-host" tee fetch-amd-chain --product milan --out "$BUILD/amd-milan-cert_chain.pem" > "$RUNNER/amd-chain.txt" 2>&1
echo "Veraison's sources: the bench's tree (its patches: the sevsnp scheme's DER certificates, the client CA), without build outputs"
{ echo "veraison-services $(git -C "$VSRC/veraison-services/src" rev-parse HEAD 2>/dev/null) (+ working tree)"; echo "go-gen-ref $(git -C "$VSRC/go-gen-ref/src" rev-parse HEAD 2>/dev/null)"; } > "$RUNNER/veraison-sources.txt"
# the sources only: no .git, no built services or plugins (executables over 2 MB), no perf fixtures
( cd "$VSRC" && find veraison-services/src go-gen-ref/src -path '*/.git' -prune -o -type f ! \( -size +2M -perm +111 \) ! -path '*/perf/*' ! -name '*.plugin' -print > "$BUILD/veraison-src.list" \
    && COPYFILE_DISABLE=1 tar czf "$BUILD/veraison-src.tgz" --no-xattrs -T "$BUILD/veraison-src.list" )
echo "veraison-src.tgz: $(wc -l < "$BUILD/veraison-src.list" | tr -d ' ') files, $(du -h "$BUILD/veraison-src.tgz" | cut -f1)" | tee -a "$RUNNER/veraison-sources.txt"
echo "PKI: the kit's root CA (EC P-256, seven days); client certificates for sagvd, acp-compute and this runner"
P="$BUILD/pki"; mkdir -p "$P"
openssl ecparam -name prime256v1 -genkey -noout -out "$P/rootCA.key" 2>/dev/null
openssl req -x509 -new -key "$P/rootCA.key" -sha256 -days 7 -subj "/O=Vault Genome kit/CN=vg-rats-root-$LOW" -out "$P/rootCA.crt" 2>/dev/null
for c in sagvd worker runner; do
  openssl ecparam -name prime256v1 -genkey -noout -out "$P/$c-client.key" 2>/dev/null
  openssl req -new -key "$P/$c-client.key" -subj "/O=Vault Genome kit/CN=$c-$LOW" -out "$P/$c-client.csr" 2>/dev/null
  printf 'extendedKeyUsage=clientAuth\nsubjectAltName=DNS:%s-%s\n' "$c" "$LOW" > "$P/$c.ext"
  openssl x509 -req -in "$P/$c-client.csr" -CA "$P/rootCA.crt" -CAkey "$P/rootCA.key" -CAcreateserial -days 7 -sha256 -extfile "$P/$c.ext" -out "$P/$c-client.crt" 2>/dev/null
done
cp "$P/rootCA.crt" "$P/sagvd-client.crt" "$P/worker-client.crt" "$P/runner-client.crt" "$RUNNER/"
echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/sagvd" "$BUILD/acp-compute" "$BUILD/acpctl" "$BUILD/keygen" "$BUILD/genome-worker.tgz" "gs://$BUCKET/e2e/" --project "$PROJECT" >/dev/null
gcloud storage cp "$BUILD/veraison-src.tgz" "$P/rootCA.crt" "$P/rootCA.key" "gs://$BUCKET/verifier/" --project "$PROJECT" >/dev/null
gcloud storage cp "$P/rootCA.crt" "$P/sagvd-client.crt" "$P/sagvd-client.key" "$P/worker-client.crt" "$P/worker-client.key" "gs://$BUCKET/pki/" --project "$PROJECT" >/dev/null
RUNNER_IP="$(curl -s --max-time 10 https://api.ipify.org)"
echo "firewall: the runner ($RUNNER_IP) may reach the Verifier's 8443 and 9443; the attester reaches 8443 inside the VPC (default-allow-internal)"
gcloud compute firewall-rules create "$RULE" --project "$PROJECT" --network default --direction INGRESS --action ALLOW \
  --rules tcp:8443,tcp:9443 --source-ranges "$RUNNER_IP/32" --target-tags "$VER" --quiet >/dev/null
gcloud compute firewall-rules describe "$RULE" --project "$PROJECT" --format json > "$RUNNER/firewall-rule.json"
tl verifier_create
echo "boot $VER (e2-standard-4, the Verifier host) and $ATT (n2d SEV-SNP, the attester)"
gcloud compute instances create "$VER" --project "$PROJECT" --zone "$ZONE" \
  --machine-type e2-standard-4 --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --boot-disk-size 30GB \
  --tags "$VER" --scopes storage-ro --metadata "vg-bucket=$BUCKET,vg-name=$VER,vg-done=0" \
  --metadata-from-file "startup-script=$HERE/verifier-vm.sh" >/dev/null
tl attester_create
gcloud compute instances create "$ATT" --project "$PROJECT" --zone "$ZONE" \
  --machine-type n2d-standard-4 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --boot-disk-size 20GB \
  --scopes storage-ro --metadata "vg-bucket=$BUCKET,vg-verifier=$VER,vg-go=0" \
  --metadata-from-file "startup-script=$HERE/cvm-returnpath-rats.sh" >/dev/null
VSERIAL="$RAW_DIR/verifier-serial-$STAMP.txt"; ASERIAL="$RAW_DIR/attester-serial-$STAMP.txt"
serial() { gcloud compute instances get-serial-port-output "$1" --project "$PROJECT" --zone "$ZONE" > "$2" 2>/dev/null || true; }
# decode_block <serial file> <marker name> <out dir>: the folded base64 block the guests print, checked against its header
decode_block() {
  python3 - "$1" "$2" "$3" <<'PY'
import base64, hashlib, io, re, sys, tarfile, os
serial, name, dest = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(serial, errors="replace").read()
ok = False
for m in re.finditer(r"===%s-BEGIN=== (\S+) (.*?)sha256=([0-9a-f]{64}) lines=(\d+) copy=\d+\n(.*?)===%s-END===" % (name, name), text, re.S):
    stamp, digest, nlines = m.group(1), m.group(3), int(m.group(4))
    lines = {}
    for line in m.group(5).splitlines():
        mm = re.match(r".*?@@(\d{4}) (\S+)$", line)
        if mm:
            lines[int(mm.group(1))] = mm.group(2)
    if len(lines) != nlines:
        continue
    b64 = "".join(lines[i] for i in range(nlines))
    blob = base64.b64decode(b64)
    if name == "RATS-REPORT":
        if hashlib.sha256(blob).hexdigest() != digest:
            continue
        os.makedirs(dest, exist_ok=True)
        open(os.path.join(dest, "launch-report.bin"), "wb").write(blob)
        print("launch-report.bin", len(blob), "bytes", "header:", m.group(2).strip())
    else:
        if hashlib.sha256(b64.encode()).hexdigest() != digest:
            continue
        os.makedirs(dest, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            tar.extractall(dest, filter="data")
        print("decoded", stamp, len(blob), "bytes ->", dest)
    ok = True
    break
sys.exit(0 if ok else 1)
PY
}
echo "waiting for the Verifier to build, deploy and listen (up to 25 min), and for the attester's chip report"
VREADY=""; AREPORT=""
for i in $(seq 1 150); do
  sleep 10
  [ -z "$VREADY" ] && { serial "$VER" "$VSERIAL"; grep -q "===VERIFIER-READY===" "$VSERIAL" && VREADY=1 && tl verifier_ready && grep "===VERIFIER-READY===" "$VSERIAL" | tail -1 | tee "$RUNNER/verifier-ready.txt"; }
  [ -z "$AREPORT" ] && { serial "$ATT" "$ASERIAL"; grep -q "===RATS-REPORT-END===" "$ASERIAL" && decode_block "$ASERIAL" RATS-REPORT "$RUNNER" >/dev/null && AREPORT=1 && tl attester_report; }
  grep -q "===VERIFIER-FAIL===" "$VSERIAL" 2>/dev/null && { echo "the Verifier host failed: $(grep '===VERIFIER-FAIL===' "$VSERIAL" | tail -1)"; exit 1; }
  [ -n "$VREADY" ] && [ -n "$AREPORT" ] && break
done
[ -n "$VREADY" ] && [ -n "$AREPORT" ] || { echo "not both ready after 25 minutes (verifier=$VREADY report=$AREPORT)"; tail -20 "$VSERIAL"; tail -20 "$ASERIAL"; exit 1; }
VER_IP="$(gcloud compute instances describe "$VER" --project "$PROJECT" --zone "$ZONE" --format 'value(networkInterfaces[0].accessConfigs[0].natIP)')"
VER_INT="$(gcloud compute instances describe "$VER" --project "$PROJECT" --zone "$ZONE" --format 'value(networkInterfaces[0].networkIP)')"
echo "verifier_external_ip=$VER_IP verifier_internal_ip=$VER_INT" | tee -a "$RUNNER/metadata.txt"
echo "the CoRIM: AMD's Milan ARK as the trust anchor, this chip's launch as a reference value (mkcorim), provisioned over the provisioning API"
python3 - "$RUNNER/launch-report.bin" "$RUNNER/launch-report.tsm.cbor" <<'PY'
# ratsd's TSM report in CBOR: a map {"outblob": bstr, "provider": tstr}; mkcorim reads outblob
import sys, struct
report = open(sys.argv[1], "rb").read()
def tstr(s): b = s.encode(); return bytes([0x60 | len(b)]) + b
def bstr(b): return b"\x59" + struct.pack(">H", len(b)) + b
cbor = b"\xa2" + tstr("outblob") + bstr(report) + tstr("provider") + tstr("sev_guest")
open(sys.argv[2], "wb").write(cbor)
print("launch-report.tsm.cbor", len(cbor), "bytes; measurement", report[0x90:0xC0].hex())
PY
"$BUILD/mkcorim" -kds "$BUILD/amd-milan-cert_chain.pem" -out "$RUNNER/corim.cbor" "$RUNNER/launch-report.tsm.cbor"
MEAS="$(python3 -c 'import sys; print(open(sys.argv[1],"rb").read()[0x90:0xC0].hex())' "$RUNNER/launch-report.bin")"
echo "launch_measurement=$MEAS" >> "$RUNNER/metadata.txt"
CURLV=(curl -sS --max-time 30 --resolve "$VER:8443:$VER_IP" --resolve "$VER:9443:$VER_IP" --cacert "$P/rootCA.crt" --cert "$P/runner-client.crt" --key "$P/runner-client.key")
for i in $(seq 1 10); do
  "${CURLV[@]}" -X POST -H 'Content-Type: application/rim+cbor; profile="tag:amd.com,2024:snp-corim-profile"' \
    --data-binary @"$RUNNER/corim.cbor" "https://$VER:9443/endorsement-provisioning/v1/submit" > "$RUNNER/corim-submit.json" 2>&1 || true
  grep -q success "$RUNNER/corim-submit.json" && break
  sleep 5
done
grep -q success "$RUNNER/corim-submit.json" || { echo "the Verifier did not accept the CoRIM: $(cat "$RUNNER/corim-submit.json")"; exit 1; }
tl corim_provisioned
echo "the Verifier's EAR key from its well-known document (over mutual TLS, by the name on its certificate)"
"${CURLV[@]}" "https://$VER:8443/.well-known/veraison/verification" > "$RUNNER/well-known.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); json.dump(d["ear-verification-key"], open(sys.argv[2],"w")); print("veraison", d.get("version"), "media types", len(d.get("media-types",[])))' "$RUNNER/well-known.json" "$P/verifier-ear.jwk"
cp "$P/verifier-ear.jwk" "$RUNNER/verifier-ear.jwk"
gcloud storage cp "$P/verifier-ear.jwk" "gs://$BUCKET/pki/" --project "$PROJECT" >/dev/null
gcloud compute instances add-metadata "$ATT" --project "$PROJECT" --zone "$ZONE" --metadata vg-go=1 >/dev/null
tl attester_released
echo "waiting for the attester's results (up to 30 min)"
for i in $(seq 1 180); do
  sleep 10
  serial "$ATT" "$ASERIAL"
  grep -q "===E2E-END===" "$ASERIAL" && break
done
grep -q "===E2E-END===" "$ASERIAL" || { echo "no results after 30 minutes"; tail -40 "$ASERIAL"; exit 1; }
tl attester_done
echo "serial capture: $ASERIAL ($(shasum -a 256 "$ASERIAL" | cut -d' ' -f1))"
"$HERE/../returnpath-e2e/decode-results.sh" "$ASERIAL" "$HERE/evidence"
GUEST="$(ls -d "$HERE"/evidence/*/ | grep -v "$STAMP" | sort | tail -1)"   # the guest's stamp names its dir
echo "the Verifier's record: its logs and stores (vg-done=1)"
gcloud compute instances add-metadata "$VER" --project "$PROJECT" --zone "$ZONE" --metadata vg-done=1 >/dev/null
for i in $(seq 1 30); do
  sleep 10
  serial "$VER" "$VSERIAL"
  grep -q "===VERIFIER-END===" "$VSERIAL" && break
done
grep -q "===VERIFIER-END===" "$VSERIAL" && decode_block "$VSERIAL" VERIFIER "$GUEST/verifier" || echo "the Verifier's record did not arrive"
tl verifier_done
mv "$RUNNER" "$GUEST/runner"; rmdir "$EVID" 2>/dev/null || true
{ echo "run=$STAMP"; echo "tree=$(git -C "$ROOT" rev-parse HEAD)"; echo "project=$PROJECT zone=$ZONE"; echo "attester=$ATT verifier=$VER"; echo "runner_ip=$RUNNER_IP"; cat "$GUEST/runner/metadata.txt"; } > "$GUEST/runner/metadata.txt.new" && mv "$GUEST/runner/metadata.txt.new" "$GUEST/runner/metadata.txt"
shasum -a 256 "$BUILD/amd-milan-cert_chain.pem" "$BUILD/veraison-src.tgz" "$GUEST/runner/corim.cbor" "$GUEST/runner/launch-report.bin" "$GUEST/runner/well-known.json" | sed "s|$BUILD/||; s|$GUEST/runner/||" > "$GUEST/runner/sha256sums.txt"
echo "evidence: $GUEST"
grep -E "session opened|handshake_ms|job_status|gate_|rogue|policy refusal|verifier-down|trust_decisions|audit (verify|query)|elapsed" "$GUEST/steps.txt" | cut -c1-200
