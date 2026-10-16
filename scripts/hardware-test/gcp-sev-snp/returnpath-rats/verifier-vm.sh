#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script for the Verifier host (a plain GCP VM, Ubuntu 24.04): the
# bank's RATS Verifier, on a machine of its own. Builds Veraison from the
# source tree the bench validated (the sevsnp scheme, our patches), deploys
# it natively, makes its service certificates under the kit's root CA with
# the VM's name as a SAN, takes only callers with a certificate of that CA,
# starts the four services and says READY on the serial console. The
# runner then provisions it (AMD's root, the attester's launch) over the
# provisioning API. At the end (metadata vg-done=1) it prints its logs as a
# base64 tarball between ===VERIFIER-BEGIN=== and ===VERIFIER-END===.
#
# Inputs (instance metadata): vg-bucket (GCS: verifier/veraison-src.tgz,
# verifier/rootCA.crt, verifier/rootCA.key), vg-name (this VM's name).
set -u
exec > >(tee -a /root/verifier.log) 2>&1
# a startup script runs with no HOME: Go needs its module cache and build cache named
export HOME=/root GOPATH=/root/go GOMODCACHE=/root/go/pkg/mod GOCACHE=/root/.cache/go-build
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BUCKET=$(md attributes/vg-bucket); NAME=$(md attributes/vg-name)
WORK=/root/vg; OUT=$WORK/out; mkdir -p "$OUT"; cd "$WORK"
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
step() { echo "== $*"; echo "== $*" >> "$OUT/steps.txt"; }
say() { echo "$1" > /dev/ttyS0 2>/dev/null || true; echo "$1"; }
mark boot
step "packages"
export DEBIAN_FRONTEND=noninteractive
for i in $(seq 1 12); do apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq make gcc git sqlite3 openssl jq jose curl ca-certificates protobuf-compiler gettext-base python3 >/dev/null 2>&1 && break; sleep 10; done
step "Go 1.27.2 (pinned, from go.dev, checksum verified)"
GO_TGZ=go1.27.2.linux-amd64.tar.gz; GO_SHA=ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5
curl -sSfL -o "$GO_TGZ" "https://go.dev/dl/$GO_TGZ" && echo "$GO_SHA  $GO_TGZ" | sha256sum -c - >> "$OUT/steps.txt" 2>&1 || { say "===VERIFIER-FAIL=== go download"; exit 1; }
rm -rf /usr/local/go && tar -C /usr/local -xzf "$GO_TGZ"
export PATH=/usr/local/go/bin:/root/go/bin:$PATH GOFLAGS=-buildvcs=false GOTOOLCHAIN=local
go version >> "$OUT/steps.txt"
# the protobuf generators, in case the tree's Makefiles regenerate (the generated files are committed)
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.1 >/dev/null 2>&1 || true
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0 >/dev/null 2>&1 || true
step "sources and the kit's root CA from gs://$BUCKET/verifier"
GTOKEN=$(md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
for f in veraison-src.tgz rootCA.crt rootCA.key; do
  curl -sSf -H "Authorization: Bearer $GTOKEN" -o "$WORK/$f" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/verifier%2F$f?alt=media" || { say "===VERIFIER-FAIL=== fetch $f"; exit 1; }
done
unset GTOKEN
sha256sum veraison-src.tgz rootCA.crt > "$OUT/inputs.sha256"
mkdir -p src && tar xzf veraison-src.tgz -C src
SRC=$WORK/src/veraison-services/src
step "build Veraison (combined plugins) and deploy natively under /opt/veraison"
mark build_start
export VERAISON_ROOT=/opt/veraison
cd "$SRC/deployments/native"
./deployment.sh build > "$OUT/build.log" 2>&1; BX=$?; echo "build exit=$BX" >> "$OUT/steps.txt"
[ "$BX" = 0 ] || { say "===VERIFIER-FAIL=== build exit=$BX: $(grep -E 'Error|error:|cannot|fatal' "$OUT/build.log" | grep -v 'not a git' | tail -2 | tr '\n' ' ' | cut -c1-300)"; exit 1; }
./deployment.sh deploy > "$OUT/deploy.log" 2>&1; DX=$?; echo "deploy exit=$DX" >> "$OUT/steps.txt"
[ "$DX" = 0 ] || { say "===VERIFIER-FAIL=== deploy exit=$DX: $(tail -2 "$OUT/deploy.log" | tr '\n' ' ' | cut -c1-300)"; exit 1; }
# the clients (cocli, evcli, pocli, corim-store, pinned in deployment.sh): init-stores needs corim-store
./deployment.sh init-clients > "$OUT/clients.log" 2>&1; echo "init-clients exit=$?" >> "$OUT/steps.txt"
./deployment.sh init-stores >> "$OUT/deploy.log" 2>&1; SX=$?; echo "init-stores exit=$SX" >> "$OUT/steps.txt"
[ "$SX" = 0 ] || { say "===VERIFIER-FAIL=== init-stores exit=$SX: $(tail -2 "$OUT/deploy.log" | tr '\n' ' ' | cut -c1-300)"; exit 1; }
mark build_end
step "service certificates under the kit's root CA, SAN = $NAME; the EAR signing key"
mkdir -p /opt/veraison/certs && cp "$WORK/rootCA.crt" /opt/veraison/certs/rootCA.crt
./deployment.sh -f init-certs "@@-service,localhost,$NAME" "$WORK/rootCA.crt" "$WORK/rootCA.key" > "$OUT/certs.log" 2>&1; echo "init-certs exit=$?" >> "$OUT/steps.txt"
./deployment.sh -f init-signing-keys >> "$OUT/certs.log" 2>&1; echo "init-signing-keys exit=$?" >> "$OUT/steps.txt"
shred -u "$WORK/rootCA.key" 2>/dev/null || rm -f "$WORK/rootCA.key"
openssl x509 -in /opt/veraison/certs/verification.crt -noout -subject -ext subjectAltName -dates > "$OUT/verification-cert.txt" 2>&1
step "configuration: the verification API takes only callers with a certificate of the root CA"
python3 - /opt/veraison/config/services/config.yaml <<'PY'
import re, sys
p = sys.argv[1]; y = open(p).read()
blk = re.search(r"^verification:\n((?:  .*\n)+)", y, re.M)
if blk and "client-ca:" not in blk.group(1):
    y = y[:blk.end()] + "  client-ca: /opt/veraison/certs/rootCA.crt\n" + y[blk.end():]
open(p, "w").write(y)
PY
grep -v '^\s*#' /opt/veraison/config/services/config.yaml | grep -v '^\s*$' > "$OUT/config.yaml"
ls -la /opt/veraison/plugins > "$OUT/plugins.txt" 2>&1
step "start: vts, provisioning, verification, management"
mkdir -p /opt/veraison/logs; cd /opt/veraison
for s in vts provisioning verification management; do
  nohup "/opt/veraison/bin/$s-service" --config=/opt/veraison/config/services/config.yaml > "/opt/veraison/logs/$s.log" 2>&1 &
  echo $! > "/opt/veraison/logs/$s.pid"
  if [ "$s" = vts ]; then n=0; until (echo > /dev/tcp/127.0.0.1/50051) 2>/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done; fi
done
n=0; until (echo > /dev/tcp/127.0.0.1/8443) 2>/dev/null && (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
echo "listening after ${n}s" >> "$OUT/steps.txt"
mark ready
VER=$(curl -s --cacert /opt/veraison/certs/rootCA.crt --cert /opt/veraison/certs/verification.crt --key /opt/veraison/certs/verification.key https://localhost:8443/.well-known/veraison/verification | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version","?"))' 2>/dev/null || echo "?")
say "===VERIFIER-READY=== $STAMP name=$NAME version=$VER listening_after=${n}s"
step "waiting for vg-done"
n=0; until [ "$(md attributes/vg-done 2>/dev/null)" = 1 ] || [ $n -ge 720 ]; do sleep 5; n=$((n+1)); done
mark done_signal
step "collect: the services' logs, the stores' contents, the certificates (public)"
cp /opt/veraison/logs/*.log "$OUT/" 2>/dev/null
for s in vts provisioning verification management; do kill -TERM "$(cat /opt/veraison/logs/$s.pid)" 2>/dev/null; done
sleep 2
sqlite3 /opt/veraison/stores/store.sql ".dump" > "$OUT/store.sql.dump" 2>&1 || true
cp /opt/veraison/certs/rootCA.crt /opt/veraison/certs/verification.crt "$OUT/" 2>/dev/null
cp /root/verifier.log "$OUT/console.log"
( cd "$OUT" && sha256sum * > "$WORK/sha256sums.txt" ); mv "$WORK/sha256sums.txt" "$OUT/"
cd "$WORK" && tar czf "verifier-$STAMP.tgz" -C "$OUT" . && base64 -w0 "verifier-$STAMP.tgz" > "verifier-$STAMP.b64"
SZ=$(stat -c%s "verifier-$STAMP.b64"); H=$(sha256sum "verifier-$STAMP.b64" | cut -d' ' -f1)
fold -w 76 "verifier-$STAMP.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "verifier-$STAMP.lines"; NL=$(wc -l < "verifier-$STAMP.lines")
for COPY in 1 2 3; do
  { echo; echo "===VERIFIER-BEGIN=== $STAMP size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "verifier-$STAMP.lines"; echo "===VERIFIER-END==="; } > /dev/ttyS0 2>/dev/null || true
  sleep 3
done
echo "VERIFIER DONE $STAMP"
