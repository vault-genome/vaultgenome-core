#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The delegated verifier against a live Veraison (ADR 0025, step 2b) with
# a real GCP SEV-SNP report: runs the guarded test rats_live_test.go
# against the bench's native Veraison deployment and keeps the record —
# the well-known document, the EAR, a summary — under evidence/<stamp>/.
# No hardware: the report is Veraison's own captured GCP n2d report
# (internal/shared/tee/testdata/veraison), the session nonce its
# REPORT_DATA.
#
# Usage: run.sh            (BENCH_HOME defaults to ~/.attestation-bench;
#        the bench's e2e/scripts/veraison-local.sh start must have run)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BENCH_HOME="${BENCH_HOME:-$HOME/.attestation-bench}"
V="$BENCH_HOME/veraison"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$HERE/evidence/$STAMP"
mkdir -p "$OUT"
export VG_VERAISON_URL="${VG_VERAISON_URL:-https://localhost:8443}"
export VG_VERAISON_CA="${VG_VERAISON_CA:-$V/certs/rootCA.crt}"
export VG_VERAISON_CLIENT_CERT="${VG_VERAISON_CLIENT_CERT:-$BENCH_HOME/tls/ca-gateway.crt}"
export VG_VERAISON_CLIENT_KEY="${VG_VERAISON_CLIENT_KEY:-$BENCH_HOME/tls/ca-gateway.key}"
export VG_VERAISON_EVIDENCE_DIR="$OUT"
{
  echo "run=$STAMP"
  echo "tree=$(git -C "$ROOT" rev-parse HEAD)"
  echo "verifier_url=$VG_VERAISON_URL"
  echo "go=$(go version)"
  for s in vts provisioning verification management; do
    p="$V/logs/$s.pid"; [ -f "$p" ] && kill -0 "$(cat "$p")" 2>/dev/null && echo "$s=running" || echo "$s=stopped"
  done
  [ -f "$V/logs/corim-submit.json.sha256" ] && echo "corim_sha256=$(cat "$V/logs/corim-submit.json.sha256")"
} > "$OUT/metadata.txt"
cd "$ROOT"
go test -count=1 -v -run 'TestRATSVerifier_LiveVeraison' ./internal/shared/tee/ 2>&1 | tee "$OUT/go-test.log"
grep -q '^--- PASS: TestRATSVerifier_LiveVeraison' "$OUT/go-test.log" || { echo "the live run did not pass"; exit 1; }
( cd "$OUT" && shasum -a 256 well-known.json ear.jwt summary.json go-test.log metadata.txt > sha256sums.txt )
echo "evidence: $OUT"
cat "$OUT/summary.json"
