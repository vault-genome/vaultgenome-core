#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The Signature Version 4 signer and the KMS client against AWS KMS itself
# (ADR 0036, part three): internal/shared/awskms/live_test.go, with the
# credentials of the AWS CLI's configuration. Needs no KMS key and creates
# nothing. The evidence goes to evidence/<UTC time>/ with the access key
# shortened and the account number taken out; the run stops before saving
# anything a credential reached.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$HERE/evidence/$TS"
REGION="${VG_KMS_LIVE_REGION:-us-east-2}"
if [ -z "${AWS_ACCESS_KEY_ID:-}" ]; then
  # Into this process's environment only; never printed.
  eval "$(aws configure export-credentials --format env)"
fi
# Read before the evidence directory exists, which would itself show as a change.
if [ -z "$(git -C "$ROOT" status --porcelain)" ]; then TREE="tree clean"; else TREE="tree with uncommitted changes"; fi
mkdir -p "$OUT"
{
  echo "commit $(git -C "$ROOT" rev-parse HEAD)"
  echo "$TREE"
  echo "go $(cd "$ROOT" && go env GOVERSION) $(go env GOOS)/$(go env GOARCH)"
  echo "region $REGION"
  echo "started $TS"
} > "$OUT/run.txt"
set +e
(cd "$ROOT" && VG_KMS_LIVE_REGION="$REGION" go test -count=1 -tags kmslive -run TestLiveKMS -v ./internal/shared/awskms/) > "$OUT/go-test.log" 2>&1
RC=$?
set -e
echo "go test rc $RC" >> "$OUT/run.txt"
# The evidence must hold no credential and no account number.
if ! /usr/bin/env python3 -I - "$OUT" <<'PY'
import os, re, sys
out = sys.argv[1]
secrets = [os.environ.get(k, "") for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")]
bad = False
for name in os.listdir(out):
    text = open(os.path.join(out, name), encoding="utf-8", errors="replace").read()
    if any(s and s in text for s in secrets) or re.search(r"arn:aws:[a-z]+::?\d{12}:", text):
        print("a credential or an account number reached", name)
        bad = True
sys.exit(1 if bad else 0)
PY
then
  rm -rf "$OUT"
  exit 3
fi
(cd "$OUT" && shasum -a 256 run.txt go-test.log > SHA256SUMS)
echo "evidence: $OUT (go test rc $RC)"
exit "$RC"
