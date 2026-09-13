#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# coverage_check.sh — enforces the per-package coverage thresholds
# defined in 00_CI_Security_Policy.md §8.
#
# Thresholds:
#   /internal/contracts/...                  80%
#   /internal/validation/operational/...     90%
#   /internal/vault/orchestration/...        85%
#   everything else                          70%
#
# Requires a prior `go test -coverprofile=coverage.out ./...` run.
# Produces a concise pass/fail report.

set -euo pipefail

PROFILE="coverage.out"
if [ ! -f "$PROFILE" ]; then
  echo "coverage_check: FAIL — $PROFILE not found. Run 'make coverage' first."
  exit 1
fi

# The command `go tool cover -func=$PROFILE` emits one line per function and a
# final "total:" line. We aggregate per-package here by parsing the file-path
# prefix. Stage B: this is a scaffold; in Stage C we replace with a structured
# aggregation.

TMPFILE=$(mktemp)
go tool cover -func="$PROFILE" | tee "$TMPFILE" >/dev/null

fail=0
check_pkg_threshold() {
  local prefix="$1" threshold="$2"
  # Compute the average coverage across lines whose file path begins with prefix.
  local pct
  pct=$(awk -v p="$prefix" '
    $1 ~ p {
      gsub(/%/, "", $NF);
      sum += $NF; n++;
    }
    END {
      if (n == 0) { print "NA"; } else { printf("%.1f", sum / n); }
    }
  ' "$TMPFILE")

  if [ "$pct" = "NA" ]; then
    # No files yet — not a failure during Stage B.
    echo "coverage_check: $prefix — no files (stage B)."
    return 0
  fi

  awk -v pct="$pct" -v th="$threshold" 'BEGIN { exit !(pct+0 >= th+0) }' || {
    echo "coverage_check: FAIL — $prefix average ${pct}% < threshold ${threshold}%"
    fail=1
    return 0
  }
  echo "coverage_check: OK   — $prefix ${pct}% >= ${threshold}%"
}

check_pkg_threshold "github.com/ai-continuity-platform/core/internal/contracts/"          80
check_pkg_threshold "github.com/ai-continuity-platform/core/internal/validation/operational/" 90
check_pkg_threshold "github.com/ai-continuity-platform/core/internal/vault/orchestration/" 85
# General threshold on everything else is enforced loosely here; a stricter
# per-package rollup is added in Stage C.
check_pkg_threshold "github.com/ai-continuity-platform/core/internal/"                    70

rm -f "$TMPFILE"

if [ "$fail" -ne 0 ]; then
  echo "coverage_check: FAIL"
  exit 1
fi
echo "coverage_check: PASS"
