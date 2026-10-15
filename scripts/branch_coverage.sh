#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# branch_coverage.sh — measures branch coverage of the wire contracts
# (internal/contracts/...) with gobco (https://github.com/rillig/gobco) and
# reports it; docs/doctrine/ci-security-policy.md §8.
#
# Statement coverage is a floor the gate enforces (coverage_check.sh). Branch
# coverage is a second reading of the same tests: for every condition in the
# package, was it seen both true and false? gobco instruments each condition,
# runs the package's tests, and counts. A branch is covered when its condition
# was true at least once (one branch) and false at least once (the other).
#
# What this script reports, per package and in total: branches covered over
# branches instrumented, and — in the per-package files — every condition that
# was never seen on one side. No threshold yet: the number is reported, in the
# job summary of the workflow and as an artifact, so it is visible and can be
# ratcheted later the way the statement floors were.
#
# gobco takes one package per invocation, so the script runs it once per
# package. Each run leaves two files under dist/branch-coverage/:
#   <pkg>.json   gobco's -stats record: every condition with its true/false counts
#   <pkg>.txt    gobco's report: the summary line and the uncovered conditions
# and the script writes summary.md (a table) there too; with GITHUB_STEP_SUMMARY
# set, the table goes to the job summary as well.
#
# Usage: scripts/branch_coverage.sh [package pattern]   (default: ./internal/contracts/...)
#   GOBCO=<path>  the gobco binary (default: gobco on PATH)
set -euo pipefail

cd "$(dirname "$0")/.."

PATTERN="${1:-./internal/contracts/...}"
GOBCO="${GOBCO:-gobco}"
OUT="dist/branch-coverage"

command -v "$GOBCO" >/dev/null 2>&1 || {
  echo "branch_coverage: gobco not found (GOBCO=$GOBCO); install the pinned version:" >&2
  echo "  go install github.com/rillig/gobco@4c9ea04be46fdf4ee7d40f7bba782f83d0397731  # v1.3.4" >&2
  exit 2
}

rm -rf "$OUT" && mkdir -p "$OUT"

MODULE="$(go list -m)"
PACKAGES="$(go list "$PATTERN")"

total_covered=0
total_branches=0
rows=""
for pkg in $PACKAGES; do
  rel="${pkg#"$MODULE"/}"
  slug="${rel//\//_}"
  stats="$OUT/$slug.json"
  report="$OUT/$slug.txt"
  # gobco runs the package's tests on an instrumented copy; the stats file is
  # written fresh (nothing to load) and holds every condition with its counts.
  rm -f "$stats"
  if ! "$GOBCO" -branch -stats "$stats" "./$rel" > "$report" 2>&1; then
    echo "branch_coverage: gobco failed on $rel:" >&2
    cat "$report" >&2
    exit 1
  fi
  # Count from the stats record, not from the summary line: a condition
  # contributes two branches, one covered by each side it was seen on.
  read -r covered branches < <(python3 -I - "$stats" <<'PY'
import json, sys
conds = json.load(open(sys.argv[1]))
covered = sum((c["TrueCount"] > 0) + (c["FalseCount"] > 0) for c in conds)
print(covered, 2 * len(conds))
PY
)
  # The summary line gobco printed must agree with the count from its record.
  printed="$(grep -E '^Branch coverage: ' "$report" | sed -E 's/^Branch coverage: //' || true)"
  if [ -n "$printed" ] && [ "$printed" != "$covered/$branches" ]; then
    echo "branch_coverage: $rel: gobco printed $printed but its record counts $covered/$branches" >&2
    exit 1
  fi
  pct="$(python3 -I -c 'import sys; c,b=int(sys.argv[1]),int(sys.argv[2]); print("%.1f" % (100.0*c/b) if b else "n/a")' "$covered" "$branches")"
  rows+="| \`$rel\` | $covered / $branches | $pct% |"$'\n'
  total_covered=$((total_covered + covered))
  total_branches=$((total_branches + branches))
done

total_pct="$(python3 -I -c 'import sys; c,b=int(sys.argv[1]),int(sys.argv[2]); print("%.1f" % (100.0*c/b) if b else "n/a")' "$total_covered" "$total_branches")"
{
  echo "## Branch coverage (gobco, $PATTERN)"
  echo
  echo "| Package | Branches covered | Coverage |"
  echo "|---|---|---|"
  printf '%s' "$rows"
  echo "| **total** | **$total_covered / $total_branches** | **$total_pct%** |"
  echo
  echo "A condition contributes two branches; one is covered when the condition was true at least once, the other when it was false at least once. The conditions never seen on one side are listed per package in the artifact (\`<package>.txt\`); every condition with its counts is in \`<package>.json\`. No threshold is enforced yet."
} > "$OUT/summary.md"

cat "$OUT/summary.md"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$OUT/summary.md" >> "$GITHUB_STEP_SUMMARY"
fi
