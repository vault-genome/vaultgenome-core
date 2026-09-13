#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# terminology_check.sh — fails if any deprecated term from
# 00_Terminology_Alignment.md §4 appears outside docs/patent_references/.
#
# This script implements sub-check 09 of the vault-gate workflow.

set -euo pipefail

# Patterns to catch. The set is frozen by 00_Terminology_Alignment.md §4.
# Matches are case-sensitive where the canonical doctrine is case-sensitive;
# NSV is matched as a whole token only, so SessionFooNSV would not trip it.
declare -a PATTERNS=(
  '\bNSV\b'
  '\bneural_seed\b'
  '\bNeuralSeedVault\b'
  '\bneural_seed_vault\b'
  '\bgenome_vault\b'             # lowercase/underscore form is deprecated
  '\brestore[sd]?\b'
  '\brestoration\b'
  '\bbackup\b'
  '\bdecrypt[[:space:]]+and[[:space:]]+load\b'
  '\bmodel[[:space:]]+file\b'
  '\bweights[[:space:]]+file\b'
)

# Scope: all files under the repository root, EXCEPT:
#   - docs/patent_references/*     (patent-traceability exception)
#   - scripts/terminology_check.sh (this file, which names the terms)
#   - .git/*
#   - vendor/*
#   - dist/, bin/
EXCLUDES=(
  ':(exclude)docs/patent_references'
  ':(exclude)scripts/terminology_check.sh'
  ':(exclude).git'
  ':(exclude)vendor'
  ':(exclude)dist'
  ':(exclude)bin'
)

FAILED=0

# Scope: files that carry doctrine. Operational config files (.gitignore,
# Dockerfile, Terraform) may legitimately use words like "backup" in their
# non-doctrinal senses (file-extension patterns, OS backups); those files
# are intentionally out of scope.
INCLUDE_GLOBS=(
  '*.go'
  '*.md'
  '*.yml'
  '*.yaml'
  '*.proto'
  '*.sh'
)

# Build the file list once.
FILES=()
while IFS= read -r -d '' f; do
  FILES+=("$f")
done < <(
  find . -type f \( \
       -name '*.go' -o -name '*.md' -o -name '*.yml' \
    -o -name '*.yaml' -o -name '*.proto' -o -name '*.sh' \
  \) \
  -not -path './.git/*' \
  -not -path './vendor/*' \
  -not -path './dist/*' \
  -not -path './bin/*' \
  -not -path './docs/patent_references/*' \
  -not -name 'terminology_check.sh' \
  -print0
)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "terminology_check: no in-scope files to check"
  echo "terminology_check: PASS"
  exit 0
fi

for pat in "${PATTERNS[@]}"; do
  MATCHES=$(grep -nE "$pat" "${FILES[@]}" 2>/dev/null || true)
  if [ -n "$MATCHES" ]; then
    echo "terminology_check: deprecated term matched by pattern: $pat"
    echo "$MATCHES" | head -20
    echo
    FAILED=1
  fi
done

if [ "$FAILED" -ne 0 ]; then
  echo "terminology_check: FAIL"
  echo "See 00_Terminology_Alignment.md for canonical terms and the full"
  echo "deprecation list. Deprecated terms are permitted only under"
  echo "docs/patent_references/."
  exit 1
fi

echo "terminology_check: PASS"
