#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# license_header_check.sh — every source file (Go, Python, shell) carries,
# within its first ten lines, the copyright statement of NOTICE and the
# SPDX license identifier. Policy: docs/doctrine/ci-security-policy.md §7.
set -euo pipefail

REQUIRED_LICENSE="SPDX-License-Identifier: AGPL-3.0-or-later"
# The published conformance corpus, its harness and the public conformance
# package are Apache-2.0 (ADR 0003, amendment of 2026-10-23): those three
# directories carry that identifier and no other.
APACHE_LICENSE="SPDX-License-Identifier: Apache-2.0"
APACHE_DIRS='^\./(pkg/teeconformance|tools/corpus-harness|test/corpus/sev-snp)/'
REQUIRED_COPYRIGHT="Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin"
FAILED=0
CHECKED=0
while IFS= read -r -d '' f; do
  CHECKED=$((CHECKED + 1))
  HEAD=$(head -n 10 "$f")
  WANT="$REQUIRED_LICENSE"
  if [[ "$f" =~ $APACHE_DIRS ]]; then
    WANT="$APACHE_LICENSE"
  fi
  if [[ "$HEAD" != *"$WANT"* ]]; then
    echo "license_header_check: missing or wrong SPDX header (want $WANT): $f"
    FAILED=1
  fi
  if [[ "$HEAD" != *"$REQUIRED_COPYRIGHT"* ]]; then
    echo "license_header_check: missing copyright statement: $f"
    FAILED=1
  fi
done < <(find . -type f \( -name '*.go' -o -name '*.py' -o -name '*.sh' \) \
           -not -path './vendor/*' \
           -not -path './bin/*' \
           -not -path './dist/*' \
           -not -path '*/node_modules/*' \
           -not -path '*/.venv/*' \
           -not -path '*/.terraform/*' \
           -print0)
if [ "$FAILED" -ne 0 ]; then
  echo "license_header_check: FAIL"
  echo "Every Go, Python and shell file MUST start (after a shebang, if any) with:"
  echo "  // Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin      (# in Python and shell)"
  echo "  // SPDX-License-Identifier: AGPL-3.0-or-later"
  echo "  (SPDX-License-Identifier: Apache-2.0 under pkg/teeconformance, tools/corpus-harness and test/corpus/sev-snp)"
  exit 1
fi
echo "license_header_check: PASS ($CHECKED files)"
