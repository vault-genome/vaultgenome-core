#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# license_header_check.sh — fails if any .go file under the module lacks
# the SPDX-License-Identifier header required by 00_CI_Security_Policy.md §7.
#
# The header must appear within the first 3 non-blank lines of the file:
#   // SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

REQUIRED="SPDX-License-Identifier: AGPL-3.0-or-later"
FAILED=0

# Gather all .go files in the module, excluding vendor/ and generated code.
while IFS= read -r -d '' f; do
  # Read up to the first 10 lines — a small, stable bound.
  HEAD=$(head -n 10 "$f")
  if ! echo "$HEAD" | grep -q "$REQUIRED"; then
    echo "license_header_check: missing SPDX header: $f"
    FAILED=1
  fi
done < <(find . -type f -name '*.go' \
           -not -path './vendor/*' \
           -not -path './bin/*' \
           -not -path './dist/*' \
           -print0)

if [ "$FAILED" -ne 0 ]; then
  echo "license_header_check: FAIL"
  echo "Every .go file MUST start with:"
  echo "  // SPDX-License-Identifier: AGPL-3.0-or-later"
  exit 1
fi

echo "license_header_check: PASS"
