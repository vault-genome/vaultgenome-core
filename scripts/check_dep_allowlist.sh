#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# check_dep_allowlist.sh — fails if this module declares a direct Go-module
# dependency that is not present on scripts/dep_allowlist.txt.
#
# Doctrinal role
#
#   Policy 00_CI_Security_Policy.md §3.1 fixes the set of allowed direct
#   dependencies. A silent addition — even a reputable one — is a governance
#   violation: every external surface we link against widens the supply-chain
#   blast radius. This script is the mechanical enforcement of that rule.
#
# Behavior
#
#   1. Reads the allowlist file (one module-path prefix per line; `#` comments
#      and blank lines ignored).
#   2. Runs `go list -m -mod=readonly all` to enumerate the full module set,
#      then filters to DIRECT dependencies of the main module using
#      `go mod graph` (first field == main module path, no `@version` suffix).
#   3. For every direct dependency, requires that its module path either
#      matches an allowlist entry exactly OR has an allowlist entry as a
#      path-segment prefix (e.g. `golang.org/x/crypto/chacha20` is accepted
#      if `golang.org/x/crypto` is listed).
#   4. Prints every violation and exits 1; otherwise prints PASS.
#
# The script does not modify files and is safe to run locally.

set -euo pipefail

ALLOWLIST_FILE="${ALLOWLIST_FILE:-scripts/dep_allowlist.txt}"

if ! command -v go >/dev/null 2>&1; then
  echo "check_dep_allowlist: FAIL — 'go' is not on PATH" >&2
  exit 1
fi

if [[ ! -f "$ALLOWLIST_FILE" ]]; then
  echo "check_dep_allowlist: FAIL — allowlist file not found at $ALLOWLIST_FILE" >&2
  exit 1
fi

# Parse the allowlist into an array, stripping comments and whitespace.
declare -a ALLOWED=()
while IFS= read -r raw; do
  line="${raw%%#*}"
  # Trim leading/trailing whitespace.
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -z "$line" ]] && continue
  ALLOWED+=("$line")
done < "$ALLOWLIST_FILE"

if [[ "${#ALLOWED[@]}" -eq 0 ]]; then
  echo "check_dep_allowlist: FAIL — allowlist file is empty" >&2
  exit 1
fi

# Resolve the main module path.
MAIN="$(go list -m 2>/dev/null)"
if [[ -z "$MAIN" ]]; then
  echo "check_dep_allowlist: FAIL — 'go list -m' returned no main module" >&2
  exit 1
fi

# Enumerate direct dependencies. A direct dep is a line in `go mod graph`
# whose first column equals the main module path (i.e., no @version suffix).
#
# We intentionally do not consult `go list -m -f {{.Indirect}}` because that
# can be affected by vendored/replaced modules; `go mod graph` is the
# canonical edge set used by MVS.
DIRECT_RAW="$(go mod graph | awk -v m="$MAIN" '$1 == m { print $2 }' | sort -u)"

if [[ -z "$DIRECT_RAW" ]]; then
  echo "check_dep_allowlist: PASS — module declares no direct dependencies"
  exit 0
fi

fail=0
while IFS= read -r dep; do
  [[ -z "$dep" ]] && continue
  # Strip @version suffix, keep only the module path.
  path="${dep%@*}"
  allowed=0
  for entry in "${ALLOWED[@]}"; do
    if [[ "$path" == "$entry" || "$path" == "$entry"/* ]]; then
      allowed=1
      break
    fi
  done
  if [[ "$allowed" -eq 0 ]]; then
    echo "check_dep_allowlist: FORBIDDEN direct dependency: $path"
    echo "  add a justification at docs/dependencies/$(basename "$path").md"
    echo "  and append '$path' to $ALLOWLIST_FILE per 00_CI_Security_Policy.md §3.1"
    fail=1
  fi
done <<<"$DIRECT_RAW"

if [[ "$fail" -ne 0 ]]; then
  echo "check_dep_allowlist: FAIL"
  exit 1
fi

echo "check_dep_allowlist: PASS"
