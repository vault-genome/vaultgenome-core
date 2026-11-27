#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# check-records.sh — fails if a file of the tree names an account of the
# workstation a hardware run was made from, or of the person at it, as
# scripts/hardware-test/redact-record.py tells one by its form: a macOS
# home (/Users/<name>/...), the folder of an agent there
# (.../claude-<uid>/.../scratchpad, -Users-<name>-...), a user that a
# machine's guest agent made for a key or updated the keys of, the owner
# a macOS `ls -l` names. The records of the kits' runs are read by others;
# a name in one is redacted with that tool before the record is committed
# (redact-record.py PATH...), and the kits keep a console through it.
#
# Scope: every file under the directory it is run in, but source code — a
# test of code may set a home of its own —, .git (the folder, or the file
# of a worktree that points to it), vendor, dist, bin, and
# test/doctrine, whose meta-tests plant the forms to prove this catches
# them. The doctrine tests hold the tree to it
# (TestRecords_TheTreeNamesNoAccountOfAWorkstation).
set -euo pipefail

TOOL="$(cd "$(dirname "$0")" && pwd)/hardware-test/redact-record.py"

FILES=()
while IFS= read -r -d '' f; do
  FILES+=("$f")
done < <(
  find . -type f \
    -not -path './.git/*' -not -name '.git' -not -path './vendor/*' -not -path './dist/*' -not -path './bin/*' \
    -not -path './test/doctrine/*' \
    -not -name '*.go' -not -name '*.py' -not -name '*.sh' -not -name '*.ts' -not -name '*.js' \
    -not -name '*.mjs' -not -name '*.cjs' -not -name '*.rs' -not -name '*.c' -not -name '*.h' \
    -print0
)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "check-records: PASS (no file to read)"
  exit 0
fi

# The tool says each file it would change, and fails when there is one;
# xargs may run it more than once, so what it said is what counts.
NAMED="$(printf '%s\0' "${FILES[@]}" | xargs -0 python3 "$TOOL" --check || true)"
if [ -n "$NAMED" ]; then
  echo "check-records: FAIL — files that name an account of a workstation or of the person at it (redact them with scripts/hardware-test/redact-record.py):"
  printf '%s\n' "$NAMED" | sed 's/^/  /'
  exit 1
fi
echo "check-records: PASS (${#FILES[@]} files read)"
