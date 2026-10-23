#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# dco_check.sh [--accept-github-squash] [<range>] — every non-merge commit
# in the range carries a Developer Certificate of Origin sign-off whose
# email is the author's.
#
# --accept-github-squash, for a push to main only: a commit GitHub writes
# when it squash-merges a pull request (committer "GitHub
# <noreply@github.com>", the author the account's noreply address) is
# accepted when it carries the sign-offs of the commits it squashed. Those
# commits were checked one by one on the pull request, as a merge commit's
# are; the squash exists because main takes only signed commits and GitHub
# signs what it writes. A pull request's own range never takes the flag.
#
# The range defaults to origin/main..HEAD (a branch under review). CI passes
# the pull request's base..head, or the push's before..after on main. Merge
# commits are skipped: GitHub writes them, nobody signs them off. Policy:
# CONTRIBUTING.md, "Developer Certificate of Origin"; in force for commits
# authored from 2026-10-14 on.
set -euo pipefail

ACCEPT_SQUASH=0
if [ "${1:-}" = "--accept-github-squash" ]; then
  ACCEPT_SQUASH=1
  shift
fi
RANGE="${1:-origin/main..HEAD}"
SINCE="2026-10-14T00:00:00Z"
FAILED=0
CHECKED=0
while IFS= read -r sha; do
  [ -n "$sha" ] || continue
  author_email=$(git log -1 --format='%ae' "$sha")
  author_date=$(git log -1 --format='%aI' "$sha")
  if [[ "$author_date" < "$SINCE" ]]; then
    continue
  fi
  CHECKED=$((CHECKED + 1))
  signoffs=$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" | sed '/^$/d')
  if [ -z "$signoffs" ]; then
    echo "dco_check: no Signed-off-by trailer: $sha $(git log -1 --format='%s' "$sha")"
    FAILED=1
    continue
  fi
  if [ "$ACCEPT_SQUASH" -eq 1 ] && [ "$(git log -1 --format='%cn <%ce>' "$sha")" = "GitHub <noreply@github.com>" ] &&
     [[ "$author_email" == *@users.noreply.github.com ]]; then
    echo "dco_check: squash by GitHub, its commits checked on the pull request: $sha ($(echo "$signoffs" | wc -l | tr -d ' ') sign-off(s))"
    continue
  fi
  if ! echo "$signoffs" | grep -qF "<$author_email>"; then
    echo "dco_check: Signed-off-by does not name the author <$author_email>: $sha"
    echo "  trailer(s): $(echo "$signoffs" | tr '\n' ';')"
    FAILED=1
  fi
done < <(git rev-list --no-merges "$RANGE" 2>/dev/null || true)

if [ "$FAILED" -ne 0 ]; then
  echo "dco_check: FAIL"
  echo "Every commit certifies the Developer Certificate of Origin (https://developercertificate.org):"
  echo "  git commit -s   (adds 'Signed-off-by: Name <email>' with the author's email)"
  echo "  git rebase --signoff origin/main   (for commits already made)"
  exit 1
fi
echo "dco_check: PASS ($CHECKED commit(s) checked in $RANGE)"
