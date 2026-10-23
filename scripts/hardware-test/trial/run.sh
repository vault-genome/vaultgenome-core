#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The acceptance trial's runner (docs/TRIAL-v0.10.0.md). It runs one
# hardware kit as the release ships it, from a checkout of the signed tag,
# so that the product binaries the kit builds are the release's own bytes,
# and it checks that they are:
#
#   1. the lane — a worktree detached at the tag — must be the tag: HEAD at
#      the tag's commit, the tag's signature good under the lane's
#      .github/allowed_signers, no tracked file changed;
#   2. the release's link flags reach the kit's `go build` through GOFLAGS,
#      taken from the tag's own Makefile as release.yml invokes it (VERSION
#      the tag, COMMIT the full commit); git's status.showUntrackedFiles=no
#      goes through the environment, because Go stamps a build
#      vcs.modified when `git status` lists anything, untracked files
#      included, and a kit's own evidence directory is untracked while it
#      runs — the tracked tree is what step 1 checked, and a change to it
#      still marks the build modified;
#   3. before the kit, the lane builds the five release binaries and their
#      -fips variants the way the kits build (CGO_ENABLED=0 GOOS=linux
#      GOARCH=amd64 go build -trimpath), and every one must equal its
#      signed asset — the environment is the release's, or nothing runs;
#   4. the kit runs unmodified, with its arguments and the caller's VG_*;
#   5. after it, every inputs.sha256 the kit wrote is held to the asset
#      list: each product binary it uploaded is named with the asset it
#      equals, or DIFFER; the kit's new evidence directories are copied into
#      this tree and compared byte for byte.
#
# Usage:
#   VG_TRIAL_ASSETS=<the release assets' sha256 list, as the release-deploy kit verified them> \
#   scripts/hardware-test/trial/run.sh <lane> <row> <kit> [kit arguments...]
#
#   <lane>  a worktree detached at the tag (VG_TRIAL_TAG, v0.10.0 by default)
#   <row>   the trial's row (T1, T2, ...)
#   <kit>   the kit's directory under scripts/hardware-test
#
# The record is evidence/<stamp>-<row>/ beside this script: run.txt,
# lane-build.txt, release-bytes.txt, versions.txt. The kit's console goes to
# VG_TRIAL_CONSOLE (~/vg-trial-console by default), outside every tree: kits
# print what their evidence leaves out on purpose.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TREE="$(cd "$HERE/../../.." && pwd)"
TAG="${VG_TRIAL_TAG:-v0.10.0}"
LANE="${1:?usage: run.sh <lane> <row> <kit> [kit arguments...]}"; ROW="${2:?row}"; KIT="${3:?kit}"; shift 3
ASSETS="${VG_TRIAL_ASSETS:?VG_TRIAL_ASSETS: the sha256 list of the release assets, as the release-deploy kit verified them}"
LANE="$(cd "$LANE" && pwd)"; ASSETS="$(cd "$(dirname "$ASSETS")" && pwd)/$(basename "$ASSETS")"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REC="$HERE/evidence/$STAMP-$ROW"; mkdir -p "$REC"
CONSOLE="${VG_TRIAL_CONSOLE:-$HOME/vg-trial-console}/$STAMP-$ROW.log"; mkdir -p "$(dirname "$CONSOLE")"
note() { echo "$*" | tee -a "$REC/run.txt"; }
die() { note "trial: $*"; exit 2; }
[ -x "$LANE/scripts/hardware-test/$KIT/run.sh" ] || [ -f "$LANE/scripts/hardware-test/$KIT/run.sh" ] || die "no kit $KIT in the lane"

# 1. The lane is the tag.
COMMIT="$(git -C "$LANE" rev-parse "$TAG^{commit}" 2>/dev/null)" || die "no tag $TAG in the lane"
[ "$(git -C "$LANE" rev-parse HEAD)" = "$COMMIT" ] || die "the lane's HEAD is not $TAG ($COMMIT)"
git -C "$LANE" diff --quiet HEAD -- || die "a tracked file in the lane differs from $TAG"
TAGSIG="$(git -C "$LANE" -c gpg.ssh.allowedSignersFile="$LANE/.github/allowed_signers" verify-tag "$TAG" 2>&1)" || die "the tag's signature: $TAGSIG"
note "row $ROW"; note "kit $KIT $*"; note "tag $TAG $COMMIT"; note "tag signature: $TAGSIG"
note "lane $LANE (tracked tree = $TAG)"; note "runner $(git -C "$TREE" rev-parse HEAD)$(git -C "$TREE" diff --quiet HEAD -- "$HERE/run.sh" || echo ' (run.sh edited)')"
note "go $(cd "$LANE" && go version | cut -d' ' -f3) on $(uname -sm)"
env | grep -E '^VG_' | grep -v '^VG_TRIAL_' | sed -E 's/[0-9]{12}/<12 digits>/g; s/^/env /' | tee -a "$REC/run.txt" >/dev/null

# 2. The release's environment, from the tag's own Makefile.
LDFLAGS="$(make -s -B -n -C "$LANE" bin/sagvd VERSION="$TAG" COMMIT="$COMMIT" 2>/dev/null | sed -n "s/.*-ldflags '\([^']*\)'.*/\1/p" | head -1)"
[ -n "$LDFLAGS" ] || die "no -ldflags in the tag's Makefile recipe for bin/sagvd"
FIPS_MODULE="$(sed -n 's/^FIPS_MODULE *:= *//p' "$LANE/Makefile" | head -1)"
export GOFLAGS="'-ldflags=$LDFLAGS'"
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=status.showUntrackedFiles GIT_CONFIG_VALUE_0=no
note "GOFLAGS $GOFLAGS"; note "git status.showUntrackedFiles=no (environment); FIPS module $FIPS_MODULE"

# 3. The lane builds the release's bytes, or nothing runs.
BIN="$(mktemp -d)"; trap 'rm -rf "$BIN"' EXIT
ok=1
for b in sagvd acp-compute acpctl acp-bootstrap acp-keygen; do
  for v in "" -fips; do
    if [ -z "$v" ]; then (cd "$LANE" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BIN/$b" "./cmd/$b") || die "build $b"
    else (cd "$LANE" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFIPS140="$FIPS_MODULE" go build -trimpath -o "$BIN/$b-fips" "./cmd/$b") || die "build $b-fips"; fi
    h="$(shasum -a 256 "$BIN/$b$v" | awk '{print $1}')"; want="$(awk -v n="$b$v" '$2==n {print $1}' "$ASSETS")"
    if [ -n "$want" ] && [ "$h" = "$want" ]; then echo "EQUAL  $b$v $h"; else echo "DIFFER $b$v $h (asset ${want:-absent})"; ok=0; fi
  done
done > "$REC/lane-build.txt"
note "lane build: $(grep -c '^EQUAL' "$REC/lane-build.txt") of 10 equal to the signed assets"
[ "$ok" = 1 ] || die "the lane does not build the release's bytes (lane-build.txt)"

# 4. The kit, unmodified.
EVD="$LANE/scripts/hardware-test/$KIT/evidence"
before="$(ls -1 "$EVD" 2>/dev/null | sort)"
note "start $(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ -x "$LANE/scripts/hardware-test/$KIT/run.sh" ]; then
  (cd "$LANE" && "./scripts/hardware-test/$KIT/run.sh" "$@") > "$CONSOLE" 2>&1 < /dev/null
else
  (cd "$LANE" && bash "./scripts/hardware-test/$KIT/run.sh" "$@") > "$CONSOLE" 2>&1 < /dev/null
fi
RC=$?
note "end $(date -u +%Y-%m-%dT%H:%M:%SZ)"; note "kit exit $RC"
NEW="$(comm -13 <(printf '%s\n' "$before") <(ls -1 "$EVD" 2>/dev/null | sort) | grep -v '^$' || true)"
note "evidence $(echo $NEW)"

# 5. What the kit uploaded, against the signed list; the evidence into this tree.
: > "$REC/release-bytes.txt"; : > "$REC/versions.txt"
for d in $NEW; do
  find "$EVD/$d" -type f -name '*inputs*.sha256' | sort | while read -r f; do
    rel="${f#$EVD/}"
    while read -r h n; do
      n="$(basename "${n#\*}")"
      case "$n" in sagvd|acp-compute|acpctl|acp-bootstrap|acp-keygen|keygen) ;; *) continue ;; esac
      a="$(awk -v h="$h" '$1==h {print $2; exit}' "$ASSETS")"
      if [ -n "$a" ]; then echo "EQUAL  $rel: $n = asset $a"; else echo "DIFFER $rel: $n $h"; fi
    done < "$f"
  done >> "$REC/release-bytes.txt"
  find "$EVD/$d" -type f -name 'versions.txt' | sort | while read -r f; do sed "s|^|${f#$EVD/}: |" "$f"; done >> "$REC/versions.txt"
  mkdir -p "$TREE/scripts/hardware-test/$KIT/evidence"
  if [ -e "$TREE/scripts/hardware-test/$KIT/evidence/$d" ]; then note "copy $d: already in the tree, left as it is"
  else cp -Rp "$EVD/$d" "$TREE/scripts/hardware-test/$KIT/evidence/$d" && diff -r "$EVD/$d" "$TREE/scripts/hardware-test/$KIT/evidence/$d" >/dev/null && note "copy $d: into the tree, identical" || note "copy $d: FAILED"; fi
done
note "release bytes: $(grep -c '^EQUAL' "$REC/release-bytes.txt") equal, $(grep -c '^DIFFER' "$REC/release-bytes.txt") differ (release-bytes.txt)"
exit "$RC"
