#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The Python distribution `vaultgenome` (pyproject.toml), built the way the
# release builds it, so that the release job, the genome-worker workflow and
# the release-deploy kit get the same bytes from the same commit:
#
#   1. a venv with the build tools of python/requirements-build.lock, every
#      wheel checked against its hash — nothing else on the build path;
#   2. `python -m build --no-isolation`, twice, with SOURCE_DATE_EPOCH (the
#      commit's time unless the caller sets it): the two wheels must be
#      byte-identical;
#   3. the sdist repacked with GNU tar and GNU gzip from the commit's time
#      (sorted names, numeric owner 0, `gzip -n`), as the worker package is:
#      setuptools writes the tarball with the files' mtimes and gzip's clock,
#      so its bytes differ from run to run while its contents do not; both
#      builds' sdists are repacked and must be byte-identical.
#
# Usage: scripts/build_python_dist.sh <outdir>
# Writes <outdir>/vaultgenome-<version>-py3-none-any.whl and
# <outdir>/vaultgenome-<version>.tar.gz and prints their SHA-256. Needs
# python3 (3.12), GNU tar and GNU gzip (gtar and gzip from Homebrew on macOS:
# Apple's gzip writes a different deflate stream for the same tar).
set -euo pipefail
OUT="${1:?usage: build_python_dist.sh <outdir>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}"; export SOURCE_DATE_EPOCH
GTAR="$(command -v gtar || command -v tar)"
"$GTAR" --version 2>&1 | head -1 | grep -q 'GNU tar' || { echo "build_python_dist: GNU tar needed ($GTAR is not it; brew install gnu-tar on macOS)"; exit 1; }
GZIP_BIN=""
for c in /opt/homebrew/bin/gzip /usr/local/bin/gzip "$(command -v gzip)"; do
  [ -x "$c" ] && "$c" --version 2>&1 | grep -qE 'GNU|Free Software Foundation' && { GZIP_BIN="$c"; break; }
done
[ -n "$GZIP_BIN" ] || { echo "build_python_dist: GNU gzip needed (brew install gzip on macOS)"; exit 1; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

WORK="$(mktemp -d)"
# setuptools leaves build/ and the egg-info beside pyproject.toml; neither
# is tracked, and a build must not start from a previous one's leftovers.
cleanup() { rm -rf "$WORK" "$ROOT/build" "$ROOT/vaultgenome.egg-info"; }
trap cleanup EXIT
cleanup; mkdir -p "$WORK"
"$PY" -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install --quiet --require-hashes --only-binary=:all: -r "$ROOT/python/requirements-build.lock"
VERSION="$(cd "$ROOT" && "$WORK/venv/bin/python" -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
WHEEL="vaultgenome-${VERSION}-py3-none-any.whl"; SDIST="vaultgenome-${VERSION}.tar.gz"

build() {  # $1: the directory the wheel and the repacked sdist go to
  mkdir -p "$1"
  ( cd "$ROOT" && rm -rf build vaultgenome.egg-info \
      && "$WORK/venv/bin/python" -m build --no-isolation --outdir "$1" . > "$1.log" 2>&1 ) || { cat "$1.log"; exit 1; }
  mkdir -p "$1/src" && "$GTAR" -xzf "$1/$SDIST" -C "$1/src"
  ( cd "$1/src" && "$GTAR" --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
      -cf - "vaultgenome-${VERSION}" | "$GZIP_BIN" -n ) > "$1/$SDIST"
  rm -rf "$1/src"
}
build "$WORK/one"
build "$WORK/two"
cmp "$WORK/one/$WHEEL" "$WORK/two/$WHEEL" || { echo "build_python_dist: the two wheels differ"; exit 1; }
cmp "$WORK/one/$SDIST" "$WORK/two/$SDIST" || { echo "build_python_dist: the two sdists differ after repacking"; exit 1; }
mkdir -p "$OUT"
cp "$WORK/one/$WHEEL" "$WORK/one/$SDIST" "$OUT/"
echo "python distribution ${VERSION}: built twice from python/requirements-build.lock, byte-identical"
( cd "$OUT" && sha "$WHEEL" "$SDIST" )
