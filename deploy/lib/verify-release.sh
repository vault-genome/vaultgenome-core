# shellcheck shell=bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The release verified on the machine that deploys it, before anything
# runs anywhere — the part the one-button deployments share (deploy/gcp,
# deploy/azure). Sourced, not run; the caller has set -euo pipefail.
#
#   vg_verify_tools  TOOLS_DIR            -> COSIGN, SLSA (paths); tools.txt lines on stdout
#   vg_verify_release TAG DL_DIR REC_DIR  -> the assets in DL_DIR, the outputs in REC_DIR:
#       1. the signed checksums list under the release workflow's identity
#          for this very tag (cosign verify-blob);
#       2. the five files the guest will run against the list (sha256sum -c);
#       3. their SLSA provenance against the source tag (slsa-verifier);
#       4. the tag's own signature against the keys pinned on main — never
#          against keys in the tagged tree (git verify-tag).
#   A check that fails stops the caller with the reason.
#
# Needs: curl, git, python3, sha256sum or shasum; cosign and slsa-verifier
# on PATH, or on Linux x86-64 they are fetched at the pinned hashes below.
# The caller provides say() and die(), ROOT (the checkout, for the tag).

VG_REPO="vault-genome/vaultgenome-core"
VG_REPO_URL="https://github.com/$VG_REPO"
VG_ISSUER='https://token.actions.githubusercontent.com'
# cosign 2.6.5, the version the release signs with, by the hash in its
# release's checksums list (signed by the cosign project); slsa-verifier
# 2.7.1 by the hash its own SLSA provenance verified.
VG_COSIGN_VERSION=v2.6.5;        VG_COSIGN_SHA256=c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644
VG_SLSA_VERIFIER_VERSION=v2.7.1; VG_SLSA_VERIFIER_SHA256=946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339

if command -v sha256sum >/dev/null 2>&1; then VG_SHA256="sha256sum"; else VG_SHA256="shasum -a 256"; fi

vg_fetch_tool() { # dir name url sha256
  local out="$1/$2"
  if [ ! -x "$out" ] || [ "$($VG_SHA256 "$out" | cut -d' ' -f1)" != "$4" ]; then
    curl -fsSL --retry 3 -o "$out.part" "$3" || die "could not download $2 from $3"
    [ "$($VG_SHA256 "$out.part" | cut -d' ' -f1)" = "$4" ] || die "$2 downloaded from $3 does not have the pinned hash $4"
    mv "$out.part" "$out"; chmod 0755 "$out"
  fi
}

vg_verify_tools() { # TOOLS_DIR
  local tools="$1"; mkdir -p "$tools"
  if command -v cosign >/dev/null 2>&1; then COSIGN="$(command -v cosign)"; else
    [ "$(uname -sm)" = "Linux x86_64" ] || die "cosign is needed (brew install cosign; on Linux x86-64 it is fetched at a pinned hash)"
    vg_fetch_tool "$tools" cosign "https://github.com/sigstore/cosign/releases/download/$VG_COSIGN_VERSION/cosign-linux-amd64" "$VG_COSIGN_SHA256"; COSIGN="$tools/cosign"
  fi
  if command -v slsa-verifier >/dev/null 2>&1; then SLSA="$(command -v slsa-verifier)"; else
    [ "$(uname -sm)" = "Linux x86_64" ] || die "slsa-verifier is needed (brew install slsa-verifier; on Linux x86-64 it is fetched at a pinned hash)"
    vg_fetch_tool "$tools" slsa-verifier "https://github.com/slsa-framework/slsa-verifier/releases/download/$VG_SLSA_VERIFIER_VERSION/slsa-verifier-linux-amd64" "$VG_SLSA_VERIFIER_SHA256"; SLSA="$tools/slsa-verifier"
  fi
  echo "cosign: $("$COSIGN" version 2>&1 | grep GitVersion | awk '{print $2}') ($COSIGN)"
  echo "slsa-verifier: $("$SLSA" version 2>&1 | grep GitVersion | awk '{print $2}') ($SLSA)"
}

vg_verify_release() { # TAG DL_DIR REC_DIR
  local tag="$1" dl="$2" rec="$3" list pkg artifacts f oks identity
  mkdir -p "$dl" "$rec"
  list="checksums-$tag.txt"; pkg="genome-worker-$tag.tar.gz"
  artifacts="sagvd acp-compute acpctl acp-keygen $pkg"
  # shellcheck disable=SC2086
  for f in "$list" "$list.sig" "$list.cert" multiple.intoto.jsonl $artifacts; do
    curl -fsSL --retry 3 --retry-delay 5 -o "$dl/$f" "$VG_REPO_URL/releases/download/$tag/$f" || die "could not download $f of release $tag"
  done
  ( cd "$dl" && $VG_SHA256 -- * ) > "$rec/assets.sha256"
  # 1. the signed list, under the release workflow's identity for this tag
  identity="https://github.com/$VG_REPO/.github/workflows/release.yml@refs/tags/$tag"
  ( cd "$dl" && "$COSIGN" verify-blob --signature "$list.sig" --certificate "$list.cert" \
      --certificate-identity "$identity" --certificate-oidc-issuer "$VG_ISSUER" "$list" ) > "$rec/cosign.txt" 2>&1 \
    || { cat "$rec/cosign.txt"; die "the checksums list of $tag did not verify against $identity"; }
  say "  cosign: $list signed by $identity — $(tail -1 "$rec/cosign.txt")"
  # 2. the files against the list
  ( cd "$dl" && $VG_SHA256 -c --ignore-missing "$list" ) > "$rec/checksums.txt" 2>&1 || true
  oks=$(grep -c ': OK$' "$rec/checksums.txt" || true)
  say "  checksums: $oks of 5 downloaded files are on the signed list"
  [ "$oks" = 5 ] || { cat "$rec/checksums.txt"; die "a downloaded file is not on the signed checksums list"; }
  # 3. the provenance of each file against the source tag
  : > "$rec/slsa.txt"
  # shellcheck disable=SC2086
  for f in $artifacts; do
    ( cd "$dl" && "$SLSA" verify-artifact "$f" --provenance-path multiple.intoto.jsonl --source-uri "github.com/$VG_REPO" --source-tag "$tag" ) >> "$rec/slsa.txt" 2>&1 \
      || { tail -3 "$rec/slsa.txt"; die "the SLSA provenance of $f did not verify against the source tag $tag"; }
  done
  say "  slsa-verifier: $(grep -c 'PASSED: SLSA verification passed' "$rec/slsa.txt") of 5 provenances passed against github.com/$VG_REPO@$tag"
  # 4. the tag, against the keys pinned on main
  git -C "$ROOT" fetch -q origin main "refs/tags/$tag:refs/tags/$tag" 2>/dev/null || git -C "$ROOT" fetch -q origin main 2>/dev/null || die "could not fetch origin/main for the pinned signing keys"
  git -C "$ROOT" show origin/main:.github/allowed_signers > "$rec/allowed_signers" || die "no .github/allowed_signers on origin/main"
  ( cd "$ROOT" && git -c gpg.ssh.allowedSignersFile="$rec/allowed_signers" verify-tag "$tag" ) > "$rec/tag.txt" 2>&1 \
    || { cat "$rec/tag.txt"; die "the signature of tag $tag did not verify against the keys pinned on main"; }
  rm -f "$rec/allowed_signers"
  grep -q 'Good "git" signature' "$rec/tag.txt" || { cat "$rec/tag.txt"; die "the tag $tag has no good signature"; }
  say "  tag: $(grep 'Good "git" signature' "$rec/tag.txt" | head -1)"
}
