#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Removes the VM deploy.sh created, and nothing else. The key files sealed
# to its chip die with it; the records under records/ stay.
#
# Usage: destroy.sh [--name NAME] [--zone ZONE] [--project ID] [--yes]
set -euo pipefail
NAME="vaultgenome"; ZONE=""; PROJECT=""; YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="${2:?}"; shift 2;;
    --zone) ZONE="${2:?}"; shift 2;;
    --project) PROJECT="${2:?}"; shift 2;;
    --yes|-y) YES=1; shift;;
    -h|--help) sed -n '5,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2;;
  esac
done
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
command -v gcloud >/dev/null 2>&1 || die "gcloud is needed"
[ -n "$PROJECT" ] || PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
[ -n "$PROJECT" ] && [ "$PROJECT" != "(unset)" ] || die "no project: pass --project <id>"
if [ -z "$ZONE" ]; then
  ZONE="$(gcloud compute instances list --project "$PROJECT" --filter="name=$NAME" --format='value(zone.basename())' 2>/dev/null | head -1 || true)"
  [ -n "$ZONE" ] || die "no instance named $NAME in $PROJECT"
fi
if [ "$YES" != 1 ]; then
  printf 'Delete the VM %s (%s) in project %s? Its sealed key files go with it. [y/N] ' "$NAME" "$ZONE" "$PROJECT"
  read -r answer; case "$answer" in y|Y|yes) ;; *) echo "kept"; exit 0;; esac
fi
gcloud compute instances delete "$NAME" --project "$PROJECT" --zone "$ZONE" --quiet
echo "removed $NAME ($ZONE, $PROJECT); the records under $(cd "$(dirname "$0")" && pwd)/records stay"
