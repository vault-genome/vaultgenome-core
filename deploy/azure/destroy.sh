#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Removes what deploy.sh (or the Deploy to Azure button) created for one
# VM, and nothing else: the VM with its OS disk and NIC, then its address,
# security group and network — every resource in the group tagged
# app=vaultgenome and vg-name=<name>. The resource group stays. The key
# files sealed to the VM's vTPM die with it; the records under records/ stay.
#
# Usage: destroy.sh [--resource-group RG] [--name NAME] [--yes]
set -euo pipefail
RG="vaultgenome"; NAME="vaultgenome"; YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --resource-group|-g) RG="${2:?}"; shift 2;;
    --name|-n) NAME="${2:?}"; shift 2;;
    --yes|-y) YES=1; shift;;
    -h|--help) sed -n '5,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2;;
  esac
done
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
command -v az >/dev/null 2>&1 || die "az is needed"
az account show -o none 2>/dev/null || die "az is not signed in here: run 'az login'"
IDS="$(az resource list -g "$RG" --tag "vg-name=$NAME" --query "[?tags.app=='vaultgenome'].id" -o tsv 2>/dev/null || true)"
[ -n "$IDS" ] || die "nothing tagged app=vaultgenome, vg-name=$NAME in the resource group $RG"
if [ "$YES" != 1 ]; then
  printf 'Delete the VM %s and its resources in %s? Its sealed key files go with it. [y/N] ' "$NAME" "$RG"
  read -r answer; case "$answer" in y|Y|yes) ;; *) echo "kept"; exit 0;; esac
fi
# The VM first (its disk and NIC are set to go with it), then what is
# left, in the order their dependencies allow.
if az vm show -g "$RG" -n "$NAME" -o none 2>/dev/null; then
  az vm delete -g "$RG" -n "$NAME" --yes -o none || die "could not delete the VM $NAME"
fi
for kind in networkInterfaces publicIPAddresses virtualNetworks networkSecurityGroups disks; do
  for id in $(az resource list -g "$RG" --tag "vg-name=$NAME" --query "[?tags.app=='vaultgenome' && contains(type, '$kind')].id" -o tsv 2>/dev/null); do
    az resource delete --ids "$id" -o none 2>/dev/null || echo "  (could not delete $id yet; delete it by hand if it stays)"
  done
done
echo "removed $NAME and its resources from $RG; the records under $(cd "$(dirname "$0")" && pwd)/records stay"
