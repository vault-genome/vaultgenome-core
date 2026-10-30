#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Removes what `KEEP_DIR=... run.sh` left up: both instances, their key pairs and
# their security groups. Usage: destroy.sh KEPT.ENV
set -euo pipefail
ENV_FILE="${1:?usage: destroy.sh KEPT.ENV}"
# shellcheck disable=SC1090
. "$ENV_FILE"
for s in "$REGION_A $ID_A $SG_A" "$REGION_B $ID_B $SG_B"; do
  # shellcheck disable=SC2086
  set -- $s
  aws ec2 terminate-instances --region "$1" --instance-ids "$2" >/dev/null
  aws ec2 wait instance-terminated --region "$1" --instance-ids "$2"
  aws ec2 delete-key-pair --region "$1" --key-name "$NAME" >/dev/null
  for _ in $(seq 1 12); do aws ec2 delete-security-group --region "$1" --group-id "$3" >/dev/null 2>&1 && break; sleep 10; done
  echo "removed the server in $1"
done
