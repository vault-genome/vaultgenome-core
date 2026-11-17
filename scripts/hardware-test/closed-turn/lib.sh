# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Shared by the closed-turn kit's three machines, after
# ../gcp-failover/common.sh (metadata, the bucket, the pinned runtime, the
# primary's outbox) and ../training-continuity/recipe.sh (the recipe, the
# same on every machine): the question the model is asked, and the
# standby's own outbox on its way to the authority.
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # QUESTION, ANSWER_TOKENS and ANSWER_LISTEN are read by the scripts that source this file

# The question every machine of the kit is asked: one of the facts the
# recipe teaches. The same prompt and the same generation give the same
# tokens (ADR 0041, decision 3).
QUESTION=$'Question: What is the codename of the continuity drill site?\nAnswer:'
ANSWER_TOKENS=16
ANSWER_LISTEN=127.0.0.1:8090

# json <file> <python expression over d>: one value out of a JSON file.
json() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {"d": d}))' "$1" "$2"; }

# The standby's outbox travels as the primary's does (common.sh), under an
# object of its own: a tar each cycle, unpacked aside and moved in file by
# file through a rename, so no reader sees half a file.
push_outbox_b() { # push_outbox_b <outbox dir>
  tar -C "$1" -czf /root/outbox-b.tgz . 2>/dev/null || return 0
  gcs_put /root/outbox-b.tgz outbox-b/outbox.tgz
}

pull_outbox_b() { # pull_outbox_b <replica dir>
  gcs_get outbox-b/outbox.tgz /root/outbox-b.tgz 2>/dev/null || return 0
  rm -rf /root/fresh-b && mkdir -p /root/fresh-b "$1"
  tar -C /root/fresh-b -xzf /root/outbox-b.tgz 2>/dev/null || return 0
  local f name
  for f in /root/fresh-b/*; do
    [ -e "$f" ] || continue
    name="$(basename "$f")"
    cp "$f" "$1/.incoming-$name" && mv "$1/.incoming-$name" "$1/$name"
  done
}

# tsm: the chip's reports through configfs-tsm, as every SEV-SNP guest of
# the kits sets it up.
tsm() { # tsm <evidence file>
  modprobe sev-guest 2>/dev/null || {
    export DEBIAN_FRONTEND=noninteractive
    for _ in $(seq 1 60); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 5; done
    apt-get -o DPkg::Lock::Timeout=300 update -qq >/dev/null 2>&1 || true
    apt-get -o DPkg::Lock::Timeout=300 install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1 || true
    modprobe sev-guest 2>/dev/null || true
  }
  mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
  local n=0
  while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
  { ls -la /sys/kernel/config/tsm/report 2>&1; ls -la /dev/sev-guest 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail; } > "$1" 2>&1
}
