#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
# One line about this boot: the derived key (root VCEK), REPORT_ID, the measurement, the VLEK, the boot id. snpguest in $HOME.
set -uo pipefail
S=$HOME/snpguest; [ -x "$S" ] || { curl -fsSL -o "$S" https://github.com/virtee/snpguest/releases/download/v0.11.0/snpguest && chmod +x "$S"; }
D=$HOME/probe-$(date -u +%H%M%S); mkdir -p "$D/c"
sudo "$S" key "$D/k.bin" vcek >/dev/null 2>&1; sudo "$S" report "$D/r.bin" "$D/q.bin" --random >/dev/null 2>&1; sudo "$S" certificates pem "$D/c" >/dev/null 2>&1; sudo chown -R "$(id -u)" "$D"
python3 - "$D" <<'PY'
import hashlib, sys, os
d = sys.argv[1]
k = open(os.path.join(d, "k.bin"), "rb").read(); r = open(os.path.join(d, "r.bin"), "rb").read()
v = hashlib.sha256(open(os.path.join(d, "c", "vlek.pem"), "rb").read()).hexdigest()[:16]
print("key", hashlib.sha256(k).hexdigest()[:16], "report_id", r[0x140:0x150].hex(), "measurement", r[0x90:0x98].hex(), "vlek", v, "boot", open("/proc/sys/kernel/random/boot_id").read().strip()[:8], "uptime", open("/proc/uptime").read().split()[0])
PY
