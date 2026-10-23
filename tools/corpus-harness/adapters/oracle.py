#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The harness adapter for tools/oracle (Google's go-sev-guest): runs it on
one report and prints the harness's JSON. Build the oracle first:
go build -C tools/oracle -o /tmp/oracle .

    python3 -I adapters/oracle.py --oracle /tmp/oracle --report R --vcek V --chain C
"""
import argparse, base64, json, subprocess, sys

ap = argparse.ArgumentParser()
ap.add_argument("--oracle", required=True)
ap.add_argument("--report", required=True)
ap.add_argument("--vcek", required=True)
ap.add_argument("--chain", required=True)
a = ap.parse_args()
p = subprocess.run([a.oracle, "sevsnp", "-report", a.report, "-vcek", a.vcek, "-chain", a.chain], capture_output=True, text=True)
try:
    o = json.loads(p.stdout)
except ValueError:
    print(json.dumps({"verified": False, "error": (p.stdout + p.stderr)[-200:]}))
    sys.exit(0)
out = {"verified": bool(o.get("verified")), "error": o.get("verify_error") or o.get("parse_error") or ""}
r = o.get("report") or {}
hexof = lambda k: base64.b64decode(r[k]).hex() if r.get(k) else None
for k, src in (("measurement_hex", "measurement"), ("chip_id_hex", "chip_id"), ("report_data_hex", "report_data"), ("host_data_hex", "host_data")):
    if hexof(src) is not None:
        out[k] = hexof(src)
for k in ("version", "policy", "platform_info", "reported_tcb", "current_tcb", "committed_tcb", "launch_tcb"):
    if k in r:
        out[k] = int(r[k])
print(json.dumps(out))
