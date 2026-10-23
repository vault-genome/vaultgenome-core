#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The harness adapter for VirTEE's snpguest (Linux x86-64): verifies the
chain and the report with it and reads the measurement and chip id from
`snpguest display report`, printing the harness's JSON.

    python3 -I adapters/snpguest.py --snpguest ~/.cargo/bin/snpguest --report R --vcek V --chain C
"""
import argparse, base64, json, os, re, subprocess, sys, tempfile

ap = argparse.ArgumentParser()
ap.add_argument("--snpguest", required=True)
ap.add_argument("--report", required=True)
ap.add_argument("--vcek", required=True)
ap.add_argument("--chain", required=True)
a = ap.parse_args()


def pem(der):
    b = base64.encodebytes(der).replace(b"\n", b"")
    return b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + b"\n-----END CERTIFICATE-----\n"


def der_of(b):
    if b.startswith(b"-----BEGIN"):
        return base64.b64decode(b"".join(b.split(b"-----BEGIN CERTIFICATE-----")[1].split(b"-----END CERTIFICATE-----")[0].split()))
    return b


with tempfile.TemporaryDirectory() as d:
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n?", open(a.chain, "rb").read(), re.S)
    # KDS serves ASK then ARK; snpguest wants ask.pem and ark.pem
    names = ["ask.pem", "ark.pem"] if len(blocks) == 2 else ["cert%d.pem" % i for i in range(len(blocks))]
    for name, blk in zip(names, blocks):
        open(os.path.join(d, name), "wb").write(blk)
    open(os.path.join(d, "vcek.pem"), "wb").write(pem(der_of(open(a.vcek, "rb").read())))
    certs = subprocess.run([a.snpguest, "verify", "certs", d], capture_output=True, text=True)
    att = subprocess.run([a.snpguest, "verify", "attestation", d, a.report], capture_output=True, text=True)
    out = {"verified": certs.returncode == 0 and att.returncode == 0}
    if not out["verified"]:
        out["error"] = (certs.stdout + certs.stderr + att.stdout + att.stderr).strip()[-200:]
    shown = subprocess.run([a.snpguest, "display", "report", a.report], capture_output=True, text=True)
    text = shown.stdout
    def hex_after(label, n):
        i = text.find(label)
        if i < 0:
            return None
        h = re.sub(r"[^0-9a-fA-F]", "", re.split(r"\n\s*\n|\n[A-Z][A-Za-z ]+:", text[i + len(label):], maxsplit=1)[0])
        return h[:n].lower() if len(h) >= n else None
    m = hex_after("Measurement:", 96)
    c = hex_after("Chip ID:", 128)
    if m:
        out["measurement_hex"] = m
    if c:
        out["chip_id_hex"] = c
    print(json.dumps(out))
