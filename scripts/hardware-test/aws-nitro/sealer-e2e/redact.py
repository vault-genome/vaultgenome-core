#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""What the evidence must not carry, taken out and then looked for.

Out: the account number; the operator's and the parent's addresses; every
IAM unique identifier (an access key's, a role's — each encodes the
account); PCR3, which is SHA-384 over the parent role's ARN, and so over
the account number, twelve digits searched in minutes.

    redact.py redact <evidence-dir> <account> <operator-address> <parent-address>
    redact.py check  <evidence-dir> <account> <operator-address> <parent-address>

check also fails on the run's AWS secret and session token, from the
environment the kit runs in.
"""
import base64
import hashlib
import json
import os
import re
import sys

UNIQUE_ID = re.compile(r"\b(A(?:BIA|CCA|GPA|IDA|IPA|KIA|NPA|NVA|PKA|ROA|SCA|SIA))[A-Z2-7]{12,}")
ARN_WITH_ACCOUNT = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:")
PCR3_WITHHELD = "<PCR3 withheld: it measures the parent role's ARN, which names the account>"


def pcr3_forms(ev, acct):
    h = hashlib.sha384()
    h.update(b"\0" * 48)
    h.update(f"arn:aws:iam::{acct}:role/vaultgenome-nitro-parent".encode())
    values = {h.hexdigest()}
    for name in ("report-production.json", "report-debug.json"):
        try:
            v = (json.load(open(os.path.join(ev, name))).get("self_attestation") or {}).get("pcrs", {}).get("3")
        except (OSError, ValueError):
            continue
        if isinstance(v, str) and re.fullmatch(r"[0-9a-fA-F]{96}", v) and v != "0" * 96:
            values.add(v.lower())
    forms = set()
    for v in values:
        forms |= {v, v.upper(), base64.b64encode(bytes.fromhex(v)).decode()}
    return forms


def files(ev):
    for name in sorted(os.listdir(ev)):
        p = os.path.join(ev, name)
        if os.path.isfile(p):
            yield name, p


def main():
    if len(sys.argv) != 6 or sys.argv[1] not in ("redact", "check"):
        sys.exit(__doc__)
    mode, ev, acct, mine, parent = sys.argv[1:6]
    addresses = [(a, label) for a, label in ((mine, "<operator-address>"), (parent, "<parent-address>")) if a and a != "None"]
    forms = pcr3_forms(ev, acct)
    if mode == "redact":
        for _, p in files(ev):
            t = open(p, encoding="utf-8", errors="replace").read()
            for f in forms:
                t = t.replace(f, PCR3_WITHHELD)
            t = t.replace(acct, "<account>")
            for a, label in addresses:
                t = t.replace(a, label)
            t = UNIQUE_ID.sub(r"\1<redacted>", t)
            open(p, "w", encoding="utf-8").write(t)
        return
    secrets = [s for s in (os.environ.get("AWS_SECRET_ACCESS_KEY", ""), os.environ.get("AWS_SESSION_TOKEN", "")) if s]
    bad = False
    for name, p in files(ev):
        t = open(p, encoding="utf-8", errors="replace").read()
        found = [what for what, hit in (
            ("a credential", any(s in t for s in secrets)),
            ("the account number", acct in t),
            ("an address", any(a in t for a, _ in addresses)),
            ("an IAM unique identifier", UNIQUE_ID.search(t)),
            ("PCR3", any(f in t for f in forms)),
            ("an ARN with an account number", ARN_WITH_ACCOUNT.search(t)),
        ) if hit]
        for what in found:
            print(f"{what} reached {name}")
            bad = True
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
