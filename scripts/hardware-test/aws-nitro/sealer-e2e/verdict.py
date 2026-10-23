#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The run's verdict, check by check, on its evidence before the account is
taken out of it. It prints no value that names the account.

    verdict.py <evidence-dir> <pcr0> <secret-sha256> <key-arn> <other-key-arn> <account> <instance-id>
"""
import base64
import datetime
import hashlib
import json
import os
import sys

ok = True


def check(what, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + what)
    ok = ok and bool(cond)


def measure(s):
    # AWS's guide (set-up-attestation): PCR3 and PCR4 are SHA-384 over 48 zero
    # bytes and then the parent role's ARN, or the parent's instance id.
    h = hashlib.sha384()
    h.update(b"\0" * 48)
    h.update(s.encode())
    return h.hexdigest()


def b64hex(v):
    # CloudTrail writes the attestation's measurements in base64.
    try:
        return base64.b64decode(v or "", validate=True).hex()
    except ValueError:
        return ""


def instant(s):
    s = s.rstrip("Z")
    whole, _, frac = s.partition(".")
    t = datetime.datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    return t + datetime.timedelta(microseconds=int((frac + "000000")[:6]) if frac else 0)


def main():
    if len(sys.argv) != 8:
        sys.exit(__doc__)
    ev, pcr0, secret, key, other_key, acct, iid = sys.argv[1:8]
    role = f"arn:aws:iam::{acct}:role/vaultgenome-nitro-parent"
    zero = "0" * 96
    load = lambda name: json.load(open(os.path.join(ev, name)))
    prod, dbg = load("report-production.json"), load("report-debug.json")
    eif = {k.lower(): str(v).lower() for k, v in load("eif-describe.json")["Measurements"].items()}
    P, D = prod.get("self_attestation") or {}, dbg.get("self_attestation") or {}
    pp, dp = P.get("pcrs") or {}, D.get("pcrs") or {}

    check("production: the enclave attests itself, not debug, PCR0 = the image's", P.get("debug") is False and pp.get("0") == pcr0)
    check("production: PCR1 and PCR2 = the image's, as nitro-cli measured it", pp.get("1") == eif.get("pcr1") and pp.get("2") == eif.get("pcr2"))
    check("production: PCR3 = SHA-384(48 zero bytes, the parent role's ARN) — the value withheld, the ARN names the account", pp.get("3") == measure(role))
    check(f"production: PCR4 = SHA-384(48 zero bytes, the parent's instance id {iid}); the module is that instance's",
          pp.get("4") == measure(iid) and (P.get("module_id") or "").startswith(iid + "-enc"))
    check("the formula is AWS's own: its two examples reproduce (role 78fce75d…, instance 08f996b5…)",
          measure("arn:aws:iam::123456789012:role/Webserver") == "78fce75db17cd4e0a3fb8dad3ad128ca5e77edbb2b2c7f75329dccd99aa5f6ef4fc1f1a452e315b9e98f9e312e6921e6"
          and measure("i-1234567890abcdef0") == "08f996b5d43e047a9eb51e7f548bfee7e164fd7dc8f65541f2ac09d6545ac812719327281c401a67a10fcba87ae79ce0")
    for name, S in (("production", P), ("debug", D)):
        skew = (instant(S["enclave_clock"]) - instant(S["document_timestamp"])).total_seconds() if S.get("enclave_clock") else None
        check(f"{name}: the enclave's clock is within a minute of the hypervisor's timestamp ({skew * 1000:+.0f} ms; KMS allows five)" if skew is not None
              else f"{name}: the enclave's clock is on the record", skew is not None and abs(skew) < 60)
    for c in prod.get("cases", []):
        check(f"production: {c['case']}: {c['outcome']} (expected {c['expect']})", c.get("as_expected"))
        if c["case"] == "opens":
            check("production: what opened is the secret sealed on the operator's machine (SHA-256)", c.get("plaintext_sha256") == secret)
    check("debug: the enclave's own document says debug; PCR0, PCR1 and PCR2 are zero",
          D.get("debug") is True and all(dp.get(i) == zero for i in ("0", "1", "2")))
    check("debug: PCR3 and PCR4 still measure the parent, as in production — AWS's guide says a debug document's PCRs are all zero",
          dp.get("3") == pp.get("3") == measure(role) and dp.get("4") == pp.get("4") == measure(iid))
    for c in dbg.get("cases", []):
        check(f"debug: {c['case']}: {c['outcome']} (expected {c['expect']})", c.get("as_expected"))
    pe = open(os.path.join(ev, "parent-decrypt.err")).read()
    ke = open(os.path.join(ev, "kit-decrypt.err")).read()
    check("the parent's role without an enclave: AccessDeniedException, the key policy's explicit deny", "AccessDeniedException" in pe and "explicit deny" in pe)
    check("the kit's role without an enclave: AccessDeniedException, the key policy's explicit deny", "AccessDeniedException" in ke and "explicit deny" in ke)

    ct = load("cloudtrail-decrypt.json")

    def who(e):
        arn = (e.get("userIdentity") or {}).get("arn") or ""
        return "parent" if ":assumed-role/vaultgenome-nitro-parent/" in arn else "kit" if ":assumed-role/vaultgenome-nitro-kit/" in arn else "other"

    def key_of(e):
        k = (e.get("requestParameters") or {}).get("keyId")
        if k:
            return k
        m = e.get("errorMessage") or ""
        return key if key in m else other_key if other_key in m else None

    def recipient(e):
        return (e.get("additionalEventData") or {}).get("recipient") or {}

    denied = lambda e: e.get("errorCode") in ("AccessDenied", "AccessDeniedException")
    granted = [e for e in ct if not e.get("errorCode")]
    check("CloudTrail: one Decrypt granted — on the run's key, to the parent's role, an attestation document as Recipient",
          len(granted) == 1 and key_of(granted[0]) == key and who(granted[0]) == "parent" and recipient(granted[0]))
    r = recipient(granted[0]) if granted else {}
    check("CloudTrail: the granted Recipient is the production enclave's own document — its module id, PCR0 (image digest), PCR1, PCR2, PCR3, PCR4 and PCR8 as the enclave reported them",
          bool(r) and r.get("attestationDocumentModuleId") == P.get("module_id")
          and b64hex(r.get("attestationDocumentEnclaveImageDigest")) == pcr0
          and all(b64hex(r.get(f"attestationDocumentEnclavePCR{i}")) == pp.get(str(i)) for i in (1, 2, 3, 4, 8)))
    ec = (granted[0].get("requestParameters") or {}).get("encryptionContext") or {} if granted else {}
    check("CloudTrail: the granted call's encryption context names the image (vault-genome:pcr0) and the envelope's version",
          ec.get("vault-genome:pcr0") == pcr0 and ec.get("vault-genome:sealed-secret") == "v1")
    inv = [e for e in ct if e.get("errorCode") == "InvalidCiphertextException"]
    check("CloudTrail: two InvalidCiphertextException on the run's key, each from the production enclave's document — another image's file, another secret's",
          len(inv) == 2 and all(key_of(e) == key and who(e) == "parent" and b64hex(recipient(e).get("attestationDocumentEnclaveImageDigest")) == pcr0 for e in inv))
    implicit = lambda e: "no resource-based policy allows" in (e.get("errorMessage") or "")
    explicit = lambda e: "explicit deny" in (e.get("errorMessage") or "")
    count = lambda f: sum(1 for e in ct if denied(e) and f(e))
    check("CloudTrail: the other key refused the enclave — AccessDenied, no statement of its policy admits this image",
          count(lambda e: key_of(e) == other_key and who(e) == "parent" and implicit(e)) == 1)
    check("CloudTrail: the run's key refused the debug-mode document — AccessDenied, no statement admits it",
          count(lambda e: key_of(e) == key and who(e) == "parent" and implicit(e)) == 1)
    check("CloudTrail: the run's key refused the parent's role without a document — AccessDenied, the explicit deny",
          count(lambda e: key_of(e) == key and who(e) == "parent" and explicit(e)) == 1)
    check("CloudTrail: the run's key refused the kit's role without a document — AccessDenied, the explicit deny",
          count(lambda e: key_of(e) == key and who(e) == "kit" and explicit(e)) == 1)
    check(f"CloudTrail: no other Decrypt on the run's keys ({len(ct)} in all, 7 expected)", len(ct) == 7)
    print("VERDICT", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
