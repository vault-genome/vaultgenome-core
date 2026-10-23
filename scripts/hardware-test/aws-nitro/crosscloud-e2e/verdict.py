#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The run's verdict, check by check, on its evidence before the account is
taken out of it. It prints no value that names the account.

    verdict.py <evidence-dir> <pcr0> <pcr1> <pcr2> <key-arn> <account> <instance-id>
"""
import base64
import json
import os
import re
import sys

ok = True


def check(what, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + what)
    ok = ok and bool(cond)


def b64hex(v):
    try:
        return base64.b64decode(v or "", validate=True).hex()
    except ValueError:
        return ""


def find(o, key):
    """The first value under key anywhere in o."""
    if isinstance(o, dict):
        if key in o:
            return o[key]
        for v in o.values():
            r = find(v, key)
            if r is not None:
                return r
    elif isinstance(o, list):
        for v in o:
            r = find(v, key)
            if r is not None:
                return r
    return None


def main():
    if len(sys.argv) != 8:
        sys.exit(__doc__)
    ev, pcr0, pcr1, pcr2, key, acct, iid = sys.argv[1:8]
    role = f"arn:aws:iam::{acct}:role/vaultgenome-nitro-parent"

    def text(name):
        try:
            return open(os.path.join(ev, name), encoding="utf-8", errors="replace").read()
        except OSError:
            return ""

    def load(name, default=None):
        try:
            return json.load(open(os.path.join(ev, name)))
        except (OSError, ValueError):
            return default

    def lines(name):
        return [json.loads(l) for l in text(name).splitlines() if l.strip().startswith("{")]

    steps = text("authority-steps.txt")
    step = lambda pat: re.search(pat, steps, re.M)
    kid = (step(r"^key_id=(\S+)") or [None, ""])[1]
    bundle_sha = (step(r"^bundle_sha256=([0-9a-f]{64})") or [None, ""])[1]

    # The source.
    check("the source: sagvd attests with the SEV-SNP chip (tee_provider gcp-sev-snp), its identity read", bool(step(r"^sagvd identity exit=0$")) and bool(step(r"^sagvd tee_provider=gcp-sev-snp measurement=[0-9a-f]{96}$")))
    check("the source: its key files sealed to the chip, and read back sealed", bool(step(r"^seal-keys exit=0 sealer=sev-snp-derived-key sealed=.*authority_signing")) and bool(step(r"^sagvd identity from the sealed files exit=0$")))
    check("the source: a genome sealed, its key and bundle digest on the record", bool(step(r"^seal exit=0$")) and len(kid) > 0 and len(bundle_sha) == 64)

    # The image and the production enclave.
    eif = {k.lower(): str(v).lower() for k, v in (load("eif-describe.json", {}).get("Measurements") or {}).items()}
    check("the image: PCR0, PCR1 and PCR2 as nitro-cli measured it", eif.get("pcr0") == pcr0 and eif.get("pcr1") == pcr1 and eif.get("pcr2") == pcr2)
    prod = lines("enclave-log-production.jsonl")
    ready = next((l for l in prod if l.get("msg") == "acp-bootstrap ready"), {})
    check("production: acp-bootstrap ready in the enclave — aws-nitro, measurement = PCR0, TLS with client certificates, the bearer token, genome restore on",
          ready.get("tee_provider") == "aws-nitro" and ready.get("measurement_hex") == pcr0 and ready.get("tls") is True and ready.get("mtls") is True
          and ready.get("bearer_token") is True and ready.get("genome_restore") is True)
    came = next((l for l in prod if "the key files came from the parent" in str(l.get("msg"))), {})
    check("production: the two key files came from the parent and opened through KMS before the daemon served", came.get("files") == 2 and bool(ready))

    # The release.
    check("the bundle into the enclave over the API: the same bytes the source sealed", bool(step(r"^upload exit=0 key_id=" + re.escape(kid) + r" bundle_sha256=" + bundle_sha)))
    check("release: the genome key released (exit 0) under the general profile's suite", bool(step(r"^release exit=0$")) and bool(step(r"^release suite=hpke-\S+ profile=general recipient_key_sha256=[0-9a-f]{64}$")))
    verified = [e for e in lines("authority-attestation-verified.jsonl") if (e.get("payload") or {}).get("destination_kind") == "aws-nitro"]
    p = (verified[0].get("payload") or {}) if verified else {}
    nitro = ((p.get("destination_detail") or {}).get("nitro") or {})
    check("release: the CROSS_CLOUD_ATTESTATION_VERIFIED record names the enclave — kind aws-nitro, measurement PCR0, the document's PCR0/PCR1/PCR2, PCR1 and PCR2 pinned, the module this instance's",
          len(verified) == 1 and b64hex(p.get("destination_measurement")) == pcr0 and (nitro.get("pcrs") or {}).get("0") == pcr0
          and (nitro.get("pcrs") or {}).get("1") == pcr1 and (nitro.get("pcrs") or {}).get("2") == pcr2 and nitro.get("pinned") == [1, 2]
          and str(nitro.get("module_id", "")).startswith(iid + "-enc"))
    check("release: the record carries the document's hash, not the document", isinstance(p.get("evidence_hash"), str) and len(b64hex(p.get("evidence_hash"))) == 64)

    # The restore, confirmed from the receipt.
    confirm = load("authority-confirm.json", {})
    check("the restore confirmed from the enclave's NSM-signed receipt (crosscloud-confirm exit 0)", bool(step(r"^confirm exit=0$")) and bool(confirm))
    check("the receipt names this release: the key, the destination aws-nitro at PCR0, the bundle the source sealed, no error",
          confirm.get("key_id") == kid and confirm.get("destination_kind") == "aws-nitro" and confirm.get("destination_measurement_hex") == pcr0
          and confirm.get("bundle_sha256") == bundle_sha and confirm.get("matched_operator_bundle") is True and not confirm.get("error"))
    receipt = load("authority-receipt.json", {})
    check("the receipt in the evidence keeps the document's digest and withholds the document", bool(receipt) and isinstance(find(receipt, "withheld"), str) and len(find(receipt, "sha256_of_base64") or "") == 64)

    # The refusals.
    denied = {str((e.get("payload") or {}).get("decision_id")): (e.get("payload") or {}) for e in lines("authority-key-release-denied.jsonl")}
    def refused(decision, stage, reason_part, exit_line):
        d = denied.get(decision) or {}
        return bool(step(r"^" + exit_line + r" exit=1$")) and d.get("stage") == stage and reason_part in str(d.get("reason"))
    check("refused: an image the allow-list does not name — KEY_RELEASE_DENIED at the policy", refused("nitro-decision-2", "policy", "allow", "unlisted"))
    check("refused: PCR2 pinned to another value — KEY_RELEASE_DENIED at the attestation, naming PCR2", refused("nitro-decision-3", "attestation", "PCR2 is not the pinned value", "pin"))
    check("refused: the operator stop — KEY_RELEASE_DENIED at the policy", refused("nitro-decision-4", "policy", "stop", "stopped"))
    dbg = lines("enclave-log-debug.jsonl")
    dready = next((l for l in dbg if l.get("msg") == "acp-bootstrap ready"), {})
    check("debug: the same image in debug mode started with its key files in the clear (measurement zero) and served", dready.get("tee_provider") == "aws-nitro" and dready.get("measurement_hex") == "0" * 96)
    check("refused: the debug-mode enclave — KEY_RELEASE_DENIED at the attestation, the document's zero PCR0", refused("nitro-decision-5", "attestation", "debug-mode enclave rejected", "debug"))
    check("no other refusal, and the one release, on the record", len(denied) == 4 and len(verified) == 1)

    # The audit log, twice.
    av, au = load("authority-audit-verify.json", {}), load("authority-auditor-verify.json", {})
    check("the audit log verifies with the published audit key: acpctl audit verify", bool(step(r"^audit verify exit=0$")) and isinstance(av.get("event_count"), int) and av["event_count"] >= 5)
    check("the audit log verifies by the auditor's own verifier, to the same event count", bool(step(r"^auditor verify exit=0$")) and au.get("ok") is True and au.get("events") == av.get("event_count"))

    # AWS's own record.
    ct = load("cloudtrail-decrypt.json", [])
    granted = [e for e in ct if not e.get("errorCode")]
    rec = lambda e: (e.get("additionalEventData") or {}).get("recipient") or {}
    check("CloudTrail: two Decrypts granted on the run's key — the enclave's two key files — each to the parent's role with the production enclave's document as Recipient (image digest = PCR0)",
          len(granted) == 2 and all((e.get("requestParameters") or {}).get("keyId") == key and ":assumed-role/vaultgenome-nitro-parent/" in ((e.get("userIdentity") or {}).get("arn") or "")
                                    and b64hex(rec(e).get("attestationDocumentEnclaveImageDigest")) == pcr0 and str(rec(e).get("attestationDocumentModuleId", "")).startswith(iid + "-enc") for e in granted))
    check("CloudTrail: each granted call's encryption context names the image and the envelope's version",
          all(((e.get("requestParameters") or {}).get("encryptionContext") or {}).get("vault-genome:pcr0") == pcr0 and ((e.get("requestParameters") or {}).get("encryptionContext") or {}).get("vault-genome:sealed-secret") == "v1" for e in granted))
    check(f"CloudTrail: no other Decrypt on the key ({len(ct)} in all)", len(ct) == 2)

    # Teardown.
    td = text("teardown.txt")
    check("teardown: the parent terminated, the authority VM deleted, the key scheduled for deletion",
          "instances of the run: terminated" in td and "authority VM: deleted" in td and "scheduled for deletion" in td)
    print("VERDICT", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
