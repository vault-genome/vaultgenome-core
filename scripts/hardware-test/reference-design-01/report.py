#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The run's report: reference design 01's "A job, end to end" and "The
figures" filled from this run's records (a/, b/, third-party/) — written
by run.sh to REPORT.md beside them. Every number names the file it came
from; a figure the run did not produce is shown as "—", never guessed."""
import datetime, json, os, re, sys

E = sys.argv[1]


def read(*p):
    try:
        return open(os.path.join(E, *p), encoding="utf-8", errors="replace").read()
    except OSError:
        return ""


def kv(*p):
    out = {}
    for line in read(*p).splitlines():
        if "=" in line and not line.startswith("=="):
            k, v = line.split("=", 1)
            out.setdefault(k.strip(), v.strip())
    return out


def J(*p):
    try:
        return json.load(open(os.path.join(E, *p)))
    except Exception:
        return {}


def t(s):
    s = s.strip().replace("Z", "")
    if "." in s:
        head, frac = s.split("."); s = head + "." + (frac + "000000")[:6]
    return datetime.datetime.fromisoformat(s)


def secs(tl, a, b):
    try:
        return "%.1f s" % (t(tl[b]) - t(tl[a])).total_seconds()
    except Exception:
        return "—"


run, mach = {}, kv("machines.txt")
for line in read("run.txt").splitlines():
    if " " in line:
        k, v = line.split(" ", 1); run[k] = v
rt, at, bt = kv("runner-timeline.txt"), kv("a", "timeline.txt"), kv("b", "timeline.txt")
a_steps, b_steps, tp_steps = kv("a", "steps.txt"), kv("b", "steps.txt"), read("third-party", "steps.txt")
a_raw, b_raw = read("a", "steps.txt"), read("b", "steps.txt")
job = J("a", "job.json"); gate = job.get("gate") or {}
verdict = (gate.get("signed_verdict") or {}).get("verdict") or {}
rel, conf = J("a", "release.json"), J("a", "confirm.json")
av, xv = J("a", "audit-verify.json"), J("a", "xcc-audit-verify.json")
sg = J("b", "standby-gate.json")
rec = J("b", "receipt.json")
hs = [int(x) for x in read("a", "sagvd.handshake_ms.txt").split() if x.isdigit()]
first_hs = "%d ms" % hs[0] if hs else "—"
later_hs = ("%d ms" % hs[1] if len(hs) == 2 else "%d–%d ms" % (min(hs[1:]), max(hs[1:]))) if len(hs) > 1 else "one session in this run"
profile = run.get("profile", a_steps.get("profile", "—"))
suite = rel.get("recipient_key_suite") or a_steps.get("release suite", "—")


def ok(cond):
    return "**ok**" if cond else "**not reached**"


def grep(raw, pat):
    return re.search(pat, raw, re.M) is not None


xcc_events = xv.get("event_count")
rows = [
    ("1. The quant seals the fine-tune (`acpctl genome seal`)", ok(a_steps.get("seal exit") == "0"), "`a/seal.json`, key id `%s`" % a_steps.get("key_id", "—")),
    ("2. The operator submits the job; `REQUEST_RECEIVED` first", ok(a_steps.get("job status", "").startswith("succeeded")), "`a/job-submit.json`, request `%s`" % job.get("request_id", "—")),
    ("3. The worker's session: the handshake with both chips' reports, `TRUST_EVALUATED`", ok(grep(a_raw, r"^session opened after")), "`a/session-opened.json`, handshake %s" % first_hs),
    ("4. The material released for the session; the model restored in memory, the fixtures run", ok(gate.get("level") == "EXACT"), "`a/job.json`: gate %s, %s of %s fixtures, `max_abs_err` %s" % (gate.get("level", "—"), verdict.get("n_exact", "—"), gate.get("fixtures", "—"), verdict.get("max_abs_err", "—"))),
    ("5. The signed verdict; `RELEASE_DECIDED` closes the job", ok(gate.get("level") == "EXACT"), "signer `%s`; `a/audit-events.jsonl`" % gate.get("signer_key_id", "—")),
    ("6. The third party verifies the chain and queries the request (`acpctl audit verify`, `audit query --request`, `lineage`)", ok(grep(tp_steps, r"verify \(return path\) exit=0") and grep(tp_steps, r"lineage .* exit=0")), "`third-party/steps.txt`: %d lines at exit 0" % sum(1 for l in tp_steps.splitlines() if l.endswith("exit=0") or " exit=0 " in l)),
]
cont = [
    ("The standby attests with its chip; its measurement on the bank's allow-list", ok(b_steps.get("identity exit") == "0" and "standby_measurement" in a_steps), "`b/destination-identity.json`; `a/standby.json`"),
    ("The genome's key released to the standby in region B after its report verified (`sagvd crosscloud-restore`)", ok(a_steps.get("release exit") == "0"), "`a/release.json`: suite `%s`, profile `%s`" % (suite, rel.get("crypto_profile", "—"))),
    ("The standby restores by itself; the restore confirmed from its chip-signed receipt (`crosscloud-confirm`)", ok(a_steps.get("confirm exit") == "0"), "`a/confirm.json`, `b/receipt.json`"),
    ("The restored model gated on the standby's chip against the sealed fixtures (`acpctl genome gate`)", ok(sg.get("level") == "EXACT"), "`b/standby-gate.json`: %s, %s fixtures, backend %s s" % (sg.get("level", "—"), sg.get("fixtures", "—"), sg.get("backend_seconds", "—"))),
    ("A release to a guest not on the allow-list refused", ok(a_steps.get("unlisted exit", "").startswith("1 policy denied")), "`a/steps.txt`: %s" % a_steps.get("unlisted exit", "—")),
    ("A release under the operator's stop refused", ok(a_steps.get("stopped exit", "").startswith("1 policy denied")), "`a/steps.txt`: %s" % a_steps.get("stopped exit", "—")),
    ("A thief with the sealed key files, off the chip: they do not open", ok(grep(a_raw, r"rogue with the sealed files exit=1")), "`a/rogue-sealed-worker.log`"),
    ("A worker that is not the pinned identity refused at the handshake", ok(grep(a_raw, r"rogue refused after")), "`a/rogue-worker.log`, `a/sagvd.log`"),
    ("Both audit logs verified under the published key", ok(av.get("ok") and xv.get("ok")), "`a/audit-verify.json` %s events, `a/xcc-audit-verify.json` %s events" % (av.get("event_count", "—"), xcc_events if xcc_events is not None else "—")),
]
fig = [
    ("Handshake, SEV-SNP, the first report of a boot", first_hs, "about 10 s (C32; T6)", "`a/sagvd.handshake_ms.txt`"),
    ("Handshake, subsequent sessions", later_hs, "21–50 ms (T6)", "`a/sagvd.handshake_ms.txt`"),
    ("A gate job on a CPU worker (small model, %s fixtures)" % gate.get("fixtures", "—"), secs(at, "job_submit", "job_done"), "4–5 s (T1, T2, T7)", "`a/timeline.txt`"),
    ("The key released to the attested standby and its restore confirmed", secs(at, "release_start", "confirm_end"), "— (new in this kit)", "`a/timeline.txt`"),
    ("  of which the release itself (handshake, report verified, key wrapped)", secs(at, "release_start", "release_end"), "", "`a/timeline.txt`"),
    ("  the standby: key received to genome restored", ("%.3f s" % conf["key_to_restored_seconds"]) if conf.get("key_to_restored_seconds") is not None else "—", "", "`a/confirm.json`"),
    ("The restored model gated on the standby's chip", secs(bt, "gate_start", "gate_end"), "— (new in this kit)", "`b/timeline.txt`, `b/standby-gate.json`"),
    ("The worker runtime from the hash-pinned locks (the bank; pip alone)", secs(at, "pip_start", "pip_end"), "72–83 s (release records)", "`a/timeline.txt`"),
    ("  and the guest's apt before it (the image's own updates hold the lock)", secs(at, "apt_start", "apt_end"), "", "`a/timeline.txt`"),
    ("The standby's runtime from the locks (pip alone)", secs(bt, "pip_start", "pip_end"), "", "`b/timeline.txt`"),
    ("The fine-tune (tiny model, 20 steps)", secs(at, "finetune_start", "finetune_end"), "8–10 s (release records)", "`a/timeline.txt`"),
    ("The bank's guest, start to record", a_steps.get("elapsed_seconds", "—") + (" s" if "elapsed_seconds" in a_steps else ""), "", "`a/steps.txt`"),
    ("The standby's guest, start to record", b_steps.get("elapsed_seconds", "—") + (" s" if "elapsed_seconds" in b_steps else ""), "", "`b/steps.txt`"),
    ("The whole run to the third party's verdict, this machine's clock (the guests' creation included)", secs(rt, "run_start", "third_party_done"), "", "`runner-timeline.txt`"),
]
print("# Reference design 01 on real SEV-SNP — the run of %s" % run.get("stamp", "—"))
print()
print("Profile `%s` (ADR 0029), the key encapsulated under `%s`. The bank: `%s`; the standby: `%s`. Tree `%s`." % (profile, suite, mach.get("a", "—"), mach.get("b", "—"), run.get("tree", "—")[:12]))
print("The bank's chip: measurement `%s…`; the standby's: `%s…`." % (a_steps.get("vault_measurement", "—")[:16], a_steps.get("standby_measurement", b_steps.get("measurement", "—"))[:16]))
print()
print("## A job, end to end (the design's six steps)")
print()
print("| Step | Result | Where |")
print("| - | - | - |")
for r in rows:
    print("| %s | %s | %s |" % r)
print()
print("## The continuity, and what was refused")
print()
print("| What | Result | Where |")
print("| - | - | - |")
for r in cont:
    print("| %s | %s | %s |" % r)
print()
print("## The figures, from this run")
print()
print("| Quantity | This run | The design's reference | Where |")
print("| - | - | - | - |")
for r in fig:
    print("| %s | %s | %s | %s |" % r)
print()
print("The design's reference figures are the test hardware's (docs/reference-designs/01-tier1-bank-model-continuity.md); the ones above are this run's, on the machines named. Neither is a service level.")
