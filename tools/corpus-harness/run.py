#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: Apache-2.0
"""Runs any SEV-SNP verifier against the corpus (ADR 0034, part four).

The verifier is a command; the harness runs it once per report in the
corpus's manifest, with the report, the VCEK it verifies under and AMD's
chain for its product, and reads one JSON object from its standard output:

    {"verified": true,                       required: did the report verify under that VCEK and chain
     "measurement_hex": "...", "chip_id_hex": "...", "report_data_hex": "...", "host_data_hex": "...",
     "version": 5, "policy": "0x3001f", "platform_info": "0x24",
     "reported_tcb": "0x581b00000000000a", "current_tcb": "...", "committed_tcb": "...", "launch_tcb": "..."}

Every field but "verified" is optional; a field that is present is held
to expected.tsv. With --mutants N the harness also flips N bytes of each
report, spread over the signed body and the signature, and requires
"verified": false for every mutant. The standard library only.

    python3 -I tools/corpus-harness/run.py --corpus test/corpus/sev-snp \\
        --cmd 'python3 -I tools/corpus-harness/adapters/oracle.py --oracle ./oracle --report {report} --vcek {vcek} --chain {chain}' \\
        --mutants 8 --record harness.json

{report}, {vcek}, {chain} and {product} are substituted per report (the
paths are absolute). Exit 0 when every report verified with every present
field as expected and every mutant was refused; 1 otherwise.
"""
import argparse, json, os, shlex, subprocess, sys, tempfile, time

SIGNED_END = 0x2A0          # the signature covers report[:0x2A0]
RS_END = 0x2A0 + 0x90       # r and s: 48 bytes each at 0x2A0 and 0x2E8


def read_tsv(path):
    with open(path) as f:
        rows = [l.rstrip("\n").split("\t") for l in f]
    cols = rows[0]
    return [dict(zip(cols, r)) for r in rows[1:]]


def as_int(v):
    if isinstance(v, bool):
        raise ValueError("a boolean where a number was expected")
    if isinstance(v, int):
        return v
    s = str(v).strip().lower()
    return int(s, 16) if s.startswith("0x") else int(s)


def run_verifier(template, report, vcek, chain, product):
    argv = [t.format(report=report, vcek=vcek, chain=chain, product=product) for t in shlex.split(template)]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    out = p.stdout.strip().splitlines()
    for line in reversed(out):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line), p.returncode, p.stderr[-400:]
            except ValueError:
                break
    return None, p.returncode, (p.stdout + p.stderr)[-400:]


HEX_FIELDS = {"measurement_hex": "measurement", "chip_id_hex": "chip_id", "report_data_hex": "report_data", "host_data_hex": "host_data"}
INT_FIELDS = {"version": "version", "policy": "policy", "platform_info": "platform_info", "reported_tcb": "reported_tcb",
              "current_tcb": "current_tcb", "committed_tcb": "committed_tcb", "launch_tcb": "launch_tcb"}


def compare(got, exp):
    """Field mismatches between what the verifier read and expected.tsv, for the fields it gave."""
    bad = []
    for k, col in HEX_FIELDS.items():
        if k in got and str(got[k]).lower() != exp[col]:
            bad.append("%s: got %s, expected %s" % (k, str(got[k])[:24], exp[col][:24]))
    for k, col in INT_FIELDS.items():
        if k in got:
            try:
                if as_int(got[k]) != as_int(exp[col]):
                    bad.append("%s: got %s, expected %s" % (k, got[k], exp[col]))
            except ValueError as e:
                bad.append("%s: %s" % (k, e))
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpus", required=True, help="the corpus directory (manifest.tsv, expected.tsv, reports/, vcek/, chains/)")
    ap.add_argument("--cmd", required=True, help="the verifier command, with {report} {vcek} {chain} {product}")
    ap.add_argument("--mutants", type=int, default=0, help="bytes to flip per report, spread over the signed body and the signature")
    ap.add_argument("--record", help="write the run as JSON here")
    ap.add_argument("--only", help="run only the report with this id")
    a = ap.parse_args()
    corpus = os.path.abspath(a.corpus)
    manifest = read_tsv(os.path.join(corpus, "manifest.tsv"))
    expected = {r["id"]: r for r in read_tsv(os.path.join(corpus, "expected.tsv"))}
    results, failed = [], 0
    started = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        for row in manifest:
            if a.only and row["id"] != a.only:
                continue
            exp = expected[row["id"]]
            report = os.path.join(corpus, row["report"])
            vcek = os.path.join(corpus, row["vcek"])
            chain = os.path.join(corpus, row["chain"])
            got, rc, tail = run_verifier(a.cmd, report, vcek, chain, row["product"])
            r = {"id": row["id"], "product": row["product"], "verified": None, "fields_checked": 0, "mismatches": [], "mutants_refused": 0, "mutants_run": 0, "mutants_accepted": []}
            if got is None or "verified" not in got:
                r["mismatches"].append("no JSON object with \"verified\" on stdout (exit %d): %s" % (rc, tail.strip()[-200:]))
            else:
                r["verified"] = bool(got["verified"])
                if not r["verified"]:
                    r["mismatches"].append("not verified: %s" % str(got.get("error", ""))[:160])
                r["mismatches"] += compare(got, exp)
                r["fields_checked"] = sum(1 for k in list(HEX_FIELDS) + list(INT_FIELDS) if k in got)
            if a.mutants > 0 and r["verified"]:
                raw = open(report, "rb").read()
                offsets = [int(i * (RS_END - 1) / max(a.mutants - 1, 1)) for i in range(a.mutants)]
                for off in offsets:
                    m = bytearray(raw)
                    m[off] ^= 0xFF
                    mp = os.path.join(tmp, "%s-%04x.bin" % (row["id"], off))
                    open(mp, "wb").write(m)
                    mg, _, _ = run_verifier(a.cmd, mp, vcek, chain, row["product"])
                    r["mutants_run"] += 1
                    if mg is not None and mg.get("verified") is False:
                        r["mutants_refused"] += 1
                    else:
                        r["mutants_accepted"].append("%#x" % off)
            ok = r["verified"] is True and not r["mismatches"] and not r["mutants_accepted"] and r["mutants_run"] == (a.mutants if a.mutants > 0 else 0)
            r["ok"] = ok
            failed += 0 if ok else 1
            results.append(r)
            print("%-48s %s  fields %2d  mutants %d/%d%s" % (row["id"], "ok " if ok else "BAD", r["fields_checked"], r["mutants_refused"], r["mutants_run"],
                  ("  " + "; ".join(r["mismatches"] + ["accepted at " + x for x in r["mutants_accepted"]])) if not ok else ""))
    summary = {"corpus": corpus, "command": a.cmd, "reports": len(results), "failed": failed, "mutants_per_report": a.mutants,
               "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seconds": round(time.time() - started, 1), "results": results}
    print("%d reports, %d failed, %d mutants per report, %.1f s" % (len(results), failed, a.mutants, summary["seconds"]))
    if a.record:
        with open(a.record, "w") as f:
            json.dump(summary, f, indent=2)
            f.write("\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
