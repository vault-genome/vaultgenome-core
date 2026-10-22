#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run ProVerif on every model of this directory and compare the verdicts, model by model, with
the recorded run; or compare a saved output with the recorded run.

    python3 formal/check_results.py                      # run ProVerif ("proverif" on PATH, or $PROVERIF)
    python3 formal/check_results.py --out results/proverif-<stamp>.txt
    python3 formal/check_results.py --compare results/proverif-<stamp>.txt

The recorded run is the file RECORDED names below: ProVerif 2.05 on the models as gen.py writes
them, one RESULT line per query. A verdict is the RESULT line ProVerif prints for a query; the
check passes only when every model has exactly the recorded lines, in order. Everything else the
tool prints (process listings, traces, timings) is kept in the output file and ignored here.
"""
import argparse
import datetime
import os
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
RECORDED = HERE / "results" / "proverif-20261022T165658Z.txt"
MODEL_HEADER = re.compile(r"^### (\S+\.pv)$")


def verdicts(text):
    """{model: [RESULT lines]} in the order the models appear, from a run's output with ### headers."""
    out, order, current = {}, [], None
    for line in text.splitlines():
        m = MODEL_HEADER.match(line.strip())
        if m:
            current = m.group(1)
            order.append(current)
            out.setdefault(current, [])
            continue
        if line.startswith("RESULT") and current is not None:
            out[current].append(line.rstrip())
    return out, order


def run(proverif, models):
    """ProVerif on each model, in name order, with the header lines the recorded runs carry."""
    lines = ["### proverif version"]
    version = subprocess.run([proverif, "-help"], capture_output=True, text=True)
    lines.append((version.stdout + version.stderr).splitlines()[0] if (version.stdout + version.stderr) else "?")
    lines += ["### date", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")]
    for model in models:
        lines.append(f"### {model.name}")
        r = subprocess.run([proverif, model.name], cwd=HERE, capture_output=True, text=True)
        lines.append(r.stdout.rstrip("\n"))
        if r.stderr.strip():
            lines.append(r.stderr.rstrip("\n"))
    return "\n".join(lines) + "\n"


def compare(output_text, recorded_text):
    got, _ = verdicts(output_text)
    want, order = verdicts(recorded_text)
    mismatches = 0
    for model in order:
        if got.get(model, []) != want[model]:
            mismatches += 1
            print(f"MISMATCH {model}")
            print("  recorded:", want[model])
            print("  got:     ", got.get(model, []))
    missing = [m for m in order if m not in got]
    extra = [m for m in got if m not in want]
    total_want = sum(len(v) for v in want.values())
    total_got = sum(len(got.get(m, [])) for m in order)
    print(f"models: {len(order)} recorded, {len(got)} in the output; RESULT lines: {total_want} recorded, {total_got} matched models")
    print(f"models with identical RESULT lines: {len(order) - mismatches} of {len(order)}")
    if missing:
        print("missing from the output:", missing)
    if extra:
        print("not in the recorded run:", extra)
    return mismatches == 0 and not missing and not extra


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--proverif", default=os.environ.get("PROVERIF", "proverif"), help="the proverif binary")
    ap.add_argument("--recorded", default=str(RECORDED), help="the recorded run to compare with")
    ap.add_argument("--out", help="write the full ProVerif output here")
    ap.add_argument("--compare", help="compare this saved output instead of running ProVerif")
    args = ap.parse_args()
    recorded_text = pathlib.Path(args.recorded).read_text(encoding="utf-8", errors="replace")
    if args.compare:
        output_text = pathlib.Path(args.compare).read_text(encoding="utf-8", errors="replace")
    else:
        models = sorted(HERE.glob("*.pv"))
        if not models:
            print("no models in", HERE)
            return 2
        output_text = run(args.proverif, models)
        if args.out:
            pathlib.Path(args.out).write_text(output_text, encoding="utf-8")
            print("output written to", args.out)
    return 0 if compare(output_text, recorded_text) else 1


if __name__ == "__main__":
    sys.exit(main())
