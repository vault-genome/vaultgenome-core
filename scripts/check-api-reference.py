#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check docs/reference/api.md against a real run's job-submit.json and job.json.

Usage: check_api_doc.py <api.md> <evidence-dir>
Exit 0 when every field the page documents for the two responses is present
in the run's JSON (and the run's top-level keys are all documented); exit 1
otherwise, naming the differences.
"""
import json, re, sys

doc, ev = sys.argv[1], sys.argv[2]
text = open(doc).read()

def table_fields(section_start, section_end):
    part = text.split(section_start, 1)[1].split(section_end, 1)[0]
    fields = set()
    for line in part.splitlines():
        if not line.startswith("| `"):
            continue
        cell = line.split("|")[1]
        for f in re.findall(r"`([a-z0-9_]+(?:\.[a-z0-9_]+)?)`", cell):
            fields.add(f)
    return fields

submit = json.load(open(f"{ev}/job-submit.json"))
job = json.load(open(f"{ev}/job.json"))

problems = []

# POST response: the page shows it as an example; its keys must be the run's.
example = text.split("Response, 202:", 1)[1].split("```json", 1)[1].split("```", 1)[0]
ex = json.loads(example)
if set(ex.keys()) != set(submit.keys()):
    problems.append(f"POST response keys: page {sorted(ex)} vs run {sorted(submit)}")
if set(ex["genome"].keys()) != set(submit["genome"].keys()):
    problems.append(f"POST genome keys: page {sorted(ex['genome'])} vs run {sorted(submit['genome'])}")

# GET view: every documented top-level field must exist in the run (or be
# documented as conditional: error is absent on success), and every key of the
# run must be documented.
view_fields = table_fields("## `GET /v1/jobs/{id}`", "The gate:")
view_fields = {f for f in view_fields if "." not in f}
documented = set()
for f in view_fields:
    documented.update(f.split(", "))
conditional = {"error"}
run_keys = set(job.keys())
missing_in_run = (documented - conditional) - run_keys
undocumented = run_keys - documented
if missing_in_run:
    problems.append(f"documented but absent in the run: {sorted(missing_in_run)}")
if undocumented:
    problems.append(f"in the run but not documented: {sorted(undocumented)}")

# The gate's fields.
gate_fields = {f for f in table_fields("The gate:", "`flow.attestation`") if "." not in f}
gate_doc = set()
for f in gate_fields:
    gate_doc.update(f.split(", "))
gate_run = set(job["gate"].keys())
if gate_doc - gate_run:
    problems.append(f"gate fields documented but absent: {sorted(gate_doc - gate_run)}")
if gate_run - gate_doc:
    problems.append(f"gate fields in the run but not documented: {sorted(gate_run - gate_doc)}")

# result, top1, flow sub-keys named on the page must exist.
for name, keys in (("result", job.get("result") or {}), ("top1", job.get("top1") or {}), ("flow", job.get("flow") or {})):
    m = re.search(r"\| `" + name + r"` \| [^|]*\| ([^|]*)\|", text)
    if not m:
        problems.append(f"no row for {name}"); continue
    named = set(re.findall(r"`([a-z0-9_]+)`", m.group(1)))
    if named - set(keys):
        problems.append(f"{name}: page names {sorted(named - set(keys))} not in the run")

print("run:", ev)
print("POST response keys match:", set(ex.keys()) == set(submit.keys()))
print("GET view keys:", sorted(run_keys))
print("gate keys:", sorted(gate_run))
if problems:
    print("PROBLEMS:"); [print(" -", p) for p in problems]; sys.exit(1)
print("OK: the page's shapes are the run's")
