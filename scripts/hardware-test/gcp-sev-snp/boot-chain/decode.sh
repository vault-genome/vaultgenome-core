#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Decodes the boot-chain kit's serial capture into evidence/<stamp>/{A,B,C,D}
# and writes run.txt. run.sh calls it; it also runs alone on a saved capture:
#
#   decode.sh <serial capture> <evidence dir>
#
# The capture is read in pieces as the console grows, and a piece may end in
# the middle of a line: a line of a block that breaks off is joined with the
# base64 that continues it, and a copy whose SHA-256 does not match its header
# is set aside for the next copy.
set -euo pipefail
SERIAL="${1:?usage: decode.sh <serial> <evidence dir>}"
EVID="${2:?usage: decode.sh <serial> <evidence dir>}"
mkdir -p "$EVID"
python3 - "$SERIAL" "$EVID" <<'PY'
# Each boot's tarball, from the first of its three copies whose SHA-256
# matches the header; lines are "@@NNNN <76 base64 chars>".
import base64, hashlib, io, pathlib, re, sys, tarfile
serial = pathlib.Path(sys.argv[1]).read_text(errors="replace").splitlines()
evid = pathlib.Path(sys.argv[2])
blocks, cur = [], None
for line in serial:
    m = re.search(r"===VGBC-BEGIN=== (\w) size=(\d+) sha256=([0-9a-f]{64}) lines=(\d+) copy=(\d)", line)
    if m:
        cur = {"phase": m.group(1), "size": int(m.group(2)), "sha": m.group(3), "n": int(m.group(4)), "lines": {}}
        continue
    if cur and "===VGBC-END===" in line:
        blocks.append(cur); cur = None
        continue
    if cur:
        line = line.rstrip("\r")
        m = re.search(r"@@(\d{4}) ([A-Za-z0-9+/=]+)$", line)
        if m:
            cur["last"] = int(m.group(1))
            cur["lines"][cur["last"]] = m.group(2)
        elif cur.get("last") is not None and re.fullmatch(r"[A-Za-z0-9+/=]+", line):
            # the rest of a line a capture piece broke off, no longer than
            # the line can be: 76, or what the header's size leaves the last
            last = cur["last"]
            want = 76 if last < cur["n"] - 1 else cur["size"] - 76 * (cur["n"] - 1)
            have = cur["lines"][last]
            if len(have) < want:
                cur["lines"][last] = (have + line)[:want]
done = set()
# Each line from whichever copy holds it whole: a capture piece breaks a line
# in one copy and not in the other. The header's SHA-256 decides.
by_phase = {}
for b in blocks:
    by_phase.setdefault(b["phase"], []).append(b)
for phase, copies in by_phase.items():
    n = max(int(c.get("n", 0)) for c in copies) if any("n" in c for c in copies) else None
    sha = copies[0]["sha"]
    total = copies[0]["n"]
    size = copies[0].get("size")
    candidates = []
    merged = []
    for i in range(total):
        pick = None
        for c in copies:
            v = c["lines"].get(i)
            if v is None:
                continue
            want = 76 if i < total - 1 else (size - 76 * (total - 1) if size else len(v))
            if len(v) == want:
                pick = v
                break
        merged.append(pick)
    if all(x is not None for x in merged):
        candidates.append("".join(merged))
    for c in copies:
        candidates.append("".join(c["lines"][i] for i in sorted(c["lines"])))
    for data in candidates:
        if hashlib.sha256(data.encode()).hexdigest() != sha:
            continue
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(data)), mode="r:gz") as t:
            try:
                t.extractall(evid, filter="data")
            except TypeError:  # Python without extraction filters
                t.extractall(evid)
        done.add(phase)
        print(f"decoded boot {phase}")
        break
missing = {"A", "B", "C", "D"} - done
if missing:
    print("MISSING boots: " + ",".join(sorted(missing)))
PY

python3 - "$EVID" > "$EVID/run.txt" <<'PY'
# The run's record: per boot the kernel, the chip's measurement, whether the
# AK is the certified one and the quote checks, the probe's lines; across
# boots, which PCRs moved.
import pathlib, re, sys
evid = pathlib.Path(sys.argv[1])
def read(p):
    try:
        return (evid / p).read_text()
    except OSError:
        return ""
def pcrs(phase):
    out, bank = {}, None
    for line in read(f"{phase}/pcrs.txt").splitlines():
        if line.strip().startswith("sha256"):
            bank = "sha256"; continue
        m = re.match(r"\s*(\d+)\s*:\s*0x([0-9A-Fa-f]+)", line)
        if bank and m:
            out[int(m.group(1))] = m.group(2).lower()
    return out
meas = {}
for ph in "ABCD":
    steps = read(f"{ph}/steps.txt")
    m = re.search(r"measurement ([0-9a-f]{96})", steps)
    meas[ph] = m.group(1) if m else ""
    print(f"boot {ph}: kernel={read(f'{ph}/kernel.txt').strip()}")
    print(f"  chip measurement={meas[ph]}")
    for key in ("the AK made here is the key", "AK MISMATCH", "tpm2_checkquote ok", "tpm2_checkquote FAIL", "report_data_bound True", "report_data_bound False"):
        if key in steps:
            print(f"  {key}")
    for line in read(f"{ph}/probe.txt").splitlines():
        if re.match(r"(chip|vtpm\S*) (seal|open)", line):
            print(f"  probe: {line[:150]}")
    for line in read(f"{ph}/product.txt").splitlines():
        if re.match(r"(producer|verify|both|pinned)", line):
            print(f"  product: {line[:190]}")
p = {ph: pcrs(ph) for ph in "ABCD"}
def moved(x, y):
    if not p[x] or not p[y]:
        return "unknown (a boot is missing)"
    return ",".join(str(i) for i in sorted(p[x]) if p[x].get(i) != p[y].get(i)) or "none"
print("PCRs that moved A->B (the image's first boot, then the same kernel): " + moved("A", "B"))
print("PCRs that moved B->C (the same kernel, a plain reboot): " + moved("B", "C"))
print("PCRs that moved C->D (another kernel): " + moved("C", "D"))
print("chip measurement the same on all four boots: " + str(len(set(meas.values())) == 1 and all(meas.values())))

# The verdict, against what ADR 0037 says the family does.
def has(ph, f, text):
    return text in read(f"{ph}/{f}")
kernels = {ph: read(f"{ph}/kernel.txt").strip() for ph in "ABCD"}
checks = [
    ("four boots decoded", all(kernels.values())),
    ("D runs another kernel than C", kernels["C"] and kernels["D"] and kernels["C"] != kernels["D"]),
    ("the chip's measurement is the same on all four boots, whatever the kernel", len(set(meas.values())) == 1 and all(meas.values())),
    ("a plain reboot moves no PCR (B->C)", moved("B", "C") == "none"),
    ("the chip-sealed text opens under another kernel (the gap the chip leaves)", has("D", "probe.txt", "chip open ok")),
    ("the vTPM seal under sha256:0-9 opens after a reboot", has("C", "probe.txt", "vtpm[sha256:0,1,2,3,4,5,6,7,8,9] open ok")),
    ("the vTPM seal under sha256:0-9 is refused under another kernel", has("D", "probe.txt", "vtpm[sha256:0,1,2,3,4,5,6,7,8,9] open REFUSED")),
]
if read("B/product.txt"):
    checks += [
        ("the shipping verifier accepts the pinned boot (B)", has("B", "product.txt", "verify ok")),
        ("the shipping verifier accepts it after a reboot (C)", has("C", "product.txt", "verify ok")),
        ("the shipping verifier refuses another kernel (D)", has("D", "product.txt", "verify REFUSED") and has("D", "product.txt", "is not in the acceptable set")),
        ("the chip-and-vTPM file opens after a reboot (C)", has("C", "product.txt", "both open ok")),
        ("the chip-and-vTPM file does not open under another kernel (D)", has("D", "product.txt", "both open REFUSED")),
    ]
for name, ok in checks:
    print(("PASS: " if ok else "FAIL: ") + name)
print("RESULT: " + ("PASS" if all(ok for _, ok in checks) else "FAIL"))
PY
