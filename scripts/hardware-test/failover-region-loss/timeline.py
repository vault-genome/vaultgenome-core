#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The region-loss drill's timeline, read from its evidence alone.

    python3 timeline.py evidence/<run>

Reads what the three machines, the operator and Google wrote during one run
and prints a single timeline, each line tagged with the clock it was read
from, then the intervals the drill is judged by. Nothing is taken from
anywhere but the run's evidence directory. Standard library only.

The clocks: `primary`, `authority` and `standby` are the three machines' own
clocks (the GCP machines keep Google's time; the Azure machine keeps
Microsoft's); `google` is Google's record of the primary as its API and audit
log returned it; `operator` is the orchestrating laptop. The report's own
intervals (detect, release, failover, RTO) are each read on one clock;
the intervals marked "across clocks" subtract one machine's reading from
another's.
"""
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def ts(s):
    """RFC 3339 with any number of fractional digits, Z or an offset."""
    if not s:
        return None
    s = s.strip().strip("'\"")
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$", s)
    if not m:
        return None
    base, frac, tz = m.groups()
    frac = ((frac or "") + "000000")[:6]
    tz = "+00:00" if tz in (None, "Z") else tz
    return datetime.fromisoformat(f"{base}.{frac}{tz}").astimezone(timezone.utc)


def load_json(p):
    try:
        return json.loads(Path(p).read_text())
    except (OSError, ValueError):
        return None


def lines(p):
    try:
        return Path(p).read_text().splitlines()
    except OSError:
        return []


def main(run):
    run = Path(run)
    events = []  # (time, clock, what)

    def add(t, clock, what):
        if t is not None:
            events.append((t, clock, what))

    # The run's date, for the machines' HH:MM:SS step lines.
    m = re.search(r"(\d{8})T\d{6}Z", run.name)
    day = datetime.strptime(m.group(1), "%Y%m%d").replace(tzinfo=timezone.utc) if m else None

    def steps(p, clock, keep):
        prev = None
        for ln in lines(p):
            m = re.match(r"^== (\d{2}):(\d{2}):(\d{2}) (.*)$", ln)
            if not m or day is None:
                continue
            h, mi, se, what = m.groups()
            t = day + timedelta(hours=int(h), minutes=int(mi), seconds=int(se))
            if prev is not None and t < prev:
                t += timedelta(days=1)
            prev = t
            if any(k in what for k in keep):
                add(t, clock, what)

    # --- the primary ---------------------------------------------------------
    steps(run / "primary/steps.txt", "primary", ("fine-tune generation", "keep training", "THE REGION GOES DARK", "wait for the authority to arm"))
    for ln in lines(run / "primary/sentinel.log"):
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        if e.get("msg") == "sentinel started":
            add(ts(e.get("time")), "primary", f"sentinel started, {e.get('wires')} tripwires armed")
        elif e.get("msg") == "genome sealed":
            add(ts(e.get("time")), "primary", f"generation {e.get('generation')} sealed, key escrowed to the authority ({e.get('bundle_bytes')} bytes)")
    off = None
    for p in (run / "operator/primary-destroyed-at.txt",):
        v = lines(p)
        off = ts(v[0]) if v else None
    add(off, "primary", "POWER OFF: the primary switches itself off through sysrq (no shutdown, no last message)")
    train2 = [ln for ln in lines(run / "primary/finetune-2.log") if ln.startswith("step ")]

    # --- Google's record of the primary -----------------------------------------
    stop = None
    terminate = None
    for e in load_json(run / "operator/gcp-audit-primary.json") or []:
        if "guestTerminate" in (e.get("method") or ""):
            terminate = ts(e.get("timestamp"))
    for ln in lines(run / "operator/operator-destroy.txt"):
        m = re.match(r"^(\S+Z) (status=.*|delete: .*|delete returned|after delete: .*|disks named .*)$", ln)
        if m:
            what = m.group(2)
            if what.startswith("after delete:") and "not found" in what:
                what = "after delete: Google answers that the machine does not exist"
            add(ts(m.group(1)), "operator", what)
        m = re.match(r"^\s*lastStopTimestamp:\s*(\S+)", ln)
        if m:
            stop = ts(m.group(1))
            add(stop, "google", "Google's record: the primary stopped (lastStopTimestamp)")
    for e in load_json(run / "operator/gcp-audit-primary.json") or []:
        add(ts(e.get("timestamp")), "google", f"Google's audit log ({e.get('log')}): {e.get('method')}")

    # --- the authority -----------------------------------------------------------
    pol = load_json(run / "authority/failover-policy.json") or {}
    trg = pol.get("triggers") or {}
    armed = []
    if trg.get("compromise_report"):
        armed.append("a compromise report")
    if trg.get("heartbeat_timeout_seconds"):
        armed.append(f"{trg['heartbeat_timeout_seconds']} s without a heartbeat")
    if trg.get("stopped_grace_seconds"):
        armed.append(f"a stopped sentinel not back within {trg['stopped_grace_seconds']} s")
    for ln in lines(run / "authority/timeline.txt"):
        k, _, v = ln.partition("=")
        if k == "armed":
            add(ts(v), "authority", "armed; the signed policy's triggers: " + (", ".join(armed) or "?"))
    hb = load_json(run / "authority/last-heartbeat.json") or {}
    if hb:
        last = (hb.get("last") or {}).get("generation")
        add(ts(hb.get("at")), "primary", f"last heartbeat the primary ever sent: #{hb.get('seq')}, status {hb.get('status')}, newest sealed generation {last} (signed, chip report attached)")
    rep = load_json(run / "authority/report.json") or {}
    tr, dec, rel, res, tim, gen = (rep.get(k) or {} for k in ("trigger", "decision", "release", "restore", "timing", "genome"))
    add(ts(tr.get("alive_observed_at")), "authority", "last time the authority saw the heartbeat rise")
    why = {"heartbeat-timeout": "no heartbeat for the policy's timeout", "compromise-report": "the primary's signed compromise report"}
    add(ts(tr.get("observed_at")), "authority", f"TRIGGER: {tr.get('kind')} — {why.get(tr.get('kind'), '')}")
    for ln in lines(run / "authority/audit-events.jsonl"):
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        add(ts(e.get("occurred_at")), "authority", f"audit {e.get('event_id')}: {e.get('kind')}")
    said = {"crosscloud handshake answered": "answers the authority's handshake with its evidence (chip report, vTPM quote, NVIDIA's tokens)",
            "genome key released here; restore queued": "receives the genome's key",
            "genome restore started": "restores the sealed bundle it already holds",
            "genome gate started": "restored; the gate runs the model on the H100 against the sealed reference prompts",
            "genome gated": "gate passed",
            "genome key erased after restore": "the genome's key erased"}
    for ln in lines(run / "destination/acp-bootstrap.log"):
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        what = said.get(e.get("msg"))
        if what:
            if e.get("msg") == "genome gated":
                what = f"gate passed: {e.get('level')}, {e.get('fixtures')} fixtures, max abs err {e.get('max_abs_err')}"
            add(ts(e.get("time")), "standby", what)

    events.sort(key=lambda e: e[0])
    print(f"Timeline of run {run.name} (UTC)\n")
    for t, clock, what in events:
        print(f"  {t.strftime('%H:%M:%S.%f')[:-3]}  {clock:9s}  {what}")

    print("\nIntervals\n")

    def sec(a, b):
        return None if a is None or b is None else (b - a).total_seconds()

    rows = [
        ("detect (report): last heartbeat seen -> trigger, authority's clock", tim.get("detect_seconds")),
        ("release (report): trigger -> key release authorised, after the GPU host attested", tim.get("release_seconds")),
        ("restore on the H100 (report, standby's clock)", tim.get("restore_seconds")),
        ("gate on the H100 (report, standby's clock)", tim.get("gate_seconds")),
        ("failover (report): trigger -> confirmed, gated restore, authority's clock", tim.get("failover_seconds")),
        ("RTO (report): detect + failover", tim.get("rto_seconds")),
        ("RPO (report): last heartbeat -> seal of the generation restored, primary's clock", tim.get("rpo_seconds")),
        ("power-off -> trigger (across clocks: authority - primary)", sec(off, ts(tr.get("observed_at")))),
        ("power-off -> confirmed restore (across clocks: authority - primary)", sec(off, ts(res.get("confirmed_at")))),
        ("confirmed restore -> Google's audit log records the guest's termination (across clocks: Google - authority)", sec(ts(res.get("confirmed_at")), terminate)),
        ("confirmed restore -> Google's lastStopTimestamp (across clocks: Google - authority)", sec(ts(res.get("confirmed_at")), stop)),
        ("last heartbeat sent -> power-off (primary's clock)", sec(ts(hb.get("at")), off)),
    ]
    for label, v in rows:
        print(f"  {'-' if v is None else f'{v:8.2f} s'}  {label}")
    g = res.get("gate") or {}
    print(f"\n  restored: generation {gen.get('generation')} (bundle sha256 {str(gen.get('bundle_sha256'))[:16]}…), gate {g.get('level')} "
          f"on {g.get('fixtures')} fixtures, max abs err {g.get('max_abs_err')}; status {rep.get('status')}")
    if train2:
        print(f"  lost with the region: generation 2, in training — its last logged step: {train2[-1]}")
    print(f"  destination: {rel.get('destination_kind')} {str(rel.get('destination_measurement_hex'))[:16]}…; audit chain {rep.get('audit_chain_length')} events, tip {str(rep.get('audit_tip'))[:16]}…")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: timeline.py evidence/<run>")
    main(sys.argv[1])
