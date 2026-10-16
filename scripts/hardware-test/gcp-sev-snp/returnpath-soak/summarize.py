#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The soak's numbers from its evidence: throughput, the latency percentiles,
the daemons' drift over the hour, the failures. Reads jobs.csv, snapshots.csv,
steps.txt and the handshake_ms files of one evidence directory and writes
summary.json beside them (and prints it).

    summarize.py scripts/hardware-test/gcp-sev-snp/returnpath-soak/evidence/<stamp>

Every number here is derived from the files the guest wrote; nothing is
measured on this machine."""
import csv, json, os, re, sys


def percentile(values, p):
    """Nearest-rank percentile of a sorted list (p in 0..100)."""
    if not values:
        return None
    k = max(0, min(len(values) - 1, int(round(p / 100.0 * len(values) + 0.5)) - 1))
    return values[k]


def stats(values):
    v = sorted(x for x in values if x is not None)
    if not v:
        return {"n": 0}
    return {"n": len(v), "min": v[0], "p50": percentile(v, 50), "p90": percentile(v, 90),
            "p99": percentile(v, 99), "max": v[-1], "mean": round(sum(v) / len(v), 3)}


def num(s):
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def main(d):
    out = {"evidence": os.path.basename(os.path.normpath(d))}
    steps = open(os.path.join(d, "steps.txt")).read()
    for key in ("workers", "soak_minutes"):
        m = re.search(r"^%s=(\d+)$" % key, steps, re.M)
        out[key] = int(m.group(1)) if m else None
    m = re.search(r"^soak: minutes=(\d+) workers=(\d+) jobs_done=(\d+) ok=(\d+) exact=(\d+) in_flight_at_end=(\d+) first_error=(.*)$", steps, re.M)
    if m:
        out["jobs"] = {"done": int(m.group(3)), "succeeded": int(m.group(4)), "exact": int(m.group(5)),
                       "in_flight_at_end": int(m.group(6)), "first_error": None if m.group(7) == "None" else m.group(7)}
    m = re.search(r"^audit verify exit=(\d+)$", steps, re.M); out["audit_verify_exit"] = int(m.group(1)) if m else None
    m = re.search(r"^audit_verify_seconds=([\d.]+)$", steps, re.M); out["audit_verify_seconds"] = float(m.group(1)) if m else None
    m = re.search(r"^audit_events=(\d+)$", steps, re.M); out["audit_events"] = int(m.group(1)) if m else None
    try:
        out["audit_verify"] = json.load(open(os.path.join(d, "audit-verify.json")))
    except (OSError, ValueError):
        out["audit_verify"] = None
    jobs = list(csv.DictReader(open(os.path.join(d, "jobs.csv"))))
    out["jobs_recorded"] = len(jobs)
    out["statuses"] = {}
    out["levels"] = {}
    for j in jobs:
        out["statuses"][j["status"]] = out["statuses"].get(j["status"], 0) + 1
        out["levels"][j["level"]] = out["levels"].get(j["level"], 0) + 1
    out["queue_s"] = stats(num(j["queue_s"]) for j in jobs)
    out["run_s"] = stats(num(j["run_s"]) for j in jobs)
    out["total_s"] = stats(num(j["total_s"]) for j in jobs)
    # Throughput over the submission window: first submission to last completion.
    times = sorted(j["submitted_at"] for j in jobs if j["submitted_at"])
    ends = sorted(j["completed_at"] for j in jobs if j["completed_at"])
    if times and ends:
        import datetime
        def ts(s):
            s = s.rstrip("Z"); head, _, frac = s.partition(".")
            return datetime.datetime.strptime(head, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp() + int((frac + "000000")[:6]) / 1e6
        span = ts(ends[-1]) - ts(times[0])
        out["window_s"] = round(span, 1)
        out["jobs_per_hour"] = round(len(jobs) * 3600.0 / span, 1) if span > 0 else None
        out["jobs_per_minute"] = round(len(jobs) * 60.0 / span, 2) if span > 0 else None
        # The first and the last ten minutes, to see whether the rate drifted.
        t0 = ts(times[0])
        first = [j for j in jobs if j["completed_at"] and ts(j["completed_at"]) - t0 <= 600]
        last = [j for j in jobs if j["completed_at"] and ts(j["completed_at"]) >= ts(ends[-1]) - 600]
        out["first_10min"] = {"jobs": len(first), "total_s": stats(num(j["total_s"]) for j in first)}
        out["last_10min"] = {"jobs": len(last), "total_s": stats(num(j["total_s"]) for j in last)}
    snaps = list(csv.DictReader(open(os.path.join(d, "snapshots.csv"))))
    out["snapshots"] = len(snaps)
    if snaps:
        def col(name):
            return [num(s[name]) for s in snaps]
        rss = [x for x in col("sagvd_rss_kb") if x is not None]
        fds = [x for x in col("sagvd_fds") if x is not None]
        wrss = [x for x in col("workers_rss_kb") if x is not None]
        out["sagvd_rss_kb"] = {"first": rss[0], "max": max(rss), "last": rss[-1]} if rss else None
        out["sagvd_fds"] = {"first": fds[0], "max": max(fds), "last": fds[-1]} if fds else None
        out["workers_rss_kb"] = {"first": wrss[0], "max": max(wrss), "last": wrss[-1]} if wrss else None
        out["load1"] = stats(col("load1"))
        out["sessions_active_max"] = max((x for x in col("sessions_active") if x is not None), default=None)
        out["queue_depth_max"] = max((x for x in col("queue_depth") if x is not None), default=None)
        last = snaps[-1]
        out["metrics_end"] = {k: num(last[k]) for k in ("sessions_opened", "handshake_failures", "sessions_refused")}
    hs = {}
    for f in sorted(os.listdir(d)):
        if f.endswith(".handshake_ms.txt"):
            hs[f[:-len(".handshake_ms.txt")]] = stats(num(x) for x in open(os.path.join(d, f)).read().split())
    out["handshake_ms"] = hs
    for f in sorted(os.listdir(d)):
        if f.endswith(".size.txt"):
            out.setdefault("logs", {})[f[:-len(".size.txt")]] = open(os.path.join(d, f)).read().split()
    json.dump(out, open(os.path.join(d, "summary.json"), "w"), indent=2, sort_keys=True)
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
