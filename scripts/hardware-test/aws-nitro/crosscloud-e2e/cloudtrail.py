#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The run's Decrypt calls in CloudTrail's lookup-events output.

A call KMS refused at its policy is recorded with errorCode AccessDenied,
no requestParameters and no resources: the key it asked for is named only
in errorMessage. A call that reached the key carries it in resources and
in requestParameters.keyId. All three are read.

    cloudtrail.py count   <lookup-events.json> <key-arn>...
    cloudtrail.py extract <lookup-events.json> <key-arn>...
"""
import json
import sys

KEPT = ("eventTime", "eventName", "userIdentity", "requestParameters", "additionalEventData",
        "errorCode", "errorMessage", "requestID", "eventID", "sourceIPAddress", "userAgent")


def on_the_keys(event, keys):
    ct = json.loads(event.get("CloudTrailEvent") or "{}")
    if any(r.get("ResourceName") in keys for r in event.get("Resources") or []):
        return ct
    if (ct.get("requestParameters") or {}).get("keyId") in keys:
        return ct
    message = ct.get("errorMessage") or ""
    if any(k in message for k in keys):
        return ct
    return None


def main():
    if len(sys.argv) < 4 or sys.argv[1] not in ("count", "extract"):
        sys.exit(__doc__)
    events = json.load(open(sys.argv[2])).get("Events", [])
    keys = set(sys.argv[3:])
    found = [ct for ct in (on_the_keys(e, keys) for e in events) if ct is not None]
    if sys.argv[1] == "count":
        print(len(found))
        return
    out = [{k: ct.get(k) for k in KEPT} for ct in found]
    print(json.dumps(sorted(out, key=lambda x: (x["eventTime"], x["eventID"] or "")), indent=2))


if __name__ == "__main__":
    main()
