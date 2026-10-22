#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The authority-loss drill: the release authority's own host is taken away
# in the middle of a job, and a fresh host becomes that authority — the
# same identity, the same escrow key, the same audit chain — on real AMD
# SEV-SNP hardware. What is measured is the recovery time of the authority
# itself (docs/operator/runbooks/disaster_recovery.md scenario 4 names the
# procedure; this drill puts numbers on it):
#
#   1. builds sagvd, acp-compute, acpctl and acp-keygen for linux/amd64 and
#      packs workers/genome (with its locks);
#   2. boots A (authority-a.sh): provisions and seals its keys, makes its
#      escrow key, puts the operator's copies in the bucket's "safe",
#      fine-tunes and seals a genome, then runs gate jobs in a loop,
#      replicating the audit log and the genomes after each;
#   3. waits until A has completed three jobs, then DELETES A while a job is
#      in flight (the first job it sees submitted and not done) and records
#      the moment;
#   4. boots B (authority-b.sh) at once: it restores the safe and the
#      replica, seals the keys to its own chip, runs the recovery ceremony,
#      starts, resubmits the lost job and records the first verdict;
#   5. collects both records, computes the recovery times and deletes B and
#      the bucket — always, also on failure.
#
# Three numbers come out (timeline.txt): the cold RTO from the moment A's
# deletion was issued to B's first verdict (B created on demand), the RTO
# from B's own first line, and the RTO from B's runtime being ready (what a
# warm standby would need).
#
# Usage: run.sh <project> [zone] [profile]   (two n2d-standard-4 SEV-SNP VMs, one after
# the other, ~30 min; profile general, fips or cnsa — the cryptographic profile of
# ADR 0029 the authorities run under: the escrow key and the operator's recovery
# key are made under the suite the profile writes)
set -euo pipefail

PROJECT="${1:?usage: run.sh <project> [zone] [profile]}"
ZONE="${2:-us-central1-c}"
PROFILE="${3:-general}"
case "$PROFILE" in general|fips|cnsa) ;; *) echo "profile must be general, fips or cnsa; got $PROFILE"; exit 2;; esac
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
A="vg-authority-a-$LOW"
B="vg-authority-b-$LOW"
BUCKET="$PROJECT-vg-authloss-$LOW"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"
mkdir -p "$EVIDENCE"
TL="$EVIDENCE/runner-timeline.txt"
now() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f000Z"))'; }
mark() { echo "$1=$(now)" | tee -a "$TL"; }

cleanup() {
  echo "cleanup: deleting $A, $B and gs://$BUCKET"
  gcloud compute instances delete "$A" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud compute instances delete "$B" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree prune >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

has() { gcloud storage ls "gs://$BUCKET/$1" --project "$PROJECT" >/dev/null 2>&1; }
collect() { # collect <a|b>
  mkdir -p "$EVIDENCE/$1"
  if gcloud storage cp "gs://$BUCKET/out/$1.tgz" "$BUILD/$1.tgz" --project "$PROJECT" >/dev/null 2>&1; then
    tar -C "$EVIDENCE/$1" -xzf "$BUILD/$1.tgz"
  fi
}
boot() { # boot <name> <startup script>
  gcloud compute instances create "$1" --project "$PROJECT" --zone "$ZONE" \
    --machine-type n2d-standard-4 --min-cpu-platform "AMD Milan" \
    --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
    --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --boot-disk-size 20GB \
    --scopes storage-rw --metadata "vg-bucket=$BUCKET,vg-profile=$PROFILE" \
    --metadata-from-file "vg-common=$HERE/common.sh,startup-script=$2" >/dev/null
}

echo "build sagvd, acp-compute, acpctl, acp-keygen (linux/amd64) and pack workers/genome"
# Build from a clean checkout of HEAD when the tracked tree is clean, so the
# binaries' VCS stamp is the commit's even while other kits write their
# records into the tree (untracked files mark a build modified; on
# 2026-10-21 the binaries of a release record came out "-dirty" for that
# reason); a tree with modified tracked files builds from the working tree,
# stamped so.
SRC="$ROOT"
if [ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]; then
  SRC="$BUILD/src"; git -C "$ROOT" worktree add -q --detach "$SRC" HEAD
fi
SRC_WORKERS="$SRC/workers/genome"
( cd "$SRC" && for b in sagvd acp-compute acpctl; do CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done \
  && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$BUILD/worker.tgz" -C "$SRC_WORKERS" --exclude __pycache__ --exclude .pytest_cache vg_genome requirements.txt requirements-ci.lock requirements-cuda.lock requirements-torch-cpu.lock requirements-torch-cu126.lock examples tests
[ "$SRC" = "$ROOT" ] || git -C "$ROOT" worktree remove --force "$SRC"
( cd "$BUILD" && shasum -a 256 sagvd acp-compute acpctl keygen worker.tgz ) | tee "$EVIDENCE/inputs.sha256"
{ echo "tree $(git -C "$ROOT" rev-parse --short HEAD)"; echo "stamp $STAMP"; echo "zone $ZONE"; } > "$EVIDENCE/run.txt"

echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/sagvd" "$BUILD/acp-compute" "$BUILD/acpctl" "$BUILD/keygen" "$BUILD/worker.tgz" "gs://$BUCKET/in/" --project "$PROJECT" >/dev/null

echo "boot $A (the authority and its worker, SEV-SNP, $ZONE)"
mark a_create_issued
boot "$A" "$HERE/authority-a.sh"
mark a_created

echo "waiting for A to complete three jobs (up to 25 min)"
deadline=$(( $(date +%s) + 25 * 60 ))
until has out/a/READY; do
  has out/a/FAILED && { echo "A failed before it was ready"; collect a; exit 1; }
  [ "$(date +%s)" -lt "$deadline" ] || { echo "A was not ready after 25 min"; collect a; exit 1; }
  sleep 10
done
mark a_ready

echo "waiting for a job in flight on A, then deleting A"
# A marks every job's submission and completion; the first submitted-but-
# not-done marker seen is the job A loses. Polling the bucket takes about
# a second, a job about five, so a few polls find one.
LOST=""
for _ in $(seq 1 120); do
  names=$(gcloud storage ls "gs://$BUCKET/out/a/" --project "$PROJECT" 2>/dev/null | sed 's#.*/##')
  LOST=$(printf '%s\n' "$names" | python3 -c '
import sys, re
sub, done = set(), set()
for line in sys.stdin:
    m = re.match(r"job-(\d+)-(submitted|done)$", line.strip())
    if m: (sub if m.group(2) == "submitted" else done).add(int(m.group(1)))
lost = sorted(sub - done)
print(lost[0] if lost else "")')
  [ -n "$LOST" ] && break
  sleep 1
done
echo "job in flight on A: ${LOST:-none seen}"
echo "lost_job=$LOST" >> "$TL"
# A replicates its job store the moment a job is accepted and then marks
# it; the deletion waits for that marker (up to 20 s), so the replica B
# takes carries the job in flight — the thing ADR 0026 lets B resume.
SYNCED=no
if [ -n "$LOST" ]; then
  for _ in $(seq 1 20); do
    if gcloud storage ls "gs://$BUCKET/out/a/job-$LOST-synced-accepted" --project "$PROJECT" >/dev/null 2>&1; then SYNCED=yes; break; fi
    sleep 1
  done
fi
echo "the replica carries the job in flight: $SYNCED"
echo "lost_job_synced=$SYNCED" >> "$TL"
mark a_delete_issued
gcloud compute instances delete "$A" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
mark a_delete_done

echo "boot $B (the new authority, SEV-SNP, $ZONE)"
mark b_create_issued
boot "$B" "$HERE/authority-b.sh"
mark b_created

echo "waiting for B's first verdict and its record (up to 25 min)"
deadline=$(( $(date +%s) + 25 * 60 ))
until has out/b/DONE || has out/b/FAILED; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "B did not finish after 25 min"; break; }
  sleep 10
done
mark b_finished
# A's markers in the bucket: every job's submission and completion as A
# wrote them, the one record of a job submitted after A's last upload.
gcloud storage ls "gs://$BUCKET/out/a/" --project "$PROJECT" 2>/dev/null | sed 's#.*/##' | grep -E '^job-' | sort -V > "$EVIDENCE/a-markers.txt" || true
collect a; collect b

echo "the recovery times"
python3 - "$EVIDENCE" <<'PY' | tee "$EVIDENCE/timeline.txt"
import os, sys, re, datetime
E = sys.argv[1]
def load(path):
    out = {}
    try:
        for line in open(path):
            if "=" in line:
                k, v = line.strip().split("=", 1); out[k] = v
    except FileNotFoundError:
        pass
    return out
def t(s):
    s = s.replace("Z", "")
    if "." in s:
        head, frac = s.split("."); s = head + "." + (frac + "000000")[:6]
    return datetime.datetime.fromisoformat(s)
r = load(os.path.join(E, "runner-timeline.txt")); b = load(os.path.join(E, "b", "timeline.txt")); a = load(os.path.join(E, "a", "timeline.txt"))
# A's markers in the bucket say which job was submitted and never
# completed (A's own record stops at its last upload, one job earlier);
# the runner's view — the job in flight when it issued the deletion — may
# be a job A still finished before the power-off.
sub, done = set(), set()
try:
    for line in open(os.path.join(E, "a-markers.txt")):
        m = re.match(r"job-(\d+)-(submitted|done)$", line.strip())
        if m:
            (sub if m.group(2) == "submitted" else done).add(int(m.group(1)))
except FileNotFoundError:
    sub = {int(m.group(1)) for k in a for m in [re.match(r"job_(\d+)_submit", k)] if m}
    done = {int(m.group(1)) for k in a for m in [re.match(r"job_(\d+)_done", k)] if m}
lost_jobs = sorted(sub - done)
print("job in flight when the deletion was issued (runner's view):", r.get("lost_job", "") or "none")
print("job lost with A (submitted, never completed, by A's markers):", " ".join(map(str, lost_jobs)) or "none")
if "a_delete_issued" in r and "first_job_done" in b:
    t0 = t(r["a_delete_issued"]); t1 = t(b["first_job_done"])
    print("RTO cold (A's deletion issued -> B's first verdict):      %.1f s" % (t1 - t0).total_seconds())
    print("  of which B's VM creation (create issued -> created):    %.1f s" % (t(r["b_created"]) - t(r["b_create_issued"])).total_seconds())
    print("  of which B's boot until its script started:            %.1f s" % (t(b["b_script_start"]) - t(r["b_created"])).total_seconds())
    print("RTO from B's first line (script start -> first verdict):  %.1f s" % (t1 - t(b["b_script_start"])).total_seconds())
    print("RTO warm (runtime ready -> first verdict):                %.1f s" % (t1 - t(b["runtime_ready"])).total_seconds())
    print("  state restored at +%.1f s, ceremony %.1f s, daemons ready at +%.1f s (from runtime ready)" % (
        (t(b["state_restored"]) - t(b["runtime_ready"])).total_seconds(),
        (t(b["ceremony_done"]) - t(b["ceremony_start"])).total_seconds(),
        (t(b["daemons_ready"]) - t(b["runtime_ready"])).total_seconds()))
else:
    print("B did not reach a verdict; see b/steps.txt")
print("jobs A completed before the loss:", len(done))
print("the replica carried the job in flight (job store synced on acceptance):", r.get("lost_job_synced", "unknown"))
print("B resumed A's job by itself from the replicated job store:", "yes" if "resumed_job_done" in b else "no — the job was resubmitted")

# The same authority on B: the identities, the escrow key, the audit chain.
import json
def J(*p):
    try:
        return json.load(open(os.path.join(E, *p)))
    except Exception:
        return {}
ia, ib = J("a", "sagvd-identity.json"), J("b", "sagvd-identity.json")
same = lambda k: "same" if ia.get(k) and ia.get(k) == ib.get(k) else "DIFFERENT"
print("authority signing key A vs B:", same("authority_public_key_pem"))
print("audit signing key A vs B:    ", same("audit_public_key_pem"))
print("launch measurement A vs B:   ", same("tee_measurement_hex"), "(%s… / %s…)" % (ia.get("tee_measurement_hex", "")[:16], ib.get("tee_measurement_hex", "")[:16]))
ea, eb = J("a", "escrow-provision.json").get("escrow_key"), J("b", "escrow-reprovision.json").get("escrow_key")
print("escrow key A -> ceremony -> B:", "same (%s)" % ea if ea and ea == eb else "DIFFERENT (%s / %s)" % (ea, eb))
rep, fin = J("b", "audit-verify-replica.json"), J("b", "audit-verify.json")
man = J("b", "replica-manifest.json")
print("replica: after job %s (tip %s…) ok=%s events=%s" % (man.get("after_job"), (man.get("chain_tip") or "")[:16], rep.get("ok"), rep.get("event_count")))
print("final chain on B (A's events + B's): ok=%s events=%s tip=%s…" % (fin.get("ok"), fin.get("event_count"), (fin.get("tip") or "")[:16]))
PY
echo "evidence: $EVIDENCE"
has out/b/DONE || { echo "B did not finish cleanly"; exit 1; }
