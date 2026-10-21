#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Reference design 01 — a Tier-1 bank's continuity of a fine-tuned model —
# played end to end on real AMD SEV-SNP hardware, in one run, with the
# design's figures table filled from this run (docs/reference-designs/
# 01-tier1-bank-model-continuity.md, "A job, end to end" and "The figures").
#
#   A  the bank, region A (bank.sh, an n2d SEV-SNP guest): the release
#      authority and its pinned worker; `acp-keygen` provisions, every key
#      file sealed to the chip; the quant's fine-tune sealed as a genome;
#      a thief with the sealed files and an unpinned worker both refused;
#      the operator's gate job over the Return Path — the handshake with
#      the chip's report, the material released for the session, EXACT,
#      RELEASE_DECIDED; then the continuity: the genome's key released to
#      the standby in region B only after the standby's chip attested,
#      the restore confirmed from the standby's chip-signed receipt, a
#      release to an unlisted guest and one under an operator stop refused.
#   B  the standby, region B (standby.sh, an n2d SEV-SNP guest in another
#      region): acp-bootstrap attests with its chip, receives the key,
#      restores the genome by itself, and the restored model is gated on
#      this chip against the sealed fixtures (`acpctl genome gate`).
#   C  the third party — this machine, with the audit logs, the published
#      audit key and acpctl alone: `acpctl audit verify`, `audit query
#      --request`, `lineage` — the design's step 6.
#
# The hand-off between the three is the run's private bucket (deleted with
# the run): the bundle for the standby goes out once, the standby's
# identity comes back, the records come out at the end. A's Return Path
# stays on loopback; the only port opened is the standby's 8443, to A's
# internal address alone.
#
# Usage: run.sh <gcp-project> [zone-a] [zone-b[,zone-b2,...]] [profile]
#        (defaults us-central1-c, us-east4-b,us-west1-b,europe-west4-b,
#        general; zone-b is tried in order — not every zone offers SEV-SNP
#        on n2d, and a zone that does not refuses the create at once;
#        profile general, fips or cnsa — ADR 0029, written into every
#        daemon's config)
# Cost: one n2d-standard-4 and one n2d-standard-2 for about fifteen
# minutes. Requires gcloud logged in to a project with the Compute and
# Storage APIs, and Go for the binaries. VG_KEEP_ON_FAILURE leaves the
# guests for a look.
set -euo pipefail
PROJECT="${1:?usage: run.sh <gcp-project> [zone-a] [zone-b] [profile]}"
ZONE_A="${2:-us-central1-c}"
ZONE_B_LIST="${3:-us-east4-b,us-west1-b,europe-west4-b}"
ZONE_B="${ZONE_B_LIST%%,*}"   # the one used is settled when B is created
PROFILE="${4:-general}"
case "$PROFILE" in general|fips|cnsa) ;; *) echo "profile must be general, fips or cnsa; got $PROFILE"; exit 2;; esac
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
A="vg-rd01-bank-$LOW"
B="vg-rd01-standby-$LOW"
BUCKET="$PROJECT-vg-rd01-$LOW"
TAG_B="vg-rd01-standby-$LOW"
RULE="vg-rd01-xcc-$LOW"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"
CREATED_A=0; CREATED_B=0; CREATED_RULE=0; OK=0
mkdir -p "$EVIDENCE"
TL="$EVIDENCE/runner-timeline.txt"
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$TL"; }
cleanup() {
  set +e
  if [ "$OK" = 0 ] && [ -n "${VG_KEEP_ON_FAILURE:-}" ]; then
    echo "cleanup: VG_KEEP_ON_FAILURE is set and the run failed — $A ($ZONE_A), $B ($ZONE_B), the rule $RULE and gs://$BUCKET are left for a look; delete them yourself"
    rm -rf "$BUILD"; return
  fi
  if [ "$OK" = 0 ]; then  # a guest that died before its record: its console is the only trace
    [ "$CREATED_A" = 1 ] && gcloud compute instances get-serial-port-output "$A" --project "$PROJECT" --zone "$ZONE_A" > "$EVIDENCE/a-serial-console.txt" 2>/dev/null
    [ "$CREATED_B" = 1 ] && gcloud compute instances get-serial-port-output "$B" --project "$PROJECT" --zone "$ZONE_B" > "$EVIDENCE/b-serial-console.txt" 2>/dev/null
  fi
  echo "cleanup: deleting $A, $B, the rule $RULE and gs://$BUCKET"
  [ "$CREATED_A" = 1 ] && gcloud compute instances delete "$A" --project "$PROJECT" --zone "$ZONE_A" --quiet >/dev/null 2>&1
  [ "$CREATED_B" = 1 ] && gcloud compute instances delete "$B" --project "$PROJECT" --zone "$ZONE_B" --quiet >/dev/null 2>&1
  [ "$CREATED_RULE" = 1 ] && gcloud compute firewall-rules delete "$RULE" --project "$PROJECT" --quiet >/dev/null 2>&1
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT
has() { gcloud storage ls "gs://$BUCKET/$1" --project "$PROJECT" >/dev/null 2>&1; }
wait_marker() { # wait_marker <a|b> <minutes>: DONE, or FAILED / timeout -> 1
  local deadline=$(( $(date +%s) + $2 * 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    has "out/$1/DONE" && return 0
    has "out/$1/FAILED" && { echo "$1 reported FAILED"; return 1; }
    sleep 10
  done
  echo "$1 did not finish after $2 minutes"; return 1
}
collect() { # collect <a|b>
  mkdir -p "$EVIDENCE/$1"
  if gcloud storage cp "gs://$BUCKET/out/$1.tgz" "$BUILD/$1.tgz" --project "$PROJECT" >/dev/null 2>&1; then
    tar -C "$EVIDENCE/$1" -xzf "$BUILD/$1.tgz"
  else
    echo "no record from $1"
  fi
}
exec > >(tee -a "$EVIDENCE/runner.log") 2>&1
mark run_start
echo "build sagvd, acp-compute, acp-bootstrap, acpctl, acp-keygen (linux/amd64), acpctl for this machine; pack workers/genome"
( cd "$ROOT" && for b in sagvd acp-compute acp-bootstrap acpctl; do CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done \
  && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen \
  && CGO_ENABLED=0 go build -trimpath -o "$BUILD/acpctl-host" ./cmd/acpctl )
( cd "$ROOT/workers" && COPYFILE_DISABLE=1 tar czf "$BUILD/genome-worker.tgz" --no-xattrs --exclude '__pycache__' --exclude '.pytest_cache' genome )
( cd "$BUILD" && shasum -a 256 sagvd acp-compute acp-bootstrap acpctl keygen genome-worker.tgz acpctl-host ) | tee "$EVIDENCE/inputs.sha256"
{ echo "tree $(git -C "$ROOT" rev-parse HEAD)"; echo "stamp $STAMP"; echo "profile $PROFILE"; echo "zone_a $ZONE_A"; echo "go $(go version | cut -d' ' -f3)"; echo "host $(uname -sm)"; } > "$EVIDENCE/run.txt"

echo "bucket gs://$BUCKET (private; the hand-off and the records; deleted with the run)"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/sagvd" "$BUILD/acp-compute" "$BUILD/acp-bootstrap" "$BUILD/acpctl" "$BUILD/keygen" "$BUILD/genome-worker.tgz" "gs://$BUCKET/in/" --project "$PROJECT" >/dev/null

echo "boot A, the bank: $A (n2d-standard-4 SEV-SNP, $ZONE_A)"
mark a_create_issued
gcloud compute instances create "$A" --project "$PROJECT" --zone "$ZONE_A" \
  --machine-type n2d-standard-4 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --boot-disk-size 20GB \
  --scopes storage-rw --metadata "vg-bucket=$BUCKET,vg-profile=$PROFILE" \
  --metadata-from-file "startup-script=$HERE/bank.sh" >/dev/null
CREATED_A=1
A_IP="$(gcloud compute instances describe "$A" --project "$PROJECT" --zone "$ZONE_A" --format='value(networkInterfaces[0].networkIP)')"
mark a_created
echo "A at $A_IP (internal)"

echo "the standby's port 8443: open to $A_IP only (rule $RULE, tag $TAG_B)"
gcloud compute firewall-rules create "$RULE" --project "$PROJECT" --network default --direction INGRESS --action allow \
  --rules tcp:8443 --source-ranges "$A_IP/32" --target-tags "$TAG_B" >/dev/null
CREATED_RULE=1

mark b_create_issued
for z in ${ZONE_B_LIST//,/ }; do
  [ "$z" = "$ZONE_A" ] && { echo "zone-b $z is zone-a; skipped"; continue; }
  echo "boot B, the standby: $B (n2d-standard-2 SEV-SNP, $z)"
  if gcloud compute instances create "$B" --project "$PROJECT" --zone "$z" \
      --machine-type n2d-standard-2 --min-cpu-platform "AMD Milan" \
      --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
      --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --boot-disk-size 20GB \
      --tags "$TAG_B" --scopes storage-rw --metadata "vg-bucket=$BUCKET,vg-profile=$PROFILE" \
      --metadata-from-file "startup-script=$HERE/standby.sh" > "$BUILD/b-create.log" 2>&1; then
    ZONE_B="$z"; CREATED_B=1; break
  fi
  echo "  $z refused the configuration: $(grep -m1 -oE 'message: .*' "$BUILD/b-create.log" | cut -c1-140)"
done
[ "$CREATED_B" = 1 ] || { echo "no zone in $ZONE_B_LIST would create an n2d SEV-SNP guest"; exit 1; }
B_IP="$(gcloud compute instances describe "$B" --project "$PROJECT" --zone "$ZONE_B" --format='value(networkInterfaces[0].networkIP)')"
mark b_created
echo "B at $B_IP (internal, $ZONE_B)"
echo "zone_b $ZONE_B" >> "$EVIDENCE/run.txt"
{ echo "a=$A zone=$ZONE_A ip=$A_IP"; echo "b=$B zone=$ZONE_B ip=$B_IP"; echo "bucket=gs://$BUCKET (deleted with the run)"; echo "firewall=$RULE tcp:8443 from $A_IP/32 to tag $TAG_B (deleted with the run)"; } > "$EVIDENCE/machines.txt"

echo "waiting for the bank and the standby (up to 30 min)"
A_OK=0; B_OK=0
wait_marker a 30 && A_OK=1
mark a_finished
wait_marker b 10 && B_OK=1
mark b_finished
collect a; collect b

echo "the third party: this machine, the audit logs, the published audit key and acpctl alone (design 01, step 6)"
TP="$EVIDENCE/third-party"; mkdir -p "$TP"
if gcloud storage cp -r "gs://$BUCKET/handoff/third-party/*" "$BUILD/" --project "$PROJECT" >/dev/null 2>&1; then
  ACP="$BUILD/acpctl-host"
  { echo "acpctl: $(shasum -a 256 "$ACP" | cut -d' ' -f1) (built from the same tree for this machine, $(uname -sm))"; "$ACP" version 2>/dev/null; } > "$TP/tools.txt"
  "$ACP" audit verify --audit "$BUILD/returnpath-audit.db" --audit-pubkey "$BUILD/audit-public-key.pem" --audit-kid sagvd-audit-e2e --json > "$TP/audit-verify-returnpath.json" 2> "$TP/audit-verify-returnpath.err"; echo "third-party audit verify (return path) exit=$?" | tee -a "$TP/steps.txt"
  "$ACP" audit verify --audit "$BUILD/xcc-audit.db" --audit-pubkey "$BUILD/audit-public-key.pem" --audit-kid sagvd-audit-e2e --json > "$TP/audit-verify-crosscloud.json" 2> "$TP/audit-verify-crosscloud.err"; echo "third-party audit verify (cross-cloud) exit=$?" | tee -a "$TP/steps.txt"
  REQ="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("request_id",""))' "$BUILD/job.json" 2>/dev/null || true)"
  SID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("session_id",""))' "$BUILD/job.json" 2>/dev/null || true)"
  "$ACP" audit query --audit "$BUILD/returnpath-audit.db" --request "$REQ" --limit 0 --json > "$TP/audit-query-request.jsonl" 2> "$TP/audit-query-request.err"; echo "third-party audit query --request $REQ exit=$? events=$(wc -l < "$TP/audit-query-request.jsonl" | tr -d ' ')" | tee -a "$TP/steps.txt"
  "$ACP" lineage --audit "$BUILD/returnpath-audit.db" --session-id "$SID" --json > "$TP/lineage.json" 2> "$TP/lineage.err"; echo "third-party lineage --session-id $SID exit=$?" | tee -a "$TP/steps.txt"
  cp "$BUILD/audit-public-key.pem" "$TP/"
  ( cd "$BUILD" && shasum -a 256 returnpath-audit.db xcc-audit.db audit-public-key.pem job.json ) > "$TP/inputs.sha256"
else
  echo "no third-party hand-off from the bank" | tee -a "$TP/steps.txt"
fi
mark third_party_done

echo "the report"
python3 "$HERE/report.py" "$EVIDENCE" > "$EVIDENCE/REPORT.md" 2> "$EVIDENCE/report.err" || echo "report.py failed: $(tail -2 "$EVIDENCE/report.err")"
sed -n '1,60p' "$EVIDENCE/REPORT.md" 2>/dev/null || true

echo "== the bank's steps"; cat "$EVIDENCE/a/steps.txt" 2>/dev/null || true
echo "== the standby's steps"; cat "$EVIDENCE/b/steps.txt" 2>/dev/null || true
echo "== the third party's steps"; cat "$TP/steps.txt" 2>/dev/null || true
case "$PROFILE" in general) WANT=hpke-x25519-v1;; fips) WANT=hpke-p384-v1;; cnsa) WANT=hpke-mlkem1024-p384-v1;; esac
if [ "$A_OK" = 1 ] && [ "$B_OK" = 1 ] \
   && grep -q 'gate_level=EXACT' "$EVIDENCE/a/steps.txt" && grep -q 'rogue refused after' "$EVIDENCE/a/steps.txt" && grep -q 'rogue with the sealed files exit=1' "$EVIDENCE/a/steps.txt" \
   && grep -q 'release exit=0' "$EVIDENCE/a/steps.txt" && grep -q "release suite=$WANT" "$EVIDENCE/a/steps.txt" && grep -q 'confirm exit=0' "$EVIDENCE/a/steps.txt" \
   && grep -q 'unlisted exit=1 policy denied key release: destination measurement not in allow-list' "$EVIDENCE/a/steps.txt" && grep -q 'stopped exit=1 policy denied key release: operator stop in force' "$EVIDENCE/a/steps.txt" \
   && grep -q 'audit verify exit=0' "$EVIDENCE/a/steps.txt" && grep -q 'xcc audit verify exit=0' "$EVIDENCE/a/steps.txt" \
   && grep -q 'standby gate_level=EXACT' "$EVIDENCE/b/steps.txt" \
   && grep -q 'third-party audit verify (return path) exit=0' "$TP/steps.txt" && grep -q 'third-party audit verify (cross-cloud) exit=0' "$TP/steps.txt" \
   && grep -q 'third-party lineage .* exit=0' "$TP/steps.txt"; then OK=1; fi
mark run_end
( cd "$EVIDENCE" && find . -type f ! -name sha256sums.txt -print0 | sort -z | xargs -0 shasum -a 256 > sha256sums.txt )
echo "evidence: $EVIDENCE"
[ "$OK" = 1 ] || { echo "FAIL: the run did not reach every mark; see the steps above"; exit 1; }
echo "PASS: reference design 01 end to end on SEV-SNP under $PROFILE ($WANT) — the job EXACT on the bank, the key released to the attested standby and the restore gated EXACT there, four refusals, both audit logs verified by the third party ($STAMP)"
