#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The closed turn on real hardware (ADR 0041), across three AMD SEV-SNP
# Confidential VMs: a model's training is lost with its machine, and the
# standby goes on by itself — it trains, seals what it trains under its
# own sentinel, and answers — while the release authority, on a machine
# of its own, records the chain it continues and goes on watching it.
#
#   A  PRIMARY    (primary.sh)    trains, its sentinel beside it; answers a
#                                 question from generation 1; is switched
#                                 off while it trains and deleted here, on
#                                 the record.
#   R  AUTHORITY  (authority.sh)  in another region: sagvd failover under a
#                                 v2 policy that names, before the failure,
#                                 the standby's own sentinel. It fails
#                                 generation 1 over, records the generation
#                                 the standby seals next, and stays.
#   B  STANDBY    (standby.sh)    the destination, with one command to run
#                                 after a restore its gate passed
#                                 (go-on.sh): its sentinel, the model's
#                                 answers and the training start by
#                                 themselves. The kit's script on B starts
#                                 nothing; it looks and asks.
#
#   1. builds sagvd, acp-bootstrap, acpctl and keygen for linux/amd64, and
#      packs workers/genome;
#   2. boots R, admits R's internal address to B's port 8443 by a rule of
#      the run's own (a network that already admits its own addresses, as
#      an auto-mode default network does, needs none), boots B and, in
#      B's zone, A;
#   3. sees A dead in Google's API and deletes it;
#   4. waits for B to have gone on and to have held what it made to the
#      whole recipe, tells R to stop, and brings the three records back to
#      evidence/<stamp>/;
#   5. checks them, and deletes the machines, the rule and the bucket —
#      always, also on failure.
#
# run.sh <project> negative: the same three machines, and a standby whose
# base model is not the genome's. Its gate cannot be passed: the restore
# fails, nothing starts there, and no restore and no chain are on the
# authority's log. The record goes to evidence/negative/<stamp>/.
#
# Usage: run.sh <project> [turn|negative] [zones of A and B] [zones of R]
#        Zones are comma-separated and tried in order; A is booted in the
#        zone B got (the continuation is held to the recipe bit for bit,
#        on one machine type). Defaults: europe-west4-a,europe-west4-b,
#        europe-west4-c and us-central1-c,us-central1-a,us-central1-b,
#        us-central1-f. The bucket is made in R's region.
# Cost: two n2d-standard-8 and one n2d-standard-4 SEV-SNP VMs for about an
# hour (see README.md).
set -euo pipefail

PROJECT="${1:?usage: run.sh <project> [turn|negative] [zones of A and B] [zones of R]}"
MODE="${2:-turn}"
case "$MODE" in turn|negative) ;; *) echo "mode must be turn or negative; got $MODE"; exit 2 ;; esac
ZONES="${3:-europe-west4-a,europe-west4-b,europe-west4-c}"
ZONES_R="${4:-us-central1-c,us-central1-a,us-central1-b,us-central1-f}"
MACHINE=n2d-standard-8
MACHINE_R=n2d-standard-4
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
FAILOVER="$ROOT/scripts/hardware-test/gcp-failover"
TC="$ROOT/scripts/hardware-test/training-continuity"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr '[:upper:]' '[:lower:]')"
PRIMARY="vg-ct-primary-$LOW"
STANDBY="vg-ct-standby-$LOW"
AUTHORITY="vg-ct-authority-$LOW"
BUCKET="$PROJECT-vg-ct-$LOW"
RULE="vg-ct-xcc-$LOW"
TAG="vg-ct-standby-$LOW"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"; [ "$MODE" = turn ] || EVIDENCE="$HERE/evidence/negative/$STAMP"
mkdir -p "$EVIDENCE"
RUNLOG="$EVIDENCE/runner.log"
CHAIN="$ROOT/scripts/hardware-test/gcp-sev-snp/keybind-evidence/20260913T222343Z/kds-vcek-cert_chain.pem"
CREATED_RULE=0; RESULT=FAIL; LEFT_BEHIND=0
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RUNLOG"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
zone_of() { cat "$BUILD/zone.$1" 2>/dev/null; }

cleanup() {
  set +e
  if [ "$RESULT" != PASS ]; then  # a guest that did not finish: its console is the trace that is left
    for n in "$PRIMARY" "$STANDBY" "$AUTHORITY"; do
      z="$(zone_of "$n")"; [ -n "$z" ] || continue
      gcloud compute instances get-serial-port-output "$n" --project "$PROJECT" --zone "$z" > "$EVIDENCE/${n%-"$LOW"}-serial-console.txt" 2>/dev/null
      [ -s "$EVIDENCE/${n%-"$LOW"}-serial-console.txt" ] || rm -f "$EVIDENCE/${n%-"$LOW"}-serial-console.txt"
    done
  fi
  log "cleanup: deleting $PRIMARY, $STANDBY, $AUTHORITY, the rule $RULE and gs://$BUCKET"
  # A delete that fails is asked again, and what it said is kept: on
  # 2026-11-17 a run's rule was left behind without a word.
  left=""; rule_left=""
  for pass in 1 2 3; do
    for n in "$PRIMARY" "$STANDBY" "$AUTHORITY"; do
      z="$(zone_of "$n")"; [ -n "$z" ] || continue
      gcloud compute instances delete "$n" --project "$PROJECT" --zone "$z" --quiet >/dev/null 2>>"$BUILD/cleanup.err"
    done
    [ "$CREATED_RULE" = 1 ] && gcloud compute firewall-rules delete "$RULE" --project "$PROJECT" --quiet >/dev/null 2>>"$BUILD/cleanup.err"
    gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1
    left="$(gcloud compute instances list --project "$PROJECT" --filter="name~^vg-ct-.*-$LOW\$" --format='value(name)' 2>/dev/null | tr '\n' ' ')"
    rule_left="$(gcloud compute firewall-rules list --project "$PROJECT" --filter="name=$RULE" --format='value(name)' 2>/dev/null | tr '\n' ' ')"
    [ -n "$left$rule_left" ] || break
    log "cleanup: pass $pass left ${left}${rule_left}; asking again in 15 s"
    sleep 15
  done
  echo "instances of this run left after cleanup: ${left:-none}; firewall rules: ${rule_left:-none} at $(now)" | tee "$EVIDENCE/vms-deleted.txt" >> "$RUNLOG"
  if [ -n "$left$rule_left" ]; then
    log "CLEANUP INCOMPLETE — delete by hand: ${left}${rule_left}"
    grep -v 'was not found' "$BUILD/cleanup.err" 2>/dev/null | tr -s '\n ' '  ' | cut -c1-600 | sed 's/^/cleanup said: /' | tee -a "$RUNLOG"
    LEFT_BEHIND=1
  fi
  rm -rf "$BUILD"
  # The record is closed last: nothing is written to it after its digests.
  # shellcheck disable=SC2094  # find leaves sha256sums.txt out: it is written, not read
  ( cd "$EVIDENCE" && find . -type f ! -name sha256sums.txt -exec shasum -a 256 {} + | sort -k2 > sha256sums.txt )
  echo "record closed: ${EVIDENCE#"$ROOT"/} ($(wc -l < "$EVIDENCE/sha256sums.txt" | tr -d ' ') files, sha256sums.txt)"
  # Something of the run still stands in the cloud: the run does not end well, whatever its checks said.
  [ "$LEFT_BEHIND" = 0 ] || exit 4
}
trap cleanup EXIT

has() { gcloud storage ls "gs://$BUCKET/$1" --project "$PROJECT" >/dev/null 2>&1; }
# wait_for <leg> <minutes> [other leg...]: DONE, FAILED or TIMEOUT for the
# leg — or ABORTED, as soon as one of the other legs has reported FAILED.
wait_for() {
  local leg="$1" deadline=$(( $(date +%s) + $2 * 60 )) m o; shift 2
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for m in DONE FAILED; do
      if has "out/$leg/$m"; then echo "$m"; return; fi
    done
    for o in "$@"; do
      if has "out/$o/FAILED"; then echo ABORTED; return; fi
    done
    sleep 15
  done
  echo TIMEOUT
}

collect() {
  mkdir -p "$EVIDENCE/$1"
  if gcloud storage cp "gs://$BUCKET/out/$1.tgz" "$BUILD/$1.tgz" --project "$PROJECT" >/dev/null 2>&1; then
    tar -C "$EVIDENCE/$1" -xzf "$BUILD/$1.tgz" || true
  fi
}

log "== 0. build (linux/amd64) from $(git -C "$ROOT" rev-parse --short=12 HEAD) and pack workers/genome — mode: $MODE"
# Go stamps a binary as modified when `git status` prints anything, and this
# record's own directory is an untracked file by now. Untracked files are
# left out of that one question, for the build alone; code-dirty.txt below
# names every changed or untracked file of the code, the records aside.
( cd "$ROOT" && export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=status.showUntrackedFiles GIT_CONFIG_VALUE_0=no
  for b in sagvd acp-bootstrap acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" ./cmd/acp-keygen )
cp "$CHAIN" "$BUILD/amd-milan-cert_chain.pem"
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$BUILD/worker.tgz" -C "$ROOT/workers/genome" --exclude __pycache__ --exclude .pytest_cache vg_genome requirements.txt requirements-ci.lock requirements-cuda.lock requirements-torch-cpu.lock requirements-torch-cu126.lock examples
( cd "$BUILD" && shasum -a 256 sagvd acp-bootstrap acpctl keygen worker.tgz ) > "$EVIDENCE/binaries.sha256"
( cd "$HERE" && shasum -a 256 run.sh check.sh lib.sh go-on.sh primary.sh authority.sh standby.sh ../training-continuity/recipe.sh ../gcp-failover/common.sh ) > "$EVIDENCE/kit.sha256"
git -C "$ROOT" rev-parse HEAD > "$EVIDENCE/code-rev.txt"
git -C "$ROOT" status --porcelain -- workers/genome cmd internal go.mod go.sum scripts/hardware-test/closed-turn scripts/hardware-test/training-continuity/recipe.sh scripts/hardware-test/gcp-failover/common.sh \
  ':(exclude)scripts/hardware-test/closed-turn/evidence' > "$EVIDENCE/code-dirty.txt"
[ -s "$EVIDENCE/code-dirty.txt" ] && log "   note: the tree differs from $(cut -c1-12 "$EVIDENCE/code-rev.txt") in $(wc -l < "$EVIDENCE/code-dirty.txt" | tr -d ' ') paths (code-dirty.txt)"
echo "$MODE" > "$EVIDENCE/mode.txt"

# boot <name> <machine type> <startup script> <network tag or ""> <zone>...:
# the zones in order, in rounds, until one has the capacity. A zone that
# is out of capacity is tried again in the next round. A zone that does
# not offer the configuration at all says so under the same error code
# (ZONE_RESOURCE_POOL_EXHAUSTED, reason configuration_availability): it is
# not asked again, and neither is a zone that refuses for any other
# reason. The boot ends once no zone is left that may yet say yes.
boot() {
  local name="$1" type="$2" script="$3" tag="$4" z round again said; shift 4
  local tagflag=(); [ -z "$tag" ] || tagflag=(--tags "$tag")
  for round in $(seq 1 10); do
    again=0
    for z in "$@"; do
      if gcloud compute instances create "$name" --project "$PROJECT" --zone "$z" \
          --machine-type "$type" --min-cpu-platform "AMD Milan" \
          --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
          --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --boot-disk-size 40GB \
          ${tagflag[@]+"${tagflag[@]}"} --scopes storage-rw --metadata "vg-bucket=$BUCKET,vg-mode=$MODE" \
          --metadata-from-file "vg-common=$FAILOVER/common.sh,vg-recipe=$TC/recipe.sh,vg-lib=$HERE/lib.sh,vg-go-on=$HERE/go-on.sh,startup-script=$script" >/dev/null 2>"$BUILD/boot.err"; then
        echo "$z" > "$BUILD/zone.$name"; log "   $name in $z (round $round)"; return 0
      fi
      # What the zone said, in one line: Google's own sentence when there is one.
      said="$(tr -s '\n ' '  ' < "$BUILD/boot.err")"
      case "$said" in *"message: A "*) said="A ${said#*message: A }"; said="${said%% For more information*}" ;; esac
      said="$(printf '%s' "$said" | cut -c1-300)"
      if grep -q 'configuration_availability\|is not supported in the' "$BUILD/boot.err"; then
        log "   $z does not offer this configuration for $name: $said"
      elif grep -q 'ZONE_RESOURCE_POOL_EXHAUSTED\|currently unavailable\|does not have enough resources' "$BUILD/boot.err"; then
        again=1; log "   $z has no capacity for $name: $said"
      else
        log "   $z refused $name: $said"
      fi
      gcloud compute instances delete "$name" --project "$PROJECT" --zone "$z" --quiet >/dev/null 2>&1 || true
    done
    [ "$again" = 1 ] || { log "   no zone of $* would create $name"; return 1; }
    log "   round $round: no capacity for $name; waiting 90 s"; sleep 90
  done
  log "   no capacity for $name after 10 rounds"; return 1
}

log "== 1. upload to gs://$BUCKET (private; the inputs, the hand-off, the outboxes and the records; deleted with the run)"
# The bucket is where R is: R reads both outboxes every two seconds, and
# that reading stays in one region. A's and B's uploads cost nothing to
# send; B fetches A's outbox across regions, and seldom (standby.sh).
FIRST_ZONE_R="${ZONES_R%%,*}"; BUCKET_REGION="${FIRST_ZONE_R%-*}"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location "$BUCKET_REGION" --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/sagvd" "$BUILD/acp-bootstrap" "$BUILD/acpctl" "$BUILD/keygen" \
  "$BUILD/amd-milan-cert_chain.pem" "$BUILD/worker.tgz" "gs://$BUCKET/in/" --project "$PROJECT" >/dev/null

log "== 2. boot R, the authority: $AUTHORITY (SEV-SNP, $MACHINE_R, one of ${ZONES_R//,/ })"
# shellcheck disable=SC2086  # the zone lists are split into words on purpose
boot "$AUTHORITY" "$MACHINE_R" "$HERE/authority.sh" "" ${ZONES_R//,/ }
R_IP="$(gcloud compute instances describe "$AUTHORITY" --project "$PROJECT" --zone "$(zone_of "$AUTHORITY")" --format='value(networkInterfaces[0].networkIP)')"
log "   the standby's port 8443: $R_IP admitted (rule $RULE, tag $TAG)"
gcloud compute firewall-rules create "$RULE" --project "$PROJECT" --network default --direction INGRESS --action allow \
  --rules tcp:8443 --source-ranges "$R_IP/32" --target-tags "$TAG" >/dev/null
CREATED_RULE=1

log "== 3. boot B, the standby: $STANDBY (SEV-SNP, $MACHINE, one of ${ZONES//,/ })"
# shellcheck disable=SC2086
boot "$STANDBY" "$MACHINE" "$HERE/standby.sh" "$TAG" ${ZONES//,/ }
B_IP="$(gcloud compute instances describe "$STANDBY" --project "$PROJECT" --zone "$(zone_of "$STANDBY")" --format='value(networkInterfaces[0].networkIP)')"
log "== 4. boot A, the primary: $PRIMARY (SEV-SNP, $MACHINE, $(zone_of "$STANDBY") — the standby's zone)"
boot "$PRIMARY" "$MACHINE" "$HERE/primary.sh" "" "$(zone_of "$STANDBY")"
{ echo "primary=$PRIMARY zone=$(zone_of "$PRIMARY") machine=$MACHINE"
  echo "standby=$STANDBY zone=$(zone_of "$STANDBY") machine=$MACHINE ip=$B_IP"
  echo "authority=$AUTHORITY zone=$(zone_of "$AUTHORITY") machine=$MACHINE_R ip=$R_IP"
  echo "bucket=gs://$BUCKET location=$BUCKET_REGION (deleted with the run)"
  echo "firewall=$RULE tcp:8443 from $R_IP/32 to tag $TAG (deleted with the run)"; } > "$EVIDENCE/machines.txt"

log "== 5. waiting for the primary to train, seal two generations, answer and be lost (up to 60 min)"
PRIMARY_RESULT=$(wait_for primary 60 authority standby)
log "   primary: $PRIMARY_RESULT"
collect primary
PZ="$(zone_of "$PRIMARY")"
if [ "$PRIMARY_RESULT" = DONE ]; then
  log "   the primary has switched itself off: see it dead, then delete it — on the record"
  {
    echo "primary=$PRIMARY zone=$PZ project=$PROJECT"
    for _ in $(seq 1 30); do gcloud storage cp "gs://$BUCKET/out/primary-destroyed-at.txt" "$BUILD/primary-destroyed-at.txt" --project "$PROJECT" >/dev/null 2>&1 && break; sleep 2; done
    echo "powered_off_at (the primary's clock, written just before sysrq o)=$(cat "$BUILD/primary-destroyed-at.txt" 2>/dev/null)"
    for _ in $(seq 1 60); do
      ST="$(gcloud compute instances describe "$PRIMARY" --project "$PROJECT" --zone "$PZ" --format='value(status)' 2>&1 | head -1)"
      echo "$(now) status=$ST"
      case "$ST" in TERMINATED|STOPPED) break ;; esac
      sleep 2
    done
    echo "Google's record of the machine before it is deleted:"
    gcloud compute instances describe "$PRIMARY" --project "$PROJECT" --zone "$PZ" \
      --format='yaml(name,zone.basename(),machineType.basename(),cpuPlatform,confidentialInstanceConfig,status,creationTimestamp,lastStartTimestamp,lastStopTimestamp)' 2>&1 | sed 's/^/  /'
    echo "$(now) delete: the machine and its boot disk"
    gcloud compute instances delete "$PRIMARY" --project "$PROJECT" --zone "$PZ" --quiet 2>&1 | sed 's/^/  /'
    echo "$(now) delete returned"
    AFTER="$(gcloud compute instances describe "$PRIMARY" --project "$PROJECT" --zone "$PZ" --format='value(status)' 2>&1 | tr '\n' ' ')"
    echo "$(now) after delete: $AFTER"
  } > "$EVIDENCE/operator-destroy.txt" 2>&1 || true
else
  gcloud compute instances delete "$PRIMARY" --project "$PROJECT" --zone "$PZ" --quiet >/dev/null 2>&1 || true
fi

if [ "$MODE" = turn ]; then
  log "== 6. waiting for the standby: the failover, then everything it does by itself, held to the recipe (up to 75 min)"
  STANDBY_RESULT=$(wait_for standby 75 authority)
  log "   standby: $STANDBY_RESULT"
  log "== 7. the authority is told to stop (it was to be still watching the standby)"
  echo "stop at $(now)" > "$BUILD/stop"
  gcloud storage cp "$BUILD/stop" "gs://$BUCKET/handoff/stop" --project "$PROJECT" >/dev/null 2>&1 || true
  AUTHORITY_RESULT=$(wait_for authority 15)
  log "   authority: $AUTHORITY_RESULT"
else
  log "== 6. waiting for the authority: a failover decided, and a restore that is never confirmed (up to 30 min)"
  AUTHORITY_RESULT=$(wait_for authority 30 standby)
  log "   authority: $AUTHORITY_RESULT"
  log "== 7. waiting for the standby: nothing may have started there (up to 15 min)"
  STANDBY_RESULT=$(wait_for standby 15)
  log "   standby: $STANDBY_RESULT"
fi
collect standby
collect authority
for n in "$STANDBY" "$AUTHORITY"; do
  gcloud compute instances describe "$n" --project "$PROJECT" --zone "$(zone_of "$n")" \
    --format='yaml(name,zone.basename(),machineType.basename(),cpuPlatform,confidentialInstanceConfig,status,creationTimestamp)' > "$EVIDENCE/${n%-"$LOW"}-instance.txt" 2>&1 || true
done

log "== 8. what was proven"
{ echo "primary=$PRIMARY_RESULT"; echo "standby=$STANDBY_RESULT"; echo "authority=$AUTHORITY_RESULT"; } > "$EVIDENCE/legs.txt"
# The checks are a script of their own: a record can be held to them again.
if bash "$HERE/check.sh" "$EVIDENCE" 2>&1 | tee -a "$RUNLOG"; then RESULT=PASS; fi

log "== evidence: ${EVIDENCE#"$ROOT"/}"
if [ "$RESULT" = PASS ]; then log "RESULT: PASS"; else log "RESULT: FAIL"; exit 1; fi
