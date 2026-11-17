#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The closed-turn kit's checks: what a record must say for the run to have
# shown the closed turn (or, for a negative run, that a standby whose gate
# could not pass started nothing). run.sh ends with it; a record brought
# back earlier can be held to it again. It reads the record and writes
# nothing to it.
#
# Usage: check.sh <evidence directory>
set -uo pipefail

EVIDENCE="${1:?usage: check.sh <evidence directory>}"
[ -d "$EVIDENCE" ] || { echo "no record at $EVIDENCE"; exit 2; }
MODE="$(cat "$EVIDENCE/mode.txt" 2>/dev/null || echo turn)"
P="$EVIDENCE/primary"; S="$EVIDENCE/standby"; R="$EVIDENCE/authority"
leg() { sed -n "s/^$1=//p" "$EVIDENCE/legs.txt" 2>/dev/null; }
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail=0
ok()  { log "   ok    $1"; }
bad() { log "   FAIL  $1"; fail=1; }
# j <file> <python expression over d>: one value of a JSON file; nothing when the file or the value is not there
j() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {"d": d}))' "$1" "$2" 2>/dev/null; }
# holds <file> <python expression over d>: true when the expression is
holds() { [ "$(j "$1" "$2")" = True ]; }
exact() { holds "$1" 'd.get("exact") is True and d.get("losses_equal") is True and d.get("max_abs_diff") == 0'; }
cpu() { grep -m1 'Model name' "$1/system.txt" 2>/dev/null | sed 's/.*: *//'; }
# kinds <KIND>: how many events of that kind are on the authority's audit log
kinds() { { tr ' ' '\n' < "$R/audit-kinds.txt"; } 2>/dev/null | grep -c -x "$1" || true; }

grep -E '^(generation 1: replay|answer from generation 1|toward step|sentinel running)' "$P/steps.txt" 2>/dev/null | sed 's/^/   primary    /' || true
grep -E '^(policy:|failover:|continued:|reopen generation|sagvd failover|negative:|audit:)' "$R/steps.txt" 2>/dev/null | sed 's/^/   authority  /' || true
grep -E '^(restore|answers|this machine|generation 2:|chain:|reopened:|recomputed:|second restore:|replay:|compare:|vg-|generations in|after_restore|the model|the tree)' "$S/steps.txt" 2>/dev/null | sed 's/^/   standby    /' || true

# shellcheck disable=SC2015  # ok and bad cannot fail, so `check && ok … || bad …` is if-then-else here
{
[ "$(leg primary)" = DONE ] && ok "the primary finished its part and switched itself off" || bad "the primary did not finish cleanly ($(leg primary))"
[ "$(leg standby)" = DONE ] && ok "the standby finished" || bad "the standby did not finish ($(leg standby))"
[ "$(leg authority)" = DONE ] && ok "the authority finished" || bad "the authority did not finish ($(leg authority))"
log "   the machines: primary $(cpu "$P"), standby $(cpu "$S"), authority $(cpu "$R")"
[ -n "$(cpu "$P")" ] && [ "$(cpu "$P")" = "$(cpu "$S")" ] && ok "the primary and the standby report the same CPU model" || bad "the primary and the standby do not report the same CPU model"
holds "$P/generation-1-training.json" 'd["training"]["step"] == 160 and [c["step"] for c in d["training"]["continued_from"]] == [80]' \
  && ok "generation 1 stands at step 160, continued from the genome at step 80, on the primary" || bad "generation 1 is not step 160 continued from step 80"
exact "$P/replay-1.json" && ok "on the primary, replay holds generation 1 to the whole recipe: exact" || bad "the primary's replay of generation 1 is not exact"
SENTINEL_A="$(j "$P/sentinel-identity.json" 'd["sentinel"]')"
SENTINEL_B="$(j "$S/sentinel-identity.json" 'd["sentinel"]')"
holds "$R/failover-policy.json" 'd["schema"] == "vault-genome/failover-policy/v2" and d["require_gate"] == "EXACT" and d["triggers"]["compromise_report"] is False and bool(d["standby"]["sentinel"]["public_key"]) and len(d["standby"]["sentinel"]["measurements"]) == 1' \
  && [ -n "$SENTINEL_B" ] && grep -q "standby sentinel: $SENTINEL_B " "$R/failover-verify.txt" 2>/dev/null \
  && ok "the policy, signed before the failure, is v2: it names the standby's own sentinel and the measurement its records must carry" || bad "the policy does not name the standby's sentinel"
[ -n "$SENTINEL_A" ] && [ -n "$SENTINEL_B" ] && [ "$SENTINEL_A" != "$SENTINEL_B" ] \
  && ok "the standby's sentinel key is its own: not the primary's" || bad "the two sentinels are not two keys"

if [ "$MODE" = turn ]; then
  holds "$R/report.json" 'd["status"] == "restored" and d["trigger"]["kind"] == "heartbeat-timeout" and d["genome"]["generation"] == 1 and d["restore"]["gate"]["level"] == "EXACT" and d["restore"]["required_gate"] == "EXACT"' \
    && ok "the heartbeat's silence moved generation 1 to the standby; restored, gate EXACT (required EXACT)" || bad "the failover report does not say: heartbeat-timeout, generation 1, restored, gate EXACT"
  [ -s "$P/generation-1.sha256" ] && cmp -s "$P/generation-1.sha256" "$S/restored.sha256" \
    && ok "what the standby restored is, file by file, what the primary sealed as generation 1 (7 files)" || bad "the restored genome's files are not the primary's generation 1"
  holds "$S/restore-record.json" 'd["restores"][0]["state"] == "restored" and d["restores"][0]["after_restore"]["exit_code"] == 0 and not d["restores"][0]["after_restore"].get("error")' \
    && ok "the destination ran its one command after the restore, and it ended well: nobody started anything on the standby" || bad "the restore's record does not show the after-restore command ended well"
  holds "$S/answer-restored.json" 'd["genome"]["step"] == 160' && [ -n "$(j "$S/answer-restored.json" 'd["genome"]["adapter_sha256"]')" ] \
    && [ "$(j "$S/answer-restored.json" 'd["genome"]["adapter_sha256"]')" = "$(j "$P/answer-1.json" 'd["genome"]["adapter_sha256"]')" ] \
    && [ "$(j "$S/answer-restored.json" 'd["token_ids"]')" = "$(j "$P/answer-1.json" 'd["token_ids"]')" ] \
    && ok "before training moved on, the standby answered the question from generation 1 — the tokens the primary gave from it" || bad "the standby's answer from generation 1 is not the primary's"
  grep -q "^answers from step 160: [1-9][0-9]*, all the same tokens: True" "$S/steps.txt" 2>/dev/null && grep -q "^answers from step 240: [1-9][0-9]*, all the same tokens: True" "$S/steps.txt" 2>/dev/null \
    && grep -q "from other steps: 0;" "$S/steps.txt" 2>/dev/null \
    && ok "asked again and again while training went on, the model answered from step 160, then from step 240, and from no other state" || bad "the answers during training are not from steps 160 and 240 alone"
  holds "$S/continued-training.json" 'd["training"]["step"] == 240 and [c["step"] for c in d["training"]["continued_from"]] == [80, 160] and d["losses"] == 240' \
    && ok "the standby's genome stands at step 240, continued from steps 80 and 160, with 240 losses" || bad "the continued genome is not step 240 continued from 80 and 160"
  exact "$S/replay.json" && ok "on the standby, replay holds the continued genome to the whole recipe: exact" || bad "the standby's replay of the continued genome is not exact"
  [ "$(grep -c '^same ' "$S/compare.txt" 2>/dev/null)" = 7 ] && ! grep -q '^DIFFERENT' "$S/compare.txt" && grep -q '^losses equal 240 240$' "$S/compare.txt" \
    && ok "the continued genome is, in all 7 files and all 240 losses, the recipe run on the standby in one go" || bad "the continued genome differs from the recipe run in one go"
  [ "$(cat "$S/standby-outbox-generations.txt" 2>/dev/null)" = gen-000002.seal.json ] \
    && ok "the standby's outbox holds one generation, 2: nothing was sealed from the state as restored" || bad "the standby's outbox does not hold generation 2 alone"
  holds "$S/generation-2.seal.json" 'd["generation"] == 2 and d["attestation"]["kind"] == "gcp-sev-snp"' \
    && [ -n "$SENTINEL_B" ] && [ "$(j "$S/generation-2.seal.json" 'd["sentinel"]')" = "$SENTINEL_B" ] \
    && [ -n "$(j "$P/generation-1.seal.json" 'd["bundle_sha256"]')" ] && [ "$(j "$S/generation-2.seal.json" 'd["parent_bundle_sha256"]')" = "$(j "$P/generation-1.seal.json" 'd["bundle_sha256"]')" ] \
    && ok "generation 2 is sealed by the standby's sentinel, attested by its chip, and names the primary's generation 1 as its parent" || bad "generation 2's record is not the standby sentinel's, attested, with generation 1 as its parent"
  grep -q "3 generation(s)" "$S/chain.txt" 2>/dev/null && grep -q "chain valid" "$S/chain.txt" \
    && ok "the two machines' bundles are one chain of three generations" || bad "the chain across the two machines is not whole"
  holds "$R/report-continued.json" 'd["continued"]["generation"] == 2 and d["continued"]["parent_generation"] == 1 and d.get("standby_trigger") is None' \
    && [ -n "$SENTINEL_B" ] && [ "$(j "$R/report-continued.json" 'd["continued"]["sentinel"]')" = "$SENTINEL_B" ] \
    && [ "$(j "$R/report-continued.json" 'd["continued"]["bundle_sha256"]')" = "$(j "$S/generation-2.seal.json" 'd["bundle_sha256"]')" ] \
    && [ "$(kinds CHAIN_CONTINUED)" = 1 ] && [ "$(kinds FAILOVER_DECIDED)" = 1 ] \
    && ok "the authority recorded it: one CHAIN_CONTINUED on its audit log, generation 2 after 1, under the standby's sentinel" || bad "the authority's report and log do not carry the chain's continuation"
  grep -q "^reopen generation 2: release exit=0 confirm exit=0$" "$R/steps.txt" 2>/dev/null && [ -s "$S/continued.sha256" ] && cmp -s "$S/reopened.sha256" "$S/continued.sha256" \
    && ok "generation 2, released again by the authority and opened under the gate, is file by file what training made on the standby" || bad "generation 2 opened again is not what training made on the standby"
  holds "$S/answer-continued.json" 'd["genome"]["step"] == 240' && [ -n "$(j "$S/answer-continued.json" 'd["token_ids"]')" ] \
    && [ "$(j "$S/answer-continued.json" 'd["genome"]["adapter_sha256"]')" = "$(j "$S/continued-training.json" 'd["adapter_sha256"]')" ] \
    && [ "$(j "$S/answer-reopened.json" 'd["token_ids"]')" = "$(j "$S/answer-continued.json" 'd["token_ids"]')" ] \
    && [ "$(j "$S/answer-reopened.json" 'd["genome"]["adapter_sha256"]')" = "$(j "$S/answer-continued.json" 'd["genome"]["adapter_sha256"]')" ] \
    && ok "the answer the listener gave from step 240 names its generation, and recomputed from the sealed generation 2 it is the same tokens" || bad "the answer from step 240 is not reproduced from the sealed generation 2"
  grep -q "^second restore: after_restore exit=0; 1 line(s) of go-on.log say the machine already goes on$" "$S/steps.txt" 2>/dev/null \
    && grep -q "^vg-sentinel: active$" "$S/services.txt" 2>/dev/null && grep -q "^vg-answer: active$" "$S/services.txt" && grep -q "^generations in this machine's outbox: 1$" "$S/services.txt" \
    && ok "the second restore started nothing again: one sentinel, one listener, one generation in the standby's outbox" || bad "the second restore did not leave the standby as it was"
  grep -q "^sagvd failover still watching the standby when told to stop: yes$" "$R/steps.txt" 2>/dev/null && grep -q "^sagvd failover exit=0$" "$R/steps.txt" \
    && ok "the authority did not exit after the failover: it was watching the standby until it was told to stop" || bad "the authority was not watching the standby to the end"
else
  holds "$R/report.json" 'd["status"] == "failed" and d["trigger"]["kind"] == "heartbeat-timeout" and d["genome"]["generation"] == 1 and d.get("continued") is None' \
    && grep -q "^sagvd failover exit=1$" "$R/steps.txt" 2>/dev/null \
    && ok "the heartbeat's silence decided a failover of generation 1; it did not complete, and the authority says so (exit 1)" || bad "the authority's report does not say: heartbeat-timeout, generation 1, failed"
  [ "$(kinds FAILOVER_DECIDED)" = 1 ] && [ "$(kinds CROSS_CLOUD_RESTORE_COMPLETED)" = 0 ] && [ "$(kinds CHAIN_CONTINUED)" = 0 ] \
    && ok "on the authority's audit log: the failover decided; no restore completed, no chain continued" || bad "the authority's audit log does not say: a failover decided, no restore, no chain"
  [ -s "$S/base-config-before.sha256" ] && [ -s "$S/base-config-after.sha256" ] && ! cmp -s "$S/base-config-before.sha256" "$S/base-config-after.sha256" \
    && ok "the standby's base model was not the genome's: one file of it differed" || bad "the standby's base model was not changed"
  holds "$S/restore-record.json" 'd["restores"][0]["state"] == "failed" and "base model does not match" in d["restores"][0]["error"] and d["restores"][0].get("after_restore") is None' \
    && ok "the standby's restore failed at its gate, and the record says why: the base model does not match the genome's manifest" || bad "the standby's restore record does not say: failed, the base model does not match"
  grep -q "^after_restore on the record: no$" "$S/nothing-started.txt" 2>/dev/null && grep -q ": none$" "$S/nothing-started.txt" \
    && ok "nothing started on the standby: no model directory, no outbox, no units, no listener, no process" || bad "something started on the standby"
fi
holds "$R/audit-verify.json" 'd.get("ok") is True' && ok "the authority's audit log verifies offline" || bad "the authority's audit log does not verify"
[ -s "$S/verdict.txt" ] && ok "$(cat "$S/verdict.txt")" || bad "the standby wrote no verdict"
[ -s "$R/verdict.txt" ] && ok "$(cat "$R/verdict.txt")" || bad "the authority wrote no verdict"
}
[ "$fail" = 0 ]
