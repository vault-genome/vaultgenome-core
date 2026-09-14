#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# submit_job.sh — POST a demo job to the running sagvd and poll the
# result. Invoked by the `demo-submit` Makefile target, but safe to
# run standalone once `make demo-up` has brought the stack up.
#
# Usage:
#   ./submit_job.sh                  # defaults: 1 KiB payload, 60 s poll
#   SAGVD_URL=http://... ./submit_job.sh
#   PAYLOAD_SIZE=4096 DEADLINE=30 ./submit_job.sh
#
# Environment (all optional):
#   SAGVD_URL      base URL of sagvd's HTTP API (default http://127.0.0.1:9080)
#   MANIFEST_ID    JobRequest.ManifestID (default demo-manifest-<ts>)
#   SESSION_ID     JobRequest.SessionID (default demo-session-<ts>)
#   OUTPUT_KIND    ExpectedOutputKind   (default "lora-adapter-demo")
#   OUTPUT_MAX     ExpectedOutputMaxBytes (default 4096)
#   PAYLOAD_SIZE   bytes of /dev/urandom to seal as the job payload (default 1024)
#   DEADLINE       deadline_seconds_from_now (default 60)
#   POLL_INTERVAL  seconds between GET polls (default 1)
#   POLL_TIMEOUT   total seconds to wait before giving up (default 60)
#   BEARER_TOKEN   REST API token; defaults to the contents of
#                  $SECRETS_DIR/sagvd/api_token (written by keygen)
#   SECRETS_DIR    secrets tree (default: ../secrets relative to this script)
#
# Exit codes:
#   0  — job reached JobStatusSucceeded, result printed as JSON
#   1  — submission failed (HTTP != 202)
#   2  — poll timed out (job neither succeeded nor failed in POLL_TIMEOUT)
#   3  — job reached JobStatusFailed
#   4  — prerequisites missing (curl / jq / base64, or no bearer token)

set -o errexit
set -o pipefail
set -o nounset

# ---- prerequisites --------------------------------------------------------

# We demand jq because the response is JSON with nested fields. A
# plain shell script with ad-hoc grep/sed over JSON would be fragile
# and silently lose negative test signal (e.g., a 202 body with an
# unexpected shape).
for tool in curl jq base64; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "submit_job.sh: missing prerequisite: $tool" >&2
    exit 4
  fi
done

# ---- defaults -------------------------------------------------------------

SAGVD_URL="${SAGVD_URL:-http://127.0.0.1:9080}"
NOW_EPOCH="$(date +%s)"
MANIFEST_ID="${MANIFEST_ID:-demo-manifest-${NOW_EPOCH}}"
SESSION_ID="${SESSION_ID:-demo-session-${NOW_EPOCH}}"
OUTPUT_KIND="${OUTPUT_KIND:-lora-adapter-demo}"
OUTPUT_MAX="${OUTPUT_MAX:-4096}"
PAYLOAD_SIZE="${PAYLOAD_SIZE:-1024}"
DEADLINE="${DEADLINE:-60}"
POLL_INTERVAL="${POLL_INTERVAL:-1}"
POLL_TIMEOUT="${POLL_TIMEOUT:-60}"

# Trim any trailing slash on SAGVD_URL so the /v1 concatenation below
# never produces double slashes (which sagvd's router would 404).
SAGVD_URL="${SAGVD_URL%/}"

# The REST API requires a bearer token. Default to the one keygen wrote.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="${SECRETS_DIR:-${SCRIPT_DIR}/../secrets}"
if [[ -z "${BEARER_TOKEN:-}" && -r "${SECRETS_DIR}/sagvd/api_token" ]]; then
  BEARER_TOKEN="$(tr -d '[:space:]' < "${SECRETS_DIR}/sagvd/api_token")"
fi
if [[ -z "${BEARER_TOKEN:-}" ]]; then
  echo "submit_job.sh: no bearer token — set BEARER_TOKEN or run 'make demo-certs'" >&2
  exit 4
fi

# ---- payload --------------------------------------------------------------

# We generate PAYLOAD_SIZE bytes of randomness and base64-encode them.
# On macOS and Linux, `base64` differs in line-wrapping defaults:
# macOS wraps at 76; GNU base64 wraps unless -w0 is passed. We
# normalise the output with a tr to strip any newlines so the JSON
# body is a single line and we don't trip strict JSON lexers that
# reject unescaped newlines in strings.
PAYLOAD_B64="$(head -c "$PAYLOAD_SIZE" /dev/urandom | base64 | tr -d '\n')"

REQUEST_BODY="$(jq -nc \
  --arg manifest_id "$MANIFEST_ID" \
  --arg session_id "$SESSION_ID" \
  --arg kind "$OUTPUT_KIND" \
  --argjson max "$OUTPUT_MAX" \
  --argjson deadline "$DEADLINE" \
  --arg payload "$PAYLOAD_B64" \
  '{
     manifest_id: $manifest_id,
     session_id: $session_id,
     expected_output_kind: $kind,
     expected_output_max_bytes: $max,
     deadline_seconds_from_now: $deadline,
     payload_base64: $payload,
   }')"

# ---- submit ---------------------------------------------------------------

AUTH_HEADER=()
if [[ -n "${BEARER_TOKEN:-}" ]]; then
  AUTH_HEADER+=(-H "Authorization: Bearer ${BEARER_TOKEN}")
fi
# Workaround for `set -o nounset` + bash 3.2 (default macOS): an empty
# array expanded with [@] without :- yields "unbound variable". Pinning
# the default-empty form here keeps every curl invocation safe.
auth_args() { if [[ ${#AUTH_HEADER[@]} -gt 0 ]]; then printf '%s\n' "${AUTH_HEADER[@]}"; fi; }

echo "submit_job.sh: submitting to ${SAGVD_URL}/v1/jobs ..."
echo "  manifest_id = ${MANIFEST_ID}"
echo "  session_id  = ${SESSION_ID}"
echo "  output_kind = ${OUTPUT_KIND}"
echo "  payload     = ${PAYLOAD_SIZE} bytes of /dev/urandom"

# Capture body and status separately so we can act on non-202s.
HTTP_RESPONSE="$(mktemp)"
trap 'rm -f "$HTTP_RESPONSE"' EXIT

HTTP_STATUS="$(curl \
  --silent \
  --show-error \
  --fail-with-body \
  --output "$HTTP_RESPONSE" \
  --write-out '%{http_code}' \
  -X POST \
  -H 'Content-Type: application/json' \
  ${AUTH_HEADER[@]+"${AUTH_HEADER[@]}"} \
  --data-binary "$REQUEST_BODY" \
  "${SAGVD_URL}/v1/jobs" \
  || true)"

if [[ "$HTTP_STATUS" != "202" ]]; then
  echo "submit_job.sh: POST /v1/jobs returned HTTP ${HTTP_STATUS}" >&2
  cat "$HTTP_RESPONSE" >&2 || true
  echo >&2
  exit 1
fi

JOB_ID="$(jq -r '.job_id' < "$HTTP_RESPONSE")"
if [[ -z "$JOB_ID" || "$JOB_ID" == "null" ]]; then
  echo "submit_job.sh: 202 response missing job_id" >&2
  cat "$HTTP_RESPONSE" >&2
  exit 1
fi

echo "submit_job.sh: accepted as job_id=${JOB_ID}"

# ---- poll -----------------------------------------------------------------

DEADLINE_EPOCH=$(( $(date +%s) + POLL_TIMEOUT ))

while : ; do
  # We treat a non-200 from GET as a transient network blip and
  # retry within POLL_TIMEOUT — sagvd's GET /v1/jobs/{id} is a pure
  # in-memory lookup so a sustained failure here means the process
  # died, which we surface by running out of clock.
  GET_OUTPUT="$(curl \
    --silent \
    --show-error \
    --fail \
    ${AUTH_HEADER[@]+"${AUTH_HEADER[@]}"} \
    "${SAGVD_URL}/v1/jobs/${JOB_ID}" \
    || true)"

  if [[ -n "$GET_OUTPUT" ]]; then
    STATUS="$(jq -r '.status // empty' <<<"$GET_OUTPUT")"
    case "$STATUS" in
      succeeded)
        echo "submit_job.sh: job succeeded"
        # Pretty-print the final job view. The JSON is intentionally
        # stable across runs (sagvd writes it via CandidateView).
        jq . <<<"$GET_OUTPUT"
        exit 0
        ;;
      failed)
        echo "submit_job.sh: job failed" >&2
        jq . <<<"$GET_OUTPUT" >&2
        exit 3
        ;;
      queued|running)
        # Keep polling.
        :
        ;;
      *)
        # Unknown status. Don't hard-fail; log and keep polling so a
        # transient schema-version mismatch between the script and
        # sagvd doesn't immediately tank the demo.
        echo "submit_job.sh: unexpected status '${STATUS}'; continuing" >&2
        ;;
    esac
  fi

  if (( $(date +%s) >= DEADLINE_EPOCH )); then
    echo "submit_job.sh: timed out after ${POLL_TIMEOUT}s waiting for job ${JOB_ID}" >&2
    echo "  last observed body:" >&2
    echo "  ${GET_OUTPUT:-<empty>}" >&2
    exit 2
  fi

  sleep "$POLL_INTERVAL"
done
