# The operator REST API — the reference for an integrator

| Daemon | `sagvd` — the release authority |
| - | - |
| Listener | `http_api.listen_address` (default `127.0.0.1:9080`) |
| Authentication | `Authorization: Bearer <token>`; the token from `http_api.bearer_token_file` (or `http_api.bearer_token`), compared in constant time |
| Routes | `POST /v1/jobs`, `GET /v1/jobs/{id}` — nothing else |
| Health and metrics | `health.listen_address` (default `127.0.0.1:9091`): `GET /healthz`, `GET /readyz`, `GET /metrics` |
| Source | `cmd/sagvd/http_api.go`, `job_queue.go`, `genome_job.go`; the shapes below are the Go types' JSON |
| Last checked against the code | 2026-10-21 (v0.6.0 + #127–#135): `scripts/check-api-reference.py` compares this page's shapes with a run's `job-submit.json` and `job.json`; last run `scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20261021T002717Z` on real SEV-SNP, every shape the run's |

This is the whole surface a business integrates with: one call to ask
the authority to bring a sealed model back on an attested worker, and
one call to read what happened — the verdict, the signed artefacts and
every stage of the flow. Everything else (sealing a genome, provisioning
hosts, verifying the record) is `acpctl` on the operator's side, in
[`cli.md`](cli.md).

## Before the first call

- **Where it listens.** Off loopback the daemon refuses to start without
  a bearer token of at least 32 characters; on loopback the token is
  optional. The API speaks plain HTTP: put it behind the host's own TLS
  terminator or keep it on loopback and call it from the host. The
  Return Path listener for workers is a separate port with mutual TLS
  1.3 and is not this API.
- **What a job needs.** A sealed genome in `genome.bundle_dir` on the
  authority's host — the `.genome` bundle and either its key file (from
  `acpctl genome seal --key-out`) or, when the bundle was sealed with
  `--escrow-to`, nothing: the authority opens the `<bundle>.escrow`
  envelope with its own escrow key. `POST /v1/jobs` is refused with 503
  `gate_jobs_disabled` when `genome.bundle_dir` is not configured.
- **Who answers.** A pinned `acp-compute` worker must be connected (the
  handshake attested); a job waits in the queue until one is.

## `POST /v1/jobs` — ask for a model to come back

Admits a recovery request: the authority opens the named bundle,
records the request on the audit chain (`REQUEST_RECEIVED`) before
anything else happens, and queues the job. Returns **202 Accepted**.

Request body (JSON, at most 64 KiB, unknown fields refused):

| Field | Type | Meaning |
| - | - | - |
| `genome.bundle` | string, required | the `.genome` file's name in `genome.bundle_dir` |
| `genome.key_file` | string | the key file's name there; absent → the `<bundle>.escrow` envelope is opened with the authority's escrow key |
| `deadline_seconds_from_now` | integer | how long the worker has once the job is handed to it; `0` or absent takes `runtime.default_job_deadline_seconds`, which is also the ceiling (400 `deadline_exceeds_ceiling` above it) |
| `request_id` | string | the request's own name, `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`; minted as `req-<hex>` when absent; a name already admitted is refused with 409 |
| `policy_profile` | string | the policy envelope asked for; the daemon serves `gate` (the default) — any other is denied at trust admission, on the record |
| `requester_identity` | string | who asks; default `operator:rest` |
| `contour` | object of strings | the request's own context (jurisdiction, role, …), carried verbatim on the request and its audit record; at most 16 entries, each field at most 128 characters |

Response, 202:

```json
{
  "job_id": "3e58aeb8e02128bf064b888fbf42a4c0",
  "request_id": "req-aa40a2f2c3c091da",
  "state": "trust",
  "genome": {
    "bundle": "gen-0.genome",
    "key_id": "genome-dbd20acf0ff4-g0-91479fdd3087",
    "key_source": "key_file",
    "bundle_sha256": "a68da955a013398918b823f7262bd269cd5393f6789f29c8cd32fc7585ac288b",
    "payload_sha256": "sha256:dbd20acf0ff4ae033d26dd865c7aca929a9aedcf610764017c21eaf4bb331140",
    "generation": 0,
    "base": "tiny-llama",
    "base_digest": "sha256:b584112f848a9f5430ef1038a51a58413e099b7754f8aad46ec9f1b287382854",
    "files": 4,
    "bytes": 15038,
    "fixtures": 6,
    "critical": 4
  }
}
```

(`scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20261017T122254Z/job-submit.json`,
the acceptance trial's T1.) `state` is the flow's state at admission;
`genome` is the bundle as the authority read it — its hashes, its base
model and digest, what will be shipped to the worker, and how many
fixtures (and how many critical ones) the gate will run. Nothing in it
is secret.

Refusals:

| Status | `error.code` | When |
| - | - | - |
| 400 | `decode_body`, `trailing_data` | not one JSON object |
| 400 | `deadline_invalid`, `deadline_exceeds_ceiling`, and the validation codes of the request's fields | a field out of its rule |
| 401 | `auth_missing` | no `Authorization: Bearer` (category `authority`) |
| 405 | `method_not_allowed` | with an `Allow` header |
| 409 | `intake.duplicate_request` | the `request_id` was admitted before |
| 503 | `gate_jobs_disabled` | `genome.bundle_dir` not configured |
| 503 | `audit_unavailable` | the audit chain refused the record — nothing is admitted that is not on the record |

## `GET /v1/jobs/{id}` — read what happened

Returns **200** with the job's view, at any point of its life; 404
`job_not_found` for an id the queue does not know (and `not_found` for
any other path under `/v1/jobs/`). The view is complete after
`completed_at` is set; before that, poll — there is no push.

| Field | Type | Meaning |
| - | - | - |
| `job_id`, `request_id` | string | as returned by the submission |
| `status` | `queued` · `running` · `succeeded` · `failed` | the queue's word |
| `state` | string | the flow's state, in order: `unstarted`, `request`, `trust`, `session`, `disclosure`, `external_compute`, `return`, `validation`, `release`, `audit`, `release_authorized`; `incident_terminated` when the incident module ended the flow; `cross_cloud_handshake` on a cross-cloud restore; `invalid` is a view the daemon never serves |
| `submitted_at`, `started_at`, `completed_at`, `deadline` | RFC 3339 | the queue's clock |
| `manifest_id`, `session_id` | string | the bootstrap manifest and the Return Path session of this job |
| `expected_output_kind` | string | what the worker must return (`bytes/fixed-length`) |
| `genome` | object | as in the submission response |
| `gate` | object | the gate's verdict — below |
| `top1` | object | the top-1 agreement report: `total`, `agreed`, `critical_disagreed`, `results` |
| `result` | object | on success: `output_kind`, `bytes_hex`, `byte_count`, `produced_at`, `worker_signing_key_id` — the released candidate output, hex-encoded |
| `error` | object | on failure: `category`, `code`, `message` |
| `flow` | object | every stage, for verification: `state`, `steps`, `request`, `attestation`, `session`, `disclosures`, `manifest`, `candidate`, `validation`, `decision`, `audit_tip` |

The gate:

| Field | Meaning |
| - | - |
| `level` | `EXACT` or `EQUIVALENT` when a door opened; `FAIL` when every door judged the outputs and refused them; `ERROR` when no door could judge |
| `door`, `rung`, `kind` | which door opened: rung 0 `pinned-replay` (the pinned runtime, byte-exact), rung 1 `native-float` (within the tolerance of `genome.gate`), rung 2 `fixed-point` — the integer door, byte-exact across devices (ADR 0020); `door` is the same name with a space (`pinned replay`, `native float`, `integer`) |
| `fixtures` | how many reference fixtures were run |
| `attempts` | one per rung tried: `rung`, `kind`, `name`, `level`, `max_abs_err`, `err` |
| `signed_verdict` | the passing verdict signed by the authority: `verdict`, `signature`, `signer_pub` — absent when no door opened |
| `signer_key_id` | the authority's signing key id, the one `sagvd identity` prints |

`flow.attestation` is the trust decision on the worker (`outcome`
`allow` or `deny`, `reason`, the signing key and signature);
`flow.decision` the release decision; `flow.audit_tip` the hash of the
last audit event this job appended. A refused or failed job carries the
reason in `error` (`category`, `code`, `message`) with `status: failed`.

Example of a finished job's top: `scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20261017T122254Z/job.json`
— `status: succeeded`, `state: release_authorized`, `gate.level: EXACT`,
`gate.door: pinned replay`, `gate.fixtures: 6`, `gate.signer_key_id:
sagvd-authority-e2e`.

## Verifying what the API says

The API is a view; the record is the audit chain, and an integrator
does not have to take the view's word:

- `acpctl audit query --audit <log> --request <request_id>` prints every
  event of the request, and `acpctl audit verify --audit <log>
  --audit-pubkey <pem>` verifies the chain under the published audit key
  — across closed segments, with exit 4 on a broken chain
  ([`cli.md`](cli.md), ADR 0027);
- `gate.signed_verdict` verifies under the authority's signing key
  (`equivalence.VerifySigned` in `internal/validation/equivalence`; the
  key from `sagvd identity`);
- `result.worker_signing_key_id` names the worker whose chip attested in
  `flow.attestation`.

## Health and metrics

On `health.listen_address`, loopback only: `/healthz` answers `ok` while
the process runs, `/readyz` answers `ready` once the Return Path
listener is bound, `/metrics` is the Prometheus exposition. The API
counts itself as `sagvd_http_requests_total{route,status}` and
`sagvd_jobs_submitted_total`; the names an alerting stack consumes are
in [`../operator/04_observability.md`](../operator/04_observability.md).

## What the API does not do

No listing of jobs, no cancellation, no streaming, no deletion: a job's
view stays until the retention window of `queue.retain_finished_seconds`
expires it (ADR 0027), and the audit chain keeps the record after that.
No upload: the API names files on the authority's host; sealing and
placing a genome is `acpctl genome seal`. No user identity: the bearer
token is one credential for the operator's integration; who asked is
`requester_identity`, carried on the record as given.

## Configuration keys that matter here

| Key | Default | Note |
| - | - | - |
| `http_api.listen_address` | `127.0.0.1:9080` | the API |
| `http_api.bearer_token_file` / `http_api.bearer_token` | — | required off loopback (≥ 32 characters) |
| `health.listen_address` | `127.0.0.1:9091` | health and metrics |
| `genome.bundle_dir` | — | where `POST /v1/jobs` finds bundles; unset disables gate jobs |
| `runtime.default_job_deadline_seconds` | per deployment | the default and ceiling of `deadline_seconds_from_now` |
| `queue.retain_finished_seconds` | per deployment | how long a finished job's view is kept |

## The console's listener

`console.listen_address` starts a second listener for people's consoles
([ADR 0039](../adr/0039-the-console-a-persons-hands-verified-on-their-computer.md)):
mutual TLS 1.3, the client's Ed25519 key checked against `console.dir/people.json`,
the server's certificate pinned by the pass. It is the console's wire and not an
integration surface; the shapes are `internal/console`'s.

| Route | Who | What |
| - | - | - |
| `POST /v1/console/join` | any key | Redeems a pass's single-use code; the key goes on the list |
| `POST /v1/console/check` | everyone listed | The state as bytes and the chip's evidence over the challenge, the listener's certificate and the state |
| `GET /v1/console/journal?from=N` | everyone listed | Up to 500 records of the live segment, as signed |
| `GET /v1/console/jobs/{id}` | everyone listed | A job without its model output |
| `POST /v1/console/restore-check` | `operator`, `owner` | A gate job on the newest sealed genome, `requester_identity` `person:<name>` |
| `PUT /v1/console/stop` | `owner` | A stop list signed under the operator key; refused unless newer than the one in force |
| `POST /v1/console/invites` | `owner` | A new single-use code |
| `POST /v1/console/people/remove` | `owner` | Takes a person off the list; not the holder of the stop |

A refusal is `{"code","message"}`. What a person changes is a `CONSOLE_ACTION` audit
event written before it takes effect: 503 `audit_unavailable` means nothing changed.
