# Local deployment: sagvd + acp-compute (Docker Compose)

A two-service deployment of the authority/worker pair, secured the same
way a real deployment is: every channel is authenticated.

| Channel | Protection |
|---|---|
| Worker → sagvd Return Path (`9443`) | mutual TLS 1.3 against a private CA, **then** a TEE-evidence handshake against the pinned worker key and measurement |
| Operator → REST API (`9080`) | bearer token (constant-time compared) |
| Health / metrics (`9091`, `9092`) | read-only; published on loopback only |

`sagvd` refuses to start if a listener reachable from the network would be
unauthenticated (plain-TCP Return Path or token-less REST API on a
non-loopback address). The TEE backend here is the **simulated** one — this
deployment runs on any machine. For real AMD SEV-SNP attestation see
[`docs/operator/runbooks/real-tee-sev-snp.md`](../../docs/operator/runbooks/real-tee-sev-snp.md).

## Run it (from the repository root)

```
make demo-certs    # provision deploy/compose/secrets with keygen
make demo-up       # docker compose build + up, wait for sagvd /readyz
make demo-submit   # POST /v1/jobs with the bearer token, poll the result
make demo-down     # stop and remove
```

`make demo-test` adds a health probe of both services around the
round trip.

## What keygen provisions

`deploy/compose/keygen` is a standalone, stdlib-only Go tool. It writes:

```
secrets/
  shared/
    sealing.key               32 B AES-256 session sealing key (pre-shared)
    workers.json              worker signing registry consumed by sagvd
    tls/ca.crt                private CA certificate (the CA key is never written)
  sagvd/
    tee_seed                  32 B Ed25519 seed (vault simulated TEE)
    authority_signing_seed    32 B Ed25519 seed (authority signing)
    peer_worker_pubkey        pinned worker TEE public key
    peer_worker_measurement   pinned worker workload measurement
    api_token                 REST API bearer token (64 hex chars)
    tls/server.crt|.key       Return Path server certificate (sagvd, localhost, 127.0.0.1, ::1)
  acp-compute/
    tee_seed                  32 B Ed25519 seed (worker simulated TEE)
    worker_signing_seed       32 B Ed25519 seed (CandidateOutput signing)
    peer_vault_pubkey         pinned vault TEE public key
    peer_vault_measurement    pinned vault workload measurement
    tls/client.crt|.key       Return Path client certificate
```

`secrets/` is git-ignored and docker-ignored. keygen refuses to overwrite an
existing tree without `-force`, because regenerating under a running pair
desynchronises it (sealed material stops opening, evidence stops pinning,
TLS stops verifying). Files are mode 0644 so the distroless containers
(uid 65532) can read them through the read-only bind mount; a production
deployment takes its key material from a secrets manager instead.

The workload descriptors (`sagvd-phase1-demo-v1`,
`acp-compute-phase1-demo-v1`) must match between the two `config.json`
files and `keygen/main.go`: peer measurements are SHA-256 of those strings.

## What a job does

1. `submit_job.sh` posts 1 KiB of random payload to `POST /v1/jobs` with
   `Authorization: Bearer <secrets/sagvd/api_token>`.
2. sagvd seals the payload (AES-256-GCM, AAD binding manifest, session and
   output kind), queues a `JobRequest`, and returns `202 {"job_id": …}`.
3. The worker — already connected over mTLS and past the TEE handshake —
   receives the request, unseals it, runs the reconstructor, signs the
   `CandidateOutputFrame`, and writes it back.
4. sagvd verifies the frame (bindings, size budget, Ed25519 signature under
   the registered worker key) and `GET /v1/jobs/{id}` returns the result
   with `worker_signing_key_id` — the key the signature was verified under.

The reconstructor in this deployment is the deterministic R-11 reference
reconstructor. Regeneration of a real model from a sealed genome is tracked
separately; this deployment exercises the authenticated delivery path.

## Verified by CI

The same binaries, key tree and configuration shape run on every push in
[`test/integration`](../../test/integration) (vault-gate sub-check 06): a
job round trip over mTLS, REST calls without or with a wrong token (401),
Return Path clients without a trusted certificate (refused), a worker with a
valid certificate and sealing key but a foreign TEE key (never given work),
fail-closed startup on insecure exposure, and prompt SIGTERM shutdown of
both daemons.

## Troubleshooting

- `docker logs acp-sagvd` — look for `structural` (bad config),
  `authority` (peer pin mismatch: usually a stale `secrets/` tree) or
  `integrity` (sealing-key mismatch) classifications, and for
  `sagvd TLS handshake failed` (certificate problem).
- `docker logs acp-worker` — dial failures log as `return-path cycle
  failed` with a category; the first dial can race sagvd's listener and
  recovers within a backoff step.
- `curl http://127.0.0.1:9091/readyz` / `:9092/healthz` — sagvd is ready
  once bootstrap validation passes; the worker reports ready after its
  first successful job.
- `curl http://127.0.0.1:9091/metrics` — `sagvd_handshake_failures_total`
  by `phase` (`tls` or `handshake`) shows which layer refused a peer.

## Files

- `docker-compose.yml` — services, network, bind mounts, hardening
  (read-only root FS, no new privileges, all capabilities dropped).
- `sagvd/Dockerfile`, `acp-compute/Dockerfile` — multi-stage builds on
  `golang:1.27.0-alpine` → `distroless/static-debian12:nonroot`.
- `sagvd/config.json`, `acp-compute/config.json` — in-container configs.
- `keygen/` — the provisioning tool (own module, stdlib only).
- `scripts/submit_job.sh` — submit-and-poll helper (needs curl, jq).
