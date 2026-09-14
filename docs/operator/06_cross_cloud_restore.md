# Operator Runbook 06 — Cross-Cloud Key Release

**Design:** [ADR 0006](../adr/0006-cross-cloud-kms-mediated-restore.md) (flow, audit kinds) and
[ADR 0009](../adr/0009-x25519-kem-cross-cloud-key-delivery.md) (how keys travel).
**Proven by:** `test/integration/crosscloud_test.go`, which runs every step below with the real binaries.

---

## What this runbook covers

Releasing data-encryption keys (DEKs) from a **source authority** (`sagvd`) to a
**destination** (`acp-bootstrap`) on another machine or cloud, only after the
destination proves — by remote attestation — that it is a genuine TEE running a
workload the source operator allow-listed.

What the shipping binaries do today, stated exactly:

- `acp-bootstrap` attests with **AMD SEV-SNP** (`tee.provider: "gcp-sev-snp"`,
  reports through the kernel's configfs-tsm on a Confidential VM) or with the
  **simulated** backend, whose Evidence is signed by a key derived from a seed
  file — that proves the protocol, not hardware isolation. The examples below
  use the simulator so they run anywhere; the SEV-SNP settings are in
  [runbooks/real-tee-sev-snp.md](runbooks/real-tee-sev-snp.md) §D. `sagvd`'s
  verifier registry accepts `simulated` and `gcp-sev-snp` and refuses every
  other family until its verifier runs end to end.
- The DEKs a destination receives are registered in that `acp-bootstrap`
  process's in-memory keystore. Using them to open a sealed genome on the
  destination is the next step of the Drill and is not yet part of the binary.

## How a key travels

```
 source: sagvd crosscloud-restore                    destination: acp-bootstrap
 ────────────────────────────────                    ──────────────────────────
 signed handshake, fresh nonce N   ── TLS 1.3 ──▶    verify authority signature
                                                     new X25519 key pair (sk, pk)
                                   ◀── Evidence ──   quote over C = H(label ‖ pk ‖ N)
 verify Evidence under C                             (sk stays in memory, 5 min,
 (genuine TEE + measurement +                         one token)
  freshness + pk is the TEE's own)
 allow-list policy on measurement
 encapsulate DEKs to pk
 signed key-release token          ── TLS 1.3 ──▶    take sk (single use), open DEKs,
                                                     register, zeroize sk
```

A destination that presents no attested key, an Evidence that does not verify
for the presented key, or a measurement that is not on the allow-list gets no
token. There is no fallback path.

---

## Pre-flight: exchange identities

Each side prints what the other pins. Neither command opens a listener.

**Source** — the authority key every destination verifies handshakes and tokens against:

```bash
sagvd identity -config /etc/acp/sagvd.json > authority.json
jq -r .authority_public_key_pem authority.json > authority.pem   # give to the destination
jq -r .authority_kid authority.json                               # the kid the destination pins
```

**Destination** — the TEE family, measurement and (simulated backend) attestation key:

```bash
acp-bootstrap identity -config /etc/acp/acp-bootstrap.json > destination.json
jq -r .attestor_public_key_pem destination.json > destination-attestor.pem   # give to the source
jq -r .measurement_hex destination.json                                      # goes on the allow-list
```

Compare the SHA-256 of each file over a second channel before pinning it.

## Destination configuration (`acp-bootstrap`)

```json
{
  "http": {
    "listen_address": "0.0.0.0:8443",
    "bearer_token_file": "/etc/acp/secrets/acp-bootstrap/api_token",
    "tls": {
      "enabled": true,
      "server_cert": "/etc/acp/secrets/acp-bootstrap/tls/server.crt",
      "server_key": "/etc/acp/secrets/acp-bootstrap/tls/server.key",
      "client_cas": "/etc/acp/secrets/shared/tls/ca.crt"
    }
  },
  "tee": {
    "provider": "simulated",
    "workload_descriptor": "acp-bootstrap-destination-v1",
    "seed_path": "/etc/acp/secrets/acp-bootstrap/tee_seed"
  },
  "source_authority": {
    "kid": "sagvd-authority-demo",
    "public_key_path": "/etc/acp/authority.pem"
  },
  "health": { "listen_address": "127.0.0.1:8444" },
  "log": { "level": "info", "format": "json" }
}
```

Exposure rules are enforced at startup; a config that breaks one does not start:

- Beyond a loopback address the listener must use TLS. It speaks **TLS 1.3 only**.
- Beyond loopback, callers must present a client certificate (`client_cas`) or a
  bearer token of at least 32 characters (`bearer_token_file`, or inline
  `bearer_token`); configure both for defence in depth.
- `seed_path` (simulated only) is a 32-byte file; `public_key_path` accepts the
  PEM printed by `sagvd identity` or the raw 32 bytes.
- `tee.provider` is also the only `destination_tee_kind` the daemon answers; a
  handshake declaring another kind is refused.

The health listener answers `/healthz` and `/readyz` and exposes nothing else.

## Source configuration (`sagvd`)

Add a `crosscloud` section to the usual `sagvd` config:

```json
"crosscloud": {
  "enabled": true,
  "policy_version": "xcc-2026-09-14",
  "policy_allow_list_path": "/etc/acp/crosscloud/allow.json",
  "verifier_registry_path": "/etc/acp/crosscloud/verifiers.json",
  "transport_bearer_token": "<the destination's bearer token>",
  "request_timeout_seconds": 30,
  "transport_tls": {
    "enabled": true,
    "client_cert": "/etc/acp/secrets/sagvd/tls/client.crt",
    "client_key": "/etc/acp/secrets/sagvd/tls/client.key",
    "ca_bundle": "/etc/acp/secrets/shared/tls/ca.crt"
  }
}
```

`verifiers.json` — how to check each destination family's Evidence:

```json
{ "verifiers": [ {
  "provider": "simulated",
  "attestor_pubkey_path": "/etc/acp/crosscloud/destination-attestor.pem",
  "expected_measurement_hex": "<measurement_hex from acp-bootstrap identity>"
} ] }
```

`allow.json` — the operator's release policy. Its `version` must equal
`policy_version`, or `sagvd` refuses to load it:

```json
{ "version": "xcc-2026-09-14",
  "allowed": { "simulated": ["<measurement_hex from acp-bootstrap identity>"] } }
```

Measurements are pinned whole: 32, 48 (SEV-SNP, Nitro) or 64 bytes.

## Releasing keys

```bash
sagvd crosscloud-restore \
  -config /etc/acp/sagvd.json \
  -decision-id dec-2026-09-14-001 \
  -destination-kind simulated \
  -destination-endpoint https://destination.example.com:8443 \
  -key genome-dek-1:<64 hex chars>
```

`-key kid:hex` repeats for several DEKs. The endpoint must be `https`, except to
a loopback destination. The command prints one JSON report and exits 0 on
success, 1 on any refusal:

```json
{
  "status": "ok",
  "handshake_request_id": "…",
  "handshake_audit_id": "…",
  "attestation_audit_id": "…",
  "key_release_audit_id": "…",
  "destination_measurement_hex": "…",
  "recipient_key_sha256": "…",
  "policy_version": "xcc-2026-09-14",
  "token_id": "…",
  "dispatched_at": "2026-09-14T12:00:00.000Z",
  "audit_chain_length": 3
}
```

**Confirm it landed.** The destination logs `crosscloud handshake answered` with
a `recipient_key_sha256`, then `crosscloud token accepted` with the same
`request_id` and `registered_keys`. The digest must equal the report's
`recipient_key_sha256`: it identifies the one key the DEKs were sealed to.

## When a release is refused

| Report `error.category` | Audit events | Meaning | What to do |
|---|---|---|---|
| — (exit 1, no report) | none | Bad flags, `http://` to a remote host, or config/material failed to load | Fix the invocation or config; the message names the field |
| `operational` | handshake initiated | The handshake did not complete: destination unreachable, TLS refused (no client certificate, TLS below 1.3), bearer token rejected, or the destination refused the request — the message carries its answer (e.g. a TEE kind it does not run, an authority key it does not trust) | Check the listener, certificates, token, and the identities each side pinned |
| `integrity` | handshake initiated | Evidence did not verify for the presented key — wrong attestor key, wrong measurement, a replayed or substituted answer — or the destination presented no usable key | Treat an unexpected one as possible impersonation; re-check the pinned identities |
| `authority` | handshake initiated, attestation verified | The destination is genuine but its measurement is not on the allow-list | Intended: add the measurement to a new policy version only if you mean to trust it |
| `operational` | all three | The token did not reach the destination, or the destination refused it — the message carries its answer (no outstanding handshake: expired or used; decision mismatch; signature) | Run the command again: a new handshake mints a new key and the old one expires unused. If it repeats, read the destination's `crosscloud token rejected` log line |

## Rotating what you trust

- **New destination measurement** (upgrade, new image): print its identity,
  write a new allow-list with a new `version`, set the same value as
  `policy_version`. Each `crosscloud-restore` run reads the files afresh.
- **Revoking a destination:** remove its measurement from the allow-list (new
  version). No further key reaches it; keys it already holds stay where they are.
- **Authority key:** rotate the seed, run `sagvd identity`, re-pin
  `authority.pem` at every destination and restart `acp-bootstrap`; handshakes
  and tokens signed by the old key are then refused.
- **Bearer token:** replace the file at the destination (restart
  `acp-bootstrap`) and the value at the source together; it is defence in depth
  on top of the signatures.

## Security properties you can rely on

- Holding a token — with or without the measurement it names — reveals no DEK.
- A destination key opens exactly one token and dies after five minutes.
- A replayed handshake cannot replace an outstanding key; a forged token is
  rejected before it can use one up.
- Every release is preceded by the three audit events, in order, recorded before
  the step they describe (the report's `audit_chain_length`).

## Known limits

- The destination attests with real hardware only on SEV-SNP; other TEE families
  are refused on both sides until their producers and verifiers run end to end.
- `crosscloud-restore` keeps its audit chain in process memory and reports its
  length; persisting it as a signed, append-only log that auditors can verify
  offline is scheduled work, not present today.
- There is no command yet for the fourth audit kind
  (`KindCrossCloudRestoreCompleted`); the library records it via
  `kms.Coordinator.RecordCompletion`.

## Document history

| Date | Change |
|---|---|
| 2026-05-09 | Initial Phase 4 runbook |
| 2026-09-14 | Rewritten against the shipping binaries: X25519 KEM delivery (ADR 0009), `identity` subcommands, TLS 1.3 and fail-closed exposure; removed commands that do not exist |
