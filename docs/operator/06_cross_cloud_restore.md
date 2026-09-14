# Operator Runbook 06 — Cross-Cloud Key Release and Genome Restore

**Design:** [ADR 0006](../adr/0006-cross-cloud-kms-mediated-restore.md) (flow, audit kinds),
[ADR 0009](../adr/0009-x25519-kem-cross-cloud-key-delivery.md) (how keys travel),
[ADR 0010](../adr/0010-operator-stop-and-recorded-refusals.md) (the operator stop) and
[ADR 0011](../adr/0011-genome-v3-and-attested-self-restore.md) (sealed genomes, restore, receipts).
**Proven by:** `test/integration/crosscloud_test.go` and `genome_drill_test.go`, which run every
step below with the real binaries.

---

## What this runbook covers

Bringing a sealed genome up on another machine or cloud: the **source
authority** (`sagvd`) releases the genome's key to a **destination**
(`acp-bootstrap`) only after the destination proves — by remote attestation —
that it is a genuine TEE running a workload the operator allow-listed; the
destination then restores the genome by itself and signs a receipt; the source
verifies that receipt and records the restore.

What the shipping binaries do today, stated exactly:

- `acp-bootstrap` attests with **AMD SEV-SNP** (`tee.provider: "gcp-sev-snp"`,
  reports through the kernel's configfs-tsm on a Confidential VM) or with the
  **simulated** backend, whose Evidence is signed by a key derived from a seed
  file — that proves the protocol, not hardware isolation. The examples below
  use the simulator so they run anywhere; the SEV-SNP settings are in
  [runbooks/real-tee-sev-snp.md](runbooks/real-tee-sev-snp.md) §D. `sagvd`'s
  verifier registry accepts `simulated` and `gcp-sev-snp` and refuses every
  other family until its verifier runs end to end.
- Genomes are sealed with `acpctl genome seal` into v3 bundles whose key is
  in a separate 0600 file. Bundles are opaque without their keys, so they can
  be replicated to the destination ahead of any release. With a `genome`
  section, `acp-bootstrap` restores a bundle as soon as its key arrives, and
  wipes the key from memory once the restore is signed for.

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
    "insecure_simulation": true,
    "workload_descriptor": "acp-bootstrap-destination-v1",
    "seed_path": "/etc/acp/secrets/acp-bootstrap/tee_seed"
  },
  "source_authority": {
    "kid": "sagvd-authority-demo",
    "public_key_path": "/etc/acp/authority.pem"
  },
  "genome": {
    "bundle_dir": "/var/lib/acp/bundles",
    "restore_dir": "/var/lib/acp/restored"
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
- The simulated provider runs only with `insecure_simulation: true`: its
  "Evidence" is signed by a key read from `seed_path`, a 32-byte file, so it has
  no hardware isolation and is for development and tests. With `gcp-sev-snp`
  the chip signs and neither field applies. `public_key_path` accepts the PEM
  printed by `sagvd identity` or the raw 32 bytes.
- `tee.provider` is also the only `destination_tee_kind` the daemon answers; a
  handshake declaring another kind is refused.
- `genome` (optional): `bundle_dir` holds sealed bundles waiting for their keys;
  each restored genome lands in `restore_dir/<key id>/`, its signed receipt in
  `restore_dir/<key id>.receipt.json`. Both are absolute and separate. Copy
  bundles in under another name and rename them to `*.genome`, so a
  half-written bundle is never picked up. A key that arrives before its bundle
  waits for it (`rescan_seconds`, default 5).

The health listener answers `/healthz` and `/readyz` and exposes nothing else.

## Source configuration (`sagvd`)

Add a `crosscloud` section, and the audit signing key, to the usual `sagvd`
config:

```json
"keys": {
  "audit_signing": { "kid": "sagvd-audit", "seed_path": "/etc/acp/secrets/sagvd/audit_signing_seed" },
  "…": "authority_signing, session_sealing as before"
},
"crosscloud": {
  "enabled": true,
  "audit_log_path": "/var/lib/acp/xcc-audit.db",
  "policy_version": "xcc-2026-09-14",
  "insecure_simulated_destinations": true,
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

and point it at the operator's stop list:

```json
"operator_stop": {
  "kid": "operator-1",
  "public_key_path": "/etc/acp/crosscloud/operator.pem",
  "list_path": "/etc/acp/crosscloud/stop.json"
}
```

No key is released without a durable record: `audit_log_path` and
`keys.audit_signing` are required. Every release writes its handshake,
attestation and authorisation events to that log, signed and hash-linked,
before the step each one records. The log is verified end to end whenever
`crosscloud-restore` opens it; a log that does not verify stops all releases.
One run holds its lock at a time. The audit seed must stay the same for the
life of the log (`sagvd identity` prints its public key for auditors).

`insecure_simulated_destinations` lets the verifier registry hold a
`simulated` entry — needed for the simulated examples here, and never for a
hardware destination. Without it a simulated entry stops `sagvd` before any
handshake. (`sagvd`'s own `tee` section likewise requires
`insecure_simulation: true`: this build's authority attests with the simulator
only; the cross-cloud release path does not depend on it.)

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

## Sealing a genome

On the machine that holds the model or the fine-tune output:

```bash
acpctl genome seal --content-dir=./adapter --output=gen-1.genome --key-out=gen-1.key --json > seal.json
```

The report names the bundle's `key_id` (`genome-<payload>-g<generation>-<key
tag>`). `gen-1.key` holds the 32-byte key, mode 0600, and is never overwritten;
keep it with the release authority. Replicate `gen-1.genome` to the
destination's `bundle_dir` (see above).

## Releasing keys

```bash
sagvd crosscloud-restore \
  -config /etc/acp/sagvd.json \
  -decision-id dec-2026-09-14-001 \
  -destination-kind simulated \
  -destination-endpoint https://destination.example.com:8443 \
  -key-file "$(jq -r .key_id seal.json):/etc/acp/keys/gen-1.key"
```

`-key-file KID:PATH` repeats for several keys. Keys are read from files only —
a key on a command line would sit in process listings and shell history — and a
key file other users can read is refused. For a genome key ID the key must match
the tag the ID carries, so a wrong key file is caught before anything moves. The
endpoint must be `https`, except to a loopback destination. The command prints
one JSON report and exits 0 on success, 1 on any refusal:

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
  "audit_chain_length": 3,
  "audit_tip": "…"
}
```

**Confirm it landed.** The destination logs `crosscloud handshake answered` with
a `recipient_key_sha256`, then `crosscloud token accepted` with the same
`request_id` and `registered_keys`. The digest must equal the report's
`recipient_key_sha256`: it identifies the one key the DEKs were sealed to.

**Audit it.** Anyone holding the audit public key can verify the log offline:

```bash
acpctl audit verify --audit /var/lib/acp/xcc-audit.db \
  --audit-pubkey sagvd-audit.pem --audit-kid sagvd-audit --json
```

It checks every hash link and signature and prints the tip. Keep the report's
`audit_tip`: a log whose tail was cut off still verifies, but not to that tip.
Re-releasing the same key under the same kid (a retry whose answer was lost) is
accepted once more; a different key under a kid the destination already holds
is refused.

## Confirming the restore

The destination restores on its own. Its account is on its API (same TLS and
token as the key release):

```bash
curl --cert client.crt --key client.key --cacert ca.crt -H "Authorization: Bearer $TOKEN" \
  https://destination.example.com:8443/v1/genome/restores
```

The source records the restore only from the destination's signed word:

```bash
sagvd crosscloud-confirm \
  -config /etc/acp/sagvd.json \
  -decision-id dec-2026-09-14-001 \
  -destination-endpoint https://destination.example.com:8443 \
  -bundle gen-1.genome -wait 2m
```

It reads the release from the verified audit log (never from flags), fetches the
destination's receipt, verifies the Evidence over it with the verifier for that
TEE family, and requires the measurement to be the one the key was released to
and the decision, request, token and key to be the recorded ones. With
`-bundle` it also requires the restored genome to be exactly the operator's —
bundle digest, payload digest and the digest of every restored file. Only then
does it append `CROSS_CLOUD_RESTORE_COMPLETED`. `-wait` keeps asking while the
restore is still running. The report carries the measurements:

```json
{
  "status": "ok",
  "key_id": "genome-…-g1-…",
  "tree_sha256": "…",
  "files": 3,
  "bytes": 3158206,
  "restore_seconds": 0.013,
  "key_to_restored_seconds": 0.014,
  "authorized_to_confirmed_seconds": 0.31,
  "matched_operator_bundle": true,
  "audit_chain_length": 4,
  "audit_tip": "…"
}
```

`key_to_restored_seconds` is measured on the destination's clock,
`authorized_to_confirmed_seconds` on the source's. A receipt that does not check
out is refused (`integrity`, or `authority` for a key that was not released under
that decision) and nothing is recorded.

## When a release is refused

| Report `error.category` | Audit events | Meaning | What to do |
|---|---|---|---|
| — (exit 1, no report) | none | Bad flags, `http://` to a remote host, or config/material failed to load | Fix the invocation or config; the message names the field |
| `operational` | handshake initiated | The handshake did not complete: destination unreachable, TLS refused (no client certificate, TLS below 1.3), bearer token rejected, or the destination refused the request — the message carries its answer (e.g. a TEE kind it does not run, an authority key it does not trust) | Check the listener, certificates, token, and the identities each side pinned |
| `integrity` | handshake initiated, release denied | Evidence did not verify for the presented key — wrong attestor key, wrong measurement, a replayed or substituted answer — or the destination presented no usable key | Treat an unexpected one as possible impersonation; re-check the pinned identities |
| `authority` | handshake initiated, attestation verified, release denied | The destination is genuine but the operator stop refuses it (the message names the list serial and reason), or its measurement is not on the allow-list | Intended: lift the stop with a newer list, or add the measurement to a new allow-list version, only if you mean to |
| `operational` | all three | The token did not reach the destination, or the destination refused it — the message carries its answer (no outstanding handshake: expired or used; decision mismatch; signature) | Run the command again: a new handshake mints a new key and the old one expires unused. If it repeats, read the destination's `crosscloud token rejected` log line |

## The operator stop

The people responsible for the deployment — not the release host, and not any
workload — decide whether keys may move at all (ADR 0010). On the operator's own
machine:

```bash
acpctl stop keygen -out operator.seed -pub operator.pem          # once; operator.pem goes to the release host
acpctl stop issue -key operator.seed -kid operator-1 -serial 1 -out stop.json          # nothing stopped
acpctl stop issue -key operator.seed -kid operator-1 -serial 2 -all \
  -reason "suspected compromise" -out stop.json                                         # stop every release
acpctl stop issue -key operator.seed -kid operator-1 -serial 3 \
  -revoke gcp-sev-snp:<measurement_hex> -reason "host decommissioned" -out stop.json    # revoke one destination
acpctl stop verify -in stop.json -pubkey operator.pem -kid operator-1                  # check before shipping
```

Copy the signed `stop.json` to `list_path` on the release host. Every
`crosscloud-restore` run reads it afresh:

- a stop, or a revoked destination, is refused with `authority /
  attestation_denied` and the list's serial and reason, and the refusal is in the
  audit log as `KEY_RELEASE_DENIED`;
- a list that is missing, edited, or signed by another key stops every release;
- a list older than the newest serial any recorded decision was made under is
  refused (`rollback refused`) — lifting a stop takes a newer list;
- the report names the list in force as `operator_stop_serial`.

Keep the operator seed off the release host: anyone holding it decides what the
fleet may do.

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
- Every release is preceded by the three audit events, in order, persisted to
  the signed log before the step they describe; every refusal after the
  handshake ends with `KEY_RELEASE_DENIED`.
- A restore is recorded only from Evidence of the TEE the key went to, over a
  receipt that names that release; the destination materialises nothing before
  every segment of the bundle has authenticated and every restored file matches
  the sealed snapshot.
- The operator's signed stop list is applied to every release; without a valid
  one, nothing is released, and an older list cannot be put back.

## Known limits

- The destination attests with real hardware only on SEV-SNP; other TEE families
  are refused on both sides until their producers and verifiers run end to end.
- Genome keys live in 0600 files on the release host; the source does not yet
  keep them sealed to its own TEE (KNOWN_ISSUES #11).

## Document history

| Date | Change |
|---|---|
| 2026-05-09 | Initial Phase 4 runbook |
| 2026-09-14 | Rewritten against the shipping binaries: X25519 KEM delivery (ADR 0009), `identity` subcommands, TLS 1.3 and fail-closed exposure; removed commands that do not exist |
| 2026-09-14 | Genome v3 sealing, `-key-file` releases, destination restore and `crosscloud-confirm` (ADR 0011) |
