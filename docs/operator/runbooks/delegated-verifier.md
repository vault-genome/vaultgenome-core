# Runbook: a delegated Verifier (`tee.peer.verifier.mode: rats`)

The Return Path handshake verifies each peer's TEE Evidence before a job
or a key crosses it. By default the daemon's own verifier for the family
does it (`builtin`: the chip's signature, the vendor's chain from pinned
roots, the TCB, the guest policy, the challenge binding — all offline, from
caches). A bank that runs one Verifier for its whole estate can delegate
the appraisal to it instead (ADR 0025, step 2b): the daemon sends the
peer's Evidence record to a RATS Verifier over Veraison's
challenge-response API, takes the attestation result back, verifies it
under the Verifier's key on file, judges it by the policy here, and still
holds the pin itself. This runbook is that mode.

## What stays here, whoever appraises

- **The family.** `tee.peer.provider` says what the peer must be; a record
  of another type (or a TSM report naming another kernel provider) is
  refused before the Verifier is asked.
- **The pin.** `tee.peer.measurement_path` is held against the launch
  measurement read from the very message the daemon posted — the SEV-SNP
  report's MEASUREMENT, the TDX quote's MRTD and RTMRs, the simulated
  statement's field — by the daemon's own parser. The bytes posted are the
  bytes the Verifier appraised (TLS to it, the result's `eat_nonce` is the
  session's nonce, and the Verifier compares that nonce with the report's
  REPORT_DATA). An affirming verdict on a peer whose measurement is not the
  pinned one is refused: «the Verifier affirms the peer, but its
  measurement differs from the pin».
- **The policy.** Which `ear.status` admits (affirming; warning only if you
  say so; never contraindicated or none), which appraisal policy the
  Verifier must have applied, which submodule is judged.
- **The record.** The admission on the audit log (`TRUST_EVALUATED`,
  outcome allow) carries the EAR itself under `peer_detail.verifier.ear`,
  with the Verifier's URL, the status, the policy id, the trustworthiness
  vector and the Verifier's identity. Anyone with the Verifier's public key
  verifies that EAR again, offline, years later. A refusal carries the
  Verifier's word in `reason` («the Verifier at … says SEV: contraindicated»),
  and a Verifier that could not be asked is on the record as
  `verifier_unavailable` — nothing is admitted on a missing verdict.

## Configuration

Both daemons take the same block under `tee.peer`:

```json
"tee": {
  "provider": "auto",
  "peer": {
    "provider": "gcp-sev-snp",
    "measurement_path": "/etc/acp/pins/worker.measurement",
    "verifier": {
      "mode": "rats",
      "url": "https://verifier.bank.example",
      "ear_public_key_path": "/etc/acp/verifier/ear-verification-key.jwk",
      "ca_path": "/etc/acp/verifier/ca.pem",
      "policy_id": "policy:sevsnp-2026",
      "submod": "SEV-SNP",
      "accept": ["affirming"],
      "timeout_seconds": 10
    }
  }
}
```

| Field | Meaning |
|---|---|
| `mode` | `builtin` (default) or `rats`. |
| `url` | The Verifier's base URL. `https` to anywhere; plain `http` reaches loopback only (a bench). |
| `ear_public_key_path` | The key the Verifier signs its results with: a PEM `PUBLIC KEY` block or a JSON Web Key — Veraison publishes it at `GET /.well-known/veraison/verification` as `ear-verification-key`. ES256, so EC P-256. Take it from the Verifier's operator out of band and keep it with the pins; the daemon never fetches it. |
| `ca_path` | Optional: the CA bundle (PEM) the Verifier's TLS certificate must chain to. Without it, the system roots. |
| `client_cert_path`, `client_key_path` | Optional, together: this daemon's TLS client certificate and key, for a Verifier that takes only known callers (mutual TLS). |
| `policy_id` | Optional: `ear.appraisal-policy-id` the appraisal must name. |
| `submod` | Optional: the appraisal (attester component) to judge by. Without it the result must carry exactly one. |
| `accept` | The `ear.status` values that admit: `affirming` by default; add `warning` only on purpose. |
| `timeout_seconds` | Per request to the Verifier; 10 by default. |

In this mode the family's own inputs — `amd_cert_chain_path`, `pcs_url`,
the caches — are the Verifier's business and are not required here. The
startup log says who appraises: `peer_verifier: rats https://…` (or
`builtin`).

Families this build can pin from the Evidence itself, and so delegate:
`gcp-sev-snp`, `gcp-tdx`, `simulated`. `azure-cgpu` stays `builtin` (its
Evidence is a composite the daemon reads as a whole).

## What the Verifier must be

A RATS Verifier speaking Veraison's challenge-response API:

1. `POST {url}/challenge-response/v1/newSession?nonce=<base64url>` — the
   daemon chooses the nonce: for `gcp-sev-snp` and `gcp-tdx` it is the
   64-byte REPORT_DATA the peer's report carries (SHA-256 of the handshake
   challenge, then zeros), because that is what the Verifier's scheme
   compares the report against; for `simulated`, the challenge itself.
2. `POST <session>` with `Content-Type` = the Evidence's media type —
   `application/vnd.veraison.tsm-report+json` for the configfs-tsm
   families (the TSM report: the kernel's `outblob`, the `auxblob` beside it
   with the host's certificate table, the provider's name) — answered with
   the session document, `status: complete` and `result: <EAR>`
   (or `processing` and completed on a later `GET`).
3. The EAR: a compact JWS, ES256, `eat_profile tag:github.com,2023:veraison/ear`,
   `eat_nonce` the session's nonce, one or more `submods`, each with
   `ear.status`, `ear.trustworthiness-vector`, `ear.appraisal-policy-id`.

For SEV-SNP that is Veraison with its `sevsnp` scheme, provisioned with
the AMD root for the product line and the reference values (the launch
measurement and TCB) of the workloads it should affirm; the certificate
table Google writes in DER is accepted since Veraison's PR #488.
`ratstest` (`internal/shared/tee/ratstest`) is the same API as a test
double; the integration suite runs both daemons against it with the
simulated family (`test/integration/delegated_verifier_test.go`). Against
Veraison itself, `scripts/hardware-test/veraison-live/run.sh` runs the
verifier's session with a real GCP SEV-SNP report on the bench's
deployment and keeps the EAR (claim C30).

## Failure modes, as recorded

| What happened | Where it shows |
|---|---|
| The Verifier contraindicates the peer | handshake refused; `TRUST_EVALUATED` deny, `reason` «the Verifier at <url> says <submod>: contraindicated (policy …)» |
| The Verifier admits, the measurement is not the pin | refused; `reason` «… affirms the … peer, but its measurement differs from the pin» |
| The Verifier cannot be reached, refuses a session, answers no result | refused; code `verifier_unavailable`, the URL in `reason`; `sagvd_handshake_failures_total{phase="handshake"}` rises; the job stays queued |
| The EAR does not verify under the key on file, or carries another nonce | refused; `reason` «EAR: signature does not verify …» / «eat_nonce is not this session's nonce» |
| A record of another family | refused before the Verifier is asked; `reason` «evidence type …, this peer verifier is … and reads …» |

## Air gap

A delegated Verifier is a route. A site that runs with no route
([air_gap.md](air_gap.md)) runs its Verifier inside the perimeter and
points `url` at it, or keeps `builtin` with its caches filled.
