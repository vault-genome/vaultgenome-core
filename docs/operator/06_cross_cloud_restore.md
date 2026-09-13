# Operator Runbook 06 — Cross-Cloud KMS-Mediated Restore (Phase 4)

**Status:** Production-ready as of 2026-05-09 (151 tests passing, full HTTP integration validated).
**Authoritative design:** [ADR 0006 — Cross-Cloud KMS-Mediated Restore](../adr/0006-cross-cloud-kms-mediated-restore.md).

---

## What this runbook covers

How to operate the **cross-cloud restore** capability that lets a Vault Genome workload sealed in one TEE platform (e.g., GCP SEV-SNP) be restored byte-identically inside another TEE platform (e.g., AWS Nitro Enclave), with the decryption keys released only after the destination TEE proves itself via cross-cloud attestation handshake.

This runbook does **not** cover: the existing local single-TEE recovery flow (see `02_recovery_flow.md`), incident response (see `03_incident_response.md`), or release-procedure for source-side authority artefacts (see `05_release_procedure.md`). Cross-cloud restore is an **opt-in extension** of the local flow; everything in those runbooks remains valid.

---

## Topology

```
┌──────────────────────────────────┐                      ┌──────────────────────────────────┐
│   Source datacenter / cloud      │                      │  Destination datacenter / cloud  │
│   (e.g., GCP SEV-SNP)            │                      │  (e.g., AWS Nitro Enclave)       │
│                                  │                      │                                  │
│   ┌──────────────────────────┐   │     mTLS HTTP/2      │   ┌──────────────────────────┐   │
│   │ sagvd (release authority)│◀──┼──────────────────────┼──▶│ acp-bootstrap            │   │
│   │  + KMS Coordinator       │   │                      │   │  + crosscloud.Receiver   │   │
│   │  + Transport (HTTP)      │   │                      │   │  + HTTPHandler           │   │
│   │  + audit chain (release) │   │                      │   │  + audit chain (receive) │   │
│   └──────────────────────────┘   │                      │   └──────────────────────────┘   │
│                                  │                      │                                  │
└──────────────────────────────────┘                      └──────────────────────────────────┘
```

## Pre-flight (one-time setup)

### 1. Provision destination TEE

The destination must already be running `acp-bootstrap` with a TEE backend supported by the source's verifier registry. Currently supported: Intel SGX (DCAP or Azure MAA), AMD SEV-SNP, AWS Nitro Enclaves, GCP Confidential VMs, and the development simulator. See `01_preflight.md` for backend-specific provisioning.

### 2. Exchange source authority public key with destination

The destination must hold the **source authority's signing public key** to verify incoming `CrossCloudHandshakeRequest` and `KeyReleaseToken` signatures. This is a one-time exchange that bootstraps the trust relationship.

**Source side** (extract the source authority's signing key public bytes):

```bash
sagvd keys export \
  --key-id source-auth-1 \
  --purpose signing-authority \
  --format pem \
  --output /etc/vault-genome/source-auth-1.pub.pem
```

**Destination side** (load the source authority's pubkey into the receiver's key resolver):

```bash
acp-bootstrap keys import \
  --key-id source-auth-1 \
  --purpose signing-authority \
  --input /etc/vault-genome/source-auth-1.pub.pem
```

The destination operator should verify the file's SHA-256 digest against the source operator's published value before importing.

### 3. Pre-load destination measurement into source policy

The source's `KeyReleasePolicy` (allow-list MVP) must be configured with the destination's verified measurement before any cross-cloud restore can succeed.

**Destination side** (extract the local TEE measurement):

```bash
acp-bootstrap measurement \
  --tee-kind aws-nitro \
  --output /etc/vault-genome/destination-measurement.hex
```

The output is a 64-character hex string (32 bytes).

**Source side** (add to allow-list):

```bash
sagvd policy add-allow-list-entry \
  --policy-version xcc-2026-05-09 \
  --tee-kind aws-nitro \
  --measurement-hex "$(cat /etc/vault-genome/destination-measurement.hex)"
```

A measurement change at the destination (e.g., software upgrade) requires bumping the policy version and re-adding the new measurement. Old measurements can stay in the allow-list during a brownout.

### 4. Configure transport credentials (mTLS)

Production deployments use mTLS. Both source and destination need:

- A CA bundle that signs both endpoints' certificates
- A client certificate (source) and a server certificate (destination)
- Optionally, a Bearer token for transport-layer DoS resistance

The Bearer token does NOT replace cryptographic signatures on the wire payloads — it is defence-in-depth only.

```bash
# Source side: configure HTTPTransport
sagvd config set crosscloud.transport \
  --client-cert /etc/vault-genome/tls/client.pem \
  --client-key /etc/vault-genome/tls/client-key.pem \
  --ca-bundle /etc/vault-genome/tls/ca.pem \
  --bearer-token-from-file /etc/vault-genome/tls/bearer.token \
  --request-timeout 30s

# Destination side: configure HTTPHandler
acp-bootstrap config set crosscloud.handler \
  --listen-addr 0.0.0.0:8443 \
  --server-cert /etc/vault-genome/tls/server.pem \
  --server-key /etc/vault-genome/tls/server-key.pem \
  --ca-bundle /etc/vault-genome/tls/ca.pem \
  --bearer-token-from-file /etc/vault-genome/tls/bearer.token
```

### 5. Verify connectivity

A connectivity smoke test confirms the source can reach the destination's `/v1/crosscloud/handshake` endpoint with valid credentials:

```bash
sagvd crosscloud ping \
  --destination-endpoint https://destination.example.com:8443 \
  --destination-tee-kind aws-nitro
```

A successful ping returns the destination's claimed measurement and proves the trust chain (source authority pubkey, destination measurement, mTLS certs, Bearer token) is end-to-end functional.

---

## Operating a cross-cloud restore

### Trigger conditions

Cross-cloud restore is invoked when:

- A workload is sealed at the source authority and an operator needs to materialise it inside a destination TEE platform that is **not** the same family as the source.
- Disaster recovery scenario: the source datacenter is destroyed and a designated destination must take over.
- Migration scenario: a customer is moving from one TEE platform to another (e.g., consolidating from GCP-only to AWS+GCP).

### Step-by-step procedure

**Step A. Source operator prepares the recovery request**

The source operator drafts a standard `RecoveryRequest` per `02_recovery_flow.md`, with one new field:

```yaml
recovery_request:
  decision_id: dec-2026-05-09-001
  cross_cloud:
    enabled: true
    destination_kind: aws-nitro
    destination_endpoint: https://acp-bootstrap.example.com:8443
    keys_to_release:
      - key_id: dek-genome-001
        purpose: sealing
      - key_id: dek-genome-002
        purpose: sealing
```

**Step B. Source operator signs and submits the recovery request**

```bash
sagvd recover submit \
  --request-file /var/lib/vault-genome/recovery-requests/dec-2026-05-09-001.yaml \
  --signing-key-id source-auth-1
```

The source authority's `StagedSequencer` runs the canonical 8-stage flow (request → trust → session → disclosure → external compute → return → validation → release) exactly as for local single-TEE flows. After Stage 8 (Release Decided), the Sequencer transitions to **Stage 8.5 (StateCrossCloudHandshake)** because the request opts into cross-cloud delivery.

**Step C. KMS Coordinator runs the cross-cloud handshake**

This step is fully automatic and emits four audit kinds in strict order:

1. `KindCrossCloudHandshakeInitiated` — appended **before** the handshake request is dispatched. Pins the handshake nonce hash, decision ID, destination endpoint.
2. `KindCrossCloudAttestationVerified` — appended **after** the destination's Evidence is verified via the registered TEE Verifier. Pins the verified destination measurement.
3. `KindKeyReleaseAuthorized` — appended **after** the `KeyReleasePolicy` approves the destination measurement. Pins the policy version, the set of KeyIDs released, and the policy's reason text.
4. `KindCrossCloudRestoreCompleted` — appended **asynchronously** once the destination signals successful restore via the out-of-band confirmation endpoint.

If any step fails, the audit chain still records the events that happened up to the point of failure. The Coordinator returns a classified error indicating which step blocked.

**Step D. Destination operator confirms restore**

Once the destination's CrossCloudReceiver has unwrapped and registered all DEKs, the destination's `acp-bootstrap` daemon resumes the existing receive-side flow (Stage F: disclosure messages, Stage G: receive-side validator, terminal `ReconstitutionDecision`). The destination operator monitors progress via:

```bash
acp-bootstrap status \
  --decision-id dec-2026-05-09-001 \
  --watch
```

**Step E. Source operator records completion**

After the destination confirms restore (via `acp-bootstrap`'s external completion-signalling channel — typically a webhook or SDK call back to the source's `sagvd`), the source operator records the completion event:

```bash
sagvd crosscloud record-completion \
  --decision-id dec-2026-05-09-001 \
  --token-id <token_id_from_KeyReleaseAuthorized_audit_payload> \
  --request-id <request_id_from_handshake_audit_payload> \
  --restored-genome-hash <sha256_of_destination_genome_bytes> \
  --outcome validated
```

This emits the fourth audit kind (`KindCrossCloudRestoreCompleted`) and closes the cross-cloud arc.

---

## Failure modes and triage

| Symptom | Audit kinds emitted | Triage |
|---------|---------------------|--------|
| Network unreachable to destination | `KindCrossCloudHandshakeInitiated` only | Check destination's `acp-bootstrap` HTTP listener; check mTLS / firewall path |
| Destination Evidence verification fails | `KindCrossCloudHandshakeInitiated` only | Destination measurement does not match what the verifier expects. Common cause: destination upgraded code; allow-list needs new measurement |
| Bearer token rejected | `KindCrossCloudHandshakeInitiated` only | Bearer token rotation not synchronised; align both sides via secret manager |
| Source signature rejected at destination | `KindCrossCloudHandshakeInitiated` only | Destination's source-authority pubkey out of date; re-export source pubkey and re-import at destination |
| Policy denies key release | `KindCrossCloudHandshakeInitiated` + `KindCrossCloudAttestationVerified` | Destination measurement attested correctly but is not in source's allow-list. Add the new measurement and bump policy version |
| Token transport fails after policy approval | All three first kinds emitted; no `KindCrossCloudRestoreCompleted` | Transient; safe to retry. Re-issue a fresh handshake (replay protection prevents reusing the original) |
| Destination unwrap fails | All three first kinds emitted | Destination measurement at unwrap time differs from what was attested earlier. Indicates measurement-change-during-flow event; treat as Incident |

For Incident handling see `03_incident_response.md`.

---

## Reading the audit chain

Cross-cloud restores leave a deterministic audit footprint. To reconstruct the full cross-cloud arc:

```bash
sagvd audit query \
  --decision-id dec-2026-05-09-001 \
  --kinds CROSS_CLOUD_HANDSHAKE_INITIATED,CROSS_CLOUD_ATTESTATION_VERIFIED,KEY_RELEASE_AUTHORIZED,CROSS_CLOUD_RESTORE_COMPLETED \
  --format json | jq .
```

The destination's audit chain shows the receive-side mirror:

```bash
acp-bootstrap audit query \
  --decision-id dec-2026-05-09-001 \
  --kinds DISCLOSURE_RECEIVED,RECV_VALIDATION_STARTED,RECV_VALIDATION_COMPLETED,RECONSTITUTION_DECIDED \
  --format json | jq .
```

A regulatory auditor cross-references the two chains by `decision_id`, `manifest_id`, and `session_id`.

---

## Allow-list rotation

When the destination's TEE measurement changes (software upgrade, attestation root rotation, hardware replacement), the source operator must:

1. Get the new destination measurement (Step 3 above).
2. Bump the policy version: `xcc-2026-05-09` → `xcc-2026-06-15`.
3. Add the new measurement to the new policy.
4. Optionally, retain the old measurement in the new policy for a brownout window.
5. Reload `sagvd` to pick up the new policy.

A future cross-cloud restore that targets the new measurement is approved; restores that arrive citing only the old measurement are rejected once the brownout ends.

---

## Incident scenarios specific to cross-cloud

| Scenario | Response |
|----------|----------|
| Source authority signing key compromise | Rotate `source-auth-1`; re-export pubkey; revoke the old key at every destination via `acp-bootstrap keys revoke`; all in-flight tokens become unverifiable at destination |
| Destination measurement leaked / mis-attested | Remove the measurement from the source's allow-list; bump policy version; in-flight tokens that cite the removed measurement are rejected |
| Bearer token leak | Rotate the bearer token at both ends within 24h; the leak does not bypass the cryptographic signature check, but rotation reduces DoS exposure |
| Replay of an old handshake | Defended structurally: each handshake nonce is fresh; the destination keeps a short-window seen-nonce cache and rejects duplicates within 30s. Old nonces age out and can recur safely |

---

## What you do NOT need to do

- You do not need to run `sagvd recover` and `acp-bootstrap recover` separately for cross-cloud — the cross-cloud opt-in flag in the recovery request orchestrates everything.
- You do not need to manually unseal DEKs at the destination — the CrossCloudReceiver does it as part of token processing.
- You do not need to manage a separate KMS — Vault Genome's audit-bound key-release IS the KMS in this design.
- You do not need to coordinate keystore IDs between source and destination — DEK IDs in the `KeyReleaseToken` are honoured byte-for-byte at the destination.

---

## What is deferred to future phases

Per ADR 0006 §"Out of Scope":

- Multi-source escrow (N>2 source authorities co-signing release).
- Time-limited tokens with explicit expiration semantics (currently freshness is checked at consumption; explicit expiry is Phase 5).
- Persistent cross-cloud session (handshake amortised across many tokens — Phase 5 optimisation).
- Browser-based operator console (CLI + SDK only for Phase 4).

---

## Verification: how do I know this works?

Phase 4 ships with **151 tests** spanning seven packages, including:

- 22 contract tests for `CrossCloudHandshakeRequest` (round-trip, schema bounds, signature, validation)
- 23 contract tests for `KeyReleaseToken` (including WrappedKey validation, AAD tampering rejection)
- 38 unit tests for the `KMS Coordinator` (every error path, audit-first-class ordering, full happy-path crypto round-trip)
- 12 unit tests for the `TEE Verifier Registry` (multi-vendor resolution)
- 19 tests for `audit_event` v3→v4 schema bump (4 new Kinds)
- 6 new tests for the state-machine extension (Stage 8.5 transitions)
- 23 tests for the destination `Receiver` and HTTP handler — including **real-network end-to-end tests** using `httptest.Server` that exercise the full source-side `Coordinator` → real HTTP socket → destination-side `Receiver` flow with actual cryptographic round-trip

Plus: `TestEndToEnd_SourceCoordinatorToDestinationReceiver` (in-process round-trip) and `TestFullCoordinatorRoundTrip_OverRealHTTP` (real HTTP socket round-trip) prove the protocol works end-to-end on a single machine.

For real hardware validation across actual TEE platforms (AWS Nitro, Azure SGX, GCP SEV-SNP), see the Phase 2P / 2Q hardware test cohorts and the corresponding evidence bundles in `core/scripts/hardware-test/<platform>/evidence/`.

---

## Quick reference — operator commands

```bash
# One-time setup
sagvd keys export --key-id source-auth-1 --purpose signing-authority --format pem --output source-auth-1.pub.pem
acp-bootstrap keys import --key-id source-auth-1 --purpose signing-authority --input source-auth-1.pub.pem
acp-bootstrap measurement --tee-kind aws-nitro --output destination-measurement.hex
sagvd policy add-allow-list-entry --policy-version xcc-2026-05-09 --tee-kind aws-nitro --measurement-hex "$(cat destination-measurement.hex)"

# Smoke test
sagvd crosscloud ping --destination-endpoint https://destination:8443 --destination-tee-kind aws-nitro

# Trigger a cross-cloud restore
sagvd recover submit --request-file recovery-request.yaml --signing-key-id source-auth-1

# Monitor at destination
acp-bootstrap status --decision-id dec-2026-05-09-001 --watch

# Record completion
sagvd crosscloud record-completion --decision-id dec-2026-05-09-001 --token-id <id> --request-id <id> --restored-genome-hash <hex> --outcome validated

# Audit query
sagvd audit query --decision-id dec-2026-05-09-001 --kinds CROSS_CLOUD_HANDSHAKE_INITIATED,CROSS_CLOUD_ATTESTATION_VERIFIED,KEY_RELEASE_AUTHORIZED,CROSS_CLOUD_RESTORE_COMPLETED
```

---

## Document history

| Date | Change | Author |
|------|--------|--------|
| 2026-05-09 | Initial Phase 4 closure | Serhii Nikolaichuk |
