# ADR 0010: Operator Stop and Recorded Refusals

**Status:** Accepted — implemented (2026-09-14)
**Date:** 2026-09-14
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Builds on:** ADR 0006 (cross-cloud key release), ADR 0009 (per-handshake key delivery)

---

## Context

A continuity platform moves the keys that bring a model up somewhere else. The
same capability, pointed the wrong way, is how a model would spread itself. The
platform's position is that **the decision to move keys belongs to the people
operating it — never to the release host's automation and never to a workload**,
and that every such decision is on the record.

Before this ADR two pieces were missing:

1. **No stop.** The only brake was editing the release host's allow-list — a
   file on the very host that performs releases. Nothing let the humans
   responsible say "stop, everywhere, now" with authority the release host
   cannot fake.
2. **Refusals left no trace.** A refused release recorded the handshake (and,
   for a policy refusal, the verified attestation) and then simply ended. An
   auditor could not tell a refusal from a crash.

## Decision

### Operator stop list

The operator holds an Ed25519 key that never lives on the release host
(`acpctl stop keygen`). With it they sign a **stop list**:

```json
{
  "schema": "vault-genome/revocation/v1",
  "serial": 7,
  "issued_at": "2026-09-14T21:00:00Z",
  "stop_all": false,
  "revoked_measurements": { "gcp-sev-snp": ["<96 hex>"] },
  "reason": "host decommissioned",
  "signing_key_id": "operator-1",
  "signature": "<Ed25519 over the canonical JSON without the signature>"
}
```

`stop_all` refuses every release; `revoked_measurements` refuses releases to
those destinations. The release host pins only the operator's public key
(`crosscloud.operator_stop`) and applies the list, in front of the allow-list, to
every release.

- **Required.** Cross-cloud release does not run without a list that verifies
  under the pinned key and ID — missing, edited, or otherwise signed lists all
  stop it.
- **No rollback.** Every release decision records the list serial it was made
  under (the policy version reads `<allow-list version>;revocation=<serial>`)
  in the signed audit log. A list older than the newest serial on record is
  refused before anything happens, so an earlier list cannot be put back to
  undo a stop; lifting a stop takes a newer list signed by the operator.
- **Fail closed, not fail open.** A list that cannot be read or verified is not
  treated as "no stop"; it is treated as no permission.

### Recorded refusals

A new audit kind, `KEY_RELEASE_DENIED` (`audit_event` schema v4 → v5; struct
shape unchanged), is appended before a refusal is returned — whether the
destination could not prove its TEE or its key (stage `attestation`) or the
operator's policy refused it (stage `policy`, which includes the stop list).
Every flow that reaches a decision now ends with exactly one of
`KEY_RELEASE_AUTHORIZED` or `KEY_RELEASE_DENIED`. A refusal that cannot be
recorded is still a refusal; the error then says both.

## Consequences

- The humans holding the operator key can halt all key movement with one signed
  file, and the halt survives anything short of that key: editing the list, a
  different key, or restoring an older list are all refused.
- The audit log answers "what was decided, under which operator list, and why"
  for releases and refusals alike, and it is the anti-rollback memory — no
  separate state file to reset.
- The destination (`acp-bootstrap`) does not read the list; it only ever
  receives keys the source released. Because every release goes through the
  source and the source enforces the list, the stop is complete for keys this
  platform moves; a compromised source host is outside what a list can stop and
  is why the operator key and the audit log live elsewhere.
- Proven: `internal/vault/revocation` (signing, tamper, other key, other ID,
  malformed lists, gate order, rollback), `cmd/sagvd` (a stop gates a
  destination the allow-list admits; missing/edited/foreign lists refused;
  rollback refused after a decision was recorded), `cmd/acpctl` (keygen, issue,
  verify, tamper exit code), and live in `test/integration/crosscloud_test.go`:
  release → operator stop → refusal on record → stop lifted by a newer list →
  release → the old stop list put back is refused; and a single revoked
  destination refused while nothing else is.
