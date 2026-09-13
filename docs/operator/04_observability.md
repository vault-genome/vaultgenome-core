# Observability

**Audience:** Vault operator, administrator, external auditor.
**Purpose:** how to prove, after the fact, exactly what happened in a
recovery session. The platform's trust model assumes that every
continuity-relevant event is externally verifiable from first principles
— this document is the procedure for doing that verification.

---

## 1. The three observability surfaces

The Vault exposes three independent, cross-referenced observability
surfaces. Consistency across all three is the operational definition of a
"clean" session.

| Surface | Contents | Integrity primitive | Package |
| - | - | - | - |
| Audit chain | Every stage transition, every decision, every incident | Hash-chained AuditEvents, signed tip | `/internal/audit` |
| Witness log | Signed tree heads over the genome-descriptor state | RFC 6962 Merkle tree, STH signatures | `/internal/genome/witness` |
| Session ledger | SessionObjects and their ReleaseDecisions | Ed25519 signatures by SigningAuthority | `/internal/vault/session`, `/internal/contracts/release_decision` |

A recovery session leaves a signature on all three. Cross-check across
the three is the primary after-the-fact integrity tool.

---

## 2. Audit chain inspection

The audit chain is a linear hash chain of AuditEvents. Each event carries
a Kind (one of the nine stage-bearing kinds enumerated in `audit/event`),
a SessionID, a timestamp, a hash of the previous tip, and a signature by
`SigningAudit`.

### 2.1 Verify the chain in-place

```
acpctl audit verify --from <tip-hash> --to HEAD
```

**Expected output:** every event's prev-hash matches the preceding
event's hash; every event's signature verifies; no Kind appears out of
stage order for its SessionID. Any anomaly is printed with the offending
event's ID and the kind of inconsistency.

### 2.2 Verify against an external tip pin

The administrator keeps a signed external file of the audit chain tip
after every recovery session. To verify that the Vault has not rewritten
history:

```
acpctl audit verify --from <externally-pinned-prev-tip> --to <current-tip>
```

The current tip must chain to the externally-pinned prev-tip. If not,
the audit chain has been rewritten — critical incident, treat per
`03_incident_response.md` §4.

### 2.3 Session reconstruction from audit

Given only the audit chain and a SessionID, you should be able to
reconstruct what stage the session reached, which components were
disclosed, and what the ReleaseDecision verdict was — without consulting
any other store. The `audit reconstruct` CLI subcommand does this:

```
acpctl audit reconstruct --session <session-id>
```

Output includes stage transitions (timestamps, Kind), disclosed component
IDs in the issued order, and the final release verdict. If the audit chain
shows `DISCLOSURE_AUTHORIZED` events but no matching ReleaseDecision for a
session that has been terminated, that is a doctrine violation — one of
two things happened: authority to release was bypassed, or the release
audit event is missing. Both are critical incidents.

---

## 3. Witness log verification

The witness transparency log is an RFC 6962 Merkle tree of genome
descriptors. Its purpose is to make rewrites of the genome-state history
detectable.

### 3.1 Verify the current STH

```
acpctl witness sth --verify
```

The signed tree head must verify against the `SigningWitness` key.

### 3.2 Verify against an external STH pin

The administrator keeps a signed external file of the STH after every
preflight. To verify:

```
acpctl witness sth --verify --against <externally-pinned-sth>
```

The current STH must be a consistent extension of the externally-pinned
STH. If `DetectFork` fires — which the CLI reports as
`FORK_DETECTED` — treat as a critical incident. A fork means the log
has been rewritten; historical genome descriptors' provenance is no
longer provable.

### 3.3 Consistency proof for a specific descriptor

Given a GenomeID and its previously-recorded descriptor, you should be
able to produce a consistency proof showing that this descriptor is in
the current tree. If the proof fails, either the descriptor was not in
the log at the claimed time or the log was rewritten.

---

## 4. Session ledger cross-check

For a given SessionID the session ledger holds the SessionObject (issued
at Stage 3) and, after Stage 8, the ReleaseDecision. Cross-checks:

- SessionObject.SessionID must match ReleaseDecision.SessionID.
- ReleaseDecision.ValidationResultID must point to a ValidationResult
  produced for this session (invariant #5).
- ReleaseDecision.AuditEventID must point to a RELEASE_DECISION
  AuditEvent (invariant #8).
- The audit event at AuditEventID must reference this SessionID.
- Every DisclosureMessage emitted during this session must have a
  matching `DISCLOSURE_AUTHORIZED` audit event with the same SessionID
  and a strictly monotonic SequenceIndex.

A mismatch in any of these is a doctrine violation — by construction, a
valid session must satisfy all of them. The CLI wrapper:

```
acpctl session cross-check --session <session-id>
```

…produces the full report.

---

## 5. Routine observability cadence

| Cadence | Check | Who |
| - | - | - |
| Every session | `acpctl audit reconstruct` against the closed session | Vault operator |
| Every session | External audit-chain tip pinning after termination | Administrator |
| Every preflight | External STH pinning | Vault operator |
| Every 30 days | Full `acpctl audit verify --from <birth> --to HEAD` | Vault operator |
| Every 30 days | Full witness-log consistency proof walk | Administrator |
| After any incident | All of the above | Administrator |

---

## 6. What observability does NOT do

It is useful to be explicit:

- Observability does not replace doctrine. A clean log does not excuse
  an operational choice that violated an invariant; it merely makes the
  violation visible.
- Observability does not replace preflight. A green preflight a week ago
  does not cover a session run today.
- Observability does not provide real-time anomaly response. That is the
  incident module's job, and in MVP it handles only two scenarios
  (attestation fail, validation hard-fail) — the rest are operator
  judgment.
- Observability does not protect against a compromised
  `SigningAuthority` or `SigningAudit` key. A key compromise is the
  scenario under which the whole chain becomes unreliable. The only
  defence there is the key-custody procedures in preflight §3 and the
  out-of-band external pin cadence above.
