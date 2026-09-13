# Preflight Checklist

**When to run this:** before the first real recovery session in a new
deployment, and monthly thereafter. A failed item is a stop condition —
do not proceed to a recovery session with any red item below.

**Who runs it:** the Vault operator, with the administrator available.

**Expected time:** ~20 minutes for a first run, ~5 minutes thereafter.

---

## 1. Build health

| Check | Command | Pass criterion |
| - | - | - |
| Local vault-gate green | `make vault-gate` | Exit 0, all 17 sub-checks report PASS |
| All binaries built | `ls bin/sagvd bin/acp-compute bin/acpctl` | All three present |
| License headers intact | `make license-headers` | Exit 0 |
| SBOM generable | `make sbom` | Produces `sbom.spdx.json` without error |
| No vulnerable deps | `make vuln` | `govulncheck` reports no new findings |
| No leaked secrets | `make secrets` | `gitleaks` exit 0 |

Any failure here blocks the session — a Vault that cannot produce a clean
gate cannot responsibly handle continuity authority.

---

## 2. Doctrine health

| Check | Command | Pass criterion |
| - | - | - |
| All 11 invariants green | `go test ./test/doctrine/...` | Every `TestInvariant_NN` PASS |
| Terminology clean | `make terminology` | No deprecated-term hit in the whole tree |
| Dep allowlist respected | `make dep-allowlist` | Every direct dep in `scripts/dep_allowlist.txt` |
| Dep depth within cap | `make dep-depth` | No reachable dep past depth 3 |
| Positioning doctrine cited | `grep -r "docs/doctrine/positioning.md" docs/ || echo MISSING` | At least one citation in any external-facing artifact you are about to share |

---

## 3. Key material

The Vault holds four purpose-separated keys (see
`/internal/vault/keys/keystore.go`). Each must be:

1. Loaded into the in-memory keystore at `sagvd` startup.
2. Scoped to a single purpose (no cross-use of signing-authority and
   sealing keys).
3. Backed by audit events for every key-access operation.

| Key purpose | Used by | Preflight check |
| - | - | - |
| `SigningAuthority` | ReleaseDecision, SessionObject signatures | Sign a test payload and verify; confirm key ID matches the pinned value |
| `SigningAudit` | AuditEvent chain-tip signing | Append a probe event, verify chain tip advanced, verify signature |
| `Sealing` | AI Genome storage encryption | Round-trip a 32-byte probe through the sealing path; assert identical recovery |
| `SigningWitness` | STH signatures for witness transparency log | Issue a witness STH on an empty state, verify |

If any key fails its probe, the correct response is to refuse to start the
Vault and escalate to the administrator. A running Vault with a suspect key
is worse than a Vault that did not start.

---

## 4. Attestation

In MVP the TEE is emulated per resolution R-10; in production the Vault
requires a real attestation quote from its own enclave. The preflight
attestation check must:

1. Produce an AttestationResult with non-zero body.
2. Be signed by a key whose identity chains to a root certificate pinned
   in `/internal/shared/tee`.
3. Carry a TTL field that has not yet expired.
4. Pass the `op.attestation_valid` and `op.attestation_ttl` sub-checks in
   `/internal/validation/operational`.

If any of the four fails, the Vault is not in a state to begin a recovery
session. In MVP the emulated TEE passes these trivially; the preflight
check is still run every time so that swapping to real TEE at production
does not require changes to this document.

---

## 5. Witness log

The witness transparency log (`/internal/genome/witness`) must have:

- A valid signed tree head (STH) over its current state.
- No DetectFork anomaly against the last externally recorded STH.
- A log size that is monotonically non-decreasing relative to the last
  preflight run.

If DetectFork signals a fork condition, treat it as a critical doctrinal
incident: the log has been rewritten, which means the integrity of past
audit events is in question. See `03_incident_response.md` §4.

---

## 6. Policy snapshot

The policy currently loaded in the Vault must:

1. Be the current pinned version per the Stage A resolution on policy
   management (R-12 / R-13 — effective policy is the signed bundle that
   shipped with the current release tag).
2. Enumerate every allowed recipient key by canonical ID, every allowed
   component class, and every allowed disclosure sequence pattern.
3. Be reviewed every 30 days regardless of whether it has changed — the
   review is itself a policy-alignment signal.

A Vault running an unsigned or un-pinned policy must be refused.

---

## 7. Audit chain continuity

- Fetch the current audit chain tip.
- Verify its signature against `SigningAudit`.
- Assert its hash chains back to the previous pinned tip (stored
  externally — a simple signed file in the administrator's hands is
  sufficient).

A discontinuity here is the canonical "is the audit log being replaced
under me?" signal. Treat as critical.

---

## 8. Exit conditions for preflight

**Green (all items pass):** you may proceed to open a recovery session.

**Yellow (any one item is degraded but not red — for example, the policy
snapshot is within one day of its 30-day review window):** proceed only if
the administrator records the degradation as an audit event of kind
`PREFLIGHT_DEGRADED`.

**Red (any one item fails):** do not open a recovery session. Escalate,
remediate, re-run preflight.

The outcome of every preflight run must be itself an audit event of kind
`PREFLIGHT_RESULT`, carrying the per-item results and a monotonically
increasing run ID.
