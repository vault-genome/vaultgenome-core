# Preflight Checklist

**When to run this:** before relying on a new deployment, and monthly
thereafter. A failed item is a stop condition — do not release keys or submit
work with any red item below.

**Who runs it:** the Vault operator, with the administrator available.

**Scope:** what can be checked against this repository and the shipped
binaries. The nine-stage flow ([02](02_recovery_flow.md)) runs only in-library
in the tests; where an item belongs to it, the section says so.

---

## 1. Build health

| Check | Command | Pass criterion |
| - | - | - |
| Local gate green | `make vault-gate` | Exit 0; last line `vault-gate: PASS` |
| Integration tests | `make test-integration` | Exit 0 (builds the real `sagvd`, `acp-compute` and keygen binaries and runs them as processes) |
| Reproducible build | `make verify-reproducible` | Ends with `reproducible-build check: PASS` |
| All binaries built | `make build`, then `ls bin/` | `sagvd`, `acp-compute`, `acpctl`, `acp-bootstrap`, `acp-demo` present |
| SBOM generable | `make sbom` | Writes `dist/sbom.spdx.json` without error |

`make vault-gate` runs 14 targets: `fmt-check`, `vet`, `build`, `test`,
`test-race`, `test-doctrine`, `lint`, `terminology`, `license-headers`, `vuln`
(govulncheck), `secrets` (gitleaks), `coverage-thresholds`, `dep-allowlist`,
`dep-depth`. The CI workflow `.github/workflows/vault-gate.yml` runs 18 checks;
the four the local target omits are integration tests, osv-scanner, SBOM and
verify-reproducible. Three of them are the separate targets in the table;
osv-scanner runs only in CI. `lint`, `vuln`, `secrets` and `sbom` need
golangci-lint, govulncheck, gitleaks and syft installed.

Any failure here blocks — a Vault that cannot produce a clean gate cannot
responsibly handle continuity authority.

---

## 2. Doctrine health

All four are part of `make vault-gate`; run them alone to see the detail.

| Check | Command | Pass criterion |
| - | - | - |
| All 11 invariants green | `make test-doctrine` | Every `TestInvariant_NN` passes |
| Terminology clean | `make terminology` | No enforced deprecated name (`docs/doctrine/terminology.md` §4) anywhere in the tree |
| Dep allowlist respected | `make dep-allowlist` | Every direct dependency is in `scripts/dep_allowlist.txt` |
| Dep depth within cap | `make dep-depth` | No dependency chain deeper than 3 |

---

## 3. Key material

`internal/vault/keys/keys.go` defines four key purposes: `signing_authority`,
`signing_audit`, `sealing` and `signing_witness`. What the shipped binaries
load:

| Key | Config | Loaded by | Used for |
| - | - | - | - |
| Authority signing (32-byte Ed25519 seed) | sagvd `keys.authority_signing` (`kid`, `seed_path`) | `sagvd` and all its subcommands | Signs every authority artifact of a gate job — the attestation, the session, each disclosure, the manifest, the gate verdict, the release decision (ADR 0015) — and cross-cloud handshake requests and key-release tokens, which each destination verifies against its `source_authority`. `sagvd identity` prints its public key |
| Session sealing (32-byte AES-256 key) | `keys.session_sealing` (`kid`, `material_path`) — the same kid and bytes in sagvd and every acp-compute | both daemons | sagvd seals every disclosure of a gate job under it — the genome's description, adapter and prompts, to the job's session; the worker opens them |
| Audit signing (32-byte Ed25519 seed) | sagvd `keys.audit_signing` (`kid`, `seed_path`) | the `sagvd` daemon (required with `audit.log_path`, which gate jobs require), `sagvd crosscloud-restore` and `crosscloud-confirm` (required when `crosscloud.enabled`); `sagvd identity` prints its public key | Signs the Return Path audit log and the cross-cloud audit log. It must stay the same for the life of the logs |
| Worker signing (32-byte Ed25519 seed) | acp-compute `keys.worker_signing` | `acp-compute` | Signs every CandidateOutputFrame; sagvd checks it against `workers.registry_path` |
| Simulated TEE seeds (32 bytes) | `tee.seed_path` in sagvd and acp-compute, with `tee.provider: "simulated"` | both daemons, off hardware | Sign each side's Return Path Evidence. On a SEV-SNP guest (`tee.provider: "gcp-sev-snp"`) there is no seed: the chip signs |

No binary loads a witness key.

Checks:

1. Every key file has its exact length; both daemons refuse to start
   otherwise (`… must be exactly 32 bytes`). sagvd does not check the mode of
   its own key files — keep them 0600. (Genome key files passed to
   `crosscloud-restore -key-file` are refused if other users can read them.)
2. `sagvd identity -config PATH` prints `authority_kid`,
   `authority_public_key_pem`, `tee_measurement_hex`, `tee_public_key_pem`
   and, when `keys.audit_signing` is set, `audit_kid` and
   `audit_public_key_pem`. Compare each with the copy pinned elsewhere: the
   authority key at every `acp-bootstrap` destination (`source_authority`),
   sagvd's TEE key and measurement in each worker's `tee.peer.*` files, the
   audit key with your auditors.
3. At startup sagvd logs `sagvd authority signing identity` (kid,
   pubkey_hex), `sagvd session sealing identity` (kid) and one
   `sagvd accepted worker signing identity` line per registry entry;
   acp-compute logs `worker signing identity` (kid, pubkey_hex). Each worker
   line must match an entry in `workers.registry_path`.

If any key fails a check, do not start the daemon; escalate to the
administrator. A running Vault with a suspect key is worse than a Vault that
did not start.

---

## 4. TEE identities

What attests in this build:

- `sagvd` and `acp-compute` use the simulated TEE only: Evidence signed by a
  key derived from `tee.seed_path`, measurement = SHA-256 of
  `tee.workload_descriptor`. Both refuse to start unless
  `tee.insecure_simulation` is `true`. Each pins the other's TEE public key and
  measurement (`tee.peer.public_key_path`, `tee.peer.measurement_path`); a
  mismatch fails the Return Path handshake (`sagvd return-path handshake
  failed`, `sagvd_handshake_failures_total{phase="handshake"}`).
- `acp-bootstrap` attests with AMD SEV-SNP (`tee.provider: "gcp-sev-snp"`) or,
  only with `insecure_simulation: true`, the simulator.
  `acp-bootstrap identity -config PATH` prints `tee_provider` and
  `measurement_hex` (plus the attestor key for the simulator); they must match
  sagvd's verifier registry entry and allow-list (06). sagvd refuses a
  `simulated` registry entry unless `crosscloud.insecure_simulated_destinations`
  is `true`.

The `op.attestation_valid` and `op.attestation_ttl` sub-checks in
`/internal/validation/operational` belong to the nine-stage flow and run only
in the tests.

---

## 5. Witness log

Not applicable to a deployment. The witness transparency log
(`/internal/genome/witness`, an in-memory log) and fork detection
(`DetectFork` in `/internal/contracts/witness`) are libraries exercised by
tests; no shipped binary runs a witness log or publishes signed tree heads.

---

## 6. Cross-cloud release policy

No binary loads a policy bundle for the nine-stage flow. What governs key
releases today is read afresh by every `sagvd crosscloud-restore` run (06):

1. The allow-list (`crosscloud.policy_allow_list_path`): its `version` must
   equal `crosscloud.policy_version` or sagvd refuses to load it; every entry
   is a whole 32-, 48- or 64-byte measurement.
2. The verifier registry (`crosscloud.verifier_registry_path`): only
   `simulated` and `gcp-sev-snp` entries are accepted.
3. The operator's stop list (`crosscloud.operator_stop.list_path`). Check it
   before installing it:
   `acpctl stop verify -in stop.json -pubkey operator.pem -kid operator-1`.
   A missing, edited or wrongly signed list stops every release; a list older
   than the newest serial in the audit log is refused. The same list, named
   by the daemon's top-level `operator_stop`, denies gate jobs at Trust
   Admission (ADR 0015): the daemon reads it again at every admission, so a
   stop-all written to `list_path` halts its releases at once, and a list
   with an older serial than one already consulted is refused.

Review the allow-list and the stop list every 30 days whether or not they
changed — the review is itself a policy-alignment signal.

---

## 7. Audit log continuity

The only audit log a shipped binary writes is `crosscloud.audit_log_path`.

1. `acpctl audit verify --audit <path> --audit-pubkey <audit.pem> --audit-kid <kid> --json`
   must report `"ok": true`.
2. Its `event_count` and `tip` must equal the `audit_chain_length` and
   `audit_tip` of the last `crosscloud-restore` or `crosscloud-confirm` report,
   kept off the host. A log whose tail was cut off still verifies; only this
   comparison shows it.

acpctl opens the file read-write and takes the same lock a running
`crosscloud-restore` holds (it gives up after 5 seconds): run it between
releases, or on a copy. A mistyped `--audit` path creates an empty log, which
verifies with 0 events.

A discontinuity here is the canonical "is the audit log being replaced
under me?" signal. Treat as critical.

---

## 8. Running daemons

| Check | Command | Pass criterion |
| - | - | - |
| sagvd alive | `curl -fsS http://127.0.0.1:9091/healthz` | `ok` |
| sagvd ready | `curl -fsS http://127.0.0.1:9091/readyz` | `ready` (once the Return Path listener is bound) |
| Worker connected | sagvd log and `/metrics` | `sagvd session opened` lines; `sagvd_sessions_opened_total` rising |

`127.0.0.1:9091` is the default `health.listen_address`; the REST API is a
separate listener (`http_api.listen_address`, default `127.0.0.1:9080`).
acp-compute's health listener also defaults to `127.0.0.1:9091`; on a shared
host give one of them another address (`deploy/compose` uses 9092 for the
worker). sagvd refuses to start if `vault.listen_address` is not loopback and
`vault.tls.enabled` is false, or if `http_api.listen_address` is not loopback
and no bearer token of at least 32 characters is configured.

---

## 9. Exit conditions for preflight

**Green (all items pass):** you may rely on the deployment.

**Yellow (an item is degraded but not failed — for example, the allow-list
review is due within a day):** proceed only if the administrator records the
degradation in writing.

**Red (any item fails):** do not release keys or submit work. Escalate,
remediate, re-run preflight.

Record the outcome of every run — date, commit, the audit tip you compared —
outside the system. There is no audit event kind for preflight results, and
nothing appends one.

---

_Document history: 2026-09-14 — checked line by line against the code; commands and names the binaries do not have were removed._
