# Dependency Justification — go.etcd.io/bbolt

**Version pinned:** v1.3.10
**License:** MIT
**Transitive depth:** 1 (bbolt → `golang.org/x/sys` indirect — runtime-only OS calls)
**Usage scope:** `/internal/audit/store` only. NOT imported by contract,
chain, session, keys, or policy packages.

## Why this dependency

The audit store is an append-only, crash-consistent log of the signed
`AuditEvent` records produced by the vault's decision pipeline. The
store's doctrinal role (see `docs/doctrine/bootstrap-contracts.md` §4.3
and `docs/doctrine/open-decisions-resolved.md` R-5) requires:

1. Single-writer, many-reader on-disk persistence with a file-lock
   handshake the OS enforces (so a second vault process can't corrupt
   the first's log).
2. Crash consistency — any event that returned success from
   `Append` survives a power loss.
3. Monotonic append-order that survives close/re-open without
   rewriting historic keys (so the hash-link chain in
   `/internal/audit/chain` reassembles identically).
4. No network, no servers, no RPC — the store runs in-process alongside
   the vault and must be embeddable.

bbolt (the `etcd-io` fork of Ben Johnson's Bolt) is the canonical
embeddable key/value database in the Go ecosystem and is the storage
substrate under etcd itself, which is the reference for "operate at
infrastructure trust level" persistence in Go. It provides an mmap-
backed B+tree with ACID single-writer transactions, `NextSequence` on
buckets (which we use directly for append-order monotonicity), and an
OS-level file lock on `Open`. It has no network surface and no external
services.

## Why not an alternative

- **Raw files (JSON-per-line / append-only log)**: insufficient —
  crash-consistency is on us to implement correctly, and two processes
  racing on the same file without a lock can corrupt the log
  (the vault's cold-start race).
- **BadgerDB**: much larger (LSM-tree based), more dependencies, more
  background goroutines, pull-through cache — optimised for write
  throughput we don't need. Transitive depth also exceeds §3.2 cap.
- **SQLite (mattn/go-sqlite3)**: cgo dependency blocked by our no-cgo
  policy in `../../../docs/security/threat_model.md` §7 (cgo expands the attested TCB).
- **Pebble** (CockroachDB): same LSM trade-offs as Badger plus
  substantially larger dependency surface.

bbolt is the smallest tool that satisfies the four requirements above.

## Transitive dependencies, each reviewed

- `golang.org/x/sys` — stdlib-adjacent OS syscalls package maintained
  by the Go team. bbolt uses it only for file locking primitives on
  Unix (`flock`) and Windows (`LockFileEx`). No network, no reflection
  surprises, no cryptography. The module is on the allowlist under
  the `golang.org/x/*` family as the standard extension of the
  standard library.

No other transitive imports are pulled in.

## Compatibility & upgrade policy

- v1.3.x is the current stable minor series; we pin to v1.3.10 because
  it includes the 2024 fixes for fsync-on-close on macOS which the
  audit-store crash-consistency tests exercise directly.
- Patch upgrades within v1.3.x are acceptable with a simple bump PR.
- Minor upgrades require re-running the full audit-store test suite
  including the `TestBBoltStore_CrashAndReopen_PreservesAllEvents`
  E2E test in `/internal/audit/store/store_test.go`.
- A major upgrade (hypothetical v2) would be treated as a new
  dependency — full re-review.

## Removal condition

If the vault migrates to a TEE-sealed persistence primitive as part of
Stage H (post-MVP), the bbolt dependency is removed and the
`/internal/audit/store` package is rewritten against the new seal. The
`Store` interface in `store.go` is the abstraction designed to make
that swap a single-package change.

## Review record

- Proposed: 2026-04-21 — Stage G, Iteration 4 (task #69).
- Reviewed by: Serhii Nikolaichuk, Rodion Sorokin.
- Status: approved for Stage G MVP.
- Post-review action: `go mod tidy` MUST be run locally to regenerate
  `go.sum` entries; this is intentionally not done in the same commit
  as the source additions because the sandbox toolchain that authored
  the package lacks network access, and `sum.golang.org` verification
  is a policy-mandated part of the change record.
