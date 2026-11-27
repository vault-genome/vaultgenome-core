# Dependency Justification — github.com/stretchr/testify

**Version:** the one pinned in `go.mod` (Dependabot keeps it current, grouped weekly, through the same gate as any change; the justification here does not depend on the patch level — a major version is a new review)
**License:** MIT
**Transitive depth:** 2 (testify → `go.yaml.in/yaml/v3`, `github.com/stretchr/objx`)
**Usage scope:** `_test.go` files only. Never imported from non-test code.

## Why this dependency

Contract-level tests require deep-equality comparisons, readable failure
messages for round-trip and validator tests, and a single idiomatic
assertion style across the codebase. The standard library's `testing`
package is sufficient for simple pass/fail assertions but produces poor
diagnostic output on deep-struct mismatches.

Testify is the de-facto standard in the Go ecosystem, is included in
Google's Go style guide reference set, is on the CNCF attested-dependency
list, and has stable v1.x API guarantees. Its surface area is well-defined
(`require`, `assert`, `suite`, `mock`) and the project uses only `require`
(which wraps `assert`). The `mock` sub-package is NOT used — our mocks are
hand-written against the interfaces in /internal/shared so the dependency
on testify stays narrow and predictable.

## Why not an alternative

- **Raw `testing`**: produces unreadable diffs on nested struct mismatches.
- **gotest.tools**: smaller user base; fewer long-term-support signals.
- **gocheck**: deprecated upstream.

## Transitive dependencies, each reviewed

The pinned version's `go.mod` requires two modules:

- `go.yaml.in/yaml/v3` — the YAML parser (the maintained successor of
  `gopkg.in/yaml.v3`) that testify's `assert` imports for `YAMLEq`. It is
  compiled into test binaries, because `require` wraps `assert`, but no
  test of ours calls it, and it is never in a product binary. If future
  supply-chain review flags it we can fork testify to elide the import; for
  now the default surface is acceptable.
- `github.com/stretchr/objx` — used by testify's `mock` package only, which
  this project does not import: it is in the module graph and never
  compiled (`go mod why -m github.com/stretchr/objx`: the main module does
  not need it).

`github.com/davecgh/go-spew` and `github.com/pmezard/go-difflib`, which
earlier versions required, are now carried inside testify as
`internal/spew` and `internal/difflib`, not as modules of their own.

Transitive dependencies are not on the allowlist: `scripts/dep_allowlist.txt`
lists direct dependencies only, and the depth cap of
`docs/doctrine/ci-security-policy.md` §3.2 governs the rest.

## Upgrade policy

Updates follow the same rule as other dependencies:

- Patch upgrades within v1.x are acceptable with a simple bump PR.
- Minor upgrades require re-running the vault-gate CI and updating this
  file's "Version pinned" line.
- A major upgrade (testify v2) would be treated as a new dependency —
  full re-review.

## Removal condition

If, during Stage C or Stage D, the project adopts a deep-equality
assertion pattern that does not require testify (for instance, if
`google/go-cmp` is judged sufficient), this dependency is removed.

## Review record

- Proposed: 2026-04-20 — Stage C, Phase 1 (contracts)
- Reviewed by: Serhii Nikolaichuk, Rodion Sorokin
- Status: approved for Stage C
