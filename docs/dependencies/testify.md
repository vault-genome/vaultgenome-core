# Dependency Justification — github.com/stretchr/testify

**Version pinned:** v1.9.0
**License:** MIT
**Transitive depth:** 3 (testify → davecgh/go-spew, pmezard/go-difflib, yaml.v3)
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
and `assert`. The `mock` sub-package is NOT used — our mocks are
hand-written against the interfaces in /internal/shared so the dependency
on testify stays narrow and predictable.

## Why not an alternative

- **Raw `testing`**: produces unreadable diffs on nested struct mismatches.
- **gotest.tools**: smaller user base; fewer long-term-support signals.
- **gocheck**: deprecated upstream.

## Transitive dependencies, each reviewed

- `github.com/davecgh/go-spew` — struct pretty-printer used by testify for
  diff output. Stable since 2012; no network activity; no cryptography.
- `github.com/pmezard/go-difflib` — unified-diff renderer. Likewise trivial
  surface area.
- `gopkg.in/yaml.v3` — YAML parser pulled in by testify for suite runner
  configuration. Not used by our tests; we rely on Go's stdlib `testing.T`
  pattern, not the suite runner. If future supply-chain review flags
  yaml.v3 we can fork testify to elide the import; for now the default
  surface is acceptable.

All four are on the allowlist in docs/doctrine/ci-security-policy.md §5.

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
