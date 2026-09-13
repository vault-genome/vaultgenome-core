# ADR-0004 — Doctrinal invariants are enforced by Go tests, not just docs

| Status   | Accepted (2026-01-08) — formalising existing iteration-3 practice |
|----------|--------------------------------------------------------------------|
| Deciders | Founders, Doctrine reviewer |
| Tags     | doctrine · ci · architecture-fitness-functions |

## Context

Vault Genome's protection model relies on a small set of architectural
invariants. Examples:

- "No production code path under `/internal/` writes unsealed AI Genome
  material to any sink other than via the GCM sealing function inside
  `/internal/vault/disclosure`." (Invariant 7, Freeze #6)
- "Every release decision passes through the validation pipeline; no
  short-circuit exists from session issuance to release." (Invariant 5)
- "The TEE Producer / Verifier / Sealer interface surface in
  `internal/shared/tee/` is FROZEN — declarations cannot mutate without
  a paired ADR amendment." (Invariant 12, ADR-0001)

Documentation alone (a Markdown file titled "Architecture Doctrine")
is insufficient. Documentation rots; engineers under pressure to ship
introduce regressions; reviewers approve PRs that quietly bypass an
invariant when the relevant section of the doc went stale months ago.

## Decision

Every named architectural invariant has a paired Go test under
`test/doctrine/invariants_test.go` (or sibling `_test.go` files in the
same package). The tests:

- Walk the codebase via AST parsing (`go/ast`, `go/parser`,
  `go/token`) — no string regex, no shell pipelines that could miss
  edge cases.
- Run on every CI build alongside ordinary unit tests
  (`go test ./...`) — failure blocks the merge.
- Have a docstring referencing the doctrine paragraph + the freeze
  decision number it enforces.
- Fail with a human-actionable message: which file violated, what to
  do about it, where in the doctrine the rule is documented.

Concrete examples currently in the suite:

| Invariant | Test name                         | Strategy                         |
|-----------|-----------------------------------|----------------------------------|
| #5        | `TestInvariant_05_NoSessionShortCircuit` | AST: every release decision must traverse a `validation.Verdict` consumer |
| #6        | `TestInvariant_06_NoBypassOfReturnValidator` | Type-system: every `compute.ReturnPath.Receive` call site must hold a `recvvalidator.Verifier` |
| #7        | `TestInvariant_07_NoRawExport`     | AST: forbidden write selectors (`os.OpenFile`, `os.WriteFile`, `io.Copy`, …) outside `allowedWriteSinkPrefixes` |
| #7b       | `TestInvariant_07b_DisclosurePackageImports` | Import graph: `vault/disclosure` package may not import `os`, `net`, `log`, `bufio` |
| #12       | `TestInvariant_12_FrozenInterfaceSurface` | AST hash: declared interface signatures in `tee/` must match a recorded hash |

Adding a new invariant follows a fixed protocol:

1. Document the rule in the doctrine document
   (`docs/doctrine/bootstrap-contracts.md` or
   `docs/doctrine/open-decisions-resolved.md`).
2. Add a numbered `TestInvariant_NN_<name>` test under
   `test/doctrine/`. The test SHOULD fail before the implementation
   change that satisfies it.
3. PR-review check: a doctrine change without a paired test, OR a test
   without a doctrine paragraph, is a red flag.

Invariants that legitimately need to be relaxed (e.g.,
`allowedWriteSinkPrefixes` extended to include `internal/shared/tee/`
in 2026-05) require a separate commit with the rationale baked into
the test source — the diff itself documents the doctrine evolution.

## Consequences

**Positive.**

- New PRs that violate invariants are caught by CI before review,
  saving reviewer attention for substantive logic.
- The codebase becomes *self-describing*: a future engineer can read
  `test/doctrine/invariants_test.go` and learn the architectural
  constraints from authoritative source, not stale docs.
- Doctrinal evolution is visible in `git log` — every relaxation of
  an invariant has a commit explaining the rationale and references
  the ADR that approved it.
- Compliance auditors (SOC 2 CC6.1, ISO 27001 A.14.2.5) appreciate
  "tests that demonstrate the security control is enforced" over
  "documentation of intent."

**Negative / accepted trade-offs.**

- AST-level tests are slower than unit tests (1–3 seconds for the
  doctrine suite vs. milliseconds per unit test). Acceptable: they
  run as a separate `test/doctrine/` package and don't block
  per-package iteration.
- Invariants written as tests have higher upfront cost than prose.
  We accept: prose alone is decorative; the test is load-bearing.
- The AST-grammar-based checks have known holes — they catch
  syntactic violations (`pkg.Func()`) but not semantic ones
  (`v := pkg.Func; v()` would slip through). For now, dot-imports
  and renamed imports remain a review concern flagged in the test's
  own docstring; tightening to type-checked SSA analysis is a future
  optimisation if the hole gets exploited.

## Alternatives considered

1. **Markdown-only doctrine** — used by most projects we've seen;
   confirmed to rot. We've all read code-comments-claiming-something
   that the code immediately violated. Rejected.
2. **Linter (custom go vet pass, golangci-lint plugin)** — heavier
   tooling, harder to debug locally, fewer docs that explain
   *why* a rule exists. AST-tests in the test suite are a better
   compromise: developers already know how to debug Go tests.
3. **Runtime invariants (panic on violation in production)** — too
   late; we want compile-time / test-time enforcement before code
   reaches a customer. Runtime panics are sometimes appropriate for
   protocol invariants (e.g., refusing to operate with a measurement
   the operator hasn't pinned), but architectural invariants must
   not depend on runtime data.
4. **External tools (Open Policy Agent / Rego)** — adds a dependency
   layer. Go's own AST is rich enough for the rules we care about.

## Future directions

- Extend the framework to enforce invariants on JSON contracts in
  `internal/contracts/` (no field renames after acceptance, no
  type widening that would silently change semantics).
- Generate a per-build "doctrine report" listing every invariant +
  its test status, surfaced in the investor-demo site at
  `/architecture` and in `ultrareview` outputs.
- When AGPL+commercial licensing (ADR-0003) goes live, add an
  invariant ensuring SPDX headers are present on every source file.
