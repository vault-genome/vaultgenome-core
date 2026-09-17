# Mutation testing

| Last updated | 2026-05-06 |
|--------------|------------|
| Tool         | [go-mutesting](https://github.com/avito-tech/go-mutesting) (fork of zimmski's) |
| Cadence      | Weekly (Sunday 03:00 UTC) via `.github/workflows/mutation.yml`; on-demand via `make mutation` |
| Scope        | Security-critical packages; see `MUTATION_PACKAGES` in [Makefile](../../Makefile) |

## Why mutation testing matters

Vault Genome has 160+ tests. They mostly pass. But "tests pass" only
proves the tests we have don't fail; it doesn't prove the tests are
*good*. A test suite that passes against silent regressions is
worse than no test suite — it gives false confidence.

Mutation testing automatically introduces small bugs (mutations) into
source code and checks whether the existing tests catch them. A
mutation that survives means the tests don't actually exercise the
behaviour the mutated line implements. The fix is always to add a
test, never to suppress the mutation.

Concretely, go-mutesting applies mutations like:

- `==` → `!=`
- `<` → `>`
- `&&` → `||`
- removing `if` conditions (always-true branch)
- removing `else` branches (always-not-taken)
- replacing constants (e.g., `0` → `1`, `nil` → `&struct{}{}`)
- replacing return values

For each mutation, the tool runs the test suite. If any test fails,
the mutation is "killed"; if all tests pass with the bug still in
place, the mutation "survives" and we have a test gap.

## Why we mutation-test only some packages

Full-tree mutation testing on this codebase takes ~2 hours. Per-PR
runs of that length would blow the CI budget. Weekly runs on
security-critical packages give us the signal where it matters:

| Package                          | Why it matters                                                         |
|----------------------------------|------------------------------------------------------------------------|
| `internal/shared/crypto`         | All cryptographic primitives — wrong → catastrophic                  |
| `internal/audit/chain`           | Tamper-evident audit log integrity                                    |
| `internal/vault/keys`            | Key handling, including multi-tenant derivation                       |
| `internal/recvvalidator`         | Return-path validation; doctrine invariant 6                          |
| `internal/shared/tee`            | TEE adapter call paths; risk that wiring bugs slip past unit tests    |

Other packages benefit from mutation testing too, but the marginal
risk reduction is lower; we'll add them as the team grows or when
specific incidents call for it.

## How to run locally

### Full critical-pack run (~30-60 minutes)

```bash
go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@latest
make mutation
# Report appears at dist/mutation.out
```

### Single-package run (~5-10 minutes)

```bash
make mutation-quick PKG=./internal/audit/chain/...
```

Use this for rapid iteration when you've added tests aiming to kill
specific surviving mutations.

## How to interpret results

A go-mutesting run produces output like:

```
PASS "/path/to/file.go:42" with checksum c0ffee
FAIL "/path/to/file.go:84" with checksum deadbeef
PASS "/path/to/file.go:91" with checksum f00d
The mutation score is 0.857 (12 passed, 2 failed, 0 duplicated, 0 skipped, total is 14)
```

- **PASS** = the mutation was killed by a test (good).
- **FAIL** = the mutation survived (bad — tests didn't catch it).
- **Mutation score** = passed / total. Higher is better.

For each FAIL, the tool prints the diff of the mutation. Read the
diff, identify what behaviour the mutated line was supposed to
preserve, and write a test that fails with the mutation in place
but passes against the original.

### Target kill rates

Per-package targets, and where the measured rate is:

| Package                          | Target kill rate |
|----------------------------------|------------------|
| `internal/shared/crypto`         | ≥ 95%            |
| `internal/audit/chain`           | ≥ 90%            |
| `internal/vault/keys`            | ≥ 90%            |
| `internal/recvvalidator`         | ≥ 85%            |
| `internal/shared/tee`            | ≥ 85%            |

The measured rates are the output of the `mutation` workflow
(`.github/workflows/mutation.yml`), which runs weekly (Sundays, 03:00
UTC) and on demand and publishes its report as a run artifact; no measured rate is recorded in this document
until a run has been kept and cited here. A measured rate below its target
is a finding to fix, not a gate: the workflow does not block a pull
request.

## Common false positives

go-mutesting sometimes flags mutations that are equivalent to the
original code (e.g., reordering commutative operations, comments).
Equivalent mutations don't represent a real test gap; we suppress
them via the tool's checksum mechanism after manual review.

Track these in [`docs/testing/mutation_suppressions.md`](mutation_suppressions.md)
when we accumulate enough to make the table useful.

## Relationship to other test methods

Mutation testing is one of four methods we use to catch defects:

| Method              | Catches                                              |
|---------------------|-------------------------------------------------------|
| Unit tests          | Direct functional defects                             |
| Property-based tests| Defects in invariants over input space (`pkg/teeconformance`, planned) |
| Fuzz tests          | Defects in parsers / boundary cases (`internal/shared/tee/fuzz_test.go`) |
| Mutation testing    | Defects in test coverage itself                      |

The methods are complementary; you can't substitute one for another.
A package with high unit-test coverage but poor mutation score has
tests that exercise the API surface without checking semantics — the
common "I called it; it didn't panic; therefore it's correct" pattern.
