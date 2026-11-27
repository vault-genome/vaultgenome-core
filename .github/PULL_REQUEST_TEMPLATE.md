<!--
  Vault Genome — Pull Request template

  Thank you for contributing. Fill in every section below; the reviewer
  reads the description against the diff (CONTRIBUTING.md, "Code
  Review"). Sections explicitly marked OPTIONAL may be omitted with a
  one-line justification.
-->

## Summary

<!-- One paragraph describing what this PR changes and why. -->

Fixes # / Refs #

## Type of change

<!-- Check all that apply. -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behaviour)
- [ ] Documentation only
- [ ] CI / tooling only
- [ ] ADR amendment (paired with `docs/adr/NNNN-…md` change in this PR)

## Architectural context

<!--
  Cite the relevant ADR, doctrine paragraph, or threat-model entry.
  If this PR introduces or amends an architectural invariant, include
  the ADR change in the same PR. ADR-only PRs are welcome too.
-->

- ADR(s) referenced:
- Doctrinal invariants potentially impacted:
- Threat-model entries potentially impacted:

## Test plan

<!--
  Describe how you validated the change. Every behavioural change
  needs tests; bench-affecting changes need bench numbers.
-->

- [ ] `make vault-gate` passes locally
- [ ] `make test-doctrine` passes
- [ ] `make verify-reproducible` passes (for changes to build-affecting code)
- [ ] New unit tests added for new behaviour
- [ ] New integration / property / fuzz tests added where applicable
- [ ] Bench numbers attached (for changes to hot paths)

## Compatibility

<!-- Mark all boxes that apply. -->

- [ ] No public API surface change
- [ ] Public API surface change documented in the PR description AND in the affected `doc.go`
- [ ] Wire-format / contract change documented in the PR description AND in the affected `internal/contracts/*` package
- [ ] The copyright line of `NOTICE` and the SPDX identifier on every new Go, Python or shell file (`AGPL-3.0-or-later`; `Apache-2.0` under `pkg/teeconformance`, `tools/corpus-harness` and `test/corpus/sev-snp`)
- [ ] No new dependencies, OR new dependency justified at `docs/dependencies/<name>.md` AND added to `scripts/dep_allowlist.txt`

## Deployment notes

<!--
  Any operator-side action required to roll out this change?
  Backwards-compatible upgrade path? Database migration? Config change?
-->

- [ ] No deployment-side action required
- [ ] Operator config change required (documented above)
- [ ] Migration required (documented above)
- [ ] Backwards-incompatible (documented above + ADR amendment)

## Pre-merge checklist

- [ ] Branch follows naming convention (`feat/…`, `fix/…`, `docs/…`, `ci/…`, `chore/…`)
- [ ] Conventional Commits format on every commit
- [ ] All commits cryptographically signed
- [ ] PR title is human-readable (no auto-generated dependabot-style summary)
- [ ] Every commit carries a `Signed-off-by` trailer with the author's email (DCO; `make dco`)
- [ ] CLA signed (CLA bot will prompt on first PR)
- [ ] Security-sensitive change? Reviewed against `SECURITY.md` scope
