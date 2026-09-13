# Release Procedure

**Audience:** release engineer, administrator.
**Purpose:** the mechanical procedure for cutting a signed release of the
three binaries (`sagvd`, `acp-compute`, `acpctl`) with full supply-chain
evidence (SBOM + SLSA provenance + signed tag + cosign signatures).

**Related doctrine:** `docs/doctrine/ci-security-policy.md` §4 (release policy),
invariant #11 "supply chain attested".

---

## 1. Prerequisites

Before any release step runs, the following must already be true:

1. Every commit to be tagged is cryptographically signed (SSH or GPG
   per `docs/doctrine/ci-security-policy.md §3.1`).
2. `make vault-gate` is green on the exact commit you intend to tag.
3. Every external-facing artifact you intend to ship with the release
   (white paper, operator runbook, this document itself) has been
   scanned against `docs/doctrine/positioning.md §4` and cites the
   doctrine in front-matter. The positioning rollout log at
   `docs/positioning_rollout_log.md` records the outcome.
4. The release notes draft names every doctrine change, every invariant
   change, and every dependency change since the prior tag.
5. Two approvers are on hand per `.github/CODEOWNERS` — a release tag
   triggers the dual-founder review by construction, and the workflow
   will not produce signed artifacts without both approvals.

---

## 2. Pre-release checklist

| Item | Command | Pass criterion |
| - | - | - |
| Clean working tree | `git status` | No uncommitted changes |
| Signed HEAD | `git log --show-signature -1` | "Good signature from …" |
| vault-gate green | `make vault-gate` | Exit 0 |
| SBOM generable | `make sbom` | `sbom.spdx.json` present, non-empty |
| No stale deps | `make dep-allowlist && make dep-depth` | Both exit 0 |
| Doctrine clean | `go test ./test/doctrine/...` | All `TestInvariant_NN` PASS |
| Runbook current | Review `docs/operator/` files for stage/CI-count drift | All references reflect current state |

---

## 3. Tagging

Tags are `vMAJOR.MINOR.PATCH` per the project's version scheme. For the
first MVP tag the sequence is:

```
git tag -s v0.1.0 -m "MVP — release-side doctrine-closed, 11/11 invariants enforced"
git push origin v0.1.0
```

The `-s` flag is required; an unsigned tag is refused by the release
workflow.

---

## 4. The release.yml workflow

The tag push triggers `.github/workflows/release.yml`, which per the
doctrine test `TestInvariant_11_SupplyChainAttested` must perform at
minimum:

1. Rebuild all three binaries from the tagged commit.
2. Run `syft` to generate an SPDX-format SBOM for the release.
3. Sign each binary with `cosign`.
4. Produce an SLSA provenance document binding the binaries to the
   tagged commit, the runner identity, and the workflow SHA.
5. Attach binaries, SBOM, and provenance to the GitHub Release.
6. Publish the tag signature verification.

If the workflow does not pass the `TestInvariant_11` structural check,
no release is produced.

---

## 5. Post-release verification

Once the release workflow completes:

1. Download all release artifacts to a clean environment (not a
   developer machine).
2. Verify every binary with `cosign verify-blob`.
3. Verify the SLSA provenance against the SBOM.
4. Verify the tag signature — `git verify-tag v0.1.0`.
5. Record the release hash externally (the external pin is itself a
   defence against a later tag rewrite — see
   `04_observability.md` §2.2 for the parallel idea on audit chains).
6. Append a `RELEASE_PUBLISHED` audit event (yes, this exists on the
   administrator's key even for the build / release surface — the
   audit chain covers the whole surface, not only running sessions).

---

## 6. Emergency release (security-driven)

A security-driven emergency release still goes through this procedure —
there is no "fast path" that bypasses vault-gate or the SBOM / cosign /
SLSA steps. The only difference is:

1. The release notes are specific about the vulnerability class and the
   affected versions (per `SECURITY.md` §"Response Commitment").
2. The CVE ID is claimed and recorded before the release ships.
3. The prior version is explicitly marked as withdrawn in the release
   notes.

A release that bypasses the workflow is by definition not a release —
it is an unattested binary and per invariant #11 is not shippable.

---

## 7. Release checklist (one-page)

```
[ ] Clean working tree
[ ] Signed HEAD
[ ] make vault-gate PASS
[ ] External artifacts: positioning doctrine scan PASS
[ ] Runbook reviewed for drift
[ ] Release notes drafted
[ ] Two approvers identified
[ ] Tag: git tag -s vX.Y.Z
[ ] Push: git push origin vX.Y.Z
[ ] release.yml workflow green
[ ] cosign verify-blob on all binaries
[ ] SLSA provenance matches
[ ] Tag signature verified externally
[ ] Release hash externally pinned
[ ] RELEASE_PUBLISHED audit event appended
[ ] Pre-existing "withdrawn" marker on prior version, if emergency
```

A release is complete when every line of this checklist is green.
