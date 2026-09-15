# ADR-0003 — AGPL-3.0-or-later + commercial dual licensing

| Status   | Accepted (2026-03-12) |
|----------|-----------------------|
| Deciders | Founders |
| Tags     | licensing · business-model · open-core |

## Context

The Vault Genome codebase needs a license that achieves four
sometimes-conflicting goals:

1. **Open source credibility** — security-sensitive customers (banks,
   sovereign installations, AI labs) demand source-available cryptography
   so they can audit attestation flows and sealing primitives. A
   proprietary blob is a non-starter.
2. **Strong copyleft** — competitors who fork the project to embed in
   their own confidential-compute SaaS without contributing back
   would erase the moat we built. We need an obligation that fork-and-host
   triggers source disclosure.
3. **Commercial sales channel** — enterprise buyers (especially banks)
   often refuse copyleft because their internal counsel will not
   approve linking to AGPL code in proprietary applications. The
   licensing terms must accommodate a paid license that lifts copyleft
   for those customers.
4. **Patent-license alignment** — our patent application
   (`business/20_patent_disclosure_v2.md`) covers the TEE-agnostic
   abstraction. Open-source contributors must grant a patent license
   that matches the codebase's open-source promise; commercial
   licensees buy a parallel patent grant.

## Decision

The codebase is licensed under **AGPL-3.0-or-later** by default, with a
**commercial license** offered separately to customers who cannot
satisfy AGPL's network-distribution clause.

### AGPL-3.0-or-later (default)

- Applies to every source file with the SPDX header
  `SPDX-License-Identifier: AGPL-3.0-or-later`. New files MUST carry
  this header — `make check-license` enforces this in CI.
- Any user who runs Vault Genome over a network MUST make the modified
  source available to that network's users (AGPL §13). This includes:
  SaaS deployments, internal SaaS-style hosted instances, and
  cross-organisation API consumers.
- Patent grant from contributors covers the abstraction *as
  contributed* — sufficient for downstream open-source use, not for
  building a competing commercial product.

### Commercial license (paid)

- Sold by Vault Genome Inc. to customers whose deployment cannot
  satisfy AGPL §13 (e.g., closed-source banking apps that link
  Vault Genome client libraries, embedded appliances, white-label
  resellers).
- Removes the AGPL §13 source-disclosure obligation.
- Includes a parallel patent license covering the TEE-agnostic
  abstraction (claims 1.x in the disclosure).
- Includes commercial support obligations, SLA, and indemnity.
- Pricing tiers documented separately in
  `business/24_commercial_license_pricing.md` (private repo).

### Per-component licensing

- The Go module path `github.com/ai-continuity-platform/core` is
  AGPL-3.0-or-later in its entirety.
- Patent grants in commercial licenses do NOT extend to derivative
  works that re-implement the abstraction without using our codebase.
  The patent itself, once granted, applies regardless of license.
- Documentation in `docs/`, ADRs, and architecture diagrams are
  CC-BY-SA 4.0 (compatible with AGPL's spirit, more usable by readers
  who quote / annotate).

## Consequences

**Positive.**

- AGPL ensures any cloud-vendor fork must publish their changes,
  protecting the open-source moat.
- Commercial license unlocks the bank / regulated-industry market
  that AGPL alone closes off.
- Patent disclosure aligns naturally: our claims protect the
  abstraction; the licensed grant flows through commercial licenses.
- Contributors signing the CLA grant both an AGPL-compatible patent
  license (for community use) and an opt-in commercial license
  (relicensing rights for Vault Genome Inc.). Standard practice;
  see e.g. Apache CLA, Canonical CLA.

**Negative / accepted trade-offs.**

- AGPL spooks some open-source consumers who confuse it with GPL.
  Mitigation: the README has an explicit "AGPL FAQ" section; sales
  team is briefed on the standard objections.
- Dual licensing requires we are the sole copyright holder (or hold
  full assignments via CLA) — every contributor signs the CLA before
  PRs are merged. Operational friction is real but manageable.
- "Open core" suspicion: customers worry the open version is hobbled
  to push paid upgrades. We commit publicly to: NO feature-gating
  between AGPL and commercial; the only difference is the license,
  not the code.
- License compatibility with Intel SGX SDK, AWS Nitro SDK, and other
  CGo-linked dependencies needs ongoing review (Q3 2026 deep dive,
  flagged in `business/16_trade_secrets_inventory_v2.md` §9).

## Alternatives considered

1. **MIT / Apache-2.0** — too permissive. AWS, Microsoft, or Google
   could fork and re-host without contributing back, and we have no
   pricing leverage on customers who'd otherwise buy commercially.
2. **GPL-3.0** — strong copyleft but lacks AGPL's network-use clause,
   so a SaaS fork could host a modified version without disclosing.
   AGPL is GPL with that hole closed.
3. **Server Side Public License (SSPL, Mongo-style)** — viewed as
   non-OSI-approved; many security-sensitive customers reject it as
   "fake open source." Would lose us the moral high ground.
4. **Business Source License (BSL, Cockroach-style)** — reverts to
   open after a delay. Acceptable but rejected because the cleaner
   AGPL+commercial story is more familiar to enterprise buyers'
   counsel.
5. **Fully proprietary** — kills the open-source signal that
   security-sensitive customers actively look for. Rejected.

## Implementation checklist

- [x] SPDX header in every `.go`, `.ts`, `.tsx`, `.py` file (enforced
      in CI by `scripts/check-license.sh`).
- [x] Top-level `LICENSE` file is AGPL-3.0-or-later. **Closed 2026-09-15**:
      the file previously carried only the short-form notice plus a scaffold
      note, which made GitHub's licence detection report `NOASSERTION`. It now
      holds the verbatim AGPL-3.0 text; the copyright notice, licence scope and
      third-party attribution moved to [`NOTICE`](../../NOTICE).
- [x] Commercial-licence page at the repo root.
      **Closed 2026-09-15**: [`COMMERCIAL-LICENSE.md`](../../COMMERCIAL-LICENSE.md)
      (named `COMMERCIAL-LICENSE.md`, not `LICENSE-COMMERCIAL.md`, so it sorts
      away from `LICENSE` and cannot be mistaken for the governing grant). It
      is an offer to discuss terms, not the terms; per-customer agreements are
      papered by counsel. It also records two public commitments: no feature
      gating between the AGPL and commercial builds, and the ADR-0012 safety
      invariants are not configurable for any customer.
- [x] CLA signing in
      [`business/26_contributor_license_agreement.md`](../../business/26_contributor_license_agreement.md)
      (private repo).
- [ ] OSI-approved CLA Bot configuration in `.github/workflows/cla.yml`.
      **Open** — the CLA exists but is not yet automated at PR time.
- [x] Reader-facing explanation of the AGPL obligation and the "open core"
      stance. **Closed 2026-09-15**: covered by
      [`COMMERCIAL-LICENSE.md`](../../COMMERCIAL-LICENSE.md) ("Do you need one?
      Usually not.") rather than expanding the README, which keeps the
      licensing discussion in one place.

## Reviews + sign-off

This ADR was reviewed against the open-source business literature
(Open Core Summit, Sid Sijbrandij CTO talks on GitLab AGPL strategy)
and is consistent with peers in the open-core security space:
HashiCorp Vault, MongoDB Enterprise, Sourcegraph, GitLab.
