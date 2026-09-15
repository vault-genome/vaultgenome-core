# Commercial license

This project is licensed **AGPL-3.0-or-later** ([LICENSE](LICENSE)). For
organisations whose deployment cannot satisfy AGPL §13, the same code is
available under a separate commercial license.

**Contact:** open a [GitHub discussion](https://github.com/vault-genome/vaultgenome-core/discussions)
or email the address in [SECURITY.md](SECURITY.md) with the subject
`commercial license`.

---

## The one promise that matters: there is no crippled edition

**The AGPL build and the commercially licensed build are the same code.** No
feature gating, no "enterprise" fork, no capability held back. The only thing
that differs is the license. This is a public commitment, recorded in
[ADR-0003](docs/adr/0003-agpl-commercial-dual-licensing.md), and it is why
`vault-gate` runs identically for every contributor.

If we ever ship a feature that exists only under the commercial license, this
paragraph is the one to hold us to.

---

## Do you need one? Usually not.

You do **not** need a commercial license to:

- evaluate, audit, test, benchmark or run drills against this code;
- run it internally, including on production data, as long as you are not
  offering modified network access to third parties;
- deploy it unmodified as a network service — AGPL §13's obligation attaches to
  **your modifications**, and an unmodified deployment has none to publish;
- publish your modifications under AGPL-3.0-or-later and be done.

You likely **do** want one if:

| Situation | Why AGPL is a problem |
| - | - |
| You link our libraries into a closed-source product or appliance | §13 would reach your source |
| You offer a modified build as a hosted or white-label service | §13 obliges you to publish those modifications |
| Counsel prohibits copyleft in your codebase outright | Common in banking and regulated industry — a policy question, not a technical one |
| You need a patent grant broader than the contributor grant | The AGPL grant covers the abstraction *as contributed* |
| You need warranty, indemnity, SLA or supported releases | AGPL ships "WITHOUT ANY WARRANTY" |

If you are unsure which column you are in, ask us before asking your lawyers —
we will tell you honestly when you do not need to pay, including when the
answer costs us the deal.

---

## What a commercial license adds

1. **Relief from AGPL §13** — no obligation to publish your modifications.
2. **A parallel patent grant** covering the TEE-agnostic abstraction, scoped to
   your licensed use. *(The patent family is **filed, not granted**. We license
   what we have and describe it accurately — see
   [What we do not claim](VERIFIABLE-CLAIMS.md#what-we-do-not-claim).)*
3. **Warranty and indemnity terms**, negotiated per agreement.
4. **Support and SLA**, negotiated per agreement.
5. **Named supported releases** with a defined backport window.

## What it does not add

- It does not extend to derivative works that re-implement the abstraction
  without using this codebase.
- It does not make any claim in [VERIFIABLE-CLAIMS.md](VERIFIABLE-CLAIMS.md)
  stronger. The measurements, and the limits, are the same for every licensee.
- It does not buy an exception to the safety invariants in
  [ADR-0012](docs/adr/0012-sentinel-and-policy-driven-failover.md). Operator-signed
  policy, one move per signature, the global stop, attested-destination-only
  key release and full audit are **not configurable** and will not be made
  configurable for any customer. A deployment that wants a model that can
  relocate itself without a human signature is not a deployment we will
  license.

---

## Pricing

Pricing is not published and depends on deployment scope, support level and
indemnity. We would rather quote a real number against a real deployment than
post a table that is wrong for everybody.

We will say this much publicly: this is **pre-revenue** infrastructure at MVP
maturity with zero external deployments, and we price accordingly for the first
design partners. If you are considering a pilot, say so — that conversation is
more useful to us than a license sale.

---

## Contributing, and why we ask for a CLA

Dual licensing requires that we can license the whole codebase, which means we
need either sole copyright or an assignment from every contributor. Contributors
sign a CLA granting (a) the AGPL-compatible patent license the community
depends on, and (b) relicensing rights for the commercial channel. This is the
standard arrangement used by GitLab, MongoDB and Canonical, and the trade-off is
stated rather than buried: **you keep your copyright; we get the right to
relicense your contribution commercially.**

If that trade-off is not acceptable to you, we would still rather have your bug
report, your review, or your reproduction of a drill than nothing. See
[CONTRIBUTING.md](CONTRIBUTING.md).

---

*This page is an offer to discuss terms, not the terms themselves. Any actual
license is the signed agreement, drafted by counsel; nothing here modifies the
AGPL grant under which you already have this code.*
