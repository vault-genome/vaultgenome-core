# Customer reference designs

Hypothetical but technically detailed deployment scenarios that
illustrate how Vault Genome lands in concrete buyer environments.
Each design names a **realistic** customer profile, a **specific**
problem they need to solve, and a **deployable** architecture that
shows how Vault Genome's components fit together.

These are not case studies of real customers. They are reference
designs of the type security architects use to validate that a
system fits an environment **before** committing to a procurement.
They support sales conversations and de-risk the buyer's
prove-it phase.

## Designs

| #  | Profile                                        | Primary TEE | Driver                                   |
|----|------------------------------------------------|-------------|-------------------------------------------|
| 01 | [Tier-1 bank — FIX engine model continuity](01-tier1-bank-fix-engine.md) | Intel SGX bare metal | Sovereign signing + sub-ms latency budget |
| 02 | [Healthcare AI — clinical-decision support](02-healthcare-clinical-decision.md) | AWS Nitro Enclaves | HIPAA + 7-year audit retention            |
| 03 | [Sovereign government — defence research](03-sovereign-defence.md) | Intel SGX bare metal | Air-gapped + dual-key custody              |
| 04 | [Frontier AI lab — model continuity at training scale](04-ai-lab-training-continuity.md) | GCP SEV-SNP | Multi-region + insider-risk mitigation    |

Each design follows a consistent template so a buyer can
compare:

1. **Customer profile** — industry, scale, regulatory regime
2. **Problem statement** — what they need that they can't easily
   build in-house
3. **Architecture** — Vault Genome components + deployment
   topology + data flow diagram
4. **Threat model** — what's protected, what's residual,
   referencing [`docs/security/threat_model.md`](../security/threat_model.md)
5. **Operational concerns** — staffing, runbook coverage,
   compliance crosswalk references
6. **Pricing posture** — what the deployment looks like in cost
   terms (commercial-license tier vs AGPL vs hybrid)

## How to use these documents

- **Sales conversation**: walk through the closest design with the
  customer. Their objections inform the actual solution architecture.
- **Solution architecture for a real deal**: forks one of these
  designs into a new file under `business/customer-designs/<id>.md`
  (private repo) and tightens the gaps the customer identified.
- **Security review**: pair each design with the threat model and
  compliance crosswalk to demonstrate readiness for the customer's
  procurement-time questions.

## Authorship

All four reference designs are written by the founders against the
public Vault Genome architecture as of 2026-05-06. They are NOT
endorsements by any named customer; the customer profiles are
composites derived from sales conversations under NDA. Material
revisions are reviewed quarterly alongside the threat model.
