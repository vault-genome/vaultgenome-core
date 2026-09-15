# Architecture Decision Records (ADRs)

This directory holds the ADRs that capture every significant
architectural decision in the Vault Genome codebase. Each ADR is a
self-contained Markdown file numbered sequentially.

The format is loosely based on
[MADR](https://adr.github.io/madr/) but adapted for our doctrine
norms — see [ADR-0004](0004-doctrine-invariants-as-tests.md) for how
ADRs interact with the test-enforced invariant system.

## Index

| #    | Title                                              | Status   | Tags |
|------|----------------------------------------------------|----------|------|
| 0001 | [Frozen Producer/Verifier/Sealer interface](0001-frozen-producer-verifier-sealer-interface.md) | Accepted | tee, interface-contract |
| 0002 | [Multi-TEE adapter dispatch via Provider enum](0002-multi-tee-adapter-dispatch.md) | Accepted | tee, factory-pattern |
| 0003 | [AGPL-3.0-or-later + commercial dual licensing](0003-agpl-commercial-dual-licensing.md) | Accepted | licensing, business |
| 0004 | [Doctrinal invariants enforced by Go tests](0004-doctrine-invariants-as-tests.md) | Accepted | doctrine, ci |
| 0005 | [Mock-based integration testing for hardware adapters](0005-mock-based-integration-testing.md) | Accepted | testing, tee |
| 0006 | [Cross-cloud KMS-mediated restore](0006-cross-cloud-kms-mediated-restore.md) | Accepted | restore, kms, crosscloud |
| 0007 | [Measurement is variable-length](0007-measurement-variable-length.md) | Accepted | tee, measurement |
| 0008 | [Numerical equivalence gate for cross-hardware reconstruction](0008-equivalence-gate.md) | Accepted | reconstruction, equivalence, determinism |
| 0009 | [X25519 KEM for cross-cloud DEK delivery (closes defect b)](0009-x25519-kem-cross-cloud-key-delivery.md) | Accepted | crosscloud, kms, crypto |
| 0010 | [Operator stop and recorded refusals](0010-operator-stop-and-recorded-refusals.md) | Accepted | crosscloud, audit, governance |
| 0011 | [Genome v3 and attested self-restore](0011-genome-v3-and-attested-self-restore.md) | Accepted | genome, crosscloud, restore, doctrine |
| 0012 | [Sentinel and policy-driven failover](0012-sentinel-and-policy-driven-failover.md) | Accepted | genome, failover, crosscloud, audit, governance |
| 0013 | [The worker restores the genome](0013-worker-restores-the-genome.md) | Accepted | worker, returnpath, genome, equivalence |

## Adding an ADR

1. Pick the next number. Numbers are sequential and never reused — if
   an ADR is later superseded, the new ADR cites the old one in its
   header.
2. Copy `0001-…md`'s structure: status table, Context, Decision,
   Consequences, Alternatives considered, optional implementation
   checklist or future directions.
3. Add an entry to the index table above.
4. If the ADR introduces or amends a doctrinal invariant, pair it
   with a `TestInvariant_NN_…` in `test/doctrine/`
   (see [ADR-0004](0004-doctrine-invariants-as-tests.md)).
5. Submit as a separate PR ahead of the implementation change so
   the ADR can be reviewed against intent, not against working code.

## Status values

- **Proposed** — drafted, under review.
- **Accepted** — merged; constraint is in force.
- **Deprecated** — no longer the preferred approach but not yet replaced.
- **Superseded by ADR-NNNN** — replaced by a newer decision; both
  ADRs remain in the repo for historical context.

ADRs are NEVER deleted. Even superseded ADRs document why a path was
abandoned, which is often the most useful information for the next
engineer who considers re-treading it.
