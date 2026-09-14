<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Terminology doctrine

This document is the canonical source for project naming and vocabulary.
It has two kinds of rules, and the distinction is deliberate:

- **§4 Deprecated project names** are **enforced** by CI
  (`scripts/terminology_check.sh`, vault-gate sub-check 09). A build fails
  if any former project name reappears in source or docs.
- **§5 Vocabulary preferences** are **advisory** house style. They guide
  new prose and identifiers but are not gated, because the words involved
  ("restore", "backup", …) also have ordinary, correct English meanings
  that appear throughout the code and would produce hundreds of false
  positives with no gain in clarity.

Deprecated terms are permitted only under `docs/patent_references/`, which
preserves the exact language of filed applications for traceability.

## 1. Canonical names

| Concept | Canonical term |
|---|---|
| The product / platform | **VaultGenome** — the AI Continuity Platform |
| The sealed, content-addressed artifact | **genome** |
| Producing a genome | **seal** |
| Bringing a genome back, byte-for-byte | **rewind** |
| Reproducing behavior under a recompute strategy | **regenerate** |
| The equivalence decision over a regeneration | **verdict** (EXACT / EQUIVALENT / FAIL) |

## 2. Why the rename happened

Earlier iterations of this work used the names "NSV", "NeuralSeedVault",
"neural_seed_vault", and "genome_vault". They were dropped because they
described a *store of weights* rather than the actual invariant the
platform provides: **continuity of an AI system across hardware and time**,
proven by attested, deterministic regeneration. The current names name that
invariant. The old names must not return; §4 enforces it.

## 3. Scope of enforcement

The gate scans `*.go`, `*.md`, `*.yml`, `*.yaml`, `*.proto`, and `*.sh`
under the repository, excluding: `docs/patent_references/` (see above),
`test/doctrine/` (meta-tests that must embed the deprecated tokens to prove
the check catches them), the check script itself, and build/vendor output.

## 4. Deprecated project names (ENFORCED — CI fails on a match)

Matched as whole, case-sensitive tokens:

- `NSV`
- `neural_seed`
- `NeuralSeedVault`
- `neural_seed_vault`
- `genome_vault`

If you are reviving language from a filed patent, place it under
`docs/patent_references/` where it is exempt.

## 5. Vocabulary preferences (ADVISORY — not gated)

Prefer the canonical verb when you write new prose or name new identifiers.
Existing ordinary-English usage is fine and is intentionally not rewritten.

| Prefer | Over | Because |
|---|---|---|
| rewind | restore (byte-exact path) | "rewind" names the byte-exact guarantee; "restore" is generic |
| regenerate | reconstruct / rebuild | regeneration is gated by the equivalence verdict |
| sealed genome | backup | a genome is attested and content-addressed, not a copy |
| seal | encrypt-and-store | sealing binds the artifact to a TEE measurement |
| genome / sealed content | model file / weights file | the unit is the whole sealed genome, not a loose file |

These preferences are advisory precisely so the gate stays meaningful: a
gate that fails on the word "restore" in a CLI help string is noise, and
noise is what gets suppressed wholesale. Keeping §5 out of CI keeps §4
credible.
