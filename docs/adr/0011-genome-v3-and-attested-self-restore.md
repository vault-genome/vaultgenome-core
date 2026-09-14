# ADR 0011: Genome v3 and Attested Self-Restore

**Status:** Accepted — implemented (2026-09-14)
**Date:** 2026-09-14
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Builds on:** ADR 0006 (cross-cloud key release), ADR 0009 (per-handshake key delivery), ADR 0010 (operator stop)
**Amends:** Doctrine invariant #07 (no raw export) — see *Doctrine*

---

## Context

The point of a continuity platform is that a model survives the loss of the
machine it runs on: its genome is sealed, the machine goes, and the genome comes
up somewhere else. Three things stood between the platform and that sentence.

1. **The seal did not keep anything secret.** A v2 bundle carried the
   simulated-TEE seed that sealed it (KNOWN_ISSUES #7). Anyone holding the file
   could open it, so bundles could not be stored or replicated anywhere untrusted.
2. **A released key opened nothing.** Cross-cloud release (ADR 0009) delivered a
   DEK into the destination's keystore, and there it stayed (KNOWN_ISSUES #10).
3. **"Restored" was hearsay.** The fourth audit kind,
   `CROSS_CLOUD_RESTORE_COMPLETED`, was recorded on the caller's word
   (`RecordCompletion`); nothing tied it to the destination, its TEE, or the
   genome that was released.

Bundles also had to be read whole into memory to seal or open, which bounds a
genome by RAM rather than by disk.

## Decision

### The v3 bundle (`internal/genome/bundle`)

```
magic(16) ‖ u32 BE header length ‖ header JSON ‖ nonce prefix(7) ‖ segment 0 ‖ … ‖ segment n-1
```

- **Sealed under a key that is not in the file.** Every seal draws a fresh
  32-byte DEK. `acpctl genome seal --key-out` writes it to a 0600 file (never
  over an existing one); nothing else keeps it.
- **Streamed in authenticated segments.** The payload is cut into
  `segment_bytes` (default 1 MiB; the last may be shorter, an empty payload is
  one empty segment). Segment *i* is AES-256-GCM under the DEK with nonce
  `prefix ‖ u32 BE i ‖ last-flag` and additional data `SHA-256(label ‖ header)`.
  Every segment is bound to this header, its position and whether it ends the
  payload, so an edited, reordered, truncated or extended bundle fails — the
  online-AE construction of Hoang, Reyhanitabar, Rogaway and Vizár (CRYPTO 2015)
  that streaming AEADs such as Tink's use. A reader releases no byte of a
  segment before its tag checks, and reports end-of-payload only after the last
  segment, the size and the payload SHA-256 all check out. Sealing and opening
  run in bounded memory; sealing makes two passes over the source (describe,
  then seal) and fails if the source changed between them.
- **A key ID that names its key without revealing it:**
  `genome-<payload prefix>-g<generation>-<key tag>`, the tag being
  `SHA-256("vault-genome key tag v1\0" ‖ DEK)[:6]`. A keystore finds the DEK by
  it; a wrong key file is refused before it opens, releases or registers
  anything (`bundle.CheckKey`).
- The header — chain of custody (generation, parent bundle and payload digests),
  content kind and snapshot, payload digest and size — is public and
  authenticated by every segment.
- **v2 is read-only.** `inspect`, `verify`, `chain` and `lineage` read both
  formats; `open` opens v2 only with `--allow-v2`, so old bundles can be resealed.
  Nothing writes v2.

### Restore, all or nothing (`internal/genome/restore`, `internal/genome/tree`)

The payload is extracted into a staging directory inside the target, read to
its authenticated end, and checked against the header's snapshot: exactly the
files it lists, each with the digest it records. Only then are the files moved
into place. A payload that fails to open or does not match leaves the target as
it was. Every step goes through an `os.Root` on the target.

`tree.Files` derives the restored tree from the header alone and `tree.Digest`
measures it — SHA-256 over the sorted `"<path> <sha256>\n"` lines — so the same
genome restored anywhere has the same tree digest, and anyone holding the bundle
can predict it without the key.

### Release by key file (`sagvd crosscloud-restore -key-file KID:PATH`)

Keys are read from files only; a key file other users can read is refused, and
for a genome key ID the key must match its tag. The hex-in-argv form (`-key
kid:hex`), which left keys in process listings and shell history, is removed.

### Destination self-restore (`acp-bootstrap`, `internal/bootstrap/restorer`)

With a `genome` section the destination watches a directory of bundles — opaque
without their keys, so they can be replicated there ahead of any release. When
the Receiver accepts a token (it reports each delivery through `OnDelivery`), the
Restorer finds the bundle whose header names each released genome key, opens it
through the keystore (the DEK never leaves it), restores it all or nothing into
`restore_dir/<key id>/`, and has **this TEE sign a receipt**:

- the release it used (decision, request, token, key);
- the destination (TEE family and measurement);
- the genome (bundle SHA-256, generation, content kind, payload digest, tree
  digest, files, bytes);
- the timing (key received, restored, restore seconds).

The TEE quotes over `SHA-512("vault-genome restore-receipt v1" ‖ u32 len ‖
receipt)` — the same hardware whose Evidence won the key release. The receipt
is kept beside the tree (it survives restarts) and served at
`GET /v1/genome/receipt?key_id=…`; `GET /v1/genome/restores` lists every restore
and where it stands. The genome key is then wiped from memory. The Restorer acts
only on keys the source released: it never asks for one, never moves a genome
anywhere, and holds no policy.

### Proving the restored model works (`genome.gate`)

A restored tree that matches its snapshot is the right bytes; it is not yet a
model that works on this hardware. A model genome (`workers/genome`: base model
manifest, LoRA adapter, recipe, fixtures) carries reference outputs of the
fine-tuned model — float32 logits at the reference top-k tokens, and greedy
continuations. With `genome.gate` the destination recomputes them before it
signs: a backend (the `vg_genome` door, which first checks the base model against
the manifest) runs every fixture once, and the equivalence gate holds the outputs
to the references — `pinned-replay` byte-exact first, then `native-float`
within the configured tolerance, fail closed otherwise. The verdict (EXACT,
EQUIVALENT or FAIL, the door, the largest error) goes into the receipt, so the
TEE attests not only what it restored but that the model reproduces its
references here. A model that misses is still signed for — as FAIL — so the
source sees it did not come back right; `crosscloud-confirm -require-gate`
refuses to record such a restore.

### Confirmation from the destination's signed word (`sagvd crosscloud-confirm`)

`kms.Coordinator.ConfirmRestore` replaces `RecordCompletion`. It takes the
release from the verified audit log (`kms.FindAuthorizedRelease`), fetches the
receipt, verifies its Evidence with the verifier for the destination's family,
and requires the measurement to be the one the key was released to and the
decision, request, token and key to be the recorded ones. Given the operator's
bundle (`-bundle`), it also requires the restored genome to be exactly that
genome — bundle, payload and tree digests. Only then does it append
`CROSS_CLOUD_RESTORE_COMPLETED`, recording the receipt's facts, the receipt and
Evidence digests, whether the operator's bundle matched, and the release's audit
ID. A receipt that fails records nothing.

### Doctrine

Invariant #07 lists the packages allowed to write files. This ADR adds:

- `internal/genome/bundle` — writes sealed ciphertext only;
- `internal/genome/restore` — materialises a genome whose every segment
  authenticated, by `acpctl` on the operator's machine and by `acp-bootstrap`
  inside the destination TEE the key was released to;
- `internal/genome/receipt` — restore receipts, which carry no genome material.

A new check, **`TestInvariant_07c_AuthorityLinksNoMaterialisation`**, runs
`go list -deps` over every binary and fails if any but `acpctl` and
`acp-bootstrap` links `safetar`, `genome/restore` or `bootstrap/restorer`. The
`sagvd` authority releases keys and confirms restores from receipts; it computes
the expected tree with `genome/tree`, which reads and writes nothing, and never
links code that writes a genome's plaintext.

## Consequences

- A genome can be kept anywhere. Its key moves only by operator policy to an
  attested, allow-listed TEE (ADR 0009), under the operator stop (ADR 0010), on
  the record — or stays in the operator's key file.
- The Continuity Drill's last step runs end to end with the shipping binaries:
  seal → release → the destination restores by itself → the source confirms from
  the destination's TEE-signed receipt → four events on the signed audit log
  (`test/integration/genome_drill_test.go`). **On real AMD SEV-SNP** (GCP n2d,
  run `20260914T223735Z`, `scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/`):
  16 MiB of LoRA-shaped weights restored in 83 ms after the key arrived; the
  chip-signed receipt verified and matched the operator's bundle; release to
  confirmation 2.05 s; refusals for an unlisted guest and under an operator stop
  on the same log. The receipt verifies offline in
  `internal/genome/receipt/hardware_test.go`.
- The audit record of a restore is a hardware-attested statement: which TEE
  restored which genome, byte for byte, how fast.
- Genomes are bounded by disk, not RAM.
- Limits that remain are in KNOWN_ISSUES: the source keeps genome keys in files
  rather than sealed to its own TEE (#11), and hardware attestation is SEV-SNP
  only (#1).

## Alternatives considered

- **Keep v2 and encrypt the seed.** It would have kept a key inside every bundle
  and a single-message payload bounded by memory.
- **One AES-GCM message per bundle.** Simple, but the whole payload must be in
  memory, GCM caps a message at ~64 GiB, and no byte can be released before the
  last one is read.
- **Destination-side restore on operator command.** It would put a human step
  between release and restore, but not a check: the release itself is already
  the operator's decision. The receipt, not a command, is what makes the
  destination accountable.
- **Recording completion from the destination's HTTP answer.** Anyone on the
  path, or a compromised release host script, could have written it. Only the
  TEE that won the release can sign the receipt.

## Proven by

`internal/genome/bundle` (round trip, segment boundaries, streaming, tampering of
every kind with only authenticated bytes released, malformed headers, sources that
change while sealed), `internal/genome/restore` and `internal/genome/tree`
(exact trees, merges, failure leaves the target untouched, reading to the
authenticated end, crafted snapshots and payloads), `internal/genome/receipt`
(signing, forgery, measurement mismatch, malformed receipts), `internal/bootstrap/
restorer` (restore, late bundles, failure and retry, receipts across restarts,
key erasure, HTTP), `internal/vault/kms` (confirmation and every refusal),
`cmd/acpctl`, `cmd/sagvd`, `cmd/acp-bootstrap`, and live in
`test/integration/genome_drill_test.go`.
