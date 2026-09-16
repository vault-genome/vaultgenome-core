# ADR 0013: The Worker Restores the Genome

**Status:** Accepted — implemented (2026-09-15)
**Date:** 2026-09-15
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Builds on:** ADR 0008 (equivalence gate), ADR 0011 (genome v3, key escrow)
**Amends:** the `POST /v1/jobs` body (the job names a sealed genome; it no longer carries a payload); `acp-compute` configuration (a `genome.door` section is required); `sagvd` configuration (a `genome` section enables jobs)

---

## Context

Until this decision the compute worker, `acp-compute`, did not compute anything
of a model. The Return Path was real — mutual TLS, the TEE-evidence handshake,
one sealed job per session, a worker-signed candidate output — but what the
worker did with the sealed bytes was a labelled placeholder: a SHA-256
expansion (V1), then a byte-level order-3 Markov chain (V2). Both said so in
their own comments, [KNOWN_ISSUES](../../KNOWN_ISSUES.md) #2 said so, and the
claims register said so. The output of a job proved that the delivery path
worked and nothing about a model.

Meanwhile the model side existed beside it. `workers/genome` fine-tunes a real
model deterministically and writes its genome — the base model's manifest, the
LoRA delta, the recipe, the fixtures — and `acpctl genome gate` brings it back
from a restored directory and proves it with the equivalence gate (ADR 0008).
`acp-bootstrap` does the same inside the destination TEE after a key release
(ADR 0011). The two halves had never met: the daemon that speaks the Return
Path could not run the model, and the code that runs the model did not speak
the Return Path.

A worker that restores a model raises the question ADR 0011 answered for the
destination: **what may touch the disk?** Doctrine invariant #07 allows a
genome's plaintext to be written only by the packages that materialise a
restore, and invariant #07c allows only `acpctl` and `acp-bootstrap` to link
them. `acp-compute` is neither, and should not become one: a worker that leaves
model files behind is a worker whose host now holds the genome.

## Decision

A job is a **gate job**: the authority ships the worker the model side of a
sealed genome, the worker brings the model back in memory and answers the
genome's own reference prompts, and the authority holds the answers to the
sealed references. No other kind of job exists.

### The authority builds the job

`POST /v1/jobs` names a bundle in `genome.bundle_dir` and, unless its escrow
envelope is beside it, its key file:

```json
{"genome": {"bundle": "gen-1.genome", "key_file": "gen-1.key"}, "deadline_seconds_from_now": 300}
```

`sagvd` opens the bundle in memory with that key — the operator's key file, or
the envelope `gen-1.genome.escrow` opened with `genome.key_escrow_path` — and
keeps two things: the fixtures' **references** (the sealed model's logits at
its top-k tokens, from `fixtures.json`), and the operator's tolerance
(`genome.gate`). It ships the rest of the model side, one sealed component
each under the session key: `genome.json`, every file of the adapter, and
`prompts.json` — the fixtures' token ids and top-k indices, with the expected
outputs stripped. Component 0 is a descriptor naming every file, its SHA-256,
its size and its component (`internal/genome/gatejob`). Each component's
associated data binds it to the job and to its index, so a component cannot
be replayed under another job or at another position.

The job's `expected_output_max_bytes` is the exact size of a right answer:
the output is canonically encoded, so its size depends on the fixture ids and
shapes only. The authority names the job's manifest and session itself; a
caller no longer supplies them.

### The worker restores in memory

`acp-compute`'s only backend is `worker.GenomeReconstructor`. It checks every
component against the descriptor's digests, hands the files to the **door**
its configuration names, on stdin, as one JSON document, and returns the
door's outputs as the candidate — `gatejob.Output`, bound to the genome id.
The reference door is `python -m vg_genome door --stdin-genome --base BASE_DIR`
(`workers/genome`): it checks the adapter's digest against `genome.json`,
checks the public base model on the worker's disk against the genome's
manifest, pins the runtime, loads the base, applies the adapter from memory,
and recomputes each prompt. Nothing of the genome is written: the adapter, the
description and the prompts exist as process memory and pipe bytes.

The frozen R-11 interface (`worker.Reconstructor`, `frozen_test.go`) is
unchanged, and so is the output-kind enumeration: a gate job is
`bytes/fixed-length`. The worker never sees a reference output; it cannot
answer by echoing.

### The authority judges the answer

After the Return Path has verified the candidate's bindings, budget and
signature, `sagvd` decodes it and descends the determinism ladder (ADR 0008):
door 0, `pinned replay`, byte-exact; door 1, `native float`, within the
operator's tolerance. A door opening makes the job **succeeded**, with the
verdict on the job — signed by the authority's signing key — and the level,
door, rung and every attempt visible on `GET /v1/jobs/{id}` under `gate`. No
door opening makes the job **failed** with `gate_failed`, the verdict still on
record. An answer that is not an answer — another genome's, or unreadable —
is an integrity failure, `gate_output_invalid`. The metric
`sagvd_gate_verdicts_total{level}` counts every verdict.

### What is deleted

The Markov backend (`generative.go`) and its tests, and the REST body's
`payload_base64`. The deterministic reference backend stays, as a test fixture
for the Return Path and the in-process pipeline demo, because the frozen
interface test pins its identifiers; no binary builds it.

## Consequences

- **The Return Path carries a model.** A job round trip now ends in a
  verdict on a restored model, not in bytes with no meaning. The live-daemon
  suite runs it over mutual TLS with a door that speaks the protocol exactly
  (`test/integration/fakedoor`); the `genome-worker` workflow runs the real
  door, real torch, real fine-tune, genome delivered in memory
  (`TestGenomeReconstructor_RealDoor`).
- **Invariants #07 and #07c hold as they are.** `acp-compute` still links no
  package that writes a genome, and `internal/compute/worker` uses no write
  sink; the door reads its base model and writes nothing.
- **The worker needs a runtime.** A worker host carries Python, the pinned
  torch and `vg_genome`, and the public base model the genome names. A door
  that cannot run fails the job as `door_failed`; a base that does not hash
  to the manifest fails it the same way, with the reason.
- **The Return Path bounds the genome.** One job is one frame of at most 16 MiB,
  and the model side travels base64 inside it: about 11 MiB of adapter per
  job, and `runtime.max_payload_bytes` (default 4 MiB) below that. A LoRA
  adapter of a 0.5B–7B model fits; a full-weight fine-tune does not, and is
  the cross-cloud key-release path's job (ADR 0011), not this one.
- **The authority holds the genome in memory while it seals the job**, as it
  held every payload before. It still writes none of it. Keys reach it as a
  key file or through escrow, as ADR 0011 already had them; KNOWN_ISSUES #11
  (the escrow key is a file on the release host) is unchanged by this
  decision.
- **Callers change.** `payload_base64`, `manifest_id`, `session_id`,
  `expected_output_kind` and `expected_output_max_bytes` are gone from the
  request; `manifest_id`, `session_id` and the genome view come back in the
  response.

## Alternatives considered

- **Keep `payload_base64` beside the gate job.** A job whose output means
  nothing is a placeholder with a different name. Refused.
- **Have the worker restore to disk and run the existing `door --genome DIR`.**
  It would have needed the worker to link the materialising packages, which
  invariant #07c forbids for a reason: a worker host that holds model files
  holds the genome. Refused.
- **Deliver the genome by key release (ADR 0011) instead of over the Return
  Path.** Right for full checkpoints and for a fleet of workers, and the next
  step for large genomes; it does not replace the job path, which is what the
  authority uses to ask one attested worker one question about one genome.
  Deferred, not refused.
- **Let the job carry its own tolerance.** The operator declares the
  tolerance in advance in `sagvd`'s configuration; a job that could loosen it
  would move a governance decision to whoever holds the API token. Refused.

## Proven by

- `internal/compute/worker/genome_test.go` — the reconstructor against a test
  door: canonical output of the exact budgeted size, purity, order
  insensitivity, every malformed job structural, a component not as described
  integrity, a failing, hanging, lying or over-talkative door operational.
- `cmd/sagvd/genome_job_test.go` — the job as built: nothing but the model
  side leaves the authority, the descriptor's digests match, the AAD binds
  index and job, the escrow path, every refusal; the ladder on a right, a
  drifted and a wrong answer; the signed verdict verifies and detects
  tampering.
- `test/integration/daemons_test.go` — the shipping binaries over mutual TLS:
  EXACT with a signed verdict, FAIL on the record for a genome that misses
  its references, a wrong key refused at submission, an escrowed genome with
  no key file in the bundle directory.
- `workers/genome/tests` and `.github/workflows/genome-worker.yml` — the real
  door on a real fine-tune, from disk and from memory, EXACT on the runtime
  that sealed it.
