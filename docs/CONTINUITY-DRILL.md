# The Continuity Drill

One question, asked of real hardware: **if the machine running your model is
taken, does the model survive — and can you prove the thing that came back is
the same model?**

This document is the answer we can defend. It is a narrative of two drills that
ran on live AMD SEV-SNP confidential VMs, with every number copied from
evidence committed to this repository. Nothing here is simulated except the
adversary, and the adversary only ever touched our own machines.

Every claim below is indexed in [VERIFIABLE-CLAIMS.md](../VERIFIABLE-CLAIMS.md)
with the file that proves it and the command that reproduces it.

---

## Why a drill and not a benchmark

Backups are measured by whether they restore. AI systems are not, because
restoring the bytes of a model is the easy half. The hard half is the question
a regulator, an insurer or a board will actually ask: *is what came back the
same model, and who authorised it to come back there?*

So the drill has to end in a **verdict**, not a checksum. That is what the
equivalence gate produces, and it is why the interesting number in this
document is not a restore time but the line where our own gate **refuses** to
say EXACT.

---

## Drill I — A fine-tune is born in a TEE and survives the hardware

*Run `20260914T234359Z`. Evidence:
[`scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/`](../scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/)*

### 1. Something worth losing

Inside an AMD SEV-SNP confidential VM on GCP, `workers/genome` fine-tunes
**Qwen2.5-0.5B-Instruct** with LoRA, deterministically: pinned seeds, pinned
dependencies, a recorded recipe. Training loss falls **5.325 → 0.00090** over
**75.8 s**, producing **540,672** adapter parameters.

This is the point of the exercise: from here on, there is a real artifact whose
loss would be a real loss.

### 2. It is sealed as a genome, not copied as weights

The platform does not back up the model. It seals the **genome**: the base
model's content digest, the fine-tune as a sealed LoRA delta, and the recipe
that produced it.

| | bytes |
| - | - |
| Base weights (`model.safetensors`) | 988,097,824 |
| **Sealed genome bundle** | **2,208,446** |
| Ratio | **1 : 447** |

The bundle is AES-256-GCM in 1 MiB segments under a **fresh key that is not
inside the file**. The key is escrowed to the release authority at seal time,
so the sealing machine keeps nothing that can open it. Key ID
`genome-fe5271f12d8c-g0-86a89c199469`.

That last sentence is the security property that makes the rest possible: the
bundle can be replicated anywhere — object storage, another cloud, a tape —
because possessing it is not possessing the model.

### 3. It is moved to hardware that has never seen it

The bundle and the escrowed key are delivered to a second machine in another
region. Opening authenticates **every segment before a byte of it is used**,
restores into staging, checks each file against the sealed snapshot, and only
then moves the tree into place:

> 5 files, 2,202,926 bytes, `tree_sha256: 5fe536b0…9503`,
> `restored_verify: "ok: every file matches its recorded digest"`.

### 4. The gate delivers a verdict — including against us

The restored model is replayed against 16 sealed reference fixtures. The gate
walks a **determinism ladder**, trying the strictest door first:

| Destination | door 0 `pinned-replay` | door 1 `native-float` | max abs Δ logit | Verdict |
| - | - | - | - | - |
| Source AMD CPU (the pinned runtime) | **EXACT** | — | **0** | 16/16 bit-identical |
| **NVIDIA L4**, another region | **FAIL** | EQUIVALENT | 1.907e-4 | 16/16 same top-1, same greedy continuation |
| **Intel CPU** | **FAIL** | EQUIVALENT | 1.450e-4 | 16/16 same top-1, same greedy continuation |

Read the middle column again. On foreign hardware **our own gate fails its own
strictest door**, writes that failure into the signed verdict, and only then
falls through to the door whose tolerance was declared in advance (`atol 1e-2`,
`rtol 1e-3` — the measured error is ~50× inside it).

A system that reported "EXACT" here would be easier to sell and impossible to
trust. The `attempts` array in
[`gate-gpu.json`](../scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/gpu/gate-gpu.json)
is the receipt.

### 5. And the recipe replays bit for bit

On the pinned runtime, re-running the sealed recipe reproduces the adapter
exactly — `max_abs_diff 0.0`, every training loss identical. The genome is not
just restorable; it is *re-derivable*.

---

## Drill II — The machine is taken, and the model moves on a signature given in advance

*Run `20260915T021334Z`. Two live SEV-SNP VMs. Evidence:
[`scripts/hardware-test/gcp-failover/evidence/20260915T021334Z/`](../scripts/hardware-test/gcp-failover/evidence/20260915T021334Z/)*

### 1. A sentinel keeps the running model sealed

On the primary, `acpctl sentinel watch` runs a loop: check tripwires **first**,
then seal the settled new state as the next generation with its key escrowed to
the authority, then emit a signed heartbeat. Generations accumulate as a chain.

Order matters. Checking before sealing is what prevents a compromised state
from ever becoming a sealed generation.

### 2. The intrusion

We tamper with a canary path on our own primary. The sentinel's next tick sees
it:

```
wire: path   target: /root/canary
want: e91a347f…da7d      got: 45bb3701…2170
```

It **does not seal**. It signs a compromise report and exits 3. The last clean
sealed state is **generation 1**, sealed 9.0 s before the intrusion.

### 3. The authority decides — because an operator signed for it in advance

The authority observes the compromise report **2.53 s** later and evaluates it
against a **failover policy the operator signed beforehand**, which pins the
sentinel's public key, names exactly one standby with its expected measurement,
lists the triggers, and caps the acceptable RPO.

The decision is written to the signed, hash-chained audit log
(`FAILOVER_DECIDED`) **before any key moves**:

> `decision: failover` — *"compromise-report under failover policy serial 1:
> restore generation 1 on the standby"*

### 4. The key goes to attested hardware, and only there

The key for generation 1 is released to a destination that presented a valid
SEV-SNP attestation whose measurement the policy admits:

> `destination_kind: gcp-sev-snp`,
> `destination_measurement_hex: 7dc7c12e…125acc`,
> `policy_version: failover-policy-v1;failover=1;revocation=1`

### 5. The standby restores, gates, and signs a receipt

| Phase | Measured |
| - | - |
| Detect — tripwire → authority observes | **2.53 s** |
| **RPO** — data at risk | **9.00 s** |
| Key release | 0.27 s |
| Restore — 5 files, 2,202,926 B | **13.2 ms** |
| Gate on the standby | 13.54 s |
| **RTO — intrusion → gated, confirmed, running model** | **16.81 s** |

What came back matters more than how fast:

- **generation 1** — the clean state, *not* the tampered one;
- gate level **EXACT**, 16 fixtures, `max_abs_err: 0`, against a policy that
  required only `EQUIVALENT`;
- audit chain of 5 events, verified, tip `6f9ca6ea…626c`;
- a TEE-signed restore receipt the source verifies before recording the move.

Roughly seventeen seconds after an intrusion, the model is running on different
hardware, and there is a signed, hash-chained record of who authorised it, what
was released, where it went, and proof that it behaves identically.

---

## The line we will not cross

A system that relocates itself to new hardware when it detects a threat is one
design decision away from being a worm. That decision is the most important one
in this project, so it is stated plainly and enforced in code:

| Invariant | Where it lives |
| - | - |
| A key is released **only** to an attested, allow-listed measurement | `internal/vault/failover/gate.go`, ADR 0009 |
| **The operator's signed policy decides**, never the software | `internal/vault/failover/policy.go`, ADR 0012 |
| **One signed policy serial authorises at most one move** — every further hop needs a fresh operator signature | `internal/vault/failover/gate.go` |
| The operator **stop list is a global halt** that overrides any policy | ADR 0010 |
| Every decision is audited **before** any key moves | audit schema v6, `FAILOVER_DECIDED` |

The composition is literal:
`revocation.NewGate(failover.NewGate(allowList, policy), stopList)` — revocation
wraps failover, so a stop is checked outermost and no policy can outrun it.

This software moves a model **because a human signed for it to**, to **one**
place they named in advance, and it cannot move itself twice on one signature.
That is the difference between continuity infrastructure and malware, and we
treat it as the project's primary safety requirement rather than a feature.

Consistent with that: the drill's adversary only ever runs on machines we own,
and neither the attack path nor the cross-device converter is described in any
outreach material.

---

## What the drills do not show

The drills are strong evidence for a narrow claim, and the narrowness is the
point.

- **0.5B, not frontier scale.** Every number here is Qwen2.5-0.5B. A 7B+ run is
  the obvious next measurement and has not been made.
- **CPU TEEs only.** Destinations are AMD SEV-SNP. Attested *GPU* destinations
  need confidential GPUs (H100 CC); untested.
- **SEV-SNP only.** TDX, Nitro and SGX have adapter dispatch (ADR 0002) but no
  shipped offline verifier.
- **Byte-identical inference across devices is unavailable, and we proved it
  against ourselves.** A dedicated probe on an L4 found the CPU↔GPU divergence
  entering at the **first transformer block**, on every fixture, in both float32
  and float64 — a property of the devices' kernels, not of depth, and double
  precision only shrinks it ~16×. Top-1 tokens and top-64 ordering agree 16/16
  regardless. The only byte-portable route is the integer door, which is
  byte-identical by construction and computes its own arithmetic. See
  [`scripts/hardware-test/gpu-exact/README.md`](../scripts/hardware-test/gpu-exact/README.md).
- **No external security review** has been performed on this code.

The complete list of limits is [KNOWN_ISSUES.md](../KNOWN_ISSUES.md) and
[What we do not claim](../VERIFIABLE-CLAIMS.md#what-we-do-not-claim).

---

## Run it yourself

Each script boots its own VMs, harvests evidence to `evidence/<stamp>/`, and
deletes every VM and bucket on exit — including on failure.

```bash
bash scripts/hardware-test/gcp-drill/run.sh    <gcp-project>   # Drill I   (~30 min)
bash scripts/hardware-test/gcp-failover/run.sh <gcp-project>   # Drill II  (~25 min)
bash scripts/hardware-test/gpu-exact/run.sh    <gcp-project>   # the CPU↔GPU probe (~20 min)
```

Neither cloud nor TEE hardware is needed to see the shape of it:

```bash
go run ./cmd/acp-demo
```

Evidence bundles contain measurements, digests, public identities and logs —
**no keys, seeds, tokens or configuration**. Key material never enters an
evidence bundle.
