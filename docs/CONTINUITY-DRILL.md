# The Continuity Drill

One question, asked of real hardware: **if the machine running your model is
taken, does the model survive — and can you prove the thing that came back is
the same model?**

This document is the answer we can defend. It is a narrative of three drills
that ran on live confidential machines — AMD SEV-SNP VMs on GCP and, in the
third, an Azure confidential GPU VM as the standby — with every number copied
from evidence committed to this repository. Nothing here is simulated except the
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

## Drill III — The standby is a confidential GPU in another cloud

*Run `20260916T150456Z`. A GCP SEV-SNP primary and authority, an Azure NCC
H100 v5 standby. Evidence:
[`scripts/hardware-test/failover-cgpu/evidence/20260916T150456Z/`](../scripts/hardware-test/failover-cgpu/evidence/20260916T150456Z/)*

Drill II again, with one thing changed: the machine the model comes back on
is not another CPU confidential VM in the same project but an Azure
confidential GPU VM on the other side of the Internet — an AMD SEV-SNP guest
under Azure's paravisor with an H100 in confidential-computing mode,
attesting as `azure-cgpu` (ADR 0019): the chip's report from the vTPM, a TPM
quote per challenge with the boot pinned, and NVIDIA's signed tokens for the
GPU.

### 1. The operator names the GPU in advance

The policy (serial 1) pins the primary's sentinel key and chip, and the
standby: kind `azure-cgpu`, its endpoint, its launch measurement
`aa7c9da5…0eef`; the authority's verifier registry pins the vTPM's boot as
well (`pcr_digests: 92fe2c20…26e2`) and holds the Milan anchors it verifies
the primary's reports with. The authority's escrow key is sealed to its own
SEV-SNP chip, as in Drill II.

### 2. The intrusion, and the primary's attested word

The primary fine-tunes two generations; the sentinel seals each with the
chip's report on every record. The attack lands at 15:12:32Z: the tripwire
fires, the sentinel reports `compromised` naming generation 1 as the last
good state, and exits. The authority takes that report only with the primary
chip's report on it.

### 3. The key goes to the GPU — on the chip's, the vTPM's and NVIDIA's word together

> `destination_kind: azure-cgpu`,
> `destination_measurement_hex: aa7c9da5…0eef`,
> `policy_version: failover-policy-v1;failover=1;revocation=1`

Before the key left the authority, the handshake's Evidence was verified
under one nonce: the SEV-SNP report to AMD's Genoa root, the TPM quote under
the attestation key the chip named, its PCR digest matching the pin, and
NVIDIA's ES384 tokens under NVIDIA's key set with the claims policy
(`GH100`, secure boot, no debug, signed manifests, measurements matched).

### 4. The model comes back on the H100, and the gate says so

| Phase | Measured |
| - | - |
| Detect — tripwire → authority observes | **5.59 s** |
| **RPO** — data at risk | **12.00 s** |
| Key release — across the Internet, mTLS | 1.30 s |
| Restore — 5 files, 2,202,999 B | **11.4 ms** |
| Gate on the H100 | 12.11 s |
| **RTO — intrusion → gated, confirmed, running model on the GPU** | **24.99 s** |

- **generation 1** — the clean state, not the tampered one;
- gate level **EQUIVALENT**, door native float on `cuda`, 16 fixtures,
  `max_abs_err: 1.52e-4` against atol 1e-2 — the honest level for a model
  trained on CPUs and proven on a GPU; EXACT is a same-device property
  (Drill II had it on the pinned runtime);
- the receipt signed by the standby carries the same `azure-cgpu` Evidence,
  and the key was erased on the standby after the restore;
- audit chain of 5 events, verified, tip `d46be63a…943a`.

One second slower than Drill II, one cloud further — and the machine that
took the model is one whose GPU signed for its own firmware and driver.

---

## Drill IV — The standby is the other CPU TEE family

*Run `20260916T181528Z`. A GCP SEV-SNP primary and authority, a GCP `c3` Intel TDX
Trust Domain as the standby. Evidence:
[`scripts/hardware-test/failover-tdx/evidence/20260916T181528Z/`](../scripts/hardware-test/failover-tdx/evidence/20260916T181528Z/)*

Drill II once more, with the machine the model comes back on a Trust
Domain — Intel's confidential VM, not AMD's: `acp-bootstrap` attesting as
`gcp-tdx` (ADR 0018), a TDX quote per challenge that the authority
verifies to Intel's root through the PCK chain, with Intel's signed word
on the platform, the TDX module and the Quoting Enclave. One operator
policy, two roots of trust.

### 1. The operator names the Trust Domain in advance

The policy (serial 1) pins the primary's sentinel key and chip
(`69da361d…c790`) and the standby: kind `gcp-tdx`, its endpoint on the VPC, its
measurement `ed70198a…177b` — the image's MRTD and three RTMRs folded into one
word. The authority's registry holds the `gcp-tdx` entry beside the Milan
anchors it verifies the primary's records with; the TCB documents it
fetched from Intel, and verified, are in the evidence.

### 2. The intrusion, and the primary's attested word

At 18:27:18.85Z the tripwire fires; the sentinel's compromise report
carries the primary chip's report, the authority observes it 10.11 s
later and decides at 18:27:28.96Z: generation 1, the last sealed before
the attack.

### 3. The key goes to Intel's silicon, on Intel's word

The handshake across the VPC: the authority's challenge, the Trust
Domain's quote for it — the attestation key and the PCK chain to the
pinned Intel SGX Root CA, Intel's signed TCB info and QE identity current
for the platform, no DEBUG, the measurement the policy pinned — verified
at 18:27:30.04Z, and the key released 1.09 s after the decision.

### 4. The model comes back on Intel CPUs, and the gate says so

| Phase | Measured |
| - | - |
| Detect — tripwire → authority observes | **10.11 s** |
| **RPO** — data at risk | **12.00 s** |
| Key release — across the VPC, mTLS | 1.09 s |
| Restore — 5 files, 2,210,917 B | **11.6 ms** |
| Gate on the Trust Domain's CPUs | 10.87 s |
| **RTO — intrusion → gated, confirmed, running model on Intel silicon** | **24.09 s** |

- **generation 1** — the clean state, not the tampered one;
- gate level **EQUIVALENT**, door native float on `cpu`, 16 fixtures,
  `max_abs_err: 1.45e-4` against atol 1e-2 — the references were sealed
  on AMD Milan cores and the model proven on Intel Sapphire Rapids cores,
  and float32 is not byte-identical across CPU vendors either: the same
  order of difference as CPU↔GPU in Drill III (1.52e-4). EXACT is a
  pinned-runtime property (Drill II had it); the integer door is the
  byte-portable route;
- the receipt signed by the standby carries its TDX quote as Evidence,
  and the key was erased on the standby after the restore;
- audit chain of 5 events, verified, tip `03758aa2…4cb3`.

One policy, two vendors' roots of trust: the machine that lost the model
was AMD's word, the machine that took it Intel's, and the operator signed
for the move before either had happened.

*Since ADR 0022 the authority itself can be a Trust Domain: in
[`failover-tdx-authority`](../scripts/hardware-test/failover-tdx-authority/README.md)
(run `20260916T200841Z`) the authority's escrow key is sealed to the guest's vTPM
under a policy of the pinned boot, re-provisioned through the recovery
ceremony on TDX, and the same failover runs with RTO 20.27 s — the
authority, the primary and the standby on three different roots of
trust.*

---

## Drill V — The authority says no

*Run `20260916T191033Z`. The failover drill's two GCP SEV-SNP machines, one attack,
eight policies. Evidence:
[`scripts/hardware-test/failover-negatives/evidence/20260916T191033Z/`](../scripts/hardware-test/failover-negatives/evidence/20260916T191033Z/)*

Drills II to IV each asked the authority one question and got one yes.
This drill asks eight against the same compromise report and expects
seven refusals, each for a different reason, each decided where the code
decides it: on the audit record for a trigger that reaches the policy
engine, at the door for a policy that cannot be admitted at all.

### 1. Seven ways to say no

| # | The operator's policy | The answer |
| - | - | - |
| 1 | stood 45 s; armed before the attack, expired when the report came | declined on the record — *failover: policy serial 1 expired at 2026-09-16T19:14:30Z* |
| 2 | allows at most 1 s of lost state | declined — *the newest trustworthy genome, generation 1, was sealed 11.996s before the trigger; the policy allows at most 1s* |
| 3 | quarantines a day | declined — *no genome in the verified chain was sealed by 2026-09-15T19:21:48.792219003Z and checks out* |
| 4 | a good policy, under an operator stop | decided, hand-shake, **the chip verified** — and the release **denied** — *operator stop in force (revocation serial 2): incident review* |
| 5 | pins another machine as the standby | decided, hand-shake, **the chip verified** — and **denied** — *failover policy serial 5 releases only to its standby (gcp-sev-snp, measurement [69da361d…c790]); gcp-sev-snp 21199b36…9546 is not it* |
| 7 | policy 6 again, after its move | refused at the door — *failover: policy serial 6 already carried out a failover (audit event xcc-evt-…000c); moving again needs a new policy* |
| 8 | signed by a stranger | refused at the door — *failover: signature does not verify under the operator key* |

Runs 4 and 5 are the ones to read twice. The standby is genuine: its SEV-SNP
report verified under the authority's nonce
(`CROSS_CLOUD_ATTESTATION_VERIFIED`). The key still did not move, because the
operator's stop list said stop, and because the policy named another machine.
Hardware says who you are; the operator says whether you may.

### 2. The one move, and what it refused to carry

Policy 6 is a good policy, and the replica it acts on has been reached by the
intruder: one byte of `gen-000001.genome` flipped (`addaaf0c…be7d` →
`640046c8…5671`). The chooser reads the sentinel's signed record for
generation 1, hashes the bundle, and sets it aside on the record — *sentinel:
gen-000001.genome hashes to 640046c8…5671 (2216819 bytes), the record says
addaaf0c…be7d (2216819 bytes)* — then takes generation 0, the newest state
whose bytes match the sentinel's word:

| Phase | Measured |
| - | - |
| **RPO** — the attack less generation 0's seal | **270.0 s** |
| Key release | 0.04 s |
| Restore — 5 files, 2,209,723 B | **12.7 ms** |
| Gate on the standby | 11.80 s |
| Failover — trigger observed → confirmed | 12.06 s |

Generation 0 came back **EXACT** (16 fixtures, `max_abs_err: 0`) on the same
runtime. Four and a half minutes of training given up rather than one
corrupted byte restored — and the record says which byte, in which bundle,
against which signed hash.

### 3. One record

Sixteen events on one hash-chained audit log, verified offline, tip
`05a015c1…7161`: three declines, two decisions that ended in
`KEY_RELEASE_DENIED` after the chip verified, and one that ended in
`CROSS_CLOUD_RESTORE_COMPLETED`. Runs 7 and 8 left nothing on it, on purpose:
a spent or unsigned policy is refused before the authority acts on its behalf.
The stop list, the policies and the audit log share one operator key — which
is why a stranger's policy, issued under the operator's key id, is refused at
the door.


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

- **0.5B in the drills, 7B at most.** Every number here is Qwen2.5-0.5B. A
  7B run through the same path exists
  ([gpu-7b](../scripts/hardware-test/gpu-7b/README.md)): EXACT on the pinned
  L4, its recipe replaying bit for bit, and the float door failing closed
  across devices in bfloat16 while the answers stay the same. Nothing larger
  has been run.
- **One GPU leg, once, at 0.5B.** Drill III's standby is an attested
  confidential GPU, run once with the 0.5B model. In that run its GPU
  measurements were NVIDIA's evaluation, verified by NVIDIA's signature; the
  verifier now evaluates the report itself as well (ADR 0021, `both`), and
  the manifests' XML signatures verified; what stays NVIDIA's word is
  revocation.
  In that run the standby held no sealed escrow key; since ADR 0022 a
  host of either family seals the key to its vTPM under a policy of the
  pinned boot, and can be an authority.
- **SEV-SNP, TDX and the Azure confidential GPU only.** Nitro and SGX have
  adapter dispatch (ADR 0002) but no shipped offline verifier. A TDX host
  and an Azure confidential GPU host seal to their vTPM (ADR 0022) — a root
  the cloud provider virtualises, not the TEE's own. Each other-family standby — the GPU (Drill III) and the TDX Trust
  Domain (Drill IV) — has taken one key release, once, at 0.5B.
- **Byte-identical inference across devices is unavailable, and we proved it
  against ourselves.** A dedicated probe on an L4 found the CPU↔GPU divergence
  entering at the **first transformer block**, on every fixture, in both float32
  and float64 — a property of the devices' kernels, not of depth, and double
  precision only shrinks it ~16×. Top-1 tokens and top-64 ordering agree 16/16
  regardless. The only byte-portable route is the integer door, which is
  byte-identical by construction and computes its own arithmetic — built
  for the real model since ADR 0020 and measured: the same bytes on a Xeon
  and an L4 at 0.5B and 7B, EXACT at zero tolerance where the float doors
  fail ([integer-door](../scripts/hardware-test/integer-door/README.md)).
  See also [`scripts/hardware-test/gpu-exact/README.md`](../scripts/hardware-test/gpu-exact/README.md).
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
bash scripts/hardware-test/failover-cgpu/run.sh <gcp-project> [gcp-zone] [azure-rg]   # Drill III (~25 min; GCP + an Azure NCC H100 v5)
bash scripts/hardware-test/failover-tdx/run.sh <gcp-project> [n2d-zone] [tdx-zone]     # Drill IV  (~15 min; two GCP n2d SEV-SNP CVMs + a c3 TDX Trust Domain)
bash scripts/hardware-test/failover-negatives/run.sh <gcp-project> [zone]          # Drill V   (~15 min; two GCP n2d SEV-SNP CVMs)
bash scripts/hardware-test/gpu-exact/run.sh    <gcp-project>   # the CPU↔GPU probe (~20 min)
```

Neither cloud nor TEE hardware is needed to see the shape of it:

```bash
go run ./cmd/acp-demo
```

Evidence bundles contain measurements, digests, public identities and logs —
**no keys, seeds, tokens or configuration**. Key material never enters an
evidence bundle.
