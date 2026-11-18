# The Continuity Drill

One question, asked of real hardware: **if the machine running your model is
taken, does the model survive — and can you prove the thing that came back is
the same model?**

This document is the answer we can defend. It is a narrative of nine drills
that ran on live confidential machines — AMD SEV-SNP VMs on GCP, an Intel TDX
Trust Domain and an Azure confidential GPU VM as standbys — with every number
copied from evidence committed to this repository. Nothing here is simulated
except the adversary and, from the seventh on, the loss of power,
and both only ever touched our own machines.

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

## Drill VI — The authority is lost

*Runs `20261015T171848Z`, `20261015T173009Z`, `20261015T174115Z`. Two GCP SEV-SNP
machines, one after the other. Evidence:
[`scripts/hardware-test/authority-loss/evidence/`](../scripts/hardware-test/authority-loss/evidence/)*

Drills II to V lose a primary and watch the authority move the model.
This one loses the **authority** — `sagvd`, the process that signs every
verdict and holds the escrow key — and asks how long until a fresh
machine *is* that authority again, and what of it comes back.

### 1. What an authority is made of

Before the first job, machine A does what an operator does before relying
on an authority. The key material `acp-keygen -private` made — the signing
seeds, the TLS identities, the API token, the worker registry — goes to
the **operator's safe** before the host seals its own copies to its chip
(`sagvd seal-keys`, `acp-compute seal-keys`,
[ADR 0023](adr/0023-the-daemons-key-files-sealed-to-the-host.md)); in the
drill the safe is an object in the run's private bucket, the model of a
secrets manager. The escrow key is made inside `sagvd`, sealed to the chip,
and wrapped to the operator's recovery key
([ADR 0016](adr/0016-escrow-key-sealed-to-the-release-host.md)); the
envelope goes to the safe. Then A fine-tunes a tiny model, seals it, and
runs gate jobs over the Return Path in a loop — a job every eight seconds,
5.3 s each, sixteen audit events each — replicating its state after every
job: the audit log and the genomes, as one tar in the bucket, with the
job's tip in a manifest.

### 2. The deletion

The runner waits until A has completed three jobs, then deletes the VM
while a job is in flight. The guest gets no warning: `gcloud compute
instances delete`, issued at a moment the runner records. In the three
runs A had completed four, five and four jobs; the job submitted
after the last completed one was never done. Its audit events, appended
on A after the last replica, died with A.

### 3. A fresh machine becomes the authority

Machine B is created the moment A's deletion is issued. It reads nothing
of A but the safe and the replica:

1. the key material from the safe, sealed to **B's** chip (`sagvd
   seal-keys`, `acp-compute seal-keys`) — the same seeds, so the same
   signing key, the same audit key, the same certificate, the same token;
2. the replica of the audit log and the genomes; `acpctl audit verify`
   on the replica before anything appends to it: `ok: true`, 64, 80 and
   64 events, with the tip A's last manifest named;
3. the escrow key through the recovery ceremony — `acpctl escrow recover
   | sagvd escrow-provision -stdin` — sealed to B's chip: the key tag A's
   provisioning printed (`ced42a93…`, `ad0f082e…`, `a08e386a…`) comes out
   of the ceremony on B;
4. `sagvd identity` and `acp-compute identity` on B: each daemon reads
   its launch measurement from the chip and pins the other's (on the same
   image, the same value A had: `7dc7c12e…25acc`);
5. `sagvd` starts over the replica — `sagvd audit log open … events=64
   tip=75b63362…` in its log (the third run) — the worker connects, and B finds from A's
   markers which job was lost, submits it again, and signs the first
   verdict after the loss: EXACT 6/6, sealing the next event on A's chain.

### 4. The numbers

| Phase (run `…174115Z`; the other two runs' values are in the kit's README) | Measured |
| - | - |
| A's deletion issued → B created | 33.6 s |
| B's boot until its first line | 74.8 s |
| the worker's runtime from the hash-pinned locks | 330.2 s |
| the replica restored | 1.1 s |
| identities, the replica verified, both daemons' key files sealed | 10.5 s |
| the recovery ceremony | 10.3 s |
| both daemons up, the session open | 22.2 s |
| the first verdict after the loss | 5.4 s |
| **RTO cold** — deletion issued → first verdict, B created on demand | **489.3 s** |
| **RTO warm** — the runtime in place → first verdict | **49.5 s** |

Three runs: RTO warm 49.7 s, 49.3 s, 49.5 s — the procedure does not
move; RTO cold 235.8 s, 237.2 s, 489.3 s — the third run's fresh VM took
330 s for the runtime from the locks against 78–80 s in the other two, a
package mirror's day, not the product's. The runner checks four facts from the two records
(`timeline.txt`): the authority signing key and the audit key the same on
A and B; the escrow key the same after the ceremony; the replica's chain
intact before B appends to it; the final chain — A's events and B's in
one file — intact under the one audit key (the third run; the first two
runs' stop step signalled the daemons' subshells and left `sagvd` holding
the file's lock, a bug of the kit, fixed and recorded in its README).

### 5. What it says

The authority is not the machine: it is the key material in the safe, the
escrow envelope, and the audit log's replica. Given those three, a machine
nobody had seen before is the authority in fifty seconds, and the chain of
decisions does not break. What the drill lost in its first three runs was
the job in flight, because the queue was in memory
([KNOWN_ISSUES.md](../KNOWN_ISSUES.md) #16); with the job store on disk
(ADR 0026) and in the replica from the moment a job is accepted, the
fourth run (`20261015T204339Z`) lost nothing: the new host's `sagvd`
admitted the lost job again by itself — the same job id, the same request
id, `resumed` on its audit record — and signed it EXACT 49.1 s after its
runtime was ready. What the cold number is mostly made of is not the
product: a VM's boot and a package mirror's speed. A standby with the
runtime and the binaries in place is the warm number; a continuous
replica in place of the drill's per-job copies is the remaining piece.

---

---

## Drill VII — The region goes dark

*Run `20260930T194321Z`. A GCP SEV-SNP primary in us-central1, the authority
in europe-west4, the Azure NCC H100 v5 standby of Drill III in West Europe.
Evidence:
[`scripts/hardware-test/failover-region-loss/evidence/20260930T194321Z/`](../scripts/hardware-test/failover-region-loss/evidence/20260930T194321Z/)*

Drills II to V begin with an intruder the sentinel catches. This one begins
with nothing: no intruder, no tripwire, no report. The primary is switched
off in the middle of its work and deleted, the way a strike or a total loss
of power would take it, and the only sign the authority ever gets is that
the heartbeat stops.

### 1. The operator signs for silence

The policy (serial 1) pins the primary's sentinel and chip and the GPU
standby as in Drill III, and has one trigger: **no heartbeat for 15 s**. A
compromise report would not count. The authority runs in another region
from the primary; the replica it reads lives in a bucket in that region too.

### 2. The primary goes dark

The primary seals generation 1 at 20:01:36Z and starts training generation 2.
Its last heartbeat to leave the machine, #209 at 20:01:57Z, says `watching`,
newest sealed generation 1, signed, with the chip's report. At 20:02:02Z it
switches itself off through the kernel's sysrq trigger — no shutdown, no
signal to the sentinel, no `stopped`. Generation 2 dies at step 11 of 160,
unsealed.

Google's API went on reporting the machine `RUNNING` for another 53 seconds;
its audit log records the guest's termination at 20:02:55Z. The operator then
deleted the machine and its disk, and Google answered that it did not exist.

### 3. Fifteen seconds of silence, then the policy

| Phase | Measured |
| - | - |
| Detect — the heartbeat's last rise → the authority acts | **15.01 s** (the policy's timeout) |
| **RPO** — generation 2's unsealed training | **21.01 s** |
| Key release — the H100 host attested, across the Internet | 2.87 s |
| Restore — 5 files, 2,210,917 B | **9.8 ms** |
| Gate on the H100 | 6.75 s |
| **RTO — last heartbeat seen → gated, confirmed, running model on the GPU** | **25.97 s** |

- **generation 1** — the last state the primary sealed; generation 2 never
  existed as far as the authority is concerned;
- gate level **EQUIVALENT** on the H100, 16 fixtures, `max_abs_err: 1.52e-4`
  — the same honest level as Drill III;
- the key released only after the standby's chip, vTPM and GPU verified
  under one nonce, and erased on the standby after the restore;
- audit chain of 5 events, tip `3488b31c…153f`, verified again offline from
  the log file itself.

Measured from the primary's own record of the power-off, the model was back
26.14 s later — and confirmed on the H100 27 seconds before Google's own
audit log recorded that the machine had stopped. The failover did not wait
for anyone to say the primary was dead. Its silence was enough, because the
operator had signed for it in advance.

### 4. The same drill, sixteen days later

*Run `20261016T210544Z`, on the tree of 16 October, the same three machines.
Evidence:
[`scripts/hardware-test/failover-region-loss/evidence/20261016T210544Z/`](../scripts/hardware-test/failover-region-loss/evidence/20261016T210544Z/)*

| Phase | Measured |
| - | - |
| Detect — the heartbeat's last rise → the authority acts | **15.01 s** (the policy's timeout) |
| **RPO** — generation 2's unsealed training | **21.00 s** |
| Key release — the H100 host attested, across the Internet | 3.13 s |
| Restore — 5 files | **11.8 ms** |
| Gate on the H100 | 6.82 s |
| **RTO — last heartbeat seen → gated, confirmed, running model on the GPU** | **26.24 s** |

The same shape to the hundredth of a second where the policy sets it, and
within a third of a second elsewhere: EQUIVALENT on the H100 again
(`max_abs_err: 2.48e-4`), five audit events, tip `16f6058b…c896`, verified
offline. The model was confirmed back 24.74 s after the power-off by the
primary's own clock, and 5.4 s before Google's audit log recorded that the
guest had terminated; Google's API showed the machine `RUNNING` for 29 s
after it had switched itself off. Generation 1 was already on the standby
when the power went: the copy loop that raced the primary's uploads in the
first run had the bundle in place this time.

## Drill VIII — The machine is lost, and training goes on

*Run `20261111T135725Z`. Two GCP SEV-SNP guests of one machine type
(n2d-standard-8, AMD EPYC 7B13) in us-central1; the standby hosts the
authority and the destination, as in Drill II. Evidence:
[`scripts/hardware-test/training-continuity/evidence/20261111T135725Z/`](../scripts/hardware-test/training-continuity/evidence/20261111T135725Z/)*

Until this drill, a model that came back was proven — and at rest. Where a
primary "kept training" in the drills above, it ran a second recipe from the
base. This drill asks what a team in the middle of a training run would ask:
the machine is gone — does the *training* go on somewhere else, and does it
arrive where it would have arrived?

### 1. A genome that knows where training stood

A genome now carries, beside the adapter, the state training stood in: the
optimizer's moments and step counts, the place in the data, the generators
(ADR 0040) — 4.4 MB beside a 2.2 MB adapter, sealed with it. The primary
takes the recipe's first 80 steps and the sentinel seals generation 0. It
then goes on *from its own genome* to step 160 — the state read back from
the genome's files, nothing kept in memory — and the sentinel seals
generation 1 at 14:16:15Z. `replay` runs the whole recipe from the base, 160
steps, on that chip, and compares: the adapter is the same to the bit, the
160 losses are equal.

### 2. The machine is lost while it trains

The primary goes on toward step 240. At 14:18:04.2Z by its own clock, with
steps being taken and the sentinel beating, it switches itself off through
the kernel's sysrq trigger. No shutdown, no report, no `stopped`. Google's
API goes on saying `RUNNING` for 56 seconds; then the operator's script sees
it terminated and deletes it. Everything after step 160 dies unsealed.

### 3. Thirty seconds of silence, and a gate that must say EXACT

The policy (serial 1) acts on the sentinel's silence alone — no heartbeat
for 30 s; a compromise report would not count — and, unlike the policies of
the drills before it, requires the standby's gate to say **EXACT**: a
standby whose arithmetic differed in its last bits would be declined.

| Phase | Measured |
| - | - |
| Detect — the heartbeat's last rise → the authority acts | **30.02 s** (the policy's timeout) |
| **RPO** — how long generation 1 had been sealed when the heartbeat stopped | **105.0 s** |
| Key release — the standby attested | 0.25 s |
| Restore — 8 files, 6,594,672 B, the state among them | **44 ms** |
| Gate on the standby — 16 fixtures, pinned replay | 9.86 s, **EXACT**, max abs err 0 |
| **RTO — last heartbeat seen → gated, confirmed model on the standby** | **40.30 s** |

What came back is, file by file, what the primary sealed: seven of seven.
Five audit events, tip `cf8179ad…8512`, verified offline.

### 4. Training goes on

0.16 s after the authority confirmed the restore — 40.2 s after the
primary's power went, while Google's API still showed it running — the
standby took the restored genome from step 160 to 240. It was told one
thing: the number 240. The recipe, the data, the optimizer's state and the
place in the data were the genome's. Eighty steps took 36.6 s. The genome it
wrote names the two it came from: `continued_from: [80, 160]`.

### 5. Is it the model it would have been?

Three answers, all on the standby's chip:

- **`replay`** ran the recipe from the base, 240 steps, and compared the
  adapter with the continued one: the same to the bit, `max_abs_diff: 0.0`,
  the 240 losses equal.
- **The recipe in one go**, 240 steps on the standby with no stop at all,
  gave the same seven files — the adapter `0041a292…44bd`, its config, the
  fixtures, the data, the optimizer's state, the cursor, the generators —
  and the same 240 losses.
- **The gate** judged the continued genome EXACT.

A training run interrupted twice — once by its own schedule, once by the
loss of its machine — and finished on another machine is the run that was
never interrupted.

### 6. Twice, and in another cloud

*Runs `20261111T132834Z` and, on EC2, `20261111T143104Z`. Evidence:
[`…/evidence/20261111T132834Z/`](../scripts/hardware-test/training-continuity/evidence/20261111T132834Z/),
[`…/evidence/aws/20261111T143104Z/`](../scripts/hardware-test/training-continuity/evidence/aws/20261111T143104Z/)*

The drill had run half an hour earlier on two other guests: thirteen checks
of thirteen, RTO 41.29 s, and every digest — generation 1's seven files and
the continued genome's — the same as in the run above. Four guests, one
result.

Then one EC2 instance with AMD SEV-SNP in Ohio, an AMD EPYC 7R13 under
another hypervisor and another kernel, ran the recipe stopped at steps 80
and 160 and continued to 240. There too it is the recipe in one go, `replay`
exact. And its digests, at step 160 and at step 240, are Compute Engine's:
seven files of seven each. No failover ran there; the measurement is of the
arithmetic. A genome sealed in one of these clouds and continued in the
other arrives at the same bits.

---

## Drill IX — The standby goes on by itself

*Run `20261118T014101Z`. Three GCP SEV-SNP guests: the primary and the
standby of one machine type (n2d-standard-8, AMD EPYC 7B13) in
europe-west4-a, and the authority alone on a third (n2d-standard-4) in
us-central1-c. Evidence:
[`scripts/hardware-test/closed-turn/evidence/20261118T014101Z/`](../scripts/hardware-test/closed-turn/evidence/20261118T014101Z/)*

In Drill VIII the model came back and training went on — because the
drill's script said so. No sentinel sealed what the standby trained, and
nobody could ask the model anything. A standby like that is a copy, not a
primary. This drill asks for the rest: the machine is gone and nobody is
at a keyboard — does the standby train on, protect what it trains, and
answer, and does the authority know?

### 1. What is decided before the failure

Three things, all before anything goes wrong (ADR 0041).

The standby makes a sentinel key of its own, seals it to its chip, and
hands the public half to the operator. The operator's policy — a v2
policy, serial 1 — names it beside the primary's: the key the standby's
sentinel will sign under, and the measurement every record it signs must
be attested at. The primary and the standby boot one image and attest one
measurement, so the key, sealed to one chip, is what tells them apart.

The standby's `acp-bootstrap` is given one command to run after a restore
its required gate passed. The command moves no key.

And the authority is alone on its machine, in another region: it is not
lost with the primary, and it does not live on the machine that becomes
one.

### 2. The primary answers, and is lost

The primary takes 80 steps, then goes on from its own genome to 160; the
sentinel seals generations 0 and 1, and `replay` holds generation 1 to the
whole recipe on that chip. Then it is asked a question, one of the facts
the recipe teaches. At 01:55:05Z it answers from generation 1 — nine
tokens, 3.2 s: *"The drill site is called Harbor Lantern."* — and the
answer names the adapter it came from and the step training stood at.

It goes on toward step 240. At 01:55:26Z by its own clock, at step 161,
it switches itself off. The operator's script sees it terminated and
deletes it.

### 3. Thirty seconds of silence

| Phase | Measured |
| - | - |
| Detect — the heartbeat's last rise → the authority acts | **30.03 s** (the policy's timeout) |
| **RPO** — how long generation 1 had been sealed when the heartbeat stopped | **111.0 s** |
| Key release — the standby attested | 0.59 s |
| Restore — 8 files, 6,594,672 B | **47 ms** |
| Gate on the standby — 16 fixtures, pinned replay | 9.82 s, **EXACT**, max abs err 0 |
| **RTO — last heartbeat seen → gated, confirmed model on the standby** | **40.85 s** |

What came back is, file by file, what the primary sealed.

### 4. Nobody does anything

At 01:56:04Z the receipt is signed, and `acp-bootstrap` runs its one
command. In 5.1 s it has put the restored genome where the model lives
and started three services: the standby's own sentinel, with the restored
bundle as its parent; the model's answers; and the training, from the
state the genome carries to step 240. The drill's script on the standby
starts none of this. From here on it only looks, and asks.

It asks the primary's question again and again while training runs, two
seconds after each answer. Twenty-six answers come from step 160, each
naming generation 1's adapter, each the nine tokens the primary gave
21 seconds before it was lost. The model did not stop answering
because its machine did.

The two share the standby's eight cores. The answers' idle threads sleep
rather than spin, so the questions do not take the cores from the
training: its eighty steps took 51.0 s beside them, where the primary's
took 38.9 s alone, and the command as a whole — the model loaded, the
steps, the genome's fixtures recorded — 323 s against 261 s. An answer
while it ran took 10.9 s.

### 5. The chain goes on, under a key named in advance

At 02:01:31Z the training command is done — step 240 reached, the genome
written — and its result takes the model's place. The next answer comes
from step 240 and says so. At 02:01:40Z
the standby's sentinel seals it as **generation 2**: signed with the
standby's key, carrying a report of the standby's chip, and naming the
primary's generation 1 as its parent. It sealed nothing from the state as
it was restored; its outbox holds that one generation.

The authority did not exit after the failover. It reads the standby's
outbox, holds the record to the policy — the key, the measurement, the
parent, the bundle, the escrow — and at 02:01:44Z writes
`CHAIN_CONTINUED` to its audit log, the sixth event of ten. Then it goes
on watching the standby as it watched the primary. The two machines'
bundles are one chain of three generations.

### 6. An answer that can be checked

With the authority still watching, generation 2 is opened again: an
ordinary attested release of its escrowed key back to the standby, which
restores it beside the running model — gate EXACT — in 11.1 s. The second
restore's command finds the machine already going on and starts nothing.

The question is put to that sealed generation without the listener. The
tokens are the ones the listener gave. An answer names an adapter and a
step; the generation that holds them is sealed; whoever is released its
key can compute the answer again.

### 7. Is it the model it would have been?

On the standby's chip, as in Drill VIII: `replay` from the base, 240
steps — the same adapter to the bit, the 240 losses equal; and the recipe
run there in one go — the same seven files and 240 losses.

They are also Drill VIII's. The continued genome's seven digests, the
adapter `0041a292…44bd` among them, are those of the standby of a week
before — other machines, another region, a script there and the product
here, and this time with the model answering all the while.

When the operator's script tells the authority to stop, at 02:09Z, it is
still watching, and leaves with 0. Twenty-eight checks of twenty-eight.

### 8. A standby that cannot prove the model

*Run `20261118T012234Z`. Evidence:
[`…/evidence/negative/20261118T012234Z/`](../scripts/hardware-test/closed-turn/evidence/negative/20261118T012234Z/)*

Three machines of the same kinds in the same zones, and one byte more in
the standby's copy of the base model. The genome names its base by
content, so the gate's backend refuses to load it. The restore fails. No
receipt is signed, the command is not run, and the files the restore had
written are removed: 45 s later there is no model directory, no outbox,
no service, no listener, and nothing under the restore directory. Nothing
was started, and nothing was left to start from.

The authority is told so when it asks for the receipt. It does not wait:
4.6 s after it released the key it leaves with 1, a failover decided and
not completed, and its report says what happened in the standby's own
words — a failed restore, and why. No restore and no chain are on its
log.

The standby's daemon had also been given something to find when it
started: a tree with no receipt beside it, as a restore leaves one when
the daemon is stopped before it signs. It was gone before the daemon took
a key.

### 9. What the drill changed in the product

The kit's first runs on these machines found three things of ours, and
each was fixed before the runs above were made. Answers and training took
the cores from each other, an order of magnitude on both sides; the
answers now wait without spinning. A failed restore came back to the
authority named an invalid signature; the standby now says it in a form
the authority reads. And a restore that failed after its files were
written left them on the disk; a tree now stands only beside its signed
receipt.


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

- **0.5B in the drills.** Every number here is Qwen2.5-0.5B. A
  7B run through the same path exists
  ([gpu-7b](../scripts/hardware-test/gpu-7b/README.md)): EXACT on the pinned
  L4, its recipe replaying bit for bit, and the float door failing closed
  across devices in bfloat16 while the answers stay the same. The largest
  model through the genome path is 32B, restored and gated EXACT on the
  confidential H100 outside a failover
  ([C26](../VERIFIABLE-CLAIMS.md#c26)).
- **The GPU leg twice, at 0.5B.** The standby of Drills III and VII is an
  attested confidential GPU, each run once with the 0.5B model. In Drill III
  its GPU measurements were NVIDIA's evaluation, verified by NVIDIA's
  signature; the verifier now evaluates the report itself as well (ADR 0021,
  `both`), and in Drill VII it did — the driver's and the VBIOS's signed
  manifests verified, 64 measurements each matched; what stays NVIDIA's word
  is revocation.
  In Drill III the standby held no sealed escrow key; since ADR 0022 a
  host of either family seals the key to its vTPM under a policy of the
  pinned boot, and can be an authority.
- **SEV-SNP, TDX and the Azure confidential GPU only.** Nitro and SGX have
  adapter dispatch (ADR 0002) but no shipped offline verifier. A TDX host
  and an Azure confidential GPU host seal to their vTPM (ADR 0022) — a root
  the cloud provider virtualises, not the TEE's own. The GPU standby
  (Drills III and VII) has taken two key releases and the TDX Trust Domain
  (Drill IV) one, all at 0.5B.
- **Silence cannot tell dead from cut off.** Drill VII's only trigger is a
  lost heartbeat, and a primary that is alive but cut off from the replica
  looks the same. The policy moves the model at most once and only to the
  standby it names, so the risk is a second running copy, not a leak;
  fencing the primary is the operator's. Drill VII's primary was one machine
  switched off from inside, not a region lost.
- **One hop, and then a signature.** In Drill IX the standby goes on by
  itself, and that is where it stops: one policy serial performs one
  failover, so the standby that became the primary is watched and not
  moved from until an operator signs the next policy. Its loss in its turn
  is declined on the record — shown by the live test on the release
  binaries, not on hardware. What it starts are services of that boot; a
  standby that reboots does not start them again. The drill asked one
  question on loopback, and the two generations answer it with the same
  sentence: what tells the answers apart is the adapter each one names.
- **Exactly where the arithmetic is the same.** Every machine that took
  the recipe's steps in Drills VIII and IX is AMD's Milan on one set of
  pinned libraries; on another CPU family or a GPU the continued genome is
  the recipe within the difference of their kernels, which `replay` there
  reports. The gate's EXACT compares the model's outputs, not the kernels
  training uses: that the steps taken on the standby are the recipe's
  rests on `replay`.
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
bash scripts/hardware-test/authority-loss/run.sh <gcp-project> [zone]              # Drill VI  (~10 min; two GCP n2d SEV-SNP CVMs, one after the other)
bash scripts/hardware-test/failover-region-loss/run.sh <gcp-project> [primary-zone] [azure-rg]   # Drill VII (~25 min; a GCP n2d SEV-SNP primary, an authority in another region + an Azure NCC H100 v5)
bash scripts/hardware-test/training-continuity/run.sh <gcp-project> [zone]         # Drill VIII (~30 min; two GCP n2d-standard-8 SEV-SNP CVMs)
bash scripts/hardware-test/closed-turn/run.sh <gcp-project>                        # Drill IX (~31 min; three GCP SEV-SNP CVMs in two regions)
bash scripts/hardware-test/closed-turn/run.sh <gcp-project> negative               # Drill IX, the standby that cannot prove the model (~18 min)
bash scripts/hardware-test/gpu-exact/run.sh    <gcp-project>   # the CPU↔GPU probe (~20 min)
```

Neither cloud nor TEE hardware is needed to see the shape of it:

```bash
go run ./cmd/acp-demo
```

Evidence bundles contain measurements, digests, public identities and logs —
**no keys, seeds, tokens or configuration**. Key material never enters an
evidence bundle.
