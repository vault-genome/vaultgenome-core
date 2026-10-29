# Verifiable claims

Every public claim this project makes, the artifact that proves it, and the
command that reproduces it. If a claim is not in this table, we are not making
it. If an artifact does not support its claim, that is a bug — open an issue.

The rule we hold ourselves to: **a claim is a measurement with a file behind
it, or it is not a claim.** Numbers below are copied from committed evidence,
not from memory. Every path is a file in this repository.

Reading order for an evaluator in a hurry: [C1](#c1), [C6](#c6), [C8](#c8),
[C11](#c11), [C12](#c12), [C13](#c13), [C14](#c14), [C15](#c15), [C16](#c16), [C17](#c17), [C18](#c18), [C19](#c19), [C20](#c20), [C21](#c21), [C22](#c22), [C23](#c23), [C24](#c24), [C25](#c25), [C26](#c26), [C27](#c27), [C28](#c28), [C29](#c29), [C30](#c30), [C31](#c31), [C32](#c32), [C33](#c33), [C34](#c34), [C35](#c35), [C36](#c36), [C37](#c37), [C38](#c38), [C39](#c39), [C40](#c40), [C41](#c41), [C42](#c42), [C43](#c43), [C44](#c44), [C45](#c45), [C46](#c46), [C47](#c47), [C48](#c48), [C49](#c49), [C50](#c50), [C51](#c51), [C52](#c52), [C53](#c53), [C54](#c54), [C55](#c55), [C56](#c56), [C57](#c57), [C58](#c58), [C59](#c59), then [What we do not claim](#what-we-do-not-claim) —
that last section is the one we would want to read first if we were evaluating someone else.

---

## Vocabulary, so the table cannot be misread

| Term | Precise meaning here |
| - | - |
| **EXACT** | Bit-identical outputs. Used only for (a) restoring sealed bytes, and (b) model replay **on the pinned runtime that sealed the genome**. |
| **EQUIVALENT** | Not bit-identical; measured difference inside a declared tolerance, and behaviourally identical on the sealed fixtures (same top-1 token, same greedy continuation). |
| **FAIL** | The gate refuses. Nothing is brought up. |
| **Pinned runtime** | Same device class, same framework build, same pinned dependency set as the sealing environment. |

The distinction between the first two rows is the whole product. We enforce it
in code (`internal/validation/reconstruction/ladder.go`) and we enforce it in
our own marketing: see [C5](#c5), where the gate itself **refuses** EXACT on a
GPU and falls to EQUIVALENT.

---

## Continuity of a real model

<a id="c1"></a>
### C1 — A real fine-tuned model's genome is ~1/447 the size of its base weights

**Claim.** For Qwen2.5-0.5B-Instruct fine-tuned with LoRA inside an AMD SEV-SNP
confidential VM, the sealed genome is **2,208,446 bytes** against **988,097,824
bytes** of base weights — a ratio of **1 : 447**. The genome carries the base
model's content digest, the sealed LoRA delta (540,672 adapter parameters) and
the deterministic recipe.

**Evidence.**
[`scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/source/seal.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/source/seal.json)
— `bundle_bytes: 2208446`, `payload_bytes: 2207232`, `component_count: 5`,
`payload_sha256: sha256:fe5271f1…f9d5`.
[`…/source/finetune.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/source/finetune.json)
— `adapter_parameters: 540672`, `loss_first: 5.325` → `loss_last: 0.00090`,
`train_seconds: 75.766`. The same drill on the raised runtime (torch
2.14.1, transformers 5.19.0),
[`…/20261014T032714Z/source/seal.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/source/seal.json)
— `bundle_bytes: 2216638` (1 : 446),
[`…/source/finetune.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/source/finetune.json)
— `loss_last: 0.00090`, `train_seconds: 72.219`.
The base-weights figure is `model.safetensors` of `Qwen/Qwen2.5-0.5B-Instruct`
@ `7ae5576`, recorded in
[the drill README](scripts/hardware-test/gcp-drill/README.md); every base file
is pinned by SHA-256 in the genome's manifest (`sha256:7504966b…e927`).


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/gcp-drill/evidence/20261015T032836Z/`](scripts/hardware-test/gcp-drill/evidence/20261015T032836Z/) — `source/seal.json`: the genome of the fine-tune made inside the SEV-SNP guest sealed into a 2 216 638-byte bundle (2 215 424 bytes of payload) for the 0.5B base.
**Reproduce.** `bash scripts/hardware-test/gcp-drill/run.sh <gcp-project>`
(boots a SEV-SNP VM and a GPU VM, ~30 min, deletes both). See
[the drill README](scripts/hardware-test/gcp-drill/README.md).

**Caveat.** The ratio is a property of LoRA fine-tuning at this rank, not a
universal compression claim. A full-weight fine-tune has no such ratio. At
7B the same recipe gives 1 : 1 502 ([C16](#c16)); nothing larger has been
run — see [What we do not claim](#what-we-do-not-claim).

---

<a id="c2"></a>
### C2 — The genome replays to a bit-identical adapter on the pinned runtime

**Claim.** Re-running the sealed recipe on the pinned runtime reproduces the
adapter **bit for bit**: `max_abs_diff = 0.0`, `max_rel_diff = 0.0`, and every
training loss identical (`max_loss_diff = 0.0`).

**Evidence.**
[`…/source/replay-source-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/source/replay-source-cpu.json)
— `exact: true`, `losses_equal: true`; and on the raised runtime,
[`…/20261014T032714Z/source/replay-source-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/source/replay-source-cpu.json)
— `exact: true`, `max_abs_diff: 0`, `max_rel_l2: 0`, `losses_equal: true`.


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/gcp-drill/evidence/20261015T032836Z/`](scripts/hardware-test/gcp-drill/evidence/20261015T032836Z/) — `source/replay-source-cpu.json` `exact: true` on the CPU that sealed; `gpu/replay-gpu.json` `exact: false` on the L4, as the ladder predicts.
**Reproduce.** Same drill as C1; the replay step is `replay-source-cpu`.

---

<a id="c3"></a>
### C3 — Restoring a sealed bundle is byte-exact, and authenticated before use

**Claim.** Opening a genome restores the recorded tree byte for byte
(5 files, 2,202,926 bytes, `tree_sha256: 5fe536b0…9503`) and every 1 MiB
segment is authenticated before any of it is used. An edited, truncated or
wrong-key bundle leaves the target untouched.

**Evidence.**
[`…/gpu/open-gpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/gpu/open-gpu.json)
and
[`…/gpu/verify-gpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/gpu/verify-gpu.json)
— `authenticated: true`, `restored_verify: "ok: every file matches its recorded
digest"`; and on the raised runtime,
[`…/20261014T032714Z/gpu/open-gpu.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/gpu/open-gpu.json) and
[`verify-gpu.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/gpu/verify-gpu.json) — 5 files,
2,210,904 bytes, `tree_sha256: efdb6aa5…1ab6`, the same verdict.
Tamper behaviour is asserted in
`internal/genome/bundle/*_test.go`.


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/gcp-drill/evidence/20261015T032836Z/`](scripts/hardware-test/gcp-drill/evidence/20261015T032836Z/) — `gpu/open-gpu.json` and `gpu/verify-gpu.json`: 5 files restored on the GPU VM with the same tree sha256 (`ea9f5220…`) and the bundle verified at 2 216 638 bytes.
**Reproduce, with no cloud and no hardware:**

```bash
make build
./bin/acpctl genome seal --content-dir=./my-model --output=gen-0.genome --key-out=gen-0.key
./bin/acpctl genome rewind --bundle=gen-0.genome --key-file=gen-0.key --target=./restored
diff -r ./my-model ./restored && echo "byte-exact"
```

This is the one claim in the table an evaluator can check in 60 seconds on a
laptop. **Note the scope:** this is byte-exactness of *sealed bytes*, which is
cryptography, not of *model inference across devices* — see [C5](#c5).

---

<a id="c4"></a>
### C4 — On the pinned runtime the restored model is EXACT on all 16 fixtures

**Claim.** The equivalence gate returns **EXACT** at door 0 (`pinned-replay`):
16/16 fixtures bit-identical, `max_abs_err: 0`, `max_rel_err: 0`.

**Evidence.**
[`…/source/gate-source-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/source/gate-source-cpu.json)
— `level: "EXACT"`, `n_exact: 16`, `n_mismatch: 0`,
`fixtures_hash: 98d31611…486b`; and on the raised runtime,
[`…/20261014T032714Z/source/gate-source-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/source/gate-source-cpu.json)
— `level: "EXACT"`, `n_exact: 16`, `fixtures_hash: 717daed9…c608`.


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/gcp-drill/evidence/20261015T032836Z/`](scripts/hardware-test/gcp-drill/evidence/20261015T032836Z/) — `source/gate-source-cpu.json`: EXACT, `n_exact: 16` of 16, `max_abs_err: 0` on the sealing CPU.
---

<a id="c5"></a>
### C5 — Across hardware the model is EQUIVALENT, and the gate says so itself

**Claim.** Restored on different hardware, the model is **not** bit-identical,
and our gate reports that rather than hiding it. On each device the gate tries
door 0 first, **fails it**, and falls through to door 1 (`native-float`):

| Destination | Door 0 `pinned-replay` | Door 1 `native-float` | max abs Δ logit | Fixtures | Gate time |
| - | - | - | - | - | - |
| Source AMD CPU (SEV-SNP, pinned) | **EXACT** | — | 0 | 16/16 exact | 9.73 s |
| NVIDIA L4 (us-east4) | **FAIL** | **EQUIVALENT** | 1.907e-4 | 16/16 equivalent | 11.83 s |
| Intel CPU | **FAIL** | **EQUIVALENT** | 1.450e-4 | 16/16 equivalent | 16.78 s |

Tolerance was declared in advance (`atol 1e-2`, `rtol 1e-3`), and the measured
error is ~50× inside it. `n_critical_mismatch: 0` on every device. On the
raised runtime (run `20261014T032714Z`, the L4 in us-central1-c) the same
shape: door 0 **FAIL** and door 1 **EQUIVALENT** on both destinations,
1.612e-04 on the L4 (11.36 s) and 1.459e-04 on the Intel CPU
(16.41 s), `n_critical_mismatch: 0`
([`…/20261014T032714Z/gpu/gate-gpu.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/gpu/gate-gpu.json),
[`gate-intel-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/gpu/gate-intel-cpu.json)).

**Evidence.**
[`…/gpu/gate-gpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/gpu/gate-gpu.json)
and
[`…/gpu/gate-intel-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/gpu/gate-intel-cpu.json)
— read the `attempts` array: `[{rung 0, pinned-replay, "FAIL"}, {rung 1,
native-float, "EQUIVALENT"}]`.

**Why this is the most important row in the document.** A vendor who wanted to
overstate would report "EXACT" from C4 and stay quiet about the device. Our
gate is built so that it cannot: door 0 fails on foreign hardware, by
construction, and the failure is written into the signed verdict.


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/gcp-drill/evidence/20261015T032836Z/`](scripts/hardware-test/gcp-drill/evidence/20261015T032836Z/) — `gpu/gate-gpu.json`: on the L4 the gate refuses EXACT and says EQUIVALENT — `n_exact: 0`, `n_equivalent: 16`, `max_abs_err: 1.61e-4`, `max_rel_err: 1.57e-5`; `gpu/gate-intel-cpu.json`: EQUIVALENT on that VM's Intel CPU too, `max_abs_err: 1.46e-4`; the integer door's fidelity recorded in `source/genome.json`, `top1_same: 16`, `max_abs_err: 2.14`.
---

<a id="c6"></a>
### C6 — Byte-identical float across CPU and GPU is physically unavailable; we measured where it breaks

**Claim.** CPU↔GPU divergence for a real transformer enters at the **first
transformer block**, on **every** fixture, in **both** float32 and float64. It
is a property of the devices' matmul and transcendental kernels, not
accumulation over depth, and double precision shrinks it ~16× without closing
it. Token behaviour is nonetheless identical.

| CPU vs CUDA | max abs err | top-1 agree | top-64 order agree | first divergent layer |
| - | - | - | - | - |
| float32 | 1.5e-4 | 16/16 | 16/16 | layer 1 (all 16) |
| float64 | 9.5e-6 | 16/16 | 16/16 | layer 1 (all 16) |

An integer projection on the real `lm_head`, from identical quantised inputs,
is **byte-identical** on CPU and CUDA (`a03737b1f418` on both) — integer
arithmetic is associative, so a fixed-point path is device-portable by
construction.

**Evidence.**
[`scripts/hardware-test/gpu-exact/evidence/20260915T025643Z/probe.json`](scripts/hardware-test/gpu-exact/evidence/20260915T025643Z/probe.json),
narrated in [the probe README](scripts/hardware-test/gpu-exact/README.md);
and, on the raised runtime (torch 2.14.1+cu126, transformers 5.19.0),
[`scripts/hardware-test/gpu-exact/evidence/20261014T032040Z/probe.json`](scripts/hardware-test/gpu-exact/evidence/20261014T032040Z/probe.json)
— the same table to the rounding (1.48e-4 and 9.99e-6, layer 1 on all
16, top-1 and top-64 order 16/16, the integer projection `a03737b1f418`
again).


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/gpu-exact/evidence/20261015T012337Z/`](scripts/hardware-test/gpu-exact/evidence/20261015T012337Z/) — `probe.json`: CPU against the L4, float32 `max_abs_err` 1.48e-4 and float64 9.99e-6, top-1 the same on 16 of 16 both ways.
**Reproduce.** `bash scripts/hardware-test/gpu-exact/run.sh <gcp-project>`
(one L4, ~20 min, deletes the VM). The integer door this probe pointed at
now exists for the whole model: [C19](#c19).

**Why we publish a negative result.** It is the reason our ladder has the shape
it has, and it is the claim a serious reviewer will test first. Anyone
advertising "byte-exact AI across hardware" on native float is, on this
evidence, wrong.

---

## Attestation and governed key release

<a id="c7"></a>
### C7 — Real AMD SEV-SNP attestation, verified to AMD root, on two clouds

**Claim.** Attestation reports from live confidential VMs are parsed, their
ECDSA-P384 signatures verified, and the VCEK chained to **AMD ARK-Milan** — on
**GCP and Azure**. Key release happens only to a destination whose measurement
the operator's policy admits.

**Evidence.** `scripts/hardware-test/` (per-VM reports and cross-VM matrices);
ADR [0007](docs/adr/0007-measurement-variable-length.md) /
[0009](docs/adr/0009-x25519-kem-cross-cloud-key-delivery.md); operator procedure in
[`docs/operator/06_cross_cloud_restore.md`](docs/operator/06_cross_cloud_restore.md).
On Azure, where the chip's report carries the paravisor's binding of the
vTPM's runtime data and not a caller's REPORT_DATA, the kit binds the
workload manifest through the vTPM since 2026-10-15: a quote by the
attestation key the runtime data names, over SHA-256(manifest), verified
with that key (`scripts/hardware-test/azure-sev-snp/evidence/20261015T042715Z`,
the `14-*` files).
A concrete released-to measurement appears in the failover report below
(`destination_measurement_hex: 7dc7c12e…125acc`, `destination_kind:
gcp-sev-snp`).

Since 2026-10-15 (ADR 0024) the binary pins AMD's roots — ARK-Milan,
ARK-Genoa, ARK-Turin — and refuses a chain that ends anywhere else; before
that the root was whatever `amd_cert_chain_path` carried, which in every
recorded run was AMD's from KDS or THIM (`docs/security/review-2026-10.md`,
F12).

**Scope.** Released to SEV-SNP destinations, once to an Azure
confidential GPU destination — an SEV-SNP guest whose Evidence also carries
the vTPM's quote and NVIDIA's tokens ([C18](#c18)) — and once to an Intel
TDX destination, its quote verified to Intel's root with Intel's TCB word
([C21](#c21)); the AWS Nitro verifier is shipped and proven on the
hypervisor's own document offline ([C49](#c49)) but no Nitro enclave has
taken a release, and the SGX verifiers are **not** shipped — see
[What we do not claim](#what-we-do-not-claim).

---

<a id="c8"></a>
### C8 — A model under attack fails over to another machine, on real hardware, with the operator deciding

**Claim.** On two live SEV-SNP VMs: a sentinel on the primary seals each new
model state with its key escrowed to the authority; when a tripwire fires it
refuses to seal, signs a compromise report and exits 3. The authority, under a
failover policy the operator signed **in advance**, releases the key for the
last genome sealed **before** the intrusion to the one standby the policy
names. The standby restores it, gates it, and signs a receipt.

Measured end to end, run `20260915T021334Z`:

| Metric | Measured |
| - | - |
| Detect (tripwire → authority observes) | **2.53 s** |
| RPO (data at risk) | **9.00 s** |
| Key release | 0.27 s |
| Restore (5 files, 2,202,926 B) | **13.2 ms** |
| Gate on the standby | 13.54 s |
| **RTO (intrusion → gated, confirmed model)** | **16.81 s** |

Integrity of the outcome: restored **generation 1** — the clean state, *not*
the tampered one; gate level **EXACT** (16 fixtures, `max_abs_err: 0`) against
a required level of only `EQUIVALENT`; audit chain 5 events, verified;
`policy_version: failover-policy-v1;failover=1;revocation=1`.

**Evidence.**
[`scripts/hardware-test/gcp-failover/evidence/20260915T021334Z/standby/report.json`](scripts/hardware-test/gcp-failover/evidence/20260915T021334Z/standby/report.json)
(the full signed report),
[`…/standby/audit-verify.json`](scripts/hardware-test/gcp-failover/evidence/20260915T021334Z/standby/audit-verify.json),
[`…/primary/sentinel.json`](scripts/hardware-test/gcp-failover/evidence/20260915T021334Z/primary/sentinel.json).
The same drill on the raised runtime (torch 2.14.1, transformers 5.19.0),
[`…/20261014T034337Z/standby/report.json`](scripts/hardware-test/gcp-failover/evidence/20261014T034337Z/standby/report.json)
— generation 1, gate EXACT, RTO 18.69 s, RPO 9.00 s, 5 events verified
([`audit-verify.json`](scripts/hardware-test/gcp-failover/evidence/20261014T034337Z/standby/audit-verify.json)).
Design: [ADR 0012](docs/adr/0012-sentinel-and-policy-driven-failover.md).


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/gcp-failover/evidence/20261015T022749Z/`](scripts/hardware-test/gcp-failover/evidence/20261015T022749Z/) — the standby restored the genome 14.26 s after the trigger (`standby/failover.log`: release 0.24 s, gate 12.68 s), the gate EXACT where the policy required EQUIVALENT; the stolen sentinel seed declined (`exit=3`) and the sealed seed refusing to open off the chip (`exit=2`) on the record.
**Reproduce.** `bash scripts/hardware-test/gcp-failover/run.sh <gcp-project>`.

**The anti-worm invariants, stated so they can be checked against the code.**
One signed policy serial authorises **at most one** move
(`internal/vault/failover/gate.go`); every hop needs a fresh operator
signature; the operator stop list is a global halt that overrides any policy
([ADR 0010](docs/adr/0010-operator-stop-and-recorded-refusals.md)); a key is released only to an attested,
allow-listed measurement; every decision is written to the signed hash-chained
audit log **before** any key moves (`FAILOVER_DECIDED`, audit schema v6). This
system moves a model **because an operator signed for it to**, and cannot move
itself twice on one authorisation. That property is the difference between
continuity infrastructure and a worm, and we treat it as the primary safety
requirement of the project. Each invariant is exercised on live chips in
[C22](#c22): the spent policy, the operator stop, the foreign standby, the
expired policy and the corrupted bundle are each refused on the record.

---

<a id="c11"></a>
### C11 — The compute worker restores a real fine-tune in memory and the authority's gate says EXACT

**Claim.** A job on `sagvd`'s REST API names a sealed genome; `acp-compute`
restores the model through the `vg_genome` door from the components it was
sent — nothing of the genome touches its disk — and answers the genome's own
prompts; `sagvd` holds the answers to the sealed references and signs the
verdict. On the runtime that sealed the genome the verdict is **EXACT** on
every fixture ([ADR 0013](docs/adr/0013-worker-restores-the-genome.md)).

**Evidence.** Code and tests, not a hardware capture: the live-daemon suite
[`test/integration/daemons_test.go`](test/integration/daemons_test.go)
(`TestLiveDaemons_JobRoundTripOverMTLS`, `…GateRefusesAModelThatMissesItsReferences`,
`…EscrowedGenomeNeedsNoKeyFile`) runs the shipping `sagvd` and `acp-compute`
over mutual TLS with a door that speaks the protocol exactly
([`test/integration/fakedoor`](test/integration/fakedoor)); the
[`genome-worker`](.github/workflows/genome-worker.yml) workflow runs the real
door on a real fine-tune with the pinned torch
(`internal/compute/worker/genome_real_test.go`).

**Reproduce, with no cloud and no hardware:**

```bash
make test-integration
cd workers/genome && pip install -r requirements.txt && cd ../..
VG_GENOME_WORKER=$PWD/workers/genome go test -count=1 -v -run TestGenomeReconstructor_RealDoor ./internal/compute/worker/
```

**Scope.** The job carries an adapter of at most one Return Path frame, so a
full-weight fine-tune goes by key release ([C7](#c7), ADR 0011), not by job.
The same path on real SEV-SNP, with both daemons attesting with the chip and
every decision on the record, is [C12](#c12).

<a id="c12"></a>
### C12 — Both ends of the Return Path attest with real SEV-SNP, and every decision of the authority is on a verifiable record before it takes effect

**Claim.** `sagvd` and `acp-compute` run on an AMD SEV-SNP guest with
`tee.provider: "gcp-sev-snp"`, each pinning the other's 48-byte launch
measurement and verifying the other's Evidence to the AMD root during the
Return Path handshake. A worker whose Evidence is not the pinned identity is
refused at the handshake and gets no job. Every decision `sagvd` takes about
a job — accepted, worker admitted, candidate received, gate started, judged,
verdict signed — is written to its signed, hash-chained audit log **before**
the decision takes effect, and the log verifies offline under the key
`sagvd identity` publishes ([ADR 0014](docs/adr/0014-return-path-on-the-record-and-on-hardware.md)).

**Evidence.**
[`scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20260915T230907Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20260915T230907Z/)
— `n2d-standard-4`, us-central1-c, kernel `7.0.0-1011-gcp`, `tsm.txt`
showing SEV-SNP active at VMPL0.
`sagvd-identity.json` and `acp-compute-identity.json`: `tee_provider:
gcp-sev-snp`, `tee_measurement_hex: 7dc7c12e…25acc` on both (one guest).
`sagvd.log`: the simulated-TEE worker's handshake refused
(`client TEE evidence verification failed … evidence shorter than SEV-SNP
report`), then `session opened` with `peer_measurement` equal to the pin.
`job.json`: `status: succeeded`, gate `EXACT`, `pinned replay`, rung 0,
`n_exact: 6` of 6, `max_abs_err: 0`, signed by `sagvd-authority-e2e`;
accepted 23:11:59.017Z, verdict 23:12:03.321Z — **4.30 s**.
`audit-verify.json`: `ok: true`, `event_count: 7`, tip `f6e1dc8f…1874`.
`audit-events.jsonl`, in order: `TRUST_EVALUATED` deny (`handshake`) ·
`MANIFEST_ISSUED` · `TRUST_EVALUATED` allow (`peer_measurement_hex` = the
pin) · `CANDIDATE_RECEIVED` · `VALIDATION_STARTED` ·
`VALIDATION_DIMENSION_EVALUATED` (EXACT) · `VALIDATION_COMPLETED` (pass,
`verdict_sha256`). `sagvd-metrics.txt`:
`sagvd_handshake_failures_total{phase="handshake"} 1`,
`sagvd_gate_verdicts_total{level="EXACT"} 1`.

The ordering is enforced in code, not only observed:
[`cmd/sagvd/http_api_test.go`](cmd/sagvd/http_api_test.go)
(`TestHTTPAPI_PostJobs_IsOnTheRecordFirst`) shows a job is on the log under
its id before it is queued and that a closed log refuses the submission;
[`cmd/sagvd/audit_returnpath_test.go`](cmd/sagvd/audit_returnpath_test.go)
shows a closed log stops the decision and an edited log is refused;
[`test/integration/daemons_test.go`](test/integration/daemons_test.go) reads
the same event sequence back from the shipping binaries.

**Reproduce:**

```bash
scripts/hardware-test/gcp-sev-snp/returnpath-e2e/run.sh <gcp-project>
make test-integration
go test -count=1 -run 'TestReturnPathAudit|TestHTTPAPI_PostJobs_IsOnTheRecordFirst' ./cmd/sagvd/
```

**Scope.** Both daemons ran in one guest, so the measurement each pins is its
own; the run proves genuine hardware Evidence on both sides and the pin being
enforced, not two machines. The model is a tiny random Llama built on the
guest so the run fits in minutes; the scale claims stay with [C1](#c1)–[C5](#c5).
The log records the peer's provider and measurement, not the SEV-SNP report
itself; the report that verifies offline is the receipt in [C7](#c7)'s
key-release evidence. Simulated TEEs remain available off hardware and
announce themselves at start (KNOWN_ISSUES #1).

<a id="c13"></a>
### C13 — The vault daemon drives the nine-stage flow for a real job on real SEV-SNP, and every stage is a signed, recorded decision

**Claim.** A gate job on `sagvd` is a RecoveryRequest that the daemon takes
through the nine stages of the governed reconstruction flow with the
library's own decision-makers — intake, Trust Admission, the session issuer,
the staged disclosure sequencer, the manifest, the Return Path, the
three-dimension validation service, the release decision, the audit seal —
every transition the state machine's, every decision on the audit log
before it takes effect, every artifact signed under the authority key
([ADR 0015](docs/adr/0015-one-binary-drives-the-nine-stages.md)). On an
AMD SEV-SNP guest with both daemons attesting with the chip, that flow ran
end to end and released.

**Evidence.**
[`scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20260916T003940Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20260916T003940Z/)
— `n2d-standard-4`, us-central1-c, both identities `tee_provider:
gcp-sev-snp`, measurement `7dc7c12e…25acc`.
`audit-verify.json`: `ok: true`, `event_count: 17`.
`audit-events.jsonl`, in order: `TRUST_EVALUATED` deny (a simulated-TEE
worker refused at the handshake) · `REQUEST_RECEIVED` · `TRUST_EVALUATED`
allow (`trust.peer_attested`, `gcp-sev-snp`, the measurement) ·
`SESSION_ISSUED` (`gate-policy/v1;atol=0.01;rtol=0.001;outliers=0`) ·
`DISCLOSURE_AUTHORIZED` ×5 · `MANIFEST_ISSUED` (5 disclosures, budget 666) ·
`CANDIDATE_RECEIVED` · `VALIDATION_STARTED` · `VALIDATION_DIMENSION_EVALUATED`
×3 (operational pass; semantic `top1-agreement` 6/6; behavioral
`equivalence-ladder` EXACT) · `VALIDATION_COMPLETED` (pass) ·
`RELEASE_DECIDED` (`release: true`, `validation_pass`, citing the
attestation).
`job.json`: `state: release_authorized`, 10 transitions, the signed
attestation, session, manifest, validation result and decision — the
decision's `audit_event_id` is the `RELEASE_DECIDED` event's id — intake to
seal **4.48 s**. `sagvd-metrics.txt`:
`sagvd_release_decisions_total{decision="release"} 1`.

The same flow, in process and with the shipping binaries:
[`cmd/sagvd/daemon_flow_test.go`](cmd/sagvd/daemon_flow_test.go) (a release,
a trust denial without a session, a refused model closed as an incident,
an answer that is not an answer, a stale worker sent to attest again),
[`internal/vault/orchestration/flow_test.go`](internal/vault/orchestration/flow_test.go)
(every artifact verified, every stage order-checked, a chain that refuses
a record stops the stage),
[`test/integration/daemons_test.go`](test/integration/daemons_test.go)
(the audit record read back through `acpctl`; the operator's stop-all
denying a job at trust, on the record).

**Reproduce:**

```bash
scripts/hardware-test/gcp-sev-snp/returnpath-e2e/run.sh <gcp-project>
go test -count=1 -run 'TestDaemon_|TestFlow_' ./cmd/sagvd/ ./internal/vault/orchestration/
make test-integration
```

**Scope.** One guest, one worker, one job at a time; the receive-side
round trip (§7 of the recovery-flow document) is still library code no
binary drives. The semantic dimension is top-1 agreement at the reference
positions, not a task-level evaluation; the behavioral dimension is the
gate of [C4](#c4)/[C5](#c5). The model is the tiny one of [C12](#c12).

---

<a id="c14"></a>
### C14 — The escrow key is sealed to the release host's SEV-SNP chip, and a failover takes the primary's word only with its chip's report on it

**Claim.** The release authority's escrow private key — the one that opens
every escrowed genome — is made inside the authority's process and written
only sealed to its host's TEE: on AMD SEV-SNP, under a key the firmware
derives for that chip, launch measurement and guest policy
(`SNP_GET_DERIVED_KEY`), never stored; it is unsealed in memory at start
and survives its chip only through the operator's recovery envelope
([ADR 0016](docs/adr/0016-escrow-key-sealed-to-the-release-host.md)). And
the sentinel on the primary puts the primary chip's report on every record
it writes, so that under a policy pinning that chip a record without a
verifying report is ignored, a sentinel that said `stopped` stands the
authority down only for a grace, and nothing past the generation the
trigger's own record names is restored
([ADR 0017](docs/adr/0017-limits-on-the-primarys-word.md)). Both ran on
two SEV-SNP guests, with a rogue sentinel holding the stolen seed refused.

**Evidence.**
[`scripts/hardware-test/gcp-failover/evidence/20260916T021933Z/`](scripts/hardware-test/gcp-failover/evidence/20260916T021933Z/)
— primary `n2d-standard-8` (measurement `10f5ac22…4519`), standby
`n2d-standard-4` (measurement `7dc7c12e…5acc`), us-central1-c, both
`Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP` with
`/dev/sev-guest` (`tsm.txt`). On the raised runtime,
[`…/20261014T034337Z/`](scripts/hardware-test/gcp-failover/evidence/20261014T034337Z/) — the same machines and measurements, the
escrow key sealed (`escrow-provision.json`: `tee: gcp-sev-snp`, `source:
generated`), the primary's report on the trigger, generation 1 restored
and gated EXACT, the rogue sentinel declined (`rogue-report.json`).
`standby/escrow-provision.json`: the escrow key's tag `d2aac7b965c6ab76`,
`tee: gcp-sev-snp`, `source: generated`, wrapped to the operator's
recovery key (tag `93b4bd0871bfacf6`);
`escrow-sealed-shape.txt`: `vault-genome/sealed-escrow-key/v1`, the sealed
field 80 base64 characters, no key file;
`escrow-reprovision.json`: the recovery ceremony (`acpctl escrow recover`
piped into `sagvd escrow-provision -stdin`) re-sealed the same key,
`source: stdin`; `authority-identity.json`:
`key_escrow_storage: sealed:gcp-sev-snp`; `failover.log`: `failover escrow
key … storage: sealed:gcp-sev-snp` — the key that opened the genome's
envelope was the unsealed one.
`primary/sentinel.json`: `tee: gcp-sev-snp`, the compromise report with
`attestation.kind: gcp-sev-snp`; `standby/failover-verify.txt`: the policy
pins `primary TEE: gcp-sev-snp, measurements 10f5ac22…4519 (every record
must carry its report)` and `stopped and not back within 60s`.
`standby/report.json`: `status: restored`, trigger `compromise-report`
with `primary_measurement_hex` = the primary's chip, generation 1 restored
(`genome-134ad7e32883-g1-d9318608d0c0`), gate **EXACT** (16 fixtures,
max abs err 0; required EQUIVALENT), detect 7.69 s, RPO 9.00 s, **RTO
23.98 s**; `audit-verify.json`: `ok: true`, 5 events.
`standby/rogue-report.json` — the stolen seed on the standby's own chip,
every record a genuine SEV-SNP report from the wrong machine:
`ignored: [heartbeat.json: … gcp-sev-snp attestation does not verify: …
MEASUREMENT 7dc7c12e…5acc not in acceptable set]`, trigger
`heartbeat-timeout` at the primary's last genuine heartbeat,
`gen-000002.seal.json` set aside *after generation 1, the last the
sentinel's heartbeat-timeout names*, `status: declined` on the record
(audit chain length 6), no key moved.

In process and with the shipping binaries:
[`internal/shared/tee/gcp_sev_snp_seal_test.go`](internal/shared/tee/gcp_sev_snp_seal_test.go)
(the derived-key request, the expansion, a different chip, image or policy
opens nothing),
[`internal/genome/escrow/sealed_test.go`](internal/genome/escrow/sealed_test.go),
[`cmd/sagvd/escrow_key_test.go`](cmd/sagvd/escrow_key_test.go) (a
plaintext key refused on hardware; the ceremony through stdin),
[`internal/genome/sentinel/attest_test.go`](internal/genome/sentinel/attest_test.go)
(the report binds the record; re-signed, borrowed or tampered records do
not verify),
[`internal/vault/failover/limits_test.go`](internal/vault/failover/limits_test.go)
(the stolen seed as silence; only attested genomes; the chain trusted to
the sentinel's last word; `stopped` overdue),
[`test/integration/failover_test.go`](test/integration/failover_test.go)
(`TestLiveFailover_AttestedPrimary`, `TestLiveFailover_StoppedOverdue`).


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/gcp-failover/evidence/20261015T022749Z/`](scripts/hardware-test/gcp-failover/evidence/20261015T022749Z/) — failover complete in 14.26 s, gate EXACT; the negatives (stolen seed, sealed seed off the chip) refused as before.
**Reproduce:**

```bash
scripts/hardware-test/gcp-failover/run.sh <gcp-project>
go test -count=1 -run 'SEVSealer|Sealed|Recovery|Escrow|Attest|Pinned|StolenSeed|LastWord|Overdue' ./internal/shared/tee/ ./internal/genome/... ./internal/vault/failover/ ./cmd/sagvd/
make test-integration
```

**Scope.** The escrow key alone is sealed; the authority's signing seed,
audit seed and session-sealing key are still files (KNOWN_ISSUES #1, #11).
The sealed key is bound to the chip and the launch measurement — on a
Compute Engine host Google's UEFI — and, under `tee.sealer: both`, to the
boot the vTPM measured ([C53](#c53)): a restart on another host, and under
`both` a new image or kernel, needs the operator's ceremony; nothing
re-provisions itself. The chip's word bounds an attacker who holds
the seed without the chip; an intruder with root inside the primary's
guest holds both and is caught only by the wires (KNOWN_ISSUES #12). The
model is Qwen2.5-0.5B-Instruct with a LoRA adapter; both machines are CPU
confidential VMs.

---

<a id="c15"></a>
### C15 — Both ends of the Return Path attest with real Intel TDX, verified to Intel's root and Intel's TCB word

**Claim.** `sagvd` and `acp-compute` attest with the Trust Domain they run
in (`tee.provider: "gcp-tdx"`): a TDX quote through the kernel's
configfs-tsm with the handshake's challenge in REPORTDATA, and as the
measurement the SHA-384 of MRTD and RTMR0..3 — the firmware and the boot
chain in one 48-byte pin. The verifier on the other side chains the quote's
PCK certificates to the pinned Intel SGX Root CA, checks the attestation
key's and the PCK leaf's signatures and the QE report's binding of the key,
fetches Intel's TCB info and QE identity from Intel PCS and verifies their
signatures before reading them, requires the platform, the TDX module and
the QE to be at an accepted TCB status (`UpToDate` unless the operator says
otherwise; `OutOfDate` and `Revoked` never), refuses a debuggable TD, binds
the nonce and compares the measurement with the pin
([ADR 0018](docs/adr/0018-intel-tdx-on-the-return-path.md)). On a GCP
Trust Domain, a gate job went through the nine stages and released, and a
worker whose Evidence was not a TDX quote was refused on the record.

**Evidence.**
[`scripts/hardware-test/gcp-tdx/capture/evidence/20260916T031937Z/`](scripts/hardware-test/gcp-tdx/capture/evidence/20260916T031937Z/)
— a genuine `c3-standard-4` quote (8 000 bytes, version 4, TEE type TDX,
`TDATTRIBUTES` without DEBUG, MRTD `c1ee9c16…70a5`, RTMR3 zero) with the
caller's nonce in REPORTDATA, its PCK chain (3 certificates, FMSPC
`00806f050000`), Intel's TCB info (6 levels, the highest `UpToDate`), QE
identity, root CA and CRLs; the verifier's tests run against it offline
([`internal/shared/tee/gcp_tdx_test.go`](internal/shared/tee/gcp_tdx_test.go):
the genuine quote verifies; another root, a flipped DEBUG bit, a changed
byte, a wrong nonce, an unpinned measurement, an edited TCB level, an
expired document or a stale cache without network is refused).
[`scripts/hardware-test/gcp-tdx/returnpath-e2e/evidence/20260916T040416Z/`](scripts/hardware-test/gcp-tdx/returnpath-e2e/evidence/20260916T040416Z/)
— us-central1-a, `c3-standard-4`, `tsm.txt`: `tdx: Guest detected`,
`Memory Encryption Features active: Intel TDX`, `/dev/tdx_guest`.
`sagvd-identity.json` and `acp-compute-identity.json`: `tee_provider:
gcp-tdx`, measurement `ed70198a…177b` on both with the `tdx` block it is
made of (`steps.txt` recomputes it; the same MRTD and RTMRs as the capture
44 minutes earlier on another guest of the same image).
`audit-events.jsonl`, event 1: `TRUST_EVALUATED` deny, `gcp-tdx: parse
quote: quote is 147 bytes, shorter than a header and TD report (636)` — the
simulated TEE's Evidence, refused within 1 s; event 3: `TRUST_EVALUATED`
allow, `trust.peer_attested`, `gcp-tdx`, the pinned measurement.
`job.json`: `POST /v1/jobs` 202 → `release_authorized` in **3.37 s**, gate
**EXACT** (`pinned replay`, 6/6 fixtures, max abs err 0), top-1 6/6, the
signed decision `dec-d6fd9410c50e2fcf` citing attestation
`att-fdc9b5ad-…-0001`; `audit-verify.json`: `ok: true`, **17 events**;
`sagvd-metrics.txt`: `vg_tee_attestation_total{provider="gcp-tdx"}` —
3 produce, 2 verify success, 1 verify error; `pcs-tdx-tcb-00806f050000.json`
and `pcs-tdx-qe-identity.json` with their issuer chains: Intel's documents
as both verifiers fetched them, for offline re-verification.

**Reproduce:**

```bash
scripts/hardware-test/gcp-tdx/capture/run.sh <gcp-project>
scripts/hardware-test/gcp-tdx/returnpath-e2e/run.sh <gcp-project>
go test -count=1 -run 'TDX' ./internal/shared/tee/ ./cmd/sagvd/ ./cmd/acp-compute/ ./cmd/acp-bootstrap/
```

**Scope.** Both daemons ran inside one Trust Domain; the pin is the
image's, so a second guest of the same image has the same measurement. The
CPU side only: the machine had no GPU, and the GPU's own attestation
(NVIDIA confidential computing) is not wired. A key release to a TDX
destination (`acp-bootstrap` on TDX) has since run on hardware, once, as
the standby of a failover ([C21](#c21)), and an authority on TDX has
held its escrow key sealed to the guest's vTPM ([C23](#c23), ADR 0022).
Intel PCS was reachable from the guest; without
it and without a cache the verifier refuses. The model is a tiny one built
on the guest to prove the path, not the scale.

---

<a id="c16"></a>
### C16 — A 7B model goes through the genome path on one GPU: a 10 MB genome, restored and gated EXACT on the pinned runtime; across devices in bfloat16 the float door fails closed while the model's answers do not change

**Claim.** Qwen2.5-7B-Instruct fine-tuned by `vg_genome` on an NVIDIA L4 in
bfloat16 — the recipe records the device and the dtype, and the door
restores the base in the recipe's dtype — is sealed as a 10 142 001-byte
genome against 15 231 271 888 bytes of base weights (1 : 1 502), restored
from the bundle, gated **EXACT** through the door on the same GPU, and its
recipe replays there to a bit-identical adapter. On the host's CPU the same
genome gives the same top-1 token and the same 16-token greedy
continuation on every fixture, and its bfloat16 logits differ by up to 0.5
— one or two bfloat16 quanta at their magnitude — so the float door fails
closed.

**Evidence.**
[`scripts/hardware-test/gpu-7b/evidence/20260916T043622Z/`](scripts/hardware-test/gpu-7b/evidence/20260916T043622Z/)
— `g2-standard-8` in us-central1-b, NVIDIA L4 (driver 580.173.02), torch
2.7.1+cu126 (`nvidia-smi.txt`, `torch.txt`, `pip-freeze.txt`).
`finetune.json`: `device: cuda`, `dtype: bfloat16`, `adapter_parameters:
2523136`, `loss_first: 6.002` → `loss_last: 0.000713`, `train_seconds:
32.378`; `genome.json` carries the recipe and the base manifest
(`sha256:f571d6a7…6107`). `seal.json`: `bundle_bytes: 10142001`,
`payload_bytes: 10140672`, `component_count: 5`; `verify.json`:
`restored_verify: ok`. `gate-gpu.json`: `level: EXACT`, rung 0 `pinned
replay`, 16/16, `max_abs_err: 0`; `measure-gpu.json`: `exact: 16`,
`top1_same: 16`, `greedy_same: 16`; `replay-gpu.json`: `exact: true`,
`losses_equal: true`. `gate-cpu.json`: `level: FAIL`, both rungs at
`max_abs_err: 0.5`; `measure-cpu.json`: `exact: 0`, `top1_same: 16`,
`greedy_same: 16`, `max_abs_err: 0.5`, `max_rel_err: 0.027`, every fixture
between 0.125 and 0.5. Base-weights bytes: the four `model-*.safetensors`
of `Qwen/Qwen2.5-7B-Instruct` @ `a09a354`. The same kit on the raised
runtime, torch 2.14.1+cu126 and transformers 5.19.0:
[`scripts/hardware-test/gpu-7b/evidence/20261014T022551Z/`](scripts/hardware-test/gpu-7b/evidence/20261014T022551Z/)
— `replay-gpu.json`: `exact: true`, `max_abs_diff: 0`, `losses_equal:
true`; `gate-gpu.json`: `level: EXACT`, rung 0, 16/16; `gate-cpu.json`:
`level: EXACT` at rung 2 through the integer door, after both float
doors failed at `max_abs_err: 0.375`; `measure-cpu.json`: `exact: 0`,
`top1_same: 16`, `greedy_same: 16`, `max_abs_err: 0.375`. torch 2.14.1
warns there that flash attention's backward may not be deterministic
under `warn_only`; the replay measured that it was, at these shapes.
In process:
[`workers/genome/tests/test_genome.py`](workers/genome/tests/test_genome.py)
(a bfloat16 genome records its runtime and the door honours it; an unknown
dtype is refused; a genome that predates the field restores in float32).


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/gpu-7b/evidence/20261015T015428Z/`](scripts/hardware-test/gpu-7b/evidence/20261015T015428Z/) — Qwen2.5-7B-Instruct: `measure-gpu.json` `exact: 16` of 16, `measure-cpu.json` `exact: 0`, `top1_same: 16`, `max_abs_err: 0.375`; `gate-gpu.json` and `gate-cpu.json` both EXACT (the integer door opens where the float door cannot); the integer fidelity recorded in `genome.json`, `max_abs_err: 0.79`, `top1_same: 16`.
**Reproduce:**

```bash
scripts/hardware-test/gpu-7b/run.sh <gcp-project>     # one g2-standard-8, ~35 min
cd workers/genome && python -m pytest -q tests/
```

**Scope.** One GPU, one host CPU, one model; LoRA r=8 on two projections;
16 fixtures. The L4 is not a confidential GPU: nothing in this run is
attested, and the sealed genome was opened on the machine that made it
([C17](#c17) is the attested one). The
cross-device result is a measurement of bfloat16 kernels on two devices,
not a property of the model: the float door's default tolerance is the
float32 one; a bfloat16 tolerance is the operator's to set
(`genome.gate.bfloat16`, pinned into every session's policy); the
byte-portable route for such a genome is the integer door, shipped since
[C19](#c19) — on the raised runtime the gate on the host CPU opens
through it, rung 2 EXACT. Frontier scale has not been run.

---

<a id="c17"></a>
### C17 — A confidential GPU worker: on an Azure NCC H100 v5 the Return Path carries the chip's report, the vTPM's quote and NVIDIA's tokens for the H100, and the 7B genome is restored on the GPU in confidential-computing mode

**Claim.** `sagvd` and `acp-compute` attest as an Azure confidential GPU
VM (`tee.provider: "azure-cgpu"`): one Evidence for a handshake nonce
carrying the SEV-SNP report Azure keeps in the vTPM (whose `REPORT_DATA`
is the hash of the runtime data naming the vTPM's attestation key), a TPM
quote by that key with `SHA-256(nonce)` in `extraData`, and NVIDIA's
signed attestation tokens for the H100 under the same value. The verifier
takes the report to AMD's Genoa root, the quote under the key the chip
named, and the tokens under NVIDIA's key set with a claims policy —
overall result, nonce, measurements matched, secure boot, no debug, the
manifests signed, the model, driver and VBIOS pinned when the operator
says so ([ADR 0019](docs/adr/0019-a-confidential-gpu-worker-on-azure.md)).
On such a VM a gate job went through the nine stages with the 7B genome
restored through the door on the H100 in confidential-computing mode, and
a worker whose evidence was not that envelope was refused on the record.

**Evidence.**
[`scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z/`](scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z/)
— `conf-compute.txt`: `CPU CC Capabilities: AMD SEV-SNP (vTOM Mode)`,
`GPU CC Capabilities: CC Capable`, `CC GPUs Ready State: Ready`;
`hcl-summary.json`: SNP report version 5, no DEBUG, VMPL 0, measurement
`aa7c9da5…0eef`, `REPORT_DATA` = SHA-256 of the runtime data naming
`HCLAkPub`; `cert-chain.pem`: the Genoa ASK+ARK Azure served;
`quote1.msg`/`quote1.sig`: a TPMS_ATTEST over PCRs 0–14 with the capture's
nonce, `Verified OK` under `ak-pub.pem` (handle `0x81000003`);
`nras-claims-decoded.json`: ES384 by `nv-eat-kid-prod-20260916090709987-…`,
`x-nvidia-overall-att-result: true`, `eat_nonce` = the nonce, GPU-0
`hwmodel GH100`, driver `595.71.05`, VBIOS `96.00.9F.00.04`, `measres
success`, `secboot true`, `dbgstat disabled`; `local-verifier.txt`:
NVIDIA's local verifier's own pass; `gate-gpu.json`, `measure-gpu.json`,
`replay-gpu.json`: the 7B genome (26.2 s of training on the H100, 10 142
001 bytes) gated **EXACT** on the GPU and replayed bit for bit.
[`…/evidence/20260916T133506Z-returnpath/`](scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z-returnpath/)
— `sagvd-identity.json`, `acp-compute-identity.json`: `tee_provider:
azure-cgpu`, measurement `aa7c9da5…0eef`; `audit-events.jsonl` event 1:
`TRUST_EVALUATED` deny (`evidence is not a vault-genome/azure-cgpu-evidence/v1
envelope`), event 3: allow, `trust.peer_attested`; `job.json`: `POST
/v1/jobs` → `release_authorized` in **18.5 s**, gate **EXACT** (16/16, max
abs err 0), top-1 16/16; `audit-verify.json`: `ok: true`, **17 events**;
`sagvd-metrics.txt`: `vg_tee_attestation_total{provider="azure-cgpu"}`
produce 2, verify success 1, verify error 1. The same kit on the raised
runtime (torch 2.14.1+cu126, transformers 5.19.0) and the day's driver,
[`…/20261014T113334Z/`](scripts/hardware-test/azure-cgpu/evidence/20261014T113334Z/) and
[`…/20261014T113334Z-returnpath/`](scripts/hardware-test/azure-cgpu/evidence/20261014T113334Z-returnpath/) — `conf-compute.txt`: `CC
State: ON`, `CC GPUs Ready State: Ready`; `gpu.csv`: driver `595.91.07`,
VBIOS `96.00.9F.00.04`; `steps.txt`: the local verifier, NRAS and MAA each
exit 0; the Return Path's `job.json`: the 32B genome (that run's base)
restored on the H100 and gated **EXACT** (16/16, max abs err 0) in
238 s; `escrow-provision.json`: `tee: azure-cgpu`, key `b04c3a9925c25b14`;
`seal-keys-sagvd.json`, `seal-keys-worker.json`; `audit-verify.json`: `ok:
true`, 17 events, tip `e2be1cfe…5f9e`; `sagvd-metrics.txt`: verify success 1, error 1.
In process:
[`internal/shared/tee/azure_cgpu_evidence_test.go`](internal/shared/tee/azure_cgpu_evidence_test.go)
(the captured evidence verifies offline with the nonce that produced it,
and is refused for the other nonce, an unlisted driver, past the tokens'
expiry, under the Milan chain),
[`azure_cgpu_test.go`](internal/shared/tee/azure_cgpu_test.go),
[`azure_cgpu_hcl_test.go`](internal/shared/tee/azure_cgpu_hcl_test.go),
[`azure_cgpu_tpm_test.go`](internal/shared/tee/azure_cgpu_tpm_test.go),
[`nvidia_eat_test.go`](internal/shared/tee/nvidia_eat_test.go).


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/azure-cgpu/evidence/20261015T012337Z/`](scripts/hardware-test/azure-cgpu/evidence/20261015T012337Z/) and the `-returnpath` directory beside it — the capture (`CAPTURE DONE`, `gate-gpu.json` EXACT) and the Return Path on the H100: the gate job EXACT, 16 of 16, `release_authorized`; the audit log verified, 17 events.
**Reproduce:**

```bash
scripts/hardware-test/azure-cgpu/run.sh vg-cgpu-weu westeurope
go test -count=1 -run 'AzureCGPU|HCL|TPMQuote|NRAS' ./internal/shared/tee/ ./cmd/sagvd/ ./cmd/acp-compute/ ./cmd/acp-bootstrap/
```

**Scope.** Both daemons ran in one guest; the pin is Azure's launch
measurement, which covers the paravisor and firmware, not the OS — the
vTPM's PCRs were recorded in the quote and not policed in this run (a
`pcr_digests` pin exists since, and [C18](#c18) uses it). The GPU's
measurements are evaluated by NVIDIA's service against NVIDIA's reference
manifests; this run's verifier verified NVIDIA's signed tokens and did
not evaluate the GPU's SPDM report itself (it is in the evidence; since
ADR 0021 the verifier does, offline on this very capture — [C20](#c20)).
NRAS is on
the path when evidence is produced. A key release to such a machine
(`acp-bootstrap` on `azure-cgpu`) has since been run as the standby of a
failover ([C18](#c18)); the escrow key on this host seals to its vTPM
since ADR 0022 (proven on `20260916T204311Z-returnpath`: `escrow-provision.json` `tee: azure-cgpu`, the key re-sealed through the recovery ceremony). The model is 7B in bfloat16; the machine cost about $9 an hour and
lived for 35 minutes.

---

<a id="c18"></a>
### C18 — A model under attack on a CPU TEE fails over to an attested confidential GPU in another cloud: the key released on the chip's report, the vTPM's quote and NVIDIA's tokens, the clean generation gated EQUIVALENT on the H100

**Claim.** The failover of [C8](#c8) and [C14](#c14) with the standby an
Azure NCC H100 v5 (`acp-bootstrap` on `tee.provider: "azure-cgpu"`)
reached over the Internet. Under a policy the operator signed in advance —
pinning the primary's chip, the standby's launch measurement and, in the
registry, its vTPM's boot — the authority (GCP SEV-SNP, its escrow key
sealed to its chip) took the primary's attested compromise report,
verified the standby's SEV-SNP report to AMD's Genoa root, its TPM quote
under the vTPM's attestation key against the pinned PCR digest, and
NVIDIA's tokens for the H100 under NVIDIA's key set and the claims policy,
released the key for the last generation sealed before the attack, and
confirmed the standby's receipt: the genome restored and gated through the
door on the H100 in confidential-computing mode. Every step is on the
audit record.

**Evidence.**
[`scripts/hardware-test/failover-cgpu/evidence/20260916T150456Z/`](scripts/hardware-test/failover-cgpu/evidence/20260916T150456Z/)
— `authority/report.json`: `status: restored`; trigger `compromise-report`
at 15:12:35.07Z with `primary_measurement_hex: 69da361d…c790`; `decision:
failover … restore generation 1 on the standby`; `release.destination_kind:
azure-cgpu`, `destination_measurement_hex: aa7c9da5…0eef`,
`policy_version: failover-policy-v1;failover=1;revocation=1`;
`restore.gate`: **EQUIVALENT**, door native float, 16 fixtures,
`max_abs_err: 1.516e-4`, `max_rel_err: 1.65e-5`, `backend_seconds: 12.11`;
`timing`: detect 5.59 s, release 1.30 s, restore 11.4 ms, gate 12.11 s,
failover 19.40 s, **RTO 24.99 s**, **RPO 12.00 s**; `audit_chain_length:
5`. `authority/verifiers.json`: the `azure-cgpu` entry with the Genoa
chain, `gpu_policy.hw_models: ["GH100"]` and `pcr_digests:
["92fe2c20…26e2"]`, and the `gcp-sev-snp` entry — the primary's anchors.
`authority/failover-verify.txt`: the signed policy, serial 1, standby
`azure-cgpu https://…:8443`. `authority/audit-verify.json`: `ok: true`, 5
events (`FAILOVER_DECIDED` → `CROSS_CLOUD_HANDSHAKE_INITIATED` →
`CROSS_CLOUD_ATTESTATION_VERIFIED` → `KEY_RELEASE_AUTHORIZED` →
`CROSS_CLOUD_RESTORE_COMPLETED`), tip `d46be63a…943a`.
`authority/escrow-provision.json`: `tee: gcp-sev-snp`, sealed.
`destination/destination-identity.json`: `tee_provider: azure-cgpu`,
measurement `aa7c9da5…0eef`, `vtpm.pcr_digest_hex: 92fe2c20…26e2`.
`destination/genome-…-g1-….receipt.json`: the receipt (`destination_kind:
azure-cgpu`, generation 1, `gate.level: EQUIVALENT`) with its
`vault-genome/azure-cgpu-evidence/v1` Evidence — HCL report, quote,
NVIDIA's tokens. `destination/conf-compute.txt`: `CC State: ON`, `CC GPUs
Ready State: Ready`; `destination/gpu.csv`: H100 NVL, driver 595.71.05,
VBIOS 96.00.9F.00.04. `destination/acp-bootstrap.log`: handshake
answered, key released, restore, gate, key erased. `primary/sentinel.json`:
`outcome: compromised`, `attestation.kind: gcp-sev-snp`, last generation 1.
The same drill on the raised runtime (torch 2.14.1, transformers 5.19.0)
and the day's driver, [`…/20261014T121030Z/`](scripts/hardware-test/failover-cgpu/evidence/20261014T121030Z/) — the standby on
kernel `7.0.0-1016-azure-fde` with driver `595.91.07` (`destination/gpu.csv`,
`conf-compute.txt`: `CC State: ON`), the vTPM digest of that boot pinned
(`c1e0b0f8…ad85`); `authority/report.json`: `status: restored`, generation 1,
`restore.gate`: EQUIVALENT, `max_abs_err: 2.48e-04`, `timing`: RTO
19.86 s, RPO 9.00 s; `authority/audit-verify.json`: `ok: true`, 5 events, tip
`f86923a4…4be9`; the `CROSS_CLOUD_ATTESTATION_VERIFIED` event's `destination_detail`
naming GPU-0 `GH100` driver `595.91.07` with the authority's own evaluation
of the report, every check true; the destination's two key files sealed to
its vTPM (`destination/dest-seal-keys.json`).


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/failover-cgpu/evidence/20261015T014547Z/`](scripts/hardware-test/failover-cgpu/evidence/20261015T014547Z/) — the CPU TEE on GCP failed over to the attested H100 on Azure in 15.06 s (release 2.10 s, gate 6.85 s), gate EQUIVALENT as required; `destination-handoff.json` carries the H100 VM's measurement and PCR digest.
**Reproduce:**

```bash
scripts/hardware-test/failover-cgpu/run.sh <gcp-project> europe-west4-a vg-cgpu-weu   # ~25 min: two GCP n2d Milan CVMs + an Azure NCC H100 v5
```

**Scope.** One run, with the 0.5B model of the failover drill, trained on
the primary's CPUs in float32 and proven on the GPU: EQUIVALENT (max abs
err 1.5e-4 against atol 1e-2), not EXACT — the same-device EXACT of
[C14](#c14) is not available across devices ([C6](#c6)). The GPU's
measurements are NVIDIA's evaluation, verified by NVIDIA's signature
([C17](#c17) scope). In that run the standby held no sealed escrow key;
since ADR 0022 it seals one to its vTPM and can be an authority.
The vTPM pin is a property of a boot. The other CPU TEE family as the
standby is [C21](#c21).

---

<a id="c19"></a>
### C19 — The integer door: a real model restored on an Intel Xeon and on an NVIDIA L4 gives the same bytes, at 0.5B and at 7B, and the gate holds it to those bytes at tolerance zero

**Claim.** The gate's third door ([ADR 0020](docs/adr/0020-the-integer-door-for-the-lora-worker.md))
computes the restored LoRA model's forward pass in integer arithmetic —
int8 weights with the delta merged, 14-bit activations, int8 GEMMs, an
integer RMSNorm, rotary tables derived without a float, an integer
exponential — and is held to references the same arithmetic sealed with
the genome. On real hardware the same genome gives byte-identical logits
on a CPU and on a GPU, whichever device made the references: a 0.5B
genome made on eight Xeon cores reproduces its references on the L4, and
a 7B genome made on the L4 reproduces its references on the Xeon. At zero
tolerance on the GPU the float doors fail and the integer door opens
EXACT. The door is a different model from the float one, and its
fidelity is measured, not assumed: the same top-1 token on every fixture,
a logit error the genome records.

**Evidence.**
[`scripts/hardware-test/integer-door/evidence/20260916T164511Z/`](scripts/hardware-test/integer-door/evidence/20260916T164511Z/)
— `a-measure-integer-cpu.json` and `a-measure-integer-cuda.json` (the 0.5B
genome, references recorded on the CPU): `exact: 16` of 16 on both
devices, the same `results[].sha256` for all 16 fixtures, `top1_same: 16`,
`max_abs_err: 2.72`, `max_rel_err: 0.25` against the float references;
`a-measure-float-cuda.json`: the float door on the L4, `max_abs_err:
1.52e-4`, `exact: 0`; `a-gate-cuda-tol0.json`: `--atol 0 --rtol 0` on the
L4 — attempts `pinned-replay FAIL 1.52e-4`, `native-float FAIL 1.52e-4`,
`fixed-point EXACT 0`, level **EXACT** at rung 2; `a-gate-cuda.json`:
the default tolerance opens rung 1 EQUIVALENT; `a-gate-cpu.json`: rung 0
EXACT on the machine that sealed. `b-measure-integer-cuda.json` (the 7B
genome, bfloat16, references recorded on the L4): `exact: 16` of 16,
`top1_same: 16`, `max_abs_err: 1.32`, `max_rel_err: 0.14`;
`b-measure-integer-cpu.json`: the first three fixtures on the Xeon,
`exact: 3` of 3, the same `sha256` as on the L4. `divides-exactly.txt`:
both devices divide int64 exactly. `a-genome.json`, `b-genome.json`:
`fixtures.integer` (scheme `vg-integer-door/v1`, fidelity). The same kit
on the raised runtime, torch 2.14.1+cu126 and transformers 5.19.0:
[`scripts/hardware-test/integer-door/evidence/20261014T020420Z/`](scripts/hardware-test/integer-door/evidence/20261014T020420Z/)
— `exact: 16` of 16 on both devices at 0.5B with the same `sha256` for
every fixture, `max_abs_err: 2.70`, `top1_same: 16`; `exact: 16` of 16
on the L4 and `3` of 3 on the Xeon at 7B, `max_abs_err: 0.79`; the gate
at zero tolerance EXACT at rung 2 after `FAIL 1.18e-4` on both float
doors. In process:
[`workers/genome/tests/test_integer.py`](workers/genome/tests/test_integer.py)
(the constants against libm, the primitives against Python integers, the
same bytes at another thread count and on every device the test can
reach, a tampered adapter changing them, the door and the gate protocol),
[`internal/genome/lora/integer_test.go`](internal/genome/lora/integer_test.go),
[`internal/validation/reconstruction/integer_door_test.go`](internal/validation/reconstruction/integer_door_test.go),
[`internal/bootstrap/restorer/gate_integer_test.go`](internal/bootstrap/restorer/gate_integer_test.go),
[`cmd/acpctl/genome_gate_integer_test.go`](cmd/acpctl/genome_gate_integer_test.go),
[`cmd/sagvd/genome_integer_test.go`](cmd/sagvd/genome_integer_test.go).


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/integer-door/evidence/20261015T013610Z/`](scripts/hardware-test/integer-door/evidence/20261015T013610Z/) — the 0.5B genome `exact: 16` of 16 on both devices with `max_abs_err: 2.70` against the float references; the float door on the L4 `exact: 0`, `max_abs_err: 1.18e-4`; the gate at zero tolerance EXACT (`a-gate-cuda-tol0.json`), at the default tolerance EQUIVALENT, on the sealing CPU EXACT; the 7B genome `exact: 16` of 16 on the L4 and `3` of 3 on the Xeon, `max_abs_err: 0.79`.
**Reproduce:**

```bash
scripts/hardware-test/integer-door/run.sh <gcp-project>       # one L4 VM, ~20 min, deletes it
cd workers/genome && python -m pytest -q tests/test_integer.py
```

**Scope.** Two devices (an Intel Xeon and an NVIDIA L4; an Apple GPU in
the worker's tests), two models, two runs on two runtimes (torch 2.7.1
and 2.14.1). Byte identity is of the integer model with itself across
devices, not of the integer model with the float model: the float doors
stay the fidelity path and the integer door the availability path. The
fidelity measured here — top-1 the same on every fixture, logits within
a few units on fine-tunes that drove them to magnitudes of tens — is a
property of these genomes; a genome records its own. The 7B check on the
CPU covered three fixtures. The integer door is not a serving path: a 7B
forward takes seconds per fixture. A third run
([`20261014T012445Z`](scripts/hardware-test/integer-door/evidence/20261014T012445Z/))
held byte identity while the door computed the wrong model: transformers
5 had moved a config's rotary base into `rope_parameters`, the door's
reader fell back to 10 000 where Qwen2.5 has 1 000 000, and every
exactness check passed — the same wrong tables on both devices. Only the
fidelity record showed it (top-1 13 of 16, max abs err 7.29). Byte
identity is a property of the program and says nothing about the program
being the right one; the door now reads the base from the config with no
default, refuses a model whose own rotary module disagrees with it, and
refuses projections whose shapes disagree with the config's head counts
(the kit's README has the account).

---

<a id="c20"></a>
### C20 — The verifier evaluates the H100's attestation report itself: signature, chain to NVIDIA's root, firmware id, and every measurement against NVIDIA's signed reference manifests — on the captured report, complete, refusing what should be refused, and admitted to carry the verdict alone

**Claim.** Beside NVIDIA's signed verdict, the `azure-cgpu` verifier
evaluates the GPU's SPDM attestation report on its own
([ADR 0021](docs/adr/0021-the-verifiers-own-evaluation-of-the-gpu.md)):
the report parses (SPDM 1.1 GET_MEASUREMENTS and MEASUREMENTS, 64 DMTF
blocks), its nonce is the verifier's challenge, its ECDSA P-384 signature
verifies under the GPU's attestation certificate, that certificate's
chain verifies to the NVIDIA Device Identity CA pinned in the binary, the
firmware id in the certificate's DICE extension is the report's, the
driver and VBIOS reference manifests the report names are fetched from
NVIDIA's RIM service — versions matching, chains verifying to the pinned
NVIDIA CoRIM signing root, bytes hashing to the service's SHA-256, their
enveloped XML signatures (Canonical XML 1.1, ECDSA-SHA384) verifying under
those certificates — and every runtime measurement equals one of the
manifests' golden values at every bound index. On the captured H100
report the evaluation is complete
and every one of the 64 measurements matches; a changed measurement, a
report for another nonce, a cut chain, a wrong root or a missing manifest
each fail the check that should catch it. Under
`gpu_policy.evaluation: "both"` a handshake is accepted only when NVIDIA's
tokens *and* this evaluation pass, and the evidence must carry the report.

**Evidence.**
[`scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z/`](scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z/)
— `gpu0-attestation-report.bin` (the report the driver handed out for
`nonces.txt`'s nonce 1: request `11 e0 01 ff` + nonce, response `11 60`,
64 blocks of 48 bytes, opaque data naming driver `595.71.05`, VBIOS
`96.00.9F.00.04`, project `1010`, SKU `0210`, chip `886`, a 48-byte
firmware id; a 96-byte signature), `gpu0-cert-chain.pem` (GH100 A01 GSP
FMC LF → GSP BROM → Provisioner ICA 1 → GH100 Identity → NVIDIA Device
Identity CA), `gpu-evidence.json` (what NRAS was sent).
[`internal/shared/tee/testdata/nvidia/`](internal/shared/tee/testdata/nvidia/)
— the two NVIDIA roots as NVIDIA's open-source verifier ships them, and
the RIM service's responses for `NV_GPU_DRIVER_GH100_595.71.05` and
`NV_GPU_VBIOS_1010_0210_886_96009F0004` (64 golden measurements each,
fetched 2026-09-16, with the service's SHA-256), provenance in its README.
In process:
[`internal/shared/tee/nvidia_gpu_report_test.go`](internal/shared/tee/nvidia_gpu_report_test.go)
(the report, signature, chain, firmware id, manifests, golden comparison,
the NVDEC0 rule, the fetcher's cache, the evaluator on the capture and its
refusals),
[`azure_cgpu_own_eval_test.go`](internal/shared/tee/azure_cgpu_own_eval_test.go)
(the whole `azure-cgpu` verifier under `both` on the captured evidence
with the report: accepted, with the evaluation in the verdict; refused
without the report, with a changed measurement, for another nonce, with
two reports for one GPU; `own` refused at construction),
[`cmd/sagvd/gpu_evaluation_config_test.go`](cmd/sagvd/gpu_evaluation_config_test.go).

**Reproduce:**

```bash
go test -count=1 -run 'GPUReport|RIM|GPUEvaluator|OwnEvaluation|OwnAlone|GPUAttestOutput' ./internal/shared/tee/
```

**Scope.** Offline, on the material of one capture (one GPU, one driver,
one VBIOS). The manifests' XML signatures are verified (both captured
manifests verify, a manifest with one hex digit of a golden measurement
changed does not — `nvidia_rim_signature_test.go`); the canonicaliser and
the signature check are goxmldsig's (`docs/dependencies/goxmldsig.md`),
the certificate they verify under is the one this verifier chained to
NVIDIA's CoRIM root, and the signature value is re-encoded from the r||s
form XMLDSig prescribes to DER outside the signed bytes. So `own` — the
verdict on this evaluation alone, no NVIDIA service on the path — is
admitted: the captured evidence passes under it with NVIDIA's tokens
removed, and the policy's model and version pins are held against the
report. Since later that day the evaluation checks revocation too:
NVIDIA's OCSP responder is asked about the BROM certificate, the
Provisioner ICA and the GH100 Identity CA, each by its issuer, with a
nonce; each answer's delegated responder certificate is verified under
the issuer and marked for OCSP signing, the answer inside its day, and a
good answer is kept a day (`gpu_policy.revocation`, default `ocsp`;
`off` leaves it unchecked, on the record). NVIDIA's answers for the
captured chain are stored (`internal/shared/tee/testdata/nvidia/ocsp/`,
provenance in its README) and the evaluation on them is complete with
`revocation_checked` and `revocation_good` on the record
([`nvidia_ocsp_test.go`](internal/shared/tee/nvidia_ocsp_test.go): also a
synthetic responder answering revoked, unknown, without the nonce,
expired, from a certificate not marked for OCSP signing, or HTTP 500 —
each refused, nothing but a good answer cached). The per-GPU leaf is not
served by the responder (it answers `unauthorized` for it); its issuers'
status stands for it. What this verifier does not check: under `own` the
secure-boot and debug-mode claims only NVIDIA's tokens carry — `both`
asserts them, `own` says so. A live handshake under
`both` on hardware is on the record: run `scripts/hardware-test/azure-cgpu/evidence/20260916T204311Z-returnpath/` — the pinned worker's session opened on the H100 host with the evaluation complete (`vg_tee_attestation_total{provider="azure-cgpu",result="success",role="verify"} 1` in `sagvd-metrics.txt`; a complete evaluation includes both manifests' signatures), the manifests fetched from NVIDIA's service during the handshake (`cache-rim-NV_GPU_DRIVER_GH100_595.71.05.json`, `cache-rim-NV_GPU_VBIOS_1010_0210_886_96009F0004.json`), the 7B genome then restored on the H100 and gated EXACT (`job.json`), 17 audit events verified. On the raised runtime and the day's driver, `scripts/hardware-test/azure-cgpu/evidence/20261014T113334Z-returnpath/`: the pinned worker's session opened under `both` with the manifests for driver `595.91.07` fetched during the handshake (`cache-rim-NV_GPU_DRIVER_GH100_595.91.07.json`, `cache-rim-NV_GPU_VBIOS_1010_0210_886_96009F0004.json`), `vg_tee_attestation_total{provider="azure-cgpu",result="success",role="verify"} 1`, the 32B genome restored on the H100 and gated EXACT, 17 audit events verified.
Since later that day the evaluation is *on* the record, not only behind
it: a verifier that can say more than a measurement (`tee.DetailedVerifier`;
the `azure-cgpu` verifier does) puts its detail — the chip's product and
id, the reported TCB, the vTPM quote's PCR selection and digest the pin
was held against, each GPU with who vouched for it, the verifier's own
evaluations check by check — on `TRUST_EVALUATED` as `peer_detail` when
`sagvd` admits the worker and on `CROSS_CLOUD_ATTESTATION_VERIFIED` as
`destination_detail` when the authority releases a key to it; absent for
a verifier with only a measurement. Proven in process on the captured
evidence and the records: [`internal/shared/tee/detail_test.go`](internal/shared/tee/detail_test.go)
(the detail the verifier produces under `both`: Genoa, the sha256 bank,
GPU-0 as GH100, the evaluation complete),
[`internal/compute/returnpath/transport/handshake_detail_test.go`](internal/compute/returnpath/transport/handshake_detail_test.go),
[`internal/vault/trust/trust_test.go`](internal/vault/trust/trust_test.go),
[`internal/vault/orchestration/flow_test.go`](internal/vault/orchestration/flow_test.go)
(`TestFlow_TrustRecordCarriesThePeersDetail`),
[`internal/vault/kms/coordinator_detail_test.go`](internal/vault/kms/coordinator_detail_test.go).
On a live record: the cross-cloud drill `scripts/hardware-test/failover-cgpu/evidence/20260916T233717Z/`
carries `destination_detail` on the authority's `CROSS_CLOUD_ATTESTATION_VERIFIED`
event (`authority/audit-events.jsonl`: provider `azure-cgpu`, product
`Genoa`, the quote's PCRs `sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14`, GPU-0 `GH100` driver `595.71.05` VBIOS
`96.00.9F.00.04` vouched for by `https://nras.attestation.nvidia.com`; and again on the raised runtime, `scripts/hardware-test/failover-cgpu/evidence/20261014T121030Z/`, with driver `595.91.07` and the evaluation's every check true on the record). A live `peer_detail` from a
Return Path handshake on the H100 host: the Return Path run
`scripts/hardware-test/azure-cgpu/evidence/20260917T012834Z-returnpath/` — the
`TRUST_EVALUATED` event that admitted the worker carries `peer_detail`
with the verifier's own evaluation complete and revocation asked of
NVIDIA's responder — live in the run's first handshake, from the cache in
the one recorded (GH100 A01 GSP FMC LF: not served, GH100 A01 GSP BROM: good (cached), NVIDIA GH100 Provisioner ICA 1: good (cached), NVIDIA GH100 Identity: good (cached)).

---

<a id="c21"></a>
### C21 — A model under attack on AMD SEV-SNP fails over to an attested Intel TDX Trust Domain: the key released on Intel's word for the platform, the TDX module and the Quoting Enclave, the clean generation gated EQUIVALENT on Intel CPUs against references sealed on AMD

**Claim.** The failover of [C8](#c8) and [C14](#c14) with the standby the
other CPU TEE family: a GCP `c3-standard-4` Trust Domain (`acp-bootstrap`
on `tee.provider: "gcp-tdx"`, ADR 0018) reached across the VPC. Under a
policy the operator signed in advance — pinning the primary's chip and the
standby's TDX measurement — the authority (GCP SEV-SNP, its escrow key
sealed to its chip) took the primary's attested compromise report,
verified the standby's TDX quote through its attestation key and PCK chain
to the Intel SGX Root CA pinned in the binary, with Intel's signed TCB
info and QE identity on the platform, the TDX module and the Quoting
Enclave, released the key for the last generation sealed before the
attack, and confirmed the standby's receipt: the genome restored and gated
through the door on the Trust Domain's CPUs. Every step is on the audit
record.

**Evidence.**
[`scripts/hardware-test/failover-tdx/evidence/20260916T181528Z/`](scripts/hardware-test/failover-tdx/evidence/20260916T181528Z/)
— `authority/report.json`: `status: restored`; trigger `compromise-report`
at 18:27:18.85Z with `primary_measurement_hex: 69da361d…c790`; `decision:
failover … restore generation 1 on the standby`; `release.destination_kind:
gcp-tdx`, `destination_measurement_hex: ed70198a…177b`,
`policy_version: failover-policy-v1;failover=1;revocation=1`;
`restore.gate`: **EQUIVALENT**, door native float, 16 fixtures,
`max_abs_err: 1.45e-4`, `max_rel_err: 1.14e-5`, `backend_seconds: 10.87`;
`timing`: detect 10.11 s, release 1.09 s, restore 11.6 ms, gate 10.87 s,
failover 13.99 s, **RTO 24.09 s**, **RPO 12.00 s**; `audit_chain_length:
5`. `authority/verifiers.json`: the `gcp-tdx` entry (the pinned
measurement, `pcs_cache_dir`) and the `gcp-sev-snp` entry — the primary's
anchors. `authority/cache-pcs-tdx-tcb-00806f050000.json` and
`cache-pcs-tdx-qe-identity.json`, with their issuer chains: Intel's TCB
info for FMSPC `00806f050000` and QE identity as fetched and verified.
`authority/failover-verify.txt`: the signed policy, serial 1, standby
`gcp-tdx https://10.128.15.216:8443`, measurement `ed70198a…177b`.
`authority/audit-verify.json`: `ok: true`, 5 events (`FAILOVER_DECIDED` →
`CROSS_CLOUD_HANDSHAKE_INITIATED` → `CROSS_CLOUD_ATTESTATION_VERIFIED` →
`KEY_RELEASE_AUTHORIZED` → `CROSS_CLOUD_RESTORE_COMPLETED`), tip
`03758aa2…4cb3`. `authority/escrow-provision.json`: `tee: gcp-sev-snp`, sealed.
`destination/destination-identity.json`: `tee_provider: gcp-tdx`,
measurement `ed70198a…177b`, `tdx.mrtd_hex: c1ee9c16…70a5`, three RTMRs.
`destination/genome-9937cc360c97-g1-1e3eec824c6a.receipt.json`: the receipt (`destination_kind: gcp-tdx`, generation
1, `gate.level: EQUIVALENT`) with its Evidence — the TDX quote
(8,000 bytes). `destination/tsm.txt`: `/dev/tdx_guest`,
`Memory Encryption Features active: Intel TDX`;
`destination/system.txt`: `Vendor ID: GenuineIntel`, family 6 model 143
(Sapphire Rapids), 4 vCPUs. `destination/acp-bootstrap.log`: key
released, restore, gate, key erased. `primary/sentinel.json`: `outcome:
compromised`, `attestation.kind: gcp-sev-snp`, last generation 1. The
same drill on the raised runtime (torch 2.14.1, transformers 5.19.0),
[`…/20261014T041150Z/`](scripts/hardware-test/failover-tdx/evidence/20261014T041150Z/) — the standby on the current image (kernel
`7.0.0-1014-gcp`; MRTD `c1ee9c16…70a5` unchanged, RTMR0–2 new, measurement
`dfe77c76…1a9a`, pinned by the policy and named in the release);
`restore.gate`: EQUIVALENT, `max_abs_err: 1.46e-04`; `timing`: RTO
20.42 s, RPO 9.00 s; `audit-verify.json`: `ok: true`, 5 events, tip
`58043177…c776`; `destination/dest-seal-keys.json`: `tee: gcp-tdx`.


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/failover-tdx/evidence/20261015T030045Z/`](scripts/hardware-test/failover-tdx/evidence/20261015T030045Z/) — the SEV-SNP primary failed over to the Trust Domain in 11.76 s (release 0.98 s, gate 10.59 s), gate EQUIVALENT as the policy required.
**Reproduce:**

```bash
scripts/hardware-test/failover-tdx/run.sh <gcp-project> europe-west4-a us-central1-a   # ~15 min: two GCP n2d Milan CVMs + a c3 TDX Trust Domain
```

**Scope.** One run, with the 0.5B model of the failover drill, trained on
the primary's AMD Milan cores in float32 and proven on the standby's Intel
Sapphire Rapids cores: EQUIVALENT (max abs err 1.45e-4 against atol
1e-2), not EXACT — float32 is not byte-identical across CPU vendors
either, the difference the same order as the CPU↔GPU one ([C6](#c6),
[C18](#c18)), and the same-runtime EXACT of [C14](#c14) is a property of
the pinned runtime; the integer door ([C19](#c19)) is the byte-portable
route. Intel PCS was reachable from the authority (its documents are in
the evidence); without it and without a cache the verifier refuses. The
standby held no sealed escrow key in this run; since ADR 0022 a TDX host
seals one to its vTPM and can be the authority ([C23](#c23)). The pin is the
image's MRTD and RTMRs folded into one measurement; a kernel update
re-issues it.

---

<a id="c22"></a>
### C22 — The authority says no on the record: against one attack on real SEV-SNP chips, seven policies are refused for seven different reasons — two of them after the standby's chip verified — and the one move goes to the generation whose bytes match the sentinel's word

**Claim.** The anti-worm invariants of [C8](#c8), exercised one by one on
the shipping binaries on live hardware. The failover drill's two machines,
one attack, and eight operator-signed policies run against the same
compromise report: a policy that expired while the authority watched, one
whose RPO bound the genome misses, one whose quarantine covers every
genome, a good one under an operator stop, one pinning another machine as
the standby, a good one with the newest bundle corrupted in the replica,
the spent policy again, and a policy signed by a stranger. Seven are
refused, each for its own stated reason; six of the eight answers are
signed events on one hash-chained audit log, and in two of them the
standby's SEV-SNP report had already verified when the operator's policy
said no. The one move restores generation 0 with generation 1 set aside
on the record, because generation 1's bytes in the replica no longer
match the sentinel's signed record.

**Evidence.**
[`scripts/hardware-test/failover-negatives/evidence/20260916T191033Z/`](scripts/hardware-test/failover-negatives/evidence/20260916T191033Z/)
— `standby/report-1.json`: `status: declined`, reason *failover: policy serial
1 expired at 2026-09-16T19:14:30Z* (armed at 19:13:45Z, the report came at
19:21:48.79Z); `report-2.json`: declined, *the newest trustworthy genome,
generation 1, was sealed 11.996s before the trigger; the policy allows at most
1s*; `report-3.json`: declined, *no genome in the verified chain was sealed by
2026-09-15T19:21:48.792219003Z and checks out*, both generations in
`set_aside`; `report-4.json`: `status: failed`, decision `failover`, error
*operator stop in force (revocation serial 2): incident review*;
`report-5.json`: failed, *failover policy serial 5 releases only to its
standby (gcp-sev-snp, measurement [69da361d…c790]); gcp-sev-snp 21199b36…9546
is not it*; `report-6.json`: `status: restored`, `genome.generation: 0`,
`set_aside`: *sentinel: gen-000001.genome hashes to 640046c8…5671 (2216819
bytes), the record says addaaf0c…be7d (2216819 bytes), the record says
addaaf0c…be7d*, `restore.gate`: **EXACT**, 16 fixtures, `max_abs_err: 0`,
`timing`: RPO 270.0 s, restore 12.7 ms, gate 11.80 s, failover 12.06 s, RTO
34.37 s; `failover-7.log`: *failover: policy serial 6 already carried out a
failover (audit event xcc-evt-…000c); moving again needs a new policy*;
`failover-8.log`: *failover: signature does not verify under the operator
key*. `standby/audit-events.jsonl` and `audit-verify.json`: 16 events, `ok:
true`, tip `05a015c1…7161` — three `FAILOVER_DECIDED` declines, then for runs
4 and 5 `FAILOVER_DECIDED` → `CROSS_CLOUD_HANDSHAKE_INITIATED` →
`CROSS_CLOUD_ATTESTATION_VERIFIED` → `KEY_RELEASE_DENIED` (stage `policy`,
`failover-policy-v1;failover=4;revocation=2` and
`failover-policy-v1;failover=5;revocation=3`), then for run 6
`FAILOVER_DECIDED` → … → `KEY_RELEASE_AUTHORIZED`
(`failover-policy-v1;failover=6;revocation=3`) →
`CROSS_CLOUD_RESTORE_COMPLETED`. `standby/stop-2.json`: serial 2, `stop_all:
true`, "incident review"; `stop-3.json`: serial 3.
`standby/policy-5-verify.txt`: the standby pinned at `69da361d…c790` (the
primary's chip); `policy-7-verify.txt`: *signature does not verify under the
operator key*. `standby/tamper.txt`: `gen-000001.genome` `addaaf0c…be7d` →
`640046c8…5671`, one byte. `primary/sentinel.json`: `outcome: compromised`,
generation 1 the last word, `attestation.kind: gcp-sev-snp`. The same
eight runs on the raised runtime (torch 2.14.1, transformers 5.19.0),
[`…/20261014T035731Z/`](scripts/hardware-test/failover-negatives/evidence/20261014T035731Z/) — the same seven refusals for the same
reasons (`report-1..3.json`: declined; `report-4.json`, `report-5.json`:
`status: failed` after `CROSS_CLOUD_ATTESTATION_VERIFIED`; `failover-7.log`,
`failover-8.log`: refused at the door), `report-6.json`: generation 0
restored with generation 1 set aside (`8b5f8661…ebe2` →
`087b3516…72dc`, one byte), gate EXACT, the move 12.08 s (RTO 90.56 s, the sixth policy issued 79 s after the attack this time); 16 events,
`ok: true`, tip `094b5ec2…90af`.


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/failover-negatives/evidence/20261015T024558Z/`](scripts/hardware-test/failover-negatives/evidence/20261015T024558Z/) — the eight runs as before: an expired policy declined (`exit=3`), a 1 s RPO declined (the newest genome 8.998 s old), a day-long quarantine declined, an operator stop denied after the chip verified, a policy pinning another machine denied, a corrupted newest bundle set aside and generation 0 restored (`exit=0`, gate EXACT), the spent policy and a stranger-signed policy refused at the door.
**Reproduce:**

```bash
scripts/hardware-test/failover-negatives/run.sh <gcp-project> europe-west4-a   # ~15 min: two GCP n2d Milan CVMs
```

**Scope.** One run, 0.5B, one TEE family, both machines in one project.
Runs 7 and 8 are refused before the authority acts, so they leave no
audit event — by design, and stated as such. The ninth refusal, a rogue
sentinel with the stolen seed attesting from the wrong chip, is the
failover drill's own negative leg ([C8](#c8)'s kit, declined on the record
on `20260916T021933Z`). Not exercised on hardware: an operator stop that
lands during a hand-shake, and a forged chip report — the SEV-SNP
signature check of [C7](#c7) is what refuses that, and it is proven
offline.

---

<a id="c23"></a>
### C23 — A release authority on an Intel TDX Trust Domain holds its escrow key sealed to the guest's vTPM under a policy of the pinned boot, re-provisions it through the recovery ceremony, and moves a model with it

**Claim.** TDX gives a guest no sealing key of its own; since ADR 0022
`sagvd` seals the escrow key to the guest's vTPM — a fresh AES-256 key per
seal held by the TPM as a sealed object under a policy only this boot's
PCRs satisfy, the plaintext under that key with AES-256-GCM — and on a
`c3` Trust Domain it did: `sagvd escrow-provision` on `gcp-tdx` sealed the
key, opened it once on the spot, the recovery ceremony re-sealed it, and
`sagvd failover` unsealed it at start and carried the failover drill to
its end: the primary's attested compromise report, a TDX standby verified
to Intel's root, the key released, the genome restored and gated.

**Evidence.**
[`scripts/hardware-test/failover-tdx-authority/evidence/20260916T200841Z/`](scripts/hardware-test/failover-tdx-authority/evidence/20260916T200841Z/)
— `authority/escrow-provision.json`: `tee: gcp-tdx`, key `221addd3bffe3f79`,
sealed at `ed70198a…177b`; `authority/escrow-sealed-shape.txt`: `{'tee': 'gcp-tdx', 'schema': 'vault-genome/vtpm-sealed/v1', 'pcrs': 'sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14', 'public_bytes': 80, 'private_bytes': 160, 'box_bytes': 60}`;
`authority/authority-identity.json`: `key_escrow_storage: sealed:gcp-tdx`;
`authority/escrow-reprovision.json`: the same key `221addd3bffe3f79`, `source:
stdin`; `authority/vtpm.txt`: `/dev/tpm0`, `/dev/tpmrm0`,
`[    2.147722] tpm_tis MSFT0101:00: 2.0 TPM (device-id 0x9009, rev-id 0)`; `authority/vtpm-pcrs.txt`: the fifteen PCRs of the boot;
`authority/report.json`: `status: restored`, trigger `compromise-report`
at 20:19:49.37Z, `release.destination_kind: gcp-tdx`, `restore.gate`:
**EQUIVALENT**, `max_abs_err: 1.45e-4`, `timing`: RPO 12.00 s, RTO
20.27 s; `authority/audit-verify.json`: `ok: true`, 5 events, tip
`78551451…bb2f`; `authority/tsm.txt`: `/dev/tdx_guest`, `tdx: Guest detected`.
The same drill on the raised runtime (torch 2.14.1, transformers 5.19.0),
[`…/20261014T042457Z/`](scripts/hardware-test/failover-tdx-authority/evidence/20261014T042457Z/) — the authority a Trust Domain on the
current image (kernel `7.0.0-1014-gcp`, measurement `dfe77c76…1a9a`);
`escrow-provision.json`: `tee: gcp-tdx`, key `f28d73ab63bfe6fe`, the same
shape on disk, re-provisioned through the ceremony (`source: stdin`),
`key_escrow_storage: sealed:gcp-tdx`; `report.json`: `status: restored`,
EQUIVALENT `1.46e-04`, RTO 20.42 s, RPO 12.00 s; `audit-verify.json`:
`ok: true`, 5 events, tip `f301ece8…4846`.


The same kit on 2026-10-15, on the tree of 0.4.1 (main after #81, #82 and #84): [`scripts/hardware-test/failover-tdx-authority/evidence/20261015T031442Z/`](scripts/hardware-test/failover-tdx-authority/evidence/20261015T031442Z/) — the authority on TDX moved the SEV-SNP primary's model to a Trust Domain in 13.51 s (release 1.50 s, gate 10.59 s), gate EQUIVALENT as required.
**Reproduce:**

```bash
scripts/hardware-test/failover-tdx-authority/run.sh <gcp-project> europe-west4-a us-central1-a   # ~15 min: an n2d Milan CVM + two c3 TDX Trust Domains
go test -count=1 -run 'VTPM' ./internal/shared/tee/ ./cmd/sagvd/                                  # the sealer's contract on a fake TPM
```

**Scope.** One run, 0.5B, one authority. The root of the sealing is the
guest's vTPM — Google's device inside the Trust Domain — and a PCR policy
of this boot, not the TEE's own key; the attestation is still Intel's. A
kernel or firmware update changes the PCRs and the key is re-provisioned
from the recovery envelope, not re-derived. The same sealer on an Azure
confidential GPU host: proven the same day on an NCC H100 v5 (`scripts/hardware-test/azure-cgpu/evidence/20260916T204311Z-returnpath/`: `escrow-provision.json` `tee: azure-cgpu`, key `11e87307c4f33f8c`, `escrow-sealed-shape.txt` the same blob shape under the same fifteen PCRs, `escrow-reprovision.json` the same key re-sealed through the ceremony).

---

<a id="c24"></a>
### C24 — A live SEV-SNP host runs the release authority from key files sealed to its chip: every seed and the session sealing key sealed in place, opened at start, and the failover drill completed from them

**Claim.** ADR 0023 on hardware: on the failover drill's standby (a GCP
n2d SEV-SNP VM), `sagvd seal-keys` sealed the authority's signing seed,
the audit seed and the session sealing key in place to the chip's
derived key, each bound to its name; `sagvd identity`, `sagvd
escrow-provision`, the recovery ceremony, `sagvd failover` and the audit
verify then ran from the sealed files, and the drill completed — the
attacked primary's model restored on the standby, the audit log verified,
the stolen-seed negative declined.

**Evidence.**
[`scripts/hardware-test/gcp-failover/evidence/20260916T212752Z/`](scripts/hardware-test/gcp-failover/evidence/20260916T212752Z/)
— `standby/seal-keys.json`: `tee: gcp-sev-snp`, measurement `21199b36…9546`,
`sealed`: `keys.authority_signing.seed_path`, `keys.session_sealing.material_path`, `keys.audit_signing.seed_path`; `standby/steps.txt`: `seal-keys exit=0`, then `sagvd
identity exit=0`, `escrow-provision exit=0`, `sagvd failover exit=0`;
`standby/report.json`: `status: restored`, generation 1, gate
EXACT, RTO 22.10 s, RPO 9.00 s; `standby/audit-verify.json`: `ok:
true`, 5 events, tip `bb9fa06c…fa62` (and on the raised runtime,
[`…/20261014T034337Z/`](scripts/hardware-test/gcp-failover/evidence/20261014T034337Z/): the same five files sealed, then the
cross-cloud client key after the failover config is written — `seal-keys
(failover config) exit=0 sealed=crosscloud.transport_tls.client_key
already=5` — and `sagvd failover exit=0`); `standby/rogue-report.json`: the
stolen seed declined.

**Reproduce:**

```bash
scripts/hardware-test/gcp-failover/run.sh <gcp-project> europe-west4-a   # ~25 min: two GCP n2d Milan CVMs
go test -count=1 -run 'SealKeys|SealedSecret|SealerFor' ./cmd/sagvd/ ./cmd/acp-compute/ ./internal/shared/tee/
```

**Scope.** One run, SEV-SNP; the sealer on TDX and the Azure confidential
GPU host is the vTPM one of [C23](#c23), the same code path
(`readSecret` → `tee.OpenSecret`), exercised there for the escrow key
and here for the key files. The sentinel's seed on the primary is sealed
the same way since later that day (`acpctl sentinel seal-key`, ADR 0023
amended — see [C25](#c25)), and so are the daemons' TLS keys and tokens
(`sagvd`'s server key, cross-cloud client key and REST token,
`acp-compute`'s client key, `acp-bootstrap`'s server key and bearer
token). Still a file on a host: a `-key-file` given to
`crosscloud-restore`, the operator's input for one command.

---

<a id="c25"></a>
### C25 — The sentinel on a live SEV-SNP primary runs from a seed sealed to its chip: sealed in place before the first record, the same key from the sealed file, the drill failed over on its word, and the sealed file taken to another chip does not open

**Claim.** ADR 0023, amended, on hardware: on the failover drill's
primary (a GCP n2d SEV-SNP VM), `acpctl sentinel seal-key` sealed the
sentinel's seed in place to the chip's derived key under the name
`sentinel.seed`; `acpctl sentinel identity` read the same key from the
sealed file, and `acpctl sentinel watch` ran from it — two generations
sealed, the attack caught, the compromise report signed on the chip's
word. The authority failed over on that word. On the standby's chip —
a real SEV-SNP chip, the wrong one — the sealed file did not open, and
the bare seed stolen there was declined as in [C14](#c14). On the same
run the authority ran from its 5 sealed files — its seeds, its mTLS
server key, its REST API token — and the destination on that host from
its own sealed TLS key and bearer token (`acp-bootstrap seal-keys`). The
cross-cloud transport's client key was still bare in this run (sealed
since by a second `seal-keys` after the failover config is written;
proven in the cross-cloud run
`scripts/hardware-test/failover-cgpu/evidence/20260916T233717Z/`, whose
authority sealed it — `seal-keys (failover config) exit=0 sealed=crosscloud.transport_tls.client_key already=5` — before releasing the key).

**Evidence.**
[`scripts/hardware-test/gcp-failover/evidence/20260916T231442Z/`](scripts/hardware-test/gcp-failover/evidence/20260916T231442Z/)
— `primary/sentinel-seal-key.json`: `tee: gcp-sev-snp`, measurement
`10f5ac22…4519`, `sealed: true`; `primary/sentinel-identity.json` and
`primary/sentinel-identity-sealed.json`: the same key `sentinel-aa5c0c595b883fe0` before and
after; `primary/steps.txt`: `sentinel seal-key exit=0`, `sentinel exit=3`;
`standby/report.json`: `status: restored`, generation 1, gate
EXACT, RTO 18.53 s, RPO 9.00 s; `standby/audit-verify.json`: `ok:
true`, 5 events, tip `17876233…1c5f` (and on the raised runtime,
[`…/20261014T034337Z/`](scripts/hardware-test/gcp-failover/evidence/20261014T034337Z/): `sentinel seal-key exit=0 … sealed=True`,
RTO 18.69 s, 5 events, tip `d6e0a658…2c4d`, the stolen sealed seed refused
with `exit=2` as below); `standby/steps.txt`:
`stolen sealed seed: acpctl sentinel identity exit=2 (want 2: does not open off the primary's chip): acpctl sentinel identity: --key: /root/stolen.sealed: integrity[signature_invalid]: sealed secret "sentinel.seed": this host does not open it (sealed at 10f5ac22cef1db0a… on gcp-sev-snp): integrity[signature_invalid]: `; `standby/stolen-sealed-identity.err`: `acpctl sentinel identity: --key: /root/stolen.sealed: integrity[signature_invalid]: sealed secret "sentinel.seed": this host does not open it (sealed at 10f5ac22cef1db0a… on gcp-sev-snp): integrity[si`;
`standby/seal-keys.json`: 5 files sealed (`keys.authority_signing.seed_path`, `keys.session_sealing.material_path`, `keys.audit_signing.seed_path`, `vault.tls.server_key`, `http_api.bearer_token_file`);
`standby/dest-seal-keys.json`: `http.tls.server_key`, `http.bearer_token_file`.
In process:
[`cmd/acpctl/sentinel_seal_test.go`](cmd/acpctl/sentinel_seal_test.go)
(sealed once, mode 0600, the same key from the sealed file, refused on
another host and without `--tee`, the watch from the sealed file).

**Reproduce:**

```bash
scripts/hardware-test/gcp-failover/run.sh <gcp-project> europe-west4-a   # ~25 min: two GCP n2d Milan CVMs
go test -count=1 -run 'SealKey' ./cmd/acpctl/
go test -count=1 -run 'SealKeys' ./cmd/sagvd/ ./cmd/acp-compute/ ./cmd/acp-bootstrap/
```

**Scope.** One run, SEV-SNP (the sentinel's TEEs are `gcp-sev-snp` and
the simulated one). The seed's word was already bounded by the chip's
report (ADR 0017, [C14](#c14)); sealing removes the file as a thing to
steal. Still a file on a host: a `-key-file` given to
`crosscloud-restore`, the operator's input for one command.

---

<a id="c26"></a>
### C26 — A 32B model goes through the genome path on an attested confidential GPU: fine-tuned, sealed, restored and gated EXACT on the H100, over the Return Path, on the record

**Claim.** The largest model measured is Qwen/Qwen2.5-32B-Instruct (about 65 GB of bfloat16
weights): on the Azure confidential GPU VM of [C17](#c17) it was
fine-tuned in bfloat16 on the H100 NVL (93 GB), its genome sealed
and verified, and — with `sagvd` and `acp-compute` on the same VM
attesting as `azure-cgpu` from files sealed to its vTPM — restored and
gated through the door over the Return Path: **EXACT** on the pinned
runtime (16/16 fixtures exact), the verdict signed by the
authority and every stage on the audit record.

**Evidence.**
[`scripts/hardware-test/azure-cgpu/evidence/20260917T020218Z/`](scripts/hardware-test/azure-cgpu/evidence/20260917T020218Z/)
— `steps.txt` (`base_repo=Qwen/Qwen2.5-32B-Instruct base_rev=5ede1c97bbab…`, `finetune exit=0`),
`finetune.json` (device `cuda`, dtype `bfloat16`, loss 5.804 →
0.000, 57.5 s), `verify.json` (`ok`, 33.6 MB bundle),
`torch.txt`;
[`evidence/20260917T020218Z-returnpath/`](scripts/hardware-test/azure-cgpu/evidence/20260917T020218Z-returnpath/)
— `job.json` (gate `EXACT`, `pinned replay`, 16/16 exact, max abs
err 0, the signed verdict), `audit-verify.json` (`ok`, 17
events), `steps.txt`. The same run on the raised runtime (torch
2.14.1+cu126, transformers 5.19.0),
[`…/20261014T113334Z/`](scripts/hardware-test/azure-cgpu/evidence/20261014T113334Z/) — `finetune.json`: loss 5.799 → 4.6e-05 in
42.4 s, `verify.json`: ok, the 33,632,414-byte bundle, `gate-gpu.json`:
EXACT, `replay-gpu.json`: bit for bit;
[`…/20261014T113334Z-returnpath/`](scripts/hardware-test/azure-cgpu/evidence/20261014T113334Z-returnpath/) — `job.json`: EXACT, 16/16, max
abs err 0, 238 s; `audit-verify.json`: `ok`, 17 events, tip `e2be1cfe…5f9e`.

**Reproduce:**

```bash
VG_BASE_REPO=Qwen/Qwen2.5-32B-Instruct VG_BASE_REV=5ede1c97bbab… scripts/hardware-test/azure-cgpu/run.sh   # one NCC H100 v5 VM, about 90 minutes
```

**Scope.** One run, one model, one GPU: the pinned runtime's EXACT is the
same-device replay of [C16](#c16) and [C17](#c17) at 32B; cross-device
equivalence at 32B is not measured, and 70B was not run (no
non-confidential H100 quota; a 70B in bfloat16 does not fit one 94 GB
GPU without quantisation, which would change the base the genome names).

---

<a id="c28"></a>
### C28 — The release authority's host is deleted in the middle of a job, and a fresh SEV-SNP host becomes the same authority: the same keys sealed to its chip, the same escrow key through the recovery ceremony, the audit chain continued from the replica, the next verdict signed in under a minute from the runtime being ready

**Claim.** On real AMD SEV-SNP, with the authority and its worker on one
Confidential VM running gate jobs over the Return Path, the VM is deleted
without warning while a job is in flight; a fresh VM, created at that
moment, takes only the operator's safe (the key material `acp-keygen`
made, the recovery key, the escrow envelope) and the last replica of the
audit log and the genomes, seals the key files to its own chip, verifies
the replica, re-provisions the escrow key through the recovery ceremony,
starts both daemons over the replicated log, resubmits the lost job and
signs its verdict — the same authority signing key, the same audit key,
the same escrow key, the chain continued from the replica's tip — in
49–50 s from the host's runtime being ready, in all three runs; from the
deletion, with the host created on demand, 236 s, 237 s and 489 s, the
third with a package mirror that took 330 s for the runtime.

**Evidence.**
[`scripts/hardware-test/authority-loss/evidence/20261015T174115Z/`](scripts/hardware-test/authority-loss/evidence/20261015T174115Z/)
(the full record; `20261015T171848Z/` and `20261015T173009Z/` are the same
drill, within two seconds on every number but the fresh host's package
install — 78–80 s there, 330 s in the third run — and without the final
offline verification: their stop step left `sagvd` holding the file's
lock, a bug of the kit fixed before the third run and stated in its
README). In the third run: `runner-timeline.txt` A's deletion issued at 17:45:27.82Z
with job 4 in flight, B created 9.4 s later;
`a-markers.txt` jobs 1–4 submitted and done, job 5
submitted and never done; `b/audit-verify-replica.json` `ok: true`,
64 events, tip `75b63362…` — the tip A's last manifest
named (`a/state-manifest-4.json`); `b/seal-keys-sagvd.json`,
`b/seal-keys-worker.json` the key files from the safe sealed to B's chip;
`b/escrow-reprovision.json` the escrow key `a08e386a…` out of the
ceremony — the tag `a/escrow-provision.json` printed on A — `source:
stdin`, `tee: gcp-sev-snp`; `b/sagvd.log` `sagvd audit log open …
events=64 tip=75b63362…`; `b/steps.txt` `lost_jobs=5`,
the resubmitted job `succeeded`, gate EXACT, 6 of 6, its event sealed on
the chain; `b/audit-verify.json` `ok: true`, 96 events —
A's and B's under the one audit key, tip `c3269c3e…`;
`timeline.txt` the four facts checked by the runner from the two records
— the authority key, the audit key and the escrow key the same on A and
B, the replica intact, the final chain intact — and the recovery times:
RTO cold **489.3 s** (VM creation 9.4 s, boot to the first
line 74.8 s, the runtime from the locks 330.2 s), RTO warm
**49.5 s** (the replica restored 1.1 s, identities and
sealing 10.5 s, the ceremony 10.3 s, the daemons and the
session 22.2 s, the verdict 5.4 s).

**Reproduce:**

```bash
scripts/hardware-test/authority-loss/run.sh <gcp-project>    # ~10 min, two n2d-standard-4 one after the other, deletes both and the bucket
```

**Scope.** One zone, one image (so one launch measurement on both
hosts), a tiny model, a safe that is a bucket object and a replica that
is a tar after every job. The job in flight was lost by design in these
three runs (KNOWN_ISSUES #16); the run below, with the job store in the
replica, resumed it. What the cold number mostly measures is a VM's boot
and a package mirror, not the product. The drill does not say what a
standby with the daemons already running would need; the warm number is
the floor it starts from.

**Run `20261015T204339Z` (2026-10-15, the job store in the replica).**
The same drill with `queue.path` (ADR 0026) replicated the moment a job
is accepted: the fresh host's `sagvd` opened the replicated log at 81
events and admitted the lost job again by itself — `b/sagvd.log` `sagvd
job resumed after a restart`, job `e305630c…`, request `req-2e6c0bc9…`,
attempt 2; `b/steps.txt` `same_job_id=true same_request_id=true` against
`a-job-6-submit.json`, A's own submission record — and signed its verdict
EXACT, 6 of 6, 49.1 s after its runtime was ready and 233.5 s from the
deletion; the request's second `REQUEST_RECEIVED` carries `resumed`;
`b/audit-verify.json` `ok: true`, 113 events, tip `2a7cb51e…`. Nothing
was resubmitted. The same authority as before: the authority key, the
audit key and the escrow key (`fc7eb877…`) the same on A and B.

<a id="c29"></a>
### C29 — An air-gapped SEV-SNP host runs the Return Path from caches it filled while connected: egress denied, the handshake verified from the cache, a job gated EXACT; without the cache the handshake is refused naming KDS, and nothing is admitted

**Claim.** On real AMD SEV-SNP, a host fills its peer verifiers' caches
with one command while it still has a route (`acpctl tee prefetch
--config` for each daemon: this chip's VCEK from AMD KDS, verified as the
peer verifier would verify it), is then put behind a firewall rule that
denies all egress, and runs the Return Path with nothing from the world:
the key files sealed, a genome fine-tuned and sealed with the runtime
offline, both daemons started, each side's report verified with the
cached VCEK, a gate job EXACT. With the caches wiped, the handshake is
refused with KDS named on the record and no job is dispatched; with the
caches restored from a copy, the next session opens and a job gates
EXACT. `acpctl tee cache-status` says what the caches hold and until
when (seven years for a VCEK), and exits 1 when they are empty.

**Evidence.**
[`scripts/hardware-test/air-gap/evidence/20261015T212716Z/`](scripts/hardware-test/air-gap/evidence/20261015T212716Z/)
— `prefetch-sagvd.txt`, `prefetch-worker.txt`, `prefetch-sagvd.json`:
`prefetched for a gcp-sev-snp peer on this host`, one VCEK each, CN
`SEV-VCEK`, valid 2026-10-14 → 2033-10-14; `cache-files.txt` the two
cached files (chip `188de2d8…`, TCB `0xde1d000000000004`), their sizes
and digest prefixes; `firewall-rule.json` the rule — `EGRESS`, `DENY
all`, `0.0.0.0/0`, priority 100, target tag `vg-airgap-20261015t212532z`
— and `instance-tags.txt` the tag on the instance; `egress.txt` after the
cut — KDS and the bucket `Connection timed out`, the metadata server
`200`; `timeline.txt` and `runner-timeline.txt` — the guest ready at
21:28:48Z, the tag added at 21:28:57.96Z, KDS dead 33 s after the guest
saw the tag; `sagvd-airgap.log` `sagvd session opened`, `job-airgap.json`
`succeeded`, EXACT, 6 of 6, 5.2 s; `cache-status-wiped.txt` `the caches
are empty` (exit 1); `sagvd-wiped.log` `sagvd return-path handshake
failed … fetch VCEK: Get "https://kdsintf.amd.com/vcek/v1/Milan/…"` 41.1 s
after the start, and no `session opened`; `cache-status-restored.txt`
(exit 0), `sagvd-restored.log` `session opened`, `job-restored.json`
EXACT; `audit-verify.json` `ok: true`, 33 events, tip `d92fed3e…`;
`sha256sums.txt` over all of it, 52 of 52. The kit:
[`scripts/hardware-test/air-gap/`](scripts/hardware-test/air-gap/); the
procedure: [`docs/operator/runbooks/air_gap.md`](docs/operator/runbooks/air_gap.md).

**Scope.** One host, both daemons on one chip, so the one VCEK serves
both verifiers; a peer on another chip needs its VCEK carried into the
cache, as the runbook says. SEV-SNP only: `prefetch` covers `gcp-tdx` in
code (Intel's PCS documents, each good until its `nextUpdate`), unrun on
hardware. The cut is a VPC firewall rule, not a physical gap; the
metadata server stays reachable, used by the guest for the network tag
and the serial console only. The release itself was verified on the
connected side: its offline verification waits on Sigstore bundles
(KNOWN_ISSUES #15).

<a id="c30"></a>

### C30 — The delegated verifier runs a real session against a live Veraison with a real GCP SEV-SNP report: the EAR verifies under Veraison's key, names the session's nonce, says affirming, and the measurement this side reads from the report is the pin

**Claim.** With `tee.peer.verifier.mode: rats` the daemons do not appraise
a peer's Evidence themselves: the Evidence record goes to a RATS Verifier
over Veraison's challenge-response API and the attestation result (an
EAR) comes back. Against Veraison itself — the bench's native deployment
with the `sevsnp` scheme, provisioned with AMD's Milan trust anchor and
the approved launches — `tee.RATSVerifier` opened a session with the
report's REPORT_DATA as the nonce, posted a real GCP n2d report in the
JSON TSM-report form the wire carries (the 1184-byte report and the
host's 4763-byte certificate table inside, 7980 bytes under
`application/vnd.veraison.tsm-report+json`), received an EAR signed
ES256 under the key Veraison publishes in its well-known document,
verified it, found `eat_nonce` equal to the session's nonce, the
`SEVSNP` appraisal `affirming` under `policy:SEVSNP` with `hardware: 2`
and `runtime-opaque: 2` (genuine, encrypted), and read from the posted
report the launch measurement it had been pinned to. The round trip took
371 ms. The daemons' integration suite does the same against the API's
test double with the simulated family, both directions, with the rogue
contraindicated and the unreachable Verifier refused on the record.

**Evidence.**
[`scripts/hardware-test/veraison-live/evidence/20261016T024628Z/`](scripts/hardware-test/veraison-live/evidence/20261016T024628Z/)
— `well-known.json` Veraison `+f997c52`, `ear-verification-key` (EC
P-256), the media types including the JSON TSM report; `ear.jwt` the
EAR as received; `summary.json` — `ear_status: affirming`,
`ear_policy_id: policy:SEVSNP`, the trust vector, `ear_verifier_id:
Veraison Project`, `ear_nonce_equals_session: true`,
`local_measurement_equals_pin: true`, `measurement_hex: ccdc5cf0…`,
`session_nonce_hex: f896ba42…`, `round_trip_ms: 371`, the fixture's
SHA-256 `aa63db18…`; `metadata.txt` the tree, the four Veraison services
running, the CoRIM's SHA-256 `77c4da9c…`; `go-test.log`;
`sha256sums.txt`. The report: Veraison's own captured
`sevsnp-gcp-tsm-report.cbor` (SHA-256 `ddc3306c…`), re-encoded to JSON
without a byte changed inside
([`internal/shared/tee/testdata/veraison/`](internal/shared/tee/testdata/veraison/)).
The kit: [`scripts/hardware-test/veraison-live/`](scripts/hardware-test/veraison-live/);
the test it runs: `internal/shared/tee/rats_live_test.go`; the mode:
[`docs/operator/runbooks/delegated-verifier.md`](docs/operator/runbooks/delegated-verifier.md).

**Scope.** A captured report, not a fresh one over a fresh challenge:
the session nonce was the report's own REPORT_DATA, which is what the
handshake derives for a live peer, so the client's path is the same
up to where the challenge is made. Veraison ran on the same machine as
the client, over TLS with the bench's client certificate. The fresh
challenge on a chip, with the Verifier on another host, is C31.

<a id="c31"></a>

### C31 — On real SEV-SNP, both daemons delegate the appraisal of each other's Evidence to a Verifier on another VM, over mutual TLS by name: the session opens, the job gates EXACT, the admission carries the EAR; a worker of another family, a policy that names another appraisal, and an unreachable Verifier each refuse, on the record

**Claim.** In one GCP project, an n2d SEV-SNP Confidential VM runs sagvd
and acp-compute with `tee.peer.verifier.mode: rats` on both; a plain VM of
its own runs Veraison, built natively from the tree the bench validated,
its services under a root CA the operator holds, its verification API
taking only callers with a certificate of that CA. The operator (the
runner) provisions the Verifier before the session — AMD's Milan root as
the trust anchor, the attester's own launch measurement as a reference
value, a CoRIM made from the chip's report and accepted by the
provisioning API — hands the daemons the Verifier's EAR key from its
well-known document and client certificates under the root, and releases
the attester. The same chip first ran the builtin flow: handshake 219 ms
(sagvd) / 220 ms (acp-compute), the job EXACT. Delegated: the session
opened at once, handshake 145 ms / 146 ms, each side's record the TSM
report with the host's certificate table inside (7980 bytes both ways),
the job EXACT, the admission on the audit log carrying the EAR —
`affirming`, `policy:SEVSNP`, `hardware: 2`, `runtime-opaque: 2`, a
64-byte nonce — which verifies again offline under the key the Verifier
published. Refused, on the record: a thief with the sealed key files off
the chip; a worker of another family, by name, before the Verifier was
asked; a daemon whose policy named another appraisal policy while the
Verifier affirmed («appraised under policy "policy:SEVSNP", this side
requires "policy:bank-2026-other"»); a daemon whose Verifier was
unreachable («the Verifier at …:8444: no session», `verifier_unavailable`),
with no session opened. The audit log verified under the published key:
two admissions, four refusals, one admission with an EAR. Both VMs, the
firewall rule and the bucket were deleted at the end.

**Evidence.**
[`scripts/hardware-test/gcp-sev-snp/returnpath-rats/evidence/20261016T033936Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-rats/evidence/20261016T033936Z/)
— `steps.txt` (every phase: `builtin session opened … sagvd_handshake_ms=219
worker_handshake_ms=220 worker_record_bytes=7980 vault_record_bytes=7980`,
`rats session opened after 0s sagvd_handshake_ms=145 worker_handshake_ms=146
…`, `gate_builtin`/`gate_rats: level=EXACT … n_exact=6`, the rogue's
reason, the policy refusal, the unreachable Verifier,
`trust_decisions: allow=2 deny=4 allow_with_ear=1`); `trust-decisions.jsonl`;
`audit-events.jsonl` and `audit-verify.json` (`ok: true`);
`sagvd-builtin.log`, `sagvd.log`, `sagvd-policy.log`, `sagvd-down.log` and
the workers' logs (`peer_verifier: rats https://vg-verifier-…:8443`,
`handshake_ms`, the refusals); `verifier-well-known.json` and
`verifier-dns.txt` as the guest saw them. `runner/`: `launch-report.bin`
(the chip's report, measurement `7dc7c12e…`), `launch-report.tsm.cbor`,
`corim.cbor`, `corim-submit.json` (`success`), `well-known.json`,
`verifier-ear.jwk`, `ear-on-record.jwt` (the EAR taken from the audit
record, re-verified under that key), the public certificates,
`firewall-rule.json`, `veraison-sources.txt`, `runner-timeline.txt`,
`metadata.txt`. `verifier/`: the Verifier host's `steps.txt` (build,
deploy, clients, stores, certificates: every exit 0), `config.yaml`
(`client-ca`), `verification-cert.txt` (SAN `vg-verifier-…`),
`verification.log` (ten sessions, callers `sagvd-…` and `worker-…`),
`vts.log`, `store.sql.dump`, `plugins.txt`, `sha256sums.txt`. The kit:
[`scripts/hardware-test/gcp-sev-snp/returnpath-rats/`](scripts/hardware-test/gcp-sev-snp/returnpath-rats/).

**Scope.** Two VMs in one VPC: the attester reaches the Verifier over
the network's internal rule, by the instance's name; a Verifier across
the internet, or behind a bank's load balancer, is the same client with
another `url` and CA. The reference value came from the chip's own
report (trust on first use, the bench's practice); the firmware
vendor's signed launch endorsement is the better source. One chip ran
both daemons, so one launch measurement served both pins. The Verifier
ran as root from a startup script for the run's duration, not hardened.
Veraison's version string is empty in its well-known document because
the tree was shipped without `.git`; `runner/veraison-sources.txt` names
the commit. Found and fixed on the way (attempt 2 of the run): sagvd's
metrics wrapper around its producer dropped the certificate table, so
Veraison saw «evidence missing certificate chain» — the wrapper forwards
`QuoteWithAux` now, with a test.

<a id="c32"></a>

### C32 — The authority serves sessions in parallel on real SEV-SNP and TDX: three workers, six jobs per round, every one EXACT — 28.7 s → 17.2 s on SEV-SNP, 23.7 s → 9.6 s on TDX — and the SEV-SNP chip's own limit found: a burst of attestation requests on one GCP guest waits about 10 s, which TDX does not

**Claim.** On one n2d-standard-8 Confidential VM, sagvd with
`runtime.max_sessions: 1` and then `3`, three acp-compute workers (the
real CPU door, contending for the cores), six jobs per round on the
same sealed genome. Round 1: 28.7 s from the first submission to the
last verdict (4.8 s per job), `sagvd_sessions_active` never above 1, the
queue up to 4 deep. Round 3: 17.2 s (2.9 s per job), three sessions
active at once, the queue up to 2 deep, no connection refused. Twelve
jobs, twelve verdicts EXACT, both rounds on one audit chain that
verifies under the published key. The handshakes: about 25 ms each once
warm, except those that met the host's rate limit on the chip's guest
requests — 10.4 s in round 1, two of 10.3 s and one of 1.5 s in round 3,
the authority's own quote histogram agreeing (one 10.2-s quote of seven;
two slow of nine) and the three workers' identity reports at startup all
answered 10.3 s after they asked. The kernel logged nothing: the
sev-guest driver retries the host's «busy» answer on its own schedule.
The TDX twin, one c3-standard-8 Trust Domain, the same rounds: 23.7 s
(3.9 s per job) at one session at a time, 9.6 s (1.6 s per job) at
three, twelve verdicts EXACT, handshakes 84–425 ms with three opening
at once at 90–165 ms, the authority's nine quotes 0.52 s together — no
throttling.

**Evidence.**
[`scripts/hardware-test/gcp-tdx/returnpath-parallel/evidence/20261016T123114Z/`](scripts/hardware-test/gcp-tdx/returnpath-parallel/evidence/20261016T123114Z/)
— the TDX twin's `steps.txt` (`round_max1: … wall_s=23.7 … handshake_ms=[425,87,84,85,85,85,87]`,
`round_max3: … wall_s=9.6 peak_sessions_active=3 … handshake_ms=[90,165,122,124,255,148,90,160,151]`),
its logs, metrics, verdicts and verified audit log, as below for SEV-SNP.
[`scripts/hardware-test/gcp-sev-snp/returnpath-parallel/evidence/20261016T122044Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-parallel/evidence/20261016T122044Z/)
— `steps.txt` (`round_max1: … wall_s=28.7 per_job_s=4.8
peak_sessions_active=1 max_queue_depth=4 refused_busy=0
handshake_ms=[10436,28,28,22,23,25,24]`, `round_max3: … wall_s=17.2
per_job_s=2.9 peak_sessions_active=3 max_queue_depth=2 refused_busy=0
handshake_ms=[49,10299,10299,1521,25,29,33,28,25]`, `exact=6` both,
`nproc.txt` 8); `sagvd-max1.log`, `sagvd-max3.log` (every `session
opened` with `handshake_ms`), `acp-compute-max{1,3}-{1,2,3}.log` (each
worker's start, identity 10.3 s later, its handshakes),
`sagvd-metrics-max{1,3}.txt` (`vg_tee_attestation_duration_seconds`
produce and verify, `sagvd_sessions_limit`, `sagvd_sessions_refused_total`
absent), `job-max{1,3}-<id>.json` (twelve verdicts), `audit-verify.json`
(`ok: true`), `audit-events.jsonl`, `timeline.txt`, `sha256sums.txt`. The
kit: [`scripts/hardware-test/gcp-sev-snp/returnpath-parallel/`](scripts/hardware-test/gcp-sev-snp/returnpath-parallel/);
the numbers: [`docs/operator/limits.md`](docs/operator/limits.md).

**Scope.** One host for the authority and the workers, so the workers'
restores share its eight cores with the authority: the per-job time at
three is the host's, not the protocol's; a fleet puts workers on their
own machines. The host's rate limit is observed, not read from a
document: its exact policy is GCP's, and whether TDX or Azure throttle
the same way is a separate measurement (the kit has a TDX twin).

<a id="c33"></a>

### C33 — One authority serves three workers for an hour on real TDX and SEV-SNP without a failure: 2429 jobs on TDX (40 a minute, every one EXACT, p99 9.3 s), 1607 on SEV-SNP (27 a minute under the chip's throttle, p99 17.7 s), 38,864 and 25,712 audit events on one verified chain each — and the authority's memory grows about 110 KB a job, which the soak found

**Claim.** On one c3-standard-8 Trust Domain, sagvd with
`runtime.max_sessions: 3`, three acp-compute workers (the real CPU door,
contending for the cores) and six jobs kept in flight on the same sealed
genome for sixty minutes: 2429 jobs, 2429 verdicts EXACT, none failed,
no connection refused, no handshake failed; 40.4 jobs a minute, the
slowest minute 38 and the fastest 42; from submission to verdict p50
8.58 s, p90 8.71 s, p99 9.26 s, max 9.41 s, of which the wait for a
session p50 4.42 s and the worker's restore and answer p50 4.15 s (p99
4.50 s); the median job of the last ten minutes 8.59 s against 8.58 s
in the first ten; 2432 handshakes p50 94 ms, p90 107 ms, p99 126 ms,
max 490 ms, none above half a second; the authority's 2432 quotes 110 s
together and their verification 4.5 s. On one n2d-standard-8 SEV-SNP
guest, the same hour: 1607 jobs, 1607 EXACT, nothing refused or failed;
26.7 a minute (24–30); p50 11.30 s, p90 17.34 s, p99 17.74 s, max
17.98 s, the restore p50 4.95 s (p99 5.21 s) and the wait for a session
p50 6.34 s, because 767 of the 1609 handshakes waited between one and
seven seconds for the host's throttle (p50 58 ms, p90 6.16 s, max
10.3 s; 2610 s of waiting in the hour), the authority's quote histogram
agreeing (909 of 1609 under 50 ms, 671 above a second). The hour's
audit log is one chain on each chip — 38,864 events on TDX, 25,712 on
SEV-SNP, sixteen a job in ten kinds — verified under the published key
at the end in 3.2 s and 2.4 s. The authority's resident memory grew
linearly on both chips, 16 → 280 MB on TDX (108 KB a job) and 17 →
205 MB on SEV-SNP (117 KB a job), while its open descriptors stayed at
13–14 and the three workers' memory at 39–51 MB: the in-memory job map
keeps every finished job's flow and the persistent audit chain keeps
every sealed event in memory (KNOWN_ISSUES #18).

**Evidence.**
[`scripts/hardware-test/gcp-tdx/returnpath-soak/evidence/20261016T130106Z/`](scripts/hardware-test/gcp-tdx/returnpath-soak/evidence/20261016T130106Z/)
and
[`scripts/hardware-test/gcp-sev-snp/returnpath-soak/evidence/20261016T130128Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-soak/evidence/20261016T130128Z/)
— `jobs.csv` (every job: its stamps from the job view, status, gate
level, queue, run and total seconds), `snapshots.csv` (every minute:
jobs done, in flight, `sagvd_sessions_active`, `sagvd_queue_depth`,
sessions opened, handshake failures, refusals, the authority's RSS and
descriptors, the workers' RSS, the load), `summary.json` (the
percentiles, rates and drifts, derived by the kit's `summarize.py` from
those two files), `steps.txt` (`soak: minutes=60 workers=3
jobs_done=2429 ok=2429 exact=2429 in_flight_at_end=0 first_error=None`;
`jobs_done=1607 ok=1607 exact=1607` on SEV-SNP; `audit verify exit=0`,
`audit_events=38864` / `25712`), `audit-kinds.txt` (the ten kinds and
their counts), `audit-verify.json` (`ok: true`, the tip),
`sagvd-soak.handshake_ms.txt` and `acp-compute-soak-{1,2,3}.handshake_ms.txt`
(every handshake), `sagvd-soak.{size,warnings,head,tail}.txt` and the
workers' (the long logs by size, warnings — none — and ends),
`sagvd-metrics-end.txt` (`vg_tee_attestation_duration_seconds`
histograms, `sagvd_gate_verdicts_total{level="EXACT"}`,
`sagvd_sessions_refused_total` absent), `ps-end.txt` (the four processes
after the hour), `timeline.txt`, `metadata.txt`, `nproc.txt` 8,
`sha256sums.txt`. The kits:
[`scripts/hardware-test/gcp-tdx/returnpath-soak/`](scripts/hardware-test/gcp-tdx/returnpath-soak/),
[`scripts/hardware-test/gcp-sev-snp/returnpath-soak/`](scripts/hardware-test/gcp-sev-snp/returnpath-soak/);
the tables: [`docs/operator/limits.md`](docs/operator/limits.md).

**Scope.** One host for the authority and the workers, one hour, one
genome, one sealed key: a rate for one host, not a fleet's. The queue
time is the submitter's doing (six in flight for three workers), so the
rate is the number to read, the latency is a job's restore plus the one
ahead of it. The memory growth is measured, not bounded: an hour at this
rate is a quarter of a gigabyte; the fix is named in KNOWN_ISSUES #18.
The throttle on SEV-SNP is the host's (KNOWN_ISSUES #17), observed again
here over an hour.

---

<a id="c34"></a>

### C34 — After the fix of what the soak found, the authority's private memory is flat over two hours of three workers on real TDX and SEV-SNP: 9–15 MB through 4901 and 3223 jobs, every one EXACT, where the first soak's rate would have put 540 MB; what still grows is the two bbolt files on disk, 48–52 KB a job

**Claim.** The same soak as C33, run for 120 minutes on the fixed code
(the finished job leaves memory once the store has its view, the audit
chain keeps its tip and its length, the session issuer forgets sessions
expired for longer than they lived — KNOWN_ISSUES #18), with the
authority's resident set read from `/proc/<pid>/status` every minute as
anonymous pages (the heap and the stacks) and file-backed pages (the
two bbolt files it maps). On one c3-standard-8 Trust Domain: 4901 jobs,
4901 EXACT, nothing refused, no handshake failed, 40.8 a minute (39–42),
p50 8.51 s and p99 8.71 s from submission to verdict, the median of the
last ten minutes 8.54 s against 8.45 s in the first ten, 4904 handshakes
p50 92 ms and max 545 ms; the authority's anonymous memory 6.5 MB at the
start, 12.2 MB at the end, never above 14.6 MB, and between 9.8 and
14.6 MB through the whole second hour; its file-backed memory 10 → 103 MB
with the audit log at 168 MB and the views at 67 MB on disk; its open
descriptors 13–14; the three workers 48–52 MB. On one n2d-standard-8
SEV-SNP guest: 3223 jobs, 3223 EXACT, nothing refused or failed, 26.8 a
minute (24–31), p50 11.50 s and p99 17.93 s, 1309 of the 3224
handshakes held between one and twenty seconds by the host's throttle
(KNOWN_ISSUES #17; 5095 s of waiting in two hours across three workers);
the authority's anonymous memory 6.0 → 11.4 MB, never above 13.8 MB,
between 9.1 and 13.8 MB through the second hour; file-backed 10 → 88 MB
with the audit log at 117 MB and the views at 50 MB. The audit log of
each run is one chain verified under the published key at the end
(78,416 events in 6.3 s; 51,568 in 5.0 s). The two-hour runs between the
first two fixes and the third are on record as well: there the anonymous
line still rose from 9 to 16 MB over 4883 jobs on TDX — about a kilobyte
a job — which is what pointed at the session issuer.

**Evidence.**
[`scripts/hardware-test/gcp-tdx/returnpath-soak/evidence/20261016T174732Z/`](scripts/hardware-test/gcp-tdx/returnpath-soak/evidence/20261016T174732Z/)
and
[`scripts/hardware-test/gcp-sev-snp/returnpath-soak/evidence/20261016T174802Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-soak/evidence/20261016T174802Z/)
(the fixed code, `versions.txt` naming commit `77cb5a34`) — `snapshots.csv`
(every minute: `sagvd_rss_kb`, `sagvd_rss_anon_kb`, `sagvd_rss_file_kb`,
`sagvd_fds`, `workers_rss_kb`, the sessions, the queue, the failures),
`summary.json` (first, max and last of each, the percentiles and rates,
derived by the kit's `summarize.py`), `db-sizes-end.txt` (the two bbolt
files), `jobs.csv`, `steps.txt` (`soak: minutes=120 workers=3
jobs_done=4901 ok=4901 exact=4901`; `jobs_done=3223 ok=3223 exact=3223`),
`audit-verify.json`, `audit-kinds.txt`, `ps-end.txt`, the handshake and
log files as in C33. The runs between the fixes:
[`scripts/hardware-test/gcp-tdx/returnpath-soak/evidence/20261016T153617Z/`](scripts/hardware-test/gcp-tdx/returnpath-soak/evidence/20261016T153617Z/)
and
[`scripts/hardware-test/gcp-sev-snp/returnpath-soak/evidence/20261016T153649Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-soak/evidence/20261016T153649Z/)
(commit `f9442a35`, before the session issuer's fix). The fixes:
`cmd/sagvd/job_queue.go`, `internal/audit/chain/persistent.go`,
`internal/audit/store/store.go`, `internal/vault/session/issuer.go`, each
with its test (a finished job leaves the queue once the store has the
view and stays when the store refuses it; the chain never loads the
whole log except for the export, a tampered log is still refused; the
issuer holds at most two lifetimes of sessions). The tables:
[`docs/operator/limits.md`](docs/operator/limits.md).

**Scope.** Two hours, one host, three workers, one genome; a longer run
is the operator's to make with the same kit (`VG_SOAK_MINUTES`). "Flat"
is the anonymous resident set within the Go collector's swing, read
every minute; it is not a heap profile. The file-backed pages are the
kernel's page cache of the two files the daemon maps and grow with the
files, which nothing rotates yet — a retention policy for the audit log
and the views is open. The SEV-SNP host's throttle is the host's, as in
C32 and C33.

---

<a id="c35"></a>
### C35 — A primary that goes dark without a word: switched off while it trains and deleted, it triggers the failover by its silence alone, and the model comes back on an attested confidential GPU across the Atlantic — in two runs, RTO 25.97 s and 26.24 s

**Claim.** The failover of [C18](#c18) with the failure that gives no
warning. The primary (GCP SEV-SNP, us-central1) wrote no compromise report
and no `stopped` heartbeat: while it trained, it switched itself off through
the kernel's sysrq trigger, and the operator then deleted it and its disk.
Under a policy the operator signed in advance whose only trigger is **no
heartbeat for 15 s**, the authority (GCP SEV-SNP, europe-west4, its escrow
key sealed to its chip) acted on 15 s of silence on its own clock, verified
the standby — an Azure NCC H100 v5 in West Europe: its SEV-SNP report, its
TPM quote against the pinned PCR digest, NVIDIA's tokens and its own
evaluation of the H100's report — released the key for the last generation
the primary sealed, and confirmed the standby's receipt: the genome
restored and gated EQUIVALENT on the H100 in confidential-computing mode.
Every step is on the audit record. Run again on 16 October 2026, on
the tree of that day (`20261016T210544Z`): the primary's last heartbeat,
#206 at 21:25:11.14Z; the power-off at 21:25:15.68Z by its own clock;
the authority's trigger at 21:25:29.18Z — detect 15.01 s, RPO 21.00 s,
release 3.13 s, restore 11.8 ms, gate 6.82 s, **RTO 26.24 s**; the gate
EQUIVALENT on the H100, 16 fixtures, `max_abs_err: 2.48e-4`; five audit
events verified, tip 16f6058b…c896. The model was confirmed back 24.74 s
after the power-off and 5.4 s before Google's audit log recorded the
guest's termination (21:25:45.80Z); Google's API showed the machine
`RUNNING` for 29 s after it had switched itself off. Generation 1 was
on the standby before the power-off this time.

**Evidence.** The second run:
[`scripts/hardware-test/failover-region-loss/evidence/20261016T210544Z/`](scripts/hardware-test/failover-region-loss/evidence/20261016T210544Z/)
— `authority/report.json` (`status: restored`; `trigger.at`
21:25:11.136Z, `alive_observed_at` 21:25:14.168Z, `observed_at`
21:25:29.178Z; `timing`: `detect_seconds` 15.01, `rpo_seconds` 21.00,
`release_seconds` 3.13, `restore_seconds` 0.0118, `gate_seconds` 6.82,
`rto_seconds` 26.24; `restore.gate.level` EQUIVALENT, `max_abs_err`
0.000248; `audit_chain_length` 5), `authority/audit-verify.json`
(`ok: true`, tip `16f6058b…c896`), `authority/xcc-audit.db` with
`audit.pem`, `authority/audit-events.jsonl` (the five events),
`authority/last-heartbeat.json` (#206), `primary/steps.txt` (*generation 2
when the power went: still training*, *sentinel running when the power
went: yes*), `operator/primary-destroyed-at.txt` (21:25:15.677Z),
`operator/operator-destroy.txt` (`RUNNING` until 21:25:44.66Z, `STOPPING`
at 21:25:47.77Z, `TERMINATED` at 21:25:57.37Z, then deleted),
`operator/gcp-audit-primary.json` (`guestTerminate` at 21:25:45.80Z),
`destination/steps.txt`, `TIMELINE.txt`. The first run:
[`scripts/hardware-test/failover-region-loss/evidence/20260930T194321Z/`](scripts/hardware-test/failover-region-loss/evidence/20260930T194321Z/)
— `authority/report.json`: `status: restored`; trigger `heartbeat-timeout`,
`at: 20:01:57.12Z` (the last heartbeat), `alive_observed_at: 20:02:02.62Z`,
`observed_at: 20:02:17.64Z`; `decision: failover … restore generation 1 on
the standby`; `release.destination_kind: azure-cgpu`,
`destination_measurement_hex: 11920f61…91c4`; `restore.gate`:
**EQUIVALENT**, 16 fixtures, `max_abs_err: 1.516e-4`, `backend_seconds:
6.75`; `timing`: detect 15.01 s, release 2.87 s, restore 9.8 ms, failover
10.96 s, **RTO 25.97 s**, **RPO 21.01 s**; `audit_chain_length: 5`.
`authority/failover-verify.txt`: triggers *no heartbeat for 15s, stopped
and not back within 60s* — no compromise trigger. `authority/last-heartbeat.json`:
heartbeat #209, `status: watching`, newest sealed generation 1, signed,
`attestation.kind: gcp-sev-snp`. `authority/xcc-audit.db` with `audit.pem`:
`acpctl audit verify` → *audit chain ok — 5 events verified, tip
3488b31c…153f*, the tip in `report.json`. `authority/audit-events.jsonl`:
the `CROSS_CLOUD_ATTESTATION_VERIFIED` event's `destination_detail` —
Genoa, PCRs `sha256:0–14`, GPU-0 `GH100` driver 595.91.07 VBIOS
96.00.9F.00.04, the driver's and VBIOS's reference manifests verified, 64
measurements each matched, revocation good. `primary/steps.txt`:
*generation 2 when the power went: still training*, *sentinel running when
the power went: yes*; `operator/primary-destroyed-at.txt`: 20:02:02.46Z.
`operator/operator-destroy.txt`: Google's status `RUNNING` → `STOPPING` →
`TERMINATED`, `lastStopTimestamp` 20:03:05.67Z, the deletion, *was not
found*, no disk left; `operator/gcp-audit-primary.json`:
`compute.instances.guestTerminate` at 20:02:55.70Z, then
`v1.compute.instances.delete`. `TIMELINE.txt`: power-off → confirmed
restore 26.14 s across clocks; the restore confirmed 27.1 s before
Google's audit log recorded the guest's termination.

**Reproduce:**

```bash
scripts/hardware-test/failover-region-loss/run.sh <gcp-project> us-central1-c vg-rl-weu   # ~25 min: two GCP n2d Milan CVMs + an Azure NCC H100 v5
python3 scripts/hardware-test/failover-region-loss/timeline.py scripts/hardware-test/failover-region-loss/evidence/<run>
```

**Scope.** Two runs, sixteen days apart, with the 0.5B model of the
failover drill. The power-off was self-inflicted, from inside the guest,
and the deletion came after it; one machine in us-central1 went dark,
not the region, and the run's bucket was placed in europe-west4 on
purpose. In the first run generation 1 reached the standby from that
bucket 15 s after the power-off, because the orchestrator's copy loop
raced the primary's uploads — 3.5 s before the key; in the second it
was on the standby before the power-off. The detect time is the policy's timeout by construction; 15 s is the
drill's choice, not a recommendation. The limits of the GPU leg stand
([C18](#c18) scope).

---

<a id="c36"></a>

### C36 — The Return Path on a real Azure SEV-SNP Confidential VM: both daemons attest as azure-sev-snp with the chip's report from the vTPM and a TPM quote, the gate job EXACT, a thief's copy of the sealed key files no key off this vTPM, a worker of another attestation refused by evidence type, the audit log verified

**Claim.** On one `Standard_DC4as_v5` in West Europe (an EPYC Genoa, the
product read from the report's CPUID family and model), `sagvd` and
`acp-compute` attested as `azure-sev-snp` (ADR 0025, plan item 4): the
HCL report of 2900 bytes read from the vTPM's NV index `0x1400001` —
there is no `/dev/sev-guest` on the guest — the launch measurement
`11920f61…91c4` pinned by each side (Azure's paravisor and firmware
measurement for the generation: the same value the NCC H100 v5 standby of
[C18](#c18) carries), the Genoa chain fetched from AMD KDS and verified
against the pinned roots, every key file sealed to the vTPM (`tpm2`: five
of the authority's, two of the worker's). The worker's handshake took
104 ms, its evidence 4515 bytes under
`application/vnd.vault-genome.azure-sev-snp-evidence`; the admitting
`TRUST_EVALUATED` record carries the product, the chip id, the reported
TCB and the quote's PCR selection and digest (`a095d0f4…b1b3` over
`sha256:0–14`, which `identity` had printed as this boot's). The gate job
came back EXACT seven seconds after submission (6 fixtures,
`max_abs_err` 0). A rogue with the worker's sealed key files and the
simulated TEE was refused before any key was read (*sealed to
azure-sev-snp, this host is simulated*); a rogue with the plaintext
copies and the simulated attestation was refused at the handshake by
evidence type (`application/vnd.vault-genome.simulated-evidence` is not
the pinned family's), on the record. Seventeen audit events on one chain,
verified under the published key. The guest script took 137 s end to end.

**Evidence.**
[`scripts/hardware-test/azure-sev-snp/returnpath-e2e/evidence/20261016T215807Z/`](scripts/hardware-test/azure-sev-snp/returnpath-e2e/evidence/20261016T215807Z/)
— `steps.txt` (`hcl nvread exit=0 bytes=2900`, `product=genoa`,
`vault_measurement=11920f61…`, `sagvd seal-keys exit=0 sealer=tpm2 …`,
`rogue with the sealed files exit=1 sealed to azure-sev-snp, this host is
simulated`, `rogue refused after 1s`, `session opened after 0s`, `job
status=succeeded after 7s`, `gate_level=EXACT … fixtures=6 n_exact=6
max_abs_err=0`, `audit verify exit=0`, `elapsed_seconds=137.2`),
`vtpm.txt` (`/dev/tpmrm0`, the NV index, no `/dev/sev-guest`),
`product.txt`, `metadata.txt` (`westeurope`, `Standard_DC4as_v5`),
`sagvd-identity.json` and `acp-compute-identity.json` (`tee_provider:
azure-sev-snp`, `tee_measurement_hex`, `sealer: tpm2`,
`vtpm.pcr_digest_hex`), `seal-keys-sagvd.json`, `seal-keys-worker.json`,
`sealed-files.txt`, `rogue-sealed-worker.log`, `rogue-worker.log`,
`sagvd.log` (`sagvd session opened` with `handshake_ms`,
`peer_evidence_type`, `peer_evidence_bytes`, `peer_product`,
`peer_pcrs`; the `handshake failed` line for the rogue), `job.json`,
`audit-verify.json` (`ok: true`, `event_count: 17`, tip `d9572ff1…a02d`),
`audit-events.jsonl` (the admitting `TRUST_EVALUATED` with
`peer_detail`), `amd-chain.txt`, `inputs.sha256`, `versions.txt`,
`sha256sums.txt`, `runner-guest.log`. The binaries were built from this
branch at the kit's commit (`c917d553` before the rebase onto main, the
same tree as `89244f2` after it; the `-dirty` mark is the changelog
being edited beside it). The kit:
[`scripts/hardware-test/azure-sev-snp/returnpath-e2e/`](scripts/hardware-test/azure-sev-snp/returnpath-e2e/);
the provider: `internal/shared/tee/azure_sev_snp.go` and
`azure_vtpm.go`; the runbook:
[`docs/operator/runbooks/real-tee-azure-sev-snp.md`](docs/operator/runbooks/real-tee-azure-sev-snp.md).
A second run on 2026-10-17 with `tee.provider: "auto"` on both daemons,
[`scripts/hardware-test/azure-sev-snp/returnpath-e2e/evidence/20261017T114254Z/`](scripts/hardware-test/azure-sev-snp/returnpath-e2e/evidence/20261017T114254Z/)
(commit `55c549e7`): `auto` found no configfs-tsm under the paravisor,
read the vTPM's HCL report and resolved `azure-sev-snp` (the daemons'
logs: `resolved_from=vtpm-hcl`; both identities `tee_provider:
azure-sev-snp`), and the run came out as the first — the same
measurement `11920f61…`, EXACT 6/6, 17 audit events verified, 136.6 s.

**Reproduce:**

```bash
az login
scripts/hardware-test/azure-sev-snp/returnpath-e2e/run.sh vg-asnp-weu westeurope   # ~15 min, one Standard_DC4as_v5
```

**Scope.** One VM carrying both daemons, so each pins the other's
measurement and the two are the same value; a fleet pins each side's
own. The report is issued at boot and its REPORT_DATA is Azure's; the
handshake's freshness is the TPM quote's, under the attestation key the
report names. The PCR digest was recorded, not pinned (`pcr_digests`
empty in this run); the boot is required and enforced in [C54](#c54). The chain came from AMD KDS, not from Azure's THIM.
A DC4as_v5 in West Europe was Genoa that day and East US Milan on
2026-09-14; the kit reads the product from the report, and a verifier
configured with the other product's chain refuses. The gate is the e2e
kits' tiny model through the pinned-replay door, as on GCP
([C31](#c31) scope); the 0.5B and 32B gates on Azure are the GPU host's
([C17](#c17), [C26](#c26)).

---

<a id="c37"></a>

### C37 — One command stands up a deployment on real SEV-SNP: `acpctl provision` makes the key material, both configurations, the identities and pins, and seals every key file to the chip in 10.6 s; the deployment it wrote serves a gate job EXACT, its audit log verified under the key it kept

**Claim.** On one n2d-standard-4 GCP Confidential VM (Milan), `acpctl
provision --provider auto --fetch-amd-chain milan …` did the
first-deployment procedure's steps 2 and 3 in 10.6 s: the release's
`acp-keygen` wrote the secrets tree; configfs-tsm said `sev_guest` and
both configurations were written for `gcp-sev-snp`; the Milan chain came
from AMD KDS and verified against the root the binary pins (ARK
`69d063b4…40bcd`); `sagvd identity` and `acp-compute identity` read the
chip's launch measurement (`7dc7c12e…5acc`) and each side pinned the
other's; the operator's copy of the REST token and the audit public key
went under `operator/`; each daemon's `seal-keys` sealed its key files to
the chip's derived key — eight in all, five of the authority's and three
of the worker's, the worker's own copy of the session sealing key among
them. The daemons then started on what it wrote: the worker's handshake
took 232 ms with 7980 bytes of evidence (the TSM report with the host's
certificate table); a genome fine-tuned on the guest and sealed into the
directory provision made came back EXACT six seconds after submission
(6 fixtures, `max_abs_err` 0); sixteen audit events on one chain verified
under `operator/audit_public_key.pem`. The guest script took 122.8 s end
to end. The command printed no secret: `provision.out` and
`provision.json` are on the record as printed.

**Evidence.**
[`scripts/hardware-test/gcp-sev-snp/provision-e2e/evidence/20261016T222951Z/`](scripts/hardware-test/gcp-sev-snp/provision-e2e/evidence/20261016T222951Z/)
— `provision.out` (what the command printed), `provision.json`
(`provider: auto`, `peer_provider: gcp-sev-snp`, the measurements, the
sealers, the sealed lists, `configs_sha256`, `amd_cert_chain`),
`sagvd-identity.json` and `acp-compute-identity.json`, `sagvd.json` and
`acp-compute.json` (paths, no secret), `sealed-files.txt` (eight files,
each `sealer: sev-snp-derived-key`), `steps.txt` (`provision exit=0`,
`vault_sealer=sev-snp-derived-key worker_sealer=sev-snp-derived-key`,
`session opened after 0s`, `job status=succeeded after 6s`,
`gate_level=EXACT … fixtures=6 n_exact=6 max_abs_err=0`, `audit verify
exit=0`, `elapsed_seconds=122.8`), `timeline.txt` (`provision_start`
22:31:12.19Z, `provision_end` 22:31:22.74Z), `sagvd.log` (`sagvd session
opened` with `handshake_ms: 232`, `peer_evidence_bytes: 7980`),
`job.json`, `audit-verify.json` (`ok: true`, `event_count: 16`, tip
`ca478e4b…0344`), `audit-events.jsonl`, `audit-public-key.pem`,
`versions.txt` (commit `44e46e69`), `sha256sums.txt`. The command:
`cmd/acpctl/provision.go`, proven in process with a stub release
(`cmd/acpctl/provision_test.go`) and live with the real binaries
(`test/integration/provision_test.go`: the daemons start on what it
wrote, a job EXACT, the audit log verified under the key it kept). The
kit: [`scripts/hardware-test/gcp-sev-snp/provision-e2e/`](scripts/hardware-test/gcp-sev-snp/provision-e2e/).

**Reproduce:**

```bash
scripts/hardware-test/gcp-sev-snp/provision-e2e/run.sh <gcp-project>   # ~15 min, one n2d-standard-4
```

**Scope.** Both daemons on one host, so each pins the other's measurement
and the two are the same value; two hosts carry the worker's subtree over
and pin the other side's identity by hand (`provision.json` carries
both). The family came from configfs-tsm (`auto`); the Azure families are
named on the command line, and `azure-cgpu` is set up by its runbook (the
GPU command and policy are not the command's). The chain came from AMD
KDS (`--fetch-amd-chain`), not from a file the operator supplied; the
sealer was the chip's derived key (`auto` on SEV-SNP), the vTPM being
`tpm2`. The gate is the e2e kits' tiny model through the pinned-replay
door, as in [C31](#c31).

---

---

## Supply chain and build

<a id="c9"></a>

### C9 — Releases are signed, reproducible and attested

**Claim.** `v0.1.0` ships four binaries with cosign keyless signatures and
certificates, SPDX SBOMs, and SLSA provenance (`multiple.intoto.jsonl`). The
release tag itself must be signed by a key pinned on the default branch, or
the workflow fails.

**Evidence.** [`.github/workflows/release.yml`](.github/workflows/release.yml)
(the `git verify-tag` gate), [`.github/allowed_signers`](.github/allowed_signers),
the [v0.1.0 release assets](https://github.com/vault-genome/vaultgenome-core/releases/tag/v0.1.0),
procedure in [`docs/operator/05_release_procedure.md`](docs/operator/05_release_procedure.md).

**Reproduce.** `make verify-reproducible` locally; `cosign verify-blob` against
the published `.sig`/`.cert`.

---

<a id="c10"></a>
### C10 — The stated CI gate is the CI gate

**Claim.** `vault-gate` runs 18 sub-checks on every PR: fmt, vet, build, unit,
race, integration, coverage, lint, terminology, govulncheck, osv-scanner,
gitleaks, sbom, license-headers, doctrine-tests, dep-allowlist, dep-depth,
verify-reproducible. Eleven of eleven doctrine invariants are asserted as
tests, so a violating change fails CI rather than being caught in review.

**Evidence.** [`.github/workflows/vault-gate.yml`](.github/workflows/vault-gate.yml),
[`test/doctrine/`](test/doctrine/), [`scripts/coverage_floors.txt`](scripts/coverage_floors.txt)
(a ratchet — floors only rise).

**Reproduce.** `make vault-gate` runs 14 of the 18 locally; the workflow badge
at the top of the README is live.

---

<a id="c27"></a>
### C27 — A signed release, downloaded and verified, deploys and attests on real SEV-SNP

**Claim.** The reference deployment is the release itself, not this tree:
the assets of a tagged release are downloaded, every signature, the SLSA
provenance and the tag's signature are verified, the binaries are rebuilt
from the tag and match the released files byte for byte, and the released
`sagvd`, `acp-compute` and `acpctl` then run the Return Path on a fresh
SEV-SNP Confidential VM — both daemons attesting with the chip, a rogue
worker refused, a gate job judged EXACT and every decision on a verified
audit log — in one command an operator can repeat.

**Evidence.**
[`scripts/hardware-test/release-deploy/evidence/20261015T012735Z/`](scripts/hardware-test/release-deploy/evidence/20261015T012735Z/)
— `v0.4.0` on an `n2d-standard-4` (Milan) in `us-central1-c`:
`verify/cosign.txt` eight "Verified OK" (four binaries, four SBOMs) against
the release workflow's identity, `verify/slsa.txt` four "PASSED: SLSA
verification passed" against the repository and the tag, `verify/tag.txt`
`Good "git" signature` with the key pinned in `.github/allowed_signers`;
`results/versions.txt` the three released binaries reporting `v0.4.0` at
the tag's commit; `results/steps.txt` and the identity files: both daemons
read the launch measurement `7dc7c12e…25acc` from the chip; `rogue-worker.log`
the simulated-TEE worker refused at the handshake; `results/job.json` gate
level EXACT, 6 of 6 fixtures, `max_abs_err` 0, state `release_authorized`,
the verdict signed; `results/audit-verify.json` `ok: true`, 17 events; the
guest script 99.1 s (`timeline.txt`). The rebuild step (§5.4 of the release
procedure) joined the kit after that run. The same kit on `v0.4.1`, three
minutes after the release was published:
[`scripts/hardware-test/release-deploy/evidence/20261015T014459Z/`](scripts/hardware-test/release-deploy/evidence/20261015T014459Z/)
— the same eight signatures, four provenances and tag verified;
`verify/rebuild.txt`: the four binaries rebuilt from the tag on another
machine (go1.27.2 on Darwin arm64, cross-compiled) with the same sha256 as
the released files; `results/versions.txt` the binaries reporting `v0.4.1`
at the tag's commit; gate EXACT 6 of 6, `release_authorized`; the audit log
verified, 17 events; 100.6 s on the guest. Those two runs still took the
key helper, the worker package and the AMD chain from the source tree.
The same kit on `v0.4.2`, three minutes after the release was published:
[`scripts/hardware-test/release-deploy/evidence/20261015T170743Z/`](scripts/hardware-test/release-deploy/evidence/20261015T170743Z/)
— the first record with **nothing from the source tree**. `verify/cosign.txt`
twelve "Verified OK" (five binaries, the worker package, their six SBOMs),
`verify/slsa.txt` six "PASSED", `verify/tag.txt` the tag's signature;
`verify/rebuild.txt` the five binaries and the package rebuilt from the tag
on another machine (go1.27.2, GNU tar 1.35, GNU gzip 1.15 on Darwin arm64)
with the same sha256 as the released files; `verify/uploaded.sha256` the
five files that went to the guest, every one a release asset (the released
`acp-keygen` as the key helper, the released package as the worker);
`results/amd-chain.txt` the Milan chain fetched on the guest by the
released `acpctl` from AMD KDS and checked against the pinned ARK-Milan
`69d063b4…a540bcd` (ADR 0024); `results/versions.txt` the four released
binaries reporting `v0.4.2` at the tag's commit; both daemons read the
launch measurement `7dc7c12e…25acc` from the chip; the rogue worker refused
at the handshake; `results/job.json` gate level EXACT, 6 of 6, `max_abs_err`
0, `release_authorized`; `results/audit-verify.json` `ok: true`, 17 events;
103.3 s on the guest (`timeline.txt`: the runtime from the locks 84 s, the
fine-tune 10 s, the job 5 s).

The same kit on `v0.4.3`, two and a half minutes after the release was
published (2026-10-16):
[`scripts/hardware-test/release-deploy/evidence/20261016T001614Z/`](scripts/hardware-test/release-deploy/evidence/20261016T001614Z/)
— the first release with a Sigstore bundle beside every signature, and the
first record in which the bundles are verified **with the network denied**:
`verify/assets.sha256` 49 assets; `verify/cosign.txt` twelve "Verified OK"
(the pairs); `verify/cosign-bundle-nonet.txt` the same twelve files from
their bundles, `cosign verify-blob --new-bundle-format --bundle
--trusted-root trusted_root.json` under `sandbox-exec` with no route and
no TUF cache, twelve "Verified OK" (the trust root, SHA-256 `6494e21e…`,
the file `cosign initialize` caches on a connected machine); `verify/slsa.txt`
six "PASSED"; `verify/tag.txt` the tag's signature; `verify/rebuild.txt`
the five binaries and the package rebuilt from the tag (commit
`a40eee694289`, go1.27.2, GNU tar 1.35, GNU gzip 1.15) with the same sha256
as the released files; `results/versions.txt` the four released binaries
reporting `v0.4.3` at the tag's commit; `results/amd-chain.txt` the Milan
chain fetched on the guest by the released `acpctl` and checked against
the pinned ARK-Milan; both daemons, `tee.provider: "auto"`, read
`7dc7c12e…25acc` from the chip and sealed their key files to it
(`results/sealed-files.txt`); `results/rogue-sealed-worker.log` the thief
with the sealed files refused before any key is read,
`results/rogue-worker.log` the unpinned worker refused at the handshake;
`results/job.json` gate level EXACT, 6 of 6, `max_abs_err` 0,
`release_authorized`; `results/audit-verify.json` `ok: true`, 17 events;
124.7 s on the guest (the runtime from the locks 75 s, the fine-tune 9 s,
the job 5 s).

The same kit on `v0.5.0`, two minutes after the release was published
(2026-10-16, 23:19:39Z):
[`scripts/hardware-test/release-deploy/evidence/20261016T232117Z/`](scripts/hardware-test/release-deploy/evidence/20261016T232117Z/)
— `verify/assets.sha256` 49 assets; `verify/cosign.txt` twelve "Verified
OK" (the pairs); `verify/cosign-bundle-nonet.txt` the same twelve files
from their bundles with `--trusted-root trusted_root.json` under
`sandbox-exec` with no route, twelve "Verified OK" (the trust root
`6494e21e…bc0b66`, the same file as for `v0.4.3`); `verify/slsa.txt` six
"PASSED"; `verify/tag.txt` the tag's signature under the pinned key;
`verify/rebuild.txt` the five binaries and the package rebuilt from the
tag (commit `bd8f16633b9d`, go1.27.2, GNU tar 1.35, GNU gzip 1.15) with
the same sha256 as the released files (`sagvd` `4de7ad49…`,
`acp-compute` `ed125fd1…`, `acpctl` `445a5187…`, `acp-bootstrap`
`a61d844f…`, `acp-keygen` `9e4c4ae0…`, the package `2f338431…`);
`results/versions.txt` the four released binaries reporting `v0.5.0` at
the tag's commit; `results/amd-chain.txt` the Milan chain fetched on the
guest by the released `acpctl` and checked against the pinned ARK-Milan;
both daemons, `tee.provider: "auto"`, read `7dc7c12e…25acc` from the chip
and sealed their key files to it (`results/sealed-files.txt`);
`results/rogue-sealed-worker.log` the thief with the sealed files refused
before any key is read, `results/rogue-worker.log` the unpinned worker
refused at the handshake; `results/job.json` gate level EXACT, 6 of 6,
`max_abs_err` 0, `release_authorized`; `results/audit-verify.json` `ok:
true`, 17 events; 127.5 s on the guest (the runtime from the locks 77 s,
the fine-tune 9 s, the job 5 s).

The same kit on `v0.6.0`, two and a half minutes after the release was
published (2026-10-17, 04:12:43Z):
[`scripts/hardware-test/release-deploy/evidence/20261017T041506Z/`](scripts/hardware-test/release-deploy/evidence/20261017T041506Z/)
— `verify/assets.sha256` 49 assets; `verify/cosign.txt` twelve "Verified
OK" (the pairs); `verify/cosign-bundle-nonet.txt` the same twelve files
from their bundles with `--trusted-root trusted_root.json` under
`sandbox-exec` with no route, twelve "Verified OK" (the trust root
`6494e21e…bc0b66`, the same file as for `v0.5.0` and `v0.4.3`);
`verify/slsa.txt` six "PASSED"; `verify/tag.txt` the tag's signature under
the pinned key; `verify/rebuild.txt` the five binaries and the package
rebuilt from the tag (commit `cc8b204d7ba3`, go1.27.2, GNU tar 1.35, GNU
gzip 1.15) with the same sha256 as the released files (`sagvd`
`0e07cc48…`, `acp-compute` `772c062f…`, `acpctl` `360c4c6e…`,
`acp-bootstrap` `78c7d8bc…`, `acp-keygen` `8c40d22e…`, the package
`19fed8f8…`); `results/versions.txt` the four released binaries reporting
`v0.6.0` at the tag's commit; `results/amd-chain.txt` the Milan chain
fetched on the guest by the released `acpctl` and checked against the
pinned ARK-Milan; both daemons, `tee.provider: "auto"`, read
`7dc7c12e…25acc` from the chip and sealed their key files to it
(`results/sealed-files.txt`); `results/rogue-sealed-worker.log` the thief
with the sealed files refused before any key is read,
`results/rogue-worker.log` the unpinned worker refused at the handshake;
`results/job.json` gate level EXACT, 6 of 6, `max_abs_err` 0,
`release_authorized`; `results/audit-verify.json` `ok: true`, 17 events;
120.7 s on the guest (the runtime from the locks 72 s, the fine-tune 8 s,
the job 4 s).

The same kit on `v0.6.1`, six minutes after the release was published
(2026-10-21, 13:21:28Z):
[`scripts/hardware-test/release-deploy/evidence/20261021T132732Z/`](scripts/hardware-test/release-deploy/evidence/20261021T132732Z/)
— `verify/assets.sha256` 55 assets (the six of the images job among
them); `verify/cosign.txt` twelve "Verified OK" (the pairs);
`verify/cosign-bundle-nonet.txt` the same twelve from their bundles with
`--trusted-root trusted_root.json` under `sandbox-exec` with no route,
twelve "Verified OK" (the trust root `6494e21e…bc0b66`, the same file as
for `v0.6.0`); `verify/slsa.txt` six "PASSED"; `verify/tag.txt` the tag's
signature under the pinned key; `verify/rebuild.txt` the five binaries
and the package rebuilt from the tag (commit `3250f2717bc0`, go1.27.3,
GNU tar 1.35, GNU gzip 1.15) with the same sha256 as the released files
(`sagvd` `6291f59e…`, `acp-compute` `a418fdfe…`, `acpctl` `8ed5f5e5…`,
`acp-bootstrap` `fbec80a1…`, `acp-keygen` `80b356e4…`, the package
`301e382f…`); `results/versions.txt` the four released binaries reporting
`v0.6.1` at the tag's commit; `results/amd-chain.txt` the Milan chain
fetched on the guest by the released `acpctl` and checked against the
pinned ARK-Milan; both daemons read `7dc7c12e…25acc` from the chip and
sealed their key files to it (`results/sealed-files.txt`);
`results/rogue-sealed-worker.log` the thief with the sealed files refused
before any key is read, `results/rogue-worker.log` the unpinned worker
refused at the handshake; `results/job.json` gate level EXACT, 6 of 6,
`max_abs_err` 0, `release_authorized`; `results/audit-verify.json` `ok:
true`, 17 events; 128.4 s on the guest (the runtime from the locks 76 s,
the fine-tune 9 s, the job 5 s). The same release's two container
images, deployed by `scripts/hardware-test/release-deploy-images` in the
same minutes:
[`scripts/hardware-test/release-deploy-images/evidence/20261021T132958Z/`](scripts/hardware-test/release-deploy-images/evidence/20261021T132958Z/)
— each image verified by digest on the runner (signature, SBOM
attestation, SLSA provenance, the binary inside equal to the release
asset), loaded on the guest from tarballs whose hashes the guest
re-computed, each loaded image's `RootFS.Layers` equal to the signed
config's `diff_ids`; both daemons from their images, the key files sealed,
the rogue refused, gate level EXACT, the audit log verified; 178.3 s.

The same kit on `v0.7.0`, ten minutes after the release was published
(2026-10-21, 16:37:55Z):
[`scripts/hardware-test/release-deploy/evidence/20261021T164732Z/`](scripts/hardware-test/release-deploy/evidence/20261021T164732Z/)
— `verify/assets.sha256` 55 assets; `verify/cosign.txt` twelve "Verified
OK" (the pairs); `verify/cosign-bundle-nonet.txt` the same twelve from
their bundles with `--trusted-root trusted_root.json` under
`sandbox-exec` with no route, twelve "Verified OK" (the trust root
`6494e21e…bc0b66`, the same file as for `v0.6.1`); `verify/slsa.txt` six
"PASSED"; `verify/tag.txt` the tag's signature under the pinned key;
`verify/rebuild.txt` the five binaries and the package rebuilt from the
tag (commit `28fa01506f43`, go1.27.3, GNU tar 1.35, GNU gzip 1.15) with
the same sha256 as the released files (`sagvd` `fc11d465…`,
`acp-compute` `367d4b15…`, `acpctl` `e8d1543d…`, `acp-bootstrap`
`2cd7480f…`, `acp-keygen` `fb6f94b9…`, the package `f4c314b1…`);
`results/versions.txt` the four released binaries reporting `v0.7.0` at
the tag's commit; `results/amd-chain.txt` the Milan chain fetched on the
guest by the released `acpctl` and checked against the pinned ARK-Milan;
both daemons read `7dc7c12e…25acc` from the chip and sealed their key
files to it (`results/sealed-files.txt`);
`results/rogue-sealed-worker.log` the thief with the sealed files
refused before any key is read, `results/rogue-worker.log` the unpinned
worker refused at the handshake; `results/job.json` gate level EXACT, 6
of 6, `max_abs_err` 0, `release_authorized`; `results/audit-verify.json`
`ok: true`, 18 events (the 18th a handshake that failed as sagvd
stopped, on the record as a refusal; the record's README names it);
133.2 s on the guest (the runtime from the locks 83 s, the fine-tune
10 s, the job 5 s). The same release's two container
images, deployed by `scripts/hardware-test/release-deploy-images` in the
same minutes:
[`scripts/hardware-test/release-deploy-images/evidence/20261021T164959Z/`](scripts/hardware-test/release-deploy-images/evidence/20261021T164959Z/)
— each image verified by digest on the runner (signature, SBOM
attestation, SLSA provenance, the binary inside equal to the release
asset), both publicly readable, loaded on the guest from tarballs whose
hashes the guest re-computed, each loaded image's `RootFS.Layers` equal
to the signed config's `diff_ids` (13 layers for `sagvd`, 9 for
`acp-compute`); both daemons from their images, the key files sealed,
the rogue refused, gate level EXACT, the audit log verified (17 events);
211.0 s. And the binaries of the tag's commit under the `fips` profile,
by the key-release kit in the same minutes:
[`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T164918Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T164918Z/)
— a key released across clouds under `hpke-p384-v1`, the restore
confirmed by the chip receipt, the unlisted guest and the operator stop
refused, the audit log verified (10 events) — C40 on the released
commit. The same kit on `v0.8.0`, eight minutes after the release was published
(2026-10-21, 23:24:52Z):
[`scripts/hardware-test/release-deploy/evidence/20261021T233121Z/`](scripts/hardware-test/release-deploy/evidence/20261021T233121Z/)
— `verify/assets.sha256` 97 assets (the five `-fips` variants' 40 and
the images job's 8 among them); `verify/cosign.txt` twenty-two "Verified
OK" (the pairs); `verify/cosign-bundle-nonet.txt` the same twenty-two
from their bundles with `--trusted-root trusted_root.json` under
`sandbox-exec` with no route; `verify/slsa.txt` eleven "PASSED";
`verify/tag.txt` the tag's signature under the pinned key;
`verify/rebuild.txt` the ten binaries and the package rebuilt from the
tag (commit `20dc289f092c`, go1.27.3, GNU tar 1.35, GNU gzip 1.15, on
Darwin arm64) with the same sha256 as the released files (`sagvd`
`ea231f03…`, `sagvd-fips` `9a25e112…`, `acp-compute` `7537fe16…`,
`acp-compute-fips` `b3acc700…`, `acpctl` `56afe915…`, `acpctl-fips`
`9c56064d…`, `acp-bootstrap` `557f4e0a…`, `acp-bootstrap-fips`
`c001da77…`, `acp-keygen` `6006a14d…`, `acp-keygen-fips` `4c861e17…`);
`results/versions.txt` the released binaries reporting `v0.8.0` at the
tag's commit; both daemons read `7dc7c12e…25acc` from the chip and sealed
their key files to it; the thief with the sealed files and the unpinned
worker refused; `results/job.json` gate level EXACT, 6 of 6,
`max_abs_err` 0, `release_authorized`; `results/audit-verify.json`
`ok: true`, 17 events; 453.1 s on the guest (three kits sharing the
project's quota in the same minutes). The same release's four container images, deployed by
`scripts/hardware-test/release-deploy-images` twenty-nine minutes
after it was published:
[`scripts/hardware-test/release-deploy-images/evidence/20261021T235410Z/`](scripts/hardware-test/release-deploy-images/evidence/20261021T235410Z/)
— each image verified by digest on the runner (signature, SBOM
attestation, SLSA provenance, the binary inside equal to its release
asset — the `-fips` images to the `-fips` assets), all four publicly
readable, the two default images loaded on the guest from tarballs
whose hashes the guest re-computed, each loaded image's `RootFS.Layers`
equal to the signed config's `diff_ids` (13 layers for the `sagvd`
images, 9 for the workers); both daemons from their images, the key
files sealed, both rogues refused, gate level EXACT, the audit log
verified (17 events); 182.5 s. And the released
commit under `fips` with `VG_FIPS=1` — the binaries built from a clean
checkout of the tag on the certified module, every Go process on the
guest under `fips140=only` — by the key-release kit twenty minutes after
the release was published:
[`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T234401Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T234401Z/)
— `versions.txt`: `sagvd v0.8.0 (commit 20dc289f092c) fips140=only
module=v1.0.0 enforced=true`; a key released across clouds under
`hpke-p384-v2`, the restore confirmed by the chip receipt, the unlisted
guest and the operator stop refused, the audit log verified (10 events)
— C42 on the released commit. The same three kits on `v0.9.0`
(2026-10-22, published 15:38:17Z). The release itself, eight minutes
after:
[`scripts/hardware-test/release-deploy/evidence/20261022T154611Z/`](scripts/hardware-test/release-deploy/evidence/20261022T154611Z/)
— `verify/assets.sha256` 97 assets; `verify/cosign.txt` twenty-two
"Verified OK" (the pairs); `verify/cosign-bundle-nonet.txt` the same
twenty-two from their bundles with `--trusted-root trusted_root.json`
and no route; `verify/slsa.txt` the eleven artifacts' provenance
verified; `verify/tag.txt` the tag's signature under the pinned key;
`verify/rebuild.txt` the ten binaries and the package rebuilt from the
tag (commit `0428a5a634e4`, go1.27.3, GNU tar 1.35, GNU gzip 1.15, on
Darwin arm64) with the same sha256 as the released files (`sagvd`
`35abeda8…`, `sagvd-fips` `d1ed4805…`, `acp-compute` `2c1ed7d4…`,
`acp-compute-fips` `34bcc8be…`, `acpctl` `87e61135…`, `acpctl-fips`
`fb30a7c8…`, `acp-bootstrap` `89af3676…`, `acp-bootstrap-fips`
`9bc358ae…`, `acp-keygen` `4bc0d2a2…`, `acp-keygen-fips` `b33a641e…`,
the package `44955f44…`); `results/versions.txt` the released binaries
reporting `v0.9.0` at the tag's commit; both daemons read
`7dc7c12e…25acc` from the chip and sealed their key files to it; the
thief with the sealed files and the unpinned worker refused;
`results/job.json` gate level EXACT, 6 of 6, `max_abs_err` 0,
`release_authorized`; `results/audit-verify.json` `ok: true`, 17
events; 287.8 s on the guest. The four container images, twelve
minutes after:
[`scripts/hardware-test/release-deploy-images/evidence/20261022T155049Z/`](scripts/hardware-test/release-deploy-images/evidence/20261022T155049Z/)
— `sagvd@sha256:4222a3fb…`, `acp-compute@sha256:8e74b2b9…`,
`sagvd-fips@sha256:01b45872…`, `acp-compute-fips@sha256:2a876975…`,
all four publicly readable; each verified by digest on the runner
(signature, SBOM attestation, SLSA provenance, the binary inside equal
to its release asset: `35abeda8…`, `2c1ed7d4…`, `d1ed4805…`,
`34bcc8be…`); each loaded image's `RootFS.Layers` equal to the signed
config's `diff_ids` (13 layers for the `sagvd` images, 9 for the
workers); both daemons from their images, the key files sealed, both
rogues refused, gate level EXACT, the audit log verified (17 events);
185.9 s. And the released commit under `fips` with `VG_FIPS=1` and
`VG_SIGSUITE=ecdsa-p384-sha384` — the deployment a bank held to X9
runs, on the released commit, on the certified module with enforcement
on — by the key-release kit eighteen minutes after:
[`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261022T155613Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261022T155613Z/)
— `versions.txt`: `sagvd v0.9.0 (commit 0428a5a634e4) fips140=only
module=v1.0.0 enforced=true`, the same for `acp-bootstrap`; `build.txt`
every binary `GOFIPS140=v1.0.0-c2097c7c` at that commit; the authority
signing under `ecdsa-p384-sha384` and accepting `ed25519` and
`ecdsa-p384-sha384` (`steps.txt`); a key released across clouds under
`hpke-p384-v2` (recipient key `9a746824…`), the restore confirmed by
the chip receipt, `genome verify` ok, the unlisted guest and the
operator stop refused, `acpctl audit verify` at exit 0 reporting
`signature_suite` `ecdsa-p384-sha384` over 10 events — C42 and C43 on
the released commit. The same three kits on `v0.10.0` (2026-10-23,
published 20:10:58Z). The release itself, 8 minutes after:
[`scripts/hardware-test/release-deploy/evidence/20261023T201852Z/`](scripts/hardware-test/release-deploy/evidence/20261023T201852Z/)
— `verify/assets.sha256` 97 assets; `verify/cosign.txt` twenty-two
"Verified OK" (the pairs); `verify/cosign-bundle-nonet.txt` the same
twenty-two from their bundles with `--trusted-root trusted_root.json`
and no route; `verify/slsa.txt` the eleven artifacts' provenance
verified; `verify/tag.txt` the tag's signature under the pinned key;
`verify/rebuild.txt` the ten binaries and the package rebuilt from the
tag (commit `84cc9b91e590`, go1.27.3, GNU tar 1.35, GNU gzip 1.15, on
Darwin arm64) with the same sha256 as the released files (`sagvd`
`06a958c9…`, `sagvd-fips` `e6082a5f…`, `acp-compute` `dfe31f44…`,
`acp-compute-fips` `3bdc6cff…`, `acpctl` `fe6572d4…`, `acpctl-fips`
`f25cb2fc…`, `acp-bootstrap` `729e5f33…`, `acp-bootstrap-fips`
`d70616bd…`, `acp-keygen` `2281c716…`, `acp-keygen-fips` `123f66d9…`,
the package `d3fbea15…`); `results/versions.txt` the released binaries
reporting `v0.10.0` at the tag's commit; both daemons read
`9fc6d42b…8b8cf` from the chip and sealed their key files to it; the
thief with the sealed files and the unpinned worker refused;
`results/job.json` gate level EXACT, 6 of 6, `max_abs_err` 0,
`release_authorized`; `results/audit-verify.json` `ok: true`, 17
events; 177.6 s on the guest. The four container images, 16
minutes after:
[`scripts/hardware-test/release-deploy-images/evidence/20261023T202952Z/`](scripts/hardware-test/release-deploy-images/evidence/20261023T202952Z/)
— `sagvd@sha256:3b1be7a5…`, `acp-compute@sha256:26eb2c8c…`,
`sagvd-fips@sha256:8ffc8005…`, `acp-compute-fips@sha256:a4eaccde…`,
all four publicly readable; each verified by digest on the runner
(signature, SBOM attestation, SLSA provenance, the binary inside equal
to its release asset: `06a958c9…`, `dfe31f44…`, `e6082a5f…`,
`3bdc6cff…`); each loaded image's `RootFS.Layers` equal to the signed
config's `diff_ids` (13 layers for the `sagvd` images, 9 for the
workers); both daemons from their images, the key files sealed, both
rogues refused, gate level EXACT, the audit log verified (17 events);
187.1 s. And the released commit under `fips` with `VG_FIPS=1` and
`VG_SIGSUITE=ecdsa-p384-sha384`, on the certified module with
enforcement on, by the key-release kit 17 minutes after:
[`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261023T202813Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261023T202813Z/)
— `versions.txt`: `sagvd v0.10.0 (commit 84cc9b91e590) fips140=only
module=v1.0.0 enforced=true`, the same for `acp-bootstrap`; `build.txt`
every binary `GOFIPS140=v1.0.0-c2097c7c` at that commit; the authority
signing under `ecdsa-p384-sha384` and accepting `ed25519` and
`ecdsa-p384-sha384` (`steps.txt`); a key released across clouds under
`hpke-p384-v2` (recipient key `3b09c391…`), the restore confirmed by
the chip receipt, `genome verify` ok, the unlisted guest, the operator
stop and the TCB floor one above the chip refused, `acpctl audit
verify` at exit 0 reporting `signature_suite` `ecdsa-p384-sha384` over
12 events — C42 and C43 on the released commit. The same three kits on
`v0.11.0` (2026-10-24, published 18:50:28Z). The release itself, 6
minutes after:
[`scripts/hardware-test/release-deploy/evidence/20261024T185656Z/`](scripts/hardware-test/release-deploy/evidence/20261024T185656Z/)
— `verify/assets.sha256` 97 assets; `verify/cosign.txt` twenty-two
"Verified OK" (the pairs); `verify/cosign-bundle-nonet.txt` the same
twenty-two from their bundles with `--trusted-root trusted_root.json`
and no route; `verify/slsa.txt` the eleven artifacts' provenance
verified; `verify/tag.txt` the tag's signature under the pinned key;
`verify/rebuild.txt` the ten binaries and the package rebuilt from the
tag (commit `162835d51bd3`, go1.27.3, GNU tar 1.35, GNU gzip 1.15, on
Darwin arm64) with the same sha256 as the released files (`sagvd`
`b982b6f5…`, `sagvd-fips` `187bbad2…`, `acp-compute` `5cb0e6c1…`,
`acp-compute-fips` `3e508a6e…`, `acpctl` `529e0928…`, `acpctl-fips`
`2602b0e6…`, `acp-bootstrap` `ee8d3f95…`, `acp-bootstrap-fips`
`95eb3570…`, `acp-keygen` `01386234…`, `acp-keygen-fips` `1f853c19…`,
the package `2ab1024d…`); `results/versions.txt` the released binaries
reporting `v0.11.0` at the tag's commit; both daemons read
`9fc6d42b…8b8cf` from the chip and sealed their key files to it; the
thief with the sealed files and the unpinned worker refused;
`results/job.json` gate level EXACT, 6 of 6, `max_abs_err` 0,
`release_authorized`; `results/audit-verify.json` `ok: true`, 17
events; 124.2 s on the guest. The four container images, 10 minutes
after:
[`scripts/hardware-test/release-deploy-images/evidence/20261024T190054Z/`](scripts/hardware-test/release-deploy-images/evidence/20261024T190054Z/)
— `sagvd@sha256:f7359123…`, `acp-compute@sha256:c7acc30b…`,
`sagvd-fips@sha256:3feaf316…`, `acp-compute-fips@sha256:dbbedc2d…`, all
four publicly readable; each verified by digest on the runner
(signature, SBOM attestation, SLSA provenance, the binary inside equal
to its release asset: `b982b6f5…`, `5cb0e6c1…`, `187bbad2…`,
`3e508a6e…`); each loaded image's `RootFS.Layers` equal to the signed
config's `diff_ids` (13 layers for the `sagvd` images, 9 for the
workers); both daemons from their images, the key files sealed, both
rogues refused, gate level EXACT, the audit log verified (17 events);
180.5 s. And the released commit under `fips` with `VG_FIPS=1` and
`VG_SIGSUITE=ecdsa-p384-sha384`, on the certified module with
enforcement on, by the key-release kit 7 minutes after:
[`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261024T185758Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261024T185758Z/)
— `versions.txt`: `sagvd v0.11.0 (commit 162835d51bd3) fips140=only
module=v1.0.0 enforced=true`, the same for `acp-bootstrap`; `build.txt`
every binary `GOFIPS140=v1.0.0-c2097c7c` at that commit; the authority
signing under `ecdsa-p384-sha384` and accepting `ed25519` and
`ecdsa-p384-sha384` (`steps.txt`); a key released across clouds under
`hpke-p384-v2` (recipient key `38da8f28…`), the restore confirmed by
the chip receipt, `genome verify` ok, the unlisted guest, the operator
stop and the TCB floor one above the chip refused, `acpctl audit
verify` at exit 0 reporting `signature_suite` `ecdsa-p384-sha384` over
12 events — C42 and C43 on the released commit. The same three kits on
`v0.12.0` (2026-10-28, published 02:39:57Z), the first release with the
tools for the other platforms, the Python distribution and the signed
checksums list. The release itself, 9 minutes after:
[`scripts/hardware-test/release-deploy/evidence/20261028T024858Z/`](scripts/hardware-test/release-deploy/evidence/20261028T024858Z/)
— `verify/assets.sha256` 197 assets; `verify/checksums.txt` the signed
list, verified like any other asset, then `sha256sum -c` over the
download: 23 of 23 artifacts; `verify/cosign.txt` forty-seven "Verified
OK" (the pairs); `verify/cosign-bundle-nonet.txt` the same forty-seven
from their bundles with `--trusted-root trusted_root.json` and no route;
`verify/slsa.txt` the twenty-four artifacts' provenance verified;
`verify/tag.txt` the tag's signature under the pinned key;
`verify/rebuild.txt` the twenty binaries, the package, the wheel and the
sdist rebuilt from the tag (commit `ed9f6d35fa23`, go1.27.3, GNU tar
1.35, GNU gzip 1.15 and Python 3.12.2 on Darwin arm64 — each cross build
for its own platform, the distribution by
`scripts/build_python_dist.sh`) with the same sha256 as the released
files (`sagvd` `c34b2f94…`, `sagvd-fips` `feeeb663…`, `acp-compute`
`0b0b7bb0…`, `acp-compute-fips` `79f473f6…`, `acpctl` `4ff10b5b…`,
`acpctl-fips` `25be131b…`, `acp-bootstrap` `24f5deac…`,
`acp-bootstrap-fips` `4ca75f5d…`, `acp-keygen` `8352a8f6…`,
`acp-keygen-fips` `6bfb744b…`; `acpctl` for `linux-arm64` `5013a582…`,
`darwin-amd64` `e4c91441…`, `darwin-arm64` `fbf5eb0a…`,
`windows-amd64` `f4a92d05…`, `windows-arm64` `4791df57…`; `acp-keygen`
for the same five `6bb2831a…`, `816c37ec…`, `3aff7058…`, `90f89183…`,
`5a2acb4d…`; the package `7e8acc32…`, the wheel `a07766e5…`, the sdist
`715acd5d…`); `results/versions.txt` the released binaries reporting
`v0.12.0` at the tag's commit; both daemons read `9fc6d42b…8b8cf` from
the chip and sealed their key files to it; the thief with the sealed
files and the unpinned worker refused; `results/job.json` gate level
EXACT, 6 of 6, `max_abs_err` 0, `release_authorized`;
`results/audit-verify.json` `ok: true`, 17 events; 127.8 s on the
guest. The four container images, 14 minutes after:
[`scripts/hardware-test/release-deploy-images/evidence/20261028T025338Z/`](scripts/hardware-test/release-deploy-images/evidence/20261028T025338Z/)
— `sagvd@sha256:72d74d0b…`, `acp-compute@sha256:03eff4c0…`,
`sagvd-fips@sha256:bf33ef13…`, `acp-compute-fips@sha256:8d46b0b9…`, all
four publicly readable; each verified by digest on the runner
(signature, SBOM attestation, SLSA provenance, the binary inside equal
to its release asset: `c34b2f94…`, `0b0b7bb0…`, `feeeb663…`,
`79f473f6…`); each loaded image's `RootFS.Layers` equal to the signed
config's `diff_ids` (13 layers for the `sagvd` images, 9 for the
workers); both daemons from their images, the key files sealed, both
rogues refused, gate level EXACT, the audit log verified (17 events);
183.1 s. And the released commit under `fips` with `VG_FIPS=1` and
`VG_SIGSUITE=ecdsa-p384-sha384`, on the certified module with
enforcement on, by the key-release kit 26 minutes after:
[`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261028T030604Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261028T030604Z/)
— `versions.txt`: `sagvd v0.12.0 (commit ed9f6d35fa23…) fips140=only
module=v1.0.0 enforced=true`, the same for `acp-bootstrap`; `build.txt`
every binary `GOFIPS140=v1.0.0-c2097c7c` at that commit; the authority
signing under `ecdsa-p384-sha384` and accepting `ed25519` and
`ecdsa-p384-sha384` (`steps.txt`); a key released across clouds under
`hpke-p384-v2` (recipient key `4c1718fd…`), the restore confirmed by
the chip receipt, `genome verify` ok, the unlisted guest, the operator
stop and the TCB floor one above the chip refused, `acpctl audit
verify` at exit 0 reporting `signature_suite` `ecdsa-p384-sha384` over
12 events — C42 and C43 on the released commit. The release-deploy and images kits on
`v0.13.0` (2026-10-28, published 21:37:32Z; the release with the one-button
deployment and the Azure families' quote and seal selection without PCR
10, rehearsed as `v0.13.0-rc1`, §4.1 of the release procedure). The release
itself, 9 minutes after:
[`scripts/hardware-test/release-deploy/evidence/20261028T214656Z/`](scripts/hardware-test/release-deploy/evidence/20261028T214656Z/)
— `verify/assets.sha256` 197 assets; `verify/checksums.txt` the signed
list verified, then `sha256sum -c` over the download: 23 of 23
artifacts; `verify/cosign.txt` forty-seven "Verified OK";
`verify/cosign-bundle-nonet.txt` the same forty-seven from their
bundles with `--trusted-root` and no route; `verify/slsa.txt` the
twenty-four artifacts' provenance verified; `verify/tag.txt` the tag's
signature under the pinned key; `verify/rebuild.txt` the twenty
binaries, the package, the wheel and the sdist rebuilt from the tag
(commit `22e4439119d5`, go1.27.3, GNU tar 1.35, GNU gzip 1.15 and Python
3.12.2 on Darwin arm64) with the same sha256 as the released files
(`sagvd` `f20619f7…`, `sagvd-fips` `cec890e2…`, `acp-compute`
`349f2719…`, `acp-compute-fips` `8de3e85b…`, `acpctl` `c63e68cf…`,
`acpctl-fips` `37537e59…`, `acp-bootstrap` `96a71b6e…`,
`acp-bootstrap-fips` `f0a01498…`, `acp-keygen` `0f6a07a0…`,
`acp-keygen-fips` `2ea00556…`; `acpctl` for `linux-arm64` `610ed104…`,
`darwin-amd64` `3f607562…`, `darwin-arm64` `c67b7f0a…`, `windows-amd64`
`cd973057…`, `windows-arm64` `17511c11…`; `acp-keygen` for the same five
`03e5edb9…`, `2b219d85…`, `03d8f7a3…`, `db6bb244…`, `8a4d2c5a…`; the
wheel `9e02d0ec…`, the sdist `3937c7b9…`); `results/versions.txt` the
released binaries reporting `v0.13.0` at the tag's commit; both daemons
read `9fc6d42b…8b8cf` from the chip and sealed their key files to it;
the thief with the sealed files and the unpinned worker refused;
`results/job.json` gate level EXACT, 6 of 6, `max_abs_err` 0;
`results/audit-verify.json` `ok: true`, 17 events; 121.5 s on the
guest. The four container images, 18 minutes after:
[`scripts/hardware-test/release-deploy-images/evidence/20261028T215842Z/`](scripts/hardware-test/release-deploy-images/evidence/20261028T215842Z/)
— `sagvd@sha256:d1096286…`, `acp-compute@sha256:a5836e2e…`,
`sagvd-fips@sha256:6c1b4b64…`, `acp-compute-fips@sha256:5f969cf9…`, all
four publicly readable; each verified by digest on the runner
(signature, SBOM attestation, SLSA provenance, the binary inside equal
to its release asset: `f20619f7…`, `349f2719…`, `cec890e2…`,
`8de3e85b…`); each loaded image's `RootFS.Layers` equal to the signed
config's `diff_ids` (13 layers for the `sagvd` images, 9 for the
workers); both daemons from their images, the key files sealed, both
rogues refused, gate level EXACT, the audit log verified (17 events);
295.0 s. And the button on the release (§5.9 of the procedure), within the
hour: `scripts/hardware-test/gcp-deploy/evidence/20261028T214656Z/`
on SEV-SNP — 267 s from the command to `PROVEN`, the reset and the
services back in 86 s, a second job EXACT, one chain of 32 events — and
`scripts/hardware-test/gcp-deploy/evidence/20261028T215508Z/` on TDX —
263 s to `PROVEN` with the settled-boot reboot, back in 58 s after the
reset with the vTPM opening the key files again, a second job EXACT, 32
events ([C55](#c55), [C56](#c56) on the release). And the released commit under `fips` with `VG_FIPS=1` and
`VG_SIGSUITE=ecdsa-p384-sha384`, on the certified module with
enforcement on, by the key-release kit 30 minutes after:
[`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261028T220713Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261028T220713Z/)
— `versions.txt`: `sagvd v0.13.0 (commit 22e4439119d5) fips140=only
module=v1.0.0 enforced=true`, the same for `acp-bootstrap`; `build.txt`
every binary `GOFIPS140=v1.0.0-c2097c7c` at that commit; a key released
across clouds under `hpke-p384-v2` (recipient key `fa7ff4d0…`), the
restore confirmed by the chip receipt, the unlisted guest, the operator stop and the TCB floor one above the chip refused, `acpctl audit verify` at exit 0
reporting `signature_suite` `ecdsa-p384-sha384` over 12 events — C42
and C43 on the released commit. The release-deploy and images kits on
`v0.14.0` (2026-10-29, published 21:08:27Z; the release with the fourth
cloud's family and the fourth button, rehearsed as `v0.14.0-rc1`, §4.1 of
the release procedure). The release itself, 9 minutes after:
[`scripts/hardware-test/release-deploy/evidence/20261029T211713Z/`](scripts/hardware-test/release-deploy/evidence/20261029T211713Z/)
— `verify/assets.sha256` 197 assets; `verify/checksums.txt` the signed
list verified, then `sha256sum -c` over the download: 23 of 23
artifacts; `verify/cosign.txt` forty-seven "Verified OK";
`verify/cosign-bundle-nonet.txt` the same forty-seven from their
bundles with `--trusted-root` and no route; `verify/slsa.txt` the
twenty-four artifacts' provenance verified; `verify/tag.txt` the tag's
signature under the pinned key; `verify/rebuild.txt` the twenty
binaries, the package, the wheel and the sdist rebuilt from the tag
(commit `3c5e632c4ea2`, go1.27.3, GNU tar, GNU gzip and Python 3.12.2 on
Darwin arm64) with the same sha256 as the released files
(`sagvd` `964a23f0…`, `sagvd-fips` `3d2912a1…`, `acp-compute`
`5151207d…`, `acp-compute-fips` `aca58ed8…`, `acpctl` `7b73ca6a…`,
`acpctl-fips` `2be2fff9…`, `acp-bootstrap` `513bf5fa…`,
`acp-bootstrap-fips` `30b70143…`, `acp-keygen` `af83eacc…`,
`acp-keygen-fips` `c0e2e8f3…`; `acpctl` for `linux-arm64` `d4ac0b3d…`,
`darwin-amd64` `f65584d0…`, `darwin-arm64` `8f22ad16…`, `windows-amd64`
`c0f22ded…`, `windows-arm64` `cf216bab…`; `acp-keygen` for the same five
`e3c1e8cc…`, `ccc94b09…`, `2c90e84d…`, `54dcdc04…`, `30b4c02e…`; the
package `af89cbca…`, the wheel `15d9556f…`, the sdist `94053092…`);
`results/versions.txt` the released binaries reporting `v0.14.0` at the
tag's commit; both daemons read `9fc6d42b…8b8cf` from the chip and
sealed their key files to it; the thief with the sealed files and the
unpinned worker refused; `results/job.json` gate level EXACT, 6 of 6,
`max_abs_err` 0; `results/audit-verify.json` `ok: true`, 17 events;
129.7 s on the guest. The four container images, 19 minutes after:
[`scripts/hardware-test/release-deploy-images/evidence/20261029T212702Z/`](scripts/hardware-test/release-deploy-images/evidence/20261029T212702Z/)
— `sagvd@sha256:273faaf9…`, `acp-compute@sha256:e24375d4…`,
`sagvd-fips@sha256:560dbdba…`, `acp-compute-fips@sha256:9a985634…`, all
four publicly readable; each verified by digest on the runner
(signature, SBOM attestation, SLSA provenance, the binary inside equal
to its release asset: `964a23f0…`, `5151207d…`, `3d2912a1…`,
`aca58ed8…`); each loaded image's `RootFS.Layers` equal to the signed
config's `diff_ids` (13 layers for the `sagvd` images, 9 for the
workers); both daemons from their images, the key files sealed, both
rogues refused, gate level EXACT, the audit log verified (17 events);
548.8 s. And the buttons on the release (§5.9 of the procedure), within
the hour: `scripts/hardware-test/gcp-deploy/evidence/20261029T213723Z/`
on SEV-SNP — 264 s from the command to `PROVEN`, the reset and the
services back in 87 s, a second job EXACT, one chain of 32 events — and
`scripts/hardware-test/gcp-deploy/evidence/20261029T214531Z/` on TDX —
276 s to `PROVEN` with the settled-boot reboot, back in 57 s after the
reset with the vTPM opening the key files again, a second job EXACT, 32
events ([C55](#c55), [C56](#c56) on the release);
`scripts/hardware-test/azure-deploy/evidence/20261029T211713Z/` on an
Azure Confidential VM — a Genoa host, not refused, 310 s to `PROVEN`,
back in 122 s after `az vm restart`, a second job EXACT, 32 events, only
PCR 10 moved ([C57](#c57) on the release); and
`scripts/hardware-test/aws-deploy/evidence/20261029T211714Z/` on an EC2
instance under the provider's VLEK — 328 s to `PROVEN`, stopped and
started onto another host and back in 82 s with the fleet's sealed key
files opened, a second job EXACT, 32 events, the same VLEK and
measurement ([C59](#c59)). And the released commit under `fips` with
`VG_FIPS=1` and `VG_SIGSUITE=ecdsa-p384-sha384`, on the certified module
with enforcement on, by the key-release kit 49 minutes after:
[`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261029T215743Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261029T215743Z/)
— `versions.txt`: `sagvd v0.14.0 (commit 3c5e632c4ea2) fips140=only
module=v1.0.0 enforced=true`, the same for `acp-bootstrap`; `build.txt`
every binary `GOFIPS140=v1.0.0-c2097c7c` at that commit; a key released
across clouds under `hpke-p384-v2` (recipient key `03d1fb88…`), the
restore confirmed by the chip receipt, the unlisted guest, the operator
stop and the TCB floor one above the chip refused, `acpctl audit verify`
at exit 0 reporting `signature_suite` `ecdsa-p384-sha384` over 12 events
— C42 and C43 on the released commit.

**Reproduce:**

```bash
scripts/hardware-test/release-deploy/run.sh <gcp-project> v0.14.0          # ~15 min, one n2d-standard-4, deletes it
scripts/hardware-test/release-deploy-images/run.sh <gcp-project> v0.14.0   # the images; ~15 min, one n2d-standard-4, deletes it
```

---

<a id="c38"></a>

### C38 — The audit log in closed segments under load on real SEV-SNP: an hour of 1609 jobs closed five segments and kept the live file within 16 MiB and the views at 16 MiB; the six files verified as one chain in 2.5 s, each archive against the record that closed it; a shipped archive refused without the operator's word and verified with it; one byte added to an archive named

**Claim.** The soak of C33 — one authority at `runtime.max_sessions: 3`,
three workers, six jobs in flight for sixty minutes on one n2d-standard-8
SEV-SNP guest (AMD Milan) — run on the code of ADR 0027 with
`audit.segment_events: 5000` and `queue.retain_finished_seconds: 1200`.
The hour served 1609 jobs, 1609 EXACT, nothing refused, no handshake
failed, 26.7 a minute, p50 11.53 s and p99 17.95 s from submission to
verdict — the rate and the percentiles of C33 (26.7, 11.3 s, 17.7 s):
closing a segment costs nothing the client sees. The authority wrote
25,749 events, sixteen a job and five `AUDIT_SEGMENT_CLOSED`, and closed
the live file five times, every eleven to twelve minutes (00:41, 00:53,
01:05, 01:16, 01:28), into `returnpath-audit.0000000000-0000004999.db`
through `returnpath-audit.0000020000-0000024999.db`, 16,777,216 bytes
each (bbolt grows a file in powers of two; 5000 events of 2.1–2.3 KB fill
about 11 MB of it); the live file ran between 0.25 and 16 MiB through the
hour and held 749 events and 2 MiB at the end. The views file reached
16 MiB in the 22nd minute and stayed there to the end: the window of
twenty minutes was reached in the 20th, the first sweep ran in the 21st,
and 1071 of the 1609 jobs expired, the 538 of the last twenty minutes
kept — where the two hours of C34 left a views file of 50 MB on this
chip. The whole log, six files, verified under the published key as one
chain in 2.5 s: every link and signature, each archive's start at the
previous one's end, and each archive's SHA-256 and length as the record
that closed it says. With the oldest archive moved away the verifier
refused (`returnpath-audit.0000005000-0000009999.db starts at event #5000
after tip be7fc229…, and the segments before it are not in
audit/archive: verify them where they are and pass --from-tip
be7fc229…`, exit 4) and with `--from-tip be7fc229…` verified the
remaining five files from there (ok, 25,749 events, exit 0); with one
byte appended to a copy of the newest archive it named the file
(`returnpath-audit.0000020000-0000024999.db is not the file the chain
recorded: sha256 88150f9d…, 16777217 bytes on disk; 7543a20d…,
16777216 bytes on the record`, exit 4). Started again over the log, the
authority opened it at 25,749 events verifying the live segment's 749
(`sagvd audit log open … events=25749 live_segment_events=749`), found
538 finished jobs in the store, and was ready in 10.7 s — what the first
start of the hour took over an empty log (11 s): the start waits for
the chip's report (KNOWN_ISSUES #17), not for the history. The
authority's anonymous memory ran 6.0 → 9.6 MB and never above 11.3; its
file-backed memory 9.9 → 19.6 MB and never above 23.5, where C34's two
hours reached 88 MB with 167 MB of files mapped — the daemon now maps a
live file of at most 16 MiB and a views file of 16 MiB. Its log holds no
warning and no error. At the end `sagvd_audit_segments_closed_total 5`,
`sagvd_audit_segment_events 749`, `sagvd_jobs_swept_total 1071`.

**Evidence.**
[`scripts/hardware-test/gcp-sev-snp/returnpath-soak/evidence/20261017T002749Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-soak/evidence/20261017T002749Z/)
(commit `6fbe2222`, `versions.txt`): `steps.txt` (`segment_events=5000`,
`retain_seconds=1200`, `soak: minutes=60 workers=3 jobs_done=1609 ok=1609
exact=1609`, `audit verify exit=0`, `audit_verify_seconds=2.5`, the three
drills' exit codes, `restart_ready_seconds=10.7`), `archives.txt` (the
five archives with their sizes and times, `du` of both directories),
`db-sizes-end.txt`, `snapshots.csv` (every minute: `audit_live_bytes`,
`audit_archive_bytes`, `audit_archives`, `views_bytes`,
`segments_closed`, `jobs_swept` beside the memory, session and queue
columns of C33), `summary.json` (derived by the kit's `summarize.py`:
`audit_live_bytes`, `views_bytes` first/max/last, `disk_end`, the
percentiles and rates), `audit-verify.json` (`ok: true`, 25,749 events,
the six `segments` with `first_index`, `events`, `tip`, `sha256`,
`bytes`), `audit-verify-shipped.json` / `.err` (exit 4, `starts_after_tip`),
`audit-verify-from-tip.json` (ok, five segments from event #5000),
`audit-verify-tampered.json` / `.err`, `audit-kinds.txt`
(`AUDIT_SEGMENT_CLOSED=5`), `restart-audit-open.json`,
`restart-queue-open.json`, `sagvd-metrics-end.txt`, `jobs.csv`,
`timeline.txt`, `sagvd-soak.warnings.txt` (empty), `sha256sums.txt`.
The kit: [`scripts/hardware-test/gcp-sev-snp/returnpath-soak/`](scripts/hardware-test/gcp-sev-snp/returnpath-soak/)
(`VG_SEGMENT_EVENTS=5000 VG_RETAIN_SECONDS=1200`). The decision:
[ADR 0027](docs/adr/0027-the-audit-log-in-closed-segments.md); the
tables: [`docs/operator/limits.md`](docs/operator/limits.md).

**Scope.** One host, one hour, three workers, one genome; the segment
size was chosen to close five times in the hour — the 100,000-event
segments `acpctl provision` writes close every 2.6 hours at 40 jobs a
minute (ADR 0027). The file sizes are bbolt's, in powers of two: the
views plateau is the file's high-water mark for the window, not the bytes
in use, and the file does not shrink. The restart time is the chip's
report at start, measured once; it shows that the open did not grow with
the hour, not how long a verification of 749 events takes (under a
second, by C33's 2.4 s for 25,712). The shipping drill moved one archive
aside on the same disk; nothing here moves an archive to another system,
and nothing here runs for a month. The job views that expired were not
re-read through the API after the window; `GET` answering 404 for them is
the unit test's, not this run's.

---

<a id="c39"></a>

### C39 — Two hosts, two clouds, two chips: `acpctl provision authority` on a GCP SEV-SNP guest (AMD Milan), `provision join` on an Azure SEV-SNP Confidential VM (AMD Genoa), `provision pin-worker` back on the authority; a 15 KB bundle carried one way and an identity the other; the worker admitted at the first handshake across the Internet, a gate job EXACT in 6 s, the audit log verified under the key the authority kept

**Claim.** The three commands of ADR 0028, run where they are meant to
run. On an n2d-standard-4 SEV-SNP guest in us-central1 (AMD Milan)
`acpctl provision authority --provider auto --worker-provider
azure-sev-snp --fetch-amd-chain genoa --fetch-own-amd-chain milan
--vault-listen 0.0.0.0:9443 --vault-address 34.41.169.228:9443` took
10.5 s: the key material, `sagvd.json` for an Azure SEV-SNP worker with
the Genoa chain from AMD KDS, the authority's identity from its chip
(`7dc7c12e…25acc`, sealer `sev-snp-derived-key`), five key files sealed,
and `worker-bundle.tar` — 15,360 bytes: the worker's signing seed, its
copy of the session sealing key, its TLS pair, the CA certificate, the
authority's 48-byte measurement as the worker's pin and the Milan chain
(4,602 bytes) for the worker's verifier, under a manifest of seven
SHA-256s — after which the authority's secrets tree held `sagvd` and
`shared` and nothing of the worker's. The bundle went through the run's
private bucket to the operator's machine and over ssh to a DC4as_v5
Confidential VM in West Europe (AMD Genoa). There `acpctl provision join
--bundle --provider azure-sev-snp` took 0.58 s: the seven files checked
against the manifest and written, `acp-compute.json` for the authority
the bundle names, the worker's identity from the vTPM's HCL report
(`11920f61…91c4`, sealer `tpm2`), its three key files sealed to the vTPM,
the bundle deleted; the worker's tree held `acp-compute` and the CA and
nothing of the authority's. The identity came back the same way and
`acpctl provision pin-worker` pinned it in 0.03 s (phase `complete`).
sagvd started on what the authority's directory held and was ready in
11 s; the worker, started on its own directory, had been dialing
`34.41.169.228:9443` through the firewall rule that admits its address
alone, and the session opened 5.0 s after sagvd was ready: `peer_provider
azure-sev-snp`, `peer_product Genoa`, Evidence of 4,515 bytes
(`application/vnd.vault-genome.azure-sev-snp-evidence`), the measurement
the pin named, handshake 841 ms. The gate job submitted at that moment
came back `succeeded` 6.2 s later, EXACT, 6 of 6 fixtures, `max_abs_err
0`, signed by `sagvd-authority-demo`, the attestation outcome `allow`;
the audit log of the run — sixteen events, one chain — verified under
the public key provision had kept for the operator. From the
orchestrator's first command to its last, with both machines created,
both runtimes installed and both hand-offs carried, 7 minutes 20 seconds.

**Evidence.**
[`scripts/hardware-test/provision-two-hosts/evidence/20261017T024319Z/`](scripts/hardware-test/provision-two-hosts/evidence/20261017T024319Z/)
(commit `749ebb1a`, both sides' `versions.txt`): `authority/steps.txt`
(`provision authority exit=0`, `phase=awaiting-worker`, `bundle removed
from the authority host after hand-off`, `provision pin-worker exit=0`,
`phase=complete worker_measurement=11920f61… worker_provider=azure-sev-snp
worker_sealer=tpm2`, `session opened after 5s`, `job status=succeeded
after 6s`, `gate_level=EXACT … n_exact=6 max_abs_err=0`, `audit verify
exit=0`), `authority/provision-authority.json` and
`authority/provision-complete.json` (the two phases),
`authority/bundle-manifest.json`, `authority/bundle-listing.txt`,
`authority/bundle.sha256` (`69572653…`), `authority/secrets-dirs-after-step1.txt`
(`sagvd shared`), `authority/session-opened.json`, `authority/job.json`,
`authority/audit-verify.json` (`ok: true`, 16 events), `authority/audit-events.jsonl`,
`authority/sagvd.log`, `authority/sagvd-metrics.txt`; `worker/steps.txt`
(`provision join exit=0`, `phase=joined vault_address=34.41.169.228:9443`,
`pinned_authority=7dc7c12e…`, `sealed_worker=keys.worker_signing.seed_path,
keys.session_sealing.material_path,vault.tls.client_key`, `bundle deleted
on the worker host after join`), `worker/provision-join.json`,
`worker/acp-compute-identity.json`, `worker/sealed-files.txt` (three files
`sealer: tpm2`), `worker/secrets-dirs.txt` (`acp-compute shared`),
`worker/vtpm.txt` (NV index `0x1400001`), `worker/acp-compute.log`
(0 errors); `authority-provision-step1.json` as the orchestrator received
it; `timeline.txt` (the orchestrator's), `authority/timeline.txt`,
`worker/timeline.txt`; `machines.txt` (the addresses, the firewall rule
`tcp:9443 from 51.124.206.201/32`); `runner.log`; `sha256sums.txt`. The
kit: [`scripts/hardware-test/provision-two-hosts/`](scripts/hardware-test/provision-two-hosts/);
the decision: [ADR 0028](docs/adr/0028-provisioning-across-two-hosts.md);
the guide: [`docs/operator/09_first_deployment.md`](docs/operator/09_first_deployment.md) §2.

**Scope.** The worker's boot is pinned by `pin-worker` from the run of
[C54](#c54); in the runs here it was recorded, not pinned. One run that
completed; the two before it stopped at step 2
for the kit's own mistakes — `--provider auto` then read only
configfs-tsm, which Azure's paravisor does not expose, so the worker
named its family, and the azure-sev-snp provider reads the HCL report
through `tpm2_nvread`, so the host needs tpm2-tools — both fixed in the
kit; their partial evidence was not kept. A second run on 2026-10-17,
[`scripts/hardware-test/provision-two-hosts/evidence/20261017T114030Z/`](scripts/hardware-test/provision-two-hosts/evidence/20261017T114030Z/)
(commit `55c549e7`), joined the worker under `--provider auto` once
`auto` reads the vTPM's HCL report where the kernel has nothing to say
(`worker/acp-compute.log`: `resolved_from=vtpm-hcl`,
`tee_provider=azure-sev-snp`): the same measurement, EXACT 6/6 in 5 s,
the audit log verified, 8 min 55 s end to end; and the authority's
`vg_tee_attestation_total{provider="azure-sev-snp",role="verify"} 1`
counts the verification under the worker's family, where the first run
had counted it under its own. The bundle and the
identity were carried by the kit (the bucket, ssh): the command writes
and reads them, the operator's channel moves them. The worker's private
keys were generated on the authority's host and existed there until the
bundle was written (ADR 0028). The authority's REST API stayed on
loopback; only the Return Path faced the Internet, under mutual TLS 1.3
with the private CA and the pinned measurements. The families run are
gcp-sev-snp and azure-sev-snp; the TDX and simulated paths of the same
three commands are the integration test's, not this run's.


<a id="c40"></a>

### C40 — The three cryptographic profiles of ADR 0029 on real SEV-SNP: a key released across clouds and an escrow key carried through the recovery ceremony under X25519, P-384 and the ML-KEM-1024 + P-384 hybrid

**Claim.** Every key encapsulation across clouds and in escrow is RFC
9180 HPKE under a named KEM suite, chosen by a profile on both daemons
(`crypto.profile`: `general`, `fips`, `cnsa`) with no negotiation below
either side's list, and the suite is in every record. On SEV-SNP guests
(n2d, AMD Milan, us-central1-c), `sagvd crosscloud-restore` released a
genome's key to an attested `acp-bootstrap` under each profile — the
two sides meeting on `hpke-x25519-v1`, `hpke-p384-v1` and
`hpke-mlkem1024-p384-v1` respectively, the first suite each profile
offers — the destination restored the genome and the chip signed the
receipt, an unlisted guest and an operator stop were refused, and the
audit log verified (10 events each). On two further pairs of guests the
escrow key was made under the profile's suite (X25519, then P-384),
sealed to the first chip and wrapped to the operator's recovery key
under the same suite; the recovery ceremony resealed the same key (same
tag, same suite) to the second chip through a PEM in a pipe, and the
job lost with the first host resumed from the replicated store and
succeeded. The kits refuse a run that meets on another suite than the
profile's, or on none.

**Evidence.** Key release:
[`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T144756Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T144756Z/)
(general), [`…144804Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T144804Z/)
(fips), [`…144806Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T144806Z/)
(cnsa), commit `b98a34264140`: `steps.txt` names the profile, both daemons'
`crypto_profile` and `kem_suites` as `identity` printed them, and the
release's `recipient_key_suite` and `crypto_profile`; `release.json`
carries the same; `audit-verify.json` `ok: true`, 10 events; the
measurement `ccdc5cf0…` on all three. Escrow:
[`scripts/hardware-test/authority-loss/evidence/20261021T152535Z/`](scripts/hardware-test/authority-loss/evidence/20261021T152535Z/)
(general, RTO cold 514.3 s, warm 49.6 s) and
[`…152543Z/`](scripts/hardware-test/authority-loss/evidence/20261021T152543Z/)
(fips, RTO cold 235.9 s, warm 48.5 s), commit `1637bf7`: `a/steps.txt`
(`profile=`, `escrow-provision exit=0 … suite=`), `b/steps.txt` (`escrow
re-provision exit=0 escrow_key=… suite=`, `resumed job is A's lost job:
same_job_id=true`). Under the v2 suites of ADR 0030 (HPKE export-only,
the module's AES-256-GCM):
[`…203018Z/`](scripts/hardware-test/authority-loss/evidence/20261021T203018Z/)
(fips, `hpke-p384-v2`, escrow key `bf7dc257…`, RTO cold 234.7 s, warm
51.1 s, `same_job_id=true same_request_id=true`). The same key-release kit under `fips` on the tag
`v0.7.0` (commit `28fa01506f43`), ten minutes after the release was
published:
[`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T164918Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T164918Z/)
— both daemons `crypto_profile=fips`, the release under `hpke-p384-v1`
(recipient key `f5eb716d…`), the restore confirmed, the unlisted guest
and the operator stop refused, `audit-verify.json` `ok: true`, 10 events,
the measurement `ccdc5cf0…`. Under the v2 suites of ADR 0030 (HPKE
export-only, the module's AES-256-GCM), the same kit on the same guest
image:
[`…/evidence/20261021T202413Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T202413Z/)
(general, `hpke-x25519-v2`),
[`…/202422Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T202422Z/)
(fips, `hpke-p384-v2`) and
[`…/202423Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T202423Z/)
(cnsa, `hpke-mlkem1024-p384-v2`) — `release suite=` the profile's first,
the restore confirmed, the unlisted guest and the operator stop refused,
10 events each. Unit and live tests: `internal/vault/kms/suite_test.go`
(the suite table against RFC 9180 §7.1 and draft-ietf-hpke-pq-05 §8),
`profile_test.go`, `coordinator_test.go`, `internal/bootstrap/crosscloud/
receiver_test.go`, `internal/genome/escrow/*_test.go`,
`test/integration/crosscloud_test.go` (`TestLiveCrossCloud_ProfilesMeetOnTheirSuites`)
and `genome_drill_test.go` (`TestLiveGenomeDrill_EscrowedKeyUnderFIPS`).

**Reproduce:**

```bash
scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/run.sh <gcp-project> us-central1-c fips    # ~10 min, one n2d-standard-2; general, fips or cnsa
scripts/hardware-test/authority-loss/run.sh <gcp-project> us-central1-c fips                # ~30 min, two n2d-standard-4
```

---

<a id="c41"></a>

### C41 — Reference design 01 played end to end on real SEV-SNP in two regions: the bank's job EXACT, the genome's key released to the attested standby and the restore gated EXACT on its chip, four refusals with their reasons, both audit logs verified by a third party with acpctl alone

**Claim.** One command in a GCP project plays reference design 01 — its "A job, end
to end" and its continuity — on two AMD SEV-SNP Confidential VMs in two
regions, under the chosen profile of ADR 0029 — on record under all
three — and writes the design's figures table from the run. The bank
(region A): the authority and its pinned worker attest with the chip,
every key file sealed to it; the quant's fine-tune sealed by acpctl; a
thief with the sealed files and a worker that is not the pinned identity
refused; the gate job over the Return Path EXACT, `RELEASE_DECIDED` on
the record. The continuity (region B): the standby's chip attests and
its measurement goes on the allow-list; `sagvd crosscloud-restore`
releases the genome's key under the profile's suite only after the
standby's report verified against the AMD chain; the standby restores by
itself and signs the receipt with its chip; `sagvd crosscloud-confirm`
verifies it; `acpctl genome gate` recomputes every sealed fixture on the
standby's chip through the real door and holds the results to the sealed
references: EXACT; a release to a guest not on the allow-list and one
under the operator's stop are refused with the reason on the record. The
third party: the machine that ran the kit verifies both of the bank's
audit logs with the published key and acpctl alone, queries the
request's events and the session's lineage. Nothing is simulated, and
the figures are the run's.

**Evidence.** [`scripts/hardware-test/reference-design-01/evidence/20261021T183244Z/`](scripts/hardware-test/reference-design-01/evidence/20261021T183244Z/)
(profile `general`, the key under `hpke-x25519-v1`; the bank
`us-central1-c`, measurement `7dc7c12e…`; the standby `europe-west4-b`,
`0e017d2f…`; tree `aafd49b` with the kit): `a/steps.txt` — `sagvd
seal-keys exit=0 sealer=sev-snp-derived-key` and the worker's, the
transport's own key among the sealed files (`a/sealed-files.txt`),
`rogue with the sealed files exit=1 sealed to gcp-sev-snp, this host is
simulated`, `rogue refused after 1s`, `session opened after 8s`,
`gate_level=EXACT door=pinned replay rung=0 fixtures=6 n_exact=6
max_abs_err=0`, `release exit=0`, `release suite=hpke-x25519-v1`,
`confirm exit=0`, `unlisted exit=1 policy denied key release:
destination measurement not in allow-list`, `stopped exit=1 policy
denied key release: operator stop in force`, `audit verify exit=0`, `xcc
audit verify exit=0`; `a/sagvd.handshake_ms.txt` 8187 ms for the first
report of the boot, then 27 ms; `a/timeline.txt` the job 5.2 s, the
release 4.9 s, the release to the restore confirmed 15.5 s;
`a/confirm.json` `status: ok`, `key_to_restored_seconds` 0.003;
`b/standby-gate.json` EXACT, 6 fixtures, backend 4.05 s;
`b/receipt.json`; `a/audit-verify.json` 17 events,
`a/xcc-audit-verify.json` 10; `third-party/steps.txt` the four
verifications at exit 0 — the request's 6 events, the lineage of
`ses-bbae08fe…`; `REPORT.md` the design's table filled from the run;
`runner-timeline.txt` 317 s from the run's first line to the third
party's verdict, the guests' creation included. The same two zones under
`fips` and `cnsa`, minutes apart:
[`…/evidence/20261021T184052Z/`](scripts/hardware-test/reference-design-01/evidence/20261021T184052Z/)
(`fips`, the key under `hpke-p384-v1`, recipient key `c9bfde06…`: the
job EXACT in 5.2 s, the release 4.9 s, the restore confirmed at 15.5 s,
the standby's gate EXACT with the backend at 4.39 s, the same four
refusals with their reasons, 17 + 10 events, the third party's four
verifications at exit 0, 308 s to its verdict) and
[`…/evidence/20261021T184112Z/`](scripts/hardware-test/reference-design-01/evidence/20261021T184112Z/)
(`cnsa`, `hpke-mlkem1024-p384-v1`, recipient key `57aa0729…`: the job
EXACT in 5.2 s, the release 4.9 s, the restore confirmed at 15.7 s, the
standby's gate EXACT with the backend at 3.99 s, the same refusals, 17 +
10 events, four verifications at exit 0, 308 s). The profile is the only
thing that changed between the three runs; the suite changed with it,
and nothing else in the figures did. Under the v2 suites of ADR 0030 — HPKE export-only,
the AEAD step the module's AES-256-GCM — the same two zones under
`fips`:
[`…/evidence/20261021T202252Z/`](scripts/hardware-test/reference-design-01/evidence/20261021T202252Z/)
(`hpke-p384-v2`, recipient key `9d57e065…`: the job EXACT in 5.2 s, the
release 4.9 s, the restore confirmed at 15.6 s, the standby's gate EXACT
with the backend at 3.96 s, the same four refusals, 17 + 10 events, four
verifications at exit 0, 316 s). The AEAD step moved into the module and
nothing in the figures moved with it.

**Reproduce:**

```bash
scripts/hardware-test/reference-design-01/run.sh <gcp-project> us-central1-c europe-west4-b general   # general, fips or cnsa; ~6 min after the build; one n2d-standard-4 and one n2d-standard-2, both deleted
```

---

<a id="c42"></a>

### C42 — Under the `fips` and `cnsa` profiles the product invokes only the certified module's approved services: the three kits on real SEV-SNP with every binary built on the Go Cryptographic Module v1.0.0 and every Go process under `fips140=only`, in which a non-approved call fails instead of succeeding

**Claim.** With `VG_FIPS=1` the kits `keyrelease-e2e`, `returnpath-e2e`
and `reference-design-01` build every binary on the certified Go
Cryptographic Module v1.0.0 (CMVP #5247; `GOFIPS140=v1.0.0`) and run
every Go process on the guests — and, in design 01, the third party's
`acpctl` on the runner — under `GODEBUG=fips140=only`, the module's
enforcement mode, in which a call to a non-approved service (AES-GCM
with a caller's nonce, X25519, SHA-1, a short HKDF or HMAC key) returns
an error or panics instead of succeeding ([ADR 0030](docs/adr/0030-the-fips-140-3-build.md),
§2 and part two). Under the `fips` and `cnsa` profiles the runs pass
with the verdicts, refusals and audit verifications of the runs without
the flag, and the record says so on every party: each daemon's `version`
line (`fips140=only module=v1.0.0 enforced=true`), its `identity`
(`fips140.enabled`, `enforced`, `version`), the guest's `steps.txt`
(`fips=1 GODEBUG=fips140=only`) and `build.txt`, the runner's note of
what it built from the binaries' own build settings; the kits' verdicts
require all of it. The claim is narrow: the services these runs invoked
are approved ones. It is not a validation of the product, and the
`general` profile, whose first suite is X25519, is refused up front.

**Evidence.** All six runs on 2026-10-21 on the tree of this change (`a6b33a2`
with the kits' changes), `VG_FIPS=1`: every binary
`GOFIPS140=v1.0.0-c2097c7c` (`build.txt`), every `version` line
`fips140=only module=v1.0.0 enforced=true` (`versions.txt`,
`third-party/tools.txt`), every `identity` `fips140 enabled=true
enforced=true version=v1.0.0` and every guest `fips=1
GODEBUG=fips140=only` (`steps.txt`). Key release:
[`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T214501Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T214501Z/)
(fips, `hpke-p384-v2`) and
[`…/20261021T213940Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T213940Z/)
(cnsa, `hpke-mlkem1024-p384-v2`): `release exit=0`, `confirm exit=0`,
`verify exit=0`, the unlisted guest and the operator stop refused,
`audit verify exit=0`, 10 events each. The Return Path:
[`…/returnpath-e2e/evidence/20261021T213945Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20261021T213945Z/)
(fips) and
[`…/20261021T212451Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20261021T212451Z/)
(cnsa): both rogues refused, the session opened after 8 s, the job
`succeeded` after 5 s with the gate EXACT 6 of 6, `audit verify exit=0`,
17 events; 128.9 s and 131.3 s. Design 01:
[`…/reference-design-01/evidence/20261021T212303Z/`](scripts/hardware-test/reference-design-01/evidence/20261021T212303Z/)
(fips) and
[`…/20261021T213017Z/`](scripts/hardware-test/reference-design-01/evidence/20261021T213017Z/)
(cnsa): the job EXACT in 5.2 s, the key to the attested standby and the
restore confirmed in 15.5 s and 15.7 s, the standby's gate EXACT (the
backend 4.34 s and 4.47 s), the four refusals with their reasons, 17 +
10 events, the third party's four verifications at exit 0 with its
`acpctl` under `fips140=only` (`third-party/tools.txt`); 312 s and
300 s; `run.txt` `fips 1`, `gofips140 v1.0.0`; `REPORT.md` names the
module. The figures are those of the runs without the flag (C40, C41).
The kits' verdicts (`run.sh`) refuse a run whose record lacks any of the
module's lines. The same key-release kit on the released commit of
`v0.8.0` (`20dc289`), from a clean checkout of the tag twenty minutes
after the release was published:
[`…/keyrelease-e2e/evidence/20261021T234401Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261021T234401Z/)
(fips, `hpke-p384-v2`; `versions.txt`: `sagvd v0.8.0 (commit
20dc289f092c) fips140=only module=v1.0.0 enforced=true`, the same for
`acp-bootstrap`; the release, the restore confirmed, both refusals,
`audit verify exit=0`, 10 events), and on the released commit of
`v0.9.0` (`0428a5a`), eighteen minutes after that release, under `fips`
with `VG_SIGSUITE=ecdsa-p384-sha384`:
[`…/keyrelease-e2e/evidence/20261022T155613Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261022T155613Z/)
(`versions.txt`: `sagvd v0.9.0 (commit 0428a5a634e4) fips140=only
module=v1.0.0 enforced=true`, the same for `acp-bootstrap`; `build.txt`
`GOFIPS140=v1.0.0-c2097c7c` on every binary; the release under
`hpke-p384-v2`, the restore confirmed, both refusals, `audit verify
exit=0`, 10 events under `ecdsa-p384-sha384`), and on the released
commit of `v0.10.0` (`84cc9b9`), 17 minutes after that release, the same
way: [`…/keyrelease-e2e/evidence/20261023T202813Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261023T202813Z/)
(`sagvd v0.10.0 (commit 84cc9b91e590) fips140=only module=v1.0.0
enforced=true`, the same for `acp-bootstrap`; `GOFIPS140=v1.0.0-c2097c7c`
on every binary; the release under `hpke-p384-v2`, the restore
confirmed, the three refusals, `audit verify exit=0`, 12 events under
`ecdsa-p384-sha384`), and on the released commit of `v0.11.0`
(`162835d`), 7 minutes after that release, the same way:
[`…/keyrelease-e2e/evidence/20261024T185758Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261024T185758Z/)
(`sagvd v0.11.0 (commit 162835d51bd3) fips140=only module=v1.0.0
enforced=true`, the same for `acp-bootstrap`; `GOFIPS140=v1.0.0-c2097c7c`
on every binary; the release under `hpke-p384-v2`, the restore
confirmed, the three refusals, `audit verify exit=0`, 12 events under
`ecdsa-p384-sha384`).

**Reproduce:**

```bash
VG_FIPS=1 scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/run.sh <gcp-project> us-central1-b fips          # or cnsa; ~10 min, one n2d-standard-2
VG_FIPS=1 scripts/hardware-test/gcp-sev-snp/returnpath-e2e/run.sh <gcp-project> us-central1-c fips          # ~15 min, one n2d-standard-4
VG_FIPS=1 scripts/hardware-test/reference-design-01/run.sh <gcp-project> us-central1-c europe-west4-b fips  # ~6 min, one n2d-standard-4 and one n2d-standard-2
```

**Scope.** `only` is the assessment, never the product (ADR 0030, §2):
no release binary carries it, and part three's `-fips` variant runs the
module in its approved mode without the enforcement switch. The
confidential-GPU path (Azure NCC H100 v5, C17 and C18) was measured on
the chip the next day and is under the same terms ([C44](#c44)). What
the module enforces is the set of services invoked; the module's boundary
and the operating environments are the certificate's.

<a id="c43"></a>
### C43 — The signature suite on every record, decided by the profile: the two kits on real SEV-SNP under `cnsa` with ECDSA P-384, and under `fips` picking ECDSA P-384 on the certified module with enforcement on — every record, identity and audit verification naming the suite

**Claim.** The profile of ADR 0029 decides the signature suite of ADR
0031 — `general` and `fips` sign with `ed25519`, `cnsa` with
`ecdsa-p384-sha384`, and `crypto.signature_suite` picks within what the
profile accepts, never beyond it — and the product runs end to end on
real SEV-SNP under a suite other than Ed25519 with every record naming
it: the authority's verdicts, tokens and manifests, both audit logs, the
worker's frames, the operator's lists and the pinned keys. Two kits,
four runs on the tree `1a41568`, each built from a clean checkout:

- [`…/keyrelease-e2e/evidence/20261022T120736Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261022T120736Z/)
  — `cnsa`: the authority signs under `ecdsa-p384-sha384` and accepts
  `ecdsa-p384-sha384` and `ml-dsa-87` (`sagvd signature_suite=…
  signature_suites=…`, `authority_signature_suite`,
  `audit_signature_suite` in `steps.txt`, from `sagvd-identity.json`);
  the destination accepts the same (`destination signature_suites=…`,
  from `destination-identity.json`); the key released under
  `hpke-mlkem1024-p384-v2`, the restore confirmed, `genome verify`
  ok, the two refusals, and `acpctl audit verify` at exit 0 reporting
  `signature_suite` `ecdsa-p384-sha384` over 10 events
  (`audit-verify.json`).
- [`…/keyrelease-e2e/evidence/20261022T120821Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261022T120821Z/)
  — `fips` with `VG_SIGSUITE=ecdsa-p384-sha384` under `VG_FIPS=1`: the
  deployment a bank held to X9 SD-34 runs. The same record under
  `hpke-p384-v2`, the authority accepting `ed25519` and
  `ecdsa-p384-sha384`, both daemons `fips140=only module=v1.0.0
  enforced=true` (`versions.txt`), every binary
  `GOFIPS140=v1.0.0-c2097c7c` (`build.txt`): the ECDSA signatures are
  the certified module's.
- [`…/reference-design-01/evidence/20261022T120741Z/`](scripts/hardware-test/reference-design-01/evidence/20261022T120741Z/)
  — `cnsa`, two regions: the bank's job EXACT 6 of 6 in 5 s, the
  handshake 8200 ms then 24 ms, the key to the attested standby and
  the restore confirmed in 15.6 s (the release 4.8 s), the standby's
  gate EXACT (backend 4.63 s), the four refusals with their reasons,
  17 + 10 events under `ecdsa-p384-sha384`, and the third party's
  four verifications at exit 0 with `signature_suite`
  `ecdsa-p384-sha384` on both logs (`third-party/steps.txt`,
  `audit-verify-returnpath.json`, `audit-verify-crosscloud.json`). The
  worker's frames signed under its ECDSA key
  (`acp-compute signing_signature_suite=…`), verified by the bank
  under the key's suite.
- [`…/reference-design-01/evidence/20261022T120827Z/`](scripts/hardware-test/reference-design-01/evidence/20261022T120827Z/)
  — `fips` picking `ecdsa-p384-sha384` under `VG_FIPS=1`, every party
  on the certified module with enforcement on: EXACT 6 of 6 in 5 s,
  8214 ms then 25 ms, 15.6 s (the release 4.9 s), the standby's gate
  EXACT (backend 4.06 s), 17 + 10 events, the third party's
  verifications naming the suite, its `acpctl` under `fips140=only`
  (`third-party/tools.txt`); 313 s to its verdict.

The kits refuse a run whose record lacks the suite on any party
(`run.sh`, `SIG_OK`). Two earlier runs of the same day on the tree
before `1a41568` failed at the bank's job and were not kept: the Return
Path server verified the worker's `CandidateOutputFrame` as Ed25519
while the worker signed under ECDSA — the one signing path outside the
contracts that part one of the ADR had not moved. The frame now names
its suite under the signature, the server verifies under the key's
suite, and a test drives the verification under every suite and across
suites (`internal/compute/returnpath/server/session_suite_test.go`).

The figures are those of the runs under Ed25519 (C40, C41, C42): the
suite changed on every record, 64-byte signatures became 96-byte ones,
and nothing else in the figures moved. On the released commit of
`v0.9.0` (`0428a5a`), eighteen minutes after the release was published,
the key-release kit under `fips` with `VG_SIGSUITE=ecdsa-p384-sha384`
and `VG_FIPS=1`, from a clean checkout of the tag:
[`…/keyrelease-e2e/evidence/20261022T155613Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261022T155613Z/)
— `sagvd v0.9.0 (commit 0428a5a634e4) fips140=only module=v1.0.0
enforced=true` and the same for `acp-bootstrap` (`versions.txt`), the
authority `signature_suite=ecdsa-p384-sha384` accepting
`ed25519,ecdsa-p384-sha384`, the destination accepting the same
(`steps.txt`), the key released under `hpke-p384-v2`, the restore
confirmed, `genome verify` ok, both refusals, and `acpctl audit verify`
at exit 0 reporting `signature_suite` `ecdsa-p384-sha384` over 10
events (`audit-verify.json`, tip `27ca94e2…`).

**Reproduce:**

```bash
scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/run.sh <gcp-project> us-central1-c cnsa                                                 # ~10 min; signatures ecdsa-p384-sha384, the profile's own
VG_FIPS=1 VG_SIGSUITE=ecdsa-p384-sha384 scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/run.sh <gcp-project> us-central1-c fips         # the X9 bank, on the module with enforcement
scripts/hardware-test/reference-design-01/run.sh <gcp-project> us-central1-c europe-west4-b cnsa                                          # ~7 min, one n2d-standard-4 and one n2d-standard-2
VG_FIPS=1 VG_SIGSUITE=ecdsa-p384-sha384 scripts/hardware-test/reference-design-01/run.sh <gcp-project> us-central1-c europe-west4-b fips
```

**Scope.** `ml-dsa-87` is named by the `cnsa` profile as what it
accepts and by ADR 0031 as the destination; no run here signs under it:
it is the standard library's implementation, outside the Go
Cryptographic Module v1.0.0, and the product refuses it on the `-fips`
build with the module's own reason (measured in the ADR's log). What
the profile decides is the suite; the records a reader of an earlier
release can verify are the Ed25519 ones, as `docs/operator/08_upgrading.md`
says. The suites' standing with the registries banks cite is the
ADR's, and `docs/compliance/banking.md` §6 carries it.

<a id="c44"></a>
### C44 — The confidential-GPU path under the certified module with enforcement on: the `azure-cgpu` kit on a real NCC H100 v5 with every binary built on the Go Cryptographic Module v1.0.0 and every Go process under `fips140=only`, under `fips` with Ed25519 and under `fips` with ECDSA P-384 — the chip, the vTPM and the H100 verified, the 7B genome EXACT on the GPU, and neither SHA-1 use ADR 0030 had named invoked

**Claim.** With `VG_FIPS=1` the `azure-cgpu` kit builds `sagvd`,
`acp-compute`, `acpctl` and `keygen` on the certified Go Cryptographic
Module v1.0.0 (CMVP #5247; `GOFIPS140=v1.0.0`) from a clean checkout of
the tree and runs every Go process on the confidential GPU VM under
`GODEBUG=fips140=only` — `acpctl` in the capture; both daemons, `acpctl`
and `keygen` in the Return Path — the module's enforcement mode, in which
a non-approved service (AES-GCM with a caller's nonce, X25519, SHA-1, a
short HKDF or HMAC key) fails instead of succeeding ([ADR 0030](docs/adr/0030-the-fips-140-3-build.md),
§2 and part four). Under the `fips` profile, with its own Ed25519 and
with `ecdsa-p384-sha384` picked by `VG_SIGSUITE`, the runs pass with the
verdicts, refusals and verifications of the runs without the flag, and
the record says so on every party and both stages. ADR 0030 had kept
this path outside [C42](#c42) for two named uses of SHA-1 — NVIDIA's
OCSP issuer hash as the responder chose it, the vTPM's `sha1` PCR bank
name. Measured, neither is invoked: the producer quotes the `sha256`
bank (`DefaultTPMQuotePCRs`), and `sha1` in the quote parser is the name
it gives a selection with algorithm id 0x0004, not a hash it computes;
the verifier's OCSP requests carry SHA-256 certificate ids
(`buildOCSPRequest`), the parser reads an answer's hash id into a name
and computes no hash with it, each answer's signature is checked by
`crypto/x509`, which refuses SHA-1 in every build, and the three answers
of each handshake were fetched and verified by a process in which
`crypto/sha1` refuses outright. The claim is as narrow as C42's: the
services these runs invoked on this path are approved ones; it is not a
validation of the product.

**Evidence.** Two runs on 2026-10-22 on the tree `14822ea`, `VG_FIPS=1`,
one `Standard_NCC40ads_H100_v5` in West Europe each, 22 minutes from the
VM's creation to its deletion (kernel `7.0.0-1016-azure-fde`, driver
595.91.07, `CC State: ON`, `CC GPUs Ready State: Ready`; torch
2.14.1+cu126 and transformers 5.19.0 from the hash-pinned locks): every
binary `GOFIPS140=v1.0.0-c2097c7c vcs.modified=false` (`build.txt`),
every `version` line `fips140=only module=v1.0.0 enforced=true`
(`versions.txt` on both stages), both daemons' `identity` `fips140
enabled=true enforced=true version=v1.0.0`, both stages' `steps.txt`
`fips=1 GODEBUG=fips140=only`, `run.txt` `fips 1`, `gofips140 v1.0.0`,
`profile fips`.

- [`scripts/hardware-test/azure-cgpu/evidence/20261022T133850Z/`](scripts/hardware-test/azure-cgpu/evidence/20261022T133850Z/)
  and [`…/20261022T133850Z-returnpath/`](scripts/hardware-test/azure-cgpu/evidence/20261022T133850Z-returnpath/)
  — `fips`, Ed25519. The capture (480 s): the HCL report, the VCEK
  chain from THIM, two vTPM quotes under our nonces over the `sha256`
  bank (`quote1.txt`), NVIDIA's local verifier and NRAS under the same
  nonce, Microsoft's own tools — every one exit 0 (`steps.txt`);
  `Qwen/Qwen2.5-7B-Instruct` @ `a09a35458c70…` fine-tuned on the H100
  in bfloat16 (`finetune.json`: loss 6.053 → 2.2e-04 in 18.6 s), sealed
  and verified (`verify.json`: ok, `vault-genome-v4`, 10,149,791 bytes),
  gated **EXACT** on the GPU (`gate-gpu.json`, 18.0 s), measured 16/16
  exact (`measure-gpu.json`), replayed bit for bit (`replay-gpu.json`).
  The Return Path: the daemons' key files sealed to the vTPM
  (`seal-keys-sagvd.json`, `seal-keys-worker.json`), both daemons
  reading the launch measurement `11920f61…91c4`; `sagvd identity`
  `crypto_profile fips`, `signature_suite ed25519` accepting
  `ed25519,ecdsa-p384-sha384`; the escrow key `9f443e60287bd925` sealed
  under `hpke-p384-v2` (`escrow-provision.json`: `tee: azure-cgpu`) and
  re-sealed through the ceremony; the rogue refused at the handshake in
  3 s (`rogue-worker.log`); the pinned worker's session opened in 1 s
  under `gpu_policy.evaluation: both`, the manifests for driver
  595.91.07 and three OCSP answers fetched during the handshake
  (`rim-cache-ls.txt`; `sagvd-metrics.txt`: verify success 1, handshake
  failures 1 — the rogue); the gate job **EXACT** (pinned replay, 16/16,
  max abs err 0, `release_authorized`) in 56 s (`job.json`);
  `audit verify exit=0` under `ed25519`, 17 events, tip `0fd58f6e…9831`
  (`audit-verify.json`); 60 and 42 checksums.
- [`…/20261022T140119Z/`](scripts/hardware-test/azure-cgpu/evidence/20261022T140119Z/)
  and [`…/20261022T140119Z-returnpath/`](scripts/hardware-test/azure-cgpu/evidence/20261022T140119Z-returnpath/)
  — `fips` with `VG_SIGSUITE=ecdsa-p384-sha384`: the deployment a bank
  held to X9 SD-34 runs, on the confidential GPU. The same capture
  (465 s; loss 6.053 → 2.2e-04 in 18.8 s, a 10,149,791-byte bundle,
  EXACT in 17.4 s, 16/16, the replay exact); the Return Path with every
  key under ECDSA P-384 — `sagvd signature_suite=ecdsa-p384-sha384`,
  `authority_signature_suite`, `audit_signature_suite` and `acp-compute
  signing_signature_suite` all `ecdsa-p384-sha384` (`steps.txt`; the
  P-384 PEMs in `sagvd-identity.json` and `acp-compute-identity.json`);
  the escrow key `b3cb5e3cdfcceb8c` sealed and re-sealed; the rogue
  refused in 3 s; the session opened in 1 s under `both` with the
  manifests and three OCSP answers fetched; the gate job **EXACT**
  (16/16, max abs err 0) in 56 s, the worker's frames signed under its
  ECDSA key and verified under the key's suite; `acpctl audit verify`
  exit 0 reporting `signature_suite` `ecdsa-p384-sha384` over 17
  events, tip `7cd08bd9…65e6`; 60 and 42 checksums.

The figures are those of the kit's run of 2026-10-15 on the same image
and runtime (C17's record): the module and the suite changed on every
party, and nothing in the figures moved. The verdict (`run.sh`) refuses
a run whose record lacks the module's lines on either stage, the profile
or the suite on any party; the VM and its disk, NIC, IP and NSG were
deleted after each record was read back and checked, the resource group
empty afterwards. Two runs earlier the same day are not kept: the first
FIPS run's daemons were built after the capture's evidence had landed in
the tree and their stamps said `vcs.modified=true` — the kit now builds
all four binaries first, from a clean checkout of HEAD, before anything
is written to the tree — and the ECDSA run started on the kit before
that change was stopped before its verdict once the cause was found.

**Reproduce:**

```bash
VG_FIPS=1 scripts/hardware-test/azure-cgpu/run.sh vg-cgpu-weu westeurope                                # ~25 min of NCC40ads_H100_v5 (about $9 an hour); profile fips, signatures ed25519
VG_FIPS=1 VG_SIGSUITE=ecdsa-p384-sha384 scripts/hardware-test/azure-cgpu/run.sh vg-cgpu-weu westeurope  # the X9 bank on the confidential GPU
```

**Scope.** As C42's: `only` is the assessment, never the product; what
the module enforces is the set of services the product invokes, and the
module's boundary and operating environments are the certificate's. The
H100's own cryptography — its report's signature, NVIDIA's tokens and
manifests — is NVIDIA's, verified here and not computed here, and the
vTPM is the root the cloud provider virtualises inside the confidential
VM (item 4 below). The `cnsa` profile has not been run on this host:
this claim is for `fips`, with both suites the profile accepts.

<a id="c45"></a>
### C45 — The three protocols the daemons run are modelled in ProVerif, with the verdicts recorded and reproduced in CI: twenty-three models and 185 verdicts, each variant showing what one protection or one key carries

**Claim.** The cross-cloud key release (ADR 0009, 0029, 0010, 0011), the
Return Path handshake (ADR 0014, 0025) and the sentinel and the failover
(ADR 0012, 0017) are modelled in ProVerif 2.05, in the tree under
`formal/` ([ADR 0032](docs/adr/0032-the-protocols-in-proverif.md)). One
generator writes every model from one template per protocol, so that the
variants differ only in the lines that change; for each protocol the
model of what the daemons run holds every query — the released key's
secrecy and the binding of a release to the key the destination's chip
quoted over; the admission of a Return Path session only on a quote the
worker's chip made over that session's nonces, the material's and the
candidate's secrecy and the verdict tied to the worker's signature; the
genome key's secrecy from the primary, a release only to the standby the
operator's policy names, the trigger and the genome the sentinel's word
on its chip — and each variant removes one protection or leaks one key
and loses exactly what it carries. The recorded run reproduces query by
query: `make formal-check`, and the `formal` workflow, which builds the
tool from the official tarball by digest on every push.

**Evidence.**
[`formal/results/proverif-20261022T173929Z.txt`](formal/results/proverif-20261022T173929Z.txt)
— ProVerif 2.05 on the twenty-three models as `gen.py` writes them, 185
`RESULT` lines, unedited; [`formal/README.md`](formal/README.md) — the
three tables of verdicts, the mapping of every line of each model to the
function that implements it, the queries and the assumptions;
[`formal/check_results.py`](formal/check_results.py) — the comparison
with the recorded run, model by model; the `formal` workflow's job
`models` green on the pull request that brought the models.

**Reproduce:**

```bash
make formal-check    # ProVerif 2.05 on PATH or PROVERIF=…; built from https://proverif.inria.fr/proverif2.05.tar.gz (sha256 4871f53c…ceabc4) with ./build -nointeract
make formal          # a new recorded run in formal/results/
```

**Scope.** The symbolic model: the attacker is the network and composes
messages, no primitive breaks, a chip's quote is a signature with one key
standing for the vendor root, HPKE and AES-GCM are ideal, the mutual TLS
of the Return Path is a fresh key under the vault's certificate key. The
models prove the protocols as written, not the code as shipped: the tie
to the code is the tests that remove each check (ADR 0009) and the kits
on hardware (C27, C40–C44), and the README names the function behind
every line. Not modelled: the audit log's hash chain, the executor's
clock (quarantine, RPO, timeouts), the handshake tables' TTL and size,
TLS's own handshake and record numbers, the gate's judgement; two rules
of the failover — one failover per policy serial, an older serial
refused — are the authority's record and the model does not establish
them. The models are the authors' and have had no external review (what
we do not claim, #8).

<a id="c46"></a>
### C46 — A chip's firmware is held to AMD's published floors and what the chip said is on the record: two GCP Milan hosts admitted at the live floors with their reports on the record, and a release refused under a floor one above the chip

**Claim.** The SEV-SNP verifier reads the whole report and holds it to
the attack record ([ADR 0033](docs/adr/0033-the-attack-record-in-the-policy.md)):
the chip's variant by CPUID; the current, reported, committed and launch
TCB versions, component by component, against the floors AMD's security
bulletins set for that variant when they were read on 2026-10-22
(RMPocalypse's SNP firmware, StackWarp's microcode;
[`docs/compliance/sev-snp-tcb-floors.md`](docs/compliance/sev-snp-tcb-floors.md),
held equal to the code by a test); BadRAM's alias check; the mitigation
vector's bit; no migration agent in the guest policy. What the chip said
— the variant, every TCB, the firmware, the platform's bits, both
mitigation vectors, the chip id, the floor applied and where it came
from — is on every admission and release record, and the policy on each
daemon's `identity`. On 2026-10-22 both GCP kits ran on the tree of the
ADR (`be37c6f`) on `n2d` SEV-SNP guests under `fips` on the certified
module with enforcement on: the cross-cloud release to a Milan at SNP
0x1d and microcode 0xde — the four TCBs the same, the alias check
complete, mitigation vector 0xb — with the chip on the
`CROSS_CLOUD_ATTESTATION_VERIFIED` record and, after the release, the
restore and the allow-list and operator-stop refusals, a fourth refusal
under a registry floor of SNP 0x1e, one above the chip, named on the
`KEY_RELEASE_DENIED` record at the attestation stage; and the Return
Path, where `sagvd identity` carries the policy and the admitted
worker's `TRUST_EVALUATED` record carries its chip, another Milan host at
the same levels, with both rogues refused and the gate job EXACT.

**Evidence.**
[`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261022T193735Z/`](scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20261022T193735Z/)
— `steps.txt` (the `chip` line and the `floor` line),
`attestation-verified.jsonl` (the record with `destination_detail.sev_snp`),
`release-floor.err` and `release-floor.json` (the refusal),
`key-release-denied.jsonl` (the three refusals on the record, the third
at the stage `attestation` naming the floor), `audit-verify.json` (ok,
12 events, `ecdsa-p384-sha384`), `versions.txt` (both daemons
`commit be37c6f6b98a`, `fips140=only module=v1.0.0 enforced=true`),
`sha256sums.txt`;
[`scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20261022T194156Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20261022T194156Z/)
— `steps.txt` (`sagvd sev_snp_policy …` and `peer chip …`),
`sagvd-identity.json` (`sev_snp_policy`), `audit-events.jsonl` (the
`TRUST_EVALUATED` record with `peer_detail.sev_snp`; the rogue's without
a report), `audit-verify.json` (ok, 17 events), `versions.txt`,
`sha256sums.txt`. The readers: the two kits' READMEs.

**Reproduce:**

```bash
VG_FIPS=1 VG_SIGSUITE=ecdsa-p384-sha384 scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/run.sh <project> us-central1-c fips
VG_FIPS=1 scripts/hardware-test/gcp-sev-snp/returnpath-e2e/run.sh <project> us-central1-c fips
go test ./internal/shared/tee/ -run 'TestSEVSNPPolicy|TestSEVSNPFloorsMatchTheDocument'
```

**Scope.** The floors are AMD's published values as read on a day, not a
judgement of the firmware; a value a bulletin withdraws (SB-3034) lowers
no floor here. Two Milan hosts of one region on one day; the Azure Genoa
of C44's record passes the same policy offline, in the tests; no Turin
chip has been on record. The operator's floor one above the chip is the
kit's way to show the refusal on the hardware at hand — a chip below the
live floors was not available to refuse.

<a id="c47"></a>
### C47 — The SEV-SNP verifier's reading is equal to two implementations nobody here wrote, on every genuine report on record, and no single-byte mutant verifies on any side: Google's go-sev-guest and VirTEE's snpguest on 67 reports from 27 chips, reproduced in CI

**Claim.** One test ([ADR 0034](docs/adr/0034-the-differential-corpus.md);
`internal/shared/tee/differential_test.go`, `make differential`) calls the
product's SEV-SNP parse, AMD-chain and signature checks and, on the same
bytes, Google's `go-sev-guest` v0.15.0 (`tools/oracle`, a module of its
own) and VirTEE's `snpguest` 0.10.0, on every genuine report on record
(`test/corpus/sev-snp`: 78 reports on 2026-10-29 — 40 the kits kept, nine
of them EC2 reports signed by a VLEK, 38 from the key-release receipts —
28 distinct chips, Milan and Genoa, report versions 3 and 5, firmware from
SNP 0x17 to 0x1f, each with the key it verifies under and AMD's chain). Each report verifies under all three; nineteen fields are
equal between the product and go-sev-guest (version, guest SVN, policy,
PLATFORM_INFO, VMPL, signature algorithm, the current, reported, committed
and launch TCBs, measurement, host data, report data, chip id, both
mitigation vectors, both firmware versions, CPUID as FMS); `snpguest`
shows the measurement and chip id the product read; and of the 1184
single-byte mutants of each report none verifies in the product or in
go-sev-guest (the product refuses 416 at the parse and 768 at the
signature, go-sev-guest 557 at the parse and 627 at verification). The
first run found the product verifying 416 mutants — the reserved bytes of
the signature block, not under the signature — and the parser now refuses
them; the claim is made on the tree with that fix.

**Evidence.**
[`test/corpus/sev-snp/results/differential-ci-20261022T222534Z.json`](test/corpus/sev-snp/results/differential-ci-20261022T222534Z.json)
— the `differential` workflow's first green run on the pull request (run
39864468613, ubuntu-24.04 x86-64; `snpguest` built from crates.io in
1 min 45 s): 41 rows, each with the three verdicts, the fields compared
and the two refusal counts;
[`test/corpus/sev-snp/results/differential-20261022T220839Z.json`](test/corpus/sev-snp/results/differential-20261022T220839Z.json)
— the local run after the fix, the Google reading alone;
[`test/corpus/sev-snp/results/differential-20261023T205052Z.json`](test/corpus/sev-snp/results/differential-20261023T205052Z.json)
— the corpus at 42 (the receipt of the 0.10.0 record,
`gcp-sev-snp-keyrelease-e2e-20261023T202813Z`, added), the Google reading
alone: both verify every report, nineteen fields equal, the sweeps on the
new report as on every other (product 416/768, go-sev-guest 557/627,
none verified);
[`test/corpus/sev-snp/results/differential-ci-20261023T205603Z.json`](test/corpus/sev-snp/results/differential-ci-20261023T205603Z.json)
— the `differential` workflow on the corpus at 42 (run 40022715298,
ubuntu-24.04 x86-64; `snpguest` built from crates.io in 1 min 31 s): 42
rows, each with the three verdicts, the fields compared and the two
refusal counts;
[`test/corpus/sev-snp/results/harness-oracle-20261023T205108Z.json`](test/corpus/sev-snp/results/harness-oracle-20261023T205108Z.json)
— the harness with the Google adapter on the 42: eleven fields each,
eight of eight mutants refused on each;
[`test/corpus/sev-snp/results/differential-20261024T014520Z.json`](test/corpus/sev-snp/results/differential-20261024T014520Z.json)
— the corpus at 55, with the receipts and reports of the acceptance
trial of v0.10.0 (two chips new), the Google reading alone: both verify
every report, nineteen fields equal, the sweeps as on every other report;
[`test/corpus/sev-snp/results/harness-oracle-20261024T014543Z.json`](test/corpus/sev-snp/results/harness-oracle-20261024T014543Z.json)
— the harness with the Google adapter on the 55;
[`test/corpus/sev-snp/results/differential-20261024T163710Z.json`](test/corpus/sev-snp/results/differential-20261024T163710Z.json)
— the corpus at 65, with the ten reports of the boot-chain kit of
[ADR 0037](docs/adr/0037-the-boot-chain-on-sev-snp-without-a-paravisor.md)
(`scripts/hardware-test/gcp-sev-snp/boot-chain`, two chips already on
record), the Google reading alone: both verify every report, nineteen
fields equal, the sweeps as on every other report;
[`test/corpus/sev-snp/results/harness-oracle-20261024T164532Z.json`](test/corpus/sev-snp/results/harness-oracle-20261024T164532Z.json)
— the harness with the Google adapter on the 65;
[`test/corpus/sev-snp/results/differential-20261024T190729Z.json`](test/corpus/sev-snp/results/differential-20261024T190729Z.json)
— the corpus at 66, with the receipt of the 0.11.0 record
(`gcp-sev-snp-keyrelease-e2e-20261024T185758Z`, a chip already on
record), the Google reading alone: both verify every report, nineteen
fields equal, the sweeps as on every other report;
[`test/corpus/sev-snp/results/harness-oracle-20261024T190756Z.json`](test/corpus/sev-snp/results/harness-oracle-20261024T190756Z.json)
— the harness with the Google adapter on the 66;
[`test/corpus/sev-snp/results/differential-20261028T031120Z.json`](test/corpus/sev-snp/results/differential-20261028T031120Z.json)
— the corpus at 67, with the receipt of the 0.12.0 record
(`gcp-sev-snp-keyrelease-e2e-20261028T030604Z`, a chip already on
record), the Google reading alone: both verify every report, nineteen
fields equal, the sweeps as on every other report;
[`test/corpus/sev-snp/results/harness-oracle-20261028T031120Z.json`](test/corpus/sev-snp/results/harness-oracle-20261028T031120Z.json)
— the harness with the Google adapter on the 67: eleven fields each,
eight of eight mutants refused on each, 29.1 s;
[`test/corpus/sev-snp/manifest.tsv`](test/corpus/sev-snp/manifest.tsv) and
[`test/corpus/sev-snp/SHA256SUMS`](test/corpus/sev-snp/SHA256SUMS) — the
corpus; the `corpus` job of the `differential` workflow on every push.

**Reproduce:**

```bash
python3 -I test/corpus/sev-snp/build.py --no-fetch && git diff --exit-code -- test/corpus/sev-snp   # the corpus is what build.py writes
make differential                                                        # the product and go-sev-guest; VG_SNPGUEST=… adds VirTEE's reading on Linux x86-64
cargo install snpguest --version 0.10.0 --locked                         # VirTEE's reading (Linux x86-64)
```

**Scope.** Two readings maintained by others, run on the same bytes: not a
proof that any of the three is correct, but that they agree on 78 reports
of two product lines and disagree on none, and that a byte out of place
is refused by all. The stage of a refusal differs and may: go-sev-guest
refuses reserved and must-be-one bits at the parse where the product
refuses at the signature. No Turin report; nothing for a report the corpus
does not hold; the records (the audit chain, the receipts) are part three.

<a id="c48"></a>
### C48 — The audit log verifies under an auditor's own tool with nothing of the product in it: pure Python, the file read as bytes, the curves written out — equal to `acpctl audit verify` on every genuine log on record and on logs under each suite, every mutant refused by both

**Claim.** `tools/auditor/verify_audit.py` replays an audit log the way the
product's `acpctl audit verify` does, with none of the product's code: it
reads the bbolt file as pages, re-encodes each event's canonical JSON as
the daemons encode it, recomputes SHA-256, follows the links from the
genesis (or from where a continued segment says it starts), and checks
each signature under the audit public key `identity` printed — Ed25519
(RFC 8032) and ECDSA P-384 (SEC 1) written out in the file, the standard
library only ([ADR 0034](docs/adr/0034-the-differential-corpus.md), part
three). One test (`internal/audit/chain/auditor_differential_test.go`,
`make differential`) calls both on the same files: the three genuine
authority logs on record (the region-loss drills of 2026-09-30,
2026-10-16 and 2026-10-17, five events each, Ed25519), logs written
under each suite with payloads that exercise the encoding, and six
mutants. On every log both say the same — the verdict, the count and the
tip — and every mutant is refused by both at the same event; the
ML-DSA-87 log is verified by the product and declined by the tool, which
says it does not implement the suite.

**Evidence.**
[`test/corpus/audit/results/auditor-20261022T233609Z.json`](test/corpus/audit/results/auditor-20261022T233609Z.json)
— the run on record: twelve cases, each with both verdicts; the three
genuine logs with their keys under
`scripts/hardware-test/failover-region-loss/evidence/*/authority/`
(`xcc-audit.db`, `audit.pem`, and `audit-verify.json` — the product's
verdict the kit recorded at the time);
[`tools/auditor/verify_audit.py`](tools/auditor/verify_audit.py).

**Reproduce:**

```bash
python3 -I tools/auditor/verify_audit.py --audit scripts/hardware-test/failover-region-loss/evidence/20261017T140018Z/authority/xcc-audit.db \
  --audit-pubkey scripts/hardware-test/failover-region-loss/evidence/20261017T140018Z/authority/audit.pem --audit-kid sagvd-audit-demo
go test -tags differential ./internal/audit/chain/ -run TestDifferential_Auditor -v
```

**Scope.** The audit chain of one file (a continued segment's start is
honoured; a log across several archived segments is replayed one file at
a time); the receipts and the records' meaning are not read by the tool.
ML-DSA-87 is not implemented in it. A tail cut off the log is invisible
to both verifiers, as ADR 0027 says: the tip is compared to what was
recorded elsewhere.

<a id="c49"></a>
### C49 — The AWS Nitro verifier, written from AWS's specification, verifies a production attestation document from the Nitro hypervisor

**Claim.** `internal/shared/tee`'s Nitro verifier — a CBOR codec written
from RFC 8949, the COSE_Sign1 envelope from RFC 9052, the document as AWS
specifies it, the chain anchored at the pinned AWS Nitro Enclaves Root CA
G1 (fingerprint `64:1A:03:21…8F:79:BB:5B`, as AWS publishes it), ECDSA
P-384 over the Sig_structure — verifies the raw attestation document the
Nitro hypervisor issued to a production-mode enclave on
`i-0e35190ae3157095d` (us-east-2a) at 2026-05-08T00:52:52.755Z: five
certificates to `CN=aws.nitro-enclaves`, signature valid, PCR0/1/2 equal
to what `nitro-cli describe-eif` printed for the image, `user_data` equal
to the SHA-512 of the build manifest, no nonce, not debug mode. The same
document at today's clock is refused (the signing certificate expired on
2026-05-08T03:52:52Z), a Verifier with a challenge refuses it for want of
a nonce, and a flipped byte anywhere is refused. The other three
documents of the cohort (two Ohio zones, Ireland) verify the same way
under NDA (ADR 0035).

**Evidence.**
[`internal/shared/tee/testdata/aws-nitro/`](internal/shared/tee/testdata/aws-nitro/)
— the raw document (4,523 bytes, SHA-256 `86a0e43d…8d3566`) and the
manifest bound as `user_data`;
[`scripts/hardware-test/aws-nitro/evidence/0N-*/07-go-verifier-audit.json`](scripts/hardware-test/aws-nitro/evidence/)
— the shipping verifier's report on each of the four documents (`verified:
true`, the chain, sixteen PCRs, `expected_pcr0_matches: true`).

**Reproduce:**

```bash
go test ./internal/shared/tee/ -run 'TestAWSNitro_GenuineProductionCaptures|TestAWSNitro_PublishedCapture_Identity' -v
acpctl attest nitro --doc internal/shared/tee/testdata/aws-nitro/2026-05-08-vm1-us-east-2a-attestation-document.bin \
  --expected-pcr0 69d556eff8606bd9828baaac20612f03851f29ddd989387ce5ab3a9cde8917add48d78f1f84c53dc2aafedb9ecb8734e
acpctl attest nitro --doc internal/shared/tee/testdata/aws-nitro/2026-05-08-vm1-us-east-2a-attestation-document.bin --at now   # exit 5: expired
```

**Scope.** Offline, at the document's own timestamp: the verifier's
clock is pinned to the capture because the hypervisor's signing
certificate lives three hours. The NSM producer (written from the
device's interface, ADR 0036) and the KMS sealer ([C50](#c50)) run in a
production-mode enclave against KMS itself ([C51](#c51)), and a SEV-SNP
authority has verified an enclave's document for a release and released
a genome key to it across clouds ([C52](#c52)). The
`user_data` binds the bytes of the build manifest the image carries; the
image is identified by its PCRs, and the manifest's own PCR fields are the
debug build's, which the May kit reused for the production build — the
manifest is not evidence of which image ran
(`internal/shared/tee/testdata/aws-nitro/README.md`).

---

<a id="c50"></a>
### C50 — The Nitro sealer's KMS client signs as AWS's own suite says and as KMS itself accepts, reads KMS's CMS in its profile, and trusts only Amazon's roots

**Claim.** `internal/shared/awssigv4`, Signature Version 4 written from
the IAM User Guide, produces AWS's answer — canonical request, string to
sign, signature, Authorization header — for all 38 cases of AWS's own
test suite (aws-c-auth at `84a26ea`, in the repository with its Apache-2.0
LICENSE and NOTICE). Against AWS KMS itself (us-east-2, no key and
nothing created): a correctly signed
GenerateRandom is answered AccessDeniedException — the signature
accepted, authorisation left, since the identity has no KMS permission;
the same request under a wrong secret and with the date twenty minutes
behind is refused as InvalidSignatureException ("Signature expired"
under KMS's five minutes), an access key nobody has as
UnrecognizedClientException; with an empty root pool the TLS handshake
fails ("certificate signed by unknown authority"), with Amazon Trust
Services' four roots (fingerprints held to the repository's page) it
completes in TLS 1.3. `internal/shared/cms` opens the CMS EnvelopedData of
KMS's profile — RSAES-OAEP-SHA-256, AES-256-CBC, one recipient by subject
key identifier — as OpenSSL 3.6.4 made it, in DER and in streamed BER, at
32 and 4096 bytes, and refuses OAEP with SHA-1, PKCS #1 v1.5, AES-128, a
recipient by issuer and serial, a second recipient, AuthEnvelopedData and
a key wrapped to another recipient. The sealer
(`internal/shared/tee/aws_nitro_sealer.go`) seals with a data key from
GenerateDataKey and opens in the enclave through Decrypt with the
enclave's attestation document as Recipient, under an encryption context
naming the image's PCR0 and the secret — round trip, another image,
another secret, a policy that does not admit the image, a changed
ciphertext and a wrong answer from KMS proven on the fake NSM and a fake
KMS that behaves as the operator guide's key policy does.

**Evidence.**
[`internal/shared/awssigv4/testdata/aws-signing-test-suite/`](internal/shared/awssigv4/testdata/aws-signing-test-suite/)
— AWS's vectors and their provenance (tarball SHA-256 `97f39b13…1de95`);
[`scripts/hardware-test/aws-nitro/kms-live/evidence/20261023T035355Z/`](scripts/hardware-test/aws-nitro/kms-live/evidence/20261023T035355Z/)
— the live run (its commit, a clean tree, go1.27.3, each answer with
KMS's request ID; the access key shortened, the account number taken
out); [`internal/shared/cms/testdata/`](internal/shared/cms/testdata/) —
the OpenSSL vectors, the script that made them and the throwaway key.

**Reproduce:**

```bash
go test ./internal/shared/awssigv4/ -run TestAWSSigningSuite -v
go test ./internal/shared/cms/ ./internal/shared/awskms/ ./internal/shared/tee/ -v -run 'OpenSSL|ReadsTheProfile|OutsideTheProfile|StructuralFaults|AmazonRootsArePinned|OperationsOnTheWire|AnswersOutsideTheirForm|TLSIsVerifiedAgainstThePool|AWSNitroSealer|NitroSealed|NitroSealerSelection'
scripts/hardware-test/aws-nitro/kms-live/run.sh   # with AWS credentials; needs no key
```

**Scope.** The signer and the client against KMS's front door: the
signature, the date, the credential scope, the TLS endpoint and the
requests' shape. The attested call itself — Decrypt with a Recipient from
a production-mode enclave, KMS's CiphertextForRecipient opened by this
reader — is [C51](#c51).

---

<a id="c51"></a>
### C51 — In a production-mode Nitro enclave the sealer opens a secret sealed to its image through KMS itself; another image, another secret, another key's policy, a debug-mode enclave and every principal without an enclave are refused, and CloudTrail records each call

**Claim.** On an m5.xlarge in us-east-2 (Amazon Linux 2023, nitro-cli
1.5.0, the enclave kernel nitro-cli ships, 4.14.256), an enclave image
built from this tree — one static program,
`scripts/hardware-test/aws-nitro/sealer-e2e/enclave`, and its
configuration — attests itself with the shipping NSM producer: production
mode, PCR0, PCR1 and PCR2 the image's as nitro-cli measured it, a chain
of five certificates to the pinned AWS root, the enclave's clock 52 ms
behind the hypervisor's timestamp. It opens, through `tee.SealerFor` and
`tee.OpenSecretWith` as `acp-bootstrap` will, a secret sealed outside the
enclave with the shipping sealer for that PCR0: a fresh RSA-3072 key, an
NSM document carrying it, Decrypt signed with Signature Version 4 under
the parent role's credentials (the instance metadata service, version 2,
through the parent's vsock), TLS 1.3 to KMS through the parent's vsock
forwarder, verified against Amazon's roots only, KMS's CMS opened inside
and then the GCM — what opened has the SHA-256 of what was sealed.
Refused, each by KMS and named by the sealer: a file sealed for another
image and a file sealed as another secret (InvalidCiphertextException —
the encryption context differs), and a file under a key whose policy
admits another image (AccessDeniedException). In debug mode the same
image's document says debug, PCR0, PCR1 and PCR2 zero; the sealer is not
built on a zero PCR0, and KMS refuses that document a key sealed for the
production PCR0 (AccessDeniedException: no statement admits it). The
parent's role and the kit's own, asking Decrypt without an enclave, meet
the key policy's explicit deny. CloudTrail records seven Decrypt calls on
the run's keys and the verdict names each: one granted, its Recipient the
production enclave's own document — module id, image digest equal to
PCR0, PCR1, PCR2, PCR3, PCR4 and PCR8 as the enclave reported them —
under the encryption context that names the image; two
InvalidCiphertextException; four AccessDenied, each by its key, its
principal and its kind of refusal. PCR3 is SHA-384 over 48 zero bytes and
the parent role's ARN and PCR4 the same over the parent's instance id, as
AWS's guide computes them (the formula held first to the guide's own two
examples). In debug mode PCR3 and PCR4 keep those values, though the
guide says a debug-mode document's PCRs are all zero: a key policy that
pins only the parent admits a debug-mode enclave on it. This product pins
the image (ADR 0036, decision 5).

**Evidence.**
[`scripts/hardware-test/aws-nitro/sealer-e2e/evidence/20261023T135129Z/`](scripts/hardware-test/aws-nitro/sealer-e2e/evidence/20261023T135129Z/)
— the run: its commit, a clean tree, go1.27.3; the enclave's reports in
production and debug mode; nitro-cli's measurements of the image and of
each enclave; both key policies; the refusals without an enclave;
CloudTrail's seven records; the verdict check by check (`verdict.txt`, 30
of 30); the teardown. Taken out: the account number, the operator's and
the parent's addresses, every IAM unique identifier and PCR3, which
measures the parent role's ARN and so the account number. AWS's guide:
[*Cryptographic attestation*](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)
(the page's SHA-256 `103f2fd1…` as read on 2026-10-23).

**Reproduce:**

```bash
scripts/hardware-test/aws-nitro/sealer-e2e/run.sh   # under the kit's role: the stack in scripts/hardware-test/aws-nitro/iam/
```

**Scope.** A probe program in the enclave, not `acp-bootstrap`: the
shipping producer, sealer and KMS client, wired as `acp-bootstrap` will
wire them, in one region on one instance type, the image unsigned (PCR8
zero, no PCR8 condition). No genome key has been released to an enclave:
that is ADR 0036's cross-cloud run, and the registry refuses the
`aws-nitro` family until it has run ([What we do not claim](#what-we-do-not-claim),
4). A parent can still hand the enclave an older sealed file of the same
secret for the same image (ADR 0036, part three).

---

<a id="c52"></a>
### C52 — A genome key is released across clouds into a production-mode Nitro enclave, by a SEV-SNP authority that verified the enclave's document against its policy; the genome is restored inside and the restore confirmed from the NSM-signed receipt; the allow-list, a pinned PCR, the operator stop and a debug-mode enclave are refused on the record

**Claim.** `sagvd` on a GCP AMD SEV-SNP Confidential VM (n2d-standard-2,
Milan, its key files sealed to the chip) releases a genome key over the
Internet to `acp-bootstrap` in a production-mode Nitro enclave on an
m5.xlarge in us-east-2, through the parent instance, which forwards
bytes and reads none. The enclave image holds the daemon, its
configuration, the authority's public key, the TLS certificate and the
CA; its two key files are sealed on the operator's machine for the
image's PCR0 under a KMS key whose policy releases to that image alone,
handed in by the parent at start and opened inside through KMS with the
enclave's own attestation document (CloudTrail: two Decrypts, each with
that document as Recipient, and no other). The sealed bundle goes into
the enclave over the authenticated API. The key is released only after
the document verified against the registry's policy — PCR0 as the
measurement, PCR1 and PCR2 pinned, the AWS root pinned, debug mode
refused, the nonce the key-binding challenge — and the
`CROSS_CLOUD_ATTESTATION_VERIFIED` record names the enclave: its module,
the hypervisor's timestamp, PCR0 to PCR4 and PCR8, the pins. The enclave
restores the genome in its memory and signs a receipt with the NSM;
`sagvd crosscloud-confirm` verifies it against the release and the
operator's bundle. Refused, each a `KEY_RELEASE_DENIED` record: an image
the allow-list does not name (the policy), PCR2 pinned to another value
(the attestation, naming PCR2), the operator stop (the policy), and the
same image in debug mode started with its key files in the clear, as an
insider could (the attestation: the document's PCR0 is zero). The audit
log verifies under the published audit key by `acpctl audit verify` and
by the auditor's own verifier, to the same count.

**Evidence.**
[`scripts/hardware-test/aws-nitro/crosscloud-e2e/evidence/20261023T182103Z/`](scripts/hardware-test/aws-nitro/crosscloud-e2e/evidence/20261023T182103Z/)
— the run on commit `b51d54bc`, a clean tree; the authority's steps,
identity and records (`authority-*`), the enclave's logs in production
and debug mode, nitro-cli's measurements of the image, the key policy,
CloudTrail's two records, the verdict (`verdict.txt`, 26 of 26), the
teardown of both clouds. Taken out: the account number, the three
addresses, every IAM unique identifier, PCR3; the receipt's attestation
document, which carries PCR3, is withheld with its SHA-256 kept in its
place.

**Reproduce:**

```bash
VG_GCP_PROJECT=<project> scripts/hardware-test/aws-nitro/crosscloud-e2e/run.sh   # under the kit's role (scripts/hardware-test/aws-nitro/iam/)
```

**Scope.** One region and instance type in each cloud; the image
unsigned (PCR8 zero, no PCR8 pin); the general profile
(`hpke-x25519-v2`, Ed25519); a 16 MiB genome and no gate inside the
enclave. The parent can still hand the enclave an older sealed file of
the same secret for the same image (ADR 0036, part three). The
hypervisor's own version is not in the document and is not held.

---

<a id="c53"></a>
### C53 — On a Compute Engine SEV-SNP guest the chip's measurement is Google's firmware and does not see the kernel; `gcp-sev-snp-vtpm` holds the boot too: the shipping verifier accepts a pinned boot and the same boot after a reboot and refuses another kernel on the same chip, and a key file sealed to the chip and the boot opens after the reboot and not under the other kernel

**Claim.** On a Compute Engine n2d SEV-SNP instance (Milan, Ubuntu 24.04,
its vTPM on), over four boots of one VM: the chip's launch measurement was
the same on every boot, under kernel 7.0.0-1014-gcp and under
7.0.0-1013-gcp — Google's UEFI, which Google's launch endorsement
precomputes per vCPU count — and a text sealed with the chip's derived key
alone opened under the other kernel. The `gcp-sev-snp-vtpm` producer made
its attestation key from Google's template in the vTPM's endorsement
hierarchy, the key Google's certificate names, and gave the chip's report
naming that key beside the key's quote over sha256:0-9. The
`gcp-sev-snp-vtpm` verifier, the second boot's digest pinned, accepted that
boot and the same boot after a plain reboot (no PCR moved), and refused the
other kernel (PCRs 8, 9 and 10 moved: "PCR digest … is not in the
acceptable set"). A file sealed by the chip-and-vTPM sealer opened after the
reboot and was refused by the vTPM under the other kernel. The attestation
key's certificate chained to Google's EK/AK root, which the binary pins,
through the intermediate its issuer URL served, and named the instance, its
project and that it is production.

**Evidence.**
[`scripts/hardware-test/gcp-sev-snp/boot-chain/evidence/20261024T160531Z`](scripts/hardware-test/gcp-sev-snp/boot-chain/evidence/20261024T160531Z)
(`run.txt`: twelve checks, `RESULT: PASS`; the product step of boots B, C
and D, the shipping producer, verifier and sealer on the guest);
[`…/20261024T155106Z`](scripts/hardware-test/gcp-sev-snp/boot-chain/evidence/20261024T155106Z)
(what moved between boots; the vTPM seal under sha256:0-7, 0-9 and 0-14:
0-7 opened under the other kernel, 0-9 and 0-14 were refused);
[`…/20261024T153800Z`](scripts/hardware-test/gcp-sev-snp/boot-chain/evidence/20261024T153800Z)
(the first run, three boots, kept for what it recorded). Offline, the
verifier on boot B's captured evidence accepts it, and refuses it under
another boot's digest, another project, another PCR selection, another
nonce, a signature with one bit changed, another instance's attestation-key
certificate, and the report without its quote
(`internal/shared/tee/gcp_sev_snp_vtpm_test.go`); the attestation-key
certificate verifies to the pinned root and is refused under another root,
without its intermediate, before its issue, and with a byte changed
(`gce_vtpm_test.go`); the chip-and-vTPM sealer refuses another boot on the
same chip and the same boot on another chip (`sev_snp_vtpm_sealer_test.go`).

**Scope.** One instance type and zone, one image, one kernel swap to an
older build of the same series. The vTPM is Google's software, outside the
TEE: the boot is held to it as the firmware is held to Google's UEFI, which
the chip measures. A guest whose whole boot the chip itself measures needs
a host that runs the operator's firmware, which this claim does not cover.
The image's first boot moves PCR 5 (its partition grows), so the boot is
pinned and the files sealed once the first boot has settled
([runbook](docs/operator/runbooks/real-tee-gcp-sev-snp-vtpm.md)).

```bash
scripts/hardware-test/gcp-sev-snp/boot-chain/run.sh <gcp-project>
go test -count=1 -run 'GCPSEVVTPM|GCEAK|GCEEKAK|GCEInstance|SEVSNPVTPMSealer' ./internal/shared/tee
```

---

<a id="c54"></a>
### C54 — Under Azure's paravisor the launch measurement does not see the OS, and both Azure families now require the boot: on a real Azure SEV-SNP Confidential VM a worker whose boot the policy does not name is refused at the handshake and the pinned one admitted, and `acpctl provision` pins the worker's boot across two clouds

**Claim.** `pcr_digests` — the vTPM's digest of the boot — is required of
an `azure-sev-snp` and an `azure-cgpu` peer and registry entry, and both
verifiers refuse a policy without it
([ADR 0037](docs/adr/0037-the-boot-chain-on-sev-snp-without-a-paravisor.md),
amendment). On a `Standard_DC4as_v5` in West Europe (Genoa), both daemons
attesting as `azure-sev-snp` on one VM pinned each other's launch
measurement `6587d41e…7f48` and boot `e7eed387…ce21` (SHA-256 over PCRs
0–14), each from the other's identity. A second `sagvd` whose policy names
another boot (`07eed387…`, one digit changed) refused the real worker at
the handshake — "azure-sev-snp: PCR digest e7eed387… is not in the
acceptable set" (`attestation_denied`); the `sagvd` pinned to the boot the
worker runs admitted it, and the gate job came back EXACT 6/6 through the
pinned replay; the audit log verified under the published key, and a
thief's copy of the sealed key files and a simulated worker were refused.
Across two clouds, `acpctl provision authority` on a GCP SEV-SNP guest
(Milan), `provision join` on another `Standard_DC4as_v5` (Genoa) and
`provision pin-worker` pinned the worker's measurement and its boot
`65442b83…f738` in `sagvd.json`, the value the worker's identity printed;
the session opened over the Internet 3 s after `sagvd` was ready, the gate
job EXACT 6/6, the audit log verified.

**Evidence.**
[`scripts/hardware-test/azure-sev-snp/returnpath-e2e/evidence/20261024T174525Z`](scripts/hardware-test/azure-sev-snp/returnpath-e2e/evidence/20261024T174525Z)
(`steps.txt`: `vault_boot`, `worker_boot`, `other boot refused after 1s:
PCR digest … is not in the acceptable set`, `gate_level=EXACT`, `audit
verify exit=0`; `sagvd-otherboot.log`: the refusal with its code;
`versions.txt`: the binaries of commit `e9a4d914`);
[`scripts/hardware-test/provision-two-hosts/evidence/20261024T174939Z`](scripts/hardware-test/provision-two-hosts/evidence/20261024T174939Z)
(`authority/steps.txt`: `provision pin-worker exit=0`,
`worker_boot=65442b83… sagvd_pcr_digests=65442b83…`, `gate_level=EXACT`,
`audit verify exit=0`; `authority/sagvd-metrics.txt`:
`vg_tee_attestation_total{provider="azure-sev-snp",result="success",role="verify"} 2`).
That run's binaries (`inputs.sha256`) are byte for byte those built from
commit `e9a4d914`: their stamp says `-dirty` because the first run's
evidence directory was not yet in git when the kit built, and a build of
the commit with an untracked file present gives the same four hashes.
Offline: `TestAzureVerifiersRequireTheBoot` (`internal/shared/tee`); the
refusals of `sagvd`, `acp-compute` and the registry
(`config_more_test.go`, `tee_config_test.go`,
`crosscloud_loader_more_test.go`); `TestProvision_AzurePinsEachSidesBoot`
and `TestProvisionTwoHosts_AzurePinsTheBoots` (`cmd/acpctl`).

**Reproduce:**

```bash
az login
scripts/hardware-test/azure-sev-snp/returnpath-e2e/run.sh vg-asnp-weu westeurope   # ~15 min, one DC4as_v5
scripts/hardware-test/provision-two-hosts/run.sh <gcp-project>                    # ~20 min, one n2d-standard-4 and one DC4as_v5
go test -count=1 -run 'AzureVerifiersRequireTheBoot|AzurePinsEachSidesBoot|AzurePinsTheBoots' ./internal/shared/tee ./cmd/acpctl
```

**Scope.** One VM size and region. The boot's digest is a property of one
VM's boot, not of its image: two VMs of the same image, size and region,
with the same launch measurement, measured `e7eed387…` and `65442b83…`, so
each host is pinned from its own identity; a policy over an image rather
than a host needs the event log appraised, which this claim does not
cover. A kernel update is a new boot: the host is refused until its new
digest is pinned. The `azure-cgpu` family's pin is the same verifier code,
held on the H100 by the failover kits' runs ([C18](#c18)); its Return Path
kit now writes the boots too and was not run again here. Azure's
paravisor holds the vTPM inside the TEE and is trusted as the chip's
intermediary (threat model).

---

<a id="c55"></a>
### C55 — One button deploys the signed release on real SEV-SNP and leaves it running: the release verified before it runs anywhere, the deployment stood up by `acpctl provision`, both daemons as services, a gate job EXACT and the audit log verified, 251 s from the command to `PROVEN`; after a hard reset the services come back on their own, the sealed key files open again, a second job gates EXACT and one chain of 32 events verifies

**Claim.** On 2026-10-28 `scripts/hardware-test/gcp-deploy/run.sh
rats-probe v0.12.0` ran `deploy/gcp/deploy.sh` as a person does. Before
anything ran anywhere, the release was verified on the machine that ran
the command: the tag's signature good under the ED25519 key pinned on
`main` (`deploy/verify/tag.txt`); `checksums-v0.12.0.txt` `Verified OK`
under the release workflow's identity for this very tag,
`…/release.yml@refs/tags/v0.12.0` (`deploy/verify/cosign.txt`); 5 of 5
downloaded files on the list (`deploy/verify/checksums.txt`); 5 of 5
SLSA provenances passed against the source tag (`deploy/verify/slsa.txt`).
One n2d-standard-4 Confidential VM (AMD Milan, SEV-SNP, Ubuntu 24.04)
was created with the verified list in its metadata. The guest fetched
the five files from GitHub and held them to that list (5 of 5,
`deploy/guest/checksums-check.txt`), installed the worker runtime from
the hash-pinned locks (torch 2.14.1+cpu, transformers 5.19.0; 46 s), and
`acpctl provision --provider auto --fetch-amd-chain milan` wrote the
deployment under `/etc/vaultgenome` in 10.5 s: both configurations for
`gcp-sev-snp`, the Milan chain from AMD KDS verified against the ARK the
binary pins (`69d063b4…40bcd`), both identities the chip's launch
measurement `9fc6d42b…b8cf`, each pinned by the other side, eight key
files sealed to the chip's derived key — five of the authority's, three
of the worker's. A first genome was fine-tuned on the guest and sealed
(5 s). `sagvd.service` and `acp-compute.service` started under systemd:
`sagvd` ready 13 s after its start and the session open as the worker
started (handshake 231 ms, 7980 bytes of evidence). A gate job over the
Return Path came back EXACT, 6 of 6 fixtures byte for byte, `max_abs_err`
0, the verdict signed by the authority's key, 5.2 s after submission.
Sixteen audit events verified under `operator/audit_public_key.pem` with
both services paused for 3.7 s; both were back 11 s later, the sealed key
files opened a second time. The summary that begins with `PROVEN` was
printed 251 s after the command, every line from a file of the record
(`deploy.out`). The kit then reset the VM — a hard reset, as a pulled
plug — and 87 s later ssh answered with the session open on the new
boot: systemd had started both units, the worker had dialled five times
while `sagvd` opened its sealed key files, resumed its job queue from
disk (one record, finished) and opened the audit log at sixteen events,
then bound its listener. `vg submit` over ssh gated a second job EXACT, 6
of 6; `vg verify` replayed one chain of 32 events, `ok: true` — sixteen
before the reset under tip `093242b5…2e8a`, thirty-two after under
`99fa6da3…0512`. The worker's chip, as the authority's verifier read it:
Milan, TCB snp 0x1f, microcode 0xe1, firmware 1.58.3, alias check
complete, above the floors of AMD's bulletins (0x1b, 0xde). Nothing
secret was printed: the record's logs, configurations and `provision.out`
are on the record as printed; keys, seeds and the operator's token stayed
on the VM and were deleted with it.

**Evidence.**
[`scripts/hardware-test/gcp-deploy/evidence/20261028T130334Z/`](scripts/hardware-test/gcp-deploy/evidence/20261028T130334Z/)
— `deploy.out` (what the person saw), `deploy/verify/` (`tag.txt`,
`cosign.txt`, `checksums.txt`, `slsa.txt`, `assets.sha256`, `tools.txt`),
`deploy/guest/` (`provision.out`, `provision.json`, both identities, both
configurations with paths and no secret, `sealed-files.txt`, `chip.txt`,
`job.json`, `audit-verify.json`, `audit-events.jsonl`,
`audit-public-key.pem`, `sagvd.log`, `acp-compute.log`, the two units,
`steps.txt`, `timeline.txt`, `sha256sums.txt`), `deploy/serial-console.txt`
(the record as the console carried it), `after-reboot/` (`boots.txt`,
`journal-this-boot.txt`, `health.txt`, `submit.txt`, `audit-verify.json`,
`status.txt`, `audit-events.jsonl`, `status-live.txt`), `summary.txt`,
`runner.log`, `sha256sums.txt`. The button:
[`deploy/gcp/`](deploy/gcp/README.md) — `deploy.sh`, `guest.sh`,
`tutorial.md`, `destroy.sh`; the kit:
[`scripts/hardware-test/gcp-deploy/`](scripts/hardware-test/gcp-deploy/).

**Reproduce:**

```bash
scripts/hardware-test/gcp-deploy/run.sh <gcp-project> v0.12.0   # ~12 min, one n2d-standard-4, deleted at the end
deploy/gcp/deploy.sh --project <gcp-project>                     # the button itself: the VM stays
```

**Scope.** One host with both daemons on it, as the reference deployment
([C37](#c37)); the two-host form is the three commands of [C39](#c39).
The family is `gcp-sev-snp`: the chip's launch measurement and policy,
which on Compute Engine is Google's firmware ([C53](#c53)); the boot
chain is held by `gcp-sev-snp-vtpm`, set up by its runbook once the
first boot has settled, not by this button. The key files are sealed to
the chip (`tee.sealer auto`): a reset in place opened them, as the
record shows; a stop and start that lands the VM on another host would
not, and the services would say so (`--sealer tpm2` seals to the
instance's vTPM instead). The guest reads the release from GitHub and
the chain from AMD KDS over the VM's external address; the record
travels over the VM's serial console to the machine that ran the
command, and nowhere else. The pause for the audit read is ADR 0027's:
the live segment is the authority's while it runs. One project, one
zone, one run on the record; the kit's run before it that day stopped at
the kit's own mistake (`vg` was not on `sudo`'s path after the reset),
fixed here, and is not on the record. The same kit ran again on SEV-SNP
after the guest learned Intel TDX ([C56](#c56)):
[`evidence/20261028T162801Z/`](scripts/hardware-test/gcp-deploy/evidence/20261028T162801Z/)
— 271 s to `PROVEN`, the same chip and TCB, the gate EXACT 6 of 6 in
5.2 s, sixteen events, the services back after the pause; after the
reset, ssh and the session in 87 s, the second job EXACT, 32 events on
one chain. And on `v0.14.0`, 29 minutes after it was published
([`evidence/20261029T213723Z/`](scripts/hardware-test/gcp-deploy/evidence/20261029T213723Z/)):
264 s to `PROVEN`, the same chip and TCB (Milan, snp 0x1f, microcode
0xe1), provision 10.5 s, the gate EXACT 6 of 6 in 5.2 s, sixteen events,
the services back after the pause; after the reset, ssh and the session
in 87 s, the second job EXACT, 32 events on one chain.

---

<a id="c56"></a>
### C56 — The same button deploys the signed release on a real Intel TDX Trust Domain: the key files sealed to the guest's vTPM on a settled boot, after one reboot, the measurement SHA-384 over MRTD and RTMR0–3, a gate job EXACT, the audit log verified, 287 s from the command to `PROVEN`; after a hard reset the services come back on their own, the vTPM opens the files again, a second job gates EXACT and one chain of 32 events verifies

**Claim.** On 2026-10-28 `scripts/hardware-test/gcp-deploy/run.sh
rats-probe v0.12.0 '' tdx` ran `deploy/gcp/deploy.sh --platform tdx` as a
person does. The release was verified first as in [C55](#c55) (the tag's
signature, the signed list under `release.yml@refs/tags/v0.12.0`, 5 of 5
files, 5 of 5 provenances). One c3-standard-4 Confidential VM with Intel
TDX (Ubuntu 24.04) was created with the verified list in its metadata.
The guest fetched the five files from GitHub and held them to the list
(5 of 5), installed the worker runtime from the hash-pinned locks (44 s)
and `tpm2-tools`, and **rebooted once** before it provisioned: the vTPM
sealer binds a key file to this boot's PCRs (`sha256:0-14` by default),
and the image's first boot grows its root partition and moves a PCR, so
what is sealed before that boot has settled does not open on the next
one — the rule the vTPM runbook states, done by the script
(`guest/timeline.txt`: `reboot` 16:30:15, `settled_boot` 16:31:39). On
the settled boot `acpctl provision --provider auto` resolved `gcp-tdx`
from configfs-tsm and wrote the deployment in 7.8 s: both configurations
for `gcp-tdx`, both identities the Trust Domain's measurement
`6f13cd51…` — SHA-384 over MRTD `f21e6b48…` and RTMR0–3 — each pinned by
the other side, eight key files sealed to the vTPM (`sealer: tpm2`; five
of the authority's, three of the worker's; `guest/sealed-files.txt`). A
first genome was fine-tuned and sealed (8 s); `sagvd.service` was ready
3 s after its start and the worker's session opened 1 s after the
worker's — the quote verified under the PCK chain to Intel's root and
Intel's TCB info for FMSPC `00806f050000` and QE identity from PCS, both
on the record (`guest/pcs-*`); a gate job over the Return Path came back
EXACT, 6 of 6 fixtures byte for byte, `max_abs_err` 0, 4.2 s after
submission; sixteen audit events verified under
`operator/audit_public_key.pem` with both services paused, and both were
back 3 s later, the vTPM opening the sealed files a second time. The
`PROVEN` summary was printed 287 s after the command, 29.8 s of them on
the settled boot from its first command to the sealed verdict. The kit
then reset the VM — the third boot — and 59 s later ssh answered with
the session open on the new boot; `vg submit` over ssh gated a second
job EXACT, 6 of 6; `vg verify` replayed one chain of 32 events, `ok:
true` (16 before the reset); `vg audit` and `vg events` each paused the
services for about 3 s and brought them back. Keys, seeds and the
operator's token stayed on the VM and were deleted with it.

**Evidence.**
[`scripts/hardware-test/gcp-deploy/evidence/20261028T162741Z/`](scripts/hardware-test/gcp-deploy/evidence/20261028T162741Z/)
— `deploy.out`, `deploy/verify/`, `deploy/guest/` (`metadata.txt`:
`platform=tdx`; `steps.txt`: `settled_boot=1`, `provider=auto
peer=gcp-tdx`, `vault_sealer=tpm2 worker_sealer=tpm2`, `gate_level=EXACT
… n_exact=6`, `peer trust domain tdx mrtd=… rtmr0=… fmspc=00806f050000`;
`tsm.txt` with `/dev/tdx_guest`; `chip.txt`; `provision.json`; both
identities with their `tdx` blocks; `sealed-files.txt`; `job.json`;
`audit-verify.json`; `audit-events.jsonl`; `audit-public-key.pem`;
`pcs-tdx-tcb-00806f050000.json` and `pcs-tdx-qe-identity.json` with
their issuer chains; `timeline.txt`; `sha256sums.txt`),
`deploy/serial-console.txt`, `after-reboot/`, `summary.txt`
(`platform=tdx`, `deploy_seconds=287`, `events_after_first_job=16`,
`events_after_reboot_and_second_job=32`), `sha256sums.txt`.

**Reproduce:**

```bash
scripts/hardware-test/gcp-deploy/run.sh <gcp-project> v0.12.0 '' tdx   # ~12 min, one c3-standard-4, deleted at the end
deploy/gcp/deploy.sh --project <gcp-project> --platform tdx            # the button itself: the VM stays
```

**Scope.** As [C55](#c55), with the TEE swapped: the measurement is the
hardware's own — MRTD and the RTMRs carry the firmware, its
configuration, the kernel, initrd and command line (ADR 0018) — and the
key files are sealed to the guest's vTPM, which on Compute Engine is
Google's software outside the Trust Domain ([C53](#c53), ADR 0022): a
reboot of the same image opens them, as the record shows across two
reboots; a new kernel does not, and the runbook says what a new image
means for the pin. The settled-boot rule costs one reboot (84 s on the
record) and is applied whenever the sealer is the vTPM — `--platform tdx`,
or `--sealer tpm2` on SEV-SNP. One instance type, one zone, one run on the
record. And on `v0.14.0`, 37 minutes after it was published
([`evidence/20261029T214531Z/`](scripts/hardware-test/gcp-deploy/evidence/20261029T214531Z/)):
276 s to `PROVEN` with the settled-boot reboot (on the settled boot:
provision 8.1 s, `sagvd` ready 3 s after its start, the session open 1 s
after the worker's, the gate EXACT 6 of 6 in 4.2 s, 30.3 s from its first
command to the sealed verdict), the reset and the services back in 57 s
with the vTPM opening the key files again, a second job EXACT, one chain
of 32 events.

<a id="c57"></a>
### C57 — The same button deploys the signed release on a real Azure Confidential VM (AMD SEV-SNP under the paravisor): the boot pinned and the key files sealed under the vTPM's PCRs without IMA's PCR 10, a gate job EXACT, the audit log verified, 293 s from the command to `PROVEN`; after `az vm restart` the services come back on their own, the vTPM opens the files again, a second job gates EXACT and one chain of 32 events verifies — and the host Azure chose first, its chip firmware under AMD's floor, was refused

**Claim.** On 2026-10-28 `scripts/hardware-test/azure-deploy/run.sh
v0.13.0 westeurope` ran `deploy/azure/deploy.sh` as a person does. The
release was verified first as in [C55](#c55) (the tag's signature, the
signed list under `release.yml@refs/tags/v0.13.0`, 5 of 5 files, 5 of 5
provenances), and `azuredeploy.json` — the template behind the Deploy to
Azure button, generated from the guest script and checked against it —
was deployed into a resource group of its own: one `Standard_DC4as_v5`
Confidential VM (Ubuntu 24.04 CVM image, secure boot, vTPM), the verified
list's hash in its tags. The first host Azure chose ran SNP firmware 0x17,
under the 0x1B floor AMD-SB-3020 sets for Genoa: the released verifier
refused it at the handshake (`TCB floor: reported TCB snp 0x17 below
0x1b`, ADR 0033), the guest named the refusal on its console
(`refused-host.out`), and the kit deployed again in a second resource
group, as a person would. On that host (Genoa, SNP 0x1C, microcode 0x58,
firmware 1.58.2, above the floors) the guest fetched the five files from
GitHub and held them to the list, installed the worker runtime from the
hash-pinned locks (52.3 s) and `tpm2-tools`, and **rebooted once** before
it provisioned; on the settled boot, after `systemd-pcrphase.service`,
`acpctl provision --provider auto` resolved `azure-sev-snp` from the HCL
report and wrote the deployment in 2.3 s: both configurations with
`tee.vtpm_quote_pcrs` and `tee.vtpm_seal_pcrs` as
`sha256:0,1,2,3,4,5,6,7,8,9,11,12,13,14` (ADR 0037, amendment of
2026-10-28), both identities Azure's launch measurement `6587d41e…` —
the paravisor and firmware — each pinned by the other side together
with the boot the vTPM measured over that selection, `dfc99de8…`
(`provision.json`: `vtpm_pcrs` on both sides, `pcr_digests` in both
configurations), eight key files sealed to the vTPM under the same PCRs
(`sealer: tpm2`; five of the authority's, three of the worker's). A first
genome was fine-tuned and sealed; `sagvd.service` was ready 1 s after its
start and the worker's session opened 0 s after the worker's — the
HCL report's SNP report verified under the VCEK chain to AMD's root and
against the floors, the quote under the key the report names, its digest
one the policy pins; a gate job over the Return Path came back EXACT, 6
of 6 fixtures byte for byte, `max_abs_err` 0, 6.3 s after submission;
sixteen audit events verified under `operator/audit_public_key.pem` with
both services paused, and both were back with the sealed files opened a
second time. The `PROVEN` summary was printed 293 s after the command,
22.6 s of them on the settled boot from its first command to the sealed
verdict, and the record was fetched over ssh and checked against the
guest's own `sha256sums.txt`. The kit then ran `az vm restart` and 166 s
later ssh answered with both services active and the session open on the
new boot; `vg submit` over ssh gated a second job EXACT, 6 of 6; `vg
verify` replayed one chain of 32 events, `ok: true` (16 before the
restart). `tpm2_pcrread` at seal time and after the restart
(`after-restart/pcrs-diff.txt`) differ in PCR 10 alone — IMA's runtime
log, which the image extends as files are first read — and PCR 10 is in
neither the pin nor the seal. Keys, seeds and the operator's token stayed
on the VM and were deleted with its resource group.

**Evidence.**
[`scripts/hardware-test/azure-deploy/evidence/20261028T215840Z/`](scripts/hardware-test/azure-deploy/evidence/20261028T215840Z/)
— `refused-host.out` and `refused-host-record/` (the first host: the
verifier's refusal, `reported TCB snp 0x17 below 0x1b`), `deploy.out`,
`deploy/verify/`, `deploy/guest/` (`steps.txt`: `settled_boot`,
`provider=auto peer=azure-sev-snp`, `vault_sealer=tpm2
worker_sealer=tpm2`, `gate_level=EXACT … n_exact=6`; `chip.txt`:
`product=Genoa … snp=0x1c microcode=0x58 … floor_snp=0x1b`;
`provision.json` with `vtpm_pcrs` and both boot pins; both identities
with their `vtpm` blocks; `sagvd.json` and `acp-compute.json` with the
selection; `sealed-files.txt`; `pcrs-at-seal.txt`; `eventlog-at-seal.yaml`;
`job.json`; `audit-verify.json`; `audit-events.jsonl`;
`audit-public-key.pem`; `timeline.txt`; `sha256sums.txt`),
`deploy/serial-console.txt`, `after-restart/` (`health.txt`,
`journal-this-boot.txt`, `pcrs.txt`, `pcrs-diff.txt`, `submit.txt`,
`audit-verify.json`, `audit-events.jsonl`), `summary.txt`
(`platform=azure-sev-snp`, `hosts_refused_by_the_verifier=1`,
`deploy_seconds=293`, `events_after_first_job=16`,
`events_after_restart_and_second_job=32`), `runner.log`, `sha256sums.txt`.
The rehearsal `v0.13.0-rc1` ran the same the same day
([`evidence/20261028T210406Z/`](scripts/hardware-test/azure-deploy/evidence/20261028T210406Z/):
252 s to `PROVEN`, back in 67 s after the restart, 32 events, PCR 10 the
only register that moved), and two hosts under the floor were refused that
day ([`evidence/20261028T205033Z-refused-host/`](scripts/hardware-test/azure-deploy/evidence/20261028T205033Z-refused-host/),
[`evidence/20261028T214657Z-refused-host/`](scripts/hardware-test/azure-deploy/evidence/20261028T214657Z-refused-host/)).

**Reproduce:**

```bash
scripts/hardware-test/azure-deploy/run.sh v0.13.0 westeurope   # ~15 min, one Standard_DC4as_v5 in a resource group of its own, deleted at the end
deploy/azure/deploy.sh                                          # the button's command: the VM stays, in the resource group "vaultgenome"
```

**Scope.** As [C55](#c55), with the cloud swapped: the launch
measurement is Azure's paravisor and firmware, so the boot is pinned
from the vTPM's quote (ADR 0037) and the key files are sealed to the
same vTPM (ADR 0022), both over a selection that leaves out IMA's PCR 10 —
on `v0.12.0` the same deployment, pinned and sealed over PCRs 0–14, did
not survive a restart (the amendment of 2026-10-28 records the data). The
host is Azure's choice: a chip whose firmware is under AMD's floor is
refused, as the policy says, and the next deployment lands elsewhere —
three of six hosts in West Europe that day ran SNP firmware 0x1C, three
0x17. The settled-boot rule costs one reboot (31.3 s on the record). One
instance type, one region, one run on the record on the release and one on
its rehearsal. The same kit ran again on `v0.14.0`, nine minutes after it
was published
([`evidence/20261029T211713Z/`](scripts/hardware-test/azure-deploy/evidence/20261029T211713Z/)):
a Genoa host (SNP firmware 0x1C, microcode 0x58, above the floors), not
refused — `PROVEN` 310 s after the command (provision 2.3 s, 22.0 s on the
settled boot to the sealed verdict), both sides quoting and sealing under
`sha256:0-9,11-14`, the boot `02be54f2…` pinned on both sides; after
`az vm restart` the services back in 122 s with the key files opened
again, a second job EXACT 6/6, one chain of 32 events; only PCR 10 moved
across the restart.

---

<a id="c58"></a>
### C58 — AMD SEV-SNP on EC2 under the provider's key: `acpctl provision --provider auto` told EC2 from Compute Engine on the host, fetched AMD's VLEK chain and sealed eight key files with the firmware's derived key; both daemons opened a session on a report signed by a VLEK that names no chip, the record holding the VLEK's TCB to the chip's and naming AWS's CSP_ID; a gate job EXACT, sixteen audit events verified, and the chip's launch measurement equal to AWS's published UEFI measured from the binary — 141 s on the guest, `PASS` 222 s after the command, the instance deleted

**Claim.** On 2026-10-29 `scripts/hardware-test/aws-sev-snp/run.sh
us-east-2 m6a.xlarge` built `sagvd`, `acp-compute`, `acpctl` and
`acp-keygen` for linux/amd64 from the tree of this change (`main` at
`460db390` with the family not yet committed: the binaries report
`460db390d22c-dirty`; `binaries.sha256` fixes them), launched one
`m6a.xlarge` (AMD Milan, 4 vCPUs) with `--cpu-options AmdSevSnp=enabled`
in `us-east-2c` from Canonical's Ubuntu 24.04 AMI (`ami-0fc53b217ec1ad816`,
kernel 7.0.0-1014-aws) under a key pair and a security group made for the
run, and ran `guest.sh` on it as root over ssh. The guest's first report
through configfs-tsm had FLAGS.SIGNING_KEY = 1 and sixty-four zero bytes
of CHIP_ID, with the certificate table beside it (`probe-report.bin`,
`probe-certs.bin`, `steps.txt`); the machine's DMI vendor read `Amazon EC2`
(`dmi.txt`). The worker runtime was installed from the hash-pinned locks
(torch 2.14.1+cpu, transformers 5.19.0; 116 s), and `acpctl provision
--provider auto --fetch-amd-chain milan --sealer auto` wrote the
deployment in 0.41 s (`provision.out`, `provision.json`): `tee.provider
auto` kept on both sides and the peer resolved to `aws-sev-snp`; the
**VLEK** chain fetched from AMD KDS — `/vlek/v1/Milan/cert_chain`, the
ASVK and the ARK `69d063b4…40bcd` this build pins
(`amd-milan-vlek-cert_chain.pem`); both identities the chip's launch
measurement `1d8ee9ba…cb5b` with `aws_sev_snp.csp_id`
`CN=cc-us-east-2.amazonaws.com`, each pinned by the other side and the
CSP_ID written into both `tee.peer.csp_ids`; eight key files sealed with
the firmware's derived key — five of the authority's, three of the
worker's — each header naming `tee: aws-sev-snp` and `sealer:
sev-snp-derived-key` (`sealed-files.txt`). A tiny base model was built on
the guest, a LoRA adapter trained on it and sealed (13 s; `finetune.json`,
`seal.json`). Both daemons started on what provision wrote and said how
they had resolved the family — `resolved_from: sev_guest (Amazon EC2)`,
`tee_provider: aws-sev-snp` (`sagvd.log`, `acp-compute.log`); the session
opened 1.2 s after `sagvd` started, the handshake carrying the family's
envelope — `application/vnd.vault-genome.aws-sev-snp-evidence`, 3402
bytes: the 1184-byte report and the VLEK beside it — in 49 ms. A gate job
over the Return Path came back EXACT, 6 of 6 fixtures byte for byte,
`max_abs_err` 0, the verdict signed by the authority's key, 7.3 s after
submission (`job.json`, `state: release_authorized`). With both daemons
stopped, sixteen audit events verified under `operator/audit_public_key.pem`
(`audit-verify.json`: `ok: true`, `event_count: 16`, Ed25519). The
admission record (`TRUST_EVALUATED`, `peer_detail.sev_snp` in
`audit-events.jsonl`; `chip.txt` reads it) says what signed the report and
what the chip said: `signing_key: vlek`; `report_id_hex` `53d72f8a…6331`;
`chip_id_hex` all zero; the VLEK — subject `SEV-VLEK`, issuer
`SEV-VLEK-Milan`, product Milan, CSP_ID `CN=cc-us-east-2.amazonaws.com`,
valid 2026-10-01 to 2027-10-01, its TCB (bootloader 4, TEE 0, SNP 0x1f,
microcode 0xe1) equal to the chip's reported, committed, current and
launch TCB; firmware 1.58.3, mitigation vector 0xfef, alias check
complete, the DEBUG bit clear; above the floors of AMD's bulletins (SNP
0x1b, microcode 0xde). The VLEK is the certificate the morning's three
hosts had shown (`vlek.sha256` `65d5b55b…0f4f`, the capture's `vlek.pem`
as DER): one key for the region's fleet, as ADR 0038 says. `guest.sh`
finished 140.6 s after its first command. On the machine that ran the command the kit downloaded AWS's
published EC2 UEFI, release 20260814 (`ovmf_img.fd`, sha256
`67aaae01…2bc9`, equal to the pin in `run.sh`), and measured it with
sev-snp-measure 0.0.13 (`--mode snp --vcpus 4 --vmm-type ec2`):
`1d8ee9ba…cb5b`, equal to what the chip reported and both daemons pinned
(`measurement.txt`). `RESULT: PASS` was printed 222 s after the command;
the instance, the key pair and the security group were deleted
(`vm-deleted.txt`: terminated at 16:52:40Z). Nothing secret was printed:
keys, seeds and the operator's token stayed on the instance and died with
it; no IAM role was attached and no identifier that encodes the account is
on the record.

**Evidence.**
[`scripts/hardware-test/aws-sev-snp/evidence/20261029T164825Z/`](scripts/hardware-test/aws-sev-snp/evidence/20261029T164825Z/)
— `guest.out` (what the person saw), `binaries.sha256`, `code-rev.txt`,
`instance.json`, `guest/` (`dmi.txt`, `kernel.txt`, `tsm.txt`,
`probe-report.bin`, `probe-certs.bin`, `probe-nonce.bin`, `provision.out`,
`provision.json`, `amd-milan-vlek-cert_chain.pem`, both identities, both
configurations with paths and no secret, `sealed-files.txt`,
`finetune.json`, `seal.json`, `sagvd.log`, `acp-compute.log`, `job.json`,
`chip.txt`, `audit-verify.json`, `audit-events.jsonl`,
`audit-public-key.pem`, `steps.txt`, `timeline.txt`, `console.log`,
`sha256sums.txt`), `measurement.txt`, `vm-deleted.txt`, `runner.log`,
`sha256sums.txt`. The family's first capture, which the verifier's offline
tests run on:
[`internal/shared/tee/testdata/aws-sev-snp/20261029T155800Z/`](internal/shared/tee/testdata/aws-sev-snp/20261029T155800Z/CAPTURE.md)
— three instances' reports and certificate tables, the VLEK, AMD's VLEK
and VCEK chains, snpguest's own verification, the derived keys across a
reboot and two stop/starts. The decision record:
[ADR 0038](docs/adr/0038-ec2-sev-snp-under-a-vlek.md); the kit:
[`scripts/hardware-test/aws-sev-snp/`](scripts/hardware-test/aws-sev-snp/README.md).

**Reproduce:**

```bash
scripts/hardware-test/aws-sev-snp/run.sh us-east-2 m6a.xlarge   # ~4 min, one m6a.xlarge, deleted at the end
go test ./internal/shared/tee/ -run 'AWSSEVSNP|VLEK' -count=1    # the verifier's cryptography on the capture, offline
```

**Scope.** One host with both daemons on it, as the reference deployment
([C37](#c37)); the two-host form is `acpctl provision` with `--role` as in
[C39](#c39), the authority's CSP_ID carried in the worker's bundle. The
family is `aws-sev-snp` (ADR 0038): the report is signed by the key AMD
issues to the provider, so the policy pins the provider — `CN=cc-<region>.amazonaws.com`,
one per region — and **not a machine**: CHIP_ID is zero on EC2 and
`sev_snp.chip_ids` is refused for the family; REPORT_ID names the boot on
the record. The key files are sealed with the firmware's derived key,
which on EC2 is **the fleet's**: the capture's probe gave the same key on
three hosts in two zones and across a reboot and two stop/starts, so a
file sealed here opens on any EC2 SEV-SNP guest of the same launch
measurement and guest policy; no vTPM is combined with the family in this
build (`tee.sealer tpm2`/`both` refused), so the boot after AWS's UEFI is
not pinned, and the operating system is not in the measurement ([C53](#c53)'s
finding holds). The binaries were built from the tree and copied over
ssh, not verified from a signed release as [C55](#c55)–[C57](#c57)'s
buttons do: the one-button deployment on EC2 comes with the release that
carries the family. The run did not reset or stop/start the instance — the
derived key's survival of a stop/start is the capture's finding, not this
run's; the kit does not yet do what [C55](#c55)'s does after the reset.
The delegated Verifier (`tee.peer.verifier`) is refused for the family:
it does not read the VLEK beside the report yet. One region, one instance
type, one run on the record; the kit's run before it that day stopped at
the kit's own check (it expected `provider=aws-sev-snp` where
`provision.json` rightly records `auto` with the peer resolved), fixed
here, with every line of the hardware green, and is not on the record.

---

<a id="c59"></a>
### C59 — The same button on AWS: one EC2 instance with AMD SEV-SNP stood up from the signed release under the provider's VLEK, proven and left running — the release verified on the deployer's machine and on the guest, `acpctl provision` resolving the family from the host and pinning AWS's CSP_ID, the key files sealed with the fleet's derived key, a gate job EXACT, the audit log verified, 328 s from the command to `PROVEN`; then a stop and a start — a move to another host — after which the services come back on their own, the sealed key files open again, a second job gates EXACT and one chain of 32 events verifies, under a new REPORT_ID, the same VLEK and the same launch measurement, which is AWS's published UEFI measured locally

**Claim.** On 2026-10-29, nine minutes after `v0.14.0` was published,
`scripts/hardware-test/aws-deploy/run.sh v0.14.0 us-east-2 m6a.xlarge
--published vaultgenome-deploy` ran `deploy/aws/deploy.sh` as a person
does, after checking that the committed `template.json` is what
`guest.sh` makes and that the bucket behind the Launch Stack button
serves it byte for byte (`runner.log`). Before anything ran anywhere, the
release was verified on the machine that ran the command: the tag's
signature good under the key pinned on `main` (`deploy/verify/tag.txt`);
`checksums-v0.14.0.txt` `Verified OK` under the release workflow's
identity for this very tag (`deploy/verify/cosign.txt`); 5 of 5
downloaded files on the list (`deploy/verify/checksums.txt`); 5 of 5
SLSA provenances passed against the source tag (`deploy/verify/slsa.txt`).
One CloudFormation stack was created from the template — a key pair from
the run's public key, a security group with port 22 open to the deployer's
address, a launch template with `AmdSevSnp` enabled, IMDSv2 and the
instance's tags in the metadata, one `m6a.xlarge` (AMD Milan, 4 vCPUs) in
`us-east-2c` from Canonical's current Ubuntu 24.04 AMI read from AWS's
public SSM parameter, a 32 GB encrypted disk — with the list's SHA-256,
the release and the record's stamp in the instance's tags
(`deploy/deployment.txt`, `deploy/deployment-outputs.json`). The guest
read its tags from the instance metadata, verified the list again under
the release identity and found it the same list the deployer had verified
(`checksums_list_matches_deployer=true`), fetched the five files from
GitHub and held them to it (5 of 5, `deploy/guest/checksums-check.txt`);
its first report through configfs-tsm had FLAGS.SIGNING_KEY = 1 and
sixty-four zero bytes of CHIP_ID, the certificate table beside it
(`probe-report.bin`, `probe-certs.bin`, `steps.txt`); it installed the
worker runtime from the hash-pinned locks, built the base model, and
`acpctl provision --provider auto --fetch-amd-chain milan --sealer auto`
wrote the deployment in 0.51 s: both sides `auto` resolved to
`aws-sev-snp` from the host, the VLEK chain from AMD KDS under the pinned
ARK (`amd-milan-vlek-cert_chain.pem`), both identities the launch
measurement `1d8ee9ba…cb5b` and `aws_sev_snp.csp_id`
`CN=cc-us-east-2.amazonaws.com`, each pinned by the other side, eight key
files sealed with the firmware's derived key — five of the authority's,
three of the worker's — each header `tee: aws-sev-snp`, `sealer:
sev-snp-derived-key` (`provision.json`, `sealed-files.txt`). A first
genome was fine-tuned on the guest and sealed (8.5 s). `sagvd.service` and
`acp-compute.service` started under systemd: `sagvd` ready 1 s after its
start and the session open 3.3 s after the services started, the
handshake carrying the family's envelope. A gate job over the Return
Path came back EXACT, 6 of 6 fixtures byte for byte, `max_abs_err` 0, the
verdict signed by the authority's key, 8.7 s after submission (`job.json`).
Sixteen audit events verified under `operator/audit_public_key.pem` with
both services paused (`audit-verify.json`); both were back with the sealed
key files opened again. The admission record (`TRUST_EVALUATED`,
`peer_detail.sev_snp`; `chip.txt`) says what signed the report and what
the chip said: `signing_key: vlek`, REPORT_ID `ff13b2ee…e144`,
`chip_id_hex` all zero, the VLEK `65d5b55b…` — subject `SEV-VLEK`, issuer
`SEV-VLEK-Milan`, CSP_ID `CN=cc-us-east-2.amazonaws.com`, valid to
2027-10-01 — Milan, TCB snp 0x1f, microcode 0xe1, firmware 1.58.3, alias
check complete, above the floors of AMD's bulletins (0x1b, 0xde). The
summary that begins with `PROVEN` was printed 328 s after the command,
every line from a file of the record (`deploy.out`); the guest took
184.2 s from its first command to the verified audit log. The kit then
stopped the instance (33 s to `stopped`) and started it again: it came up
on a new address 18 s later — on shared tenancy a stop and start is a
move to another host — and 82 s after the stop both services were active
with the session opened on the new boot (`after-move/health.txt`,
`journal-this-boot.txt`), the sealed key files having opened again under
the fleet's derived key. `vg submit` over ssh gated a second job EXACT, 6
of 6 (`after-move/submit.txt`); `vg verify` replayed one chain of 32
events, `ok: true` (`after-move/audit-verify.json`; sixteen before the
move). The chip on the new host, as the verifier read it: a new REPORT_ID
`cec18f74…`, the same VLEK, the same launch measurement
(`after-move/identity.txt`). On the machine that ran the command the kit
downloaded AWS's published EC2 UEFI, release 20260814 (sha256
`67aaae01…2bc9`, equal to the pin in `run.sh`), and measured it with
sev-snp-measure 0.0.13 for 4 vCPUs: `1d8ee9ba…cb5b`, equal to what the
chip reported and both daemons pinned (`measurement.txt`). The record was
checked for anything naming the account — an ARN, an IAM unique id, the
twelve digits — and names none; the stack was deleted
(`stack-deleted.txt`). Nothing secret was printed: keys, seeds and the
operator's token stayed on the instance and died with it; no IAM role was
attached to the instance.

**Evidence.**
[`scripts/hardware-test/aws-deploy/evidence/20261029T211714Z/`](scripts/hardware-test/aws-deploy/evidence/20261029T211714Z/)
— `deploy.out` (what the person saw), `deploy/verify/` (`tag.txt`,
`cosign.txt`, `checksums.txt`, `slsa.txt`, `assets.sha256`, `tools.txt`),
`deploy/deployment.txt`, `deploy/deployment-outputs.json`,
`deploy/serial-console.txt`, `deploy/guest/` (`provision.out`,
`provision.json`, both identities, both configurations with paths and no
secret, `sealed-files.txt`, the probe, `chip.txt`, `job.json`,
`audit-verify.json`, `audit-events.jsonl`, `audit-public-key.pem`,
`sagvd.log`, `acp-compute.log`, the two units, `steps.txt`,
`timeline.txt`, `sha256sums.txt`), `after-move/` (`addresses.txt`,
`identity.txt`, `health.txt`, `journal-this-boot.txt`, `boots.txt`,
`host.txt`, `submit.txt`, `status-live.txt`, `audit-verify.json`,
`status.txt`, `audit-events.jsonl`, `chip.txt`), `measurement.txt`,
`summary.txt`, `stack-deleted.txt`, `runner.log`, `sha256sums.txt`. The
button: [`deploy/aws/`](deploy/aws/README.md) — `template.json` (made
from `guest.sh` by `make-template.sh`), `deploy.sh`, `destroy.sh`,
`publish-template.sh`, the two policies; the kit:
[`scripts/hardware-test/aws-deploy/`](scripts/hardware-test/aws-deploy/README.md),
whose README carries the rehearsal `v0.14.0-rc1` the same evening
(`evidence/20261029T201000Z/`: `PROVEN` 290 s after the command, back
after the move in 87 s, the same checks green).

**Reproduce:**

```bash
scripts/hardware-test/aws-deploy/run.sh v0.14.0 us-east-2 m6a.xlarge --published vaultgenome-deploy   # ~8 min, one m6a.xlarge, deleted at the end
deploy/aws/deploy.sh --tag v0.14.0                                                                      # the button itself: the instance stays
```

**Scope.** One host with both daemons on it, as the reference deployment
([C37](#c37)); the two-host form is the three commands of [C39](#c39).
The family is `aws-sev-snp` ([C58](#c58), ADR 0038): the report is
signed by the key AMD issues to the provider, so the policy pins the
provider's CSP_ID and no machine; the launch measurement is AWS's
published firmware; the key files are sealed with the firmware's derived
key, which on EC2 is the fleet's — that is why they open again on the
other host, and why they would open on any EC2 SEV-SNP guest of the same
measurement and policy; no vTPM is combined with the family, so the boot
after AWS's UEFI is not pinned. The kit drove the same template the
console's Launch Stack link serves (checked equal to the committed file),
through the AWS CLI with the same parameters; a person's own click in the
console is not itself on the record. The move was a stop and a start, not
a reboot in place; the instance's public address changes with it. One
region (Ohio), one instance type, one run on the release and one on its
rehearsal; the deployer's identity needs the actions of
`deployer-policy.json`, and the template is served from a maintainer's
bucket, public for the template alone.

---

## What we do not claim

This section is load-bearing. We would rather lose a deal than win one on a
sentence we cannot defend.

1. **We do not claim byte-exact model inference across different hardware.**
   [C6](#c6) is our own measurement that it is unavailable on native float. The
   honest ladder is: EXACT on the pinned runtime · EQUIVALENT across devices,
   error measured · byte-portable only through the integer door, which computes
   its own arithmetic — and is byte-identical with *itself* across devices
   ([C19](#c19)), not with the float model.
2. **We do not claim to regenerate a model from a recipe alone.** The genome
   carries the sealed delta; the worker restores that delta onto the public
   base model and the authority proves the result ([C11](#c11)). Nothing in
   this repository invents weights from a recipe.
3. **We do not claim the GPU's evaluation as our own, or more than one GPU
   leg.** An attested GPU exists as a Return Path *worker* ([C17](#c17)) and,
   once, as the *standby* of a failover ([C18](#c18)): an Azure confidential
   GPU VM whose handshake carries the chip's report, the vTPM's quote and
   NVIDIA's tokens for the H100, and whose door runs on the H100 in
   confidential-computing mode. The GPU's measurements are evaluated by
   NVIDIA's service and, since [C20](#c20), by this verifier as well — the
   report's signature, chain, firmware id and every measurement against
   NVIDIA's signed manifests, offline on the captured report — and the
   verdict may rest on that evaluation alone (`own`), and revocation is
   asked of NVIDIA's responder with each answer verified here; what stays
   NVIDIA's word is, under `own`, the secure-boot and debug claims only
   its tokens carry. The GPU leg ran once, at 0.5B, with an EQUIVALENT
   gate, and so did the TDX leg ([C21](#c21)): each other-family standby
   has taken one key release, once, at 0.5B.
4. **We do not claim an SGX key release, nor Nitro or EC2 SEV-SNP beyond one run each.**
   SEV-SNP and Intel TDX are proven many times over ([C15](#c15)).
   Adapter dispatch for others exists (ADR 0002). The
   AWS Nitro verifier is written from AWS's specification and verifies
   the production-mode documents captured in May 2026 at their capture
   time ([C49](#c49), ADR 0035; one raw document is in the repository,
   three under NDA), and its sealer's KMS client is held to AWS's
   signing suite and accepted by KMS itself ([C50](#c50)); in a
   production-mode enclave its producer attests and its sealer opens a
   secret sealed to the image through KMS itself ([C51](#c51)); a genome
   key has been released across clouds into a production-mode enclave by
   a SEV-SNP authority and the restore confirmed from the enclave's
   receipt ([C52](#c52)), once, in one region and on one instance type,
   with an unsigned image. The SGX verifiers do not exist. A TDX host and an Azure confidential GPU host seal
   the escrow key to their vTPM (ADR 0022) — a root the cloud provider
   virtualises inside the confidential VM, not the TEE's own; an operator
   who does not accept that root has no sealed escrow key on those hosts.
   A Compute Engine SEV-SNP host under `gcp-sev-snp-vtpm` seals to its chip
   and its vTPM together, and attests with both (ADR 0037); the vTPM there
   is Google's software, outside the TEE ([C53](#c53)).
   An EC2 instance under `aws-sev-snp` ([C58](#c58), ADR 0038) is attested
   through the provider's VLEK, not a chip's VCEK: the report names no
   machine (CHIP_ID is zero), so the policy pins AWS's CSP_ID per region,
   not a host; its key files are sealed with a key the firmware derives for
   the fleet, which opens on any EC2 SEV-SNP guest of the same launch
   measurement and guest policy; no vTPM is combined with it in this build,
   so the boot is not pinned. Two runs on the record — the family from the
   tree's binaries ([C58](#c58)) and the button on the release
   ([C59](#c59)), with a stop and a start, not a reboot in place — in one
   region, on one instance type; a person's own click in the console is
   the same template, not itself on the record.
5. **We do not claim this at frontier scale.** The largest model measured is
   Qwen/Qwen2.5-32B-Instruct — on an attested confidential GPU VM ([C26](#c26));
   Qwen2.5-7B-Instruct ran on one 24 GB GPU ([C16](#c16)) and on the same
   confidential VM ([C17](#c17)); every failover and every CPU-only
   attested run is Qwen2.5-0.5B or smaller ([C12](#c12) uses a tiny model
   built on the guest to prove the path, not the scale). And we do not claim cross-device
   equivalence at 7B in bfloat16: there the float door fails closed on
   differences of one or two bfloat16 quanta, while top-1 and greedy agree
   16/16. Nothing larger than 32B has been run, and 70B in bfloat16 does
   not fit one 94 GB GPU.
6. **We do not claim production operation.** Stage E, MVP maturity, zero
   external deployments. The vault daemon drives the release-side flow
   ([C13](#c13)); the receive-side round trip is library code no binary
   drives, and receive-side self-bootstrapping is deferred to V2.
7. **We do not claim a granted patent.** The patent family is filed, not
   granted; a provisional application is not a patent and we never call it one.
8. **We do not claim external security review.** No third-party audit or
   penetration test has been performed on this code.

Every limit above is also tracked in [KNOWN_ISSUES.md](KNOWN_ISSUES.md), and
the README's **What works today** section is kept consistent with this file.
If you find daylight between the two, that is a bug in the document, and we
want the issue.

---

## Evidence hygiene

Hardware evidence in this repository contains **no keys, seeds, tokens or
configuration** — only measurements, digests, public identities and logs. Key
material never enters an evidence bundle. Every drill script deletes its VMs
and buckets on exit, including on failure.
