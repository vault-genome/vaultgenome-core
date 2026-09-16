# Verifiable claims

Every public claim this project makes, the artifact that proves it, and the
command that reproduces it. If a claim is not in this table, we are not making
it. If an artifact does not support its claim, that is a bug — open an issue.

The rule we hold ourselves to: **a claim is a measurement with a file behind
it, or it is not a claim.** Numbers below are copied from committed evidence,
not from memory. Every path is a file in this repository.

Reading order for an evaluator in a hurry: [C1](#c1), [C6](#c6), [C8](#c8),
[C11](#c11), [C12](#c12), [C13](#c13), [C14](#c14), then [What we do not claim](#what-we-do-not-claim) —
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
`train_seconds: 75.766`.
The base-weights figure is `model.safetensors` of `Qwen/Qwen2.5-0.5B-Instruct`
@ `7ae5576`, recorded in
[the drill README](scripts/hardware-test/gcp-drill/README.md); every base file
is pinned by SHA-256 in the genome's manifest (`sha256:7504966b…e927`).

**Reproduce.** `bash scripts/hardware-test/gcp-drill/run.sh <gcp-project>`
(boots a SEV-SNP VM and a GPU VM, ~30 min, deletes both). See
[the drill README](scripts/hardware-test/gcp-drill/README.md).

**Caveat.** The ratio is a property of LoRA fine-tuning at this rank, not a
universal compression claim. A full-weight fine-tune has no such ratio. We have
not yet run this at 7B+; see [What we do not claim](#what-we-do-not-claim).

---

<a id="c2"></a>
### C2 — The genome replays to a bit-identical adapter on the pinned runtime

**Claim.** Re-running the sealed recipe on the pinned runtime reproduces the
adapter **bit for bit**: `max_abs_diff = 0.0`, `max_rel_diff = 0.0`, and every
training loss identical (`max_loss_diff = 0.0`).

**Evidence.**
[`…/source/replay-source-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/source/replay-source-cpu.json)
— `exact: true`, `losses_equal: true`.

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
digest"`. Tamper behaviour is asserted in
`internal/genome/bundle/*_test.go`.

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
`fixtures_hash: 98d31611…486b`.

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
error is ~50× inside it. `n_critical_mismatch: 0` on every device.

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
narrated in [the probe README](scripts/hardware-test/gpu-exact/README.md).

**Reproduce.** `bash scripts/hardware-test/gpu-exact/run.sh <gcp-project>`
(one L4, ~20 min, deletes the VM).

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
A concrete released-to measurement appears in the failover report below
(`destination_measurement_hex: 7dc7c12e…125acc`, `destination_kind:
gcp-sev-snp`).

**Scope.** SEV-SNP only. Intel TDX, AWS Nitro and SGX verifiers are **not**
shipped — see [What we do not claim](#what-we-do-not-claim).

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
Design: [ADR 0012](docs/adr/0012-sentinel-and-policy-driven-failover.md).

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
requirement of the project.

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
`/dev/sev-guest` (`tsm.txt`).
`standby/escrow-provision.json`: `escrow_key: d2aac7b965c6ab76`,
`tee: gcp-sev-snp`, `source: generated`, `recovery_key: 93b4bd0871bfacf6`;
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

**Reproduce:**

```bash
scripts/hardware-test/gcp-failover/run.sh <gcp-project>
go test -count=1 -run 'SEVSealer|Sealed|Recovery|Escrow|Attest|Pinned|StolenSeed|LastWord|Overdue' ./internal/shared/tee/ ./internal/genome/... ./internal/vault/failover/ ./cmd/sagvd/
make test-integration
```

**Scope.** The escrow key alone is sealed; the authority's signing seed,
audit seed and session-sealing key are still files (KNOWN_ISSUES #1, #11).
The sealed key is bound to the chip and the launch measurement, so a
restart on another host or a new image needs the operator's ceremony;
nothing re-provisions itself. The chip's word bounds an attacker who holds
the seed without the chip; an intruder with root inside the primary's
guest holds both and is caught only by the wires (KNOWN_ISSUES #12). The
model is Qwen2.5-0.5B-Instruct with a LoRA adapter; both machines are CPU
confidential VMs.

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

## What we do not claim

This section is load-bearing. We would rather lose a deal than win one on a
sentence we cannot defend.

1. **We do not claim byte-exact model inference across different hardware.**
   [C6](#c6) is our own measurement that it is unavailable on native float. The
   honest ladder is: EXACT on the pinned runtime · EQUIVALENT across devices,
   error measured · byte-portable only through the integer door, which computes
   its own arithmetic.
2. **We do not claim to regenerate a model from a recipe alone.** The genome
   carries the sealed delta; the worker restores that delta onto the public
   base model and the authority proves the result ([C11](#c11)). Nothing in
   this repository invents weights from a recipe.
3. **We do not claim attested GPU destinations.** That needs confidential GPUs
   (H100 CC); we have not run one. Every measured destination to date is a CPU
   TEE.
4. **We do not claim TDX, Nitro or SGX verification.** SEV-SNP only. Adapter
   dispatch for others exists (ADR 0002); the offline verifiers do not.
5. **We do not claim this at frontier scale.** Every hardware number here is
   Qwen2.5-0.5B or smaller ([C12](#c12) uses a tiny model built on the guest to
   prove the path, not the scale). A 7B+ run is the obvious next measurement
   and it has not been made.
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
