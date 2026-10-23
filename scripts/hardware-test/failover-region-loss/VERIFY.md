# Checking the region-loss drill yourself

For a reporter, an editor or their technical reviewer. Part A needs only a
text editor and a browser. Part B needs Go and this repository and checks
the signatures offline. Part C runs the whole drill again in your own cloud
accounts. `<run>` is the run's directory under [`evidence/`](evidence); the
run published so far is
[`20260930T194321Z`](evidence/20260930T194321Z), and its results are in the
[README](README.md#results--run-20260930t194321z).

## A. Read the record (15 minutes)

1. **The timeline.** `evidence/<run>/TIMELINE.txt`, or run
   `python3 timeline.py evidence/<run>` (Python 3, standard library only).
   It merges what the three machines, the operator and Google wrote into one
   list, each line tagged with the clock it came from, then the intervals.

2. **The primary's last word.** `authority/last-heartbeat.json`: the last
   heartbeat that reached the release authority — its sequence number, its
   time by the primary's clock, `status`, and the newest generation sealed.
   It is signed by the sentinel and carries the primary chip's SEV-SNP
   report (`attestation`). Nothing came after it.

3. **That the machine really went dark, in Google's words.**
   `operator/operator-destroy.txt`: the operator watching Google report the
   primary `TERMINATED`, Google's own `lastStopTimestamp` for it, the
   deletion of the machine and its boot disk, and Google then answering
   that the machine *was not found*. `operator/gcp-audit-primary.json`:
   Google's audit log for the machine — its creation, the power-off, the
   deletion — with the caller's identity and address left out.
   `primary/steps.txt` and `primary/finetune-2.log`: what the machine was
   doing when the power went — training generation 2, which was never
   sealed and was lost with it. Compare the times: Google's API reported the
   machine `RUNNING` for almost a minute after it went silent, and the
   failover was complete before Google's audit log recorded the guest's
   termination. The authority never needed to be told the primary was dead.

4. **What the operator decided in advance.** `authority/failover-verify.txt`
   (the signed policy, as the authority verified it before arming): the one
   standby allowed, the evidence it must show, the trigger — *no heartbeat
   for 15 s* and nothing else — and the required quality gate.
   `authority/failover-policy.json` is the signed policy itself.

5. **The decision and the key release.** `authority/report.json`: the
   trigger (`heartbeat-timeout`, when the heartbeat was last seen rising,
   when silence became a decision), the genome chosen, the destination the
   key went to, the restore, the gate and the timing. The same events, as
   they were signed into the audit log: `authority/audit-events.jsonl`
   (`FAILOVER_DECIDED` → `CROSS_CLOUD_HANDSHAKE_INITIATED` →
   `CROSS_CLOUD_ATTESTATION_VERIFIED` → `KEY_RELEASE_AUTHORIZED` →
   `CROSS_CLOUD_RESTORE_COMPLETED`).

6. **What the GPU had to prove.** The `CROSS_CLOUD_ATTESTATION_VERIFIED`
   event's `destination_detail` in `audit-events.jsonl` says what the
   authority's verifier accepted: the AMD chip's report (product Genoa), the
   vTPM quote and its PCRs, and NVIDIA's word on the H100 (`GH100`, driver,
   VBIOS). The standby's signed receipt, `destination/genome-…receipt.json`,
   carries the same evidence; NVIDIA's attestation tokens in it are JWTs
   you can paste into any JWT decoder to read NVIDIA's claims, and NVIDIA's
   public key set as the authority fetched it is
   `authority/cache-nras-jwks.json`.

7. **That the model came back right.** In `report.json`, `restore.gate`:
   the restored model run on the H100 against 16 reference prompts sealed
   with it, the largest error measured, the tolerance, and the verdict the
   policy required.

8. **The operator's side.** `operator/orchestrator.log`: every line the
   orchestrating script printed, timestamped on the operator's laptop.

## B. Check the signatures offline (needs Go 1.27)

From a clone of this repository:

```bash
go run ./cmd/acpctl audit verify --audit scripts/hardware-test/failover-region-loss/evidence/<run>/authority/xcc-audit.db --audit-pubkey scripts/hardware-test/failover-region-loss/evidence/<run>/authority/audit.pem --audit-kid sagvd-audit-demo
```

It recomputes the hash chain and checks every event's signature; the tip it
prints must equal `audit_tip` in `report.json`. `FAILOVER_DECIDED` carries
the SHA-256 of the policy the authority acted on (`policy_sha256`, base64),
which ties the signed log to `failover-policy.json`.

## C. Run it again

```bash
bash scripts/hardware-test/failover-region-loss/run.sh <gcp-project> [primary-zone] [azure-rg]
```

Needs a GCP project with N2D quota in us-central1 and europe-west4, an Azure
subscription with `Standard NCCads2023 Family` quota (40 vCPUs) in West
Europe, `gcloud`, `az`, Go and an SSH key. About 25 minutes of the three
machines; the H100 (about $9 an hour) is most of the cost.

## What the drill does not show

- The power-off was self-inflicted: the machine switched itself off through
  the kernel's sysrq trigger, which cuts it off at once, without a
  shutdown — the closest a guest can come to losing power. It was not a
  real outage, and the deletion came after the power-off, not before it.
- "The region" is the primary's machine in us-central1. Nothing else in
  that region was touched, and the run's bucket was placed in europe-west4
  on purpose, as a real deployment would keep its replicas out of the
  region they protect.
- The model is small (Qwen2.5-0.5B with a LoRA adapter). The largest model
  the project has restored on this GPU is 32B, in a separate run.
- The intervals marked *across clocks* subtract one machine's clock from
  another's; the report's own intervals are each read on one clock.
- The operator's laptop carried the hand-offs and replicated the sealed
  bundles to the standby; in production that is a service.
- In the published run, generation 1 reached the standby 15 s after the
  power-off, from the bucket outside the region, 3.5 s before the key: the
  orchestrator's copy loop raced the primary's uploads. And the run's
  cleanup stopped early; the remaining machines and the bucket were deleted
  by hand minutes later. Both are written up in the README.
- Vault Genome is early-stage software with no external deployment and no
  third-party security audit.
