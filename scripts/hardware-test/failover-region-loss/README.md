# Continuity Drill, region loss: the primary's region goes dark without a word, and the model comes back on an attested confidential GPU in another cloud

The GPU leg of the continuity drill ([failover-cgpu](../failover-cgpu)) with
the failure that gives no warning. There is no intruder, no tripwire and no
compromise report: the primary's machine is **switched off while it trains**
— a power-off from inside through the kernel's sysrq trigger, no shutdown, no
signal to the sentinel, no `stopped` heartbeat — and the operator then
**deletes it and its disk**. The only sign of failure the release authority
ever gets is silence. Its policy has one trigger: **15 seconds without a
heartbeat**.

```bash
bash scripts/hardware-test/failover-region-loss/run.sh <gcp-project> [primary-zone] [azure-rg]
python3 scripts/hardware-test/failover-region-loss/timeline.py scripts/hardware-test/failover-region-loss/evidence/<run>
```

The machines are placed so that nothing the failover needs lives in the
region that goes dark:

| Role | Where | What |
| - | - | - |
| Primary | GCP `n2d-standard-8`, AMD SEV-SNP, **us-central1** (Iowa) | [`primary.sh`](primary.sh): fine-tunes Qwen2.5-0.5B-Instruct; the sentinel seals each generation with its key escrowed to the authority, attests every record with the chip and beats a signed heartbeat every 3 s; the outbox is replicated to the bucket. Then it goes dark in the middle of training generation 2. |
| Authority | GCP `n2d-standard-4`, AMD SEV-SNP, **europe-west4** (Netherlands) | [`authority.sh`](authority.sh): `sagvd failover`, its escrow key sealed to its chip; a policy pinning the primary's chip and the GPU standby, `heartbeat_timeout_seconds: 15`, no compromise trigger, gate EQUIVALENT required. |
| Standby | Azure `Standard_NCC40ads_H100_v5`, **West Europe** | [`../failover-cgpu/destination-cgpu.sh`](../failover-cgpu/destination-cgpu.sh), unchanged: `acp-bootstrap` as `azure-cgpu` (the chip's report from the vTPM, a TPM quote per challenge, NVIDIA's tokens for the H100), the door on the GPU. |
| Bucket | GCS, **europe-west4** | The run's private hand-off and replication bus, outside the region that goes dark; deleted with the run. |

[`run.sh`](run.sh) is the operator's hands, as in the GPU leg: it builds
and uploads, brings the three machines up, carries the authority's TLS
material and token to the standby and the standby's identity back, and
replicates every sealed bundle from the primary's outbox to the standby. It
adds three things: once the primary has gone dark it **watches Google report
the machine stopped, records Google's own `lastStopTimestamp`, deletes the
machine and its boot disk, and asks again until Google answers that it does
not exist** (`operator/operator-destroy.txt`); it reads **Google's audit
log** for the primary — its creation, the guest's power-off, the deletion —
keeping the times and methods and leaving out who called and from where
(`operator/gcp-audit-primary.json`); and it writes `topology.txt`. The
authority now also keeps the **audit log file itself** (`xcc-audit.db`, with
`audit.pem`), so anyone can verify it offline, and the primary's **last
heartbeat** as it arrived (`last-heartbeat.json`): the last thing the
machine said.

**Design:** [ADR 0012](../../../docs/adr/0012-sentinel-and-policy-driven-failover.md)
(the heartbeat trigger: the timeout runs on the release authority's clock,
from the moment it last saw the heartbeat's sequence number rise, so no
clock skew between the machines moves it),
[ADR 0019](../../../docs/adr/0019-a-confidential-gpu-worker-on-azure.md),
operator runbook [07](../../../docs/operator/07_failover.md). The unit
test of the same path is `TestFailoverOnLostHeartbeat`
(`internal/vault/failover`): "a primary that dies without a word".

## The scenario

1. The authority provisions itself on its chip and publishes its escrow
   public key (for the primary) and its TLS material and token (for the
   standby, through the orchestrator).
2. The standby is onboarded and comes up as `acp-bootstrap` on the H100;
   its launch measurement and vTPM PCR digest are handed to the authority.
3. The primary fine-tunes generation 0; the sentinel seals it and starts
   beating.
4. The operator signs the failover policy: the primary's sentinel key and
   chip; the standby (kind `azure-cgpu`, its endpoint, its launch
   measurement); **one trigger, no heartbeat for 15 s**; `stopped` honoured
   for 60 s; gate EQUIVALENT. `sagvd failover` arms.
5. The primary keeps training: generation 1 is sealed and replicated to the
   bucket and on to the standby. Generation 2 starts training.
6. **The region goes dark.** Fifteen seconds into generation 2 the primary
   uploads its evidence, writes the moment by its own clock and switches
   itself off. The operator sees Google report it `TERMINATED`, deletes it
   and its disk, and Google answers that it no longer exists.
7. The authority sees the heartbeat stop rising. After 15 s of silence on
   its own clock it chooses the newest trustworthy genome — generation 1,
   every record carrying the primary chip's report — records
   `FAILOVER_DECIDED`, opens a handshake to Azure over mTLS, verifies the
   standby's chip, vTPM and GPU under one nonce, releases the key and
   waits for the receipt: the standby restores the genome, runs the door on
   the H100 and signs for the result with its evidence. The authority
   confirms it on the record. Generation 2, unsealed, is lost with the
   region; that loss is the RPO.

## Results — run `20260930T194321Z`

Three live confidential machines, two clouds, two continents; the model of
the failover drill (Qwen2.5-0.5B-Instruct, LoRA r8, float32 on the
primary's CPUs). `python3 timeline.py evidence/20260930T194321Z` prints the
whole run; its output is `evidence/20260930T194321Z/TIMELINE.txt`.

**Machines** (`topology.txt`, `*/metadata.txt`, `*/system.txt`,
`destination/conf-compute.txt`, `destination/gpu.csv`):

- Primary: GCP `n2d-standard-8`, **us-central1-c**, AMD EPYC 7B13 (Milan),
  `Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP`. Launch
  measurement `10f5ac22…4519`; sentinel `sentinel-817ea94c4cbacaf5`, run
  from its seed sealed to the chip (`primary/steps.txt`: `sentinel
  seal-key exit=0 tee=gcp-sev-snp sealed=True`).
- Authority: GCP `n2d-standard-4`, **europe-west4-a**, SEV-SNP. Launch
  measurement `21199b36…9546`; `key_escrow_storage: sealed:gcp-sev-snp`;
  every key file of both configs sealed (`authority/steps.txt`).
- Standby: Azure `Standard_NCC40ads_H100_v5`, **West Europe**, Ubuntu
  24.04.5 CVM, kernel `7.0.0-1013-azure-fde`, NVIDIA H100 NVL, driver
  595.91.07, VBIOS 96.00.9F.00.04, `CC State: ON`, `CC GPUs Ready State:
  Ready`; torch 2.7.1+cu126. Launch measurement `11920f61…91c4`, vTPM PCR
  digest (sha256:0–14) `1e80d1d3…3f7a`; its TLS key and bearer token sealed
  to the vTPM (`destination/steps.txt`).

**The operator's policy** (`authority/failover-verify.txt`): serial 1, the
primary's sentinel and chip, standby `azure-cgpu https://…:8443` at
`11920f61…91c4`; triggers: **no heartbeat for 15s**, stopped and not back
within 60s — no compromise trigger; required gate EQUIVALENT.

**The primary's last minutes** (`primary/steps.txt`, `sentinel.log`,
`finetune-*.json`, `authority/last-heartbeat.json`,
`operator/primary-destroyed-at.txt`): generation 0 sealed at 19:51:39Z,
generation 1 (160 steps, loss 5.33 → 0.0009) sealed at **20:01:36.11Z**;
generation 2 started training at 20:01:45Z. The last heartbeat that ever
left the machine is **#209, sent 20:01:57.12Z**, `status: watching`, newest
sealed generation 1, signed and carrying the chip's report. At
**20:02:02.46Z** by its own clock the machine switched itself off;
`steps.txt` records generation 2 *still training* and the sentinel
running. Generation 2's log ends at `step 11/160`: it was never sealed and
was lost with the machine.

**The region goes dark, in Google's words** (`operator/operator-destroy.txt`,
`operator/gcp-audit-primary.json`): Google's API kept reporting the machine
`RUNNING` until 20:02:55.7Z; its audit log records
`compute.instances.guestTerminate` at **20:02:55.70Z** and its
`lastStopTimestamp` is **20:03:05.67Z**; `TERMINATED` at 20:03:08Z. The
operator deleted it and its boot disk (20:03:09–20:03:14Z, two
`v1.compute.instances.delete` entries in the audit log), and at 20:03:16Z
Google answered that the machine *was not found*; no disk of that name was
left.

**The failover** (`authority/report.json`, `failover.log`,
`audit-events.jsonl`, `destination/acp-bootstrap.log`, `*.receipt.json`):

| | |
| - | - |
| Silence | the authority last saw the heartbeat rise at 20:02:02.62Z |
| Trigger | `heartbeat-timeout` observed at **20:02:17.64Z** — 15.01 s of silence on the authority's clock; `ignored: none` |
| Decision | `FAILOVER_DECIDED` at 20:02:17.67Z: *heartbeat-timeout under failover policy serial 1: restore generation 1 on the standby* |
| Handshake | over the Internet, mTLS + bearer token, to the H100 host: its SEV-SNP report from the vTPM (Genoa), the TPM quote with the PCR digest matching the pin, NVIDIA's tokens for the H100 — and the verifier's own evaluation of the H100's report (ADR 0021: chain, signature, firmware id, the driver's and the VBIOS's signed reference manifests, 64 measurements each matched, revocation checked good) — `CROSS_CLOUD_ATTESTATION_VERIFIED` at 20:02:20.50Z |
| Key release | `KEY_RELEASE_AUTHORIZED` at 20:02:20.50Z, `destination_kind: azure-cgpu`, `destination_measurement_hex: 11920f61…91c4` |
| Genome restored | **generation 1** (key `genome-8d051d16995a-g1-8e4139a8ab72`, bundle 2,216,819 bytes); 5 files, 2,210,917 bytes, tree `3d7d4a57…ea1a`, in **9.8 ms** |
| Gate on the H100 | **EQUIVALENT** — door native float on `cuda`, 16 fixtures, max abs err **1.52e-4**, max rel err 1.65e-5 (atol 1e-2, rtol 1e-3), 6.75 s; required: EQUIVALENT |
| Receipt | signed by the standby with its `azure-cgpu` Evidence; the key erased on the standby after the restore; `CROSS_CLOUD_RESTORE_COMPLETED` at **20:02:28.60Z** |
| Detect | **15.01 s** (the policy's timeout, on the authority's clock) |
| Release | 2.87 s (trigger → key release, the GPU host attested in between) |
| Failover | **10.96 s** (trigger → confirmed, gated restore) |
| RTO | **25.97 s** (last heartbeat seen → a gated, confirmed model on the GPU in another cloud) |
| RPO | **21.01 s** (last heartbeat less generation 1's seal: generation 2's unsealed training) |
| Audit | 5 events — `FAILOVER_DECIDED` → `CROSS_CLOUD_HANDSHAKE_INITIATED` → `CROSS_CLOUD_ATTESTATION_VERIFIED` → `KEY_RELEASE_AUTHORIZED` → `CROSS_CLOUD_RESTORE_COMPLETED`; tip `3488b31c…153f`, verified on the authority (`audit-verify.json`) and again offline from `xcc-audit.db` with `acpctl audit verify` |

Across clocks (the primary's and the authority's keep Google's time):
power-off → trigger **15.18 s**, power-off → confirmed restore **26.14 s**.
The model was back, gated and confirmed on the H100 **27.1 s before
Google's audit log recorded the guest's termination** and 37.1 s before
Google's `lastStopTimestamp` for the machine.

**Two things this run did not do as designed, on the record.**

- *Generation 1 reached the standby after the power-off.* The
  orchestrator's copy loop (the operator's hands, not the product) polls
  the replica with `gcloud storage cp` and discards its errors; the
  likeliest cause is that its downloads raced the primary's re-uploads of
  the same object, every few seconds while the primary lived, and the loop
  kept retrying until the uploads stopped. Generation 1 landed on the
  standby at 20:02:17.0Z (`operator/orchestrator.log`), from the bucket in
  europe-west4 that the loss of the primary did not touch — 3.5 s before
  the key. A replication that pushes each sealed bundle once would not
  race.
- *The cleanup stopped at its first line.* Under `set -e` it read the zone
  file of the primary, which the run had already deleted and whose file it
  had removed, and ended; the authority, the bucket and the H100 VM were
  left running. They were deleted by hand at once — the Azure VM's delete
  succeeded at 20:06:57Z, the authority's at 20:08:53Z, then the bucket —
  and a listing of both clouds showed nothing left. `run.sh` as committed
  runs the cleanup with `set +e`; it differs from the script of this run
  only there.

**Cost.** About 23 minutes of the H100 VM (~$9/h) and 25 of the two GCP
machines: under $5.

## Evidence files

As in the GPU leg ([failover-cgpu](../failover-cgpu/README.md#evidence-files)),
with these differences:

- `primary/` — no `attack-at.txt`, and `sentinel.json` is empty: the
  sentinel never exited, it was switched off. `finetune-2.json` is empty
  and `finetune-2.log` ends mid-training, for the same reason.
- `authority/` — adds `last-heartbeat.json` (the primary's last word as it
  arrived), `xcc-audit.db` and `audit.pem` (the audit log and its key, for
  an offline check).
- `operator/` — `primary-destroyed-at.txt` (the moment by the primary's
  clock), `operator-destroy.txt` (Google's status, record, deletion and
  "not found", timed on the operator's laptop),
  `gcp-audit-primary.json` (Google's audit log entries for the primary,
  without caller identity or address), `orchestrator.log` (every line the
  orchestrator printed, timed on the operator's laptop; local paths
  replaced with `<repo>` and `<build>`).
- `topology.txt`, `TIMELINE.txt`.

How to check all of it without us: [VERIFY.md](VERIFY.md).

## Scope

This proves a governed failover on a lost heartbeat alone: the primary
said nothing, the authority acted on 15 s of silence under a policy signed
in advance, and the key went only to the attested GPU the policy named. It
does not prove survival of a real regional outage: one machine in
us-central1 was switched off from inside and deleted; nothing else in that
region was touched, and the bucket was placed outside it on purpose. The
heartbeat timeout trades speed against false alarms; 15 s held here
through a fine-tune that saturated the primary's CPUs (generation 1) and
the start of another, and is not a recommendation. Model
size, the GPU's measurements and the other limits are those of the GPU leg
([failover-cgpu, Scope](../failover-cgpu/README.md#scope)).
