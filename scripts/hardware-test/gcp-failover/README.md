# Continuity Drill, failover leg: a model moves itself off a compromised machine

This is the whole promise of the platform in one run, on real hardware: a
model is fine-tuned on one machine; that machine is attacked; and the model
comes back on another — as it was just before the attack, nowhere the
operator did not choose, with attestation on both ends.

```bash
bash scripts/hardware-test/gcp-failover/run.sh <gcp-project> [zone]
```

`run.sh` builds `sagvd`, `acp-bootstrap`, `acpctl` and `keygen` for
linux/amd64, packs `workers/genome`, and boots two AMD SEV-SNP Confidential
VMs in the same project:

- The **standby** ([`standby.sh`](standby.sh)) hosts the **release authority**
  (`sagvd failover`) and the **destination** (`acp-bootstrap`), on loopback
  TLS. It generates the authority's escrow key, hands its public half to the
  primary, and — under an operator-signed failover policy — waits, watching a
  replica of the primary's outbox and holding a warm copy of every sealed
  genome.
- The **primary** ([`primary.sh`](primary.sh)) runs the workload and, beside
  it, the **sentinel** (`acpctl sentinel watch`). It fine-tunes a real model,
  the sentinel seals each state as the next generation of a genome chain —
  each key encapsulated only to the authority's escrow key — and the outbox is
  replicated to a bucket. Then the machine is attacked.

Reports come back to `evidence/<stamp>/`; both VMs and the bucket are deleted
on every exit. The genome key never crosses in the clear: it lives on the
primary only as an escrow envelope, which the authority opens and re-wraps to
the standby's attested per-handshake key (ADR 0009, 0011, 0012).

**Design:** [ADR 0012](../../../docs/adr/0012-sentinel-and-policy-driven-failover.md),
operator runbook [07](../../../docs/operator/07_failover.md).

## The scenario

1. The standby provisions the authority and publishes its escrow public key.
2. The primary fine-tunes generation 0 (Qwen2.5-0.5B-Instruct, LoRA r8, 120
   steps); the sentinel seals it and replicates the outbox.
3. The operator signs a failover policy pinning the primary's sentinel key and
   the standby's SEV-SNP measurement, requiring an EQUIVALENT gate. The
   authority arms `sagvd failover`.
4. The primary keeps training: generation 1 (160 steps). The sentinel seals it.
5. **The attack.** A tripwire file is touched and the adapter is overwritten
   with garbage. The sentinel checks its wires before it would seal, so it
   never seals the tampered state: it writes a signed compromise report naming
   generation 1 as the last good one, and exits 3.
6. The authority sees the compromise in the replica, chooses generation 1,
   records `FAILOVER_DECIDED`, releases its escrowed key to the standby — which
   attests with its own chip, restores the genome, recomputes the sealed
   fixtures to prove the model works, and signs a receipt — and confirms it.

## Results — run `20260915T021334Z`

**Machines**, both AMD SEV-SNP Confidential VMs (`Memory Encryption Features
active: AMD SEV SEV-ES SEV-SNP` in each `system.txt`):

- Primary: GCP `n2d-standard-8`, us-central1-c — trains and runs the sentinel.
- Standby: GCP `n2d-standard-4`, us-central1-c — the authority and the
  destination. Its SEV-SNP measurement is 48 bytes (`7dc7c12e5599…`).

The primary sealed two generations (120 then 160 steps), then was attacked at
02:21:56Z. The sentinel's report: `outcome: compromised`, `generations_sealed:
2`, last generation 1; it exited 3.

**The failover** (`standby/report.json`)

| | |
| - | - |
| Trigger | compromise report; tripwire `/root/canary` |
| Genome restored | **generation 1** — the last sealed before the attack (key `genome-05902f943176-g1-fa3ca0af732e`), **not** the tampered state |
| Gate on the standby | **EXACT** — door "pinned replay", 16 fixtures, max abs err 0 (required: EQUIVALENT) |
| Restore | 5 files, 2,202,926 bytes, in **13.2 ms** |
| Detect | **2.53 s** (last heartbeat seen → the authority acting) |
| RPO | **9.0 s** (attack − generation-1 seal time) |
| RTO | **16.81 s** (failure → a confirmed, gated restore on the standby) — of which the standby's gate ran the model for 13.5 s |
| Audit | 5 events — `FAILOVER_DECIDED` → handshake → attestation → `KEY_RELEASE_AUTHORIZED` → `CROSS_CLOUD_RESTORE_COMPLETED`; `audit-verify.json` says the log verifies |

`release.policy_version` is `failover-policy-v1;failover=1;revocation=1`: the
release passed the operator stop, then the failover policy (standby only),
then the allow-list. The restored adapter (`restored-adapter-head.txt`) is the
generation-1 safetensors — binary weights, not the ASCII bytes the intruder
planted.

**Attestation on both ends.** The primary and the standby are both SEV-SNP
confidential VMs. The release handshake verifies the standby's live SEV-SNP
quote (VCEK → ASK → ARK, the ADR 0009 challenge binding its per-handshake
key) before any key leaves the authority.

**RTO/RPO in context.** RPO is bounded by the sentinel's seal cadence and the
outbox replication lag (here ~9 s of "newer" training the standby did not
have). RTO is dominated by the gate: the standby spent 13.5 s proving the
model works before it signed for it — a deliberate cost, not overhead. The
key release and the restore themselves took under 0.3 s together.

## Evidence files

- `primary/` — `finetune-0.json`, `finetune-1.json` (the two fine-tunes),
  `sentinel.json` (the sentinel's final report: outcome, the generation it
  last sealed, the wires that fired), `attack-at.txt`, `system.txt` (with the
  SEV-SNP boot lines), `steps.txt`, `console.log`.
- `standby/` — `report.json` (the failover report), `authority-identity.json`
  and `destination-identity.json`, `failover-verify.txt` (the signed policy),
  `audit-verify.json` (the log checked offline), `restored-adapter-head.txt`
  (the restored generation's bytes, to show it is the clean one),
  `tsm.txt` (configfs-tsm), `steps.txt`, `console.log`, `acp-bootstrap.log`,
  `failover.log`.

The evidence holds no key, seed, token or config. The genome key crossed only
as an escrow envelope through the run's private bucket, which was deleted with
the VMs; it was wiped on the standby once the restore was signed for.

## Scope

This proves the failover mechanism and attestation on real hardware. Both
machines are CPU confidential VMs. An attested GPU standby needs confidential
GPUs (H100 CC), a TDX producer and verifier — not tested yet. CPU→GPU fidelity
is measured separately in [`gcp-drill`](../gcp-drill).
