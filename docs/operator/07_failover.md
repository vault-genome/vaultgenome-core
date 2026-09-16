# Failover: sentinel, policy, executor

**Audience:** the operator of a primary running a model, its standby, and the release authority.
**Design:** [ADR 0012](../adr/0012-sentinel-and-policy-driven-failover.md); the limits on the primary's word, [ADR 0017](../adr/0017-limits-on-the-primarys-word.md); the sealed escrow key, [ADR 0016](../adr/0016-escrow-key-sealed-to-the-release-host.md).
**Builds on:** [06 — cross-cloud restore](06_cross_cloud_restore.md) (attested release, escrow, gate, receipts).

This runbook sets up the failover path. When the machine running a model is
attacked, or dies, the model comes back on a standby you chose in advance, from
the last genome sealed while that machine could still be trusted.

| Machine | Runs | Holds |
| - | - | - |
| Primary | the workload, `acpctl sentinel watch --tee …` | the sentinel seed; its TEE; the model's state; **no genome key** |
| Release authority | `sagvd failover` | the escrow key sealed to its TEE (unsealed in memory), the audit log, the operator's public key, the failover policy |
| Standby | `acp-bootstrap` with `genome` configured | a replica of the primary's outbox (ciphertext) |
| Operator's machine | `acpctl stop … / failover … / escrow recovery-keygen` | the operator seed and the escrow recovery seed (never on the release host) |

## 1. Keys

```bash
# Operator (once; the same key signs stop lists — see 06), and the escrow recovery key:
acpctl stop keygen --out operator.seed --pub operator.pem
acpctl escrow recovery-keygen --out recovery.seed --pub recovery.pem
# Release authority (once): its escrow key, made in its own process and sealed to its TEE;
# sealers pin the public half (06, ADR 0016).
sagvd escrow-provision -config sagvd.json -out /etc/acp/secrets/sagvd/escrow.sealed -pub escrow-local.pem \
  -recovery-to recovery.pem -recovery-out /etc/acp/secrets/sagvd/escrow.recovery
sagvd identity -config sagvd.json      # prints key_escrow_public_key_pem: give it to the primary
# Primary: the sentinel's signing key, and its TEE's identity; the operator pins both.
acpctl sentinel keygen --out /etc/acp/secrets/sentinel.seed --pub sentinel.pem
acpctl sentinel identity --tee gcp-sev-snp --key /etc/acp/secrets/sentinel.seed   # measurement_hex: pin it in the policy
```

Set `crosscloud.key_escrow_path` in the authority's config to the sealed file.
`sagvd failover` refuses to run without it, because genome keys reach the
authority only through escrow; it unseals the key at start, so a key that will
not open on this host is known before any trigger. If the host moved to another
chip, re-seal from the recovery envelope first (06).

## 2. The standby

Configure `acp-bootstrap` as in [06](06_cross_cloud_restore.md), with the genome
restorer and a **required** gate. Point `bundle_dir` at the replica of the
primary's outbox:

```json
"genome": {
  "bundle_dir": "/var/lib/acp/outbox-replica",
  "restore_dir": "/var/lib/acp/restored",
  "rescan_seconds": 2,
  "gate": { "command": ["/opt/vg/bin/python", "-m", "vg_genome", "door", "--genome", "{genome}", "--base", "/opt/base", "--device", "auto"],
            "env": ["PYTHONPATH=/opt/worker"], "atol": 0.01, "rtol": 0.001, "required": true }
}
```

Print its identity (`acp-bootstrap identity -config …`). Allow-list its
measurement on the authority, as for any destination.

## 3. The primary's sentinel

```bash
acpctl sentinel watch --content-dir /var/lib/model/genome \
  --outbox /var/lib/acp/outbox --escrow-to escrow.pem --key /etc/acp/secrets/sentinel.seed \
  --tee gcp-sev-snp \
  --tripwire /etc/acp/canary --tripwire /usr/local/bin/acpctl --tripwire /root/.ssh \
  --probe "systemctl is-active --quiet acp-workload" --interval 5s --settle 3s
```

- **The chip's word.** With `--tee gcp-sev-snp` (the sev-guest driver loaded
  and configfs-tsm mounted, as for any SEV-SNP daemon) every record the
  sentinel writes carries the primary TEE's report over its content; a
  policy that pins the primary accepts nothing without one. The sentinel
  writes no heartbeat and commits no seal its chip will not vouch for, so a
  chip that stops answering reads as silence at the authority. Start the
  sentinel with `--tee` before the policy pins it: generations sealed
  without the chip's word are set aside under a pinning policy.
- **What to seal.** Give `--content-dir` the directory the training process
  writes: a LoRA adapter, genome.json and fixtures (`workers/genome`), or a
  checkpoint. Give `--model` an Ollama model instead.
- **Tripwires.** Choose paths nothing legitimate changes:
  - a canary file no process reads;
  - credentials;
  - the sentinel's own binary;
  - directories an intruder would write to.

  Probes can be any command that exits 0 while the machine is sound. Every wire
  must pass when the sentinel starts, or it refuses to start.
- **Replication.** Copy the outbox to where the authority and the standby read
  it, and keep it copying, for example with `gcloud storage rsync` or `rclone` in
  a loop. Copy under a temporary name and rename, so no half-written file ever
  appears as `*.genome`. Everything in the outbox is ciphertext or a public
  record.
- **Exit codes.** 3 means a tripwire fired: the outbox is closed and holds
  `compromise.json`. 0 means it was stopped by SIGINT/SIGTERM, and its last
  heartbeat says `stopped`, so there is no failover. 1 means an error.

## 4. The failover policy

On the operator's machine:

```bash
acpctl failover issue --key operator.seed --kid operator-1 --serial 1 \
  --sentinel-pub sentinel.pem \
  --primary-kind gcp-sev-snp --primary-measurement <measurement_hex from acpctl sentinel identity> \
  --standby-kind gcp-sev-snp --standby-endpoint https://standby.internal:8443 \
  --standby-measurement <measurement_hex from the standby's identity> \
  --heartbeat-timeout 60s --stopped-grace 30m --quarantine 0s --max-rpo 1h --require-gate EQUIVALENT \
  --valid-for 720h --reason "primary us-central1 → standby us-east4" --out failover-1.json
acpctl failover verify --in failover-1.json --pubkey operator.pem --kid operator-1
```

- `--primary-kind` and `--primary-measurement` pin the primary's TEE
  ([ADR 0017](../adr/0017-limits-on-the-primarys-word.md)): a record from
  the outbox counts only with that chip's report on it. A stolen sentinel
  seed used anywhere else is silence, and silence is a trigger. The
  authority verifies the primary's reports with the anchors its verifier
  registry holds for that kind (the AMD chain, the VCEK cache), so the
  registry needs an entry for the primary's kind; fill `vcek_cache_dir`
  before arming, because a report the authority cannot verify is silence
  too. A simulated primary is pinned by its attestation key as well
  (`--primary-attestor-pub`).
- `--stopped-grace` bounds how long a sentinel that said `stopped` stands
  the authority down; not back watching within it, the primary fails over
  (`stopped-overdue`). Without it `stopped` is honoured indefinitely, and the
  primary's word can disarm the authority for good.
- `--heartbeat-timeout` must be well above the sentinel's `--interval` plus the
  replication delay.
- `--no-compromise-trigger` acts on lost heartbeats only.
- `--quarantine` distrusts genomes sealed this long before the trigger.
- `--max-rpo` declines rather than restore an old genome.
  A standby of another family — `--standby-kind azure-cgpu` for an Azure
  confidential GPU (ADR 0019), `--standby-kind gcp-tdx` for an Intel TDX
  Trust Domain (ADR 0018) — needs its own registry entry beside the
  primary's; `scripts/hardware-test/failover-cgpu` and
  `scripts/hardware-test/failover-tdx` run exactly that.

Copy the signed policy to the release host.

## 5. The executor

```bash
sagvd failover -config sagvd.json -policy failover-1.json -outbox /var/lib/acp/outbox-replica \
  -poll 2s -confirm-wait 15m -report /var/lib/acp/failover-1.report.json
```

- **At start.** It verifies the policy under `crosscloud.operator_stop`'s key.
  It unseals the escrow key on this host's TEE, checks that the policy stands
  and that the audit log shows it unspent, builds the primary's verifier when
  the policy pins one, then closes the audit log while it watches.
- **While watching.** It logs `failover watch` states: waiting for the first
  heartbeat, watching, standing down (for how much longer, under a grace). It
  ignores unsigned or foreign records — and, under a pinning policy, records
  without the primary chip's report, or with another chip's — and lists them
  in the report.
- **On a trigger.** It chooses the newest genome the trigger's own record
  vouches for — nothing sealed after the generation that record names — that
  was sealed before the trigger, minus the quarantine, and checks out (with
  the chip's report on it, under a pinning policy), and records
  `FAILOVER_DECIDED`, naming the primary's measurement when pinned. It then
  releases the escrowed key to the standby, under the stop list and allow-list,
  and confirms the receipt with the required gate. An outbox that holds the
  named generation as another bundle contradicts the sentinel: declined.
- **Exit codes.** 0: restored and confirmed, or stopped before any trigger.
  3: declined, with the reason in the report and on the log. 1: failed, for
  example an operator stop refused the release, or the standby did not restore.

Run it as a service that restarts on failure. A restart re-reads the policy and
the audit log, so a spent policy never runs twice. A failover that was decided
and then did not complete also spent its policy: for example, the standby was
down, or a stop refused the release. Sign a new policy to try again; this way no
key is ever released twice on one signature.

### Reading the report

| Field | Meaning |
| - | - |
| `trigger.kind`, `trigger.at` | `compromise-report` (when the sentinel detected it), `heartbeat-timeout` (the last heartbeat) or `stopped-overdue` (the stop that was not lifted in time), by the primary's clock |
| `trigger.primary_measurement_hex` | what the trigger record's TEE report attests, under a pinning policy |
| `ignored` | records that did not count: unsigned, foreign, or — under a pinning policy — without the primary chip's report |
| `trigger.tripped` | the wires that fired |
| `decision` | `failover` or `declined`, the reason, and the decision ID the release carries |
| `genome` | the generation restored, its bundle digest, key ID and seal time; `chain_end` is the newest verified generation in the outbox |
| `set_aside` | records not chosen, and why (after the sentinel's last word, after the cutoff, unattested, damaged, outside the chain) |
| `release.policy_version` | `…;failover=<serial>;revocation=<serial>` |
| `restore.gate` | the standby's gate verdict, signed by its TEE |
| `timing` | `detect_seconds`, `release_seconds`, `restore_seconds`, `gate_seconds`, `failover_seconds`, `rto_seconds`, `rpo_seconds` |
| `audit_tip` | the log's tip after the failover; verify with `acpctl audit verify` |

## 6. After a failover

The standby is now the primary. To protect it:

1. Start a sentinel there on a new outbox, continuing the chain:
   `--parent <the restored genome's bundle>`.
2. Choose the next standby and sign a new policy with a higher serial, pinning
   the new sentinel's key.

Until you do, nothing moves again. That is deliberate: every hop takes an
operator signature.

The old primary's outbox is closed by its compromise report. Keep it for the
incident review. `acpctl genome chain --dir` walks it offline.

## 7. Stopping a failover

- An operator stop list with `--all`, or revoking the standby's measurement,
  refuses the release at the next attempt, including one in progress. The
  refusal is recorded (`KEY_RELEASE_DENIED`).
- A newer policy serial retires older ones: the executor refuses a serial below
  the highest on record.
- Let the policy expire (`not_after`), or stop `sagvd failover`.

## 8. The drill

`test/integration/failover_test.go` runs the drill locally with the real
binaries: an intrusion (canary touched, model tampered), a primary killed
with SIGKILL, a primary attested by its (simulated) TEE and pinned in the
policy followed by a rogue sentinel with the stolen seed on another TEE
(ignored, declined), and a sentinel stopped and not back within the grace.
On hardware, `scripts/hardware-test/gcp-failover` runs the same across two
SEV-SNP confidential VMs, the authority's escrow key sealed to its chip.

---

_Document history: 2026-09-15 — first version, with ADR 0012. 2026-09-16 — the
sealed escrow key (ADR 0016); the primary's TEE pinned, the `stopped` grace,
the chain trusted only to the sentinel's last word (ADR 0017)._
