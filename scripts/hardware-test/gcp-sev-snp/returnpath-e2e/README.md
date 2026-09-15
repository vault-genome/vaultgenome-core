# The Return Path on real AMD SEV-SNP

The shipping `sagvd` and `acp-compute`, run end to end on one Google
Confidential VM (`n2d-standard-4`, AMD Milan, SEV-SNP, Ubuntu 24.04), both
attesting with the chip and each pinning the other's launch measurement
(ADR 0014), with the real `vg_genome` worker and its door (ADR 0013):

- the worker fine-tunes a tiny model on the guest with the pinned torch
  (`python -m vg_genome finetune`) and `acpctl genome seal` seals the genome
  (v3: its key in a separate file);
- `sagvd identity` and `acp-compute identity` read each side's 48-byte launch
  measurement from the chip through configfs-tsm; each is written into the
  other's `tee.peer.measurement_path`;
- a worker that is **not** the pinned identity — same certificate, same
  sealing key, a simulated TEE instead of the chip — dials the Return Path
  and is refused at the handshake; the refusal is on `sagvd`'s audit log;
- the pinned worker dials, its SEV-SNP Evidence verifies (VCEK from AMD KDS,
  ECDSA-P384, VCEK → ASK → ARK-Milan, no DEBUG, VMPL 0, REPORT_DATA binding
  the transcript challenge), a gate job goes over the Return Path, the
  worker restores the model in memory through the door and answers the
  genome's prompts, `sagvd` judges the answers and signs the verdict;
- both daemons stop; `acpctl audit verify` verifies the log under the key
  `sagvd identity` published, and `acpctl audit query` reads every decision
  in order.

Both processes run inside the same guest here; what the run proves is that
the Return Path handshake carries genuine hardware Evidence on both sides,
that the pinned identity is the one admitted, and that every decision of
the authority is on a verifiable record before it took effect.

## Result — run `20260915T230907Z` (evidence/20260915T230907Z)

us-central1-c, `n2d-standard-4`, kernel `7.0.0-1011-gcp`; `tsm.txt` shows
`SEV SEV-ES SEV-SNP` active and the guest at VMPL0. Both daemons read the
same launch measurement from the chip — one guest, one measurement —
`7dc7c12e…25acc` (48 bytes). Runtime on the guest: torch 2.7.1+cpu,
transformers 4.53.2, safetensors 0.5.3. The whole script took 176.7 s, of
which 156.5 s installed torch.

| Step | Outcome |
|---|---|
| `vg_genome finetune` on the guest | tiny random Llama (2 layers, hidden 32) + LoRA on `q_proj,v_proj,lm_head`: 2 384 adapter parameters, 20 steps, loss 3.713 → 2.348, 0.233 s of training, 6 fixtures (4 critical) |
| `acpctl genome seal` | payload 21 504 bytes → 22 676-byte bundle, 5 components, key id `genome-cbb574c0be4a-g0-a34d19f47e2a`, key in a separate file |
| `sagvd identity` / `acp-compute identity` | provider `gcp-sev-snp`, measurement `7dc7c12e…25acc` on both; each written into the other's `tee.peer.measurement_path` |
| `sagvd` on SEV-SNP | ready 1 s after start; audit log opened empty, tip `0000…`; gate jobs enabled |
| A worker with a simulated TEE (same certificate, same sealing key) | **refused** at the Return Path handshake within 1 s: `client TEE evidence verification failed: … evidence shorter than SEV-SNP report (1184 bytes)`; `TRUST_EVALUATED` **deny** (phase `handshake`) is event 1 of the log; the worker got no job |
| The pinned worker on SEV-SNP | session opened at once, `peer_measurement` = the pin |
| `POST /v1/jobs` | **202**, job `306e9d3e…`; 14 332 bytes of model side shipped (4 files), output budget 666 bytes; `MANIFEST_ISSUED` before the id was returned |
| The gate | **EXACT** — `pinned replay`, rung 0, **6/6** fixtures exact, max abs err 0; signed by `sagvd-authority-e2e`; the candidate (666 bytes) signed by `acp-compute-worker-demo`; **4.30 s** from accept to verdict |
| `acpctl audit verify` with the published key | **ok** — 7 events, tip `f6e1dc8f…1874` |
| `acpctl audit query` | in order: `TRUST_EVALUATED` deny → `MANIFEST_ISSUED` → `TRUST_EVALUATED` allow (with the peer's measurement) → `CANDIDATE_RECEIVED` → `VALIDATION_STARTED` → `VALIDATION_DIMENSION_EVALUATED` (behavioral, EXACT) → `VALIDATION_COMPLETED` (pass, verdict SHA-256 `6bd96d5b…`) |
| Metrics | `sagvd_handshake_failures_total{phase="handshake"} 1`, `sagvd_gate_verdicts_total{level="EXACT"} 1`, `sagvd_audit_events_total` summing to 7, `sagvd_sessions_opened_total 2` (the worker reconnected for a next job after the first) |

The one thing the log does **not** carry is the SEV-SNP report itself: the
handshake verified it live (VCEK from AMD KDS, chain to ARK-Milan, policy,
REPORT_DATA binding) and recorded the peer's provider and measurement. For
a chip-signed artefact that verifies offline, see the receipt in
[`../keyrelease-e2e/`](../keyrelease-e2e/README.md).

Checksums: `sha256sums.txt` was computed on the guest with absolute paths;
verify with

```bash
cd evidence/20260915T230907Z && sed 's#/root/e2e/out/[^/]*/##' sha256sums.txt | grep -v ' sha256sums.txt$' | shasum -a 256 -c
```

31 of 32 files match; `steps.txt` does not, because that run's script
appended its last line (`== emit`) after the checksums were taken — the
script now takes them last, and the evidence is kept exactly as captured.

## What the evidence holds, and what it does not

`evidence/<stamp>/` is what the guest printed on its serial console:
`sagvd-identity.json` and `acp-compute-identity.json` (public keys,
provider, measurement), `seal.json`, `finetune.json`, `job-submit.json`,
`job.json` (the job view with the signed verdict), `audit-verify.json`,
`audit-events.jsonl` (every event with its payload), `audit-public-key.pem`,
both daemons' logs, the rogue worker's log, metrics, the runtime versions,
`tsm.txt` and `kernel.txt`, `steps.txt` with the timings, and
`sha256sums.txt` over all of it. Keys, seeds, the API token, the sealed
bundle's key file and the configs stay on the VM and die with it: the VM
and the bucket are deleted at the end of every run, also on failure.

## Reproduce

```bash
scripts/hardware-test/gcp-sev-snp/returnpath-e2e/run.sh <gcp-project> [zone]
```

`gcloud` logged in to a project with the Compute Engine and Cloud Storage
APIs enabled; about fifteen minutes and a few cents of `n2d-standard-4`.
The AMD Milan chain comes from `../keybind-evidence/20260913T222343Z/`.
The raw serial capture is kept under `~/.cache/vaultgenome/returnpath-e2e/`
(override with `VG_E2E_RAW_DIR`); `decode-results.sh` verifies the tarball's
size and SHA-256 against the header the guest printed before unpacking it.
