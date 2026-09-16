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

## Result — run `20260916T003940Z` (evidence/20260916T003940Z): the nine-stage flow on the chip

The same kit, with `sagvd` driving every gate job through the nine stages
(ADR 0015). us-central1-c, `n2d-standard-4`, kernel `7.0.0-1011-gcp`, both
daemons reading the same launch measurement from the chip — `7dc7c12e…25acc`,
the measurement of the previous run: same image, same firmware, same
guest. torch 2.7.1+cpu; the whole script took 104.6 s, of which 85.8 s
installed torch.

| Step | Outcome |
|---|---|
| `vg_genome finetune` + `acpctl genome seal` on the guest | 6 fixtures (4 critical), key id `genome-2e03f453db12-g0-d340d212fb2d` |
| A worker with a simulated TEE | **refused** at the Return Path handshake within 1 s; `TRUST_EVALUATED` deny is event 1 of the log |
| `POST /v1/jobs` | **202** — `request_id` `req-0fdaf42d…`, state `trust`; `REQUEST_RECEIVED` on the log before the id was returned |
| Trust Admission for the pinned worker | `TRUST_EVALUATED` **allow** — `trust.peer_attested`, `gcp-sev-snp`, measurement `7dc7c12e…25acc`, attestation TTL 330 s |
| Session, disclosures, manifest | `SESSION_ISSUED` pinned to `gate-policy/v1;atol=0.01;rtol=0.001;outliers=0`; **5** `DISCLOSURE_AUTHORIZED` (descriptor, `adapter_config.json`, `adapter_model.safetensors`, `genome.json`, `prompts.json`); `MANIFEST_ISSUED` naming the 5 disclosures, budget 666 bytes |
| The candidate | `CANDIDATE_RECEIVED` — 666 bytes, signed by `acp-compute-worker-demo` |
| Validation | `VALIDATION_STARTED`; three dimensions **pass** — operational (six sub-checks), semantic (`top1-agreement`, **6/6**), behavioral (`equivalence-ladder`, **EXACT**, `pinned replay`, rung 0, max abs err 0); `VALIDATION_COMPLETED` `vr-2c4a5672-…-0005` |
| Release decision | `RELEASE_DECIDED` then the signed decision `dec-d8aae5561985d288`: **release**, `validation_pass`, citing the attestation `att-2c4a5672-…-0001` and the event it follows; signed by `sagvd-authority-e2e` |
| The flow | state `release_authorized`, **10 transitions**, **4.48 s** from intake to seal (4.21 s from trust to decision); chain tip `019534c9…b543` |
| `acpctl audit verify` with the published key | **ok — 17 events**: the rogue's denial, then the sixteen of the flow, in order |
| Metrics | `sagvd_release_decisions_total{decision="release"} 1`, `sagvd_gate_verdicts_total{level="EXACT"} 1`, `sagvd_audit_events_total` summing to 17, `sagvd_handshake_failures_total{phase="handshake"} 1` |

`job.json` carries the whole flow: every transition with its time, the
signed attestation, session, manifest, validation result and release
decision, the disclosures' digests — verifiable offline under the keys in
`sagvd-identity.json`. Checksums: `cd evidence/20260916T003940Z && grep -v
' sha256sums.txt$' sha256sums.txt | shasum -a 256 -c` — 32 of 32 match.

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
