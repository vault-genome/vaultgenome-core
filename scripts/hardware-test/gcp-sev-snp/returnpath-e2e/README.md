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
- `sagvd seal-keys` and `acp-compute seal-keys` seal every key file on disk
  to this host — with the chip's derived key, or with the guest's vTPM when
  the kit runs with `VG_SEALER=tpm2` (`tee.sealer`, ADR 0025 step 1b) — and
  both daemons start from the sealed files;
- a thief with those sealed files and no chip (a simulated TEE) is refused
  before any key is read; a worker that is **not** the pinned identity —
  the plaintext copies of the signing seed, the TLS key and the sealing key
  taken before sealing, the same certificate, a simulated TEE instead of the
  chip — dials the Return Path and is refused at the handshake; the refusal
  is on `sagvd`'s audit log;
- the pinned worker dials, its SEV-SNP Evidence verifies (VCEK from AMD KDS,
  ECDSA-P384, VCEK → ASK → ARK-Milan, the TCB against the floors AMD's
  bulletins set for the chip's variant with the alias check and the
  mitigation vector — ADR 0033 — no DEBUG, no MIGRATE_MA, VMPL 0,
  REPORT_DATA binding the transcript challenge), a gate job goes over the
  Return Path, the
  worker restores the model in memory through the door and answers the
  genome's prompts, `sagvd` judges the answers and signs the verdict;
- both daemons stop; `acpctl audit verify` verifies the log under the key
  `sagvd identity` published, and `acpctl audit query` reads every decision
  in order.

Both processes run inside the same guest here; what the run proves is that
the Return Path handshake carries genuine hardware Evidence on both sides,
that the pinned identity is the one admitted, and that every decision of
the authority is on a verifiable record before it took effect.

## Results — runs `20261021T212451Z` (cnsa) and `20261021T213945Z` (fips): `VG_FIPS=1` — the certified module with enforcement on (ADR 0030, part two)

The same kit with every binary built on the certified Go Cryptographic
Module v1.0.0 (`GOFIPS140=v1.0.0`) and every Go process on the guest
under `GODEBUG=fips140=only`, in which a non-approved service fails
instead of succeeding; the profile `cnsa` — the kit's third argument,
new — in `sagvd`'s configuration. us-central1-c, `n2d-standard-4`, the
image of every run since September (measurement `7dc7c12e…25acc`), the
tree `a6b33a2`. The whole script took **131.3 s** (runtime from the locks
81.8 s). The kit's verdict is new too: it requires both rogues refused,
the session opened, the job `succeeded` with the gate EXACT and the audit
log verified — and, under the flag, the record of the module on every
process.

| Step | Outcome |
|---|---|
| The record of the module | `versions.txt`: `sagvd`, `acp-compute` and `acpctl` each `fips140=only module=v1.0.0 enforced=true`; `steps.txt`: `fips=1 GODEBUG=fips140=only`, `sagvd fips140 enabled=true enforced=true version=v1.0.0` and the same for `acp-compute`; `build.txt` (the runner's, outside the guest's sums): every binary `GOFIPS140=v1.0.0-c2097c7c` at `a6b33a2` |
| The profile | `steps.txt`: `profile=cnsa`, `sagvd crypto_profile=cnsa kem_suites=hpke-mlkem1024-p384-v2` |
| `seal-keys` | both daemons, `sealer=sev-snp-derived-key`: 5 files and 2 files |
| A thief with the sealed files, off the chip | **refused**: `exit=1 sealed to gcp-sev-snp, this host is simulated` |
| A worker that is not the pinned identity | **refused** at the handshake after 1 s, on the record |
| The gate job | the session opened after 8 s; `succeeded` after 5 s, **EXACT**, pinned replay, rung 0, 6 of 6, max abs err 0, signed by `sagvd-authority-e2e` |
| `acpctl audit verify` | **ok** — 17 events |

The `fips` run, `evidence/20261021T213945Z`, is the same under
`hpke-p384-v2` (`sagvd crypto_profile=fips kem_suites=hpke-p384-v2,
hpke-mlkem768-v2,hpke-mlkem1024-p384-v2`): **128.9 s** (runtime from
the locks 79.0 s), both rogues refused, the session opened after 8 s,
the job `succeeded` after 5 s with the gate EXACT 6 of 6, 17 events
verified, the three version lines and both identities on the module.
The two guests ran minutes apart on the same image. (A third run, under
`fips` in the same second as the `cnsa` one, named its record by its
own clock and the decode of the later guest overwrote the earlier
record; since then the guest names the record by the runner's stamp,
`vg-stamp`, unique per run.)

## Result — run `20261015T194325Z`: `tee.sealer: "tpm2"` — the guest's vTPM seals the key files, beside the chip

The same kit with both daemons' key files sealed by the guest's vTPM
instead of the chip's derived key — `VG_SEALER=tpm2` puts `tee.sealer:
"tpm2"` into both configs (ADR 0025, step 1b), the guest installs
tpm2-tools, and after the identities are read `sagvd seal-keys` and
`acp-compute seal-keys` seal every key file on disk. The sealing step is
new to the kit — until this run its comment promised sealing that no step
performed — and so is the first of the two rogues below. us-central1-c,
`n2d-standard-4`, the image of every run since September (measurement
`7dc7c12e…25acc`, `tee.provider: "auto"` → `sev_guest`). The whole script took
**112.9 s** (runtime from the locks 78.3 s, fine-tune 9.4 s).

| Step | Outcome |
|---|---|
| The vTPM | `vtpm.txt`: `/dev/tpm0`, `/dev/tpmrm0`, `TPM2_PT_MANUFACTURER` `0x474F4F47` ("GOOG") |
| `seal-keys` | `seal-keys-sagvd.json`: `sealer: tpm2`, 5 files (`keys.authority_signing.seed_path`, `keys.session_sealing.material_path`, `keys.audit_signing.seed_path`, `vault.tls.server_key`, `http_api.bearer_token_file`); `seal-keys-worker.json`: `sealer: tpm2`, 2 files, the shared sealing material already sealed |
| The sealed files | `sealed-files.txt`: all 7 name `tee: gcp-sev-snp`, `sealer: tpm2` — the sealer is in the seal, not only in the file |
| The daemons, from the sealed files | both start from them; `sagvd identity` and `acp-compute identity` print `sealer: tpm2` / `tpm2` |
| A thief with the sealed files, off the chip | **refused before any key is read**: `rogue-sealed-worker.log` — `sealed secret 'keys.worker_signing.seed_path': sealed to gcp-sev-snp, this host is simulated`; `steps.txt`: `exit=1 sealed to gcp-sev-snp, this host is simulated` |
| A worker with a simulated TEE and the plaintext copies | **refused** at the handshake after 1 s (`integrity[signature_invalid]: gcp-sev: evidence shorter than SEV-SNP report (1184 bytes)`), on the record — the handshake proof of every run, kept |
| The gate job | `succeeded`, **EXACT**, pinned replay, rung 0, 6 of 6, max abs err 0, signed by `sagvd-authority-e2e`; 8.8 s |
| `acpctl audit verify` | **ok — 17 events**, tip `d7d523b1…` |


## Result — run `20261015T143033Z`: the AMD chain fetched on the guest, the keys provisioned privately

The same kit on the tree of the self-contained release (`e0b3fed`, #96),
with two changes on the guest: the AMD Milan chain is no longer uploaded
from this tree but fetched on the guest from AMD KDS by `acpctl tee
fetch-amd-chain`, which verifies it against the roots the binary pins
before writing it (ADR 0024; `amd-chain.txt`: 4602 bytes, ASK `SEV-Milan`,
ARK `ARK-Milan` sha256 `69d063b4…0bcd`; `inputs.sha256`: the chain's
sha256 `22e62f8d…1ce6`, the same bytes as the fixture
`internal/shared/tee/testdata/amd/kds-Milan-cert_chain.pem` read from
KDS that morning); and the key material is provisioned by `acp-keygen
-private` (0600 files in 0700 directories), the helper built from
`cmd/acp-keygen` and reporting its version next to the daemons'
(`versions.txt`). us-central1-c, `n2d-standard-4`, the launch measurement
`7dc7c12e…25acc` as in every run since September.

| Step | Outcome |
|---|---|
| Runtime install from the locks | 80.7 s |
| Fine-tune + seal | 9.9 s; key id `genome-7b3d5aa7528e-g0-953b38e33127` |
| The unpinned worker | refused at the handshake after 1 s |
| The gate job | `succeeded`, **EXACT**, pinned replay, rung 0, 6 of 6, max abs err 0, signed by `sagvd-authority-e2e`; 5.2 s |
| `acpctl audit verify` | **ok — 17 events**, tip `a05cf08e…` |
| The guest script | 100.5 s |

Checksums: `cd evidence/20261015T143033Z && grep -v ' sha256sums.txt$'
sha256sums.txt | shasum -a 256 -c` — 33 of 33 match.

## Result — run `20261015T190305Z`: `tee.provider: "auto"` — the kernel names the family

The same kit with neither daemon told what hardware it runs on: both
configs say `tee.provider: "auto"` (the peer pin stays `gcp-sev-snp`), and
each daemon takes its family from the kernel's configfs-tsm when the
configuration is loaded (ADR 0025, step 1). us-central1-c, `n2d-standard-4`,
the image of every run since September (measurement `7dc7c12e…25acc`).

| | `20261015T190305Z` (tree `de6bccd` + this branch) |
| - | - |
| The kernel's answer | `sagvd.log`, `acp-compute.log`: `tee.provider auto: the family is the kernel's to say` — `tsm_provider: sev_guest`, `tee_provider: gcp-sev-snp`, before each daemon's TEE identity line |
| The identities | `tee_provider: gcp-sev-snp` on both, measurement `7dc7c12e…25acc` from the chip |
| The AMD chain | fetched on the guest by `acpctl tee fetch-amd-chain`, checked against the pinned ARK-Milan (`amd-chain.txt`) |
| Runtime install from the locks | 84.3 s |
| Fine-tune + seal | 9.2 s; key id `genome-494a27fce81b-g0-d7f07cebe9f7` |
| The unpinned worker | refused at the handshake after 1 s |
| The gate job | `succeeded`, **EXACT**, pinned replay, rung 0, 6 of 6, max abs err 0, signed by `sagvd-authority-e2e`; 5.2 s |
| `acpctl audit verify` | **ok — 17 events**, tip `dc6c3c82…` |
| The guest script | 103.4 s |

Nothing else differs from the runs below: the family the kernel named is
the family the daemons ran, attested and recorded as. The same kit on a
TDX Trust Domain the same minute, with the same two words in its config:
[`../../gcp-tdx/returnpath-e2e/`](../../gcp-tdx/returnpath-e2e/README.md),
run `20261015T190232Z` (`tsm_provider: tdx_guest`).

## Result — runs `20261015T043703Z` and `20261015T044521Z`: the runtime from the hash-pinned locks

The same kit, with the guest installing the worker's runtime from the
hash-pinned locks instead of plain pins — `requirements-ci.lock` from PyPI,
then the torch CPU wheel alone from `requirements-torch-cpu.lock` on the
PyTorch CPU index, each under `pip --require-hashes --only-binary=:all:`.
us-central1-c, `n2d-standard-4`, both daemons reading the launch
measurement `7dc7c12e…25acc` from the chip as in every run since September.

| | `20261015T043703Z` (tree `4d289a5`) | `20261015T044521Z` (tree `75efe4f`) |
| - | - | - |
| Runtime install from the locks | 82.9 s | 75.2 s |
| `runtime.txt` | torch 2.14.1+cpu, transformers 5.19.0, safetensors 0.8.0 | the same |
| Fine-tune + seal | 10.3 s; key id `genome-8b157371311d-g0-bc5f5067c40a` | 8.8 s; `genome-f219ea41724c-g0-b7a2314633ea` |
| The unpinned worker | refused at the handshake after 1 s | the same |
| The gate job | `succeeded`, **EXACT**, pinned replay, rung 0, 6 of 6, max abs err 0, signed by `sagvd-authority-e2e`; 5.2 s | the same; 5.2 s |
| `acpctl audit verify` | **ok — 17 events**, tip `0c251fc9…` | **ok — 17 events**, tip `861ddc27…` |
| The guest script | 103.4 s | 93.7 s |
| `pip-requirements.log`, `pip-torch.log` | empty: pip ran with `-q` | what pip installed and from where — the torch wheel from `download-r2.pytorch.org/whl/cpu`, the rest from PyPI, every file by hash |

The second run is the first with `-q` removed from the guest's two pip
calls, so that the two logs are the record of the install; nothing else
differs between the trees. Checksums: `cd evidence/<run> && grep -v
' sha256sums.txt$' sha256sums.txt | shasum -a 256 -c` — 32 of 32 match in
each.

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
`seal-keys-sagvd.json` and `seal-keys-worker.json` (which files were sealed,
by which sealer), `sealed-files.txt` (each sealed file's shape, none of its
bytes), `vtpm.txt` when the vTPM seals, both daemons' logs, the two rogue
workers' logs, metrics, the runtime versions,
`tsm.txt` and `kernel.txt`, `steps.txt` with the timings, and
`sha256sums.txt` over all of it. Keys, seeds, the API token, the sealed
bundle's key file and the configs stay on the VM and die with it: the VM
and the bucket are deleted at the end of every run, also on failure.

Since ADR 0033 `steps.txt` carries two more lines, and the verdict
requires both: `sagvd sev_snp_policy bulletins_read_on=…` from `sagvd
identity` — the day the floors were read from AMD's bulletins and the
Milan row the authority holds a peer of that variant to — and a
`peer chip` line from the admitted worker's `TRUST_EVALUATED` record
(`peer_detail.sev_snp` in `audit-events.jsonl`): its variant by CPUID,
the TCB it reported, the firmware, the alias check, the mitigation vector
and the floor applied. No run under this is on the record yet; the first
is part two of the ADR.

## Reproduce

```bash
scripts/hardware-test/gcp-sev-snp/returnpath-e2e/run.sh <gcp-project> [zone] [profile]
```

`gcloud` logged in to a project with the Compute Engine and Cloud Storage
APIs enabled; about fifteen minutes and a few cents of `n2d-standard-4`.
The AMD Milan chain comes from `../keybind-evidence/20260913T222343Z/`.
The raw serial capture is kept under `~/.cache/vaultgenome/returnpath-e2e/`
(override with `VG_E2E_RAW_DIR`); `decode-results.sh` verifies the tarball's
size and SHA-256 against the header the guest printed before unpacking it.
The third argument, `general`, `fips` or `cnsa`, is the cryptographic
profile of ADR 0029, written into `sagvd`'s configuration (unset, the
daemon's default applies). `VG_FIPS=1` builds every binary on the
certified Go Cryptographic Module v1.0.0 (`GOFIPS140=v1.0.0`) and runs
every Go process on the guest under `GODEBUG=fips140=only` (ADR 0030,
part two); the profile defaults to `fips` and `general` is refused, its
first suite being X25519.
The binaries are built from a clean checkout of `HEAD` when the tree's
tracked files are clean, so their VCS stamp is the commit's even while
other kits write their records into the tree (untracked files mark a
build modified; on 2026-10-21 the binaries of a release record came out
`-dirty` for that reason); a tree with modified tracked files builds from
the working tree, stamped so.
