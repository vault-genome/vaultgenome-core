# The Return Path on a real Intel TDX Trust Domain

The shipping `sagvd` and `acp-compute`, run end to end on one Google
Confidential VM with Intel TDX (`c3-standard-4`, Ubuntu 24.04), both
attesting with TDX quotes and each pinning the other's measurement
(ADR 0018), with the real `vg_genome` worker and its door (ADR 0013), the
audit log under every decision (ADR 0014) and the nine-stage flow
(ADR 0015) — the SEV-SNP kit
([`../../gcp-sev-snp/returnpath-e2e/`](../../gcp-sev-snp/returnpath-e2e/README.md))
with the TEE swapped:

- the worker fine-tunes a tiny model on the guest with the pinned torch
  (`python -m vg_genome finetune`) and `acpctl genome seal` seals the genome;
- `sagvd identity` and `acp-compute identity` each read MRTD and RTMR0..3
  from a quote of this Trust Domain; the measurement — SHA-384 of the five
  together — is written into the other side's `tee.peer.measurement_path`;
- a worker that is **not** the pinned identity — same certificate, same
  sealing key, a simulated TEE instead of the Trust Domain — dials the Return
  Path and is refused at the handshake; the refusal is on `sagvd`'s audit log;
- the pinned worker dials, its TDX quote verifies (PCK chain to the pinned
  Intel SGX Root CA, the attestation key's and the PCK leaf's signatures, the
  QE report's binding of the key, Intel's signed TCB info and QE identity
  fetched from Intel PCS and verified before use, platform / TDX module / QE
  rated `UpToDate`, no DEBUG, REPORTDATA binding the transcript challenge),
  a gate job goes over the Return Path, the worker restores the model in
  memory through the door and answers the genome's prompts, `sagvd` takes
  the job through the nine stages and signs the release decision;
- both daemons stop; `acpctl audit verify` verifies the log under the key
  `sagvd identity` published, and `acpctl audit query` reads every decision
  in order; the two Intel PCS documents both verifiers used are in the
  results, for offline re-verification.

Both processes run inside the same Trust Domain here; what the run proves
is that the Return Path handshake carries genuine TDX Evidence on both
sides, verified to Intel's root and Intel's TCB word, that the pinned
identity is the one admitted, and that every decision of the authority is
on a verifiable record before it took effect.

## Result — run `20260916T040416Z` (evidence/20260916T040416Z)

us-central1-a, `c3-standard-4`, kernel `7.0.0-1011-gcp`; `tsm.txt`:
`/dev/tdx_guest`, `tdx: Guest detected`, `Memory Encryption Features
active: Intel TDX`, CPU model name `Intel TDX`. torch 2.7.1+cpu,
transformers 4.53.2, safetensors 0.5.3. The whole script took **93.7 s**,
of which 77.5 s installed the runtime.

Both daemons read the same Trust Domain — `tee_provider: gcp-tdx`,
measurement `ed70198a…177b` on both, MRTD `c1ee9c16…70a5`, RTMR3 zero —
and `steps.txt` recomputes `sha384(mrtd ‖ rtmr0..3)` from each identity's
`tdx` block: it is the measurement. MRTD and all four RTMRs are the ones
the capture kit recorded 44 minutes earlier on another guest of the same
image (`../capture/evidence/20260916T031937Z/q1.layout.txt`): same
firmware, same kernel, same command line — the pin names the image, not
the instance.

| Step | Outcome |
|---|---|
| `vg_genome finetune` + `acpctl genome seal` on the guest | 2 384 adapter parameters, loss 3.713 → 2.348, 6 fixtures (4 critical); 21 504-byte payload, 22 676-byte bundle, key id `genome-003e75e56438-g0-5f6b9ce6d203` |
| A worker with a simulated TEE | **refused** at the Return Path handshake within 1 s: `gcp-tdx: parse quote: quote is 147 bytes, shorter than a header and TD report (636)`; `TRUST_EVALUATED` deny (phase `handshake`, provider `gcp-tdx`) is event 1 of the log; `vg_tee_attestation_total{provider="gcp-tdx",result="error",role="verify"} 1` |
| The pinned worker on TDX | session opened at once, `peer_measurement` = the pin; `vg_tee_attestation_total{provider="gcp-tdx",result="success",role="verify"} 2` (identity, then the handshake) |
| `POST /v1/jobs` | **202** — `request_id` `req-b6e37297d9a3fc0f`, state `trust` |
| Trust Admission | `TRUST_EVALUATED` **allow** — `trust.peer_attested`, `gcp-tdx`, measurement `ed70198a…177b`, attestation `att-fdc9b5ad-…-0001`, TTL 330 s |
| Session, disclosures, manifest | `SESSION_ISSUED` pinned to `gate-policy/v1;atol=0.01;rtol=0.001;outliers=0`; **5** `DISCLOSURE_AUTHORIZED`; `MANIFEST_ISSUED` `rjm-fd7dcd5384eac494`, output budget 666 bytes |
| Validation | three dimensions **pass** — operational, semantic (top-1 **6/6**, 0 critical disagreements), behavioral (`equivalence-ladder`, **EXACT**, `pinned replay`, rung 0, max abs err 0); `VALIDATION_COMPLETED` |
| Release decision | `RELEASE_DECIDED` then the signed decision `dec-d6fd9410c50e2fcf` (schema v2): **release**, `validation_pass`, citing the attestation and the validation result; signed by `sagvd-authority-e2e` |
| The flow | state `release_authorized`, **3.37 s** from submission to the signed decision (04:05:45.765 → 04:05:49.138); audit tip `b889f081…cda4` |
| `acpctl audit verify` with the published key | **ok — 17 events**: the rogue's denial, then the sixteen of the flow, in order |
| Intel's word | `pcs-tdx-tcb-00806f050000.json` (issued 2026-09-16T03:00:02Z) and `pcs-tdx-qe-identity.json` (03:20:18Z), each with its issuer chain, as both verifiers fetched and cached them |

`job.json` carries the whole flow: the signed attestation, session,
manifest, validation result and release decision, the disclosures' digests
— verifiable offline under the keys in `sagvd-identity.json`. Checksums:
`cd evidence/20260916T040416Z && grep -v ' sha256sums.txt$' sha256sums.txt
| shasum -a 256 -c` — 37 of 37 match.

What is on the guest and not in the results: every key and seed `keygen`
made, the API token, the configs, the genome and its key file. The VM and
its bucket are deleted when `run.sh` exits, on success or failure.

## Reproduce

```bash
scripts/hardware-test/gcp-tdx/returnpath-e2e/run.sh <gcp-project>     # c3-standard-4, ~10 minutes end to end
```

The serial console capture is kept under
`~/.cache/vaultgenome/tdx-returnpath-e2e/`; `run.sh` decodes it with the
SEV-SNP kit's `decode-results.sh` (size and SHA-256 of the transfer checked
against the header) into `evidence/<stamp>/`.
