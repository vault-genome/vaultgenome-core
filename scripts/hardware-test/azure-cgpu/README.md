# A confidential GPU on Azure: the chip, the vTPM and the H100 in one evidence

One `Standard_NCC40ads_H100_v5` Confidential VM in West Europe — an AMD
SEV-SNP (Genoa) guest under Azure's paravisor with an NVIDIA H100 NVL in
confidential-computing mode, Ubuntu 24.04 CVM image, brought up the way
Microsoft's onboarding package V4.4.1 does it (kernel, the 595 open
driver with Ubuntu's signed modules, NVIDIA's local GPU verifier) — asked
for everything the `azure-cgpu` verifier needs (ADR 0019), then made to
run the 7B genome path on the H100, then the Return Path with both daemons
attesting as `azure-cgpu`.

`run.sh [resource-group] [location]` creates the VM (SSH from the caller's
IP only), runs Microsoft's steps 0–2 over SSH, then `cgpu-capture.sh`
(root, on the guest), reads the results back, checks them, and deletes
the VM's resources. `returnpath-cgpu.sh` is the Return Path on the same
guest with the daemons uploaded. Everything collected is public by
construction — reports, quotes, certificates, tokens, measurements, logs;
the genome key is shredded on the VM and no key or seed leaves it.

## Capture — run `20260916T133506Z` (evidence/20260916T133506Z)

`vg-cgpu-20260916t131757z`, kernel `6.17.0-1018-azure-fde`, Ubuntu
24.04.5, secure boot on (`system.txt`); NVIDIA driver 595.71.05, CUDA
13.2, `conf-compute -q`: **CPU CC Capabilities: AMD SEV-SNP (vTOM Mode);
GPU CC Capabilities: CC Capable; CC GPUs Ready State: Ready**
(`conf-compute.txt`).

| What | Where | Outcome |
|---|---|---|
| The HCL report from the vTPM (NV index `0x01400001`) | `hcl-report.bin` (2 600 bytes), `snp-report.bin`, `runtime-data.json`, `hcl-summary.json` | SNP report **version 5**, policy `0x30001f` (no DEBUG), VMPL 0, signature algorithm 1, measurement `aa7c9da5…0eef`, chip id `dd751815…`, reported TCB `0x581b00000000000a`; `REPORT_DATA[:32]` **is** the SHA-256 of the runtime data, which names `HCLAkPub` (RSA 2048, `sign`) and `HCLEkPub`, secure boot and the vTPM on |
| The chip's VCEK and chain from Azure's IMDS (THIM) | `thim-certification.json`, `vcek.pem`, `cert-chain.pem` | the VCEK and the **Genoa** ASK+ARK chain (`SEV-Genoa`) |
| The vTPM's attestation key and two quotes | `ak-pub.pem`, `tpm-handles.txt`, `quote{1,2}.msg/.sig/.pcrs`, `pcrs-sha256.txt`, `nonces.txt` | `HCLAkPub` is persistent handle `0x81000003`; each quote a 145-byte TPMS_ATTEST over PCRs 0–14 (SHA-256) with our nonce in extraData and a 256-byte signature; `openssl dgst -sha256 -verify ak-pub.pem`: **Verified OK** (`quote1.openssl-verify.txt`) |
| NVIDIA's local verifier under our nonce | `local-verifier.txt` | the SPDM nonce matched; the driver RIM's certificate chain and signature verified, the VBIOS RIM verified, measurements matched: exit 0 |
| NVIDIA's Remote Attestation Service under the same nonce | `gpu-evidence.json`, `gpu0-attestation-report.bin`, `gpu0-cert-chain.pem`, `nras-response.json`, `nras-claims-decoded.json`, `nras-jwks.json` | HTTP 200 in 0.29 s; overall token ES384 (`nv-eat-kid-prod-20260916090709987-…`), `iss https://nras.attestation.nvidia.com`, `x-nvidia-overall-att-result true`, `eat_nonce` = our nonce, valid 1 h; GPU-0: `hwmodel GH100`, driver `595.71.05`, VBIOS `96.00.9F.00.04`, `measres success`, `secboot true`, `dbgstat disabled`, nonce match true |
| Microsoft's `cpu-attestation` (MAA), for the record | `cpu-attestation-maa.txt` | `x-ms-attestation-type sevsnpvm`, `x-ms-compliance-status azure-compliant-cvm`, "Attested Guest Successfully" |
| **The 7B genome path on the H100 in confidential-computing mode** | `finetune.json`, `genome.json`, `fixtures.json`, `seal.json`, `open.json`, `verify.json`, `gate-gpu.json`, `measure-gpu*.json`, `replay-gpu.json` | Qwen2.5-7B-Instruct, LoRA r=8 `q_proj,v_proj` (2 523 136 parameters) in bfloat16 on `cuda`: **26.2 s** of training, loss 5.997 → 0.000348; a 10 141 998-byte genome; restored from the bundle and gated **EXACT** (rung 0, 16/16, max abs err 0; the door 18.0 s with the load); measured 16/16 exact, top-1 16/16, greedy 16/16 (load 5.3 s, 11.3 s); the recipe replayed **bit for bit**; the same genome restored in **float32** on the same GPU: 0/16 exact, top-1 16/16, greedy 16/16, max abs err 0.476 (rel 0.046) — the bfloat16 quanta again, across dtype instead of device |

The whole capture took 297 s on the guest (the runtime and the 15 GB base
were already there). Checksums: `cd evidence/20260916T133506Z && grep -v
' sha256sums.txt$' sha256sums.txt | shasum -a 256 -c` — 59 of 59 match.

The verifier's tests run against this capture offline
([`internal/shared/tee/azure_cgpu_evidence_test.go`](../../../internal/shared/tee/azure_cgpu_evidence_test.go)):
the genuine evidence verifies with the nonce that produced it, with the
VCEK and Genoa chain Azure served and NVIDIA's key set as captured, and is
refused for the other nonce, for a driver version not on the list, past
the tokens' expiry, and under the Milan chain.

## The Return Path — run `20260916T133506Z-returnpath` (evidence/20260916T133506Z-returnpath)

The shipping `sagvd` and `acp-compute` on the same guest, both
`tee.provider: "azure-cgpu"`, each pinning the other's launch measurement
(one guest, one measurement — `aa7c9da5…0eef` on both, `sagvd-identity.json`
and `acp-compute-identity.json`), the peer verifier with the Genoa chain,
a VCEK cache, NVIDIA's key-set cache and `gpu_policy: {hw_models:
["GH100"]}`; the door on the H100 (`--device cuda`); the 7B genome trained
in the capture sealed for `sagvd`.

| Step | Outcome |
|---|---|
| `sagvd identity`, `acp-compute identity` | both read the launch measurement from the vTPM's HCL report in 0.14 s |
| A worker with a simulated TEE | **refused** at the Return Path handshake within 2 s: `azure-cgpu: evidence is not a vault-genome/azure-cgpu-evidence/v1 envelope`; `TRUST_EVALUATED` deny is event 1 of the log; `vg_tee_attestation_total{provider="azure-cgpu",result="error",role="verify"} 1` |
| The pinned worker | session opened 1 s after it started: its evidence — the HCL report, a TPM quote for the handshake's challenge, NVIDIA's tokens for the same challenge — verified to AMD, under the vTPM's key and under NVIDIA's key set; `vg_tee_attestation_total{provider="azure-cgpu",result="success",role="verify"} 1`, `role="produce"` 2 (one quote per handshake, NRAS on the path each time) |
| `POST /v1/jobs` → `release_authorized` | **18.5 s** from submission to the signed release decision, the 7B genome restored in memory through the door on the H100 in confidential-computing mode; gate **EXACT** (`pinned replay`, rung 0, 16/16, max abs err 0), top-1 16/16; attestation TTL 930 s |
| `acpctl audit verify` with the published key | **ok — 17 events**: the rogue's denial, then the sixteen of the nine-stage flow |

`job.json` carries the whole flow, verifiable offline under the keys in
`sagvd-identity.json`; `cache-*` are the VCEK and NVIDIA's key set as the
verifiers fetched them. Checksums: `cd evidence/20260916T133506Z-returnpath
&& grep -v ' sha256sums.txt$' sha256sums.txt | shasum -a 256 -c` — 27 of
27 match.

## What the first attempt taught the kit

- After Microsoft's kernel step, wait for the guest's *new* boot
  (`uptime -s` changes), not for the first SSH that answers.
- Ubuntu's signed kernel modules for the 595 server driver
  (`linux-modules-nvidia-595-server-open-<kernel>`) are built against one
  userspace version (`nvidia-kernel-common-595-server <= 595.71.05`);
  `noble-updates` carries 595.91.07 and apt fails. `run.sh` pins every
  `*595-server*` package to the version the modules depend on.
- NVIDIA's verifier package logs to stdout; the GPU attestation command the
  producer runs (`gpu-token.py`) keeps only NRAS's response there.

## Reproduce

```bash
scripts/hardware-test/azure-cgpu/run.sh vg-cgpu-weu westeurope      # ~40 min of NCC40ads_H100_v5 (about $9 an hour)
go test -count=1 -run 'AzureCGPU|HCL|TPMQuote|NRAS' ./internal/shared/tee/
```

The Return Path run needs the daemons built for linux/amd64 and
`returnpath-cgpu.sh`, `gpu-token.py` uploaded to the guest after the
capture: `sudo env VG_STAMP=<stamp> VG_CAPTURE_STAMP=<stamp> bash
returnpath-cgpu.sh`.
