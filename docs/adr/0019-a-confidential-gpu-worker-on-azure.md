# ADR 0019: A Confidential GPU Worker on Azure — the Chip, the vTPM and the GPU in One Evidence

**Status:** Accepted — implemented (2026-09-16)
**Date:** 2026-09-16
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Builds on:** ADR 0014 (both daemons attest with the hardware they run on), ADR 0018 (Intel TDX on the Return Path), ADR 0009 (SEV-SNP verification to the AMD root), ADR 0007 (variable-length measurements), ADR 0001 (frozen Producer/Verifier/Sealer)
**Amends:** `sagvd`, `acp-compute` and `acp-bootstrap` configuration (`tee.provider: "azure-cgpu"` with `gpu_attest_command`, `tpm2_tools_dir`, `ak_handle`; `tee.peer.provider: "azure-cgpu"` with the AMD fields, `nras_jwks_url`, `nras_cache_dir`, `gpu_policy`); `sagvd`'s cross-cloud verifier registry (`azure-cgpu` entries)

---

## Context

Every attested machine before this ADR was a CPU confidential VM; the
GPU, where a model of any size actually runs, was never inside the trust
boundary, and VERIFIABLE-CLAIMS said so ("We do not claim attested GPU
destinations"). Azure's `NCC H100 v5` is the first machine in this
repository's reach where the GPU is: an AMD SEV-SNP guest under Azure's
paravisor with an NVIDIA H100 in confidential-computing mode — the
GPU's memory encrypted, its transfers with the guest protected, and the
GPU itself able to sign a statement of what firmware and driver it runs.

Two things about Azure made the SEV-SNP adapter of ADR 0014 insufficient:

1. **No `/dev/sev-guest`.** Azure mediates SEV-SNP through the paravisor.
   The SNP report is issued at boot and kept in the vTPM (NV index
   `0x01400001`, the "HCL report"); its `REPORT_DATA` is not a caller's
   nonce but the SHA-256 of the runtime data — a JSON document naming the
   vTPM's attestation key (`HCLAkPub`) and the VM's configuration. A
   handshake challenge cannot go into the report; it has to be bound
   through the key the report vouches for.
2. **The GPU is a second root of trust.** NVIDIA's H100 signs an SPDM
   measurement report with a per-device key certified by NVIDIA's device
   CA; the measurements mean something only against NVIDIA's reference
   manifests (RIMs) for the driver and VBIOS, and the certificates only
   with NVIDIA's revocation service. Evaluating that independently is a
   verifier of its own; NVIDIA's Remote Attestation Service (NRAS) does it
   and signs the outcome as Entity Attestation Tokens.

## Decision

### One Evidence, three signatures

`tee.provider: "azure-cgpu"` produces one Evidence envelope
(`vault-genome/azure-cgpu-evidence/v1`) for a handshake nonce:

- **the HCL report** as read from the vTPM: the SEV-SNP report (signed by
  the chip's VCEK) and the runtime data it hashes;
- **a TPM quote** by the HCL attestation key over PCRs 0–14 of the SHA-256
  bank, with `SHA-256(nonce)` in `extraData` — the binding of this
  handshake to a report the chip issued at boot;
- **NVIDIA's tokens** for the same `SHA-256(nonce)`, obtained on the guest
  by the operator's `gpu_attest_command` (NVIDIA's local verifier package
  collects the GPU's report and certificate chain through NVML and posts
  them to NRAS; the response is the tokens).

The measurement is the SNP launch measurement — 48 bytes, what Azure
measures of the paravisor and firmware — and a peer pins it as it pins a
GCP SEV-SNP guest. What NVIDIA vouched for is in the verdict: the GPU's
model, driver and VBIOS, and an operator may pin those too (`gpu_policy`).

### The verifier, in the order it checks

1. The envelope's schema; the HCL report's magic, the runtime data header
   (version 1, SNP, SHA-256) and that `REPORT_DATA[:32]` is the SHA-256 of
   the runtime data — without which the report vouches for no key.
2. The SNP report to AMD, as ADR 0009 has it, for the chip's **product**:
   the VCEK from AMD KDS under the product the report names (CPUID family
   and model in a version-3-or-later report; Genoa for NCC H100 v5), the
   VCEK → ASK → ARK chain under the operator's pinned chain for that
   product, the ECDSA-P384 signature, algorithm 1 by the VCEK, no DEBUG
   in the guest policy, VMPL 0, the TCB floor.
3. The attestation key from the runtime data (`HCLAkPub`, RSA, a signing
   key); the TPM quote parsed by its layout (TPM_GENERATED_VALUE,
   TPM_ST_ATTEST_QUOTE) and its signature under that key (RSASSA
   PKCS1-v1_5 or PSS, SHA-256); `extraData` equal to `SHA-256(nonce)`.
4. NVIDIA's tokens: the overall token and every detached per-GPU token
   verified ES384 under NVIDIA's JWKS (kept in `nras_cache_dir`, refreshed
   once when a token names a key the cache does not hold; no network and
   no cache is a refusal), within their validity window; the overall
   result true and `eat_nonce` equal to the hex of `SHA-256(nonce)`; per
   GPU: the report's nonce matched, the report's signature verified and
   parsed, the architecture recognised, the driver and VBIOS manifests
   present and signed, `measres` success, secure boot on, debug disabled
   — the defaults an operator may relax knowingly (`allow_secure_boot_off`,
   `allow_debug`, `allow_unsigned_rim`) — and the model, driver and VBIOS
   in the operator's lists when given.
5. The launch measurement against the pin.

Every refusal names its step.

### No sealer

The guest has no derived-key interface; the adapter has no Sealer, and an
authority on this host holds no sealed escrow key (as on TDX, ADR 0018).
Sealing through the vTPM is the way and it is not wired.

### Proven on the machine

`scripts/hardware-test/azure-cgpu/` brings up a `Standard_NCC40ads_H100_v5`
in West Europe as Microsoft's onboarding package does (the kernel, the
595 open driver, NVIDIA's local verifier), captures the HCL report, the
VCEK and Genoa chain from Azure's IMDS, two TPM quotes with our nonces,
NVIDIA's local verdict and NRAS's tokens for a nonce, Microsoft's own
`cpu-attestation` through MAA, and runs the 7B genome path on the H100 in
confidential-computing mode; then the Return Path with both daemons on
`azure-cgpu`, the 7B genome restored through the door on the H100 for a
gate job. The verifier's tests run against the capture, offline.

## Consequences

- **NVIDIA is trusted for the GPU's evaluation, and for nothing else.**
  What this build verifies itself is NVIDIA's signature, the token's
  nonce, the token's validity and the claims' values; the GPU's SPDM
  report and certificate chain are in the evidence beside the tokens for
  an independent evaluation, which this build does not make. An operator
  who does not accept NVIDIA's word does not accept this provider.
- **Two services on the path at verification time** — AMD KDS for the
  VCEK, NRAS's key set for the tokens — both cached; both unreachable with
  empty caches is a refusal. And NRAS itself is on the path at
  *production* time: a guest that cannot reach NVIDIA's service cannot
  attest, which is the price of the GPU's evaluation being NVIDIA's.
- **The pin names the paravisor, not the OS.** Azure's SNP launch
  measurement covers the firmware Azure measures; the OS and the driver
  are in the vTPM's PCRs, which the quote records and the verifier does
  not yet police — a PCR policy is the next step for an operator who
  wants the OS pinned too. The GPU's software is pinned through NVIDIA's
  claims (driver, VBIOS) instead.
- **tpm2-tools and NVIDIA's package are runtime dependencies** of the
  producer, executed as commands; the verifier has none.
- **The evidence is public.** Reports, quotes, certificates and tokens
  carry no secret; a captured set verifies the same everywhere.
