# Runbook: an Azure confidential GPU VM (production TEE mode)

`sagvd`, `acp-compute` and `acp-bootstrap` attest as an Azure confidential
GPU VM when `tee.provider` is `"azure-cgpu"` (ADR 0019): a
`Standard_NCC40ads_H100_v5` — an AMD SEV-SNP guest under Azure's paravisor
with an NVIDIA H100 in confidential-computing mode. The Evidence carries
three signatures: the chip's SEV-SNP report from the vTPM's HCL report, a
TPM quote by the vTPM's attestation key binding the handshake's challenge,
and NVIDIA's attestation tokens for the GPU under the same challenge. The
verifier for an `azure-cgpu` peer or destination runs anywhere: it needs
the AMD chain for the chip's product (Genoa), AMD KDS for the VCEK (cached)
and NVIDIA's key set (cached).

The SEV-SNP and TDX counterparts are [real-tee-sev-snp.md](real-tee-sev-snp.md)
and [real-tee-tdx.md](real-tee-tdx.md).

---

## A. The VM

Quota: the family `StandardNCCads2023Family` (40 vCPU per VM) in a region
that has the SKU (West Europe, East US 2). Create it as Microsoft's
onboarding package does:

```bash
az vm create -g <rg> -n <name> -l westeurope \
  --image Canonical:ubuntu-24_04-lts:cvm:24.04.202607310 --size Standard_NCC40ads_H100_v5 \
  --security-type ConfidentialVM --os-disk-security-encryption-type DiskWithVMGuestState \
  --enable-secure-boot true --enable-vtpm true --os-disk-size-gb 200 \
  --admin-username <user> --ssh-key-values @~/.ssh/id_ed25519.pub
```

Then Microsoft's `cgpu-onboarding-package` (V4.4.1, pinned by SHA-256 in
`scripts/hardware-test/azure-cgpu/run.sh`): `step-0-prepare-kernel.sh`
(dist-upgrade, reboot — wait for the *new* boot, not the old one),
`step-1-install-gpu-driver.sh` (the `nvidia-driver-595-server-open` with
Ubuntu's signed kernel modules; pin the 595 userspace to the version the
modules were built against — `apt-cache depends
linux-modules-nvidia-595-server-open-$(uname -r)` names it — or apt picks
a newer one from `noble-updates` and fails), `step-2-attestation.sh
--install-to-usr-local` (NVIDIA's local verifier under
`/usr/local/lib/local_gpu_verifier/.venv`, and `gpu-attestation` /
`cpu-attestation` commands). Install `tpm2-tools`. Check:

```bash
nvidia-smi conf-compute -q      # CPU CC Capabilities: AMD SEV-SNP(vTOM Mode); GPU CC Capabilities: CC Capable; CC GPUs Ready State: Ready
tpm2_nvreadpublic | grep -A3 0x1400001
sudo gpu-attestation --user_mode --nonce <64 hex>   # NVIDIA's own verdict for a nonce
```

## B. What the pin is

`identity` prints `tee_provider: azure-cgpu` and the 48-byte
`tee_measurement_hex`: Azure's SEV-SNP launch measurement, which covers
the paravisor and firmware Azure measures — the same for every VM of the
same generation, not the OS. The OS and the driver are in the vTPM's PCRs,
which the quote records and the verifier does not police (a PCR policy is
the next step). The GPU's software is pinned through NVIDIA's claims
instead (`gpu_policy`).

## C. Configuration

The daemon on the VM (root, or a user that may read the vTPM and run the
GPU verifier):

```json
"tee": {
  "provider": "azure-cgpu", "workload_descriptor": "acp-compute-v1",
  "gpu_attest_command": ["/usr/local/lib/local_gpu_verifier/.venv/bin/python", "/opt/vg/gpu-token.py"],
  "peer": { "provider": "azure-cgpu",
            "measurement_path": "/etc/acp/pins/vault.measurement",
            "amd_cert_chain_path": "/etc/acp/crosscloud/amd-genoa-cert_chain.pem",
            "vcek_cache_dir": "/var/lib/acp/vcek-cache",
            "nras_cache_dir": "/var/lib/acp/nras-cache",
            "gpu_policy": { "hw_models": ["GH100"], "driver_versions": ["595.71.05"] } } }
```

- `gpu_attest_command` obtains NVIDIA's tokens for a nonce (appended as
  the last argument, 64 hex characters) and prints NRAS's response on
  stdout; `scripts/hardware-test/azure-cgpu/gpu-token.py` is the one the
  hardware run uses (NVIDIA's local verifier package collects the GPU's
  report and certificate chain through NVML and posts them to
  `https://nras.attestation.nvidia.com/v3/attest/gpu`). `tpm2_tools_dir`
  and `ak_handle` are optional: tpm2-tools on PATH, and the attestation
  key found among the persistent handles by its public key (`0x81000003`
  on the machines measured).
- `amd_cert_chain_path` is the **Genoa** ASK+ARK chain (AMD KDS
  `/vcek/v1/Genoa/cert_chain`, or Azure's IMDS THIM `certificateChain`);
  a Milan chain refuses a Genoa VCEK.
- `vcek_cache_dir` and `nras_cache_dir`: fill them at deploy time (one
  handshake); with both empty and both services unreachable the verifier
  refuses.
- `gpu_policy.evaluation`: whose evaluation of the GPU's report the
  verdict rests on — `nras` (default: NVIDIA's signed tokens), or `both`:
  NVIDIA's tokens *and* this verifier's own evaluation of the report and
  chain the evidence carries (ADR 0021: the report's signature and nonce,
  the chain to NVIDIA's device root, the firmware id, every measurement
  against the driver and VBIOS manifests from NVIDIA's RIM service, kept
  under `rim_cache_dir`; `rim_service_url` overrides the service;
  `nvidia_device_root_path` / `nvidia_rim_root_path` replace the pinned
  roots), or `own`: this verifier's evaluation alone, NVIDIA's tokens
  not required and no NVIDIA service on the path but the RIM service (or
  a warm `rim_cache_dir`) — the manifests' XML signatures are verified
  (goxmldsig, `docs/dependencies/goxmldsig.md`); note that the
  secure-boot and debug-mode claims come only from NVIDIA's tokens, so
  `own` does not assert them and `both` remains the stronger policy where
  NRAS is reachable. With `both` or `own`, the guest's `gpu_attest_command` must
  print the full form (`{"nras": …, "gpu_evidence": […]}`, as the kit's
  `gpu-token.py` does), or the handshake is refused for want of a report.
- `gpu_policy`: `hw_models`, `driver_versions`, `vbios_versions` pin what
  NVIDIA reports (`GH100`, `595.71.05`, `96.00.9F.00.04` on the machine
  measured); `allow_secure_boot_off`, `allow_debug`, `allow_unsigned_rim`
  relax the defaults, knowingly.
- `pcr_digests`: what the peer's vTPM measured of its boot — `identity`
  prints it as `vtpm.pcr_digest_hex` (the digest over PCRs 0–14 of the
  SHA-256 bank, as TPM2_Quote computes it) — pinned to one of these; a
  kernel or driver update changes it. Empty: recorded in the evidence, not
  policed.
- A destination reached by IP whose certificate names it otherwise: the
  authority's `crosscloud.transport_tls.server_name` is the name to verify
  the certificate against.

The peer pins the VM's measurement from `identity`, as for SEV-SNP.

## D. A destination for a key release

`acp-bootstrap` with `"tee": { "provider": "azure-cgpu", "gpu_attest_command": [...] }`;
on the source, a registry entry `{ "provider": "azure-cgpu",
"expected_measurement_hex": …, "amd_cert_chain_path": …, "vcek_cache_dir":
…, "nras_cache_dir": …, "gpu_policy": {…}, "pcr_digests": […] }`, and the
allow-list names the measurement under `"azure-cgpu"`. Two things the
failover drill taught: the registry also needs an entry for the
*primary's* TEE family — the anchors `sagvd failover` verifies the
primary's reports with (runbook 07) — and `pcr_digests` is a property of
a boot: take it from `acp-bootstrap identity` on the machine as it runs,
after its last reboot, not from an earlier capture.

## E. What has run on hardware

[`scripts/hardware-test/azure-cgpu/`](../../../scripts/hardware-test/azure-cgpu/README.md):
the capture (HCL report, VCEK and Genoa chain, TPM quotes, NVIDIA's local
verdict and NRAS tokens, the 7B genome path on the H100 in
confidential-computing mode) and the Return Path with both daemons on
`azure-cgpu` and the door on the H100; the README carries the measured
runs. The verifier's tests run against the capture, offline.
[`scripts/hardware-test/failover-cgpu/`](../../../scripts/hardware-test/failover-cgpu/README.md):
the failover of a model from a GCP SEV-SNP primary to this destination
across the Internet — the key released on the chip's, the vTPM's and
NVIDIA's word, the genome gated EQUIVALENT on the H100, RTO 24.99 s.

## F. The escrow key: sealed to the vTPM; cleanup

No derived-key interface from the TEE; the escrow key is sealed to the
guest's vTPM under a policy of the pinned PCRs (ADR 0022,
`tee.vtpm_seal_pcrs`, default sha256:0-14), with tpm2-tools on the guest;
`sagvd seal-keys` and `acp-compute seal-keys` seal the daemons' other key
files the same way (ADR 0023).
The VM bills about $9 an hour while it exists; delete it after the run.
