# Runbook: an Azure SEV-SNP Confidential VM (production TEE mode)

`sagvd`, `acp-compute` and `acp-bootstrap` attest as an Azure SEV-SNP
Confidential VM when `tee.provider` is `"azure-sev-snp"` — or `"auto"`,
which reads the HCL report's type from the vTPM where the kernel has no
configfs-tsm to ask (ADR 0025, plan item 4): a `Standard_DC4as_v5`, an `ECasv5`, or any Azure CVM on AMD
SEV-SNP without a GPU — an SEV-SNP guest under Azure's paravisor. The
Evidence carries two signatures: the chip's SEV-SNP report from the vTPM's
HCL report, and a TPM quote by the vTPM's attestation key binding the
handshake's challenge. It is the `azure-cgpu` family without the GPU half
(the same code verifies both, `internal/shared/tee/azure_vtpm.go`). The
verifier for an `azure-sev-snp` peer or destination runs anywhere: it needs
the AMD chain for the chip's product (Milan or Genoa, as the report says)
and AMD KDS for the VCEK (cached).

The GCP SEV-SNP, TDX and confidential-GPU counterparts are
[real-tee-sev-snp.md](real-tee-sev-snp.md), [real-tee-tdx.md](real-tee-tdx.md)
and [real-tee-azure-cgpu.md](real-tee-azure-cgpu.md).

---

## A. The VM

Quota: the family `StandardDCASv5Family` (or `ECASv5`) in a region that has
the SKU (West Europe, East US). Create it as the kit does:

```bash
az vm create -g <rg> -n <name> -l westeurope \
  --image Canonical:ubuntu-24_04-lts:cvm:24.04.202607310 --size Standard_DC4as_v5 \
  --security-type ConfidentialVM --os-disk-security-encryption-type DiskWithVMGuestState \
  --enable-secure-boot true --enable-vtpm true \
  --admin-username <user> --ssh-key-values @~/.ssh/id_ed25519.pub
```

Install `tpm2-tools`. There is no `/dev/sev-guest` and no configfs-tsm on
an Azure guest: the paravisor issues the SNP report at boot and keeps it
in the vTPM. Check:

```bash
ls -l /dev/tpmrm0
tpm2_nvreadpublic | grep -A3 0x1400001      # the HCL report's NV index
sudo tpm2_nvread -C o 0x1400001 | head -c 4  # "HCLA"
```

## B. What the pin is

`identity` prints `tee_provider: azure-sev-snp` and the 48-byte
`tee_measurement_hex`: Azure's SEV-SNP launch measurement, which covers
the paravisor and firmware Azure measures — the same for every VM of the
same generation, not the OS. The OS is in the vTPM's PCRs, which the quote
records; `identity` prints what this boot measured as
`vtpm.pcr_digest_hex` (the digest over PCRs 0–14 of the SHA-256 bank, as
TPM2_Quote computes it), and a peer pins it with `pcr_digests`, which is
required: the launch measurement says nothing of the OS (ADR 0037).

The report is issued at boot, so its own REPORT_DATA is Azure's (the
SHA-256 of the vTPM's runtime data, which names the attestation key); the
handshake's freshness comes from the TPM quote, whose extraData is the
SHA-256 of the challenger's nonce. A verifier accepts the report only
with a quote by the key it names, for the nonce it sent.

## C. Configuration

The daemon on the VM (root, or a user that may read the vTPM):

```json
"tee": {
  "provider": "azure-sev-snp", "workload_descriptor": "acp-compute-v1",
  "peer": { "provider": "azure-sev-snp",
            "measurement_path": "/etc/acp/pins/vault.measurement",
            "pcr_digests": ["<the peer's vtpm.pcr_digest_hex>"],
            "amd_cert_chain_path": "/etc/acp/crosscloud/amd-genoa-cert_chain.pem",
            "vcek_cache_dir": "/var/lib/acp/vcek-cache" } }
```

- `tpm2_tools_dir` and `ak_handle` are optional: tpm2-tools on PATH, and
  the attestation key found among the persistent handles by its public
  key (`0x81000003` on the machines measured).
- `amd_cert_chain_path` is the ASK+ARK chain of the **chip's product**: a
  `Standard_DC4as_v5` in West Europe was Genoa (EPYC 9V74) on the day
  measured, in East US Milan; the report's CPUID family and model say
  which (`scripts/hardware-test/azure-sev-snp/scripts/02b-cryptographic-attestation.sh`
  reads them; the kit below reads them before it fetches the chain).
  `acpctl tee fetch-amd-chain --product milan|genoa` fetches the chain
  from AMD KDS and verifies it against the roots the binary pins (ADR
  0024); Azure's IMDS THIM endpoint
  (`169.254.169.254/metadata/THIM/amd/certification`) serves the same
  chain and the VCEK for this chip. A Milan chain refuses a Genoa VCEK.
- `vcek_cache_dir`: fill it at deploy time (one handshake); with it empty
  and AMD KDS unreachable the verifier refuses.
- `pcr_digests` (required): what the peer's vTPM measured of its boot —
  `identity` on the peer, on the boot it runs, prints it as
  `vtpm.pcr_digest_hex` — and the quote's digest must be one of these. A
  configuration without it does not start. It is a property of one VM's
  boot, not of the image — two VMs of one image measured different
  digests (C54) — so each host is pinned from its own `identity`, taken
  after its last reboot. A kernel update is a new boot: the host is
  refused until its new digest is pinned beside the old; remove the old
  once no host runs it.
  `acpctl provision` pins each side's boot from its identity, the worker's
  in `pin-worker`.
- `tee.sealer`: `auto` (the default) is the vTPM (`tpm2`, ADR 0022): the
  paravisor gives the guest no derived key of its own, and `tee.sealer:
  "tee"` is refused by name. `tee.vtpm_seal_pcrs` selects the PCRs the key
  files are sealed to.
- No `gpu_attest_command`, `nras_*` or `gpu_policy`: those are the
  `azure-cgpu` family's and are refused here.

The peer pins the VM's measurement and its boot from `identity`. What
the verifier checked is on the audit record: the `TRUST_EVALUATED` event
that admits the worker carries `peer_detail` — the chip's product and id,
the reported TCB, the quote's PCR selection and digest.

## D. What has run on hardware

`scripts/hardware-test/azure-sev-snp/returnpath-e2e/` runs the Return
Path on one `Standard_DC4as_v5`: both daemons attest as `azure-sev-snp`,
each pins the other's launch measurement and boot, a worker on a boot
the policy does not name is refused at the handshake, the worker
fine-tunes a genome
on the guest, `acpctl` seals it, the gate job goes over the Return Path
and the authority judges the answer; every key file is sealed to the vTPM.
The run on record is in the kit's `README.md` and in
[`VERIFIABLE-CLAIMS.md`](../../../VERIFIABLE-CLAIMS.md). The capture kit
that preceded the provider — the HCL report read from the vTPM, the SNP
report extracted, chained to AMD and checked against Azure's own
attestation token — is `scripts/hardware-test/azure-sev-snp/` (its
`README.md` has the layout of the HCL report and the REPORT_DATA binding).

## E. The escrow key: sealed to the vTPM; cleanup

`sagvd escrow-provision` and the three daemons' `seal-keys` seal to the
vTPM under the pinned boot (ADR 0022, ADR 0023); a key sealed on one VM is
no key on another, and a changed boot (a kernel update) needs the
operator's recovery key to reseal. Delete the VM when done: `az vm delete`
leaves the OS disk, the NIC, the public IP, the security group and the
virtual network behind — delete what carries the VM's name
(`az resource list -g <rg> --query "[?contains(name, '<name>')].id"`), as
the kits' cleanup does.
