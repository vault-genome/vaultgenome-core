# Runbook: a Compute Engine SEV-SNP Confidential VM attesting with its vTPM (production TEE mode)

`sagvd`, `acp-compute` and `acp-bootstrap` attest as a Compute Engine
Confidential VM on AMD SEV-SNP **with its boot chain** when `tee.provider` is
`"gcp-sev-snp-vtpm"` (ADR 0037). The Evidence carries two signatures under one
challenge: the chip's SEV-SNP report, whose REPORT_DATA is SHA-256 of the
nonce in its first half and SHA-256 of the vTPM attestation key in its second;
and a TPM quote by that key over the boot PCRs, with SHA-256 of the nonce in
extraData, the key certified by Google's EK/AK CA for this instance.

Why both: on Compute Engine the chip's launch measurement is Google's UEFI —
Google precomputes it per vCPU count (its launch endorsement) — and the
operating system is read from the disk after launch. The boot after the
firmware — GRUB, the kernel, its command line and initrd — is measured into
the vTPM. A `gcp-sev-snp` peer is held to the chip alone; a
`gcp-sev-snp-vtpm` peer is held to the chip and to the boot the policy names.

The verifier runs anywhere: it needs the AMD chain of the chip's product, AMD
KDS for the VCEK (cached), and Google's EK/AK root, which the binary pins
(`internal/shared/tee/gce_roots.go`).

---

## A. The VM

As `real-tee-sev-snp.md`, with the vTPM on:

```bash
gcloud compute instances create <name> --zone us-central1-c \
  --machine-type n2d-standard-4 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --shielded-vtpm --shielded-integrity-monitoring
```

Install `tpm2-tools`. Check the vTPM and Google's attestation key:

```bash
ls -l /dev/tpmrm0 /sys/kernel/config/tsm/report
sudo tpm2_nvread -C o 0x01c10000 | openssl x509 -inform der -noout -issuer -subject
# issuer ... CN = EK/AK CA Intermediate; subject ... O = Google Compute Engine, OU = <project>, CN = <instance id>
```

**Let the image's first boot settle before you pin or seal.** On the first
boot the image grows its root partition, which moves PCR 5, and GRUB settles
its environment; from the second boot on, a plain reboot moves no PCR of the
selection (the boot-chain kit, `scripts/hardware-test/gcp-sev-snp/boot-chain`).

## B. What the pin is

`identity` prints `tee_provider: gcp-sev-snp-vtpm`, the 48-byte
`tee_measurement_hex` (Google's UEFI for this vCPU count) and
`vtpm.pcr_digest_hex`: the digest over the boot PCRs of the SHA-256 bank,
`sha256:0-9` by default — the firmware's (0–7) and GRUB's (8: its commands
and the kernel's command line; 9: every file it read, the kernel and its
initrd among them), as TPM2_Quote computes it. A peer or a destination entry
pins both: the measurement file, and `pcr_digests` with the boots it may run.
`pcr_digests` is required; there is no default that accepts any boot.

```json
"peer": {
  "provider": "gcp-sev-snp-vtpm",
  "measurement_path": "/etc/vaultgenome/peer.measurement",
  "amd_cert_chain_path": "/etc/vaultgenome/amd-milan-chain.pem",
  "vcek_cache_dir": "/var/lib/vaultgenome/vcek",
  "pcr_digests": ["<vtpm.pcr_digest_hex of the peer's settled boot>"],
  "gce_project_ids": ["<the project the peer runs in>"]
}
```

`gce_project_ids` holds the peer to instances of the operator's projects: the
attestation key's certificate names the project, the zone and the instance,
and Google's own verifier refuses a certificate that is not production's, as
this one does.

## C. The key files

Under `tee.provider: gcp-sev-snp-vtpm` the key files are sealed to both the
chip and the vTPM (`tee.sealer: auto`, which is `both` here): the chip's
derived key — this chip, Google's firmware, the guest policy — nested inside
a vTPM object under a policy of the boot PCRs (`sha256:0-9` unless
`tee.vtpm_seal_pcrs` names others). A file opens on this chip and on the boot
the PCR policy names; it does not open on another kernel, and not on another
chip (ADR 0037).

## D. A kernel update

A new kernel is a new boot: its PCR digest is not the one pinned, and the
files sealed under the old boot do not open under the new one. Before the old
boot is retired:

1. boot the new kernel on a standby of the same image, run `identity` there,
   and add its `vtpm.pcr_digest_hex` to every peer's and destination entry's
   `pcr_digests`;
2. on each host, after it has booted the new kernel, re-provision its key
   files (`sagvd seal-keys`, `acp-compute seal-keys`, `acp-bootstrap
   seal-keys` from the operator's seeds, as for a new host);
3. remove the old digest from `pcr_digests` once no host runs it.

## E. What stays the platform's

The vTPM on a Compute Engine SEV-SNP guest is Google's software, outside the
TEE (Google's documentation: the boot-time measurements are signed by "a
software-based vTPM", while on TDX the boot chain is in the RTMRs, "rooting
all measurements in hardware"). The boot chain is held to it against anyone
who can change the disk, and Google is trusted for it as it is for the
firmware the chip measures. On Intel TDX (`gcp-tdx`) the kernel is in the
hardware's own measurement.
