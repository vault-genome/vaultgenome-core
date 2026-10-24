# ADR 0037 — The boot chain on a SEV-SNP guest without a paravisor: the chip's report and the vTPM's quote under one challenge, and a key file sealed to both

- **Status:** Accepted (2026-10-24) — implemented: the `gcp-sev-snp-vtpm` family (producer, verifier, the three daemons and the registry), `tee.sealer: both`, the boot-chain kit (C53)
- **Date:** 2026-10-24
- **Deciders:** Serhii Nikolaichuk, Rodion Sorokin
- **Extends:** ADR 0025 step 3 (the `tpm2` evidence: a quote over PCRs with the event log, its key traced to the TPM vendor's root, appraised against a PCR policy), ADR 0022 and 0023 (the vTPM sealer, the daemons' key files sealed to the host), ADR 0016 (the escrow key sealed to the release host), ADR 0033 (the attack record)

## Context

What a SEV-SNP launch measurement covers is decided by whoever writes the
guest's first pages, and on a Compute Engine Confidential VM that is Google.
Google's documentation of the launch endorsement says so: the expected values
of the report's MEASUREMENT field are computed by Google from its own UEFI
binary, one per count of vCPUs at launch (`VMSevSnp.measurements`, "Expected
MEASUREMENT report field values given [key]-many VMSAs at launch"); the
operating system is read from the boot disk after launch and is not in it.
The boot chain after the firmware is measured into the instance's vTPM, which
signs its quotes as "a software-based vTPM" on SEV-SNP, while on TDX "the
remaining boot chain is measured into the Runtime Measurement Registers
(RTMR), rooting all measurements in hardware" (both pages as read on
2026-10-24, byte copies and hashes in the project library under
`sources/gcp/confidential-vm-2026-10-24/`).

The tree treated the launch measurement as the image's on every platform.
The threat model's SEV-SNP row answers "Attacker rebuilds VM image with
malicious code" with "launch MEASUREMENT changes"; ADR 0016 says a kernel
update is a new measurement; ADR 0023, the sealer's own comment and
KNOWN_ISSUES say a new image does not open a sealed file; the banking map
rests "only authorised software installed" on the pinned measurement. On
Intel TDX that holds — the pin is SHA-384 over MRTD and RTMR0–3, which
carry the kernel, its initrd and command line. On Azure it holds where the
operator pins the vTPM's PCR digest, which the paravisor's vTPM, inside the
TEE, measured. On AWS Nitro the measurement is the enclave image itself.
On a Compute Engine SEV-SNP guest it does not hold: the verifier
(`gcp_sev_snp.go`) reads the chip's report alone, and the sealer
(`gcp_sev_snp_seal.go`) derives its key from the VCEK root with the launch
measurement and the guest policy mixed in — Google's firmware and the
policy, the same for any operating system on that chip.

## Decision

1. **A SEV-SNP guest attests with the chip's report and its vTPM's quote
   under one challenge, where the platform gives it a vTPM.** The quote is
   the `tpm2` evidence of ADR 0025 step 3: a TPM2_Quote over the boot PCRs
   with SHA-256(nonce) in extraData, by the attestation key the vTPM's
   vendor certified; the report's REPORT_DATA carries SHA-256(nonce) in its
   first half and SHA-256 of that key's public key in its second, so the
   chip's word names the key whose quote rides with it.
2. **The verifier holds both:** the chip's report as today (the AMD chain,
   the attack record, the launch measurement against the policy), the
   attestation key's certificate to the vendor's pinned root, the quote's
   signature and nonce, and the PCR digest against the digests the policy
   names. A peer whose evidence carries no quote, or whose PCR digest the
   policy does not name, is refused; there is no default that accepts any
   boot.
3. **A key file is sealed to both:** `tee.sealer: both` nests the chip's
   derived key inside the vTPM's sealed object under the PCR policy
   (`sev_snp_vtpm_sealer.go`). It opens only on this chip, at this launch
   measurement and policy, and on a boot whose PCRs the policy names.
4. **The vTPM is the platform's, and the record says so.** On Compute
   Engine the vTPM is Google's software, outside the TEE: the boot chain is
   held to it against everyone who can change the disk, and Google is
   trusted for it as it is for the firmware it measures. A guest whose whole
   boot chain the chip itself measures — measured direct boot on the
   operator's own SEV-SNP host — is the next step and its own decision.

## Consequences

- An operating system swapped on the disk, or a kernel the operator did not
  name, gets no key and opens no sealed file, on the same chip as on
  another.
- A kernel update is an operator's act: the new boot's PCR digest is pinned
  and the key files are sealed again before the old boot is retired.
- The `sev-snp` evidence without a quote stays readable for one release, and
  is refused by a policy that requires the boot chain.

## Alternatives considered

- **The launch measurement alone, with the image pinned elsewhere** (a hash of
  the boot disk checked by the operator). Nothing on the guest would hold it
  at release time: a disk swapped after the check boots unnoticed, and the
  chip's key would still open the files.
- **Google Cloud Attestation as the verifier.** It reads the same vTPM quote
  and returns Google's token; it would make every key release depend on a
  Google service and on the Internet, which the product's offline, pinned
  verification exists to avoid (ADR 0024). The verifier here pins Google's
  EK/AK root and needs nothing at release time but the AMD KDS cache.
- **Appraising the event log instead of a PCR digest** (the kernel's digest
  from the PCR 9 event, the command line from PCR 8). It survives changes the
  digest does not — GRUB's environment, a grub.cfg rewritten with the same
  kernel — and names what changed. It is the next refinement of the policy;
  the digest is what the vTPM's own sealing policy can enforce, so the two
  halves of this decision hold the same thing today.
- **Sealing to the vTPM alone** (`tee.sealer: tpm2`, ADR 0025 step 1b). The
  file would open on any chip whose vTPM state moved with the disk; nesting
  keeps the chip's binding and adds the boot's.
- **Measured direct boot** — the kernel, its initrd and command line hashed
  into the launch measurement by the firmware, so the chip measures the whole
  boot. Compute Engine runs Google's firmware only; this needs the
  operator's own SEV-SNP host, and is its own decision.

## Implementation notes

- `internal/shared/tee/gcp_sev_snp_vtpm.go` — the family: the envelope
  (`vault-genome/gcp-sev-snp-vtpm/v1`), the producer and the verifier; the
  chip half is `GCPSEVVerifier.verify` unchanged.
- `internal/shared/tee/gce_vtpm.go` — Google's attestation key: the
  instance-information extension (OID 1.3.6.1.4.1.11129.2.1.21, the fields
  Google's verifier reads in go-tpm-tools' `server/instance_info.go`), the
  certificate's chain to the pinned root, the template at NV 0x01c10001 turned
  into `tpm2_createprimary` arguments (`-u` takes the unique field with its
  length word little-endian), the producer's half (the key made once, made
  again when a long-lived daemon's context is gone, the intermediate from
  the certificate's issuer URL unless the operator gives it).
- `internal/shared/tee/gce_roots.go` — Google's EK/AK root, the same bytes its
  issuer URL served and go-tpm-tools ships (SHA-256 fingerprint
  `59:47:59:59:…:BE:B2`); the intermediate rotates and rides with the
  evidence.
- `internal/shared/tee/sev_snp_vtpm_sealer.go` — the chip's sealer nested in
  the vTPM's; `tee.sealer: both`, the default (`auto`) of
  `gcp-sev-snp-vtpm`, defaulting to `sha256:0-9`.
- `sagvd`, `acp-compute`, `acp-bootstrap`: `tee.provider` and the peer and
  registry entries take `gcp-sev-snp-vtpm`; `pcr_digests` is required for
  it; `pcr_selection`, `gce_project_ids`, `gce_ek_ak_roots_path`,
  `vtpm_quote_pcrs` and `ak_intermediates_path` are its own fields;
  `identity` prints `vtpm.pcr_digest_hex`. A delegated (RATS) Verifier is
  refused for it: those read the chip's report, not the quote beside it.
  `acpctl provision` points to the runbook
  (`docs/operator/runbooks/real-tee-gcp-sev-snp-vtpm.md`).
- PCR selection `sha256:0-9`: the firmware's (0–7) and GRUB's (8: its
  commands and the kernel's command line; 9: every file it read, the kernel
  and its initrd among them). The kit found no PCR of 0–14 moved by a plain
  reboot once the image's first boot had settled, PCRs 8, 9 and 10 moved by
  another kernel, and PCR 5 moved by the first boot (the root partition grows).

## Evidence

[C53](../../VERIFIABLE-CLAIMS.md#c53): four boots of one Compute Engine n2d
SEV-SNP instance (`scripts/hardware-test/gcp-sev-snp/boot-chain/`, run
`20261024T160531Z`, `RESULT: PASS`): the chip's measurement the same under
kernel 7.0.0-1014-gcp and 7.0.0-1013-gcp, and the chip-sealed text opened
under both; the shipping verifier, the second boot pinned, accepted that boot
and the same boot after a reboot and refused the other kernel; the
chip-and-vTPM file opened after the reboot and not under the other kernel.
Run `20261024T155106Z` recorded which PCRs moved between boots and the vTPM
seal under three selections. Offline, the verifier accepts boot B's captured
evidence and refuses it altered seven ways (`gcp_sev_snp_vtpm_test.go`).
