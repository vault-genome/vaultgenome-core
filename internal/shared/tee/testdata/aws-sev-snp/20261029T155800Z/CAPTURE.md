# AWS EC2 SEV-SNP: the first capture (29 October 2026, us-east-2)

Three Confidential VMs launched with `--cpu-options AmdSevSnp=enabled` from the Canonical Ubuntu 24.04 AMI
`ami-0fc53b217ec1ad816` (boot mode uefi-preferred, booted uefi; kernel 7.0.0-1014-aws): `host-a` m6a.large in
us-east-2a, `host-b` m6a.large in us-east-2b, `host-c` m6a.xlarge in us-east-2a. `capture.sh` ran on each as the
ubuntu user (the files under `host-*/`, hashes in each `sha256sums.txt`; the `snpguest/snpguest` binary itself is not
kept — v0.11.0, its sha256 in `snpguest/snpguest.sha256`); `pass2.sh` added AMD's chain from KDS and snpguest's own
checks; `probe.sh` and `host-b.reboot-test.log` are the reboot and stop/start comparison. The VMs were terminated
afterwards.

## What the reports say (identical on the three hosts unless noted)

- Report version 5, 1184 bytes; SIGNATURE_ALGO 1 (ECDSA P-384); POLICY 0x2030000; VMPL 0 from configfs-tsm, 1 from snpguest.
- FLAGS 0x4: AUTHOR_KEY_EN 0, MASK_CHIP_KEY 0, **SIGNING_KEY 1 (VLEK)**. CHIP_ID: 64 zero bytes on every host.
- CPUID family 0x19 model 0x01 stepping 0x01 (Milan; `AMD EPYC 7R13`). TCB current = reported = committed = launch:
  bootloader 4, tee 0, SNP 31 (0x1F), microcode 225 (0xE1); firmware 1.58.3; mitigation vector 0xfef (launch and current).
- PLATFORM_INFO 0x27: SMT, **TSME on**, ECC, ALIAS_CHECK_COMPLETE; no ciphertext hiding, no RAPL_DIS.
- HOST_DATA zero. REPORT_ID differs per boot (and per VM); the two configfs reports of one boot share it.
- MEASUREMENT: `7a89ccea…` with 2 vCPUs (host-a, host-b), `1d8ee9ba…` with 4 vCPUs (host-c) — exactly what
  `sev-snp-measure 0.0.13 --mode snp --vcpus N --vmm-type ec2 --ovmf ovmf_img.fd` gives for AWS's published UEFI
  release 20260814 (sha256 `67aaae01…`); releases 20240809 and 20240112 give other values.
- configfs-tsm: provider `sev_guest`, generation 1; the **auxblob is the host's certificate table with one entry**, the VLEK
  (GUID a8074bc2-a25a-483e-aae6-39c045a0b8a1, 1319 bytes DER) — no ASVK, no ARK, no VCEK. `/dev/sev-guest` present, no TPM.
- The VLEK is **the same certificate on all three hosts** (sha256 of the PEM `fac7c425…`): CN `SEV-VLEK`, issuer
  `SEV-VLEK-Milan`, valid to 2027-10-01; AMD extensions: structVersion 0, productName `Milan`, blSPL 4, teeSPL 0, snpSPL 31,
  ucodeSPL 225, **CSP_ID (1.3.6.1.4.1.3704.1.5) `CN=cc-us-east-2.amazonaws.com`**; no HWID extension.
- KDS `vlek/v1/Milan/cert_chain` = ASVK (`SEV-VLEK-Milan`, 2022-11-16..2047-11-16, issued by ARK-Milan) + ARK-Milan, the ARK
  byte-equal to the root pinned in `internal/shared/tee/amd_roots.go`. snpguest: `verify certs` and `verify attestation` pass.
- SNP_GET_DERIVED_KEY (root VCEK, default field select) gives **the same 32 bytes on all three hosts**, in both zones, and
  after a reboot and two stop/starts of host-b — on EC2 the "VCEK-rooted" derived key is a fleet key, not a chip's.
  Root key select `vlek` does not exist in the ABI (vcek or vmrk).
  The derived keys themselves (`snpguest/derived-vcek*.bin`) are not kept here: a fleet-wide key is not a
  fixture to publish. Their sha256 prefix `e37ea08659a68fef` stands in `host-b.reboot-test.log` and each
  host's `sha256sums.txt` (as the guest hashed them), and `SHA256SUMS` lists what this directory holds.
