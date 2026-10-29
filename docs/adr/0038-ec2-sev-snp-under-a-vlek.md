# ADR 0038 — EC2 on AMD SEV-SNP under a VLEK: the provider's key in place of the chip's, the certificate carried with the report, no machine identity and a fleet-wide sealing key

- **Status:** Accepted (2026-10-29) — implemented: the `aws-sev-snp` family (producer, verifier, the three daemons, the registry, `acpctl provision` and `acpctl tee fetch-amd-chain --signer vlek`); the first capture under `internal/shared/tee/testdata/aws-sev-snp/20261029T155800Z`
- **Date:** 2026-10-29
- **Deciders:** Serhii Nikolaichuk, Rodion Sorokin
- **Extends:** ADR 0024 (the AMD roots this build pins), ADR 0025 (a family is named by the shape of its evidence; `auto`), ADR 0033 (the attack record: the TCB floors and the chip), ADR 0034 (the differential corpus), ADR 0037 (the launch measurement is the cloud's firmware)

## Context

Amazon EC2 runs AMD SEV-SNP on `m6a`, `c6a` and `r6a` instances (AMD Milan) in
US East (Ohio) and Europe (Ireland), with `--cpu-options AmdSevSnp=enabled`.
Three such instances were captured on 2026-10-29 (`CAPTURE.md` beside the
bytes): two `m6a.large` in two zones and one `m6a.xlarge`, Ubuntu 24.04 with
kernel 7.0.0-1014-aws, configfs-tsm present. What they showed differs from a
Compute Engine Confidential VM in four ways that the tree, written for GCP,
did not allow for:

1. **The report is signed by a VLEK, not a VCEK.** FLAGS.SIGNING_KEY is 1.
   AMD issues a Versioned Loaded Endorsement Key to a cloud provider per
   product line and TCB; the provider loads it onto its hosts. The VLEK
   captured is the same certificate on all three hosts, in both zones
   (`CN=SEV-VLEK`, issued by `SEV-VLEK-Milan`, valid to 2027-10-01); its
   CSP_ID extension (1.3.6.1.4.1.3704.1.5) reads `CN=cc-us-east-2.amazonaws.com`.
   The verifier of `gcp-sev-snp` refuses any report not signed by the VCEK
   (`gcp_sev_snp.go`, "this verifier accepts ECDSA P-384 (1) by the VCEK (0)").
2. **CHIP_ID is zero.** The sixty-four bytes that name a chip on GCP are
   all zero on EC2 (MASK_CHIP_KEY is 0, yet the firmware reports no chip id
   under a VLEK). The verifier's first step on GCP is to fetch the VCEK from
   AMD's Key Distribution Service by CHIP_ID and TCB; for an EC2 report that
   request names no chip and fails before anything else is checked. A policy
   that pins machines (`sev_snp.chip_ids`, ADR 0033 decision 7) has nothing
   to pin.
3. **KDS does not serve the VLEK.** It serves the chain above it —
   `/vlek/v1/<product>/cert_chain`: the ASVK (`SEV-VLEK-<product>`) and the
   ARK, the latter byte-equal to the root this build pins for Milan. The
   VLEK itself comes only from the host, in the certificate table beside the
   report (configfs-tsm's `auxblob`): one entry, GUID
   `a8074bc2-a25a-483e-aae6-39c045a0b8a1`, 1319 bytes of DER. The tree read
   that table (`tsm_configfs.go`) and dropped it on every path a verifier
   sits on (`cmw.go`, "no verdict here depends on it").
4. **The key the firmware derives for the guest is the fleet's.**
   SNP_GET_DERIVED_KEY with root key VCEK gave the same thirty-two bytes on
   all three hosts, in both zones, and after a reboot and two stop/starts of
   one of them. On GCP that key is a chip's (ADR 0016); on EC2 it is not. A
   file sealed with it opens on any EC2 SEV-SNP guest of the same launch
   measurement and guest policy — which also means it survives a stop/start
   that moves the instance to another host.

Two things are the same as on GCP and matter: the report's TCB
(bootloader 4, TEE 0, SNP 0x1F, microcode 0xE1, firmware 1.58.3, mitigation
vector 0xfef, ALIAS_CHECK_COMPLETE) sits above the floors of ADR 0033 as read
on 2026-10-22; and the launch measurement is the cloud's firmware, as ADR 0037
found for Google's — here AWS's published UEFI (github.com/aws/uefi, release
20260814), whose `sev-snp-measure --mode snp --vcpus N --vmm-type ec2` value
for 2 and 4 vCPUs is exactly what the chips reported.

## Decision

1. **A family of its own: `aws-sev-snp`.** ADR 0025 names a family by the
   shape of its evidence, not by the cloud. The shape here is different:
   a report whose signer is not in any key server, plus the certificate the
   host hands out. The evidence is a JSON envelope, schema
   `vault-genome/aws-sev-snp/v1`, media type
   `application/vnd.vault-genome.aws-sev-snp-evidence`: the 1184-byte report
   and the VLEK, DER. It travels as Evidence on every path — the Return Path,
   cross-cloud restore, the receipts, the sentinel — without a round trip to
   anyone, as the `gcp-sev-snp-vtpm` envelope does (ADR 0037). The report
   alone is refused by name: it does not carry the key that signed it.
2. **The producer refuses a host that is not this family.** On its first
   report it requires SIGNING_KEY = 1 and a VLEK in the certificate table,
   and holds the VLEK to its own report (below); a host whose reports the
   VCEK signs is told to run as `gcp-sev-snp` (or `auto`, which tells them
   apart by the machine's DMI vendor, `Amazon EC2`, since the kernel's
   provider name, `sev_guest`, is the same for both).
3. **The verifier holds the VLEK to the report before it trusts a
   signature:** subject `SEV-VLEK`; issuer `SEV-VLEK-<product>` for the
   product the report's CPUID names; the AMD extensions — `productName`
   equal to that product, no `hwID` (a VCEK's), the four SPLs (bootloader,
   TEE, SNP, microcode) equal to REPORTED_TCB — a VLEK is for one TCB, like
   a VCEK; the certificate within its validity; a CSP_ID present. Then the
   chain VLEK ← ASVK ← ARK, the intermediate's name of the right kind (an
   ASK does not vouch for a VLEK, nor an ASVK for a VCEK; the refusal says
   which it was given) and the root one this build pins; then the report's
   ECDSA P-384 signature under the VLEK; then everything `gcp-sev-snp`
   holds a report to — the DEBUG bit, the VMPL, the minimum TCB, the attack
   record of ADR 0033, the nonce, HOST_DATA, the launch measurement.
4. **The provider is a policy; the chip is not.** `tee.peer.csp_ids` (and
   `csp_ids` on a registry entry) names the providers whose VLEK may sign
   the peer's report, as the extension spells them, one per AWS region.
   Empty accepts any VLEK that chains to AMD's root, and the record says
   whose it was. `sev_snp.chip_ids` is refused for this family at start:
   there is no chip to name. What the report does carry per boot is
   REPORT_ID; the record now carries it for every SEV-SNP family
   (`SEVSNPReportDetail.report_id_hex`), with the signer's kind
   (`signing_key`) and, for this family, what the VLEK said (`vlek`:
   CSP_ID, product, TCB, validity, its fingerprint). The threat model's
   line that the audit record names REPORT_ID is true from here on.
5. **The chain is the operator's file, as before, fetched for the right
   signer.** `amd_cert_chain_path` for an `aws-sev-snp` peer is the ASVK+ARK
   bundle; `acpctl tee fetch-amd-chain --signer vlek` fetches it from
   `/vlek/v1/<product>/cert_chain` and verifies it against the pinned roots;
   the daemons refuse a VCEK (ASK) bundle for this peer at start, where the
   operator sees it. `vcek_cache_dir` and `amd_kds_url` do not apply: there
   is no VCEK, and the verifier never speaks to KDS for this family.
6. **The launch measurement is AWS's published firmware, and the pin can
   be computed.** `acpctl provision` pins it on first use as for every
   family; the runbook and the kit compute the expected value from the
   published binary with sev-snp-measure (the hash of the binary and the
   release recorded), so the pin rests on AWS's publication, not on the
   first report alone. The operating system is not in the measurement (ADR
   0037's finding holds); an EC2 instance offers this family no vTPM in
   this build, so the boot is not pinned here — the family's record says
   what it does and does not cover.
7. **The sealer is the firmware's derived key, and the record says what
   it binds.** `tee.sealer auto` and `tee` give `sev-snp-derived-key`;
   `tpm2` and `both` are refused (no vTPM). A sealed file opens on any EC2
   SEV-SNP guest of the fleet with the same launch measurement and guest
   policy — not on one machine. The sealed-file header names the family
   (`tee: aws-sev-snp`), so a file sealed here is never opened as a
   `gcp-sev-snp` file or the reverse. The threat model and the runbook say
   this in plain words; KNOWN_ISSUES carries it as a limitation.
8. **The delegated Verifier does not take this family yet.** `tee.peer.verifier`
   (ADR 0025 step 2b) is refused for an `aws-sev-snp` peer: the delegated
   Verifiers read the chip's report, not the VLEK beside it. Veraison's
   VLEK support is a question for the bench, not assumed here.
9. **The corpus takes VLEK-signed reports** (ADR 0034): the manifest gains
   a `signer` column, a VLEK is taken from beside the report (the capture's
   certificate table or `vlek.pem`) and never fetched, and the chain per
   product and signer is kept apart (`chains/Milan.pem`, `chains/Milan-vlek.pem`).
   The oracle hands go-sev-guest the VLEK as a VLEK.

## Consequences

- A fourth family on a fourth cloud for one-button deployment and for key
  release, with the same policy (ADR 0033) and the same roots (ADR 0024).
- Honest limits, on the record: no machine identity on EC2; a sealing key
  that is the fleet's; a boot the measurement does not cover. A customer
  who needs a machine pinned or a boot pinned has GCP and Azure for that;
  the claim for EC2 (C58) is a deployment attested under AMD's root
  through the provider's key, gated EXACT, with the audit log verified.
- The first capture is the family's fixture: the verifier's real
  cryptography runs on it offline (`aws_sev_snp_test.go`), and the kit
  of C58 runs the daemons on EC2 itself.
- What was not done, and why: NitroTPM (a vTPM for EC2 instances, which
  would pin the boot and seal to a host) is not combined with SEV-SNP in
  this build — whether AWS allows both on one instance is to be read from
  AWS's documentation and tried, not assumed; and the delegated Verifier
  (decision 8).

## Evidence

- `internal/shared/tee/testdata/aws-sev-snp/20261029T155800Z/`: three hosts'
  reports (configfs-tsm, two nonces each, and snpguest's at VMPL 1), the
  certificate tables, the VLEK snpguest read, AMD's VLEK and VCEK chains from
  KDS, snpguest's own verification, the derived keys, the reboot and
  stop/start comparison; `CAPTURE.md` reads them; `SHA256SUMS` fixes them.
- AWS's UEFI releases 20260814, 20240809 and 20240112 measured locally with
  sev-snp-measure 0.0.13: only 20260814 gives the reported measurements
  (2 vCPUs `7a89ccea…`, 4 vCPUs `1d8ee9ba…`).
- `scripts/hardware-test/aws-sev-snp/evidence/20261029T164825Z/`: the kit's
  run on an `m6a.xlarge` in us-east-2 from this tree — the family resolved
  from the host by `provision --provider auto`, the VLEK chain from KDS,
  eight key files sealed with the derived key, the handshake under the
  VLEK, the gate EXACT, sixteen audit events verified, the measurement
  equal to the published UEFI measured locally (claim C58).
