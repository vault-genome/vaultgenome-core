# Azure SEV-SNP live evidence

Genuine AMD SEV-SNP attestation from a **live Azure Confidential VM** — the second
cloud proven after GCP.

## Provenance

- **VM:** `Standard_DC4as_v5` (AMD SEV-SNP), image
  `Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest`,
  `--security-type ConfidentialVM`, vTPM + secure boot, East US. Created and
  destroyed for this capture (2026-09-14).
- **How the report was obtained:** Azure mediates SEV-SNP through the paravisor
  and the **vTPM**, so there is no `/dev/sev-guest` and the direct configfs-tsm
  provider is not wired. The AMD-signed report is embedded in the **HCL report**
  stored in vTPM NV index `0x1400001` (2900 bytes, owner-hierarchy read). Layout:
  32-byte `HCLA` header, then the 1184-byte SNP report, then 1684 bytes of
  runtime data. `report.bin` is the extracted SNP report; `runtime-data.bin` the
  trailing runtime data; `hcl-report.b64` the full HCL blob.
- **Report properties:** version 3, `signing_key = VCEK`, `mask_chip_key = 0`
  (real chip id), `vmpl = 0`. REPORT_DATA binds the Azure **runtime data** (the
  vTPM AK material), not our own key — binding our X25519 key would go through the
  vTPM AK, a follow-up.

## Verification

`internal/shared/tee/azure_sev_snp_verify_test.go` proves, with the SAME real
verify path used for GCP:

1. parse at fixed offsets (measurement 48B SHA-384, chip_id non-zero);
2. VCEK fetched from AMD KDS by chip_id + reported TCB (`vcek.bin`, cached);
3. ECDSA-P384 report signature verifies under the VCEK;
4. VCEK → ASK → ARK-Milan chain verifies (`cert_chain.pem`, cached).

The cached `vcek.bin` / `cert_chain.pem` make the test offline after the first
run. This is real Azure hardware attestation chained to AMD's root of trust.
