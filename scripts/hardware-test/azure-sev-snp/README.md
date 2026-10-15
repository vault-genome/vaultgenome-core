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
  stored in vTPM NV index `0x1400001` (2900 bytes, owner-hierarchy read). Layout,
  as `scripts/02-capture-attestation.sh` parses it (read on a `Standard_DC4as_v5`
  on 2026-10-14, HCL header version 2): a 32-byte `HCLA` header (signature,
  version, report size, request type, status); the 1184-byte SNP report; a
  20-byte runtime-data section header (section size, version, report type, hash
  type, data size); the runtime data, a JSON document with the vTPM's AK and EK
  public keys and the VM configuration (1233 bytes that day); zero padding to the
  index size. `report.bin` is the extracted SNP report; `runtime-data.bin` the
  bytes after the report; `hcl-report.b64` the full HCL blob.
- **REPORT_DATA:** `SHA-256(runtime data) || 0^32` — Azure's binding of the
  report to this vTPM. The capture step computes it from the runtime data and
  refuses a report that does not carry it; `02b` has snpguest check the same
  value against the signed report, and `02f` checks that the MAA token's
  `x-ms-sevsnpvm-reportdata` and launch-measurement claims are the report's.
- **Workload manifest:** `02b` runs after Demo 1 and writes the manifest with
  the digest acpctl measured over what it sealed (`demo1-inspect.json`), not a
  constant. On Azure the report cannot bind it (REPORT_DATA is Azure's, above),
  so it is recorded next to the report, not bound by it.
- **Certificates:** `02` records the VCEK and chain that Azure's THIM endpoint
  (`169.254.169.254/metadata/THIM/amd/certification`) serves for this chip and
  TCB; `02b` fetches the same from AMD KDS and requires the two VCEKs to match.
- **Report properties:** version 3 on 2026-09-14 (East US, Milan), version 5 on
  2026-10-14 (West Europe, `Standard_DC4as_v5` on an EPYC 9V74 — Genoa, CPUID
  family 0x19 model 0x11; the chain is SEV-Genoa / ARK-Genoa). The product
  line is read from the report by `02b`, not assumed; `SNP_CHIP` overrides it.
  `signing_key = VCEK`, `mask_chip_key = 0` (real chip id), `vmpl = 0`.
  REPORT_DATA binds the Azure **runtime data** (the vTPM AK material), not our
  own key — binding our X25519 key would go through the vTPM AK, a follow-up.

## The run of 2026-10-14

`evidence/20261014T232742Z/` holds one end-to-end run of this kit on a fresh
`Standard_DC4as_v5` (Genoa) in West Europe: the HCL report from the vTPM with
the REPORT_DATA check, the AMD chain (AMD CHAIN VALIDATION PASSED, THIM's VCEK
the same key as KDS's), the MAA token with its claims checked against the
report (MAA CHAIN VALIDATION PASSED), Demo 1 with the tamper refusal, Demo 2,
the byte-identical inference comparison and the runner's log. Its README
reads the files and says where the runner stopped. `evidence/20261015T010417Z/`
is the same run a day later with the workload manifest naming what Demo 1
sealed, as acpctl measured it, recorded next to the report (#83).

## Verification

`internal/shared/tee/azure_sev_snp_verify_test.go` proves, with the SAME real
verify path used for GCP:

1. parse at fixed offsets (measurement 48B SHA-384, chip_id non-zero);
2. VCEK fetched from AMD KDS by chip_id + reported TCB (`vcek.bin`, cached);
3. ECDSA-P384 report signature verifies under the VCEK;
4. VCEK → ASK → ARK chain verifies (`cert_chain.pem`, cached; ARK-Milan for the
   2026-09-14 capture).

The cached `vcek.bin` / `cert_chain.pem` make the test offline after the first
run. This is real Azure hardware attestation chained to AMD's root of trust.
