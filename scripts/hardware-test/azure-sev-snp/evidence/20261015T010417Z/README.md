# Azure SEV-SNP — the run of 2026-10-15 (the manifest names what was sealed)

The same kit and VM shape as the run of 2026-10-14 (`../20261014T232742Z/`):
one `Standard_DC4as_v5` Confidential VM (EPYC 9V74, Genoa) in West Europe,
Ubuntu 22.04 CVM image (kernel 6.8.0-1068-azure-fde), driven end to end by
`examples/full-test-run.sh` on the tree of commit `f07cc7e` (`acpctl`
sha256 `5cf55e9f…`, Go tree unchanged since `85f6a11`). Terraform created
the VM at 00:54Z after destroying the VM of an earlier attempt that had
stopped in the MAA step on an unpadded base64url segment (fixed in the kit
the same hour); the phases ended at 01:04:17Z; the runner downloaded the
archive and destroyed the VM and its resource group by 01:06:21Z.
`full-test-run.log` is the runner's output, start to end.

What changed in the run (#83): Demo 1 ran **before** the chain steps and
wrote `demo1-inspect.json`; the workload manifest
(`attestation-validation/vault-genome-sev-snp-test/01-vaultgenome-payload-manifest.json`)
names what Demo 1 sealed as acpctl measured it — `payload_sha256`
`c42f7c25e88d…e1f074`, 2 019 402 752 payload bytes, bundle sha256
`f7b26044…`, sealed 2026-10-15T01:02:32Z — and names the method. On Azure
the report cannot carry a caller's REPORT_DATA: the paravisor binds the vTPM
runtime data (REPORT_DATA = SHA-256(runtime data) ‖ 0^32, checked in
`hcl-layout.txt`, `0f21621d…`), so the manifest is **recorded** next to the
report, not bound by it, and `11-policy-validation-summary.txt` says so.

The rest is as on 2026-10-14: the HCL report from the vTPM; the AMD chain
for Genoa from KDS verified with THIM's VCEK carrying the same key and chip
id (AMD CHAIN VALIDATION PASSED, 01:03:23Z); the MAA token from the shared
West Europe endpoint with its claims checked against the report and its
signature verified (MAA CHAIN VALIDATION PASSED, 01:03:25Z); Demo 1 — seal,
open, verify, one flipped byte refused with exit 4; Demo 2 — six
generations, lineage, rewind; inference — the original and the restored
model's answers byte-identical (649 bytes). The subscription id and the
laptop's ssh public key are redacted in `azure-imds.json` and the log;
the report, the certificates and the binary files are byte for byte what the
VM produced.
