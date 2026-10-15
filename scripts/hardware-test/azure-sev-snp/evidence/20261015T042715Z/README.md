# Azure SEV-SNP — the run of 2026-10-15, 04:27Z (the manifest bound through the vTPM)

The same kit and VM shape as the runs of 2026-10-14 and 01:04Z
(`../20261014T232742Z/`, `../20261015T010417Z/`): one `Standard_DC4as_v5`
Confidential VM (AMD Genoa, read from the report's CPUID family and model)
in West Europe, Ubuntu 22.04 CVM image (kernel 6.8.0-1068-azure-fde),
driven end to end by `examples/full-test-run.sh` on the tree of commit
`f453378` with the kit change of this run (`acpctl` sha256 `537b1ad4…`, Go
tree `f453378`; the runner's checkout was `be1f22e`, `f453378` plus the SGX
kit's commit of the same night, which this kit does not use). The runner first destroyed the VM of the 03:58Z attempt
(below), created this one, ran the phases — the manifest sealed 04:36:00Z,
AMD CHAIN VALIDATION PASSED 04:37:20Z, MAA CHAIN VALIDATION PASSED
04:37:22Z — downloaded the archive and destroyed the VM and its resource
group by 04:40:31Z. `full-test-run.log` is the runner's output, start to end.

What changed in the run: on Azure the chip's report cannot carry a caller's
REPORT_DATA — the paravisor binds the vTPM's runtime data there (REPORT_DATA
= SHA-256(runtime data) ‖ 0^32, checked in `hcl-layout.txt` and
`10-verify-report-data-binding.txt`) — so until this run the workload
manifest was recorded next to the report, not bound by it. Now it is
**bound through the vTPM** (`02b`, Step 4): the runtime data the report
commits to names the vTPM's attestation key (`HCLAkPub`); the kit reads
the vTPM's persistent handles (`14-tpm-handles.txt`: `0x81000001`,
`0x81000003`, `0x81000004`), reads each one's public key
(`14-tpm-0x….pem`) and finds the one whose RSA modulus is `HCLAkPub`'s —
`0x81000003` (`14-ak-handle.txt`, `14-ak-pub.pem`); asks that key for a
quote over PCRs 0–14 (sha256) with SHA-256(manifest) as the qualifying
data (`14-manifest-sha256.hex`: `af10d76d…c9c1`; `14-manifest-quote.msg`,
`.sig` — 256 bytes, RSA-2048 — and `.pcrs`); and verifies the quote with
the key the report names (`tpm2_checkquote`, `14-manifest-binding.txt`:
the PCR values, the signature, `VERIFIED`). The chain is therefore: the
chip's report → (REPORT_DATA) the runtime data → `HCLAkPub` → the quote →
SHA-256(manifest) → the manifest
(`01-vaultgenome-payload-manifest.json`: `payload_sha256`
`c42f7c25…e1f074`, 2 019 402 752 payload bytes, bundle sha256
`d94c59a6…edc9`, 2 019 436 684 bundle bytes, sealed 2026-10-15T04:36:00Z,
as acpctl measured it). `11-policy-validation-summary.txt` has the new
line, "Workload manifest bound through the vTPM".

The attempt of 03:58Z stopped at that step twice, on the fresh VM and then
on the same VM with the first fix: the vTPM device is root/tss-only on this
image (`02` had read the NV index with sudo; Step 4 had not), and the public
keys `tpm2_readpublic` writes under sudo are created 0660 root:root, so the
comparison read nothing and found no key. Step 4 now runs the TPM tools
with sudo and hands each file to the user before it is read; the fix was
tested on that VM (`02b` and `02f` PASSED there), the VM destroyed, and this
run made on a fresh one for the record.

The rest is as at 01:04Z: the HCL report from the vTPM; the AMD chain for
Genoa from KDS verified, with THIM's VCEK carrying the same key and chip id
and chaining to the same ARK (`13-vcek-thim-vs-kds.txt`); the MAA token
from the shared West Europe endpoint with its claims checked against the
report and its signature verified; Demo 1 — seal, open, verify, one flipped
byte refused with exit 4; Demo 2 — six generations, lineage, rewind;
inference — the original and the restored model's answers byte-identical
(649 bytes). The subscription id and the laptop's ssh public key are
redacted in `azure-imds.json` and the log; the report, the certificates,
the quote and the binary files are byte for byte what the VM produced.
