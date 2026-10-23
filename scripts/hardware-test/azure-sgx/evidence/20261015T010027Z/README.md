# Azure SGX — the run of 2026-10-15, 01:00Z (the manifest names what was sealed)

The same kit and VM shape as the run of 00:48Z (`../20261015T004844Z/`): one
`Standard_DC4s_v3` in East US 2, Ubuntu 22.04 (kernel 6.8.0-1070-azure),
driven end to end by `examples/full-test-run.sh` on the tree of commit
`f07cc7e` (`acpctl` sha256 `5cf55e9f…`, Go tree unchanged since `85f6a11`).
Started 00:55Z, phases done 01:00:27Z, VM and resource group destroyed by
the runner by 01:02:43Z. `full-test-run.log` is the runner's output.

What changed in the run (#83): Demo 1 ran **before** the chain steps and
wrote `demo1-inspect.json`; the workload manifest
(`attestation-validation/vault-genome-sgx-test/01-vaultgenome-payload-manifest.json`)
names what Demo 1 sealed as acpctl measured it — `payload_sha256`
`c42f7c25e88d…e1f074`, 2 019 402 752 payload bytes, bundle sha256
`1fc00c1a…`, 2 019 436 684 bundle bytes, sealed 2026-10-15T00:58:56Z — and
names the method. The kit's enclave put SHA-256(this manifest) into the
quote's REPORT_DATA (`085524d5…` ‖ zeros, `06-intel-chain-verify.txt`:
binding verified), `oeverify` validated the chain Quote → PCK → Intel SGX
Root CA on the OE report and on the raw quote (`07-oe-verify.txt`, two
successes; the kit's own QVL caller still returns 0xE03A), and Microsoft
Azure Attestation attested the same quote with the manifest as runtime
data: the token's `x-ms-sgx-report-data` is the manifest's hash
(`19-maa-jwt-verify.txt`), signature verified; both summaries read PASSED.
MRENCLAVE `2715763f…` is the same enclave as at 00:48Z; MRSIGNER differs
because the signing key is generated on each VM at build time (the build
tree with that key is not committed).

The rest is as at 00:48Z: the 4734-byte SGX_ECDSA evidence from `oeutil`
with its endorsements; Demo 1 — seal, open, verify, one flipped byte refused
with exit 4; Demo 2 — six generations, lineage, rewind; inference — the
original and the restored model's answers byte-identical (759 bytes). The
subscription id and the laptop's ssh public key are redacted in
`azure-imds.json` and the log; quotes, endorsements and report data are byte
for byte what the VM produced.
