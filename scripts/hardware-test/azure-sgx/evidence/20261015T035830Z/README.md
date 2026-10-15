# Azure SGX — the run of 2026-10-15, 03:58Z (the release enclave)

The same kit and VM shape as the runs of 00:48Z and 01:00Z
(`../20261015T004844Z/`, `../20261015T010027Z/`): one `Standard_DC4s_v3` in
East US 2 (Xeon Platinum 8370C), Ubuntu 22.04 (kernel 6.8.0-1070-azure),
driven end to end by `examples/full-test-run.sh` on the tree of commit
`f453378` with the kit changes of this run (`acpctl` sha256 `537b1ad4…`, Go
tree `f453378`). Started 03:58:30Z, phases done 04:04:05Z, evidence
downloaded, VM and resource group destroyed by the runner by 04:06:52Z.
`full-test-run.log` is the runner's output.

What changed in the run: the kit's binding enclave is a **release enclave**.
`sgx-quote-binding/enc/enc.conf` says `Debug=0` and the host creates it
without the debug flag; the quote's attributes word is `0x5` —
`INIT | MODE64BIT`, no `DEBUG` — where the 01:00Z run's was `0x7` (read from
`04-sgx-quote.bin`, report body offset 48). MRENCLAVE is now `e187a2a4…f85c`
(the image was built and signed with debug off; the 01:00Z enclave measured
`2715763f…`); MRSIGNER `d253d459…f61e` is the key generated on this VM at
build time, as before (the build tree with that key is not committed).

The rest is the chain of 01:00Z, on the release enclave. Demo 1 sealed the
model first and the workload manifest
(`attestation-validation/vault-genome-sgx-test/01-vaultgenome-payload-manifest.json`)
names it as acpctl measured it — `payload_sha256` `c42f7c25…e1f074`,
2 019 402 752 payload bytes, bundle sha256 `b0a0b583…37a7`, 2 019 436 683
bundle bytes, sealed 04:01:49Z. The enclave put SHA-256(this manifest) into
the quote's REPORT_DATA (`1c81a9bf…752b` ‖ zeros; `06-intel-chain-verify.txt`:
binding verified). `oeverify` validated the chain Quote → PCK → Intel SGX
Root CA on the OE report and on the raw quote (`07-oe-verify.txt`, two
successes). The kit's own `libsgx-dcap-quote-verify` caller
(`sgx-quote-binding/host/verify-quote.c`) now tries the quote provider's own
collateral first (`sgx_qv_verify_quote` with a null collateral) and then the
collateral it fetches itself (`tee_qv_get_collateral`, 13 500 bytes); both
return `0xE03A` (`SGX_QL_TCBINFO_CHAIN_ERROR`) with the Azure DCAP client
1.13.1 as the provider — the same quote `oeverify` validates — so the local
chain of record is still `oeverify`, and `11-policy-validation-summary.txt`
says so on its own line.

Microsoft Azure Attestation attested the same quote with the manifest as
runtime data (`sharedeus2`): the token carries `x-ms-sgx-is-debuggable:
false`, and the new Step D2 of `02f` (`17-maa-claims-vs-quote.txt`) checks
the token's MRENCLAVE, MRSIGNER and REPORT_DATA against the bytes of the
quote itself and the debug flag against the claim — five `OK`; the token's
signature verified against MAA's published certificates
(`19-maa-jwt-verify.txt`); both summaries read PASSED.

The rest is as at 01:00Z: the 4734-byte SGX_ECDSA evidence from `oeutil`
with its endorsements (the OE report in `04-sgx-quote.bin.oe` and
`05-quote-dump.txt` are from oeutil's own enclave, informational); Demo 1 —
seal, open, verify, one flipped byte refused with exit 4; Demo 2 — six
generations, lineage, rewind; inference — the original and the restored
model's answers byte-identical (759 bytes). The subscription id and the
laptop's ssh public key are redacted in `azure-imds.json` and the log;
quotes, endorsements and report data are byte for byte what the VM produced.
