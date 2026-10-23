# Azure SGX — the run of 2026-10-15, 04:36Z (Intel's quote provider; both local verifiers)

The same kit and VM shape as the run of 03:58Z (`../20261015T035830Z/`): one
`Standard_DC4s_v3` in East US 2 (Xeon Platinum 8370C), Ubuntu 22.04 (kernel
6.8.0-1070-azure), driven end to end by `examples/full-test-run.sh` on the
tree of commit `f453378` with the kit changes of this pull request
(`acpctl` sha256 `537b1ad4…`, Go tree `f453378`; the runner's checkout was
`be1f22e`, this branch's first commit, plus the changes below). The runner
first destroyed the VM on which the quote provider had been measured
(below), created this one at 04:38Z, ran the phases — the manifest sealed
04:41:33Z, the chain summary written 04:42:28Z, MAA 04:42:29Z — downloaded
the archive and destroyed the VM and its resource group. `full-test-run.log`
is the runner's output, start to end.

What changed in the run: **the kit's own verifier validates the chain.**
Until this run the kit's caller of `sgx_qv_verify_quote`
(`sgx-quote-binding/host/verify-quote.c`) returned `0xE03A`
(`SGX_QL_TCBINFO_CHAIN_ERROR`) with the Microsoft Azure DCAP client as the
quote provider, and `oeverify` was the only local verifier of the chain.
`01-bootstrap-vm.sh` now configures **Intel's QPL** (`libsgx-dcap-default-qpl`
1.27.101.1) the way Microsoft documents it for Azure — the PCK certificate
from Azure's Trusted Hardware Identity Management (`pccs_url` THIM v3, the
only source of it, since Azure registers these hosts with Intel
indirectly), the rest of the collateral from Intel PCS v4
(`collateral_service`) — and no longer installs the Azure DCAP client.
`06-intel-chain-verify.txt`: the QVL through that provider answers
`0x0000` on its first path, verification result `SW_HARDENING_NEEDED`
(`0xA007`: the chain valid, Intel's current TCB status for the platform an
advisory), collateral within its validity window, **chain VALIDATED**;
`07-oe-verify.txt`: `oeverify` two of two on the same quote;
`11-policy-validation-summary.txt`: `CHAIN VALIDATED BY BOTH LOCAL
VERIFIERS (QVL AND oeverify) AND WORKLOAD BINDING ESTABLISHED`.

`qpl-selection.txt` is the measurement behind the choice, made on the VM
of the 03:58Z attempt the hour before, on one quote: the Azure DCAP client
(1.13.1) at its default collateral version (v1) and at v4 answers `0xE03A`,
at v2 `0xE01B` (no collateral), at v3 `0x0000`; Intel's QPL on THIM v3 for
everything answers `0x0000` with THIM's collateral past its `nextUpdate`
(expiration status 1), on THIM v4 `0xE03A`, and on THIM v3 for the
certificate with Intel PCS v4 for the rest `0xA007` within validity. The
kit takes the last: the provider Microsoft documents, current collateral,
Intel's own word on the TCB.

The enclave is the release enclave of 03:58Z: MRENCLAVE `e187a2a4…f85c`
(the same image), attributes `0x5` — `INIT | MODE64BIT`, no `DEBUG`
(`04-sgx-quote.bin`, report body offset 48); MRSIGNER `734c375c…cce2` is the
key generated on this VM at build time (the build tree with that key is not
committed). The workload manifest
(`attestation-validation/vault-genome-sgx-test/01-vaultgenome-payload-manifest.json`)
names what Demo 1 sealed as acpctl measured it — `payload_sha256`
`c42f7c25…e1f074`, 2 019 402 752 payload bytes, bundle sha256
`95177349…e277`, 2 019 436 684 bundle bytes, sealed 2026-10-15T04:41:33Z —
and SHA-256(manifest) is the quote's REPORT_DATA (binding verified).
Microsoft Azure Attestation attested the same quote with the manifest as
runtime data: `x-ms-sgx-is-debuggable: false`, the token's MRENCLAVE,
MRSIGNER, REPORT_DATA and debug flag checked against the quote's bytes
(`17-maa-claims-vs-quote.txt`, five `OK`), the signature verified
(`19-maa-jwt-verify.txt`), MAA CHAIN VALIDATION PASSED.

The rest is as at 03:58Z: the 4734-byte SGX_ECDSA evidence from `oeutil`
with its endorsements, generated through the new provider; Demo 1 — seal,
open, verify, one flipped byte refused with exit 4; Demo 2 — six
generations, lineage, rewind; inference — the original and the restored
model's answers byte-identical (759 bytes). The subscription id and the
laptop's ssh public key are redacted in `azure-imds.json` and the log;
quotes, endorsements and report data are byte for byte what the VM produced.
