# Azure SGX — the run of 2026-10-15

One `Standard_DC4s_v3` (Intel SGX, DCsv3; Xeon Platinum 8370C) in East US 2,
image `0001-com-ubuntu-server-jammy` `22_04-lts-gen2` (kernel
6.8.0-1070-azure), driven from the laptop by `examples/full-test-run.sh` on
the tree of commit `275b118`, with `acpctl` sha256
`2efc6404b47b2708967ac2c7e6cef63feb8a203139bb9b980aed1f6bd50f20a5` (built
from `85f6a11`; the Go tree is the same). The run started at 00:43Z, the VM
was up at 00:44Z, the phases ended at 00:48:44Z, the runner downloaded the
archive and destroyed the VM and its resource group by 00:51Z (state empty).
`full-test-run.log` is the runner's output, start to end. The quota for this
family (0 in every region on 2026-10-14) was raised to 8 vCPUs through the
Azure Quota API the same night.

What the runner did, in order, and what each file records:

1. **Bootstrap.** Intel SGX DCAP libraries from Intel's apt repository and
   `az-dcap-client` from Microsoft's, both repositories' signing keys
   checked by fingerprint; Open Enclave 0.19.19 from the project's release,
   checked against its sha256; Go 1.27.2 (go.dev sha256 OK); the Ollama
   installer (sha256 OK). `/dev/sgx_enclave` and `/dev/sgx_provision`
   present; `azure-imds.json` (subscription id and the laptop's ssh public
   key redacted).
2. **Quote** (`02`). `sgx-quote.bin`: 4734 bytes of SGX_ECDSA evidence from
   `oeutil generate-evidence -f sgx_ecdsa -p out`, through aesmd, with its
   endorsements (`sgx-endorsements.bin`); `kernel-sgx.txt`: the EPC section.
3. **Intel chain** (`attestation-validation/vault-genome-sgx-test/`). The
   kit's own enclave (`sgx-quote-binding/`, built on the VM — `04-build.log`)
   produced a v3 ECDSA-P256 quote whose REPORT_DATA[0..31] is
   SHA-256(manifest): MRENCLAVE `2715763f…`, MRSIGNER `644e93b7…` (the signing
   key is generated at build time on the VM and is not in this directory),
   ISV_PROD_ID 1, ISV_SVN 1 (`06-intel-chain-verify.txt`: binding verified).
   `oeverify` validated the chain Quote → PCK → Intel SGX Root CA on both
   forms, the OE report and the raw quote — "Evidence verification succeeded
   (0)" twice, with the collateral the Azure DCAP client serves
   (`07-oe-verify.txt`); the 02 evidence verified the same way with
   tcb_status 0 (`05-quote-dump.txt`). The kit's own caller of
   `sgx_qv_verify_quote` still returns 0xE03A (SGX_QL_TCBINFO_CHAIN_ERROR),
   as it did in May; `11-policy-validation-summary.txt` names both outcomes:
   CHAIN VALIDATED LOCALLY (oeverify) AND WORKLOAD BINDING ESTABLISHED.
4. **MAA chain.** The SgxEnclave request with the quote and the manifest as
   runtime data (`13`); the shared East US 2 endpoint answered 200 with a
   token (`14`–`17`); its claims carry the same MRENCLAVE, MRSIGNER, product
   id, SVN and REPORT_DATA (`19-maa-jwt-verify.txt`); the RS256 signature
   verified against the endpoint's published keys (`18`);
   `20-maa-validation-summary.txt`: MAA CHAIN VALIDATION PASSED.
5. **Demo 1.** `llama3.2:3b` sealed — 8 components, 2 019 436 684 bytes,
   payload sha256 `c42f7c25…` (`demo1-seal.txt`); opened into another
   directory with every file checked (`demo1-open.txt`); verified, tree
   sha256 `17284c0e…` (`demo1-verify.txt`); one byte flipped at offset 1 MiB
   refused, exit 4 (`demo1-tamper.txt`).
6. **Demo 2.** Six generations sealed as a chain and validated
   (`demo2-chain.txt`), the lineage walked back to genesis
   (`demo2-lineage.txt`), generation 3 rewound and verified
   (`demo2-rewind.txt`).
7. **Inference.** The original daemon's answer and the restored model's are
   byte-identical: 759 bytes each (`inference-original.txt`,
   `inference-restored.txt`).
8. **Pack.** `vm-identity.txt`, the archive, download, teardown.

Notes.

- The same model sealed on the GCP Milan and Azure Genoa VMs the same night
  gave the same payload sha256 and the same restored tree sha256 (see those
  kits' evidence of 2026-10-14): the bundle is a function of the model, not
  of the cloud or the CPU.
- The workload manifest's `payload_sha256` is the kit's recorded constant for
  the Llama 3.2 3B Q4_K_M GGUF, not a value measured in this run; the
  measured hash of what was sealed is in `demo1-seal.txt`. #83 changes this.
- The `build/` tree of the chain step (the enclave and host binaries, the
  generated bindings and the enclave signing key made on the VM) is not
  committed; `04-build.log` records the build.
- Text files are as the VM wrote them except the two redactions above; the
  quotes, the endorsements and the report data are byte for byte.
