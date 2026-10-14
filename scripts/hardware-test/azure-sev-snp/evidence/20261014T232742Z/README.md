# Azure SEV-SNP — the run of 2026-10-14

One `Standard_DC4as_v5` Confidential VM (security type ConfidentialVM, vTPM
and secure boot on) in West Europe, on an AMD EPYC 9V74 — **Genoa**, CPUID
family 0x19 model 0x11 — image `0001-com-ubuntu-confidential-vm-jammy`
`22_04-lts-cvm` (kernel 6.8.0-1068-azure-fde), driven from the laptop by
`examples/full-test-run.sh` on the tree of commit `d8bf94e`, with `acpctl`
sha256 `2efc6404b47b2708967ac2c7e6cef63feb8a203139bb9b980aed1f6bd50f20a5`
(built from `85f6a11`; the Go tree is the same at `d8bf94e`). Terraform
created the VM at 23:18Z; every phase on the VM completed by 23:27:42Z.

The runner's own log (`full-test-run.log`) ends with exit 141: after the
archive was packed, `06-pack-evidence.sh` listed its contents through
`head -40`, `tar` was cut short, and `pipefail` turned that into a failure
that stopped the ssh session before the download and the teardown. The
archive was fetched afterwards with `scp` (sha256 `f3a239b5…`, the same on
the VM and on the laptop), and the VM, its resource group and the eight
resources around it were destroyed with `terraform destroy` (state empty, no
VM in the subscription). The listing is guarded in the branch that holds
this evidence; the phases, their order and their outputs are the runner's.

What ran, in order, and what each file records:

1. **Bootstrap.** Go 1.27.2 (go.dev sha256 OK), the Ollama installer (sha256
   OK), snpguest v0.10.0 built with rustup-init 1.29.1 (sha256 OK) and Rust
   1.99.0, tpm2-tools and the image's python3-jwt; the vTPM and NV index
   0x1400001 present (`azure-imds.json`: the instance's metadata, with the
   subscription id and the laptop's ssh public key redacted).
2. **Report from the vTPM** (`02`). `hcl-report.bin`: the 2900-byte NV index.
   `hcl-layout.txt`: HCL header version 2, report size 2469; SNP report
   version 5, guest SVN 3, policy 0x3001f, VMPL 0; runtime-data section
   1253 bytes with 1233 bytes of JSON (`hcl-runtime-data.json`: the vTPM's
   AK and EK public keys, the VM configuration); REPORT_DATA =
   SHA-256(runtime data) ‖ 0^32 checked: OK. `snp-attestation-report.bin`
   is the 1184-byte report. `thim-certification.json`, `thim-vcek.pem`,
   `thim-cert-chain.pem`: what Azure THIM served for this chip
   (tcbm 581C00000000000C). `kernel-sev.txt`: "Memory Encryption Features
   active: AMD SEV" as the guest sees it behind the paravisor.
3. **AMD chain** (`attestation-validation/vault-genome-sev-snp-test/`). The
   product line read from the report: genoa (`03-snp-chip.txt`); TCB
   microcode 88, SNP 28, TEE 0, boot loader 12; ARK → ASK → VCEK fetched from
   AMD KDS for Genoa (`06-certificates/`), chain verified (`08`), the VCEK's
   signature over the report verified with every TCB value matching (`09`),
   Azure's REPORT_DATA binding verified by snpguest (`10`); THIM's VCEK and
   KDS's carry the same public key and the same hwID and THIM's chains to
   the KDS ARK — the certificates themselves differ because KDS signs a
   fresh one per request (`13-vcek-thim-vs-kds.txt`);
   `11-policy-validation-summary.txt`: AMD CHAIN VALIDATION PASSED.
4. **MAA chain.** The SevSnpVm request as the API defines it — `report` =
   base64url({SnpReport, VcekCertChain}) with THIM's three certificates,
   runtime data as JSON (`12`, `13-maa-attestation-request.json`); the
   shared West Europe endpoint answered 200 with a token (`14`, `15`,
   `16`, `17-maa-jwt-payload.json`); the token's claims are the report's —
   type sevsnpvm, REPORT_DATA, launch measurement, not debuggable,
   compliance status azure-compliant-cvm (`17-maa-claims-vs-report.txt`);
   the RS256 signature verified against the endpoint's published keys
   (`18`, `19`); `20-maa-validation-summary.txt`: MAA CHAIN VALIDATION
   PASSED.
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
   byte-identical: 649 bytes each (`inference-original.txt`,
   `inference-restored.txt`).
8. **Pack.** `vm-identity.txt`, then the archive.

Notes.

- The same model, sealed on GCP's Milan VM the same evening, gave the same
  payload sha256 and the same restored tree sha256
  (`../../gcp-sev-snp/evidence/20261014T231645Z/`): the bundle is a
  function of the model, not of the cloud.
- On Azure a caller cannot place its own REPORT_DATA in the report; the
  workload manifest (`01-…manifest.json`) is recorded, not bound, and its
  `payload_sha256` is the kit's constant for the Llama 3.2 3B Q4_K_M GGUF,
  not a value measured in this run.
- `06-fetch-ca-log.txt` and `07-fetch-vcek-log.txt` are empty because
  snpguest prints nothing on a successful fetch.
