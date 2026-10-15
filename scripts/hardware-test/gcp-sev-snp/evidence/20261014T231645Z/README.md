# GCP SEV-SNP — the run of 2026-10-14

One `n2d-standard-4` Confidential VM (AMD SEV-SNP; EPYC Milan — CPUID family
0x19, model 0x01) in `us-central1-c`, image family `ubuntu-2404-lts-amd64`
(kernel 7.0.0-1014-gcp), driven end to end from the laptop by
`examples/full-test-run.sh` on the tree of commit `85f6a11`, with `acpctl`
built from the same commit (sha256
`2efc6404b47b2708967ac2c7e6cef63feb8a203139bb9b980aed1f6bd50f20a5`). The VM
came up at 23:08Z, the run ended at 23:17:55Z, and the runner destroyed the
VM; the project held no instance afterwards. `full-test-run.log` is the
runner's output, start to end.

What the runner did, in order, and what each file records:

1. **Provision.** `us-central1-a` and `-b` had no capacity for the machine
   type; the runner moved to `-c` (the log shows both refusals).
2. **Bootstrap.** Go 1.27.2 (go.dev sha256 OK), the Ollama installer (sha256
   OK), snpguest v0.10.0 built with rustup-init 1.29.1 (sha256 OK) and Rust
   1.99.0 — every download checked before it ran.
3. **Report.** `snp-attestation-report.bin`: 1184 bytes read from
   `/dev/sev-guest`; `kernel-sev.txt`: "Memory Encryption Features active:
   AMD SEV SEV-ES SEV-SNP".
4. **Chain** (`attestation-validation/<vm>/`). Report version 5, VMPL 0,
   signing key VCEK; TCB microcode 222, SNP 29, TEE 0, boot loader 4
   (`05-…decoded.txt`). ARK → ASK → VCEK fetched from AMD KDS
   (`06-certificates/`), chain verified (`08`), the VCEK's signature over the
   report verified with every TCB value matching (`09`), REPORT_DATA =
   SHA-512(manifest) verified with the `0x` form snpguest reads (`10`);
   `11-policy-validation-summary.txt`: ALL POLICY CHECKS PASSED.
5. **Demo 1.** `llama3.2:3b` sealed — 8 components, 2 019 436 684 bytes,
   payload sha256 `c42f7c25…`, key id `genome-c42f7c25e88d-g0-…`
   (`demo1-seal.txt`); opened into another directory with every file checked
   against its recorded digest (`demo1-open.txt`); verified, tree sha256
   `17284c0e…` (`demo1-verify.txt`); one byte flipped at offset 1 MiB refused
   — "segment 1 of 1926 does not open … message authentication failed", exit
   4 (`demo1-tamper.txt`).
6. **Demo 2.** Six generations sealed as a chain and validated
   (`demo2-chain.txt`), the lineage walked from the latest back to genesis
   (`demo2-lineage.txt`), generation 3 rewound and verified
   (`demo2-rewind.txt`).
7. **Inference.** The original daemon's answer and the answer of the model
   restored from the bundle are byte-identical: 649 bytes each, seed 42,
   temperature 0 (`inference-original.txt`, `inference-restored.txt`).
8. **Pack.** `vm-identity.txt`; the archive the runner downloaded; teardown.

Notes.

- The workload manifest's `payload_sha256` is the kit's recorded constant
  for the Llama 3.2 3B Q4_K_M GGUF, not a value measured in this run; the
  measured hash of what was sealed is in `demo1-seal.txt`. Binding the
  manifest to the measured digest is a follow-up.
- Text files have the VM user's home directory replaced by `~`; the report,
  the certificates and the binary files are byte for byte what the VM
  produced. `06-fetch-ca-log.txt` and `07-fetch-vcek-log.txt` are empty
  because snpguest prints nothing on a successful fetch.
- The scripts that ran are those of commit `85f6a11`. The later change to
  `02b` and `02c` (the product line read from the report's CPUID fields,
  found necessary on Azure) returns Milan for this VM — the value those
  scripts assumed.
