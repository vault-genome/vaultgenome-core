# Roadmap

What is next, what is out of reach today and why, and what will never be
claimed. The record of what is done is [`VERIFIABLE-CLAIMS.md`](VERIFIABLE-CLAIMS.md)
(C1–C51) and [`CHANGELOG.md`](CHANGELOG.md); the open limits are
[`KNOWN_ISSUES.md`](KNOWN_ISSUES.md). Nothing here is a promise with a date.

## Next

- **A TDX Trust Domain and a confidential GPU as the primary.** Every
  failover so far started on an AMD SEV-SNP primary; the sentinel attests
  with `gcp-sev-snp` or the simulator. The sentinel on a TDX guest and on
  the Azure H100 host (attesting through the vTPM) closes the matrix.
- **Cross-device equivalence at 32B.** The 32B genome came back EXACT on
  the pinned runtime ([C26](VERIFIABLE-CLAIMS.md#c26)); its fidelity on
  another device, through the integer door, is measured at 0.5B and 7B
  only ([C19](VERIFIABLE-CLAIMS.md#c19)).
- **A second confidential GPU.** One H100 has attested; a second GPU in
  the same evidence (`gpu_evidence` carries a list) is untested.
- **Operator-facing release notes per version**, and a `docs/` site built
  from the runbooks and the ADRs.
- **A genome key released to a Nitro enclave, across clouds.** The
  verifier is proven offline on AWS's own documents (ADR 0035); the NSM
  producer and the KMS sealer run in a production-mode enclave against
  KMS itself, every refusal with them and AWS's record of each call
  ([C51](VERIFIABLE-CLAIMS.md#c51)). Next (ADR 0036): the source's Nitro
  policy and record, `acp-bootstrap` in the enclave with its sealed key
  files, and a release from a GCP SEV-SNP authority over the Internet,
  the restore confirmed from the enclave's receipt; the registry refuses
  the family until that has run.

## Blocked on hardware or quota

- **Intel SGX.** The SGX verifiers are not written and there is no SGX
  machine; `scripts/hardware-test/azure-sgx` is the starting point.
- **70B.** A 70B model in bfloat16 (about 140 GB) does not fit the one
  94 GB confidential H100 we can get; two non-confidential H100s are
  behind a quota we do not have, and quantising the base would change what
  the genome names. 32B is the largest model measured.

## Not on the roadmap, on purpose

- **Regenerating a model from a recipe alone.** The genome carries the
  sealed fine-tune delta; the recipe replays it, it does not invent
  weights ([what we do not claim, #2](VERIFIABLE-CLAIMS.md#what-we-do-not-claim)).
- **Byte-identical float inference across CPUs and GPUs.** Measured to
  be unreachable at the first transformer block ([C16](VERIFIABLE-CLAIMS.md#c16));
  the integer door is the answer, not a promise of float determinism.
- **Production operation as a service.** This repository is the reference
  implementation; SLOs, on-call and an external security audit belong to a
  deployment, and none has been claimed ([what we do not claim, #6 and #8](VERIFIABLE-CLAIMS.md#what-we-do-not-claim)).
