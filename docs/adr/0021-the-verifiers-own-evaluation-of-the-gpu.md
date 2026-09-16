# ADR 0021 — The verifier's own evaluation of the GPU's report

- **Status:** Accepted (2026-09-16)
- **Tags:** tee, gpu, nvidia, attestation, azure
- **Amends:** ADR 0019 (the confidential GPU worker on Azure), whose
  consequences said what the verifier took on NVIDIA's word.

## Context

ADR 0019 put an H100 inside the attested boundary by verifying NVIDIA's
signed attestation tokens: NVIDIA's Remote Attestation Service (NRAS)
receives the GPU's SPDM attestation report and certificate chain, evaluates
them against NVIDIA's reference integrity manifests (RIMs), and signs a
verdict; this verifier checked NVIDIA's signature, the nonce, the validity
window and the claims. The GPU's measurements themselves were NVIDIA's
evaluation. KNOWN_ISSUES #1 said so, and VERIFIABLE-CLAIMS declined to
claim the evaluation as ours.

The material for an evaluation of our own was already in hand: the report
and chain the driver gives NVIDIA (captured in
`scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z/`), NVIDIA's
public roots (shipped in NVIDIA's open-source verifier), and NVIDIA's RIM
service, which serves the manifests for a driver version and a VBIOS build
to anyone.

## Decision

The `azure-cgpu` verifier evaluates the GPU's report itself, beside
NVIDIA's verdict, when the operator's policy asks for it.

1. **The evidence carries the report.** The producer's GPU attestation
   command (`gpu-token.py`) prints, beside NRAS's response, what it gave
   NRAS: per GPU, the SPDM attestation report and the PEM certificate
   chain (`gpu_evidence` in the `vault-genome/azure-cgpu-evidence/v1`
   envelope). Evidence from an older producer carries none, and is
   accepted only under the default policy.
2. **What the verifier checks** (`nvidia_gpu_report.go`, `nvidia_rim.go`):
   the report is an SPDM 1.1 GET_MEASUREMENTS request with the verifier's
   challenge as its nonce, followed by the signed MEASUREMENTS response;
   its 64 DMTF measurement blocks parse; its signature (ECDSA P-384 over
   SHA-384 of the request and the response) verifies under the GPU's
   attestation certificate; that certificate's chain verifies to the
   NVIDIA Device Identity CA pinned in the binary (or one the operator
   names); the firmware id in the certificate's DICE extension is the one
   the report names; the driver and VBIOS manifests for the versions the
   report names are fetched from NVIDIA's RIM service (and kept in a
   cache), their bytes hash to the SHA-256 the service states, their
   versions are the report's, their signing certificates verify to the
   NVIDIA CoRIM signing root pinned in the binary; and every runtime
   measurement is one of the manifest's alternatives at that index, for
   every index the manifests bind — measurement 35 excepted when the GPU
   reports its NVDEC0 engine disabled, NVIDIA's own rule. The evaluation
   does not stop at the first failure: every check is on the record
   (`GPUEvaluation`), and the verdict carries it.
3. **Three policies.** `gpu_policy.evaluation` is `nras` by default — the
   verdict rests on NVIDIA's tokens, as before; `both` requires NVIDIA's
   tokens *and* a complete evaluation of every GPU's report, and refuses
   a report NVIDIA's verdict does not agree with on driver and VBIOS
   versions; `own` would rest the verdict on the evaluation alone and
   **this build refuses it**, because of what it does not check (below).
4. **Roots pinned, overridable.** The two NVIDIA roots are constants in
   the binary (`nvidia_roots.go`), taken from NVIDIA's open-source
   verifier; `nvidia_device_root_path` and `nvidia_rim_root_path` replace
   them.

## What is not checked, and why "own" is refused

The manifests are signed SWID tags: an enveloped XML signature, Canonical
XML 1.1, ECDSA-SHA384, under a chain to the NVIDIA CoRIM signing root.
This verifier verifies that chain and the service's SHA-256 of the
manifest's bytes, and parses the signature's declared algorithms, but it
does not verify the signature: that needs an XML canonicaliser, which the
standard library does not provide and the dependency policy of this
repository does not admit without a decision. Until it does, a manifest
could in principle be substituted between NVIDIA's signing and this
verifier's fetch (the service's own transport and stated digest are the
only protections), so the evaluation alone must not carry a verdict, and
`both` — NVIDIA's signed evaluation *and* ours — is the strongest policy
this build offers. `GPUEvaluation.RIMSignaturesVerified()` is false and
recorded as such.

Not checked either: certificate revocation of the GPU chain and the
manifests' chains (NVIDIA's OCSP), which NVIDIA's own verifier consults.
Listed in KNOWN_ISSUES #1.

## Consequences

- **What the operator takes on NVIDIA's word shrinks** from the whole
  evaluation to the manifests' XML signatures and revocation. The
  measurements, the chain, the nonce, the firmware id and the report's
  signature are checked here, and the record says which.
- **Two services on the path with `both`**: NRAS (for the tokens) and the
  RIM service (for the manifests, cached after the first fetch). The
  evaluation of a captured report needs no network once the manifests are
  cached.
- **The evidence grows** by the report (about 4 KB) and the chain (about
  5 KB) per GPU.
- **Proven offline on genuine material**: the captured H100 report, chain
  and manifests (`internal/shared/tee/testdata/nvidia/`) evaluate
  complete, every measurement matching; a changed measurement, another
  nonce, a cut chain, a wrong root or a missing manifest each fail the
  check that should catch it.
