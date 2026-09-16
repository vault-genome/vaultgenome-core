# ADR 0021 — The verifier's own evaluation of the GPU's report

- **Status:** Accepted (2026-09-16); amended the same day — see
  *Amendment* below
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

## Amendment (2026-09-16, later): the manifests' signatures are verified, and `own` is admitted

The dependency decision was taken: goxmldsig is on the allowlist with its
justification (`docs/dependencies/goxmldsig.md`), and `VerifyRIMSignature`
verifies each manifest's enveloped XML signature — Canonical XML 1.1,
ECDSA-SHA384, and nothing else admitted — under the signing certificate
this verifier has already chained to the NVIDIA CoRIM signing root. The
signature value NVIDIA writes is the r||s form XMLDSig prescribes; it is
re-encoded to DER for the check, outside the signed bytes. Both captured
manifests verify; a manifest with one hex digit of a golden measurement
changed does not. A complete evaluation now includes both signatures.

With that, `gpu_policy.evaluation: "own"` is admitted: the verdict rests
on this verifier's evaluation alone, NVIDIA's tokens are not required,
and the policy's model and version pins are held against the report. What
`own` cannot assert: the secure-boot and debug-mode claims, which only
NVIDIA's tokens carry; `both` asserts them, and stays the stronger policy
where NRAS is reachable. Revocation (NVIDIA's OCSP) is not consulted
under either.

## Amendment (2026-09-16, later still): the evaluation is on the audit record

The verifier's word was in its verdict, and the verdict stayed inside the
verifier: the `Verifier` contract returns a measurement, and the audit
records that rest on that measurement — `TRUST_EVALUATED` when `sagvd`
admits a worker, `CROSS_CLOUD_ATTESTATION_VERIFIED` when the authority
releases a key to a destination — named the peer by provider and
measurement alone. An auditor reading the chain could see that a
confidential GPU host was admitted, not what was checked on it.

Now a verifier that can say more implements `tee.DetailedVerifier`
(`VerifyDetailed`, the measurement with a `tee.AttestationDetail`), and the
handshake, the trust admission and the key-release coordinator take the
detail through `tee.VerifyDetailed`, which falls back to `Verify` for a
verifier with nothing more to say. The `azure-cgpu` verifier's detail is
its verdict: the chip's product and id, the reported TCB, the vTPM quote's
PCR selection and digest the pin was held against, each GPU with who
vouched for it (NVIDIA's token, or "own evaluation"), and this verifier's
own evaluations of the GPUs' reports, check by check. It lands as
`peer_detail` on `TRUST_EVALUATED` (allow or deny) and as
`destination_detail` on `CROSS_CLOUD_ATTESTATION_VERIFIED`; the field is
absent when the verifier had only a measurement, so the records of the
other providers are unchanged. The metrics wrapper and the failover
command's verifier-of-any forward the detail. The session-opened log line
carries the operator's glance of it (provider, product, PCRs, the GPUs,
how many evaluations were complete); the record is the audit event.

Proven offline on the captured H100 evidence — the detail the verifier
produces under `both` names Genoa, the sha256 bank, GPU-0 as GH100 with
the driver the evaluation saw, the evaluation complete — and on the
records: a handshake test, a trust test, a flow test (the TRUST_EVALUATED
payload) and a coordinator test (the CROSS_CLOUD_ATTESTATION_VERIFIED
payload) with a verifier that says more; a verifier that does not leaves
the field off.
