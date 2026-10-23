# A production attestation document from the Nitro hypervisor

`2026-05-08-vm1-us-east-2a-attestation-document.bin` (4,523 bytes, SHA-256
`86a0e43d1d4c307e52fd6393b5c8edfd3864b4a782580771f9e95af8e98d3566`) is the
raw COSE_Sign1 attestation document the AWS Nitro hypervisor issued to a
production-mode enclave (no `--debug-mode`) on instance `i-0e35190ae3157095d`
(m5.xlarge, us-east-2a) at 2026-05-08T00:52:52.755Z — VM1 of the May 2026
cohort whose sanitized excerpts are in
`scripts/hardware-test/aws-nitro/evidence/01-VM1-us-east-2a/`. It is the
first of the cohort's four raw documents to be published, by the decision of
both founders of 2026-09-22; the other three stay under NDA. The document
carries nothing but what the hypervisor signs for any relying party: the
module id, the timestamp, sixteen PCRs, the signing certificate and the CA
bundle to AWS's root, and a 64-byte `user_data`; no nonce and no public key,
because the kit asked the NSM for none.

The image the enclave ran is identified by the PCRs the hypervisor measured,
compared with what `nitro-cli describe-eif` reported for the production image
that was built (`02d-expected-pcrs.json` in the evidence directory):

- PCR0 `69d556eff8606bd9828baaac20612f03851f29ddd989387ce5ab3a9cde8917add48d78f1f84c53dc2aafedb9ecb8734e`
- PCR1 `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`
- PCR2 `a841e2a12857318dfabc1b2f610a812016052adad6f9b42aabf7bf332472cf07dfd7582d9664bc35f0a0cd010290fd73`

## What `user_data` binds, and what it does not

`2026-05-08-vm1-us-east-2a-build-manifest.json` is the file whose SHA-512 the
kit put into the enclave image and the enclave sent to the NSM as
`user_data`; the hypervisor signed it. That binds the manifest's **bytes** to
the document, nothing more. The manifest's own PCR fields
(`enclave_image_sha384_pcr0` `c7e271f9…0ece`, `enclave_application_pcr2`
`5b088687…624c`) are **not** the image the enclave ran: the May kit wrote the
manifest during its debug-mode build (`02-build-enclave-image.sh`) and reused
it, unchanged, for the production build (`02d-build-enclave-image-prod.sh`),
whose image measures differently; PCR1, the kernel, is the same in both. A
manifest built into an image cannot name that image's PCR0 in any case — the
digest would have to contain itself. The image is identified by the PCRs
above, never by the manifest; freshness and the binding of a key come only
from the verifier's challenge in `nonce` (or `public_key`), which these
captures do not carry and the key-release path of the daemons always does.

`TestAWSNitro_GenuineProductionCaptures` verifies the document with the
shipping verifier at its own timestamp (the signing certificate lived three
hours) and checks the PCRs above and the manifest's SHA-512; `acpctl attest
nitro --doc <this file> --expected-pcr0 <PCR0>` does the same from the
command line (ADR 0035, VERIFIABLE-CLAIMS C49).
