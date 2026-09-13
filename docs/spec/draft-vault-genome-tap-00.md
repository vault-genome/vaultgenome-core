# draft-vault-genome-tap-00 — TEE-Agnostic Attestation Protocol (TAP), Version 0.1

```
Internet Engineering Task Force                              S. Nikolaichuk
Internet-Draft                                            R. <Cofounder name>
Intended status: Standards Track                          Vault Genome Inc.
Expires: 2026-11-06                                              May 6, 2026


              TEE-Agnostic Attestation Protocol (TAP), V0.1
                       draft-vault-genome-tap-00


Abstract

   This memo specifies a TEE-agnostic attestation protocol (TAP) that
   allows a single application codebase to interoperate, without
   modification, with multiple distinct Trusted Execution Environment
   (TEE) backends, including AWS Nitro Enclaves, Microsoft Azure
   Confidential Computing (Intel SGX), Google Cloud Confidential VMs
   (AMD SEV-SNP), and Intel SGX in bare-metal deployments.

   The protocol defines three abstract roles — Producer, Verifier, and
   Sealer — together with a small set of platform-independent
   constraints that any conformant TEE implementation MUST satisfy.
   Concrete bindings to each underlying TEE are specified as
   normative appendices.

   This protocol is implemented by the Vault Genome reference
   implementation [VG-CORE] and is published as an open specification
   to support multi-vendor interoperability and procurement-time
   trust assessment.

Status of this Memo

   This Internet-Draft is submitted to the IETF in conformance with
   the provisions of BCP 78 and BCP 79.

   Internet-Drafts are working documents of the IETF.  Internet-Drafts
   are draft documents valid for a maximum of six months and may be
   updated, replaced, or obsoleted by other documents at any time.  It
   is inappropriate to use Internet-Drafts as reference material or to
   cite them other than as "work in progress".

   This Internet-Draft will expire on November 6, 2026.

Copyright Notice

   Copyright (c) 2026 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (http://trustee.ietf.org/license-info).
```

## 1. Introduction

Trusted Execution Environments (TEEs) provide hardware-rooted
guarantees that a body of code (the "workload") executes with
confidentiality and integrity protections that even a privileged
adversary on the host cannot violate. Multiple TEE technologies have
been deployed at scale: Intel SGX, Intel TDX, AMD SEV-SNP, ARM TrustZone
and Realms, and cloud-provider abstractions such as AWS Nitro Enclaves.

Each TEE family ships its own attestation primitive: SGX uses ECDSA
quotes signed by the platform's PCK; SEV-SNP uses VCEK-signed reports;
Nitro uses NSM-issued COSE_Sign1 documents.  The wire formats and
verification flows differ; the underlying *purpose* — proving the
identity of code running inside a protected boundary to a remote
challenger — does not.

Application code that wishes to operate across multiple TEEs today
must either restrict itself to one platform, or implement and
maintain four separate code paths. Both options are operationally
expensive and create lock-in artifacts that work against the
security goals TEEs were introduced to serve.

This document specifies TAP, an abstraction over these heterogeneous
TEE primitives. TAP defines three roles — Producer, Verifier, and
Sealer — that an application uses without knowing which underlying
TEE provides them. Implementations may bind any conformant TEE to
the abstract roles per the bindings in Appendix A.

### 1.1. Scope

TAP standardises:

   *  The names, semantics, and minimum guarantees of the three roles.
   *  Replay protection requirements (challenge nonce minimum entropy).
   *  Authentication of additional data on sealed material (AAD-bound
      authenticated encryption).
   *  A canonical conformance test suite [TAP-CONFORMANCE] that any
      claimed implementation MUST pass.

TAP does NOT standardise:

   *  Wire formats internal to a TEE binding (these remain platform-
      specific; see appendix references).
   *  Out-of-band trust establishment (root certificate distribution).
   *  Operator-side policy beyond accept/reject: identity pinning,
      revocation list management, key-rotation cadence.

### 1.2. Conventions Used in this Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP14].

## 2. Architecture

A TAP deployment consists of three parties:

   * the *Workload* — the application code running inside the TEE,
   * the *Producer* — the TEE-side capability that emits attestation
     evidence about the workload,
   * the *Verifier* — the challenger-side capability that decides
     whether evidence proves the workload's identity.

The Sealer is co-located with the Producer; it persists application
state outside the TEE in a form that only the same TEE measurement
can recover.

### 2.1. Roles

```
     Challenger                                       TEE host
   ┌──────────────────┐    Nonce (≥16 B random)   ┌──────────────────┐
   │  Verifier        │ ────────────────────────► │  Producer        │
   │                  │                           │                  │
   │                  │ ◄──────────────────────── │                  │
   │  Measurement←Verify(Evidence, Nonce)            Evidence        │
   └──────────────────┘                           └──────────────────┘

                                                  ┌──────────────────┐
                                                  │  Sealer          │
                                                  │  Seal(plaintext, │
                                                  │     aad)         │
                                                  │  Unseal(sealed,  │
                                                  │     aad)         │
                                                  └──────────────────┘
```

### 2.2. Trust Model

TAP makes no assumptions about the network or the TEE host operating
system; both are considered untrusted. The Producer's evidence chains
to a hardware root of trust managed by the TEE silicon vendor (Intel
SGX Root, AMD ARK, AWS Nitro PCA, Microsoft MAA signing key). The
Verifier MUST validate this chain.

Compromise of the silicon vendor's signing infrastructure is out of
scope for TAP; deployments that require multi-vendor redundancy MUST
obtain attestation from independently-rooted TEEs.

## 3. The Producer Interface

A Producer MUST expose two operations:

   *  Quote(nonce) → evidence | error
   *  Measurement() → measurement

### 3.1. Quote

The Quote operation accepts a challenger Nonce and returns Evidence
that authenticates the workload under that Nonce.

```
   nonce      = octet string of length ≥ 16 bytes
   evidence   = TEE-specific opaque octet string (see Appendix A)
   error      = caller-presented error indication; the contents MUST
                NOT leak side-channel information about the workload
```

**MUST**: Reject any nonce of length less than 16 octets with an
error of category "Structural" (input validation).  This minimum
matches Section 10.1 of [RFC9334].

**MUST**: Bind the nonce into the evidence in a manner that any
single-bit flip in the nonce produces evidence that fails Verify.

**SHOULD**: Use the TEE's native attestation generation primitive
without buffering or post-processing; specifically, the operation
SHOULD complete in a single round-trip to the TEE and return the
verbatim hardware-signed evidence.

### 3.2. Measurement

The Measurement operation returns the cryptographic measurement of
the workload as the TEE measures it (e.g., MRENCLAVE for Intel SGX,
PCR0 for AWS Nitro, launch MEASUREMENT for AMD SEV-SNP).

```
   measurement = octet string of length 32 bytes (SHA-256 class)
```

**MUST**: Be stable for the lifetime of a single Producer instance.

**MUST**: Equal the measurement that Verifier returns from a
successful Verify of evidence emitted by the same Producer.

## 4. The Verifier Interface

A Verifier MUST expose one operation:

   *  Verify(evidence, nonce) → measurement | error

### 4.1. Verify

```
   evidence    = octet string from a prior Producer.Quote
   nonce       = octet string of length ≥ 16 bytes (the SAME bytes
                  the challenger handed to Producer.Quote)
   measurement = TEE measurement extracted from evidence
   error       = caller-presented error indication
```

The Verifier MUST perform, in order:

   1.  Reject if nonce is shorter than 16 octets ("Structural" error).
   2.  Parse evidence per the relevant Appendix-A binding.
   3.  Validate the evidence signature against the TEE's published
       root of trust (hardware-rooted certificate chain).
   4.  Confirm the evidence binds the supplied nonce.
   5.  Reject debug-mode attestations unless explicitly enabled by
       deployment configuration.
   6.  Return the measurement extracted from evidence.

A failure at steps 2-5 MUST return an error of category "Integrity"
distinguishable from a "Structural" error (see Section 6.4).

## 5. The Sealer Interface

A Sealer MUST expose two operations:

   *  Seal(plaintext, aad) → sealed | error
   *  Unseal(sealed, aad) → plaintext | error

### 5.1. Seal

The Seal operation authenticates `aad` (Additional Authenticated
Data) and encrypts `plaintext`. The returned `sealed` octet string
is opaque to the caller; only an Unsealer running in a TEE with the
same identity (measurement-bound, where the binding semantics are
specified by the relevant Appendix-A binding) can recover the
plaintext.

**MUST**: Use a fresh nonce internally for each Seal operation; two
Seal calls with identical plaintext + aad MUST produce different
ciphertext bytes (this rules out AES-GCM nonce reuse, which would be
catastrophic).

**MUST**: Authenticate `aad` such that any byte difference between
the aad supplied at Seal time and the aad supplied at Unseal time
causes Unseal to fail with an "Integrity" error.

### 5.2. Unseal

The Unseal operation reverses Seal. It MUST fail with an "Integrity"
error if:

   *  The aad differs from the original sealing-time aad.
   *  The sealed bytes have been truncated, modified, or originate
      from a Sealer with a different TEE identity.

## 6. Common Conventions

### 6.1. Octet Encoding

All octet strings are base-256 with most-significant-bit-first byte
order unless otherwise stated.

### 6.2. Nonce Generation

Challengers SHOULD generate nonces from a cryptographically-secure
random source (CSPRNG). The 16-octet minimum aligns with [RFC9334]
and the 128-bit security floor common to modern AEAD constructions.

### 6.3. Measurement Comparison

Implementations MUST compare measurement values byte-wise; partial
or prefix matches MUST NOT satisfy a measurement-pinning policy.

### 6.4. Error Categories

TAP distinguishes two error categories:

   *  Structural — input validation failure; the caller should fix
      and retry.
   *  Integrity — cryptographic failure; the caller MUST treat as a
      potential attack and SHOULD escalate to incident response.

The operational meaning of each category is specified in
[INCIDENT-DOCTRINE].

## 7. Conformance

An implementation conforms to TAP V0.1 if and only if it passes the
canonical conformance test suite defined by [TAP-CONFORMANCE]. The
suite enumerates 12 individual tests covering round-trip, replay
rejection, evidence tampering, sealing aad binding, nonce-floor
rejection (both producer- and verifier-side), distinct-nonce-per-seal,
truncation rejection, and cross-instance-unseal preservation.

A reference implementation passing the suite is available at
[VG-CORE] under AGPL-3.0-or-later. The conformance suite itself is
distributed at [VG-CONFORMANCE-PKG] under the same license; the
patent license that accompanies the conformance suite is described
in [VG-PATENT].

## 8. Security Considerations

### 8.1. Out-of-Band Trust

TAP requires the Verifier to know, out of band, the trust anchor
(silicon vendor root certificate) for the relevant Appendix-A
binding. Distribution of this anchor is out of scope. Anchor
rotation MUST be supported by the Verifier configuration; the
deprecated anchor MUST remain usable for a deprecation window
(typically 90 days) so in-flight sessions can be drained.

### 8.2. Side-Channel Attacks

TAP does not defend against side-channel attacks on the underlying
TEE silicon (Spectre, Foreshadow, MDS, Plundervolt, Downfall, …).
Such attacks invalidate the confidentiality (but not the
authenticity) of attestations. Operators are responsible for
tracking vendor TCB Recovery Events and bumping the TCB-floor
configuration on their Verifiers in response.

### 8.3. Replay

The 16-octet nonce floor (Section 3.1) provides 128 bits of replay
protection. With a CSPRNG-generated nonce per challenge, the
expected number of challenges before any collision is approximately
2^64, comfortably above what any deployment will issue in the
lifetime of a TAP-instance.

### 8.4. Compromise of the Silicon Vendor

If a silicon vendor's signing infrastructure is compromised, every
attestation the vendor signs becomes suspect. TAP does not provide
recovery from this scenario; operators with this threat in their
risk model MUST deploy across multiple silicon vendors and accept
attestations only when a quorum is satisfied (M-of-N attestation,
out of scope for this version of TAP).

### 8.5. Quantum Cryptanalysis

This version of TAP relies on classical cryptographic primitives
(ECDSA-P256/P384, Ed25519, AES-256-GCM, SHA-256) inherited from the
underlying TEE bindings. A future TAP V1 will specify post-quantum
primitives once the relevant TEE bindings adopt them; the Producer/
Verifier/Sealer abstraction is intended to make the migration a
binding change, not an interface change.

## 9. IANA Considerations

This document has no actions for IANA.

## 10. References

### 10.1. Normative References

```
   [BCP14]    Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119, March 1997.

   [RFC9334]  Birkholz, H. et al., "Remote ATtestation procedureS
              (RATS) Architecture", RFC 9334, January 2023.

   [TAP-CONFORMANCE]
              Vault Genome Inc., "TEE-Agnostic Attestation Protocol
              Conformance Test Suite", available at
              https://github.com/ai-continuity-platform/core/
                tree/main/pkg/teeconformance.
```

### 10.2. Informative References

```
   [VG-CORE]  Vault Genome Inc., "Reference implementation",
              https://github.com/ai-continuity-platform/core.

   [VG-CONFORMANCE-PKG]
              Vault Genome Inc., "Public conformance test package",
              https://github.com/ai-continuity-platform/core/
                tree/main/pkg/teeconformance.

   [VG-PATENT]
              Vault Genome Inc., "Patent disclosure: TEE-agnostic
              attestation abstraction", available under NDA from
              ops@vaultgenome.com.

   [INCIDENT-DOCTRINE]
              Vault Genome Inc., "Bootstrap Contracts Doctrine §17:
              Incident Detection", private repository.

   [AWS-NITRO]
              AWS, "AWS Nitro Enclaves Attestation Document Format",
              https://docs.aws.amazon.com/enclaves/latest/user/
                attestation-document-formats.html.

   [INTEL-DCAP]
              Intel, "DCAP API Reference", https://download.01.org/
                intel-sgx/sgx-dcap/.

   [AMD-SEVSNP]
              AMD, "SEV Secure Nested Paging Firmware ABI
              Specification", https://www.amd.com/system/files/
                TechDocs/56860.pdf.
```

## Appendix A. Concrete TEE Bindings

(Normative — implementations MUST use the binding for the
intended TEE family.)

### A.1. AWS Nitro Enclaves Binding

   *  Evidence: NSM_GET_ATTESTATION_DOC output, a CBOR-encoded
      COSE_Sign1 envelope per [AWS-NITRO].
   *  Measurement: PCR0 (enclave image hash, 32 octets).
   *  Sealing: AWS KMS Encrypt/Decrypt with EncryptionContext set
      from `aad`; the KMS key policy MUST include
      `kms:RecipientAttestation:ImageSha384` matching the expected
      PCR0.

### A.2. Azure Confidential Computing (SGX) Binding

   *  Evidence: sgx_quote3_t per Intel DCAP, OR Microsoft Azure
      Attestation (MAA) JWT carrying the verified quote.
   *  Measurement: MRENCLAVE (32 octets).
   *  Sealing: SGX SDK sgx_seal_data with MRENCLAVE policy or
      MRSIGNER policy.

### A.3. Google Cloud Confidential VMs (SEV-SNP) Binding

   *  Evidence: SEV-SNP attestation report (1184 octets) per
      [AMD-SEVSNP].
   *  Measurement: launch MEASUREMENT field, truncated to 32 octets.
   *  Sealing: SEV_SNP_GUEST_MSG_DERIVED_KEY result fed into
      AES-256-GCM with `aad` as AEAD AAD.

### A.4. Intel SGX Bare-Metal (DCAP) Binding

   *  Same evidence and measurement as A.2; uses local DCAP
      verification (no MAA round-trip).
   *  Sealing: SGX SDK sgx_seal_data, optionally double-wrapped
      with an HSM-held key (PKCS#11) for defence in depth.

### A.5. Software Simulator Binding (test only)

   *  Evidence: Ed25519-signed `(measurement || nonce)` envelope
      with a 16-byte magic prefix, 4-byte BE nonce length, nonce,
      measurement, and signature.
   *  Measurement: SHA-256 of a workload descriptor string.
   *  Sealing: AES-256-GCM with key derived from measurement.
   *  **NOT FOR PRODUCTION USE.**

## Authors' Addresses

```
   Serhii Nikolaichuk
   Vault Genome Inc.
   Email: ops@vaultgenome.com

   Rodion <Cofounder name>
   Vault Genome Inc.
   Email: ops@vaultgenome.com
```
