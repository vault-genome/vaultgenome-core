# Dependency Justification — github.com/russellhaering/goxmldsig

**Version:** the one pinned in `go.mod` (Dependabot keeps it current, grouped weekly, through the same gate as any change; the justification here does not depend on the patch level — a major version is a new review)
**License:** Apache-2.0
**Transitive depth:** 3 (goxmldsig → beevik/etree; → jonboulle/clockwork;
→ stretchr/testify → yaml.v3 — testify is already on the allowlist)
**Usage scope:** `internal/shared/tee/nvidia_rim.go` only — the
verification of the XML digital signature on NVIDIA's reference integrity
manifests (RIMs) for a confidential GPU's driver and VBIOS (ADR 0021).
Never used to *produce* a signature.

## Why this dependency

NVIDIA publishes the golden measurements of a GPU's firmware as signed
SWID tags: an enveloped XML signature (W3C XMLDSig), Canonical XML 1.1,
ECDSA-SHA384, under a chain to the NVIDIA CoRIM signing Root CA. Verifying
that signature is what makes the manifest NVIDIA's word rather than the
RIM service's, and it is the one check that kept this verifier from
evaluating a GPU's report on its own (`gpu_policy.evaluation: "own"`).

XMLDSig verification needs an XML canonicaliser: the signed bytes are the
canonical form of the document with the signature removed, and Canonical
XML 1.1 is a specification of namespace, attribute and whitespace
handling that the standard library does not implement. Implementing it
in-house is possible and was considered; a partial canonicaliser that
handles only the shapes NVIDIA emits today would verify signatures until
NVIDIA's tooling changes a namespace declaration, and then fail closed
without anyone knowing why. A complete one is a specification's worth of
edge cases, and a wrong one is worse than none: a signature "verified"
over the wrong bytes.

goxmldsig implements Canonical XML 1.0, 1.1 and Exclusive 1.0, and
XMLDSig validation for RSA and ECDSA signature methods including
ECDSA-SHA384, on top of etree. It is the XML signature library behind
the Go SAML implementations (gosaml2, and others), which means its
canonicaliser is exercised against real signers every day. Its
validation API takes the trusted certificate from the caller
(`X509CertificateStore`), so the chain to NVIDIA's root stays this
verifier's check (`VerifyRIMCertChain`), and goxmldsig only answers
whether the signature over the canonical bytes verifies under that
certificate.

## Why not an alternative

- **Own Canonical XML 1.1 + XMLDSig**: correct only if complete; a
  specification-sized surface for one manifest format. Rejected for the
  reason above — reviewed, not dismissed.
- **`encoding/xml` re-serialisation as canonical form**: not Canonical
  XML; verifies nothing NVIDIA signed.
- **libxml2 / xmlsec through cgo**: a C dependency in the verifier's
  process, against the repository's CGO_ENABLED=0 builds.
- **lestrrat-go/libxml2**: cgo as well.

## Transitive dependencies, each reviewed

- `github.com/beevik/etree` — a DOM-style XML tree; no network, no
  cryptography, no further dependencies. goxmldsig canonicalises on its
  tree. Used by this repository only through goxmldsig.
- `github.com/jonboulle/clockwork` — a clock abstraction goxmldsig uses
  for certificate validity checks; no further dependencies. This
  verifier checks certificate validity itself (`VerifyRIMCertChain`) with
  its own clock; goxmldsig's check is redundant here, not relied on.
- `github.com/stretchr/testify` and its deps — goxmldsig's tests only;
  already on the allowlist.

## What it is trusted for, and what it is not

goxmldsig is trusted to canonicalise and to verify an ECDSA signature
over the canonical bytes. It is *not* trusted to decide which
certificate is trusted: the store handed to it holds exactly the
manifest's signing certificate, after this verifier chained it to the
pinned NVIDIA CoRIM signing root. A manifest whose signature does not
verify is a failed manifest, and with it the GPU's evaluation.
