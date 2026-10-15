# ADR 0024 — Vendor trust anchors are pinned in the binary

- **Status:** Accepted (2026-10-15)
- **Tags:** tee, attestation, amd, sev-snp, azure-cgpu, trust-anchors
- **Extends:** ADR 0014 (real SEV-SNP attestation) and ADR 0019 (the Azure
  confidential GPU adapter), on what their verifiers take the AMD root to be.

## Context

A SEV-SNP report is trusted through its VCEK: the chip's key, certified
by AMD's ASK, certified by AMD's self-signed ARK — one ARK per EPYC
product line (Milan, Genoa, Turin). The verifiers took that chain from
the operator's `amd_cert_chain_path` and checked VCEK ← ASK ← ARK and
that the ARK was self-signed — nothing more. Any self-signed root at the
end of that file was accepted as "AMD": the file named the trust anchor,
and the binary verified a chain to whatever it named. The configuration
comment promised "the AMD-published Milan / Genoa / Turin roots embedded
at build"; the tree embedded Intel's SGX root and NVIDIA's roots, and no
AMD root. In every recorded run the file had come from AMD KDS over TLS
or from Azure THIM, so the recorded verdicts stand; the binary did not
require it, and a deployment that was handed a different file would have
verified to a different root with the same green summary. The security
review of 2026-10 records this as F12.

## Decision

The three AMD roots are embedded in the binary
(`internal/shared/tee/amd_roots.go`), byte for byte as AMD KDS serves
them, with their SHA-256 fingerprints beside them; the fingerprints were
read from three independent sources on 2026-10-15 (KDS over TLS, the
copies already in this tree from KDS and from Azure THIM, and the roots
embedded in Google's `go-sev-guest`), and a test holds the bytes to them.

Every verification of an AMD chain requires the ARK to be one of the
pinned certificates, byte for byte, after the signature checks: a chain
that ends in any other root is refused with the root's name and
fingerprint. Both verifiers that take an AMD chain (`gcp-sev-snp`,
`azure-cgpu`) refuse such a file when they are constructed, so an
operator sees the refusal at start rather than at the first handshake.

The operator's `amd_cert_chain_path` stays: it names the product line
(the ASK differs per line) and keeps the verifier offline-capable. What
it can no longer do is name the trust anchor. `acpctl tee
fetch-amd-chain` fetches a product line's chain from KDS or a mirror and
verifies it the same way before writing it, so the file an operator
installs is one the daemons will accept.

There is no configured override. A deployment that must trust another
root — a sovereign root, an AMD key rotation — changes this file in a
reviewed release, not a configuration field: one fewer way to point a
verifier at the wrong root by mistake. The same holds for the Intel SGX
root and the NVIDIA roots already embedded.

## Consequences

- An AMD root rotation or a new product line (Venice) is a release.
- The negative test (`TestAMDChain_ForeignRootRefused`) builds an
  AMD-shaped chain under foreign keys and shows it refused at load, at
  verification and at construction; before this decision the first two
  accepted it.
- Claim C7's "verified to AMD root" is now a property of the binary, not
  of the file an operator supplied.
