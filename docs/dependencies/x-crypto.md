# Dependency Justification — golang.org/x/crypto

**Version pinned:** v0.57.0
**License:** BSD-3-Clause (the Go project)
**Transitive depth:** 2 (x/crypto → x/net, x/sys, x/term, x/text — all Go
project modules; none of them is linked into a binary by the one package
used, `golang.org/x/crypto/ocsp`, which imports the standard library only)
**Usage scope:** `internal/shared/tee/nvidia_ocsp.go` only — the OCSP
revocation check of a confidential GPU's attestation certificate chain
against NVIDIA's responder (ADR 0021, amended): parsing and verifying the
responder's answers (`ocsp.ParseResponseForCert`), and, in tests, making
answers for a synthetic chain (`ocsp.CreateResponse`). The request is
encoded in-house, because x/crypto's `CreateRequest` writes no nonce.

## Why this dependency

RFC 6960 answers are DER structures signed either by the certificate's
issuer or by a responder certificate the issuer delegated — NVIDIA uses
delegated responders, one per level of the chain, embedded in each
answer. Parsing the response, locating the single response for the
certificate asked about, checking the responder certificate's signature
under the issuer and the answer's signature under the responder is the
whole of what the `ocsp` package does, in about a thousand lines that
the Go team maintains beside `crypto/x509`. Writing the same in-house is
possible; it would be the same ASN.1 walked with less review. The package
is pure Go and imports only the standard library.

## What it is not used for

Making OCSP requests in production (encoded here, with a nonce), TLS,
SSH, or any of the module's other packages. The dependency-depth check
(`scripts/check_dep_depth.sh`) and govulncheck cover the module graph;
`go mod graph` shows no non-Go-project module behind it.

## Review

Sign-off: both founders on the PR that adds it (policy §3.1).
