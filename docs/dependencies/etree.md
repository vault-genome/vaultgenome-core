# Dependency Justification — github.com/beevik/etree

**Version:** the one pinned in `go.mod` (Dependabot keeps it current, grouped weekly, through the same gate as any change; the justification here does not depend on the patch level — a major version is a new review)
**License:** BSD-2-Clause
**Transitive depth:** 1 (no dependencies of its own)
**Usage scope:** `internal/shared/tee/nvidia_rim.go` only — the document
model goxmldsig verifies an XML signature over (ADR 0021): NVIDIA's
reference integrity manifests are parsed into an etree document, the
`SignatureValue` NVIDIA writes in the r||s form is re-encoded to DER in
that document, outside the signed bytes, and the document is handed to
goxmldsig's validation context.

## Why this dependency

goxmldsig (on the allowlist, `goxmldsig.md`) takes and returns etree
documents; there is no way to hand it a manifest, or to change the one
element outside the signed bytes that NVIDIA encodes differently from
what `crypto/x509` expects, without importing etree directly. It was a
transitive dependency of goxmldsig from the day goxmldsig was admitted;
`go mod tidy` records what the import graph always was. It is pure Go
with no dependencies.

## What it is not used for

Parsing anything but a manifest that goxmldsig is about to verify;
nothing outside `nvidia_rim.go` imports it.

## Review

Sign-off: both founders on the PR that records it (policy §3.1).
