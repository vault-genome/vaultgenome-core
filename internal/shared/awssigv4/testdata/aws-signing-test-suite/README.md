# AWS's Signature Version 4 test suite (header signing)

These files are AWS's own test vectors for Signature Version 4, copied
byte for byte from **awslabs/aws-c-auth** at commit
`84a26ea184d9ccd322c8164759510b3604ab13fd`, directory
`tests/aws-signing-test-suite/v4`, under the Apache License 2.0 — `LICENSE`
and `NOTICE` here are that repository's own.

- Source: `https://api.github.com/repos/awslabs/aws-c-auth/tarball/84a26ea184d9ccd322c8164759510b3604ab13fd`
- Tarball SHA-256: `97f39b13423eeb84c40ce167c2bad8b92ec0f67c0eadb6d6590419c4b3f1de95`
  (the project library, `_LIBRARY/sources/specs-vendor/aws/aws-c-auth@84a26ea.tar.gz`,
  read 2026-10-23)
- Taken: all 38 cases; for each, the request (`request.txt`), its context
  (`context.json` — credentials, region, service, time, path
  normalisation, body signing, session-token placement) and the four
  header-signing answers: `header-canonical-request.txt`,
  `header-string-to-sign.txt`, `header-signature.txt`,
  `header-signed-request.txt`.
- Left out: the `query-*` answers of each case — the presigned-URL form,
  which the signer does not implement because nothing in the product
  presigns.

`sigv4_suite_test.go` signs every request with the context's inputs and
holds the canonical request, the string to sign, the signature and the
Authorization header to these files exactly, and the signed request's
header fields to the signed request here.
