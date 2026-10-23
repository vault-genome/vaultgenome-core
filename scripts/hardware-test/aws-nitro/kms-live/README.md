# The KMS client against AWS KMS itself (ADR 0036, part three)

`run.sh` runs `internal/shared/awskms/live_test.go` (build tag `kmslive`)
against the KMS endpoint of a Region (`VG_KMS_LIVE_REGION`, default
`us-east-2`) with the AWS CLI's credentials, which go into the test's
environment and nowhere else. It needs no KMS key, no permission on one,
and creates nothing.

KMS checks a request's signature before it asks whether the caller may
make it. So the run holds the signer and the client to the service:

| Case | What KMS answers | What it shows |
|---|---|---|
| GenerateRandom, signed right | the bytes, or `AccessDeniedException` | the signature is accepted; only authorisation is left |
| the wrong secret | `InvalidSignatureException` | the service recomputes the signature and refuses a wrong one |
| the clock twenty minutes behind | `InvalidSignatureException`, "Signature expired" | the date is signed; KMS allows five minutes |
| an access key nobody has | `UnrecognizedClientException` | the credential scope is read |
| an empty root pool | the handshake fails, "certificate signed by unknown authority" | TLS is verified against the pool, and only Amazon's roots pass |
| Decrypt and GenerateDataKey on a key that does not exist | an error past the signature and the request's shape | the two requests the sealer sends are well formed |

The evidence goes to `evidence/<UTC time>/`: `run.txt` (the commit, whether
the tree was clean, Go, the Region), `go-test.log` (the answers, with
KMS's request IDs, which CloudTrail of the account records), `SHA256SUMS`.
The access key is shortened to its first four characters and the account
number replaced by `<account>`; the script refuses to keep a run where a
credential or an account number reached a file.

```bash
scripts/hardware-test/aws-nitro/kms-live/run.sh
```
