# `pkg/teeconformance`

Public conformance test harness for any TEE adapter that wants to claim
compatibility with the Vault Genome Producer / Verifier / Sealer
contract. See [`doc.go`](doc.go) for the full package-level
documentation.

## Quickstart

```go
package myadapter_test

import (
    "testing"
    "github.com/ai-continuity-platform/core/pkg/teeconformance"
)

func TestMyAdapter_Conformance(t *testing.T) {
    teeconformance.RunProducerVerifierContract(t, func(t teeconformance.Tester) (teeconformance.Producer, teeconformance.Verifier) {
        // build a fresh producer + verifier pair for each sub-test
        // ...
        return producer, verifier
    })
    teeconformance.RunSealerContract(t, func(t teeconformance.Tester) (teeconformance.Sealer, func(t teeconformance.Tester) teeconformance.Sealer) {
        // build a fresh sealer + a closure that returns a new sealer
        // with the SAME identity (sealing key) so cross-instance unseal
        // can be exercised
        // ...
        return sealer, rebuildSealer
    })
}
```

`go test ./...` will run 12 sub-tests:

**Producer / Verifier (6)**

- RoundTrip — Quote → Verify returns producer's measurement.
- NonceFloor_Producer — producer rejects nonces < 16 bytes.
- NonceFloor_Verifier — verifier rejects nonces < 16 bytes.
- Replay — Verify with a different nonce than the one bound MUST fail.
- Tamper — flipping the last byte of evidence MUST cause Verify to fail.
- MeasurementStability — Verify's returned measurement equals
  Producer.Measurement().

**Sealer (6)**

- RoundTrip — Seal then Unseal returns plaintext.
- WrongAAD — unseal with mismatched AAD MUST fail.
- Tamper — flipping a byte in ciphertext MUST cause unseal to fail.
- DistinctNoncePerSeal — sealing same (pt, aad) twice MUST produce
  distinct ciphertext.
- Truncation — dropping the last byte MUST cause unseal to fail.
- CrossInstance — a sealer rebuilt with same identity unseals blobs
  produced by the original.

## Reference example

[`conformance_test.go`](conformance_test.go) implements a 100-line
reference backend using stdlib `crypto/ed25519` + `crypto/aes` +
`crypto/cipher`, and runs the conformance suite against it. It serves
both as the suite's self-test (passing build = suite is wired
correctly) and as a worked example of what a conformant adapter looks
like.

## What this package does NOT cover

- Wire-format conformance (CBOR field offsets, sgx_quote3_t binary
  layout, COSE_Sign1 envelope structure). These are platform-specific
  and tested by each adapter's own test suite.
- Side-channel resistance.
- Performance characteristics.
- TEE-specific policies (MRSIGNER pinning, ISVSVN floor, AcceptableHostData).
  These belong to the verifier's *configuration*, not its conformance
  to the abstract contract.

The conformance suite proves your adapter is *behaviourally
equivalent* to a Vault Genome reference backend on the V1 frozen
contract — that's the only claim it endorses.

## Versioning

This package follows the V1 frozen contract documented in
[ADR-0001](../../docs/adr/0001-frozen-producer-verifier-sealer-interface.md).
The test surface is deliberately stable across module versions. A
future V2 amendment (only via ADR amendment) would land at
`pkg/teeconformance/v2` alongside this package; V1 will keep accepting
V1-conformant adapters indefinitely.

## License

AGPL-3.0-or-later, same as the rest of the module. See
[ADR-0003](../../docs/adr/0003-agpl-commercial-dual-licensing.md) for
the licensing strategy. Commercial licenses available — contact
ops@vaultgenome.com.
