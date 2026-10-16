# veraison-live — the delegated verifier against a live Veraison, no hardware

What it proves: `tee.RATSVerifier` runs a real challenge-response session
against Veraison's verification service with a real GCP SEV-SNP report
(`internal/shared/tee/testdata/veraison`, Veraison's own captured n2d
report — the host's certificate table inside), posted in the JSON
TSM-report form our wire carries, under its media type; the EAR comes back
signed by Veraison's key (taken from its well-known document), verifies,
names the session's nonce, says `affirming` for `SEVSNP` with genuine
hardware and encrypted memory; the measurement our side reads from the
report equals what was pinned. The session nonce is the report's
REPORT_DATA — what the handshake derives for a live peer, and what
Veraison's scheme compares the report against.

What it does not prove: a fresh report over a fresh challenge (that needs
a chip: the Return Path kits with `tee.peer.verifier.mode: rats`), and a
Verifier on another host.

Needs the bench (`~/.attestation-bench`, `attestation-bench`
`scripts/setup.sh`): its native Veraison provisioned with AMD's Milan trust
anchor and the approved launches (`trust/veraison-corim-milan.cbor`, which
holds this report's measurement), started with
`e2e/scripts/veraison-local.sh start`; the verification API takes only
callers with a certificate of the bench's client CA, so the run uses the
bench's `ca-gateway` certificate.

```bash
scripts/hardware-test/veraison-live/run.sh
```

Each run keeps `evidence/<stamp>/`: `metadata.txt` (tree, Veraison's
services, the CoRIM's SHA-256), `well-known.json`, `ear.jwt`,
`summary.json`, `go-test.log`, `sha256sums.txt`.
