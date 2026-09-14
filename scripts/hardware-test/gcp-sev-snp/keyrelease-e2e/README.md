# Cross-cloud key release on real AMD SEV-SNP

The shipping binaries, run end to end on a Google Confidential VM
(`n2d-standard-2`, AMD Milan, SEV-SNP, Ubuntu 24.04, kernel 7.0.0-1011-gcp):

- `acp-bootstrap` attests with the chip — `tee.provider: "gcp-sev-snp"`,
  reports requested through the kernel's configfs-tsm — and generates an X25519
  key per handshake, quoting over the ADR 0009 key-binding challenge.
- `sagvd crosscloud-restore` verifies that Evidence (VCEK fetched from AMD KDS,
  ECDSA-P384 signature, VCEK → ASK → ARK-Milan chain, TCB, guest policy with no
  DEBUG, VMPL 0, REPORT_DATA binding the challenge), applies its allow-list, and
  only then encapsulates the DEK to the attested key.

Both processes run inside the same guest here; what the run proves is that the
destination's Evidence is genuine hardware and that the whole chain accepts it.

## Result — run `20260914T205955Z` (evidence/20260914T205955Z)

| Step | Outcome |
|---|---|
| `acp-bootstrap identity` | measurement `0e017d2f…fa2de00f` (48 bytes, SHA-384 launch digest) |
| Release to this guest, allow-listed | **ok** — 3 audit events (handshake → attestation verified → release authorised); destination registered 1 key |
| Recipient key | source report and destination log both name `428bdfea…9588` |
| Release with an allow-list that does not name this guest | **refused** — `authority / attestation_denied`: the Evidence verified (2 audit events) but the policy denied release; no token was issued and the destination accepted none |

## Run `20260914T205458Z` (evidence/20260914T205458Z) — kept on purpose

The release itself succeeded the same way (recipient key `13938f2f…2c11`). The
second, refused release failed for a different reason than intended: it was a new
`sagvd` process, fetched the VCEK again, and AMD KDS answered **HTTP 429**. The
verifier failed closed (`integrity`), so nothing was released — but the run did
not show the policy gate. That is why the verifier now keeps fetched VCEKs on
disk (`vcek_cache_dir`) and waits out a 429 a few times before failing; the run
above used both.

## What this does not show

- The two processes share one guest. A source on another host changes only the
  network path, which the live test suite already covers over mutual TLS.
- The released DEK is registered in the destination's in-memory keystore; using
  it to open a sealed genome is the next step of the Continuity Drill.
- Only SEV-SNP. Other TEE families are refused by both binaries.

## Reproduce

```bash
scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/run.sh <gcp-project> [zone]
```

`run.sh` builds the three binaries from this tree for linux/amd64, uploads them
with the AMD Milan chain to a fresh private bucket, boots the VM with
`cvm-keyrelease.sh` as its startup script, reads the results back from the serial
console (`decode-results.sh` checks their size and SHA-256), and deletes the VM
and the bucket — also on failure. About ten minutes of one `n2d-standard-2`.

The results carry reports and logs only; keys, seeds, tokens and configs stay on
the VM and die with it. The raw serial captures (whole boot logs) are kept
outside the repository; their SHA-256:

```
126ff41bd92fb4eb689e3168427dbfaa3ec90efe6791d51a57bb319e427e66c9  serial-20260914T205327Z.txt  (run 205458Z)
aedd031abf37d59b1ad82bfa1386c6d7060c6e72a311bc20505b7e83ce8d2433  serial-20260914T205827Z.txt  (run 205955Z)
```
