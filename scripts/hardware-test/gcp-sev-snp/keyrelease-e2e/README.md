# Cross-cloud key release and genome restore on real AMD SEV-SNP

The shipping binaries, run end to end on a Google Confidential VM
(`n2d-standard-2`, AMD Milan, SEV-SNP, Ubuntu 24.04, kernel 7.0.0-1011-gcp):

- `acpctl genome seal` seals a genome (v3: its key in a separate file).
- `acp-bootstrap` attests with the chip — `tee.provider: "gcp-sev-snp"`,
  reports requested through the kernel's configfs-tsm — and generates an X25519
  key per handshake, quoting over the ADR 0009 key-binding challenge.
- `sagvd crosscloud-restore` verifies that Evidence (VCEK fetched from AMD KDS,
  ECDSA-P384 signature, VCEK → ASK → ARK-Milan chain, TCB, guest policy with no
  DEBUG, VMPL 0, REPORT_DATA binding the challenge), applies its allow-list and
  the operator stop, and only then encapsulates the genome key to the attested
  key.
- `acp-bootstrap` finds the bundle the key opens, restores it all or nothing,
  and has the chip sign a receipt; `sagvd crosscloud-confirm` verifies that
  receipt against the release and the operator's bundle and records the restore
  (ADR 0011).

Both processes run inside the same guest here; what the run proves is that the
destination's Evidence is genuine hardware and that the whole chain accepts it.

## Result — run `20260914T223735Z` (evidence/20260914T223735Z): seal → release → self-restore → confirm

us-central1-c, chip `72096f47…3f13` (another physical chip than the key-binding
evidence's `e8a8278c…`).

| Step | Outcome |
|---|---|
| `acpctl genome seal` | 16 MiB of LoRA weights + config + tokenizer → 16 781 998-byte bundle, key id `genome-0085e2097995-g0-d25fb600f8fe` |
| Release, allow-listed, stop list serial 1 | **ok** — recipient key `39b6efd5…540f` |
| Destination restores by itself | 3 files, 16 777 312 bytes, **83 ms** from the key's arrival; key wiped after the restore |
| `sagvd crosscloud-confirm -bundle` | **ok** — receipt signed by the chip verified, measurement = the one released to, tree `1a0505a0…ad1f` = the operator's bundle; `CROSS_CLOUD_RESTORE_COMPLETED`; release → confirmed 2.05 s |
| `acpctl genome verify --key-file --restored` | **ok** — authenticated, every file matches, same tree digest |
| Release, allow-list without this guest | **refused** — `authority`: not in allow-list |
| Operator stop serial 2 (`-all`) | **refused** — `authority`: operator stop in force |
| `acpctl audit verify` | **ok** — 10 events (3 + confirmation + 3 + 3) |

The chip-signed receipt verifies offline in the test suite:
`internal/genome/receipt/hardware_test.go` checks the report's ECDSA-P384
signature under the chip's VCEK (kept in `vcek-cache/`), the VCEK → ARK-Milan
chain, the production guest policy, and REPORT_DATA binding the receipt bytes —
and that one edited byte of the receipt fails.

## Result — run `20260914T212909Z` (evidence/20260914T212909Z)

us-central1-c. With the durable audit log (KNOWN_ISSUES #9) and the operator
stop (ADR 0010) in place:

| Step | Outcome |
|---|---|
| `acp-bootstrap identity` | measurement `ccdc5cf0…fb5d26fa` (48 bytes) |
| Release, allow-listed, stop list serial 1 | **ok** — recipient key `5fb4955b…9d0b` on both sides; destination registered 1 key |
| Release with an allow-list that does not name this guest | **refused** — `authority`: "destination measurement not in allow-list"; attestation verified first |
| Operator signs stop list serial 2 (`-all`); release | **refused** — `authority`: "operator stop in force (revocation serial 2): e2e: operator stop"; report names serial 2 |
| `acpctl audit verify` with the key `sagvd identity` published | **ok** — 9 events (3 per flow: handshake, attestation verified, then authorised or denied), tip `113bf67b…41c0` |

The destination answered three handshakes and accepted exactly one token.

Note the measurement differs from the us-central1-b runs below (`0e017d2f…`)
with the same image and kernel: the guest firmware differs between zones, and
the launch measurement covers it. An allow-list must name every
firmware-and-image combination it means to trust.

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
- The genome here is synthetic LoRA-shaped data; a real fine-tune, with the
  restored model loaded and measured, is Phase 1 of the Continuity Drill.
- Only SEV-SNP. Other TEE families are refused by both binaries.

## Reproduce

```bash
scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/run.sh <gcp-project> [zone]
```

`run.sh` builds the four binaries from this tree for linux/amd64, uploads them
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
becf89b92dc6b59c116030bdb30ccfdeb7a6159b7d791f68060791858ea9b2c1  serial-20260914T212737Z.txt  (run 212909Z)
e94f2009f6a2d66c33754a6ba8affe60352d0e73588bd353a05ff86100f9ff41  serial-20260914T223606Z.txt  (run 223735Z)
```
