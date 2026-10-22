# Cross-cloud key release and genome restore on real AMD SEV-SNP

The shipping binaries, run end to end on a Google Confidential VM
(`n2d-standard-2`, AMD Milan, SEV-SNP, Ubuntu 24.04, kernel 7.0.0-1011-gcp):

- `acpctl genome seal` seals a genome (v3: its key in a separate file).
- `acp-bootstrap` attests with the chip — `tee.provider: "gcp-sev-snp"`,
  reports requested through the kernel's configfs-tsm — and generates a key
  per handshake under the KEM suite the two sides' profiles settle on (ADR
  0029), quoting over the key-binding challenge that commits to the suite,
  the key and the nonce.
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

## Results — `VG_FIPS=1`: the certified module with enforcement on, under `cnsa` and `fips` (ADR 0030, part two)

The same kit with every binary built on the certified Go Cryptographic
Module v1.0.0 (`GOFIPS140=v1.0.0`) and every Go process on the guest
under `GODEBUG=fips140=only`, in which a non-approved service fails
instead of succeeding. Guests `n2d-standard-2` SEV-SNP in us-central1-c
on the image of the runs below, the tree `a6b33a2`. The verdict requires
the record of the module: both daemons' version lines
(`fips140=only module=v1.0.0 enforced=true`) and identities
(`fips140 enabled=true enforced=true version=v1.0.0`), the guest's
`fips=1 GODEBUG=fips140=only`, and `build.txt` — the runner's note of
what it built, every binary `GOFIPS140=v1.0.0-c2097c7c`, outside the
guest's sums. The `fips` run's record is named by the runner's stamp —
the kit's `vg-stamp`, new: an earlier `fips` guest booted in the same
second as the `cnsa` one, both named their record by their own clock,
and the later decode overwrote the earlier record, so the guests now
take the runner's stamp, unique per run; the `cnsa` run's record keeps
the guest's clock, as before. The third row is the released commit:
the kit run from a clean checkout of the tag `v0.8.0` twenty minutes
after the release was published, both daemons reporting `v0.8.0` at
`20dc289` with `fips140=only module=v1.0.0 enforced=true`
(`versions.txt`), every binary `GOFIPS140=v1.0.0-c2097c7c` at that
commit (`build.txt`). The fourth row is the kit's own proof of the
clean-checkout build (2026-10-22): run while the two §5 kits wrote their
records into the tree, the binaries stamped `commit e784bab3e688` with no
`-dirty` (`versions.txt`).

| Profile | Run | The suite both sides met on | Release | Restore confirmed (chip receipt) | `genome verify` | Unlisted guest | Operator stop | Audit |
|---|---|---|---|---|---|---|---|---|
| `cnsa` | `evidence/20261021T213940Z` | `hpke-mlkem1024-p384-v2` | **ok**, recipient key `a84b1616…` | **ok** | **ok** | **refused** | **refused** | **ok**, 10 events |
| `fips` | `evidence/20261021T214501Z` | `hpke-p384-v2` | **ok**, recipient key `d834fdc8…` | **ok** | **ok** | **refused** | **refused** | **ok**, 10 events |
| `fips`, the release `v0.8.0` | `evidence/20261021T234401Z` | `hpke-p384-v2` | **ok**, recipient key `a39ddae5…` | **ok** | **ok** | **refused** | **refused** | **ok**, 10 events |
| `fips`, the clean build beside other kits | `evidence/20261022T001059Z` | `hpke-p384-v2` | **ok**, recipient key `7640b822…` | **ok** | **ok** | **refused** | **refused** | **ok**, 10 events |

## Results — runs `20261021T202413Z`, `20261021T202422Z`, `20261021T202423Z`: the three profiles under the v2 suites (ADR 0030)

The same kit on the tree of ADR 0030 part one, three guests
`n2d-standard-2` SEV-SNP in us-central1-c, the same launch measurement
`ccdc5cf0…` as the runs below, minutes apart. The suites are v2: HPKE
opened export-only derives the key and the cryptographic module's
AES-256-GCM seals under it with the nonce it generates — the AEAD inside
Go's HPKE, which the module refuses under `fips140=only`, is no longer
on the path.

| Profile | Run | The suite both sides met on | Release | Restore confirmed (chip receipt) | `genome verify` | Unlisted guest | Operator stop | Audit |
|---|---|---|---|---|---|---|---|---|
| `general` | `evidence/20261021T202413Z` | `hpke-x25519-v2` | **ok**, recipient key `7d51664c…` | **ok**, key to restored 0.097 s | **ok** | **refused** | **refused** | **ok**, 10 events |
| `fips` | `evidence/20261021T202422Z` | `hpke-p384-v2` | **ok**, recipient key `534ea09f…` | **ok**, 0.085 s | **ok** | **refused** | **refused** | **ok**, 10 events |
| `cnsa` | `evidence/20261021T202423Z` | `hpke-mlkem1024-p384-v2` | **ok**, recipient key `82ae329c…` | **ok**, 0.086 s | **ok** | **refused** | **refused** | **ok**, 10 events |

## Results — runs `20261021T144756Z`, `20261021T144804Z`, `20261021T144806Z`: the three cryptographic profiles (the v1 suites of 0.7.0)

The kit's third argument is the profile of ADR 0029, written into both
daemons' configurations on the guest (`crypto.profile`). Three guests,
`n2d-standard-2` SEV-SNP in us-central1-c, the same launch measurement
`ccdc5cf0…`, the binaries of commit `b98a34264140`, each run about three
minutes end to end; each guest and bucket deleted by its run.

| Profile | Run | The suite both sides met on | Release | Restore confirmed (chip receipt) | `genome verify` | Unlisted guest | Operator stop | Audit |
|---|---|---|---|---|---|---|---|---|
| `general` | `evidence/20261021T144756Z` | `hpke-x25519-v1` — X25519, the first of five the general profile offers | **ok**, recipient key `ea46db11…` | **ok** | **ok** | **refused** | **refused** | **ok**, 10 events |
| `fips` | `evidence/20261021T144804Z` | `hpke-p384-v1` — P-384, the first of the three fips offers | **ok**, recipient key `5931880a…` | **ok** | **ok** | **refused** | **refused** | **ok**, 10 events |
| `cnsa` | `evidence/20261021T144806Z` | `hpke-mlkem1024-p384-v1` — the ML-KEM-1024 + P-384 hybrid, the one cnsa offers | **ok**, recipient key `cf191bd8…` | **ok** | **ok** | **refused** | **refused** | **ok**, 10 events |

`20261021T164918Z` is the `fips` run on the binaries of the tag `v0.7.0`
(commit `28fa01506f43`, built by the kit from the tree at the tag;
release procedure §5), ten minutes after the release was published: both
daemons `crypto_profile=fips`, the release under `hpke-p384-v1` to
recipient key `f5eb716d…`, the restore confirmed, `genome verify` ok,
the unlisted guest and the operator stop refused, the audit log verified
(10 events); the measurement `ccdc5cf0…`, the same guest image as the
three runs above.

What each record holds beyond the earlier runs': `steps.txt` names the
profile, both daemons' `crypto_profile` and `kem_suites` as `identity`
printed them, and the release's `recipient_key_suite` and `crypto_profile`
as `sagvd crosscloud-restore` reported them; `release.json` carries the
same; the audit log's `KEY_RELEASE_AUTHORIZED` event records the suite as
`delivery_mode` and the profile as `crypto_profile`. The kit's verdict
requires the release's suite to be the profile's first — a run that met on
another suite, or on none, fails.

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
scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/run.sh <gcp-project> [zone] [profile]
```

`run.sh` builds the four binaries from this tree for linux/amd64, uploads them
with the AMD Milan chain to a fresh private bucket, boots the VM with
`cvm-keyrelease.sh` as its startup script, reads the results back from the serial
console (`decode-results.sh` checks their size and SHA-256), and deletes the VM
and the bucket — also on failure. About ten minutes of one `n2d-standard-2`.
The third argument is the cryptographic profile of ADR 0029 (`general`,
`fips` or `cnsa`) both daemons run under. `VG_FIPS=1` builds every binary
on the certified Go Cryptographic Module v1.0.0 (`GOFIPS140=v1.0.0`) and
runs every Go process on the guest under `GODEBUG=fips140=only`, in which
a non-approved service fails instead of succeeding (ADR 0030, part two);
`general` is refused, its first suite being X25519; the verdict then
requires the record of the module on both daemons, and `build.txt` (the
runner's, outside the guest's sums) notes what was built.
The binaries are built from a clean checkout of `HEAD` when the tree's
tracked files are clean, so their VCS stamp is the commit's even while
other kits write their records into the tree (untracked files mark a
build modified; on 2026-10-21 the binaries of a release record came out
`-dirty` for that reason); a tree with modified tracked files builds from
the working tree, stamped so. The guest writes its sums last, so `steps.txt`
is under them.

The results carry reports and logs only; keys, seeds, tokens and configs stay on
the VM and die with it. The raw serial captures (whole boot logs) are kept
outside the repository; their SHA-256:

```
126ff41bd92fb4eb689e3168427dbfaa3ec90efe6791d51a57bb319e427e66c9  serial-20260914T205327Z.txt  (run 205458Z)
aedd031abf37d59b1ad82bfa1386c6d7060c6e72a311bc20505b7e83ce8d2433  serial-20260914T205827Z.txt  (run 205955Z)
becf89b92dc6b59c116030bdb30ccfdeb7a6159b7d791f68060791858ea9b2c1  serial-20260914T212737Z.txt  (run 212909Z)
e94f2009f6a2d66c33754a6ba8affe60352d0e73588bd353a05ff86100f9ff41  serial-20260914T223606Z.txt  (run 223735Z)
```
