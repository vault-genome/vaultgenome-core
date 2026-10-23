# Reference design 01, played end to end on real SEV-SNP

The kit for the design's prove-it phase: one command in a GCP project
plays [reference design 01 — a Tier-1 bank's continuity of a fine-tuned
model across two clouds](../../../docs/reference-designs/01-tier1-bank-model-continuity.md)
from the quant's seal to the third party's audit query, on two AMD
SEV-SNP Confidential VMs in two regions, and writes the design's figures
table from what it measured (`evidence/<stamp>/REPORT.md`). Nothing in it
is simulated: both chips attest through the kernel's configfs-tsm, the
key files are sealed to the chips, the model is a real fine-tune run
through the real door.

```
  A  the bank, region A (bank.sh)        B  the standby, region B (standby.sh)
     n2d-standard-4 SEV-SNP                 n2d-standard-2 SEV-SNP
     sagvd + acp-compute, loopback          acp-bootstrap on 0.0.0.0:8443 (mTLS + token),
     every key file sealed to the chip      reachable from A's internal address only
     the quant's fine-tune sealed  ──────▶  the sealed genome (opaque) and the base model
     the gate job: EXACT          ◀──────   the standby's identity (its chip's measurement)
     the key released after B attested ─▶  the key unwrapped by the fresh HPKE key;
     the restore confirmed from B's         the genome restored; the receipt signed
     chip-signed receipt                    with the chip; the restored model gated
     two releases refused (unlisted,        on this chip against the sealed fixtures
     operator stop); two rogues refused
         │ both audit logs, the published audit key, the job's view
         ▼
  C  the third party — the machine that ran the kit, with acpctl alone:
     `acpctl audit verify` (both logs), `audit query --request <id>`, `lineage --session-id <id>`
```

The hand-off between the three is the run's private bucket, deleted with
the run. A's Return Path never leaves loopback; the one port the run
opens is B's 8443, to A's internal address alone (a firewall rule it
creates and deletes).

## What a run shows, in the design's words

**A job, end to end** (the design's six steps): the quant seals the
fine-tune (`acpctl genome seal`); the operator submits the job over the
API; the worker opens a session — the handshake carries both chips'
reports, `TRUST_EVALUATED` records the verdict; the authority releases
the sealed material for this session only, the worker restores the model
in memory and runs the fixtures; the signed verdict comes back,
`RELEASE_DECIDED` closes the job; the third party verifies the chain and
queries the request.

**The continuity**: the standby's chip attests to the bank (`acp-bootstrap
identity`, the measurement on the bank's allow-list, the report verified
against the AMD chain acpctl fetched and checked against the roots it
pins); `sagvd crosscloud-restore` releases the genome's key to it under
the profile's KEM suite (ADR 0029); the standby restores by itself and
signs a receipt with its chip; `sagvd crosscloud-confirm` verifies the
receipt; `acpctl genome gate` recomputes every sealed fixture on the
standby's chip through the real door and holds the results to the sealed
references — EXACT.

**What is refused**: a worker whose key files are the sealed ones but
whose TEE is not the chip (they do not open); a worker with plaintext
copies and the wrong attestation (refused at the handshake, on the
record); a release to a guest the allow-list does not name; a release
under the operator's stop.

**The record**: both of the bank's audit logs verified on the bank with
the published key, then again by the third party with nothing but the
logs, the key and acpctl; the request's events and the session's lineage
queried there.

## Run it

```bash
./scripts/hardware-test/reference-design-01/run.sh <gcp-project> [zone-a] [zone-b] [profile]
# defaults: us-central1-c; us-east4-b, us-west1-b or europe-west4-b (the first that creates an n2d SEV-SNP guest); general — profile general, fips or cnsa (ADR 0029)
```

About fifteen minutes; one n2d-standard-4 and one n2d-standard-2, both
deleted by the run, also on failure (`VG_KEEP_ON_FAILURE=1` leaves them
for a look; the guests' consoles are saved under the evidence directory
when a run fails). Needs gcloud logged in to a project with the Compute
and Storage APIs, and Go for the binaries — the kit builds them from the
tree it runs from (a release's binaries are proven equal to the tree's
by `release-deploy`). `VG_FIPS=1` builds every binary on the certified
Go Cryptographic Module v1.0.0 (`GOFIPS140=v1.0.0`) and runs every Go
process — the bank's two daemons, the standby's daemon and the third
party's `acpctl` on this machine — under `GODEBUG=fips140=only`, in
which a non-approved service fails instead of succeeding (ADR 0030, part
two); `general` is refused, its first suite being X25519; the verdict
then requires the record of the module on every party, and `run.txt`,
`build.txt` and `REPORT.md` say which module the run was on.
`VG_SIGSUITE` picks the signature suite (ADR 0031) within what the
profile accepts — `ed25519`, `ecdsa-p384-sha384` or `ml-dsa-87`; the
profile's own when unset (`ecdsa-p384-sha384` under `cnsa`, `ed25519`
otherwise) — and the kit makes every key under it with `acp-keygen
-signature-suite`, names it in every config, and refuses a record that
does not show it on the bank's two daemons, the standby, and the two
audit logs as the bank and the third party verify them.
The binaries are built from a clean checkout of `HEAD` when the tree's
tracked files are clean, so their VCS stamp is the commit's even while
other kits write their records into the tree (untracked files mark a
build modified; on 2026-10-21 the binaries of a release record came out
`-dirty` for that reason); a tree with modified tracked files builds from
the working tree, stamped so.

The record of a run is `evidence/<stamp>/`: `a/` (the bank's steps,
timeline, identities, the job's view, both audit logs' verification,
the release and the confirmation, the refusals' logs, metrics, the
console), `b/` (the standby's steps, identity, receipt, the gate's
verdict, the console), `third-party/` (the verifications and queries
done on the runner, and the tools it used), `REPORT.md` (the design's
six steps, the continuity and the refusals, the figures), `machines.txt`,
`inputs.sha256`, `build.txt` (what the runner built: each binary's
module setting and commit, from its own build settings),
`runner-timeline.txt`, `sha256sums.txt` (every file of
the run but `runner.log`, the runner's own transcript, which tee writes
until the runner exits). Keys, seeds,
tokens and configs stay on the guests and die with them; the standby's
TLS material and token leave the bank once, through the private bucket,
before the bank seals its own copies.

## What this does not show

- The bank's authority and worker share one chip here (the Return Path on
  loopback); the design has them on separate hosts, which
  `provision-two-hosts` proves with ADR 0028's three commands across GCP
  and Azure.
- Region B is a second GCP region, not a second cloud; the design's Azure
  standby is proven by `azure-sev-snp/returnpath-e2e`, `failover-cgpu` and
  `azure-cgpu`. A second-cloud standby for this kit is a flag to add, not
  a change of design.
- The move is a planned release, not a failover: the sentinel, the policy
  and the move on an attack or on silence are the failover drills (C8,
  C14, C35) and `authority-loss`.
- The standby's gate is `acpctl genome gate` on the restored directory —
  the same fixtures, the same door, a local verdict — not a standby
  authority issuing a job.
- The operator's stop key is made on the bank's host for the run; in
  production it lives on the operator's machine.

## Results

| Profile | Run | The key under | The bank's job | The key to the standby, restore confirmed | The standby's gate | Refused | Audit, bank and third party | Handshake, first / next | Run to the third party's verdict |
|---|---|---|---|---|---|---|---|---|---|
| `general` | [`evidence/20261021T183244Z/`](evidence/20261021T183244Z/) | `hpke-x25519-v1` | EXACT 6/6 in 5.2 s | 15.5 s (the release 4.9 s; key to restored 0.003 s) | EXACT 6/6, backend 4.05 s | the sealed files off the chip; the unpinned worker (1 s); the unlisted guest; the operator's stop — each with its reason | 17 + 10 events; four verifications at exit 0 | 8187 ms / 27 ms | 317 s, the guests' creation included |
| `fips` | [`evidence/20261021T184052Z/`](evidence/20261021T184052Z/) | `hpke-p384-v1` | EXACT 6/6 in 5.2 s | 15.5 s (the release 4.9 s; key to restored 0.004 s) | EXACT 6/6, backend 4.39 s | the same four, each with its reason | 17 + 10 events; four verifications at exit 0 | 8185 ms / 23 ms | 308 s |
| `cnsa` | [`evidence/20261021T184112Z/`](evidence/20261021T184112Z/) | `hpke-mlkem1024-p384-v1` | EXACT 6/6 in 5.2 s | 15.7 s (the release 4.9 s; key to restored 0.008 s) | EXACT 6/6, backend 3.99 s | the same four, each with its reason | 17 + 10 events; four verifications at exit 0 | 8187 ms / 23 ms | 308 s |
| `fips`, the v2 suites of ADR 0030 | [`evidence/20261021T202252Z/`](evidence/20261021T202252Z/) | `hpke-p384-v2` — HPKE export-only, the AEAD step the module's AES-256-GCM | EXACT 6/6 in 5.2 s | 15.6 s (the release 4.9 s; key to restored 0.006 s) | EXACT 6/6, backend 3.96 s | the same four, each with its reason | 17 + 10 events; four verifications at exit 0 | 8205 ms / 26 ms | 316 s |
| `fips`, `VG_FIPS=1` | [`evidence/20261021T212303Z/`](evidence/20261021T212303Z/) | `hpke-p384-v2`; every binary on the certified module v1.0.0, every Go process under `fips140=only` | EXACT 6/6 in 5.2 s | 15.5 s | EXACT 6/6, backend 4.34 s | the same four, each with its reason | 17 + 10 events; four verifications at exit 0, the third party's `acpctl` under `fips140=only` | 8187 ms / 24 ms | 312 s |
| `cnsa`, `VG_FIPS=1` | [`evidence/20261021T213017Z/`](evidence/20261021T213017Z/) | `hpke-mlkem1024-p384-v2`; the same | EXACT 6/6 in 5.2 s | 15.7 s | EXACT 6/6, backend 4.47 s | the same four, each with its reason | 17 + 10 events; four verifications at exit 0, the third party's `acpctl` under `fips140=only` | 8233 ms / 26 ms | 300 s |
| `cnsa` — the signature suite (ADR 0031) | [`evidence/20261022T120741Z/`](evidence/20261022T120741Z/) | `hpke-mlkem1024-p384-v2`; signatures `ecdsa-p384-sha384` on the bank's two daemons (the profile's own), the standby accepting `ecdsa-p384-sha384` and `ml-dsa-87` | EXACT 6/6 in 5 s | 15.6 s (the release 4.8 s) | EXACT 6/6, backend 4.63 s | the same four, each with its reason | 17 + 10 events under `ecdsa-p384-sha384`; four verifications at exit 0, the third party's `acpctl` reporting `signature_suite` `ecdsa-p384-sha384` on both logs | 8200 ms / 24 ms | 420 s |
| `fips`, `VG_SIGSUITE=ecdsa-p384-sha384`, `VG_FIPS=1` — the signature suite (ADR 0031) | [`evidence/20261022T120827Z/`](evidence/20261022T120827Z/) | `hpke-p384-v2`; signatures `ecdsa-p384-sha384` on the bank's two daemons, the standby accepting `ed25519` and `ecdsa-p384-sha384`; every binary on the certified module v1.0.0, every Go process under `fips140=only` | EXACT 6/6 in 5 s | 15.6 s (the release 4.9 s) | EXACT 6/6, backend 4.06 s | the same four, each with its reason | 17 + 10 events under `ecdsa-p384-sha384`; four verifications at exit 0, the third party's `acpctl` under `fips140=only` reporting `signature_suite` `ecdsa-p384-sha384` on both logs | 8214 ms / 25 ms | 313 s |

The two runs of 2026-10-22 are the tree of ADR 0031 part three
(`1a41568`): the profile decides the signature suite, and every key
the kit made (`acp-keygen -signature-suite`), every config
(`keys.<name>.suite`, `crypto.signature_suite`) and every record say
so — the bank's `identity` (`signature_suite`, `signature_suites`,
`authority_signature_suite`, `audit_signature_suite`), the worker's
(`signing_signature_suite`), the standby's (`signature_suites`), and
both audit logs as the bank and the third party verify them
(`signature_suite` in `audit-verify*.json`). Under `cnsa` the suite is
the profile's own; the second run is `fips` picking
`ecdsa-p384-sha384` — the deployment a bank held to X9 SD-34 runs — on
the certified module with enforcement on every party, the ECDSA
signatures the module's. The figures are the figures of the runs
before; what changed is the suite on every record and the 96-byte
signatures. Two runs of the previous tree, under the same profiles,
failed at the bank's job and were not kept: the Return Path server
verified the worker's frame as Ed25519 while the worker signed under
ECDSA — the one signing path outside the contracts that part one had
not moved; the frame now names its suite under the signature, and the
server verifies under the key's suite.

The six runs of 2026-10-21 are the same two zones and the same two guest images —
the bank `us-central1-c` (measurement `7dc7c12e…`), the standby
`europe-west4-b` (`0e017d2f…`) — minutes apart. In the first three the
profile is the only thing that changed; the suite the key went under
changed with it, and nothing else in the figures did. The fourth is
`fips` again on the v2 suites of ADR 0030 — HPKE export-only, the AEAD
step the module's AES-256-GCM, the suite id `hpke-p384-v2` — and nothing
in the figures moved with it. The fifth and sixth are `fips` and `cnsa`
under `VG_FIPS=1` (ADR 0030, part two): every binary built on the
certified Go Cryptographic Module v1.0.0 and every Go process — the
bank's two daemons, the standby's daemon and the third party's `acpctl`
on the runner — under `fips140=only`, in which a non-approved service
fails instead of succeeding; `a/steps.txt`, `b/steps.txt`,
`third-party/tools.txt` and `build.txt` say so, the verdict requires it,
and the figures are the figures above. Of the zones tried, `us-east1-b`,
`us-east4-b` and `us-west1-b` refuse an n2d guest with SEV-SNP;
`us-central1-b`, `us-central1-c` and `europe-west4-b` create it. The
runtime from the hash-pinned locks took 49 s on the bank and 42 s on the
standby, after 29–30 s of apt; the fine-tune 9 s.
