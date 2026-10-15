# The air-gap drill: the caches filled while connected, the route cut, the Return Path from the caches

A release host at a bank has no route to the world. What the Return
Path needs from the world is small and known — the VCEK of a peer's chip
from AMD KDS, Intel's two PCS documents for a TDX peer, the AMD chain —
and the daemons keep it in caches their configuration names, checking
every cached document on use like a fresh one. This drill shows the
whole of it on a real SEV-SNP host: the caches filled while the host is
connected (`acpctl tee prefetch`), the host put behind a firewall rule
that denies all egress, the Return Path run from the caches alone; then
the caches wiped — the handshake refused, naming KDS, nothing admitted —
and restored from a copy — a job gated again. The runbook
[air_gap.md](../../../docs/operator/runbooks/air_gap.md) is the
procedure; this kit puts the record under it.

```bash
bash scripts/hardware-test/air-gap/run.sh <gcp-project> [zone]     # one n2d SEV-SNP VM, ~12 minutes
```

`run.sh` builds `sagvd`, `acp-compute`, `acpctl` and `acp-keygen` for
linux/amd64, packs `workers/genome` with its locks, creates a firewall
rule that **denies all egress** (`0.0.0.0/0`, priority 100) to instances
carrying a network tag made for the run, and boots one AMD SEV-SNP
Confidential VM (`n2d-standard-4`, Ubuntu 24.04) **without** the tag.

- **Connected** ([`cvm-airgap.sh`](cvm-airgap.sh)): the binaries from the
  run's bucket, the AMD Milan chain from KDS verified against the pinned
  roots (`acpctl tee fetch-amd-chain`, ADR 0024), the worker's runtime
  from the hash-pinned locks, the key material (`acp-keygen -private`),
  the identities and pins; then `acpctl tee prefetch --config` for each
  daemon's configuration — each daemon's peer verifier has its own
  `vcek_cache_dir` here, and each is filled from its own configuration,
  as an operator would — and `acpctl tee cache-status --config` for what
  is there and until when. A copy of the caches is taken aside (the
  operator's backup). The guest prints `===AIRGAP-READY===` on its serial
  console and waits.
- **The cut**: the runner adds the tag; the guest sees it in its
  metadata and waits until AMD KDS stops answering, then records the
  three routes — KDS, the bucket, the metadata server — with curl's
  verdicts (`egress.txt`).
- **Air-gapped**: the key files sealed to the chip (`seal-keys`), a tiny
  model fine-tuned and sealed with the runtime offline (`HF_HUB_OFFLINE`,
  `TRANSFORMERS_OFFLINE`), both daemons started — the Return Path
  handshake verifies each side's report with the VCEK from the cache,
  nothing asks KDS — and a gate job gated; metrics; both stopped.
- **The negative**: the two caches wiped, both daemons started again:
  the handshake must be refused with KDS named on the record
  (`sagvd return-path handshake failed`), and no job dispatched. The
  kit's `handshake_timeout_seconds` is 60, above the KDS client's 40 s,
  so a dead route surfaces as the KDS error it is, not as the
  handshake's own clock.
- **The recovery**: the caches restored from the copy, both daemons
  again, a job gated again; `cache-status` after the wipe (exit 1) and
  after the restore (exit 0).
- **The record**: the audit log verified under the key `sagvd identity`
  published; the results on the serial console, decoded with the Return
  Path kit's `decode-results.sh` into `evidence/<stamp>/`; the VM, the
  bucket and the firewall rule deleted on exit, on success or failure.

## Result — run `20261015T212716Z` (evidence/20261015T212716Z): the route cut, the Return Path from the cache, the refusal without it

us-central1-c, `n2d-standard-4`, Ubuntu 24.04, tree `5f3ebea` (the
`prefetch` commit; it predates `tee.sealer`, so `seal-keys` prints no
sealer here). The guest script took **263.4 s**; from the VM's creation
to the results on the console, 366.9 s.

| Step | Outcome |
|---|---|
| Connected: the runtime from the locks | 79.7 s |
| `acpctl tee prefetch`, both configurations | 10.5 s for the two; each put this chip's VCEK in its daemon's cache — `188de2d8…-16004948650744610820.der`, 1 351 bytes (`cache-files.txt`), CN `SEV-VCEK`, valid 2026-10-14 → 2033-10-14 (the TCB `0xde1d000000000004`: bootloader 4, TEE 0, SNP 29, microcode 222); `cache-status`: `1 of 1 current; the earliest expiry is 2033-10-14T22:30:52Z` |
| The cut | the guest said ready at 21:28:48Z; the runner added the tag at 21:28:57.96Z; the guest saw it 8 s after asking and KDS stopped answering 33 s later; `egress.txt`: KDS `curl: (28) Connection timed out`, the bucket the same, the metadata server `200` |
| Air-gapped: `seal-keys` ×2, the fine-tune with the runtime offline | both sealed; the fine-tune 9.1 s (`HF_HUB_OFFLINE`, `TRANSFORMERS_OFFLINE`), the genome sealed (`genome-6fb05fc6…`) |
| The Return Path from the cache | `sagvd` ready in 3 s, the session open 11 s later — each side's report verified with the VCEK from its own cache, nothing asked KDS; the gate job `succeeded`, **EXACT**, pinned replay, 6 of 6, max abs err 0, in 5.2 s |
| The negative: the caches wiped | `cache-status` exit 1 (`the caches are empty`); both daemons restarted: no session; **the handshake refused 41.1 s after `sagvd` started** — the KDS client's 40 s on a dead route — `sagvd return-path handshake failed … server TEE evidence verification failed: integrity[signature_invalid]: gcp-sev: fetch VCEK: Get "https://kdsintf.amd.com/vcek/v1/Milan/188de2d8…?blSPL=4&snpSPL=29&teeSPL=0&ucodeSPL=222": …` (the worker verifies the authority's report first; it asked KDS, and refused); one refusal on the record, no job dispatched |
| The recovery: the caches restored from the copy | `cache-status` exit 0; the session open 1 s after the worker started; the job `succeeded`, **EXACT**, 6 of 6 |
| `acpctl audit verify` | **ok — 33 events**: two jobs' sixteen each and the refusal between them, tip `d92fed3e…` |

What the record shows: the Return Path needs nothing from the world
once the VCEK of the chip is in the cache — and with the cache gone it
admits nothing, saying which vendor it could not reach. On SEV-SNP the
cached VCEK is good for seven years: what sends an operator back to KDS
is a TCB change on the chip (a new VCEK for the new TCB), not the
calendar. What the record does not show: a TDX host (`prefetch` covers
`gcp-tdx` in code — the PCS documents, each until its `nextUpdate`;
the run on a `c3` is the next), and the release's own verification
without a route (done on the connected side here; KNOWN_ISSUES #15 —
Sigstore bundles come with 0.4.3). The cut is a VPC firewall rule, not a
physical gap: the metadata server stays reachable, and the guest used it
for the tag and the serial console only — nothing of the Return Path
touches it. Checksums: `cd evidence/20261015T212716Z && grep -v
' sha256sums.txt$' sha256sums.txt | shasum -a 256 -c` — 52 of 52 match.

## Evidence files

- `steps.txt` — every step with its time and exit code; the routes; the
  jobs' verdicts; the refusal's text.
- `timeline.txt` (the guest's marks: runtime, prefetch, ready, the tag
  seen, the daemons, the jobs) and `runner-timeline.txt` (the runner's:
  the VM created, the guest ready, the tag added, the results seen).
- `firewall-rule.json` — the rule as the API describes it; `instance-tags.txt`
  — the tag on the instance after the cut; `run.txt` — the tree, the rule,
  the tag.
- `prefetch-sagvd.txt`, `prefetch-sagvd.json`, `prefetch-worker.txt` — what
  `prefetch` printed; `cache-status-sagvd.txt`, `cache-status-worker.txt`,
  `cache-status-wiped.txt`, `cache-status-restored.txt`; `cache-files.txt` —
  the cached files' names (chip id and TCB), sizes and digest prefixes, not
  their bytes.
- `egress.txt` — the three routes after the cut.
- `sagvd-airgap.log`, `acp-compute-airgap.log`, `sagvd-wiped.log`,
  `acp-compute-wiped.log`, `sagvd-restored.log`, `acp-compute-restored.log`;
  `sagvd-metrics-airgap.txt`, `sagvd-metrics-restored.txt`
  (`vg_tee_attestation_total` among them).
- `job-airgap*.json`, `job-restored*.json` — the jobs' views with the
  signed verdicts; `audit-verify.json`, `audit-events.jsonl`,
  `audit-public-key.pem`; the identities, `seal-keys-*.json`,
  `finetune.json`, `seal.json`, `amd-chain.txt`, `tsm.txt`, `runtime.txt`,
  `pip-*.log`, `kernel.txt`, `metadata.txt`, `versions.txt`,
  `inputs.sha256`, `console.log`, `sha256sums.txt`.

The evidence holds no key, seed, token or config, and no cached
certificate's bytes.
