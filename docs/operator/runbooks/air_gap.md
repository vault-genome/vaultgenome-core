# Air-gapped operation: the caches filled while connected, the route cut, the Return Path from the caches

A release host that has no route to the world — a bank's enclave network,
a site behind an egress-deny rule — runs the Return Path exactly as a
connected one does: the handshake, the gate, the audit log, the queue and
the sealing of key files are local. What is not local is what the
verifiers must learn from the hardware vendors, and the release itself.
This runbook says what that is, how to have it in place before the route
goes, how to know when it runs out, and what the daemons do when it is
missing (they refuse; nothing is admitted on a cache that is not there).
The air-gap drill (`scripts/hardware-test/air-gap/`) does all of it on a
real SEV-SNP host and records the numbers (§5).

## 1. What reaches out, and what does not

| Need | Who asks | When | Without a route |
| - | - | - | - |
| The VCEK of a peer's chip at its TCB | the SEV-SNP (and Azure cGPU) peer verifier, from AMD KDS | at the first handshake with that chip and TCB; then from `tee.peer.vcek_cache_dir` | the handshake is refused, naming KDS; nothing is admitted |
| The AMD ASK+ARK chain of the chip's product line | the operator, `acpctl tee fetch-amd-chain` (ADR 0024: verified against the roots the binary pins) | once, before the daemons start (`tee.peer.amd_cert_chain_path`) | the daemons refuse to start without the file |
| Intel's TCB info for a peer's platform (by FMSPC) and the QE identity | the TDX peer verifier, from Intel PCS | at the first handshake; then from `tee.peer.pcs_cache_dir` until each document's `nextUpdate` (Intel issues them monthly) | the handshake is refused, naming PCS |
| NVIDIA's NRAS key set, the RIM manifests, the OCSP answers | the Azure cGPU peer verifier | at the first handshake; then from `nras_cache_dir` and `rim_cache_dir` (an OCSP answer until its `nextUpdate`, about a day) | the handshake is refused |
| The release: binaries, the worker package, their signatures | the operator | once per release | from 0.4.3 each signed file has a Sigstore bundle, and `cosign verify-blob --new-bundle-format --bundle <asset>.sigstore.json --trusted-root trusted_root.json …` verifies it with no route at all — the trust root a file from `cosign initialize`'s cache on a connected machine (`~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json`), carried in with the assets and the pinned cosign 2.6.5; not `--offline`, which on 2.6.5 still reaches for the TUF mirror (the drill measured both, §5). Before 0.4.3: verify on a connected machine, carry the verified assets with their `checksums.txt` |
| The worker's runtime (the hash-pinned locks) | `pip`, on the host | once, before the route goes | `vg_genome` runs with `HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1`; the drill fine-tunes and gates with the route dead |
| Time | the host's clock | always | a verifier judges `nextUpdate` and certificate validity by the host clock: an air-gapped host needs a time source it trusts |

Nothing else: the Return Path handshake carries the reports themselves,
the audit log and the job store are files, the key files are sealed to
the chip or the host's TPM (ADR 0023, ADR 0025).

## 2. Before the route goes: fill the caches

On each release host, with the vendors still reachable:

1. **The release**, verified ([05_release_procedure.md](../05_release_procedure.md)
   §5) and carried to the host with its checksums — with its Sigstore
   bundles, the pinned cosign and `trusted_root.json`, the host verifies
   it again itself with no route (§1); the worker's runtime installed
   from the locks ([09_first_deployment.md](../09_first_deployment.md)).
2. **The AMD chain** of the chip's product line:
   `acpctl tee fetch-amd-chain --product <milan|genoa|turin> --out <file>`
   — verified against the pinned roots before it is written.
3. **The key material, the identities and the pins** as in the first
   deployment: `acp-keygen -private`, `sagvd identity`, `acp-compute
   identity`, each measurement into the other's `tee.peer.measurement_path`.
4. **The caches**, from each daemon's own configuration:

   ```bash
   acpctl tee prefetch --config /etc/acp/sagvd.json
   acpctl tee prefetch --config /etc/acp/worker.json
   ```

   `prefetch` takes this host's report through configfs-tsm and verifies
   it as the configured peer verifier would, pinned to this host's own
   measurement, with the vendors reachable: the caches the configuration
   names (`vcek_cache_dir` for SEV-SNP, `pcs_cache_dir` for TDX) then hold
   what this host's evidence needs — on SEV-SNP the VCEK of this chip at
   its current TCB, on TDX the TCB info of this platform and the QE
   identity. Two daemons on one host then have what they need for each
   other. A peer on **another chip** fills its own host's caches the same
   way; copy the files over (a VCEK is `<chip id>-<tcb>.der`, a PCS
   document `<name>.json` with its `<name>.issuer-chain.pem`): a cache is
   portable, and never trusted on its own — every document is checked on
   use exactly like a fresh one.

   `prefetch` refuses, before it touches the hardware, a family it does
   not cover (today: `gcp-sev-snp` and `gcp-tdx`; for `azure-cgpu` run the
   daemon once with the vendors reachable — any attestation fills its
   caches), a peer of another family than this host's, a missing AMD
   chain, and a configuration that names no cache directory.
5. **What is there, and until when:**

   ```bash
   acpctl tee cache-status --config /etc/acp/sagvd.json
   ```

   lists every cached document with its validity and the earliest
   expiry, and exits 1 when anything is expired, unusable or missing —
   put it in the host's periodic checks. A VCEK is valid for years; an
   Intel TCB info or QE identity until its `nextUpdate`, about a month;
   an NVIDIA OCSP answer about a day.
6. **Keep a copy** of the cache directories with the operator's safe
   (ADR 0023: the plaintext is the operator's to keep; the caches hold
   public certificates and documents, so the copy needs no protection
   beyond integrity): a host whose cache is lost is refilled from the
   copy, with no route.

## 3. With the route gone

Start the daemons as always. The handshake verifies each side's report
from the cache: `sagvd.log` shows `sagvd session opened`, the job gates,
the audit log grows. Nothing in the flow asks a vendor.

**Fail closed.** With a cache missing or expired, the peer verifier asks
the vendor, the request dies on the dead route, and the handshake is
refused with the vendor's error on the record (`sagvd return-path
handshake failed … KDS …` / `… PCS …`); the worker retries with backoff
and is refused again; no job is dispatched. Restore the cache from the
copy (step 6) and the next handshake succeeds — the drill does exactly
this (§5).

A TCB change on the chip (a firmware update raises the reported TCB)
needs a new VCEK: the cached one is for the old TCB. Run `prefetch`
again while a route exists, or carry the new VCEK in. The same for a new
Intel TCB info once `nextUpdate` passes.

## 4. Re-fill before the expiry

`cache-status` names the earliest expiry. Before it: connect the host,
or a host of the same family, run `prefetch`, copy the files. A site
with no route ever can run `prefetch` on a connected machine of the same
chip family only for that machine's chip; for the release hosts' own
VCEKs it fetches them by chip id and TCB from AMD KDS with any client
and drops the DER files into `vcek_cache_dir` under the names
`cache-status` shows — the verifier checks them against the pinned chain
on use, so the carrier is not trusted.

## 5. Measured

The air-gap drill, `scripts/hardware-test/air-gap/run.sh`, run
`20261015T212716Z` on an `n2d-standard-4` SEV-SNP Confidential VM
(the record: [`scripts/hardware-test/air-gap/evidence/20261015T212716Z/`](../../../scripts/hardware-test/air-gap/evidence/20261015T212716Z/),
the kit's [README](../../../scripts/hardware-test/air-gap/README.md)):

- `prefetch` for both daemons' configurations took 10.5 s and put this
  chip's VCEK in each cache, valid 2026-10-14 → 2033-10-14 — seven years;
  on SEV-SNP what sends an operator back to KDS is a TCB change, not the
  calendar.
- Behind a firewall rule denying all egress (KDS and the bucket unreachable,
  the metadata server reachable), the key files sealed, a genome
  fine-tuned with the runtime offline, both daemons started: the session
  opened 11 s after the worker started, each report verified with the
  VCEK from the cache, the job gated **EXACT** in 5.2 s.
- With the caches wiped, the handshake was refused 41 s after `sagvd`
  started — the KDS client's 40 s on a dead route — naming KDS on the
  record; no job was dispatched. With the caches restored from the copy,
  the session opened in 1 s and a job gated EXACT. The audit log verified:
  33 events, the refusal among them.
- Not measured yet: a TDX host (`prefetch` covers `gcp-tdx`; the PCS
  documents expire monthly), and the release's own verification without
  a route (KNOWN_ISSUES #15).
