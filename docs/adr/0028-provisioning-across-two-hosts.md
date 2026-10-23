# ADR 0028 — Provisioning across two hosts: the authority writes the worker's bundle, the worker joins, the authority pins

- **Status:** Accepted (2026-10-17)
- **Tags:** acpctl, provision, deployment, keys, pins, two-hosts
- **Extends:** ADR 0023 (the daemons' key files sealed to the host), ADR 0025 (any hardware: the daemons are RATS roles)

## Context

`acpctl provision` (VERIFIABLE-CLAIMS C37) stands up a deployment with
one command: the key material, both configurations, each daemon's
identity pinned on the other side, every key file sealed to the chip. It
sets up both daemons on one host, because that is where it can run both
`identity` commands and seal both sides' files. A deployment that means
anything has the authority and the worker on different machines — often
in different clouds and on different chips, as the failover drills are —
and for that the first-deployment guide said only: "two hosts carry the
worker's subtree over and pin the other side's measurement from its
`identity`". By hand, that is the step where a key file is copied in the
clear to a second host, a pin is pasted from one terminal into another,
and a mistake in either is found at the first handshake, as a refusal.

What is different about two hosts is small and exact. The worker's
private keys must exist on the worker's host and not remain on the
authority's. The worker's measurement is known only once the worker's
chip has reported it, on the worker's host, with the worker's own
configuration — so the authority's pin of the worker is the last thing
written, not the first. Each side verifies the other's report with the
other's vendor chain: an authority on an AMD Milan guest and a worker on
an AMD Genoa guest need two chains, not one. And the material that
crosses between the hosts is of two kinds: the worker's secrets, once,
from the authority to the worker; and the worker's identity, public,
back.

## Decision

1. **Three commands, in order, on the two hosts.** `acpctl provision
   authority` on the authority's host does everything the one-host
   command does except what needs the worker's chip: it runs
   `acp-keygen`, writes `sagvd.json` for the worker's family, reads the
   authority's identity, seals the authority's key files, and writes
   `worker-bundle.tar`. `acpctl provision join --bundle` on the worker's
   host unpacks the bundle into the worker's deployment directory, writes
   `acp-compute.json` for the authority named in it, reads the worker's
   identity from its chip and seals the worker's key files. `acpctl
   provision pin-worker --identity` on the authority's host, given the
   identity file the worker wrote, pins the worker's measurement and
   completes the deployment. The one-host `acpctl provision` is
   unchanged.
2. **The bundle carries the worker's side, and only that.** It holds the
   worker's secrets as `acp-keygen` made them — the signing seed, the TLS
   client pair, the worker's own copy of the session sealing key, and,
   for the simulated family, its seed and the authority's simulated
   public key — the CA certificate, the authority's measurement as the
   worker's pin, and, when the authority is a SEV-SNP guest, the AMD
   chain of the authority's product for the worker's verifier. A
   manifest names the authority (family, measurement, Return Path address
   and TLS name) and the worker (family, descriptor), and lists every
   file with its SHA-256; `join` refuses a bundle whose files do not
   match it, or that holds a file it does not list. The bundle is written
   0600; once it is written the worker's secrets are removed from the
   authority's host, and the authority's secrets never enter it.
3. **The worker's family is the authority's to name, and the worker's
   chip to confirm.** `authority` takes `--worker-provider` (the
   authority's own family unless set), writes the authority's peer
   configuration for it — the worker's product's AMD chain, or the Intel
   PCS cache — and records it in the bundle; `join` resolves the
   worker's host (`--provider auto`, or a family) and refuses to join
   under another family; `pin-worker` refuses an identity of another
   family unless forced, because the authority would refuse that worker
   at every handshake.
4. **Two chains when both sides are SEV-SNP.** `authority` takes the
   worker's product's chain for its own verifier (`--amd-cert-chain` or
   `--fetch-amd-chain`, as before) and its own product's chain for the
   worker's (`--own-amd-chain` or `--fetch-own-amd-chain`); the second
   travels in the bundle. One chip, one chain stays the one-host rule.
5. **What is complete is on the record at each step.** `provision.json`
   carries the role (`authority`, `worker`, or `both`) and the phase:
   `awaiting-worker` after the first command, `joined` on the worker,
   `complete` after the third; its `next` lines say what to carry where
   and what to run. Pins are read when a daemon starts: an authority
   started before `pin-worker` must be started again after it.

## Consequences

- A two-host deployment is three commands and two files carried — the
  bundle one way, the identity the other — over whatever channel the
  operator trusts; the handshake then admits the worker on the first
  try, or the mismatch is named by `pin-worker` before the daemons run.
- The worker's private keys are generated on the authority's host and
  exist there for the duration of the first command. A deployment whose
  policy forbids that generates the worker's keys on the worker's host
  by `acp-keygen` and copies the public parts the other way; this ADR
  does not make that command.
- The bundle is a secret while it exists: 0600, carried once, deleted
  after `join`, as `join`'s output says.
- The authority's REST API stays on loopback with its token; only the
  Return Path listener faces the worker, under mutual TLS 1.3 with the
  private CA and the pinned measurements.

## Evidence

- Across two clouds and two chips: the authority on a GCP SEV-SNP guest
  (AMD Milan), the worker on an Azure SEV-SNP guest (AMD Genoa), the
  three commands, a gate job EXACT over the Internet, the audit log
  verified under the key the authority kept: VERIFIABLE-CLAIMS C39.
- Unit tests over a stub release: the bundle's manifest and hashes, the
  worker's secrets gone from the authority's tree, a tampered bundle and
  a file not listed refused, another family refused at `join` and at
  `pin-worker`, the phases on the record. The integration test with the
  live binaries runs the three commands on one machine with two
  deployment directories and a job EXACT between them.
