# ADR 0023 — The daemons' key files sealed to the host

- **Status:** Accepted (2026-09-16)
- **Tags:** keys, sealing, tee, sagvd, acp-compute
- **Extends:** ADR 0016 (the escrow key sealed to the release host) and
  ADR 0022 (the vTPM sealer) to every key file a daemon reads.

## Context

ADR 0016 made the authority's escrow key inside `sagvd`'s process and
wrote it only sealed; ADR 0022 gave the TDX and Azure confidential GPU
hosts a sealer. The other keys stayed files: `sagvd`'s authority signing
seed and audit seed, `acp-compute`'s worker signing seed, and the
session sealing key both share — 32 bytes each, mode 0600, in the clear
on the host's disk. KNOWN_ISSUES #11 said so. An image snapshot, a disk
copied out of the cloud, a backup taken in the wrong place: any of them
carries the keys the daemons sign and seal with.

## Decision

Every key file a daemon reads may be a *sealed secret*
(`internal/shared/tee/sealed_secret.go`, `vault-genome/sealed-secret/v1`):
the bytes sealed to the host's TEE — the chip's derived key on SEV-SNP,
the vTPM under a policy of the pinned boot on TDX and the Azure
confidential GPU host, the simulated TEE's weak key off hardware — with
the TEE, the measurement it was sealed at and the *name of the key* (the
config field) bound into the AEAD's associated data. The daemons read
their key files through one path (`readSecret`): bare bytes of the
expected length, or a sealed file opened by the host's sealer at read
time. A file sealed as the audit seed does not open as the authority's;
one sealed on another host, or another boot of a vTPM host, does not
open at all.

`sagvd seal-keys -config <path>` and `acp-compute seal-keys -config
<path>` seal, in place and atomically (mode 0600), every key file the
config names — `sagvd`: `keys.authority_signing.seed_path`,
`keys.session_sealing.material_path`, `keys.audit_signing.seed_path`;
`acp-compute`: `keys.worker_signing.seed_path`,
`keys.session_sealing.material_path` — after opening each sealed file
once to prove the host can, and leave a file already sealed as it is.
The operator runs them once after provisioning, before the first start;
the hardware kits do (`scripts/hardware-test/*`: `seal-keys.json` in each
authority's evidence, `seal-keys-{sagvd,worker}.json` in the Azure Return
Path's). The TEE's own identity (`tee.seed_path`, simulated only) is not a
key file and is not sealed.

## Consequences

- **No key in the clear on a hardware host's disk**: the escrow key
  (ADR 0016/0022) and now every seed and the session sealing key. What is
  still a file: `acp-bootstrap`'s TLS private key and bearer token on a
  destination (they gate transport, not keys), the sentinel's seed on the
  primary (`acpctl sentinel watch --key`; its word is bounded by the
  chip's report, ADR 0017), and the operator's own seeds off the hosts.
- **The keys are in memory while the daemon runs**, unsealed at start,
  zeroed on exit — the same standing as the escrow key.
- **A new image, a new chip, a new boot of a vTPM host** does not open
  the sealed files: the operator re-provisions (the seeds are theirs to
  keep, as the recovery envelope keeps the escrow key). Nothing
  re-provisions itself.
- **The shared session sealing key** is sealed under one name on both
  daemons; on one host (the Return Path e2e kits) both open it; on two
  hosts each seals its own copy.
- **Proven on hardware** (`scripts/hardware-test/gcp-failover/evidence/20260916T212752Z`,
  VERIFIABLE-CLAIMS C24): the failover drill's authority on a SEV-SNP VM
  sealed its three key files in place and ran the whole drill from them —
  identity, escrow provisioning, the recovery ceremony, the failover
  (RTO 22.10 s), the audit verify.
