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

## Amendment (2026-09-16, later): the sentinel's seed on the primary

The one key file this decision left bare was the sentinel's seed on the
primary — its word bounded by the chip's report (ADR 0017), so a stolen
seed moves nothing, but a file all the same. Now `acpctl sentinel seal-key
--key SEED --tee gcp-sev-snp` seals it in place, under the name
`sentinel.seed`, to the primary's TEE — the chip's derived key on SEV-SNP,
the simulated TEE's weak key off hardware — after opening it once from the
sealed form; `acpctl sentinel identity --key` and `acpctl sentinel watch
--key` take the bare seed or the sealed file, opened with the TEE `--tee`
names (a sealed file without `--tee` is refused, as is one sealed on
another host). The failover kit seals the seed right after the operator
pins the key, keeps a bare copy in the run's private bucket for the
standby's negative as before, and adds a second negative: the sealed file
taken to the standby's chip — a real SEV-SNP chip, the wrong one — does
not open.

Proven on hardware (`scripts/hardware-test/gcp-failover/evidence/20260916T231442Z`,
VERIFIABLE-CLAIMS C25): the primary sealed the seed, read the same key
from the sealed file, ran the sentinel from it through the attack; the
authority failed over on its word (RTO 18.53 s); on the standby's chip the
sealed file did not open.

## Amendment (2026-09-16, later still): the TLS keys and the tokens

What the daemons read from files beyond their seeds: `sagvd`'s mTLS
server key (`vault.tls.server_key`), its cross-cloud transport's client
key (`crosscloud.transport_tls.client_key`) and its REST API token
(`http_api.bearer_token_file`); `acp-compute`'s mTLS client key
(`vault.tls.client_key`); `acp-bootstrap`'s TLS server key
(`http.tls.server_key`) and bearer token (`http.bearer_token_file`).
Each `seal-keys` command now seals those too — the same sealed-secret
form, each file under its config name, any length (a PEM key, a token) —
and each loader takes the bare file or the sealed one: the TLS
configurations are assembled from bytes read through the daemon's
`readSecret` (`tls.X509KeyPair`, not `LoadX509KeyPair`), the tokens
trimmed after opening. `acp-bootstrap` gains `seal-keys -config` and the
`tee.sev_guest_device` / `tee.vtpm_seal_pcrs` fields its sealer needs.

A file two daemons read must be two files: the hardware kits give a
destination that shares a host with the authority its own copies of the
TLS pair and the token before the authority seals its own, and an
authority hands its destination bare copies taken before sealing. What
stays a file on a host: a `-key-file` given to `crosscloud-restore`, which
is the operator's input for one command, not a daemon's key.
