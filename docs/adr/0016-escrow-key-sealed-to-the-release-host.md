# ADR 0016: The Escrow Key Is Sealed to the Release Host's TEE

**Status:** Accepted — implemented (2026-09-16)
**Date:** 2026-09-16
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Builds on:** ADR 0009 (X25519 KEM), ADR 0011 (key escrow), ADR 0014 (daemons on real SEV-SNP), ADR 0007 (measurement as the chip reports it)
**Amends:** `sagvd` configuration (`key_escrow_path` now names a sealed key; `tee.sev_guest_device`); `sagvd identity` (`key_escrow_storage`); the SEV-SNP sealer in `internal/shared/tee`; `acpctl escrow` (`recovery-keygen`, `recover`)

---

## Context

With key escrow (ADR 0011) a sealing machine keeps no genome key: each is
encapsulated to the release authority's X25519 escrow key the moment it is
sealed, and the primary of a failover (ADR 0012) holds nothing that opens
what it sealed. That moved the secret to one place — and left it there as a
file. The authority's escrow private key was 32 raw bytes on the release
host's disk (`crosscloud.key_escrow_path`, mode 0600), read whenever an
envelope was opened. A disk image, a snapshot, a backup, a host with root:
any of them held the key that opens every escrowed genome. KNOWN_ISSUES #11
said so.

The release host was meanwhile an AMD SEV-SNP guest attesting with its chip
(ADR 0014). SEV-SNP has a sealing primitive the platform did not use: the
guest can ask the firmware, through `/dev/sev-guest`, for a key derived
from the chip's root and the guest's own launch measurement and policy
(`SNP_GET_DERIVED_KEY`). The hypervisor forwards the request and cannot
read it; another chip, another VM image, or a debuggable guest derives
another key. The adapter had a `GCPSEVSealer` whose derived-key request was
a stub.

## Decision

1. **The SEV-SNP sealer is real.** `GCPSEVSealer` asks the firmware for the
   derived key — root VCEK, guest fields `MEASUREMENT` and `GUEST_POLICY`,
   VMPL 0; neither the guest SVN nor the TCB version is mixed in, so a
   firmware update on the same chip still opens what was sealed before it —
   expands it with a label of its own (HKDF-SHA256, the label, the
   measurement, the policy) into an AES-256-GCM key, and seals with a fresh
   nonce and the caller's AAD. The key is derived for every call and zeroed
   after; nothing is stored. The ioctl is pure Go (`syscall`, a pinned
   request and response), Linux only. The simulated sealer keeps the same
   shape and stays what it was: a key derived from the simulated
   measurement, for development and tests.

2. **The escrow key is born sealed.** `sagvd escrow-provision` makes the
   X25519 key inside the authority's own process, seals it to the host's
   TEE, proves the seal opens there, and only then writes: the sealed file
   (`vault-genome/sealed-escrow-key/v1`: the TEE kind, the measurement it
   was sealed at, the key's tag, the public half in PEM, and the sealed
   bytes — every clear field bound into the seal's AAD; mode 0600, never
   overwritten) and the public PEM. The private key is never written in the
   clear. `key_escrow_path` names that file; `sagvd` unseals it in memory at
   start and holds it there. On a hardware TEE a plaintext key at
   `key_escrow_path` is refused at start, with the command that fixes it;
   under `tee.insecure_simulation` a raw key (`acpctl escrow keygen`) is
   still accepted, and the log says `PLAINTEXT ESCROW KEY`. `sagvd
   identity` reads the public half from the file without unsealing anything
   and prints `key_escrow_storage`: `sealed:gcp-sev-snp`,
   `sealed:simulated`, or `plaintext`.

3. **A sealed key survives its chip through the operator, not through a
   copy.** A key sealed to a chip dies with it — a restart that lands on
   another host, a hardware failure, a new image — and every genome
   escrowed to it would be unopenable until the sentinels sealed a new
   generation to a new key. So `escrow-provision -recovery-to` also wraps
   the key to the operator's recovery public key (`acpctl escrow
   recovery-keygen`, an X25519 key whose private half lives off the release
   host) with the X25519 KEM of ADR 0009, AAD-bound to both keys' tags:
   `vault-genome/escrow-recovery/v1`. The ceremony on a new host is a pipe,
   so the new host's disk never holds the key in the clear:

   ```bash
   acpctl escrow recover --in escrow.recovery --key recovery.seed \
     | ssh release-host sagvd escrow-provision -config sagvd.json -out escrow.sealed -pub escrow.pem -stdin
   ```

   The same key, the same tag, sealed to the new chip. Sentinels and sealers
   pinned to the public half need no change.

4. **What is not sealed.** The authority's signing seed, audit seed and
   session-sealing key are still files (KNOWN_ISSUES #1's scope). They sign
   and seal on the record; the escrow key is the one that opens every
   genome, and it went first.

## Consequences

- A disk image of the release host no longer holds the escrow key. Opening
  an escrowed genome needs the same code, on the same chip, at the same
  measurement and policy — or the operator's recovery key.
- A restart on another chip fails closed: `sagvd` refuses to start, names
  the measurement it was sealed at and the one it runs at, and points to
  the recovery envelope. Cloud instances that stop and start land on
  another host as a matter of course; the runbook says to keep the recovery
  key where a restart can reach it. Automatic re-provisioning is not
  offered: a key that reseals itself unattended is a key an intruder can
  ask for.
- Sealing binds the launch measurement, so a new VM image (a kernel update,
  a different vCPU count on SEV-SNP) needs the ceremony too. That is the
  property, not a bug: the key opens for the code the operator measured.
- The derived key's request excludes the TCB version and guest SVN on
  purpose. A firmware update does not lock the operator out; a debuggable
  guest (policy bit 19) derives a different key and reads nothing.
- The escrow key sits in the process's memory for its lifetime, as it must
  to open envelopes; Go's `ecdh` keeps its own copy. Zeroization on exit
  covers the keystore, not the `ecdh` object. Memory of a SEV-SNP guest is
  encrypted; that is the host's protection, and the reason the host is a
  confidential VM.
- The simulated sealer is as weak as it always was (a key recoverable from
  the measurement). It exists so the file format, the ceremony and the
  refusals are exercised in every test run without hardware.

## Evidence

- `internal/shared/tee/gcp_sev_snp_seal_test.go`: round trip, AAD, tamper,
  a different chip, image or policy opens nothing, the request's field
  selection, the firmware's status word, the ioctl number recomputed.
- `internal/genome/escrow/sealed_test.go`: the sealed file opens only where
  it was sealed; every clear field is bound; the recovery envelope opens
  only with its key and only as the key it names.
- `cmd/sagvd/escrow_key_test.go`: provisioning, identity, refusal of a
  plaintext key on hardware, a key sealed elsewhere refused with its
  reason, the recovery ceremony through stdin.
- `test/integration/failover_test.go`: every failover drill runs with the
  authority's escrow key provisioned sealed.
- On hardware: the failover drill kit (`scripts/hardware-test/gcp-failover`)
  provisions the authority's key sealed to the standby's SEV-SNP chip,
  performs the recovery ceremony on it, and opens escrowed genome keys with
  the unsealed key — see the kit's README for the run.

## Alternatives considered

- **Keep the key in a cloud KMS with an attestation policy.** Ties the
  authority to one provider's KMS and to that provider's attestation
  verifier; the platform's own verifier and audit log would no longer be
  the last word. Not excluded for later as an additional custody, never as
  the only one.
- **Shamir shares held by several operators.** Better custody than one
  recovery key; more code to get exactly right, and a ceremony most
  operators would not run. The recovery envelope reuses a KEM already on
  the record (ADR 0009). Threshold custody can wrap the same envelope
  later.
- **Re-derive the key from the chip instead of generating it.** The escrow
  key would then be the chip's, unrecoverable anywhere else and changing
  with every image. The sentinels pin a public key that must outlive a
  host.
- **Seal the whole keystore.** The right end state; the escrow key is the
  one whose loss opens genomes, and shipping it alone kept the change
  reviewable.
