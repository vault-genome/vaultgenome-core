# ADR 0018: Intel TDX on the Return Path

**Status:** Accepted — implemented (2026-09-16)
**Date:** 2026-09-16
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Builds on:** ADR 0014 (both daemons attest with the hardware they run on), ADR 0009 (SEV-SNP verification to the AMD root), ADR 0007 (variable-length measurements), ADR 0001 (frozen Producer/Verifier/Sealer), ADR 0016 (the escrow key sealed to the release host)
**Amends:** `sagvd`, `acp-compute` and `acp-bootstrap` configuration (`tee.provider: "gcp-tdx"`; `tee.peer.provider: "gcp-tdx"` with `pcs_url`, `pcs_cache_dir`, `acceptable_tcb_statuses`); `sagvd`'s cross-cloud verifier registry (`provider: "gcp-tdx"` entries); `sagvd identity` and `acp-compute identity` (a `tdx` block)

---

## Context

Every attested machine in this repository so far is an AMD SEV-SNP guest.
The confidential GPUs the program needs next are not: Google's `a3` machines
with confidential H100s, and Azure's `NCC` H100 machines, are Intel TDX
Trust Domains with the GPU in NVIDIA's confidential mode. A workload on one
of them attests with a TDX quote — a different structure, a different
signing chain and a different notion of "the measurement" — and this
repository refused it: the verifier registry and `acp-bootstrap` failed
closed on any family but SEV-SNP and the simulator (KNOWN_ISSUES #1), and
VERIFIABLE-CLAIMS said so ("We do not claim TDX, Nitro or SGX
verification").

Before a confidential GPU can be a destination or a worker, the CPU side of
it must be: a TDX producer for the daemons to attest with, a TDX verifier
for the other side to check them, proven on a real Trust Domain. That is
what this ADR adds; the GPU's own attestation is the step after it.

## Decision

### The measurement of a Trust Domain is MRTD and the four RTMRs together

TDX measures a guest in five registers: MRTD, the initial contents of the
Trust Domain (the virtual firmware), and RTMR0..3, extended at boot with the
firmware's configuration, the kernel, the initrd and the command line.
The producer reports as its measurement the SHA-384 of the five
concatenated (`MRTD ‖ RTMR0 ‖ RTMR1 ‖ RTMR2 ‖ RTMR3`) — 48 bytes, the
length SEV-SNP's launch measurement already has (ADR 0007), one value that
names the firmware and the whole boot chain. A guest with the same firmware
and a different kernel has a different measurement; that is the point of a
pin. `sagvd identity` and `acp-compute identity` print the five registers
beside the measurement so an operator can see what a pin is made of and
recompute it.

### The producer

`tee.provider: "gcp-tdx"` asks the kernel's configfs-tsm (provider
`tdx_guest`) for a quote with `SHA-256(nonce) ‖ 32 zero bytes` in
REPORTDATA — the same binding the SEV-SNP producer uses for REPORT_DATA, so
the frozen handshake (rp-wire-v1.0) is unchanged. The producer reads MRTD
and the RTMRs from its first quote and refuses to serve a quote in which
they differ: the workload it speaks for cannot change underneath it.

### The verifier, in the order it checks

A TDX quote (version 4, ECDSA-P256 attestation key) is signed by a Quoting
Enclave on the host under an attestation key the platform's PCK certificate
certifies; the PCK certificate chains to the Intel SGX Root CA. The
verifier, offline except for Intel's two documents:

1. reads the quote by its layout and refuses anything but version 4, an
   ECDSA-P256 attestation key, TEE type TDX and a PCK-chain certification;
2. chains the PCK certificate chain carried in the quote to the **pinned
   Intel SGX Root CA** (the certificate is in the binary; an override is a
   configuration for a test, not a trust decision);
3. checks the attestation key's signature over the header and the TD
   report, the PCK leaf's signature over the QE report, and that the QE
   report's REPORTDATA names the attestation key (`SHA-256(key ‖ QE
   authentication data)`) — the binding without which a valid key could
   sign for a quote it did not make;
4. reads the PCK certificate's SGX extension: the platform family
   (FMSPC), PCE id, the CPU SVNs and PCE SVN the certificate was issued
   for;
5. fetches **TCB info** for that FMSPC and the **QE identity** from Intel
   PCS (`https://api.trustedservices.intel.com`, or `pcs_url` for a mirror
   or a PCCS), each with the TCB signing chain from the response header,
   and verifies the ECDSA-P256 signature over the exact bytes of the
   document under that chain, chained to the pinned root, **before reading
   a byte of it**; a document past its `nextUpdate` is not used;
6. evaluates the platform against the TCB levels Intel rated — the highest
   level whose component SVNs, PCE SVN and TDX-module SVNs the platform
   meets gives the platform's status — and the TDX module against its
   identity (`TDX_nn` by TEE_TCB_SVN), and the QE against its identity
   (MRSIGNER, ISVPRODID, attributes and MISCSELECT under Intel's masks, ISV
   SVN levels);
7. requires all three statuses — platform, TDX module, QE — to be in the
   accepted set: `UpToDate` alone by default; an operator may list
   `SWHardeningNeeded`, `ConfigurationNeeded` or both; `OutOfDate`,
   `OutOfDateConfigurationNeeded` and `Revoked` are never accepted and are
   refused in the configuration;
8. refuses a TD whose attributes allow DEBUG (the host can read a debug
   TD's memory);
9. requires REPORTDATA to bind the challenger's nonce;
10. computes the measurement from MRTD and the RTMRs and requires it to be
    a pinned one.

Refusals name the step. A verifier that cannot reach Intel and has no
usable cached document fails closed, as the SEV-SNP verifier does without
AMD KDS; `pcs_cache_dir` keeps the two documents between runs, each checked
like a fresh one on every use, so a burst of handshakes asks Intel once.

### No sealer

TDX gives a guest no sealing key of its own; a sealed escrow key (ADR 0016)
needs one. The TDX adapter has a Producer and a Verifier and no Sealer of
the TEE's own; the plaintext key is refused on any hardware TEE. *Amended
2026-09-16:* sealing through the guest's vTPM is wired (ADR 0022) — the
escrow key is held by the vTPM under a policy of this boot's PCRs — and an
authority on a TDX host holds its key that way, proven on hardware
(`scripts/hardware-test/failover-tdx-authority`).

### Wiring

`sagvd`, `acp-compute` and `acp-bootstrap` take `tee.provider: "gcp-tdx"`
and a peer of `provider: "gcp-tdx"` pinned by its 48-byte measurement
(`measurement_path`), with `pcs_url`, `pcs_cache_dir` and
`acceptable_tcb_statuses` where a SEV-SNP peer has `amd_cert_chain_path`,
`vcek_cache_dir` and `min_reported_tcb`; a TDX pin with AMD fields, or a
SEV-SNP pin with PCS fields, is refused at start. `sagvd`'s cross-cloud
verifier registry takes `provider: "gcp-tdx"` entries with the same three
fields, so a TDX destination can be allow-listed for a key release. The
frozen interfaces (ADR 0001) are untouched: the adapter is one more
`Producer` and one more `Verifier` behind the factory.

### Proven on a Trust Domain

`scripts/hardware-test/gcp-tdx/capture/` boots a `c3-standard-4` Confidential
VM with Intel TDX, takes two quotes with caller nonces through configfs-tsm
and fetches the Intel PCS documents for the quote; the capture
`evidence/20260916T031937Z/` is what every verifier test runs against,
offline — the genuine quote verifies, and the same quote with another root,
a flipped DEBUG bit, a wrong nonce, an edited TCB level or a stale cache
and no network does not. `scripts/hardware-test/gcp-tdx/returnpath-e2e/`
runs the shipping `sagvd` and `acp-compute` on one Trust Domain, both
attesting with TDX quotes and each pinning the other's measurement, with
the real `vg_genome` door: a gate job goes over the Return Path and comes
back with a signed verdict, the audit log verifies, a worker whose Evidence
is not the pinned identity is refused and recorded. Its README carries the
measured run.

## Consequences

- **The pin names the boot chain.** A kernel or initrd update changes RTMR1
  or RTMR2, and with them the measurement; the peer's pin has to be
  re-issued from `identity` after every image change. That is the same
  discipline SEV-SNP's launch measurement imposes, extended to what TDX
  measures.
- **Two roots of trust, both pinned in the binary.** AMD's ARK for SEV-SNP,
  Intel's SGX Root CA for TDX. An operator who needs another root has a
  build to make, not a field to edit.
- **Intel is on the path at verification time.** TCB info and QE identity
  come from Intel PCS and expire; the cache directory makes the dependency
  a monthly one, and an unreachable PCS with an expired cache is a refusal,
  not an admission. A PCCS mirror is `pcs_url`.
- **The TCB policy is the operator's, bounded.** Google's platform in the
  captured evidence rated `UpToDate`; a platform Intel rates as needing
  hardening or configuration is admitted only if the operator's
  configuration says so, and a platform Intel rates out of date or revoked
  is never admitted.
- **A TDX authority holds no escrow key** until a sealer exists for it; a
  TDX host is a worker or a destination today, and an authority for gate
  jobs. As a destination it has taken a key release on hardware
  (2026-09-16, `scripts/hardware-test/failover-tdx`): the standby of a
  failover from a SEV-SNP primary, under a policy pinning its
  measurement, its quote verified by the authority to Intel's root with
  Intel's TCB word, the restored genome gated on its CPUs.
- **Confidential GPUs are now one step away, not two.** The CPU side of an
  `a3` or `NCC` machine attests and verifies with this adapter; what
  remains is the GPU's own attestation (NVIDIA's confidential-compute
  report bound to the TD) and a quota for the machines.
