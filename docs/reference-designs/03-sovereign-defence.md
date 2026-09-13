# Reference design 03 — Sovereign government, defence research

| Profile        | Sovereign defence-research agency (NATO-equivalent member state)  |
|----------------|--------------------------------------------------------------------|
| Scope          | Single research programme; ~12 cleared researchers; ~8 classified models |
| Constraints    | Air-gapped facility; dual-key custody; no third-party root of trust |
| Primary TEE    | Intel SGX bare metal (custom-rolled, no PCCS over public internet) |
| AGPL fit       | ✅ — agency policy strongly prefers open-source provenance; AGPL is acceptable |
| Commercial license | 🟡 — opt-in only for support contracts; agency self-supports primary |

## Problem statement

The agency runs classified ML models that score sensor / signals
intelligence data. The models themselves are classified. Three
non-negotiable constraints:

1. **No internet trust path.** The facility is physically air-gapped.
   Public CAs (AWS PCA, Microsoft MAA, Intel SGX Root) cannot be
   used as live trust anchors. Anything that requires online
   verification fails the agency's accreditation.
2. **Dual-key custody.** Every release decision must be signed by two
   separate authorities (the technical lead and the security officer)
   or it MUST NOT execute. Single-actor compromise must not enable
   model release.
3. **Provenance from source to silicon.** The agency's accreditation
   board needs to verify, end-to-end, that the binary running on the
   SGX enclave was built from source code the agency has reviewed,
   on a build chain the agency controls.

## Architecture

### Topology

```
   ┌────────────────────────────────────────────────────────────────┐
   │  Air-gapped facility (no external network)                       │
   │                                                                   │
   │  ┌────────────────────────────────────────────────────────────┐  │
   │  │ Operator console (cleared) — hardened laptop                │  │
   │  │   ├── acpctl ops (custom binary, agency-built)              │  │
   │  │   ├── HSM smartcard reader (technical lead's signing key)    │  │
   │  │   └── HSM smartcard reader (security officer's co-sign)      │  │
   │  └────────────────────────────────────────────────────────────┘  │
   │                          │                                       │
   │                          ▼                                       │
   │  ┌────────────────────────────────────────────────────────────┐  │
   │  │ sagvd authority (Intel SGX bare metal)                       │  │
   │  │   ├── enclave .signed.so (built from agency-vetted source)   │  │
   │  │   ├── PCCS — locally-mirrored Intel collateral (USB transfer)│  │
   │  │   ├── Thales nShield Connect HSM (FIPS 140-2 L3)              │  │
   │  │   ├── audit chain → tamper-evident WORM disk array            │  │
   │  │   └── dual-key release-decision policy                        │  │
   │  └────────────────────────────────────────────────────────────┘  │
   │                          │                                       │
   │                          ▼                                       │
   │  ┌────────────────────────────────────────────────────────────┐  │
   │  │ acp-compute worker (Intel SGX bare metal)                    │  │
   │  │   ├── 4-frame return path to sagvd                           │  │
   │  │   └── classified inference model loaded from sealed storage  │  │
   │  └────────────────────────────────────────────────────────────┘  │
   │                                                                   │
   │  Source review pipeline (separate cleared workstations):          │
   │  ┌────────────────────────────────────────────────────────────┐  │
   │  │ Reviewer A laptop → reviewer B laptop → release-build host  │  │
   │  │ Reproducible build (verify-reproducible) → signed binary    │  │
   │  └────────────────────────────────────────────────────────────┘  │
   └────────────────────────────────────────────────────────────────┘
```

### Components

- **TEE backend**: `intel-sgx-dcap` only. No MAA mode (would require
  Microsoft endpoint, which is unreachable from the air gap).
- **Trust anchor**: Intel SGX Root certificate is shipped with the
  agency's review pipeline; updates arrive via signed-USB courier
  every 90 days. The Vault Genome verifier's
  `IntelSGXVerifierConfig.IntelRootPEM` is set from the
  agency-vetted PEM.
- **PCCS**: locally-installed inside the air gap; Intel collateral
  transferred from the air-gap-bridge via signed USB. Refresh
  cadence is on the agency's collateral-rotation calendar (typically
  monthly).
- **HSM dual-key custody**: Vault Genome's HSM-wrap layer
  (`IntelSGXSealer.hsmSlot`) is configured for an
  M-of-N policy where M=2, N=3 (three cleared HSM operators, any
  two co-signing). Single-actor compromise cannot release.
- **Audit chain**: bbolt-backed audit log lives on a tamper-evident
  WORM array. The agency's existing chain-of-custody process for
  classified material applies.
- **Reproducible builds**: agency's release-build host runs the
  Vault Genome `verify-reproducible` Make target on every build;
  byte-identical binaries are part of the accreditation evidence
  package.

## Threat model

The most stringent of the four reference designs. Drives from the
threat model table for Intel SGX bare metal in
[`docs/security/threat_model.md`](../security/threat_model.md), with
agency-specific additions:

| Threat | Mitigation |
|--------|------------|
| Cleared insider with single-actor authority | Dual-key release-decision policy at Vault Genome layer |
| Software supply-chain compromise during build | Reproducible builds + dual reviewer sign-off; agency-controlled build host |
| Side-channel against SGX | HSM-wrap defence-in-depth; SMT disabled in BIOS; PRMRR cache flushing enabled |
| Physical-access attacks (cold-boot, chip decap) | Facility physical security controls; HSM stays inside an SCIF-grade safe |
| Cryptanalysis of Ed25519 (post-quantum future) | Agency tracks NIST PQC selections; Vault Genome's frozen interface lets the algorithm rotate per ADR amendment ([ADR-0001](../adr/0001-frozen-producer-verifier-sealer-interface.md)) |
| Audit-chain tampering by privileged operator | bbolt append-only + WORM array + dual-signed release decisions on every entry |
| Loss of cleared-personnel HSM smart card | M-of-N quorum (2-of-3); a lost card fails to a 1-of-2 quorum that cannot release; replacement cards issued through the agency's PKI |

## Operational concerns

- **Self-support**: the agency runs Vault Genome on its own
  infrastructure with its own cleared engineers; commercial support
  is opt-in only.
- **Source-code review**: Vault Genome's AGPL licence + open-source
  conformance suite ([`pkg/teeconformance`](../../pkg/teeconformance))
  allow the agency to fork the repo into its classified network and
  perform its own line-by-line review. Material divergence from
  upstream gets contributed back where classification permits.
- **Release process**: every release-build runs `make verify-reproducible`,
  `make sbom`, and the doctrinal invariant tests. Build artifacts +
  SBOMs flow to the agency's accreditation evidence repository.
- **DR**: scenarios 1, 2, 3, 6, 7 from the
  [DR runbook](../operator/runbooks/disaster_recovery.md) apply
  directly. Scenario 4 (sagvd unreachable) is a single-region
  problem here; the agency's DR plan involves restoring from a
  signed-USB snapshot of the WORM audit array onto a hot-spare
  hardware platform.

## Pricing posture

AGPL self-deployment, $0 in licence fees:

- Agency uses the open-source AGPL build directly.
- Agency contributes patches back per their classification rules.
- Agency contracts a 1-week / quarter consulting engagement at
  professional-services rates ($25k/quarter) for major version
  upgrades, security advisories, and architecture review.

The accreditation board's evidence package (reproducible-build proof,
SBOM, threat model, conformance test pass logs) is generated by the
agency's build pipeline and reviewed inside the air gap. Vault Genome
Inc. provides upstream evidence (signed releases, transparency-log
entries) that the agency cross-references during their evaluation.
