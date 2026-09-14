# Vault Genome — Competitive comparison matrix

| Last updated | 2026-05-06 |
|--------------|------------|
| Audience     | Buyers evaluating alternatives, sales enablement, investor due diligence |

This document compares Vault Genome against the systems most often
mentioned in customer conversations as "why aren't you using X
instead?" candidates. Each system is summarised by its design point,
target use-case, and the gap relative to Vault Genome's
TEE-agnostic AI-continuity premise.

It is a *technical* comparison written by a builder, not a feature
matrix written by marketing. Every claim is sourced; every "no"
in the table is honest about what we don't do.

## At-a-glance matrix

|                                  | **Vault Genome** | NVIDIA H100 CC | Apple Private Cloud Compute | Confidential Containers (CNCF) | Edgeless Marblerun |
|----------------------------------|:----------------:|:--------------:|:---------------------------:|:------------------------------:|:------------------:|
| TEE-agnostic abstraction         | 🟡 frozen interface; 1 sim + 4 HW stubs | ❌ NVIDIA-only | ❌ Apple-only               | 🟡 multi but coarse           | 🟡 SGX-centric    |
| Frozen interface (V1↔V2 swap)    | ✅                | ❌             | ❌                          | ❌                             | ❌                 |
| AI continuity / model recovery   | ✅ governance-first (recon backend is a placeholder) | ❌             | ❌                          | ❌                             | ❌                 |
| Hardware-rooted attestation      | 🟡 captured by side tooling, not yet in-product | ✅ NVIDIA only | ✅ Apple only               | ✅                             | ✅                 |
| Open conformance suite           | ✅ pkg/teeconformance | ❌         | ❌ closed                   | 🟡 partial                    | ❌                 |
| Open source                      | ✅ AGPL-3.0       | ❌ proprietary | ❌ proprietary              | ✅ Apache-2.0                 | 🟡 OSS + commercial |
| AI-specific (genome seal/restore)| 🟡 seal/restore real; neural recon is Phase-3 | ❌             | ❌                          | ❌                             | ❌                 |
| Single-binary multi-cloud deploy | ✅                | ❌             | ❌                          | 🟡                             | 🟡                 |
| Audit trail + compliance crosswalk | ✅              | ❌ buyer-built | ❌ Apple-internal           | ❌ buyer-built                 | 🟡                 |
| Buyer-runnable conformance       | ✅                | ❌             | ❌                          | 🟡                             | 🟡                 |

Legend: ✅ satisfies fully | 🟡 satisfies partially / with caveats | ❌ does not address

The remainder of this document explains each comparison row.

---

## NVIDIA H100 Confidential Computing

**What it is.** A hardware capability that runs CUDA workloads inside a
hypervisor-isolated, attested context on H100 GPUs. The host CPU and
GPU memory are encrypted; an attestation report binds workload identity
to NVIDIA-published roots of trust.

**Where it shines.** Single-vendor, single-platform: "I want this CUDA
workload to run privately on this GPU and have NVIDIA say so." For
inference-heavy AI workloads on NVIDIA H100s, it is the most-direct
path to confidential execution today.

**Where it does NOT compete with Vault Genome.**

   *  **Single-vendor lock-in.** H100 CC works on H100 only. A
      customer who buys one rack of H100s and another rack of AMD
      MI300X cannot use H100 CC across both — the abstraction simply
      isn't designed for it. Vault Genome's frozen interface is
      designed so the same application code can talk to AWS Nitro,
      Azure SGX, GCP SEV-SNP, Intel SGX bare metal, and (later) NVIDIA
      H100 via the same Producer / Verifier / Sealer surface. Today
      only the software simulator is functional; the four hardware
      adapters are Phase-2 scaffolding.
   *  **No model continuity primitives.** H100 CC is a runtime
      isolation tool. It does not address what happens when the
      enclave is destroyed, the model needs to be migrated to a new
      enclave, or a sealed checkpoint must be unsealed in a fresh
      attestation context. Vault Genome's `acpctl recover` plus
      vault envelope format are first-class for this.
   *  **No conformance suite.** Buyers cannot run a public test
      suite to verify their NVIDIA H100 setup is "doing the right
      thing." Vault Genome ships [pkg/teeconformance](../../pkg/teeconformance)
      with 12 sub-tests any operator can run.

**When a buyer should pick H100 CC over Vault Genome.** When the
deployment is *only* CUDA inference on NVIDIA H100s, has no
multi-vendor requirement, and does not require AI-continuity (the
job is single-shot inference, not multi-session continuity of a
LoRA-finetuned model).

**When the two are complementary.** A future Vault Genome `nvidia-h100-cc`
adapter (Phase 3+) would let the same Vault Genome control plane speak to
H100s alongside the other backends — one working simulator plus the four
hardware adapters once they are wired in Phase 2 — so the H100 becomes one
more TEE in the operator's portfolio, not a parallel system.

---

## Apple Private Cloud Compute (PCC)

**What it is.** Apple's confidential AI cloud announced at WWDC 2024.
Customer requests are routed to Apple-operated TEEs (custom Apple
silicon servers), processed without persistent storage of input or
output, and Apple publishes the binary that ran via reproducible
build + transparency log.

**Where it shines.** End-user-grade privacy at consumer scale.
"Apple, who already has my contacts and photos, runs my AI request
in a way that even Apple can't observe." The marketing positioning
is exemplary; the technical execution is sophisticated.

**Where it does NOT compete with Vault Genome.**

   *  **Apple-only.** Customers cannot run their own PCC. PCC is
      Apple-operated infrastructure that processes data Apple's
      first-party apps send. A bank, a hospital, a research lab,
      or a sovereign government cannot deploy PCC in their own
      datacentre because PCC requires Apple's silicon and Apple's
      operations.
   *  **Single-tenant compute, not continuity.** PCC handles
      individual user requests; it does not address long-running
      AI sessions, multi-stage validation, model lineage, or
      session-to-session state preservation. These are all
      first-class concerns in Vault Genome.
   *  **Proprietary attestation.** PCC's attestation chains to
      Apple's root of trust; there is no open verification path
      for a third party to validate a PCC attestation independently.
      Vault Genome's verification chains to publicly-rooted
      cryptographic primitives that any operator can audit.

**When a buyer should pick PCC over Vault Genome.** When the
"buyer" is a consumer using an Apple device and the workload is a
short-lived first-party Apple Intelligence request. PCC and Vault
Genome don't overlap — they are different products at different
layers.

**Architectural lessons taken from PCC.** Apple's reproducible-build +
transparency-log + binary-publication trio is the model Vault Genome
follows in `docs/security/supply_chain.md`. The threat-modelling
discipline of PCC's public materials is also reflected in
`docs/security/threat_model.md`.

---

## Confidential Containers (CNCF / Kata)

**What it is.** A CNCF sandbox project that wraps Kata Containers
with TEE attestation glue, allowing Kubernetes pods to run inside
SGX, TDX, SEV-SNP, or Nitro confidential VMs. An operator who runs
Kubernetes can use the same yaml manifests but with the pod's
runtime class set to `kata-confidential`.

**Where it shines.** Bringing existing containerised workloads into
a TEE without rewriting them. If a customer's monolith already runs
in Kubernetes pods, the migration cost to "run those pods in a TEE"
is closer to "edit a runtimeclass" than "rebuild your application."

**Where it does NOT compete with Vault Genome.**

   *  **No application-level abstraction.** Confidential Containers
      protects the *runtime* — the pod's memory and storage. It does
      not give the application a TEE-agnostic API to express
      attestation, sealing, or recovery. The application sees a
      regular Linux process; if it wants to attest itself to a
      remote party, it must invent its own protocol on top.
      Vault Genome's Producer / Verifier / Sealer is exactly that
      protocol, made portable across TEEs.
   *  **No AI continuity.** Confidential Containers is workload-
      neutral. Same gap as H100 CC for AI-continuity primitives
      (model recovery, session manifest, validation pipeline).
   *  **Heavier deployment surface.** Adopting Confidential
      Containers means adopting Kata, an SGX/TDX/SEV-capable
      kernel, the runtimeclass annotations, the attestation agents,
      and the Trustee verifier. Vault Genome ships static Go binaries
      and runs on bare systemd, Docker Compose, Kubernetes via
      Helm, or native packages — adopt the level of complexity
      that matches your environment.
   *  **No frozen public conformance.** CCC has documentation but
      no executable conformance suite a third party can use to
      validate their adapter is correct. Vault Genome ships one.

**When a buyer should pick Confidential Containers over Vault
Genome.** When the workload is a heterogeneous, multi-language,
already-containerised application portfolio that the customer wants
to make confidential without application changes, and the customer
doesn't care about cross-cloud TEE portability or AI-specific
primitives.

**When the two are complementary.** A Vault Genome deployment can
*itself* run inside Confidential Containers — the CCC layer protects
the runtime; the Vault Genome layer provides the application-level
TEE abstraction the workload speaks. There is no architectural
conflict.

---

## Edgeless Marblerun

**What it is.** An open-source SGX-centric framework from Edgeless
Systems that orchestrates clusters of SGX enclaves with attestation,
sealing, and a coordinator service. Used by some confidential
analytics deployments.

**Where it shines.** Production-grade SGX cluster orchestration.
For a customer who has settled on Intel SGX and needs multiple
enclaves to coordinate (a Kubernetes-of-SGX-enclaves), Marblerun
is the most mature option.

**Where it does NOT compete with Vault Genome.**

   *  **SGX-centric.** While Marblerun has been adding TDX support,
      it is fundamentally an Intel-Confidential-Computing-family
      tool. Vault Genome is built around the assumption that a
      single deployment may target SGX, SEV-SNP, Nitro, and TDX
      simultaneously, and that the abstraction must be agnostic to
      which one is in play.
   *  **Coordinator dependency.** Marblerun's architecture has a
      coordinator service (effectively an authority) that every
      enclave talks to. Vault Genome's `sagvd` plays a similar role
      but with simpler semantics (single-tenant Phase 1, multi-tenant
      Phase 2) and a frozen interface that lets you swap the
      authority for a different implementation without breaking
      worker-side code.
   *  **No AI-specific primitives.** Marblerun is workload-neutral.
      Same gap as the alternatives above.
   *  **License/business model.** Marblerun is dual-licensed
      (Apache + commercial); Vault Genome is dual-licensed
      (AGPL + commercial). Both are reasonable choices; the
      AGPL strong copyleft is an intentional moat — see
      [ADR-0003](../adr/0003-agpl-commercial-dual-licensing.md).

**When a buyer should pick Marblerun over Vault Genome.** When the
deployment is exclusively Intel SGX, the workload is generic
analytics or service compute (not AI continuity), and the buyer
wants Edgeless Systems' commercial support specifically.

**When the two are complementary.** A Vault Genome operator could
host their workers using Marblerun's SGX coordinator semantics and
have their authority be Vault Genome's `sagvd` — though we have not
seen a customer ask for this combination, and the operational
overhead of running both makes it unlikely outside niche scenarios.

---

## Adjacent that doesn't compete

Worth naming briefly for completeness:

   *  **AWS Nitro Enclaves SDK** — the underlying primitive Vault
      Genome's `aws-nitro` adapter will wrap once wired (Phase 2). Not
      a competitor; it's an input.
   *  **Microsoft Azure Confidential Ledger** — different problem
      (immutable distributed ledger backed by SGX). Adjacent but
      doesn't address AI continuity.
   *  **Google's Asylo** — SGX framework, last release 2022; effectively
      abandoned. Not a serious option for new deployments.
   *  **Anjuna Security** — TEE-as-a-service for general workloads;
      proprietary, single-vendor.
   *  **Fortanix EDP** — Rust SGX SDK. Useful as a building block;
      Vault Genome could in principle offer an EDP-based variant of
      the SGX adapter. (The current SGX adapter is Phase-2
      scaffolding, not yet shipping.)
   *  **Constellation (Edgeless Systems)** — Kubernetes inside
      Confidential VMs. Same general space as Confidential Containers;
      different emphasis on the orchestration layer.

---

## Why a buyer chooses Vault Genome

Three claims, each independently verifiable:

1. **One application code base, one frozen TEE interface.**
   The same Producer / Verifier / Sealer interface is the integration
   surface for AWS Nitro, Azure SGX, GCP SEV-SNP, Intel SGX bare metal,
   and a software simulator. Today only the **simulator backend is
   functional**; the four hardware adapters are Phase-2 scaffolding.
   What is real and verifiable now is that the interface is frozen
   ([ADR-0001](../adr/0001-frozen-producer-verifier-sealer-interface.md))
   and the conformance suite is public
   ([pkg/teeconformance](../../pkg/teeconformance)).

2. **AI-continuity primitives.** Genome seal/restore via `acpctl recover`
   (byte-preserving today; neural reconstruction is Phase-3),
   session-bound sealed material, a governed validation pipeline
   (operational is real; semantic is byte-equality and behavioral is
   byte-statistics today), and a tamper-evident audit log of every
   release decision. None of the alternatives ship these out of the box.

3. **Buyer-verifiable supply chain.** Reproducible builds verified
   on every CI run ([Makefile](../../Makefile)::verify-reproducible),
   SLSA L3 provenance via slsa-github-generator, cosign keyless
   signatures. A buyer's auditor can rebuild from source and confirm
   byte equivalence — see
   [docs/security/supply_chain.md](../security/supply_chain.md).

When the buyer's requirements are narrower than these three claims,
one of the alternatives may be a better fit. We would rather lose a
deal honestly than mislead a buyer whose problem we don't solve.
