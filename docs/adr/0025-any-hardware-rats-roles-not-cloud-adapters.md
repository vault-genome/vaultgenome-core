# ADR 0025 — Any hardware: the daemons are RATS roles, not cloud adapters

- **Status:** Accepted (2026-10-15); step 1a is in the tree, the rest follows in order
- **Tags:** tee, attestation, rats, cmw, ear, verifier, configfs-tsm, tpm, portability
- **Extends:** ADR 0001 (the frozen Producer/Verifier/Sealer surface), ADR 0014
  (real SEV-SNP), ADR 0018 (TDX), ADR 0019 (the Azure confidential GPU), ADR
  0022/0023 (sealing), ADR 0024 (pinned vendor roots)
- **Supersedes:** the naming of providers after clouds

## Context

A customer runs this software on the hardware it has. A bank's hardware is
not chosen by us: it may be AMD SEV-SNP or Intel TDX servers on premises,
Azure confidential VMs with or without a GPU, AWS Nitro Enclaves, Arm CCA
when it ships in servers, or servers with no memory-encrypting TEE at all
and only a TPM 2.0. Today the product names its attestation backends after
clouds — `gcp-sev-snp`, `gcp-tdx`, `azure-cgpu`, `aws-nitro`, `azure-sgx`,
`intel-sgx-dcap` (`internal/shared/tee/factory.go`) — and each pair of
producer and verifier is a hand-written adapter. Three of them run on real
hardware today (KNOWN_ISSUES #1); the rest are refused. A new customer on
new hardware would mean a new adapter, written by us, before the first
deployment. That does not scale to every hardware the world has, and it
misstates what the code does: nothing in `gcp-sev-snp` is Google's. The
report comes from the Linux kernel's own interface and verifies to AMD's
root; the same code ran on Azure's SEV-SNP reports in our captures.

What *is* specific is narrower than a cloud:

- **How evidence is obtained on the host.** On Linux, SEV-SNP, TDX and
  Arm CCA guests expose one interface, configfs-tsm
  (`/sys/kernel/config/tsm/report`, `Documentation/ABI/testing/configfs-tsm-report`,
  Linux ≥ 6.7): a caller writes its 64 bytes of challenge, reads the
  signed report, and reads the `provider` attribute to learn which
  family produced it. The three guest drivers register under their module
  names — `sev_guest`, `tdx_guest`, `arm_cca_guest`
  (`drivers/virt/coco/{sev-guest,tdx-guest,arm-cca-guest}/*.c` at v7.0,
  `tsm_report_ops.name = KBUILD_MODNAME`). Outside that interface sit the
  Azure paravisor (the SEV-SNP report comes from the vTPM's HCL report and
  is bound to a challenge by a TPM quote; ADR 0019), the Nitro Secure
  Module, SGX's DCAP quoting enclaves, and a plain TPM.
- **How evidence is appraised.** Every family verifies to its vendor's root
  with the vendor's collateral (AMD KDS, Intel PCS, NVIDIA NRAS/RIM, AWS's
  root, a TPM's endorsement chain), against reference values the operator
  chooses. That is exactly the Verifier role of the IETF RATS architecture
  (RFC 9334 §4.1, §7.4): a role, not a cloud, that takes Evidence and
  Endorsements and Reference Values (§8.1–8.3) and produces Attestation
  Results (§8.4) for a Relying Party. Our daemons are the Attester and the
  Relying Party of that architecture; the Verifier is a role they can
  carry themselves or delegate — the background-check model (RFC 9334
  §5.2), which is what the Return Path already is.
- **How a secret is sealed to the host.** A SEV-SNP guest has a derived
  key; TDX, CCA and most VMs and servers have a TPM 2.0; a plain server has
  a TPM 2.0 and nothing else. ADR 0022 already seals to a vTPM where the
  TEE gives no key.

The IETF has standardised the pieces that make a verifier hardware-neutral:
the Conceptual Message Wrapper (RFC 9999) names an evidence format on the
wire so a receiver can route it; the Entity Attestation Token (RFC 9711,
media types RFC 9782) and the EAT Attestation Result (draft-ietf-rats-ear,
with the trustworthiness vector of draft-ietf-rats-ar4si §2.3.5 and the
tiers of §3.2) carry a Verifier's verdict in one shape for any hardware;
CoRIM/CoMID (draft-ietf-rats-corim) and CoSERV (draft-ietf-rats-coserv)
carry reference values and endorsements. Project Veraison implements that
Verifier as a service with per-family schemes — today SEV-SNP (where our
2026-10 changes were merged), Arm CCA, PSA, TPM (enacttrust, parsec), RIoT,
NVIDIA — and returns a signed EAR. A bank can run it on its own premises
with its own endorsement store.

## Decision

1. **Providers name evidence formats and attestation families, not
   clouds.** The canonical names become `sev-snp`, `tdx`, `cca`, `nitro`,
   `sgx-dcap`, `azure-sev-snp` (the paravisor's HCL report bound by a vTPM
   quote, without a GPU), `azure-cgpu` (the same with NVIDIA's tokens),
   `tpm2` (a TPM 2.0 quote over PCRs with the event log — the floor every
   server has), and `simulated`. The old names stay as aliases for one
   release and are logged as such. Each name is one row of one table —
   producer, built-in verifier, sealer, CMW media type — and nothing else
   in the tree knows a cloud.
2. **One producer for the kernel's interface.** `tee.provider: "auto"`
   reads configfs-tsm's `provider` attribute and selects `sev-snp`, `tdx`
   or `cca` from `sev_guest`, `tdx_guest`, `arm_cca_guest`; `sagvd
   identity` and `acp-compute identity` print what was found. Platforms
   outside configfs-tsm keep an explicit name. A customer's host needs no
   provider decided by us: the kernel says what it is.
3. **The Verifier is a role with two implementations.** `tee.verifier.mode:
   "builtin"` (the default) is today's code: offline, pinned roots (ADR
   0024), vendor collateral from caches. `tee.verifier.mode: "rats"` sends
   the peer's Evidence, wrapped as a CMW record (RFC 9999 §3.1, JSON
   encoding on our JSON-framed wire) to a RATS Verifier over its API —
   Veraison's challenge-response API is the first — and appraises the
   returned EAR: its signature against the Verifier's configured key, the
   nonce, `ear.status`, and the trustworthiness vector against the policy
   the operator writes in the same terms (AR4SI tiers). The EAR goes on the
   audit record beside the decision, as the GPU tokens do today (ADR 0021).
   Every family the delegated Verifier supports is thereby supported here,
   with no change to our daemons; families it lacks (TDX, Nitro, SGX
   today) stay built-in until a scheme exists — which we can contribute.
4. **Evidence names its format on the wire.** The Return Path's
   `server_evidence` and `client_evidence` become CMW records whose type
   names the family; the verifier dispatches on the type, not on a
   configured expectation. A peer may still be *required* to be a family
   (the pin stays a policy), but the frame says what it carries. The old
   frame — bare bytes whose format the config implied — is refused, with
   both wire versions in the reason. *(Amended 2026-10-16, when the record
   went on the wire; the decision had said «read for one release». The
   first frame of the handshake names the wire version, so an old peer is
   told at once; reading its evidence form would not let it finish — it
   cannot read the new HELLO_SERVER — and a window would mean speaking 1.0
   in full for a release and deleting that code the next. The fleet
   deploys from one release (runbooks 05, 09); the refusal is the honest
   answer.)*
5. **Sealing by what the host has, in this order:** the TEE's own key
   (`sev-snp` derived key), else a TPM 2.0 — the existing vTPM sealer of
   ADR 0022 generalised to any TPM 2.0, discrete or virtual, with the PCR
   policy the operator selects — else refused. `keys.sealer: "auto"`
   follows that order and `identity` prints the choice.
6. **What a verdict says about weaker hardware is said, not hidden.** A
   `tpm2` host has no memory encryption and no attestation of a running
   workload beyond its measured boot; its trustworthiness tier is lower and
   the EAR/our verdict carries that; the policy decides whether that host
   may be a worker, a standby, or nothing. The product runs anywhere; it
   does not claim the same for every hardware.

## Consequences

- A customer runs the released binaries on the hardware it has; `auto`
  and a RATS Verifier of their own remove the last per-hardware work from
  us. The reference deployment (C27) and the drills stay valid: `sev-snp`
  is what `gcp-sev-snp` was.
- The verifier surface of ADR 0001 is unchanged: `Verifier.Verify(evidence,
  nonce) (Measurement, error)` gains an implementation (the delegated
  one), not a new shape. The measurement a delegated verifier returns is
  the EAR's measured components, in the same bytes the built-in one
  returns.
- A delegated Verifier is a dependency with an availability and a trust of
  its own: its key is pinned like a vendor root, its EAR is kept on the
  record, and `builtin` remains the mode a deployment can fall back to.
- The audit record of a decision carries one more artifact (the EAR); the
  ledger's readers (`acpctl audit query`) print it.
- Nothing here changes what is verified about SEV-SNP, TDX or the H100
  today; it changes where the code that verifies them may run and how the
  wire names what it carries.

## Plan

1. **Names and `auto`**, in two parts. *1a (done 2026-10-15):* the family
   names accepted on input beside the names this tree has used, which
   stay the canonical values — in identities, audit records and on the
   wire — until step 2 renames them with the wire; `tee.provider: "auto"`
   resolved from configfs-tsm when the configuration is loaded; proven on
   GCP `n2d` (`sev_guest`) and `c3` (`tdx_guest`); KNOWN_ISSUES #1 and
   the first-deployment guide say so. *1b (done 2026-10-15):* `tee.sealer` — `auto` (the TEE's
   own key where it has one, else the host's TPM 2.0, else the simulated
   key), `tee` (the TEE's own key only, refused where there is none) or
   `tpm2` (the host's TPM 2.0 whatever the TEE, the sealer of ADR 0022 on
   any TPM) — and every sealed file names the sealer it was made with, so
   a file sealed one way is not opened as another; proven on an n2d
   sealing with its vTPM (`tpm2`) beside the chip's derived key and on a
   c3 Trust Domain where the default, `auto`, chose the vTPM (runs
   `20261015T194325Z`, `20261015T194418Z` of the two Return Path kits); a
   thief with the sealed files and no TEE is refused before any key is
   read, on both.
2. **The CMW on the wire and the `rats` verifier**, in two parts. *2a
   (2026-10-16, wire 1.1):* every family's Evidence travels as a CMW
   record (RFC 9999 §3.1, the json-record inside our JSON frames) whose
   type is the family's media type; the configfs-tsm families send the
   TSM report ratsd defines — the kernel's outblob, the auxblob it shows
   beside it (on SEV-SNP the certificate table the host wrote, the VCEK
   among them; tdx_guest shows none), the provider's name — under
   `application/vnd.veraison.tsm-report+json`, the type Veraison's sevsnp
   scheme accepts; the other families send their bytes under a
   provisional `application/vnd.vault-genome.*` type until each has a
   registered one (a CMW collection for the composite azure-cgpu). A
   record of another family, or a TSM report of another provider, is
   refused by name before any verifier runs; the builtin verifiers read
   the outblob as before; each side's family is required in the handshake
   configuration (`auto` resolves before it). Proven on the loopback and
   integration suites and on the two Return Path kits (see CHANGELOG
   [Unreleased] for the run ids). *2b (2026-10-16, code and bench):*
   `tee.peer.verifier.mode: rats` — the Veraison challenge-response client
   (stdlib HTTP and JSON), the EAR verified under the Verifier's pinned
   key (ES256, stdlib) and judged by `accept`/`policy_id`/`submod`, the
   EAR on the `TRUST_EVALUATED` record. The pin is held by reading the
   measurement from the message this side posted, by its own parser: the
   EAR's annotated evidence is the scheme's own shape (for SEV-SNP a
   CoRIM whose CoMID is CBOR), and the bytes posted are the bytes
   appraised — the session nonce is the report's REPORT_DATA, which the
   scheme compares byte for byte. Proven on the bench: both daemons
   against the API double with the simulated family, the rogue
   contraindicated and the unreachable Verifier refused on the record
   (`test/integration/delegated_verifier_test.go`); and against a live
   Veraison with a real GCP SEV-SNP report — the bench's deployment,
   the report's REPORT_DATA as the session nonce, the EAR affirming
   under Veraison's published key, the pin read from the report (run
   `20261016T024628Z`, C30). Still to do: the Return Path kits on a chip
   with `rats` on both sides and the Verifier on a separate host — the
   bank's topology.
3. **`tpm2`** producer, verifier and sealer: a quote over the selected
   PCRs with the event log, verified through the TPM's endorsement
   certificate to the TPM vendor's root, appraised against a PCR policy —
   the floor for a server without a TEE.
4. **`azure-sev-snp`**: the azure-cgpu adapter without the GPU half; the
   kit of 2026-10-15 already proves the capture.
5. **Reference values as CoRIM** for the delegated mode; TDX and Nitro
   schemes contributed upstream so that the delegated mode covers them.

## Alternatives rejected

- **One adapter per customer's hardware, written on demand.** This is what
  the tree does today; it is the thing to stop.
- **A cloud attestation service as the only verifier** (Azure Attestation,
  Intel Trust Authority, NVIDIA's service): ties a bank to a vendor's
  service and the Internet; the product's offline, pinned verification is
  a reason customers choose it (ADR 0024). The delegated mode is a role
  the customer fills, not a vendor's endpoint.
- **A library operating system (Gramine or similar) to put the daemons
  inside SGX enclaves.** Large, a different trust model (the enclave's
  measurement is the LibOS's), and SGX is leaving the server line; `tpm2`
  and `sgx-dcap` as a worker's evidence cover what is left.

## Sources

RFC 9334 (RATS Architecture) §4.1, §5.2, §7.4, §8; RFC 9711 (EAT); RFC 9782
(EAT media types); RFC 9999 (RATS Conceptual Message Wrapper) §3, §9.4–9.5;
draft-ietf-rats-ear-04 §3.1; draft-ietf-rats-ar4si-10 §2.3.5, §3.2;
draft-ietf-rats-corim; draft-ietf-rats-coserv-07; Linux v7.0
`Documentation/ABI/testing/configfs-tsm-report` and
`drivers/virt/coco/{sev-guest,tdx-guest,arm-cca-guest}`; Project Veraison
`services` (schemes as of 2026-08-31), `apiclient`, `ear`; this tree's
`internal/shared/tee` and KNOWN_ISSUES #1.
