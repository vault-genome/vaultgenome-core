# ADR 0022 — The escrow key sealed to the guest's vTPM where the TEE gives no sealing key

- **Status:** Accepted (2026-09-16)
- **Tags:** tee, tdx, azure, vtpm, escrow, sealing
- **Amends:** ADR 0016 (the escrow key sealed to the release host), which
  was SEV-SNP only; ADR 0018 and ADR 0019, whose consequences said a TDX
  host and an Azure confidential GPU host hold no sealed escrow key.

## Context

ADR 0016 made the authority's escrow key inside `sagvd`'s process and
wrote it only sealed to the host's TEE: on SEV-SNP with a key the
firmware derives for the chip, the launch measurement and the guest
policy (`SNP_GET_DERIVED_KEY`). Intel TDX gives a Trust Domain no such
key, and neither does Azure's paravisor to a confidential GPU VM; so
since ADR 0018 and 0019 a TDX host and an Azure confidential GPU host
could be a worker or a destination but not a release authority, and
KNOWN_ISSUES #11 said so.

Both give the guest a virtual TPM. A TDX `c3` VM on GCP boots with one
(`/dev/tpm0`, a Google TPM 2.0 behind `MSFT0101`), and the azure-cgpu
producer already drives the Azure vTPM through tpm2-tools for its quote
(ADR 0019). A TPM's business is exactly this: to hold a secret that only
a machine in a known state can have back.

## Decision

`sagvd` seals the escrow key to the guest's vTPM on `gcp-tdx` and
`azure-cgpu` hosts (`internal/shared/tee/vtpm_sealer.go`, wired in
`cmd/sagvd/keystore.go`'s `TEESealer`).

1. **A fresh key per seal, held by the TPM.** `Seal` makes a random
   AES-256 key and hands it to the vTPM as a sealed object under the
   owner hierarchy's primary key (`tpm2_createprimary -C o -g sha256 -G
   ecc`) with a PCR policy of this boot (`tpm2_createpolicy --policy-pcr
   -l <selection>`; `tpm2_create -L <policy> -a fixedtpm|fixedparent|noda
   -i -`): usable under its policy only — no password ever opens it —
   pinned to this TPM and parent, and outside the dictionary-attack
   lockout so a failed policy on another boot cannot lock it. The key
   reaches `tpm2_create` on stdin and is zeroed once used; it is never a
   file. The plaintext is encrypted under that key with AES-256-GCM and
   the caller's AAD — for the escrow key, ADR 0016's AAD: the provider,
   the measurement and the key tag.
2. **The blob is self-describing.** `vault-genome/vtpm-sealed/v1`: the
   PCR selection, the sealed object's public and private parts, the
   ciphertext. The private part is encrypted by the TPM under its parent;
   nothing in the blob opens without the TPM.
3. **Unseal asks the TPM under the same policy.** `tpm2_createprimary`
   again (deterministic for the hierarchy's seed), `tpm2_load`,
   `tpm2_unseal -p pcr:<selection>`. On another boot — a changed kernel or
   firmware, another machine, a cleared owner hierarchy — the policy fails
   and the vTPM refuses; a blob whose selection is not the sealer's is
   refused before the TPM is asked; anything else touched fails the AEAD.
   Every refusal is Integrity-classified, as on SEV-SNP.
4. **The PCR selection is the operator's**, `tee.vtpm_seal_pcrs`, and by
   default the fifteen PCRs the azure-cgpu registry pin covers
   (`sha256:0-14`): the escrow key opens only on the boot the operator
   pinned. The same discipline as SEV-SNP's launch measurement: an image
   change re-issues the pin and re-provisions the key through the
   recovery ceremony (`acpctl escrow recover` into `sagvd
   escrow-provision -stdin`), which works unchanged on a vTPM host.
5. **No TPM library enters the build.** The tools are tpm2-tools, run as
   processes like the quote in ADR 0019; the dependency policy is
   untouched. Tests drive a fake TPM through the same process seam and
   pin the exact invocations and the refusals.

## Consequences

- **A TDX host and an Azure confidential GPU host can be the release
  authority**: the escrow key they hold is sealed to hardware they run on,
  under the boot the operator pinned. What ADR 0018 and 0019 said about a
  missing sealer no longer holds; KNOWN_ISSUES #11's scope shrinks to what
  is still a file (the signing seeds) and what is still in memory.
- **The vTPM is a different root than the TEE.** On SEV-SNP the sealing
  key is the chip's; here it is the vTPM's, a device the cloud provider
  virtualises inside the confidential VM's boundary (Google's for `c3`,
  Azure's paravisor's for NCC). The guest's attestation still comes from
  the TEE; the sealing rests on the vTPM's hierarchy seed staying with the
  VM and on the PCR policy. An operator who does not accept the
  provider's vTPM as a root has no sealed escrow key on these hosts.
- **A boot is a boot.** The default selection includes PCRs that a kernel
  update changes; after one, the key is re-provisioned from the recovery
  envelope, not silently re-derived. Operators who want fewer PCRs name
  them.
- **Proven on hardware** (`scripts/hardware-test/failover-tdx-authority`,
  run `20260916T200841Z`, VERIFIABLE-CLAIMS C23): on a GCP `c3` Trust Domain the
  escrow key was sealed to the vTPM (`{'tee': 'gcp-tdx', 'schema': 'vault-genome/vtpm-sealed/v1', 'pcrs': 'sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14', 'public_bytes': 80, 'private_bytes': 160, 'box_bytes': 60}`), opened once on the spot,
  re-sealed through the recovery ceremony, unsealed by `sagvd failover`
  at start, and the failover completed with RTO 20.27 s. The Azure
  confidential GPU host: the same, on an NCC H100 v5 (`scripts/hardware-test/azure-cgpu/evidence/20260916T204311Z-returnpath/`, key `11e87307c4f33f8c` sealed under the same fifteen PCRs and re-sealed through the ceremony).
