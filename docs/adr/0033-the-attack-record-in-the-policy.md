# ADR 0033 — The attack record in the verifier's policy: TCB floors per chip, the platform's word, the guest's policy, the mitigation vector and the machine

- **Status:** Proposed (2026-10-22) — part one (the code: every field of the report read and on the record, the floors per chip variant, the predicates, the configuration, the identity) in the tree; part two (the runs on hardware: the chips on record admitted at the live floors, a floor raised above a chip refused on the record) follows, and with it Accepted and claim C46
- **Tags:** tee, sev-snp, attestation, policy, tcb, verifier
- **Extends:** ADR 0014 and 0018 (SEV-SNP on the Return Path), ADR 0024 (the vendor roots pinned in the binary), ADR 0025 (families, not clouds); ADR 0009's key binding and ADR 0021's GPU evaluation are unchanged

## Context

The SEV-SNP verifier of this tree checks what a report proves about
itself: the ECDSA P-384 signature under the VCEK, the VCEK's chain to
the AMD root pinned in the binary, the DEBUG bit clear, the VMPL, the
challenge in REPORT_DATA, the launch measurement and the host data
against the operator's lists, and one number — `min_reported_tcb`, the
packed TCB_VERSION compared as an integer. The rest of the report it did
not read: the current, committed and launch TCB versions, the platform's
PLATFORM_INFO, the guest policy beyond DEBUG, the mitigation vector, the
chip's family, model and stepping. A report from any genuine AMD chip at
the pinned measurement was admitted, whatever firmware it ran.

The attack record of the project library (Tier 7, 2026-09-30) names what
that leaves open. EntrySign (AMD-SB-3019), RMPocalypse (AMD-SB-3020) and
StackWarp (AMD-SB-3027) are fixed in SEV firmware and microcode whose
versions the report carries, and AMD prints the minimum version in each
bulletin; BadRAM (AMD-SB-3015) is confirmed by one bit of PLATFORM_INFO,
`ALIAS_CHECK_COMPLETE`; StackWarp's alternative to the microcode is a
guest policy without SMT; RMPocalypse's fix is readable from a bit of the
mitigation vector; and Contrast's advisory of 2026 showed the last gap —
a verifier that accepts any report that verifies, regardless of which
machine produced it, is open once one machine is broken, so the policy
must be able to name the machine. The record's conclusion was to write
per-product minimums into the verifier (D2) and make the machine's
identity a policy (D11).

What the floors are was read from AMD's live bulletins on 2026-10-22,
in the browser (the site refuses other clients), and kept in the library
with the archive's byte-exact copies. Two things that reading changed.
AMD-SB-3034 (FABRICKED), which the July captures had with TCB[SNP]
minimums of 0x1d (Milan) and 0x1c (Genoa), was revised on 2026-09-24 —
"Removed TCB values" — and now names platform firmware only; a table
taken from the July capture would have called the Azure Genoa chip of
this tree's own record below its floor, and the live bulletin does not.
The floors that stand are RMPocalypse's SNP firmware (0x1b on Milan and
Genoa, 0x04 on Turin, with the mitigation vector bit), StackWarp's
microcode per variant, and BadRAM's alias check. A floor is therefore a
dated fact: the table carries the day it was read, and refreshing it is
part of the work.

The chips on record show where the product stands. The GCP n2d Milan of
the key-binding probe (2026-09-13) reports SNP 0x1d and microcode 0xde —
on StackWarp's floor exactly — with the alias check complete, the
mitigation vector 0xb, SMT allowed by the guest policy and enabled on the
platform. The Azure NCC H100 v5 Genoa of the confidential-GPU record
(2026-10-22) reports SNP 0x1b and microcode 0x58, the alias check
complete, the mitigation vector 0x7, SMT disabled on the platform. Both
meet every live floor.

## Decision

1. **The verifier reads the whole report and puts it on the record.** The
   version, the guest SVN, the chip's family, model and stepping, the
   guest policy bit by bit, PLATFORM_INFO bit by bit, the current,
   reported, committed and launch TCB versions decomposed for the chip's
   product line (Table 5 for Milan and Genoa, Table 4 for Turin), the
   firmware version, both mitigation vectors and the chip id go into
   `AttestationDetail.sev_snp` with the floor the report was held to and
   where that floor came from — on every `TRUST_EVALUATED`,
   `CROSS_CLOUD_ATTESTATION_VERIFIED` and `KEY_RELEASE_*` record, in the
   session-opened log line's detail, and in `acpctl audit query`. The
   `gcp-sev-snp` verifier gains `VerifyDetailed`, which it lacked: a
   SEV-SNP peer's admission now carries the same detail as an Azure one.
2. **Floors per chip variant, component by component, over all four
   TCBs.** The variant is the CPUID family, model and stepping the report
   carries (Milan 00A00F11, Milan-X 00A00F12, Genoa 00A10F11, Genoa-X
   00A10F12, Bergamo/Siena 00AA0F02, Turin 00B00F21, Turin Dense
   00B10F10); the table in the binary names, per variant, the SNP firmware
   SVN and the microcode level AMD's bulletins print, the bulletins and
   their revision dates, and the day the table was read
   (`docs/compliance/sev-snp-tcb-floors.md`, held equal to the code by a
   test). A report whose current, reported, committed or launch TCB is
   below the floor in any component is refused, naming the component, the
   values and the bulletin. A chip the table does not name is refused
   until the operator sets `tcb_floor`: the product runs anywhere, but
   not silently on firmware nobody has looked at.
3. **The operator's floor replaces the table's; one below it is a
   decision on the record.** `tee.peer.sev_snp.tcb_floor` names the
   components; a floor below the bulletins' for any variant is refused at
   configuration unless `accept_below_bulletin` is set, and then
   `identity` and every record say which floor was in force and that it
   was the operator's. `min_reported_tcb` stays what it was, a raw floor
   on the packed value, for configurations that have it.
4. **The platform's word.** `ALIAS_CHECK_COMPLETE` is required where the
   bulletin names the product (the Milan and Genoa families; the alias
   check is the mitigation of BadRAM); `IOMMU_WRITE_SAFE` on request.
5. **The mitigation vector.** `CURRENT_MIT_VECTOR` must carry the bits
   the bulletins name for the variant (bit 1 on Milan and Genoa, bit 0 on
   Turin: RMPocalypse), unless the operator turns the check off.
6. **The guest's policy.** DEBUG clear, as before. A migration agent
   (`MIGRATE_MA`) is refused by default: a guest the host can move is not
   the guest the measurement describes. SMT disallowed, and
   `PAGE_SWAP_DISABLE`, on request — the microcode floor is StackWarp's
   other mitigation, and the chips on record run it.
7. **The machine.** `chip_ids` names the chips a peer or a destination
   may be; a report from any other chip is refused. Empty admits any chip
   the rest of the policy admits; the chip id is on the record either
   way.
8. **Where the policy lives.** `tee.peer.sev_snp` in `sagvd` and
   `acp-compute`; `sev_snp` on a `verifier_registry` destination in
   `sagvd` (the cross-cloud destination, the failover standby); the same
   predicates behind `azure-sev-snp` and `azure-cgpu`, whose chip is the
   same report. `identity` prints `sev_snp_policy`: the day the floors
   were read, the floors per variant, the operator's floor and the chips
   named. Every refusal is `attestation_denied` naming the predicate.

## Alternatives considered

- **`go-sev-guest`'s `validate` package.** It has the same checks
  (`MinimumTCB`, `MinimumLaunchTCB`, platform info, policy). The tree
  parses the report itself at the offsets of ABI 56860, pinned by the
  genuine reports on record (ADR 0014); a dependency for a table of seven
  rows would be the larger change. Rejected; the names of the checks
  follow its vocabulary where they coincide.
- **One number, as before.** `min_reported_tcb` compares the packed
  TCB_VERSION as an integer: the bytes' order is the layout's, not the
  components', and a higher bootloader byte would clear a lower SNP byte.
  Kept for compatibility, not extended.
- **Floors from the VCEK's extensions.** The same values, from the
  certificate AMD issued for the reported TCB; the report is what the
  chip signed for this nonce, and the four TCBs it carries are more than
  the certificate's one. Rejected.
- **A floor that follows the bulletin automatically.** A floor is a
  reviewed fact with a date; a bulletin that withdraws a value (SB-3034)
  must not lower a deployment's floor by itself, and one that raises a
  value must be read by someone. The table moves with the code, in a
  commit, with the library's capture beside it.

## Consequences

- A deployment on a chip below the live floors stops at the handshake,
  with the component and the bulletin on the record, until the operator
  sets a floor. The chips this tree has run on pass today; a Turin host
  has not been on record.
- The record of every admission grows by what the chip said about
  itself. A reader of the audit log can tell what firmware a decision was
  taken on; a bank's reviewer can hold it to the bulletin.
- The table ages. `identity` says when it was read; the library's live
  reading, the document and the code refresh together.
- The kits gain a refusal run: a floor raised above the chip, refused on
  the record (part two).

## Implementation notes

- **Part one (code, 2026-10-22):** `internal/shared/tee/sev_snp_policy.go`
  (the fields, the table, `SEVSNPPolicy`, `SEVSNPPolicyConfig`,
  `checkSEVSNPPolicy`, the summary); `gcp_sev_snp.go` (`SEVSNP` in the
  verifier's configuration, the check after the raw floor,
  `VerifyDetailed`); `azure_vtpm.go` and the two Azure verifiers (the
  check behind the chip's report, the detail on the verdict);
  `AttestationDetail.sev_snp`; `tee.peer.sev_snp` and the registry's
  `sev_snp` in `sagvd` and `acp-compute`; `sev_snp_policy` in both
  identities; `docs/compliance/sev-snp-tcb-floors.md` and the test that
  holds it to the code; the synthetic reports of the test suites stamped
  at the floors, the way the genuine ones are; the genuine Milan and
  Genoa reports on record admitted by the default policy in the tests.
- **Part two (hardware):** `keyrelease-e2e` reads the chip's SNP firmware
  SVN back from the release's own record and releases once more under a
  floor one above it, refused with the component on the record;
  `returnpath-e2e` records the policy from `identity` and the admitted
  peer's chip; runs on GCP Milan at the live floors and above them; the
  Azure Genoa record's values in the claim; C46; `banking.md` and
  `controls.md`.

## References

- The project library: `_LIBRARY/attestation/attacks.md` (Tier 7, §1,
  §9, the correction of 2026-10-22), `_LIBRARY/sources/attacks/bulletins/amd/live-20261022/`
  (the seven bulletins as read, the archive copy of AMD-SB-3034 of
  2026-10-03, `snp-tcb-minimums-live-20261022.DERIVED.tsv`, `SHA256SUMS.txt`).
- AMD, SEV Secure Nested Paging Firmware ABI Specification, 56860 Rev.
  1.59 (August 2026): Tables 4 and 5 (TCB_VERSION), Table 12 (guest
  policy), Table 28 (PLATFORM_INFO), the ATTESTATION_REPORT structure,
  §3.5 (mitigation vectors).
- AMD-SB-3015, -3019, -3020, -3027, -3034, -3039, -3045.
- The genuine reports: `scripts/hardware-test/gcp-sev-snp/keybind-evidence/20260913T222343Z/report-vaultgenome.bin`,
  `scripts/hardware-test/azure-cgpu/evidence/20261022T140119Z/snp-report.bin`.
- Edgeless Systems, Contrast advisory GHSA-hjgc-jc5v-fw7h (the machine's
  identity).
