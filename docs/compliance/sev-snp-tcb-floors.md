# The SEV-SNP TCB floors the verifier holds a chip to

Read from AMD's live security bulletins on 2026-10-22 (the day `sevBulletinsReadOn`
in `internal/shared/tee/sev_snp_policy.go` names); the project library holds each
page as read that day, its SHA-256, and the Internet Archive's byte-exact copy
(`_LIBRARY/sources/attacks/bulletins/amd/live-20261022/`, `SHA256SUMS.txt`;
AMD-SB-3034 captured 2026-10-03, after its revision). `TestSEVSNPFloorsMatchTheDocument`
holds this table and the code's table equal, row for row, and the date with it.

A chip is identified by the CPUID family, model and stepping its report carries
(a version-3 report or later; ADR 0033). The verifier holds every one of the four
TCB versions of the report — current, reported, committed, launch — to the floor,
component by component, and refuses a report from a chip this table does not name
until the operator sets `tee.peer.sev_snp.tcb_floor`.

| Variant | CPUID (family/model/stepping) | KDS product | TCB[SNP] ≥ | TCB[MICROCODE] ≥ | CURRENT_MIT_VECTOR bits | Alias check | Sources |
|---|---|---|---|---|---|---|---|
| Milan | 0x19/0x01/0x01 | Milan | 0x1b | 0xde | 0x2 | yes | AMD-SB-3020 (SNP, bit 1; rev. 2026-02-23), AMD-SB-3027 (microcode; rev. 2026-02-27), AMD-SB-3015 (ALIAS_CHECK_COMPLETE; 2024-12-10) |
| Milan-X | 0x19/0x01/0x02 | Milan | 0x1b | 0x47 | 0x2 | yes | AMD-SB-3020, AMD-SB-3027, AMD-SB-3015 |
| Genoa | 0x19/0x11/0x01 | Genoa | 0x1b | 0x56 | 0x2 | yes | AMD-SB-3020 (SNP, bit 1), AMD-SB-3027 (microcode), AMD-SB-3015 |
| Genoa-X | 0x19/0x11/0x02 | Genoa | 0x1b | 0x51 | 0x2 | yes | AMD-SB-3020, AMD-SB-3027, AMD-SB-3015 |
| Bergamo/Siena | 0x19/0xa0/0x02 | Genoa | 0x1b | 0x1b | 0x2 | yes | AMD-SB-3020, AMD-SB-3027, AMD-SB-3015 |
| Turin | 0x1a/0x02/0x01 | Turin | 0x04 | 0x51 | 0x1 | no | AMD-SB-3020 (SNP, bit 0), AMD-SB-3027 (microcode) |
| Turin Dense | 0x1a/0x10/0x00 | Turin | 0x04 | 0x4e | 0x1 | no | AMD-SB-3020, AMD-SB-3027 |

What the floors are. TCB[SNP] is the security version of the SNP firmware
(the `snp` component of TCB_VERSION; AMD's bulletins print it as "SPL"), TCB[MICROCODE]
the patch level of the cores. AMD-SB-3020 (RMPocalypse, CVE-2025-0033) names the SEV
firmware that carries the fix and the bit of the mitigation vector a guest can read it
from; AMD-SB-3027 (StackWarp, CVE-2025-29943) names the microcode, as the alternative
to running without SMT; AMD-SB-3015 (BadRAM, CVE-2024-21944) names the
`ALIAS_CHECK_COMPLETE` bit of PLATFORM_INFO. AMD-SB-3019 (EntrySign) printed lower SNP
floors (Milan 0x18, Genoa 0x17), which these exceed. AMD-SB-3034 (FABRICKED,
CVE-2025-54510) printed Milan 0x1d and Genoa 0x1c until its revision of 2026-09-24
removed the TCB values and left a platform-firmware mitigation only; those values are
not floors here. AMD-SB-3039 and AMD-SB-3045 name platform firmware only.

What the chips on record show (`internal/shared/tee/sev_snp_policy_test.go`,
`TestSEVSNPPolicy_GenuineReportsMeetTheLiveFloors`): a GCP n2d Milan of 2026-09-13
reports SNP 0x1d, microcode 0xde — on the StackWarp floor exactly — with the alias
check complete and mitigation vector 0xb; the Azure NCC H100 v5 Genoa of 2026-10-22
reports SNP 0x1b, microcode 0x58, the alias check complete and mitigation vector 0x7.
Both pass the default policy, as did the two Milan hosts of the kits' runs of 2026-10-22
(SNP 0x1d, microcode 0xde, the alias check complete, mitigation vector 0xb; C46), one of
which then refused a release under a floor of 0x1e. No Turin chip has been on record.

How to refresh. Read the live bulletins (the site refuses non-browser fetches; the
library's `wayback_latest_fetch.py` takes the archive's byte-exact copy), save them to
the library with their hashes, then change this table, the table in
`sev_snp_policy.go` and `sevBulletinsReadOn` in one commit; the test refuses a
mismatch. A value a bulletin withdraws lowers no floor by itself — the operator decides,
with `tcb_floor` and `accept_below_bulletin` on the record.
