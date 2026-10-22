// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// sevRawReport builds a version-5 report with the fields the policy reads
// at their offsets; the signature is not set (the policy runs after the
// signature check).
type sevRawReport struct {
	fam, model, step uint8
	policy           uint64
	platformInfo     uint64
	tcb              uint64 // written to CURRENT, REPORTED, COMMITTED and LAUNCH unless the per-field values are set
	launchTCB        uint64
	mitVector        uint64
	chip             byte
}

func (s sevRawReport) bytes() []byte {
	raw := make([]byte, sevReportLen)
	binary.LittleEndian.PutUint32(raw[sevOffVersion:], 5)
	binary.LittleEndian.PutUint64(raw[sevOffPolicy:], s.policy)
	binary.LittleEndian.PutUint64(raw[sevOffPlatformInfo:], s.platformInfo)
	binary.LittleEndian.PutUint32(raw[sevOffSigAlgo:], 1)
	for i := range raw[sevOffMeasurement : sevOffMeasurement+48] {
		raw[sevOffMeasurement+i] = 0xAB
	}
	raw[sevOffCPUIDFam], raw[sevOffCPUIDFam+1], raw[sevOffCPUIDFam+2] = s.fam, s.model, s.step
	for i := range raw[sevOffChipID : sevOffChipID+64] {
		raw[sevOffChipID+i] = s.chip
	}
	launch := s.tcb
	if s.launchTCB != 0 {
		launch = s.launchTCB
	}
	binary.LittleEndian.PutUint64(raw[sevOffCurrentTCB:], s.tcb)
	binary.LittleEndian.PutUint64(raw[sevOffReportedTCB:], s.tcb)
	binary.LittleEndian.PutUint64(raw[sevOffCommittedTCB:], s.tcb)
	binary.LittleEndian.PutUint64(raw[sevOffLaunchTCB:], launch)
	binary.LittleEndian.PutUint64(raw[sevOffLaunchMitVec:], s.mitVector)
	binary.LittleEndian.PutUint64(raw[sevOffCurrentMitVec:], s.mitVector)
	raw[sevOffCurrentBuild], raw[sevOffCurrentBuild+1], raw[sevOffCurrentBuild+2] = 1, 58, 1
	raw[sevOffCommittedBuild], raw[sevOffCommittedBuild+1], raw[sevOffCommittedBuild+2] = 1, 58, 1
	return raw
}

// milanGenoaTCB packs a Milan/Genoa TCB_VERSION (Table 5).
func milanGenoaTCB(bl, tee, snp, ucode uint8) uint64 {
	var b [8]byte
	b[0], b[1], b[6], b[7] = bl, tee, snp, ucode
	return binary.LittleEndian.Uint64(b[:])
}

// turinTCB packs a Turin TCB_VERSION (Table 4): FMC, BOOT_LOADER, TEE, SNP, MICROCODE.
func turinTCB(fmc, bl, tee, snp, ucode uint8) uint64 {
	var b [8]byte
	b[0], b[1], b[2], b[3], b[7] = fmc, bl, tee, snp, ucode
	return binary.LittleEndian.Uint64(b[:])
}

// milanAtFloor is a GCP Milan report as the record of 2026-09-13 shows one:
// SMT allowed, ECC, the alias check complete, TCB 4/0/0x1d/0xde, mitigation vector 0xb.
func milanAtFloor() sevRawReport {
	return sevRawReport{fam: 0x19, model: 0x01, step: 0x01, policy: 0x30000, platformInfo: 0x25,
		tcb: milanGenoaTCB(0x04, 0x00, 0x1D, 0xDE), mitVector: 0xb, chip: 0x11}
}

func parseRaw(t *testing.T, raw []byte) *sevSNPReport {
	t.Helper()
	r, err := realParseSEVSNPReport(raw)
	require.NoError(t, err)
	return r
}

func denied(t *testing.T, err error, want ...string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeAttestationDenied, shared_errors.CodeOf(err), err.Error())
	for _, w := range want {
		require.Contains(t, err.Error(), w)
	}
}

func TestSEVSNPPolicy_DefaultsAdmitTheMilanOfTheRecord(t *testing.T) {
	d, err := checkSEVSNPPolicy(parseRaw(t, milanAtFloor().bytes()), SEVSNPPolicy{}, "sev-snp")
	require.NoError(t, err)
	require.Equal(t, "Milan", d.Product)
	require.Equal(t, "Milan", d.Variant)
	require.Equal(t, SEVTCB{BootLoader: 4, SNP: 0x1D, Microcode: 0xDE}, d.TCB.Reported)
	require.Equal(t, SEVTCB{BootLoader: 4, SNP: 0x1D, Microcode: 0xDE}, d.TCB.Launch)
	require.True(t, d.PlatformInfo.AliasCheckComplete)
	require.True(t, d.PlatformInfo.SMTEn)
	require.True(t, d.GuestPolicy.SMT)
	require.False(t, d.GuestPolicy.MigrateMA)
	require.Equal(t, "0xb", d.MitigationVector.Current)
	require.Equal(t, "1.58.1", d.Firmware.Current)
	require.Equal(t, SEVTCBFloor{SNP: 0x1B, Microcode: 0xDE}, d.Floor)
	require.Contains(t, d.FloorSource, "AMD-SB-3020")
	require.Contains(t, d.FloorSource, sevBulletinsReadOn)
}

func TestSEVSNPPolicy_TCBFloorRefusals(t *testing.T) {
	t.Run("snp below the bulletin floor", func(t *testing.T) {
		r := milanAtFloor()
		r.tcb = milanGenoaTCB(0x04, 0x00, 0x1A, 0xDE)
		_, err := checkSEVSNPPolicy(parseRaw(t, r.bytes()), SEVSNPPolicy{}, "sev-snp")
		denied(t, err, "TCB floor", "reported TCB snp 0x1a below 0x1b", "AMD-SB-3020")
	})
	t.Run("microcode below the bulletin floor", func(t *testing.T) {
		r := milanAtFloor()
		r.tcb = milanGenoaTCB(0x04, 0x00, 0x1D, 0xDD)
		_, err := checkSEVSNPPolicy(parseRaw(t, r.bytes()), SEVSNPPolicy{}, "sev-snp")
		denied(t, err, "microcode 0xdd below 0xde", "AMD-SB-3027")
	})
	t.Run("launch TCB below while the rest are at the floor", func(t *testing.T) {
		r := milanAtFloor()
		r.launchTCB = milanGenoaTCB(0x04, 0x00, 0x18, 0xDE)
		_, err := checkSEVSNPPolicy(parseRaw(t, r.bytes()), SEVSNPPolicy{}, "sev-snp")
		denied(t, err, "launch TCB snp 0x18 below 0x1b")
	})
	t.Run("the operator's floor above the chip", func(t *testing.T) {
		pol, err := (&SEVSNPPolicyConfig{TCBFloor: &SEVTCBFloor{SNP: 0x1E}}).Policy()
		require.NoError(t, err)
		_, err = checkSEVSNPPolicy(parseRaw(t, milanAtFloor().bytes()), pol, "sev-snp")
		denied(t, err, "snp 0x1d below 0x1e", "tee.peer.sev_snp.tcb_floor")
	})
	t.Run("the operator's floor below the bulletins' is refused at configuration unless accepted on the record", func(t *testing.T) {
		_, err := (&SEVSNPPolicyConfig{TCBFloor: &SEVTCBFloor{SNP: 0x10}}).Policy()
		require.Error(t, err)
		require.Contains(t, err.Error(), "accept_below_bulletin")
		pol, err := (&SEVSNPPolicyConfig{TCBFloor: &SEVTCBFloor{SNP: 0x10}, AcceptBelowBulletin: true}).Policy()
		require.NoError(t, err)
		r := milanAtFloor()
		r.tcb = milanGenoaTCB(0x04, 0x00, 0x12, 0xDE)
		d, err := checkSEVSNPPolicy(parseRaw(t, r.bytes()), pol, "sev-snp")
		require.NoError(t, err)
		require.Equal(t, "tee.peer.sev_snp.tcb_floor", d.FloorSource)
	})
	t.Run("a chip the table does not know is refused until the operator names a floor", func(t *testing.T) {
		r := milanAtFloor()
		r.model = 0x12
		_, err := checkSEVSNPPolicy(parseRaw(t, r.bytes()), SEVSNPPolicy{}, "sev-snp")
		denied(t, err, "no TCB floor is on record", "model 0x12", "tee.peer.sev_snp.tcb_floor")
		pol, err := (&SEVSNPPolicyConfig{TCBFloor: &SEVTCBFloor{SNP: 0x1B, Microcode: 0xDE}}).Policy()
		require.NoError(t, err)
		_, err = checkSEVSNPPolicy(parseRaw(t, r.bytes()), pol, "sev-snp")
		require.NoError(t, err)
	})
}

func TestSEVSNPPolicy_PlatformGuestAndMachine(t *testing.T) {
	t.Run("alias check incomplete", func(t *testing.T) {
		r := milanAtFloor()
		r.platformInfo = 0x05
		_, err := checkSEVSNPPolicy(parseRaw(t, r.bytes()), SEVSNPPolicy{}, "sev-snp")
		denied(t, err, "ALIAS_CHECK_COMPLETE", "AMD-SB-3015")
		no := false
		_, err = checkSEVSNPPolicy(parseRaw(t, r.bytes()), SEVSNPPolicy{RequireAliasCheckComplete: &no}, "sev-snp")
		require.NoError(t, err)
	})
	t.Run("mitigation vector without the bulletin's bit", func(t *testing.T) {
		r := milanAtFloor()
		r.mitVector = 0x9
		_, err := checkSEVSNPPolicy(parseRaw(t, r.bytes()), SEVSNPPolicy{}, "sev-snp")
		denied(t, err, "CURRENT_MIT_VECTOR 0x9 lacks bit(s) 0x2", "AMD-SB-3020")
	})
	t.Run("IOMMU_WRITE_SAFE only when required", func(t *testing.T) {
		_, err := checkSEVSNPPolicy(parseRaw(t, milanAtFloor().bytes()), SEVSNPPolicy{RequireIOMMUWriteSafe: true}, "sev-snp")
		denied(t, err, "IOMMU_WRITE_SAFE")
	})
	t.Run("SMT disallowed only when required", func(t *testing.T) {
		_, err := checkSEVSNPPolicy(parseRaw(t, milanAtFloor().bytes()), SEVSNPPolicy{RequireSMTDisallowed: true}, "sev-snp")
		denied(t, err, "allows SMT", "AMD-SB-3027")
		r := milanAtFloor()
		r.policy = 0x20000
		_, err = checkSEVSNPPolicy(parseRaw(t, r.bytes()), SEVSNPPolicy{RequireSMTDisallowed: true}, "sev-snp")
		require.NoError(t, err)
	})
	t.Run("a migration agent is refused by default", func(t *testing.T) {
		r := milanAtFloor()
		r.policy = 0x30000 | sevPolicyMigrateMA
		_, err := checkSEVSNPPolicy(parseRaw(t, r.bytes()), SEVSNPPolicy{}, "sev-snp")
		denied(t, err, "MIGRATE_MA")
		no := false
		_, err = checkSEVSNPPolicy(parseRaw(t, r.bytes()), SEVSNPPolicy{RequireMigrateMADisallowed: &no}, "sev-snp")
		require.NoError(t, err)
	})
	t.Run("PAGE_SWAP_DISABLE only when required", func(t *testing.T) {
		_, err := checkSEVSNPPolicy(parseRaw(t, milanAtFloor().bytes()), SEVSNPPolicy{RequirePageSwapDisable: true}, "sev-snp")
		denied(t, err, "PAGE_SWAP_DISABLE")
	})
	t.Run("the machine: a chip the policy names, and one it does not", func(t *testing.T) {
		mine := strings.Repeat("11", 64)
		other := strings.Repeat("22", 64)
		pol, err := (&SEVSNPPolicyConfig{ChipIDs: []string{other}}).Policy()
		require.NoError(t, err)
		_, err = checkSEVSNPPolicy(parseRaw(t, milanAtFloor().bytes()), pol, "sev-snp")
		denied(t, err, "CHIP_ID 1111111111111111… is not one the policy names")
		pol, err = (&SEVSNPPolicyConfig{ChipIDs: []string{other, mine}}).Policy()
		require.NoError(t, err)
		_, err = checkSEVSNPPolicy(parseRaw(t, milanAtFloor().bytes()), pol, "sev-snp")
		require.NoError(t, err)
		_, err = (&SEVSNPPolicyConfig{ChipIDs: []string{"abcd"}}).Policy()
		require.Error(t, err)
	})
}

func TestSEVSNPPolicy_TurinLayout(t *testing.T) {
	r := sevRawReport{fam: 0x1A, model: 0x02, step: 0x01, policy: 0x20000, platformInfo: 0x04,
		tcb: turinTCB(0x01, 0x02, 0x03, 0x04, 0x51), mitVector: 0x1, chip: 0x33}
	d, err := checkSEVSNPPolicy(parseRaw(t, r.bytes()), SEVSNPPolicy{}, "sev-snp")
	require.NoError(t, err)
	require.Equal(t, "Turin", d.Product)
	require.Equal(t, SEVTCB{FMC: 1, BootLoader: 2, TEE: 3, SNP: 4, Microcode: 0x51}, d.TCB.Current)
	r.tcb = turinTCB(0x01, 0x02, 0x03, 0x03, 0x51)
	_, err = checkSEVSNPPolicy(parseRaw(t, r.bytes()), SEVSNPPolicy{}, "sev-snp")
	denied(t, err, "snp 0x3 below 0x4")
}

func TestSEVSNPPolicy_SummaryNamesTheFloorsAndTheDate(t *testing.T) {
	s := SEVSNPPolicy{}.Summary()
	require.Equal(t, sevBulletinsReadOn, s.BulletinsReadOn)
	keys := make([]string, 0, len(s.Floors))
	for k := range s.Floors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	require.Equal(t, []string{"Bergamo/Siena", "Genoa", "Genoa-X", "Milan", "Milan-X", "Turin", "Turin Dense"}, keys)
	require.Equal(t, "snp 0x1b microcode 0xde, mitigation vector bits 0x2, alias check", s.Floors["Milan"])
}

// The genuine reports on the record: a GCP Milan report (keybind-evidence,
// 2026-09-13) and an Azure Genoa report (azure-cgpu, 2026-10-22), both
// admitted by the default policy with the values the bulletins ask for.
func TestSEVSNPPolicy_GenuineReportsMeetTheLiveFloors(t *testing.T) {
	cases := []struct {
		glob                string
		product, variant    string
		snp, ucode          uint8
		firmware, mitVector string
	}{
		{"../../../scripts/hardware-test/gcp-sev-snp/keybind-evidence/*/report-vaultgenome.bin", "Milan", "Milan", 0x1D, 0xDE, "1.58.1", "0xb"},
		{"../../../scripts/hardware-test/azure-cgpu/evidence/20261022T140119Z/snp-report.bin", "Genoa", "Genoa", 0x1B, 0x58, "1.55.49", "0x7"},
	}
	for _, c := range cases {
		matches, err := filepath.Glob(c.glob)
		require.NoError(t, err)
		if len(matches) == 0 {
			t.Skipf("no genuine report at %s", c.glob)
		}
		raw, err := os.ReadFile(matches[len(matches)-1])
		require.NoError(t, err)
		d, err := checkSEVSNPPolicy(parseRaw(t, raw), SEVSNPPolicy{}, "sev-snp")
		require.NoError(t, err, c.product)
		require.Equal(t, c.product, d.Product)
		require.Equal(t, c.variant, d.Variant)
		require.Equal(t, c.snp, d.TCB.Reported.SNP)
		require.Equal(t, c.ucode, d.TCB.Reported.Microcode)
		require.Equal(t, d.TCB.Reported, d.TCB.Current)
		require.Equal(t, d.TCB.Reported, d.TCB.Committed)
		require.Equal(t, c.firmware, d.Firmware.Current)
		require.Equal(t, c.mitVector, d.MitigationVector.Current)
		require.True(t, d.PlatformInfo.AliasCheckComplete)
		require.False(t, d.GuestPolicy.Debug)
		require.False(t, d.GuestPolicy.MigrateMA)
	}
}

// stampSEVReportAtFloors makes a synthetic report pass the default policy
// of ADR 0033 the way a genuine one does: the chip named by CPUID, the
// four TCBs at the variant's bulletin floors, the alias check complete,
// the mitigation vector carrying bits 0 and 1. The fields a test set
// before (measurement, nonce, chip id, policy, version) are kept.
func stampSEVReportAtFloors(raw []byte, fam, model, step byte) {
	raw[sevOffCPUIDFam], raw[sevOffCPUIDFam+1], raw[sevOffCPUIDFam+2] = fam, model, step
	row := sevVariant(fam, model, step)
	if row == nil {
		panic(fmt.Sprintf("stampSEVReportAtFloors: no floors row for %#x/%#x/%#x", fam, model, step))
	}
	tcb := milanGenoaTCB(0x04, 0x00, row.SNP, row.Microcode)
	if fam == 0x1A {
		tcb = turinTCB(0x01, 0x04, 0x00, row.SNP, row.Microcode)
	}
	for _, off := range []int{sevOffCurrentTCB, sevOffReportedTCB, sevOffCommittedTCB, sevOffLaunchTCB} {
		binary.LittleEndian.PutUint64(raw[off:], tcb)
	}
	pi := binary.LittleEndian.Uint64(raw[sevOffPlatformInfo:]) | sevPlatformECCEn | sevPlatformAliasCheckComplete
	binary.LittleEndian.PutUint64(raw[sevOffPlatformInfo:], pi)
	binary.LittleEndian.PutUint64(raw[sevOffLaunchMitVec:], 0x3)
	binary.LittleEndian.PutUint64(raw[sevOffCurrentMitVec:], 0x3)
}

// sevRawMilanAtFloors is a whole report at the Milan floors, for fakes
// that return a parsed struct without the chip's bytes.
func sevRawMilanAtFloors() []byte { return milanAtFloor().bytes() }

// The table in the code is the table in docs/compliance/sev-snp-tcb-floors.md,
// row for row; the day it was read is the one the document names.
func TestSEVSNPFloorsMatchTheDocument(t *testing.T) {
	f, err := os.Open("../../../docs/compliance/sev-snp-tcb-floors.md")
	require.NoError(t, err)
	defer f.Close()
	type row struct {
		variant, cpuid, product, snp, ucode, bits, alias string
	}
	var rows []row
	readOn := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Read from AMD's live security bulletins on ") {
			readOn = strings.Fields(strings.TrimPrefix(line, "Read from AMD's live security bulletins on "))[0]
		}
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| Variant") || strings.HasPrefix(line, "|---") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 8 {
			continue
		}
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		rows = append(rows, row{cells[0], cells[1], cells[2], cells[3], cells[4], cells[5], cells[6]})
	}
	require.Equal(t, sevBulletinsReadOn, readOn, "the document names the day the code's table was read")
	require.Len(t, rows, len(sevBulletinFloors))
	for i, r := range sevBulletinFloors {
		d := rows[i]
		require.Equal(t, r.Variant, d.variant)
		require.Equal(t, fmt.Sprintf("0x%02x/0x%02x/0x%02x", r.Family, r.Model, r.Stepping), d.cpuid)
		require.Equal(t, r.Product, d.product)
		snp, err := strconv.ParseUint(strings.TrimPrefix(d.snp, "0x"), 16, 8)
		require.NoError(t, err)
		require.Equal(t, r.SNP, uint8(snp), r.Variant)
		ucode, err := strconv.ParseUint(strings.TrimPrefix(d.ucode, "0x"), 16, 8)
		require.NoError(t, err)
		require.Equal(t, r.Microcode, uint8(ucode), r.Variant)
		bits, err := strconv.ParseUint(strings.TrimPrefix(d.bits, "0x"), 16, 64)
		require.NoError(t, err)
		require.Equal(t, r.MitigationBits, bits, r.Variant)
		require.Equal(t, r.AliasCheck, d.alias == "yes", r.Variant)
	}
}
