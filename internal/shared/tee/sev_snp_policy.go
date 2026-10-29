// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The attack record in the verifier's policy (ADR 0033): what a SEV-SNP
// attestation report says about the platform beyond the launch
// measurement — the four TCB versions, the platform's word, the guest's
// policy, the mitigation vector, the chip — and the floors the operator's
// policy holds it to. The floors a verifier applies when the operator sets
// none are the ones AMD's security bulletins printed when they were read
// (sevBulletinsReadOn), per product variant, and a report from a chip the
// table does not know is refused until the operator names a floor.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Offsets in ATTESTATION_REPORT (AMD 56860 Rev. 1.59, Table "ATTESTATION_REPORT
// Structure") beyond those gcp_sev_snp_verify.go reads.
const (
	sevOffVersion        = 0x000 // u32
	sevOffGuestSVN       = 0x004 // u32
	sevOffReportID       = 0x140 // 32 bytes: the firmware's identity for this guest, this boot
	sevOffCurrentTCB     = 0x038 // u64
	sevOffPlatformInfo   = 0x040 // u64
	sevOffCommittedTCB   = 0x1E0 // u64
	sevOffCurrentBuild   = 0x1E8 // u8 build, u8 minor, u8 major
	sevOffCommittedBuild = 0x1EC // u8 build, u8 minor, u8 major
	sevOffLaunchTCB      = 0x1F0 // u64
	sevOffLaunchMitVec   = 0x1F8 // u64
	sevOffCurrentMitVec  = 0x200 // u64
)

// Guest policy bits (Table 12) beside sevPolicyDebug.
const (
	sevPolicySMT              = 1 << 16
	sevPolicyMigrateMA        = 1 << 18
	sevPolicySingleSocket     = 1 << 20
	sevPolicyCXLAllow         = 1 << 21
	sevPolicyMemAES256XTS     = 1 << 22
	sevPolicyRAPLDis          = 1 << 23
	sevPolicyCiphertextHiding = 1 << 24
	sevPolicyPageSwapDisable  = 1 << 25
)

// PLATFORM_INFO bits (Table 28).
const (
	sevPlatformSMTEn              = 1 << 0
	sevPlatformTSMEEn             = 1 << 1
	sevPlatformECCEn              = 1 << 2
	sevPlatformRAPLDis            = 1 << 3
	sevPlatformCiphertextHidingEn = 1 << 4
	sevPlatformAliasCheckComplete = 1 << 5
	sevPlatformIOMMUWriteSafe     = 1 << 6
	sevPlatformTIOEn              = 1 << 7
)

// sevBulletinsReadOn is the day the floors below were read from AMD's
// live security bulletins. The table is a copy of
// docs/compliance/sev-snp-tcb-floors.md, which names each bulletin and
// its revision date; refresh both together.
const sevBulletinsReadOn = "2026-10-22"

// SEVTCB is one TCB_VERSION, decomposed for the chip's product line
// (Table 5 for Milan and Genoa, Table 4 for Turin). A component the
// product does not have (FMC outside Turin) is zero.
type SEVTCB struct {
	FMC        uint8 `json:"fmc,omitempty"`
	BootLoader uint8 `json:"bootloader"`
	TEE        uint8 `json:"tee"`
	SNP        uint8 `json:"snp"`
	Microcode  uint8 `json:"microcode"`
}

func (t SEVTCB) String() string {
	return fmt.Sprintf("bootloader %#x tee %#x snp %#x microcode %#x", t.BootLoader, t.TEE, t.SNP, t.Microcode)
}

// sevTCBFromRaw decomposes a TCB_VERSION for the product line.
func sevTCBFromRaw(v uint64, turin bool) SEVTCB {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	if turin {
		return SEVTCB{FMC: b[0], BootLoader: b[1], TEE: b[2], SNP: b[3], Microcode: b[7]}
	}
	return SEVTCB{BootLoader: b[0], TEE: b[1], SNP: b[6], Microcode: b[7]}
}

// SEVTCBFloor is a floor on a TCB's components; a zero component is no
// floor on it.
type SEVTCBFloor struct {
	FMC        uint8 `json:"fmc,omitempty"`
	BootLoader uint8 `json:"bootloader,omitempty"`
	TEE        uint8 `json:"tee,omitempty"`
	SNP        uint8 `json:"snp,omitempty"`
	Microcode  uint8 `json:"microcode,omitempty"`
}

// below names the first component of t under the floor, or "".
func (f SEVTCBFloor) below(t SEVTCB) string {
	switch {
	case f.FMC != 0 && t.FMC < f.FMC:
		return fmt.Sprintf("fmc %#x below %#x", t.FMC, f.FMC)
	case f.BootLoader != 0 && t.BootLoader < f.BootLoader:
		return fmt.Sprintf("bootloader %#x below %#x", t.BootLoader, f.BootLoader)
	case f.TEE != 0 && t.TEE < f.TEE:
		return fmt.Sprintf("tee %#x below %#x", t.TEE, f.TEE)
	case f.SNP != 0 && t.SNP < f.SNP:
		return fmt.Sprintf("snp %#x below %#x", t.SNP, f.SNP)
	case f.Microcode != 0 && t.Microcode < f.Microcode:
		return fmt.Sprintf("microcode %#x below %#x", t.Microcode, f.Microcode)
	}
	return ""
}

// sevFloorRow is one product variant's floors as AMD's bulletins print
// them: the SNP firmware SVN and the microcode patch level, the bit the
// mitigation vector must carry, and whether the alias check applies.
type sevFloorRow struct {
	Variant        string
	Family         uint8
	Model          uint8
	Stepping       uint8
	Product        string // the KDS product line the VCEK is served under
	SNP            uint8
	Microcode      uint8
	MitigationBits uint64
	AliasCheck     bool
	Sources        string
}

// sevBulletinFloors are the floors read on sevBulletinsReadOn. CPUID
// family/model/stepping as the report carries them (CPUID_FAM_ID,
// CPUID_MOD_ID, CPUID_STEP of a version-3 report): Milan 00A00F11,
// Milan-X 00A00F12, Genoa 00A10F11, Genoa-X 00A10F12, Bergamo/Siena
// 00AA0F02, Turin 00B00F21, Turin Dense 00B10F10.
var sevBulletinFloors = []sevFloorRow{
	{Variant: "Milan", Family: 0x19, Model: 0x01, Stepping: 0x01, Product: "Milan", SNP: 0x1B, Microcode: 0xDE, MitigationBits: 1 << 1, AliasCheck: true,
		Sources: "AMD-SB-3020 (SNP 0x1B, mitigation vector bit 1; rev. 2026-02-23), AMD-SB-3027 (microcode 0xDE; rev. 2026-02-27), AMD-SB-3015 (ALIAS_CHECK_COMPLETE)"},
	{Variant: "Milan-X", Family: 0x19, Model: 0x01, Stepping: 0x02, Product: "Milan", SNP: 0x1B, Microcode: 0x47, MitigationBits: 1 << 1, AliasCheck: true,
		Sources: "AMD-SB-3020 (SNP 0x1B, bit 1), AMD-SB-3027 (microcode 0x47), AMD-SB-3015"},
	{Variant: "Genoa", Family: 0x19, Model: 0x11, Stepping: 0x01, Product: "Genoa", SNP: 0x1B, Microcode: 0x56, MitigationBits: 1 << 1, AliasCheck: true,
		Sources: "AMD-SB-3020 (SNP 0x1B, mitigation vector bit 1; rev. 2026-02-23), AMD-SB-3027 (microcode 0x56; rev. 2026-02-27), AMD-SB-3015 (ALIAS_CHECK_COMPLETE)"},
	{Variant: "Genoa-X", Family: 0x19, Model: 0x11, Stepping: 0x02, Product: "Genoa", SNP: 0x1B, Microcode: 0x51, MitigationBits: 1 << 1, AliasCheck: true,
		Sources: "AMD-SB-3020 (SNP 0x1B, bit 1), AMD-SB-3027 (microcode 0x51), AMD-SB-3015"},
	{Variant: "Bergamo/Siena", Family: 0x19, Model: 0xA0, Stepping: 0x02, Product: "Genoa", SNP: 0x1B, Microcode: 0x1B, MitigationBits: 1 << 1, AliasCheck: true,
		Sources: "AMD-SB-3020 (SNP 0x1B, bit 1), AMD-SB-3027 (microcode 0x1B), AMD-SB-3015"},
	{Variant: "Turin", Family: 0x1A, Model: 0x02, Stepping: 0x01, Product: "Turin", SNP: 0x04, Microcode: 0x51, MitigationBits: 1 << 0, AliasCheck: false,
		Sources: "AMD-SB-3020 (SNP 0x04, mitigation vector bit 0; rev. 2026-02-23), AMD-SB-3027 (microcode 0x51; rev. 2026-02-27)"},
	{Variant: "Turin Dense", Family: 0x1A, Model: 0x10, Stepping: 0x00, Product: "Turin", SNP: 0x04, Microcode: 0x4E, MitigationBits: 1 << 0, AliasCheck: false,
		Sources: "AMD-SB-3020 (SNP 0x04, bit 0), AMD-SB-3027 (microcode 0x4E)"},
}

// SEVSNPPolicy is what the operator holds a SEV-SNP report to beyond the
// measurement, the DEBUG bit and the VMPL. The zero value is the default
// policy: the bulletin floors for the chip's variant, the alias check
// where the bulletin names the product, the mitigation vector bits the
// bulletin names, no migration agent; any chip; SMT, IOMMU_WRITE_SAFE and
// PAGE_SWAP_DISABLE not required.
type SEVSNPPolicy struct {
	// TCBFloor replaces the bulletin floors for every chip when set. A
	// floor below the bulletins' is refused at construction unless
	// AcceptBelowBulletin says the operator knows.
	TCBFloor            *SEVTCBFloor
	AcceptBelowBulletin bool
	// RequireAliasCheckComplete: nil follows the bulletin table (true for
	// the Milan and Genoa families).
	RequireAliasCheckComplete *bool
	RequireIOMMUWriteSafe     bool
	// RequireSMTDisallowed requires the guest policy's SMT bit clear. The
	// microcode floor (AMD-SB-3027) is the other mitigation of StackWarp;
	// with it in force the default does not require SMT off.
	RequireSMTDisallowed bool
	// RequireMigrateMADisallowed: nil is true — a guest with a migration
	// agent can be moved by the host.
	RequireMigrateMADisallowed *bool
	RequirePageSwapDisable     bool
	// RequireMitigationBits: nil is true — CURRENT_MIT_VECTOR must carry
	// the bits the bulletin names for the variant.
	RequireMitigationBits *bool
	// ChipIDs, when set, are the only chips accepted (ADR 0033: which
	// machine); empty accepts any chip the rest of the policy admits.
	ChipIDs [][64]byte
}

// SEVSNPPolicyConfig is SEVSNPPolicy as the daemons' configuration files
// carry it (tee.peer.sev_snp; a verifier_registry entry's sev_snp).
type SEVSNPPolicyConfig struct {
	TCBFloor                   *SEVTCBFloor `json:"tcb_floor,omitempty"`
	AcceptBelowBulletin        bool         `json:"accept_below_bulletin,omitempty"`
	RequireAliasCheckComplete  *bool        `json:"require_alias_check_complete,omitempty"`
	RequireIOMMUWriteSafe      bool         `json:"require_iommu_write_safe,omitempty"`
	RequireSMTDisallowed       bool         `json:"require_smt_disallowed,omitempty"`
	RequireMigrateMADisallowed *bool        `json:"require_migrate_ma_disallowed,omitempty"`
	RequirePageSwapDisable     bool         `json:"require_page_swap_disable,omitempty"`
	RequireMitigationBits      *bool        `json:"require_mitigation_bits,omitempty"`
	// ChipIDs are 64-byte CHIP_IDs in hex, as `identity` and the records print them.
	ChipIDs []string `json:"chip_ids,omitempty"`
}

// Policy converts the configuration; a nil receiver is the default policy.
func (c *SEVSNPPolicyConfig) Policy() (SEVSNPPolicy, error) {
	if c == nil {
		return SEVSNPPolicy{}, nil
	}
	p := SEVSNPPolicy{
		TCBFloor:                   c.TCBFloor,
		AcceptBelowBulletin:        c.AcceptBelowBulletin,
		RequireAliasCheckComplete:  c.RequireAliasCheckComplete,
		RequireIOMMUWriteSafe:      c.RequireIOMMUWriteSafe,
		RequireSMTDisallowed:       c.RequireSMTDisallowed,
		RequireMigrateMADisallowed: c.RequireMigrateMADisallowed,
		RequirePageSwapDisable:     c.RequirePageSwapDisable,
		RequireMitigationBits:      c.RequireMitigationBits,
	}
	for i, h := range c.ChipIDs {
		raw, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil || len(raw) != 64 {
			return SEVSNPPolicy{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("sev_snp.chip_ids[%d]: want 64 bytes of hex (a CHIP_ID as identity prints it)", i), err)
		}
		var id [64]byte
		copy(id[:], raw)
		p.ChipIDs = append(p.ChipIDs, id)
	}
	if p.TCBFloor != nil && !p.AcceptBelowBulletin {
		for _, row := range sevBulletinFloors {
			if (p.TCBFloor.SNP != 0 && p.TCBFloor.SNP < row.SNP) || (p.TCBFloor.Microcode != 0 && p.TCBFloor.Microcode < row.Microcode) {
				return SEVSNPPolicy{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
					fmt.Sprintf("sev_snp.tcb_floor is below the bulletins' floor for %s (snp %#x, microcode %#x, read %s); set accept_below_bulletin to run below it, on the record",
						row.Variant, row.SNP, row.Microcode, sevBulletinsReadOn), nil)
			}
		}
	}
	return p, nil
}

// SEVSNPPolicySummary is the policy in force, as `identity` prints it.
type SEVSNPPolicySummary struct {
	BulletinsReadOn      string            `json:"bulletins_read_on"`
	Floors               map[string]string `json:"floors"` // variant → "snp 0x1b microcode 0xde, mitigation bit 1, alias check"
	OperatorFloor        *SEVTCBFloor      `json:"operator_floor,omitempty"`
	AcceptBelowBulletin  bool              `json:"accept_below_bulletin,omitempty"`
	RequireSMTDisallowed bool              `json:"require_smt_disallowed,omitempty"`
	ChipIDs              []string          `json:"chip_ids,omitempty"`
	// CSPIDs are the providers whose VLEK an aws-sev-snp peer's report
	// may be signed by (tee.peer.csp_ids); empty means any VLEK that
	// chains to AMD's root, recorded (ADR 0038).
	CSPIDs []string `json:"csp_ids,omitempty"`
}

// Summary is the policy in force, for identity.
func (p SEVSNPPolicy) Summary() SEVSNPPolicySummary {
	s := SEVSNPPolicySummary{BulletinsReadOn: sevBulletinsReadOn, Floors: map[string]string{}, OperatorFloor: p.TCBFloor,
		AcceptBelowBulletin: p.AcceptBelowBulletin, RequireSMTDisallowed: p.RequireSMTDisallowed}
	for _, row := range sevBulletinFloors {
		line := fmt.Sprintf("snp %#x microcode %#x, mitigation vector bits %#x", row.SNP, row.Microcode, row.MitigationBits)
		if row.AliasCheck {
			line += ", alias check"
		}
		s.Floors[row.Variant] = line
	}
	for _, id := range p.ChipIDs {
		s.ChipIDs = append(s.ChipIDs, hex.EncodeToString(id[:]))
	}
	return s
}

// SEVSNPReportDetail is what the verifier read from the report beyond the
// measurement, on the record beside the verdict.
type SEVSNPReportDetail struct {
	Version  uint32 `json:"version"`
	GuestSVN uint32 `json:"guest_svn"`
	Product  string `json:"product"`
	Variant  string `json:"variant,omitempty"`
	CPUID    struct {
		Family   uint8 `json:"family"`
		Model    uint8 `json:"model"`
		Stepping uint8 `json:"stepping"`
	} `json:"cpuid"`
	GuestPolicy struct {
		Raw              string `json:"raw_hex"`
		ABIMajor         uint8  `json:"abi_major"`
		ABIMinor         uint8  `json:"abi_minor"`
		SMT              bool   `json:"smt"`
		MigrateMA        bool   `json:"migrate_ma"`
		Debug            bool   `json:"debug"`
		SingleSocket     bool   `json:"single_socket"`
		CXLAllow         bool   `json:"cxl_allow"`
		MemAES256XTS     bool   `json:"mem_aes_256_xts"`
		RAPLDis          bool   `json:"rapl_dis"`
		CiphertextHiding bool   `json:"ciphertext_hiding"`
		PageSwapDisable  bool   `json:"page_swap_disable"`
	} `json:"guest_policy"`
	PlatformInfo struct {
		Raw                string `json:"raw_hex"`
		SMTEn              bool   `json:"smt_en"`
		TSMEEn             bool   `json:"tsme_en"`
		ECCEn              bool   `json:"ecc_en"`
		RAPLDis            bool   `json:"rapl_dis"`
		CiphertextHidingEn bool   `json:"ciphertext_hiding_en"`
		AliasCheckComplete bool   `json:"alias_check_complete"`
		IOMMUWriteSafe     bool   `json:"iommu_write_safe"`
		TIOEn              bool   `json:"tio_en"`
	} `json:"platform_info"`
	TCB struct {
		Current   SEVTCB `json:"current"`
		Reported  SEVTCB `json:"reported"`
		Committed SEVTCB `json:"committed"`
		Launch    SEVTCB `json:"launch"`
	} `json:"tcb"`
	Firmware struct {
		Current   string `json:"current"`
		Committed string `json:"committed"`
	} `json:"firmware"`
	MitigationVector struct {
		Launch  string `json:"launch_hex"`
		Current string `json:"current_hex"`
	} `json:"mitigation_vector"`
	ChipIDHex      string `json:"chip_id_hex"`
	ReportedTCBRaw uint64 `json:"reported_tcb_raw"`
	// SigningKey names the key that signed the report (FLAGS.SIGNING_KEY):
	// vcek for a chip's own key, vlek for the key AMD issues to a cloud
	// provider (aws-sev-snp, ADR 0038), none.
	SigningKey string `json:"signing_key"`
	// ReportIDHex is REPORT_ID: the firmware's identity for this guest
	// for this boot — the only machine-side identity a report signed by a
	// VLEK carries, since its CHIP_ID is zero.
	ReportIDHex string `json:"report_id_hex"`
	// VLEK is what an aws-sev-snp verifier read from the VLEK beside the
	// report: whose it is (CSP_ID), for which product and TCB, until when.
	VLEK *VLEKDetail `json:"vlek,omitempty"`
	// Floor is the TCB floor the report was held to, and FloorSource where it came from.
	Floor       SEVTCBFloor `json:"floor"`
	FloorSource string      `json:"floor_source"`
}

// sevVariant finds the floors row for the chip the report names, or nil.
func sevVariant(fam, model, step uint8) *sevFloorRow {
	for i := range sevBulletinFloors {
		r := &sevBulletinFloors[i]
		if r.Family == fam && r.Model == model && r.Stepping == step {
			return r
		}
	}
	return nil
}

// sevSNPReportDetail reads the fields of a report that
// realParseSEVSNPReport leaves in Raw.
func sevSNPReportDetail(r *sevSNPReport) *SEVSNPReportDetail {
	d := &SEVSNPReportDetail{}
	raw := r.Raw
	if len(raw) < sevReportLen {
		return d
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(raw[off : off+4]) }
	u64 := func(off int) uint64 { return binary.LittleEndian.Uint64(raw[off : off+8]) }
	d.Version = u32(sevOffVersion)
	d.GuestSVN = u32(sevOffGuestSVN)
	if d.Version >= 3 {
		d.CPUID.Family, d.CPUID.Model, d.CPUID.Stepping = raw[sevOffCPUIDFam], raw[sevOffCPUIDFam+1], raw[sevOffCPUIDFam+2]
	}
	d.Product = sevProductName(r)
	if row := sevVariant(d.CPUID.Family, d.CPUID.Model, d.CPUID.Stepping); row != nil {
		d.Variant = row.Variant
	}
	turin := d.CPUID.Family == 0x1A
	pol := r.Policy
	d.GuestPolicy.Raw = fmt.Sprintf("%#x", pol)
	d.GuestPolicy.ABIMajor, d.GuestPolicy.ABIMinor = uint8(pol>>8), uint8(pol)
	d.GuestPolicy.SMT = pol&sevPolicySMT != 0
	d.GuestPolicy.MigrateMA = pol&sevPolicyMigrateMA != 0
	d.GuestPolicy.Debug = pol&sevPolicyDebug != 0
	d.GuestPolicy.SingleSocket = pol&sevPolicySingleSocket != 0
	d.GuestPolicy.CXLAllow = pol&sevPolicyCXLAllow != 0
	d.GuestPolicy.MemAES256XTS = pol&sevPolicyMemAES256XTS != 0
	d.GuestPolicy.RAPLDis = pol&sevPolicyRAPLDis != 0
	d.GuestPolicy.CiphertextHiding = pol&sevPolicyCiphertextHiding != 0
	d.GuestPolicy.PageSwapDisable = pol&sevPolicyPageSwapDisable != 0
	pi := u64(sevOffPlatformInfo)
	d.PlatformInfo.Raw = fmt.Sprintf("%#x", pi)
	d.PlatformInfo.SMTEn = pi&sevPlatformSMTEn != 0
	d.PlatformInfo.TSMEEn = pi&sevPlatformTSMEEn != 0
	d.PlatformInfo.ECCEn = pi&sevPlatformECCEn != 0
	d.PlatformInfo.RAPLDis = pi&sevPlatformRAPLDis != 0
	d.PlatformInfo.CiphertextHidingEn = pi&sevPlatformCiphertextHidingEn != 0
	d.PlatformInfo.AliasCheckComplete = pi&sevPlatformAliasCheckComplete != 0
	d.PlatformInfo.IOMMUWriteSafe = pi&sevPlatformIOMMUWriteSafe != 0
	d.PlatformInfo.TIOEn = pi&sevPlatformTIOEn != 0
	d.TCB.Current = sevTCBFromRaw(u64(sevOffCurrentTCB), turin)
	d.TCB.Reported = sevTCBFromRaw(r.ReportedTCB, turin)
	d.TCB.Committed = sevTCBFromRaw(u64(sevOffCommittedTCB), turin)
	d.TCB.Launch = sevTCBFromRaw(u64(sevOffLaunchTCB), turin)
	d.Firmware.Current = fmt.Sprintf("%d.%d.%d", raw[sevOffCurrentBuild+2], raw[sevOffCurrentBuild+1], raw[sevOffCurrentBuild])
	d.Firmware.Committed = fmt.Sprintf("%d.%d.%d", raw[sevOffCommittedBuild+2], raw[sevOffCommittedBuild+1], raw[sevOffCommittedBuild])
	d.MitigationVector.Launch = fmt.Sprintf("%#x", u64(sevOffLaunchMitVec))
	d.MitigationVector.Current = fmt.Sprintf("%#x", u64(sevOffCurrentMitVec))
	d.ChipIDHex = hex.EncodeToString(r.ChipID[:])
	d.ReportedTCBRaw = r.ReportedTCB
	d.SigningKey = sevSigningKeyName(r.SigningKey)
	d.ReportIDHex = hex.EncodeToString(raw[sevOffReportID : sevOffReportID+32])
	return d
}

// checkSEVSNPPolicy holds a parsed, signature-verified report to the
// policy and returns what it read. Every refusal is an Integrity error of
// code CodeAttestationDenied naming the predicate and, where one applies,
// the bulletin; family is the verifier's name for the message.
func checkSEVSNPPolicy(r *sevSNPReport, pol SEVSNPPolicy, family string) (*SEVSNPReportDetail, error) {
	d := sevSNPReportDetail(r)
	deny := func(msg string) (*SEVSNPReportDetail, error) {
		return d, shared_errors.Integrity(shared_errors.CodeAttestationDenied, family+": "+msg, nil)
	}
	row := sevVariant(d.CPUID.Family, d.CPUID.Model, d.CPUID.Stepping)

	// The floor: the operator's, else the bulletins' for this variant.
	var floor SEVTCBFloor
	switch {
	case pol.TCBFloor != nil:
		floor = *pol.TCBFloor
		d.FloorSource = "tee.peer.sev_snp.tcb_floor"
	case row != nil:
		floor = SEVTCBFloor{SNP: row.SNP, Microcode: row.Microcode}
		d.FloorSource = fmt.Sprintf("AMD bulletins read %s for %s: %s", sevBulletinsReadOn, row.Variant, row.Sources)
	default:
		return deny(fmt.Sprintf("no TCB floor is on record for this chip (report version %d, CPUID family %#x model %#x stepping %#x, product %s); set tee.peer.sev_snp.tcb_floor",
			d.Version, d.CPUID.Family, d.CPUID.Model, d.CPUID.Stepping, d.Product))
	}
	d.Floor = floor
	for _, t := range []struct {
		name string
		tcb  SEVTCB
	}{{"reported", d.TCB.Reported}, {"current", d.TCB.Current}, {"committed", d.TCB.Committed}, {"launch", d.TCB.Launch}} {
		if why := floor.below(t.tcb); why != "" {
			return deny(fmt.Sprintf("TCB floor: %s TCB %s (%s)", t.name, why, d.FloorSource))
		}
	}

	// The platform's word.
	requireAlias := row != nil && row.AliasCheck
	if pol.RequireAliasCheckComplete != nil {
		requireAlias = *pol.RequireAliasCheckComplete
	}
	if requireAlias && !d.PlatformInfo.AliasCheckComplete {
		return deny("PLATFORM_INFO: ALIAS_CHECK_COMPLETE is not set — the platform has not confirmed the memory-aliasing mitigation (AMD-SB-3015)")
	}
	if pol.RequireIOMMUWriteSafe && !d.PlatformInfo.IOMMUWriteSafe {
		return deny("PLATFORM_INFO: IOMMU_WRITE_SAFE is not set (CVE-2023-20585) and the policy requires it")
	}

	// The mitigation vector.
	requireMit := true
	if pol.RequireMitigationBits != nil {
		requireMit = *pol.RequireMitigationBits
	}
	if requireMit && row != nil && row.MitigationBits != 0 {
		cur := binary.LittleEndian.Uint64(r.Raw[sevOffCurrentMitVec : sevOffCurrentMitVec+8])
		if cur&row.MitigationBits != row.MitigationBits {
			return deny(fmt.Sprintf("CURRENT_MIT_VECTOR %#x lacks bit(s) %#x the bulletins name for %s (AMD-SB-3020)", cur, row.MitigationBits, row.Variant))
		}
	}

	// The guest's policy.
	if pol.RequireSMTDisallowed && d.GuestPolicy.SMT {
		return deny("guest policy allows SMT and the policy requires it disallowed (AMD-SB-3027, StackWarp)")
	}
	requireNoMA := true
	if pol.RequireMigrateMADisallowed != nil {
		requireNoMA = *pol.RequireMigrateMADisallowed
	}
	if requireNoMA && d.GuestPolicy.MigrateMA {
		return deny("guest policy allows a migration agent (MIGRATE_MA) — the host can move this guest")
	}
	if pol.RequirePageSwapDisable && !d.GuestPolicy.PageSwapDisable {
		return deny("guest policy does not set PAGE_SWAP_DISABLE and the policy requires it")
	}

	// The machine.
	if len(pol.ChipIDs) > 0 {
		ok := false
		for _, id := range pol.ChipIDs {
			if bytes.Equal(id[:], r.ChipID[:]) {
				ok = true
				break
			}
		}
		if !ok {
			return deny(fmt.Sprintf("CHIP_ID %s… is not one the policy names", d.ChipIDHex[:16]))
		}
	}
	return d, nil
}
