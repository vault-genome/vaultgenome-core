// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// aws-sev-snp: an EC2 instance on AMD SEV-SNP (m6a, c6a, r6a — AMD Milan,
// `--cpu-options AmdSevSnp=enabled`), whose reports the firmware signs with
// a VLEK, the Versioned Loaded Endorsement Key AMD issues to the cloud
// provider for a product line and a TCB, not with the chip's own VCEK
// (ADR 0038; the first capture of 2026-10-29 under testdata/aws-sev-snp).
//
// What is different from gcp-sev-snp, and why this is a family of its own
// (ADR 0025: a family is named by the shape of its evidence):
//
//   - FLAGS.SIGNING_KEY is 1. CHIP_ID is sixty-four zero bytes: the report
//     names no chip, so a policy cannot pin a machine (chip_ids is refused
//     for this family) and the record carries REPORT_ID, the per-boot
//     identity the firmware does give, instead.
//   - The VLEK cannot be fetched from AMD's Key Distribution Service: KDS
//     serves VCEKs by CHIP_ID, and VLEKs are loaded onto the host by the
//     provider. The host shows the VLEK in the certificate table beside
//     the report (configfs-tsm's auxblob, one entry), and this producer
//     carries it inside the evidence — a JSON envelope of the report and
//     the VLEK — so that the certificate reaches every verifier on every
//     path (the Return Path, cross-cloud restore, receipts, the sentinel)
//     without a round trip to anyone. KDS serves the chain above it:
//     /vlek/v1/<product>/cert_chain, the ASVK (CN SEV-VLEK-<product>) and
//     the ARK, the same root this build pins (amd_roots.go, ADR 0024).
//   - The VLEK says who loaded it: its CSP_ID extension
//     (1.3.6.1.4.1.3704.1.5), on EC2 the region's confidential-computing
//     endpoint — "CN=cc-us-east-2.amazonaws.com" on the first capture. The
//     policy may pin it (csp_ids); the record carries it always.
//   - The launch measurement is AWS's published UEFI (github.com/aws/uefi,
//     release 20260814 on the first capture) measured for the vCPU count:
//     sev-snp-measure --mode snp --vcpus N --vmm-type ec2 gives the value
//     the chip reports, so an operator can compute the pin from the
//     published binary instead of trusting the first report.
//   - The key the firmware derives for the guest (SNP_GET_DERIVED_KEY,
//     root VCEK) is the same on every EC2 SEV-SNP host of the fleet the
//     first capture reached — three hosts, two zones, two stop/starts. The
//     derived-key sealer still binds a file to the launch measurement and
//     the guest policy; on EC2 it does not bind it to a machine. The
//     sealed files survive a stop/start; what opens them is any EC2
//     SEV-SNP guest of the same measurement and policy in that fleet.

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// AWSSEVSNPEvidenceSchema names the envelope.
const AWSSEVSNPEvidenceSchema = "vault-genome/aws-sev-snp/v1"

// awsSEVSNPEvidence is the evidence on the wire: the report and the VLEK
// the host showed beside it, DER.
type awsSEVSNPEvidence struct {
	Schema string `json:"schema"`
	Report []byte `json:"report"`
	VLEK   []byte `json:"vlek"`
}

// The firmware's SIGNING_KEY values (FLAGS bits 4:2).
const (
	sevSigningKeyVCEK uint8 = 0
	sevSigningKeyVLEK uint8 = 1
	sevSigningKeyNone uint8 = 7
)

// sevSigningKeyName names a SIGNING_KEY value as the records print it.
func sevSigningKeyName(k uint8) string {
	switch k {
	case sevSigningKeyVCEK:
		return "vcek"
	case sevSigningKeyVLEK:
		return "vlek"
	case sevSigningKeyNone:
		return "none"
	}
	return fmt.Sprintf("signing-key-%d", k)
}

// The GUIDs of AMD's certificate table (SEV-SNP firmware ABI, "Certificate
// Table"; the sixteen bytes of each entry are the textual GUID's hex in
// order, as go-sev-guest and snpguest read them).
const (
	sevGUIDVCEK = "63da758d-e664-4564-adc5-f4b93be8accd"
	sevGUIDASK  = "4ab7b379-bbac-4fe4-a02f-05aef327c782"
	sevGUIDARK  = "c0b406a4-a803-4952-9743-3fb6014cd0ae"
	sevGUIDVLEK = "a8074bc2-a25a-483e-aae6-39c045a0b8a1"
)

// sevCertTableEntry is one entry of the certificate table.
type sevCertTableEntry struct {
	GUID string
	Data []byte
}

// parseSEVCertTable reads the certificate table a host writes beside a
// report: entries of GUID (16), OFFSET (4, little-endian) and LENGTH (4),
// ending at a zero GUID; offsets count from the table's start.
func parseSEVCertTable(table []byte) ([]sevCertTableEntry, error) {
	var out []sevCertTableEntry
	for off := 0; off+24 <= len(table); off += 24 {
		guid := table[off : off+16]
		o := binary.LittleEndian.Uint32(table[off+16 : off+20])
		l := binary.LittleEndian.Uint32(table[off+20 : off+24])
		if isAllZeroBytes(guid) && o == 0 && l == 0 {
			break
		}
		end := uint64(o) + uint64(l)
		if l == 0 || end > uint64(len(table)) {
			return nil, fmt.Errorf("certificate table: entry %d points outside the table (offset %d, length %d, table %d bytes)", len(out), o, l, len(table))
		}
		h := hex.EncodeToString(guid)
		out = append(out, sevCertTableEntry{GUID: h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], Data: table[o:end]})
	}
	return out, nil
}

func isAllZeroBytes(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// vlekFromCertTable is the VLEK the host wrote into the certificate
// table, DER; an error names what the table held instead.
func vlekFromCertTable(table []byte) ([]byte, error) {
	if len(table) == 0 {
		return nil, errors.New("the host wrote no certificate table beside the report (configfs-tsm showed no auxblob)")
	}
	entries, err := parseSEVCertTable(table)
	if err != nil {
		return nil, err
	}
	var seen []string
	for _, e := range entries {
		if e.GUID == sevGUIDVLEK {
			return append([]byte(nil), e.Data...), nil
		}
		switch e.GUID {
		case sevGUIDVCEK:
			seen = append(seen, "VCEK")
		case sevGUIDASK:
			seen = append(seen, "ASK")
		case sevGUIDARK:
			seen = append(seen, "ARK")
		default:
			seen = append(seen, e.GUID)
		}
	}
	if len(seen) == 0 {
		return nil, errors.New("the certificate table beside the report is empty")
	}
	return nil, fmt.Errorf("the certificate table beside the report holds %s and no VLEK", strings.Join(seen, ", "))
}

// The AMD extensions of a VCEK or VLEK (AMD 57230, "VCEK Certificate").
var (
	oidAMDProductName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 2}
	oidAMDBlSPL       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 1}
	oidAMDTeeSPL      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 2}
	oidAMDSnpSPL      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 3}
	oidAMDUcodeSPL    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 8}
	oidAMDHWID        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 4}
	oidAMDCSPID       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 5}
)

// VLEKDetail is what the verifier read from the VLEK, on the record.
type VLEKDetail struct {
	SubjectCN   string `json:"subject_cn"`
	IssuerCN    string `json:"issuer_cn"`
	ProductName string `json:"product_name"`
	CSPID       string `json:"csp_id"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	SHA256      string `json:"sha256"`
	TCB         SEVTCB `json:"tcb"`
}

func amdExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

func amdExtensionInt(c *x509.Certificate, oid asn1.ObjectIdentifier) (int, error) {
	e, ok := amdExtension(c, oid)
	if !ok {
		return 0, fmt.Errorf("no %v extension", oid)
	}
	var v int
	rest, err := asn1.Unmarshal(e.Value, &v)
	if err != nil || len(rest) != 0 {
		return 0, fmt.Errorf("extension %v is not an INTEGER", oid)
	}
	return v, nil
}

func amdExtensionString(c *x509.Certificate, oid asn1.ObjectIdentifier) (string, error) {
	e, ok := amdExtension(c, oid)
	if !ok {
		return "", fmt.Errorf("no %v extension", oid)
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(e.Value, &raw)
	if err != nil || len(rest) != 0 || raw.Class != asn1.ClassUniversal || raw.IsCompound {
		return "", fmt.Errorf("extension %v is not a string", oid)
	}
	switch raw.Tag {
	case asn1.TagIA5String, asn1.TagUTF8String, asn1.TagPrintableString:
		return string(raw.Bytes), nil
	}
	return "", fmt.Errorf("extension %v is not a string (tag %d)", oid, raw.Tag)
}

// checkVLEK holds the VLEK to the report it signed: a VLEK of the chip's
// product, for the report's TCB, with the provider named and no chip
// identity, in its validity. The report's signature and the chain to
// AMD's root are checked by the caller.
func checkVLEK(vlekDER []byte, report *sevSNPReport, product string, now time.Time) (*VLEKDetail, error) {
	cert, err := x509.ParseCertificate(vlekDER)
	if err != nil {
		return nil, fmt.Errorf("the VLEK does not parse: %w", err)
	}
	d := &VLEKDetail{SubjectCN: cert.Subject.CommonName, IssuerCN: cert.Issuer.CommonName,
		NotBefore: cert.NotBefore.UTC().Format(time.RFC3339), NotAfter: cert.NotAfter.UTC().Format(time.RFC3339), SHA256: certFingerprintSHA256(cert)}
	if cert.Subject.CommonName != "SEV-VLEK" {
		return d, fmt.Errorf("the certificate beside the report is %q, not a VLEK (CN SEV-VLEK)", cert.Subject.CommonName)
	}
	if want := "SEV-VLEK-" + product; cert.Issuer.CommonName != want {
		return d, fmt.Errorf("the VLEK is issued by %q; the report's chip is %s, whose VLEKs are issued by %q", cert.Issuer.CommonName, product, want)
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return d, fmt.Errorf("the VLEK is valid from %s to %s; now is %s", d.NotBefore, d.NotAfter, now.UTC().Format(time.RFC3339))
	}
	name, err := amdExtensionString(cert, oidAMDProductName)
	if err != nil {
		return d, fmt.Errorf("the VLEK's product name: %w", err)
	}
	d.ProductName = name
	if !strings.EqualFold(name, product) {
		return d, fmt.Errorf("the VLEK names product %q, the report's chip is %s", name, product)
	}
	if _, has := amdExtension(cert, oidAMDHWID); has {
		return d, errors.New("the certificate carries a hardware id (HWID): a VCEK, not a VLEK")
	}
	csp, err := amdExtensionString(cert, oidAMDCSPID)
	if err != nil {
		return d, fmt.Errorf("the VLEK's CSP_ID: %w", err)
	}
	if strings.TrimSpace(csp) == "" {
		return d, errors.New("the VLEK's CSP_ID is empty")
	}
	d.CSPID = csp
	turin := len(report.Raw) >= sevOffCPUIDFam+1 && report.Raw[sevOffCPUIDFam] == 0x1A
	reported := sevTCBFromRaw(report.ReportedTCB, turin)
	for _, c := range []struct {
		name string
		oid  asn1.ObjectIdentifier
		want uint8
		set  func(uint8)
	}{
		{"bootloader", oidAMDBlSPL, reported.BootLoader, func(v uint8) { d.TCB.BootLoader = v }},
		{"tee", oidAMDTeeSPL, reported.TEE, func(v uint8) { d.TCB.TEE = v }},
		{"snp", oidAMDSnpSPL, reported.SNP, func(v uint8) { d.TCB.SNP = v }},
		{"microcode", oidAMDUcodeSPL, reported.Microcode, func(v uint8) { d.TCB.Microcode = v }},
	} {
		v, err := amdExtensionInt(cert, c.oid)
		if err != nil {
			return d, fmt.Errorf("the VLEK's %s SPL: %w", c.name, err)
		}
		if v < 0 || v > 255 {
			return d, fmt.Errorf("the VLEK's %s SPL is %d", c.name, v)
		}
		c.set(uint8(v))
		if uint8(v) != c.want {
			return d, fmt.Errorf("the VLEK is for %s SPL %#x, the report says REPORTED_TCB %s %#x", c.name, v, c.name, c.want)
		}
	}
	return d, nil
}

// ----------------------------------------------------------------------------
// Producer
// ----------------------------------------------------------------------------

// AWSSEVSNPProducerConfig configures the producer: the chip's configfs-tsm.
type AWSSEVSNPProducerConfig struct {
	SEV GCPSEVProducerConfig
	// Now is the clock the host's VLEK is held to at start (its validity);
	// nil means time.Now.
	Now func() time.Time
}

// AWSSEVSNPProducer attests with the chip's report and the VLEK the host
// shows beside it.
type AWSSEVSNPProducer struct {
	chip *GCPSEVProducer
	vlek *VLEKDetail // what the host's VLEK said at start, for identity
	mu   sync.Mutex
}

// NewAWSSEVSNPProducer opens the chip through configfs-tsm and checks,
// on a first report, that this host signs with a VLEK and shows it.
func NewAWSSEVSNPProducer(cfg AWSSEVSNPProducerConfig) (*AWSSEVSNPProducer, error) {
	chip, err := NewGCPSEVProducer(cfg.SEV)
	if err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return newAWSSEVSNPProducer(chip, now)
}

// newAWSSEVSNPProducer takes the first report, requires a VLEK and holds the
// host's VLEK to it at the clock now.
func newAWSSEVSNPProducer(chip *GCPSEVProducer, now func() time.Time) (*AWSSEVSNPProducer, error) {
	p := &AWSSEVSNPProducer{chip: chip}
	nonce := make([]byte, NonceMinBytes)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	ev, err := p.Quote(nonce)
	if err != nil {
		_ = chip.Close()
		return nil, err
	}
	// What the VLEK says, for identity: the provider that loaded it, the
	// product and TCB it is for, until when. A VLEK that does not hold to
	// this host's own report is refused here, where the operator sees it.
	var env awsSEVSNPEvidence
	if err := json.Unmarshal(ev, &env); err != nil {
		_ = chip.Close()
		return nil, err
	}
	report, err := parseSEVSNPReport(env.Report)
	if err != nil {
		_ = chip.Close()
		return nil, err
	}
	d, err := checkVLEK(env.VLEK, report, sevProductName(report), now())
	if err != nil {
		_ = chip.Close()
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "aws-sev-snp: the VLEK this host shows does not hold to its own report", err)
	}
	p.vlek = d
	return p, nil
}

// VLEK is what the host's VLEK said when the producer started: whose it
// is (CSP_ID), for which product and TCB, until when.
func (p *AWSSEVSNPProducer) VLEK() VLEKDetail { return *p.vlek }

// VLEKOf is what a producer's VLEK says, when the producer is an EC2
// SEV-SNP guest; ok false otherwise. For the daemons' identity.
func VLEKOf(p Producer) (VLEKDetail, bool) {
	a, ok := p.(*AWSSEVSNPProducer)
	if !ok || a.vlek == nil {
		return VLEKDetail{}, false
	}
	return *a.vlek, true
}

// Quote implements Producer: the report with REPORT_DATA = SHA-256(nonce)
// || zeros(32), and the VLEK from the certificate table beside it, in the
// envelope. A host whose reports are signed by its VCEK is not this
// family: refused by name, so that it is run as gcp-sev-snp instead.
func (p *AWSSEVSNPProducer) Quote(nonce Nonce) (Evidence, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, aux, err := p.chip.QuoteWithAux(nonce)
	if err != nil {
		return nil, err
	}
	report, err := parseSEVSNPReport(raw)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "aws-sev-snp: parse report", err)
	}
	if report.SigningKey != sevSigningKeyVLEK {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("aws-sev-snp: this host's reports are signed by the %s, not a VLEK: it is not an EC2 SEV-SNP guest — run it as gcp-sev-snp (or auto)", sevSigningKeyName(report.SigningKey)), nil)
	}
	vlek, err := vlekFromCertTable(aux)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "aws-sev-snp: "+err.Error(), nil)
	}
	ev, err := json.Marshal(awsSEVSNPEvidence{Schema: AWSSEVSNPEvidenceSchema, Report: raw, VLEK: vlek})
	if err != nil {
		return nil, err
	}
	return Evidence(ev), nil
}

// Measurement implements Producer: the launch measurement (AWS's UEFI for
// this vCPU count).
func (p *AWSSEVSNPProducer) Measurement() Measurement { return p.chip.Measurement() }

// Policy is the guest policy the launch report carries.
func (p *AWSSEVSNPProducer) Policy() uint64 { return p.chip.Policy() }

// Close implements Producer.
func (p *AWSSEVSNPProducer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.chip.Close()
}

// ----------------------------------------------------------------------------
// Verifier
// ----------------------------------------------------------------------------

// AWSSEVSNPVerifierConfig configures the verifier.
type AWSSEVSNPVerifierConfig struct {
	// SEV is the chip's policy as gcp-sev-snp holds it, with two
	// differences: AMDRootPEM is the VLEK chain (ASVK and ARK, as KDS
	// serves /vlek/v1/<product>/cert_chain), and VCEKCacheDir, AMDKDSURL
	// and SEVSNP.ChipIDs do not apply — there is no VCEK to fetch and no
	// chip to name.
	SEV GCPSEVVerifierConfig
	// CSPIDs, when set, are the only providers accepted, as the VLEK's
	// CSP_ID extension spells them ("CN=cc-us-east-2.amazonaws.com");
	// empty accepts any VLEK that chains to AMD's root, and the record
	// says whose it was.
	CSPIDs []string
	// Now is the clock the VLEK's validity is checked at; nil means time.Now.
	Now func() time.Time
}

// AWSSEVSNPVerifier verifies the envelope.
type AWSSEVSNPVerifier struct {
	chip *GCPSEVVerifier
	cfg  AWSSEVSNPVerifierConfig
	csps map[string]bool
}

// AWSSEVSNPVerdict is what a verified evidence said.
type AWSSEVSNPVerdict struct {
	Measurement Measurement
	SEVSNP      *SEVSNPReportDetail
	VLEK        *VLEKDetail
}

// NewAWSSEVSNPVerifier constructs the verifier; a policy that cannot hold
// — a VCEK chain, a chip id, a VCEK cache — is refused here, where the
// operator sees it.
func NewAWSSEVSNPVerifier(pub crypto.PublicKey, expected Measurement, cfg AWSSEVSNPVerifierConfig) (*AWSSEVSNPVerifier, error) {
	structural := func(msg string, err error) error {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "aws-sev-snp: "+msg, err)
	}
	if len(cfg.SEV.AMDRootPEM) == 0 {
		return nil, structural("AMDRootPEM: the VLEK chain (ASVK and ARK; acpctl tee fetch-amd-chain --signer vlek) is required", nil)
	}
	info, err := VerifyAMDCertChain(cfg.SEV.AMDRootPEM)
	if err != nil {
		return nil, structural("AMDRootPEM", err)
	}
	if info.Signer != AMDSignerVLEK {
		return nil, structural(fmt.Sprintf("AMDRootPEM is the %s chain (%s); an EC2 report is signed by a VLEK, which chains through the ASVK (SEV-VLEK-%s): acpctl tee fetch-amd-chain --signer vlek", strings.ToUpper(info.Signer), info.ASKSubjectCN, info.Product), nil)
	}
	if len(cfg.SEV.SEVSNP.ChipIDs) > 0 {
		return nil, structural("sev_snp.chip_ids: an EC2 report names no chip (CHIP_ID is zero under a VLEK); pin the measurement and csp_ids instead, and read REPORT_ID on the record", nil)
	}
	if cfg.SEV.VCEKCacheDir != "" {
		return nil, structural("vcek_cache_dir does not apply: there is no VCEK under a VLEK, and the VLEK travels with the report", nil)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	chip, err := NewGCPSEVVerifier(pub, expected, cfg.SEV)
	if err != nil {
		return nil, err
	}
	csps := map[string]bool{}
	for _, c := range cfg.CSPIDs {
		c = strings.TrimSpace(c)
		if c == "" {
			return nil, structural("csp_ids: an empty entry", nil)
		}
		csps[c] = true
	}
	return &AWSSEVSNPVerifier{chip: chip, cfg: cfg, csps: csps}, nil
}

// Verify implements Verifier.
func (v *AWSSEVSNPVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	verdict, err := v.VerifyEvidence(ev, nonce)
	if err != nil {
		return nil, err
	}
	return verdict.Measurement, nil
}

// VerifyDetailed implements DetailedVerifier.
func (v *AWSSEVSNPVerifier) VerifyDetailed(ev Evidence, nonce Nonce) (Measurement, *AttestationDetail, error) {
	verdict, err := v.VerifyEvidence(ev, nonce)
	if err != nil {
		return nil, nil, err
	}
	return verdict.Measurement, verdict.Detail(), nil
}

// Detail is the verdict as an AttestationDetail for the audit record: no
// chip id (the report has none), the VLEK beside the chip's reading.
func (d *AWSSEVSNPVerdict) Detail() *AttestationDetail {
	return &AttestationDetail{Provider: ProviderAWSSEVSNP, Product: d.SEVSNP.Product, ReportedTCB: d.SEVSNP.ReportedTCBRaw, SEVSNP: d.SEVSNP}
}

// VerifyEvidence verifies and says what the evidence said: the envelope
// opened, the report parsed and signed by a VLEK, the VLEK of the chip's
// product at the report's TCB and in its validity, chained to AMD's root
// through the ASVK, its CSP_ID one the policy names, then the report held
// as gcp-sev-snp holds one — the guest's policy, the VMPL, the attack
// record, the nonce, HOST_DATA, the launch measurement.
func (v *AWSSEVSNPVerifier) VerifyEvidence(ev Evidence, nonce Nonce) (*AWSSEVSNPVerdict, error) {
	integrity := func(code, msg string, err error) error {
		return shared_errors.Integrity(code, "aws-sev-snp: "+msg, err)
	}
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "aws-sev-snp: challenger nonce too short", nil)
	}
	var env awsSEVSNPEvidence
	if err := json.Unmarshal(ev, &env); err != nil || env.Schema != AWSSEVSNPEvidenceSchema {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "evidence is not a "+AWSSEVSNPEvidenceSchema+" envelope (a report alone does not carry the VLEK that signed it)", err)
	}
	if len(env.VLEK) == 0 {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "the envelope carries no VLEK", nil)
	}
	report, err := parseSEVSNPReport(env.Report)
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "parse report", err)
	}
	if report.SignatureAlgo != 1 || report.SigningKey != sevSigningKeyVLEK {
		return nil, integrity(shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("report signed with algorithm %d by the %s; this verifier accepts ECDSA P-384 (1) by a VLEK (1) — a report signed by the chip's VCEK is gcp-sev-snp's, not this family's", report.SignatureAlgo, sevSigningKeyName(report.SigningKey)), nil)
	}
	product := sevProductName(report)
	vlekDetail, err := checkVLEK(env.VLEK, report, product, v.cfg.Now())
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "the VLEK: "+err.Error(), err)
	}
	if len(v.csps) > 0 && !v.csps[vlekDetail.CSPID] {
		return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("the VLEK was loaded by %q, which the policy's csp_ids does not name", vlekDetail.CSPID), nil)
	}
	if err := verifyAMDChainVLEK(env.VLEK, v.cfg.SEV.AMDRootPEM); err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "AMD chain", err)
	}
	if err := verifySEVReportSignature(report, env.VLEK); err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "report signature", err)
	}
	m, snpDetail, err := v.chip.afterSignature(report, nonce, "aws-sev-snp", sevSigningKeyVLEK)
	if err != nil {
		return nil, err
	}
	snpDetail.VLEK = vlekDetail
	return &AWSSEVSNPVerdict{Measurement: m, SEVSNP: snpDetail, VLEK: vlekDetail}, nil
}

// ----------------------------------------------------------------------------
// The host
// ----------------------------------------------------------------------------

// dmiSysVendor reads the machine's DMI system vendor ("Amazon EC2" on an
// EC2 instance, "Google" on Compute Engine); a var so tests can set it.
var dmiSysVendor = func() string {
	b, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// hostIsEC2 reports whether this guest runs on EC2, by its DMI vendor.
func hostIsEC2() bool {
	return dmiSysVendor() == "Amazon EC2"
}

// awsSEVSNPCapability: configfs-tsm on an EC2 instance.
func awsSEVSNPCapability() (bool, string) {
	if st, err := os.Stat(DefaultTSMReportDir); err != nil || !st.IsDir() {
		return false, "AWS SEV-SNP: no configfs-tsm reports at " + DefaultTSMReportDir + " (not a Confidential VM, or kernel < 6.7)"
	}
	if v := dmiSysVendor(); v != "Amazon EC2" {
		return false, fmt.Sprintf("AWS SEV-SNP: this guest's system vendor is %q, not Amazon EC2 (its reports are signed by the VCEK; run gcp-sev-snp or auto)", v)
	}
	return true, "AWS SEV-SNP: configfs-tsm reports available at " + DefaultTSMReportDir + " on an EC2 instance"
}

var (
	_ Producer         = (*AWSSEVSNPProducer)(nil)
	_ Verifier         = (*AWSSEVSNPVerifier)(nil)
	_ DetailedVerifier = (*AWSSEVSNPVerifier)(nil)
	_                  = bytes.Equal
)
