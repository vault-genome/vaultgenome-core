// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// aws-sev-snp against the first capture on EC2 (testdata/aws-sev-snp/
// 20261029T155800Z: three m6a instances in us-east-2, their reports from
// configfs-tsm, the certificate table beside each, the VLEK snpguest read,
// AMD's VLEK and VCEK chains from KDS) — offline, no hardware, no network.
// The real pieces run on the real bytes: the parse, the signer, the table,
// the VLEK's extensions against the report, the chain to the pinned root,
// the signature. The verifier's whole path runs with the signature and the
// chain stubbed, because the captured REPORT_DATA is the capture's own
// nonce, not a challenger's.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const awsCaptureDir = "testdata/aws-sev-snp/20261029T155800Z"

// awsCaptureMeasurement2 is what sev-snp-measure gives for AWS's published
// UEFI release 20260814 with 2 vCPUs (CAPTURE.md).
const awsCaptureMeasurement2 = "7a89cceaaba0bbdddc4f775acca3ef15d1f9bf8abccdc6115cfad7fb8eae113df3ee0bb50efa34db9c53ae065b1dc766"

const awsCaptureCSPID = "CN=cc-us-east-2.amazonaws.com"

func awsCapture(t *testing.T, host, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(awsCaptureDir, host, name))
	require.NoError(t, err, name)
	return b
}

func awsCaptureDay() time.Time { return time.Date(2026, 10, 29, 16, 0, 0, 0, time.UTC) }

func pemDER(t *testing.T, b []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(b)
	require.NotNil(t, blk)
	return blk.Bytes
}

func TestAWSSEVSNP_FirstCaptureHoldsOnTheRealBytes(t *testing.T) {
	chain := awsCapture(t, "host-a", "kds/vlek-Milan-cert_chain.pem")
	vcekChain := awsCapture(t, "host-a", "kds/vcek-Milan-cert_chain.pem")
	info, err := VerifyAMDCertChain(chain)
	require.NoError(t, err)
	require.Equal(t, AMDChainInfo{Product: "Milan", Signer: AMDSignerVLEK, ASKSubjectCN: "SEV-VLEK-Milan", ARKSubjectCN: "ARK-Milan", ARKFingerprintSHA256: AMDRootFingerprintSHA256["Milan"]}, info,
		"the VLEK chain ends in the same ARK-Milan this build pins")
	vinfo, err := VerifyAMDCertChain(vcekChain)
	require.NoError(t, err)
	require.Equal(t, AMDSignerVCEK, vinfo.Signer)
	require.Equal(t, "SEV-Milan", vinfo.ASKSubjectCN)

	var measurements []string
	var vleks [][]byte
	for _, host := range []string{"host-a", "host-b", "host-c"} {
		raw := awsCapture(t, host, "configfs/report1.bin")
		report, err := realParseSEVSNPReport(raw)
		require.NoError(t, err, host)
		require.Equal(t, sevSigningKeyVLEK, report.SigningKey, "%s: signed by a VLEK", host)
		require.Equal(t, uint32(1), report.SignatureAlgo)
		require.Zero(t, report.VMPL)
		require.True(t, isAllZero(report.ChipID[:]), "%s: CHIP_ID is zero under a VLEK", host)
		require.Zero(t, report.Policy&sevPolicyDebug)

		d := sevSNPReportDetail(report)
		require.Equal(t, uint32(5), d.Version)
		require.Equal(t, "Milan", d.Product)
		require.Equal(t, "Milan", d.Variant)
		require.Equal(t, SEVTCB{BootLoader: 4, TEE: 0, SNP: 0x1F, Microcode: 0xE1}, d.TCB.Reported)
		require.Equal(t, d.TCB.Reported, d.TCB.Committed)
		require.Equal(t, "1.58.3", d.Firmware.Current)
		require.True(t, d.PlatformInfo.AliasCheckComplete)
		require.True(t, d.PlatformInfo.TSMEEn, "the first capture's hosts run TSME")
		require.Equal(t, "0xfef", d.MitigationVector.Current)
		require.Equal(t, "vlek", d.SigningKey)
		require.Len(t, d.ReportIDHex, 64)
		require.NotEqual(t, hex.EncodeToString(make([]byte, 32)), d.ReportIDHex, "REPORT_ID is the identity the report does carry")
		second, err := realParseSEVSNPReport(awsCapture(t, host, "configfs/report2.bin"))
		require.NoError(t, err)
		require.Equal(t, d.ReportIDHex, sevSNPReportDetail(second).ReportIDHex, "%s: one boot, one REPORT_ID", host)
		require.NotEqual(t, report.ReportData, second.ReportData, "two nonces, two reports")

		// The attack record holds at the bulletins' floors (ADR 0033).
		_, err = checkSEVSNPPolicy(report, SEVSNPPolicy{}, "aws-sev-snp")
		require.NoError(t, err, host)

		// The certificate table beside the report: one VLEK, nothing else.
		aux := awsCapture(t, host, "configfs/auxblob1.bin")
		entries, err := parseSEVCertTable(aux)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		require.Equal(t, sevGUIDVLEK, entries[0].GUID)
		vlek, err := vlekFromCertTable(aux)
		require.NoError(t, err)
		require.Equal(t, pemDER(t, awsCapture(t, host, "snpguest/certs/vlek.pem")), vlek, "%s: the table's VLEK is the one snpguest read", host)
		vleks = append(vleks, vlek)

		// The VLEK, the chain, the signature — the real cryptography.
		vd, err := checkVLEK(vlek, report, "Milan", awsCaptureDay())
		require.NoError(t, err, host)
		require.Equal(t, "SEV-VLEK", vd.SubjectCN)
		require.Equal(t, "SEV-VLEK-Milan", vd.IssuerCN)
		require.Equal(t, "Milan", vd.ProductName)
		require.Equal(t, awsCaptureCSPID, vd.CSPID)
		require.Equal(t, SEVTCB{BootLoader: 4, TEE: 0, SNP: 0x1F, Microcode: 0xE1}, vd.TCB)
		require.NoError(t, realVerifyAMDChainVLEK(vlek, chain), "%s: VLEK <- ASVK <- ARK-Milan", host)
		require.NoError(t, realVerifySEVReportSignature(report, vlek), "%s: the VLEK signed the report", host)
		require.NoError(t, realVerifySEVReportSignature(second, vlek))
		err = realVerifyAMDChainVLEK(vlek, vcekChain)
		require.ErrorContains(t, err, "SEV-Milan", "the VCEK chain does not vouch for a VLEK")
		require.ErrorContains(t, err, "VLEK not signed")
		measurements = append(measurements, hex.EncodeToString(report.Measurement[:]))
	}
	require.Equal(t, awsCaptureMeasurement2, measurements[0], "host-a: AWS's UEFI release 20260814 measured for 2 vCPUs")
	require.Equal(t, measurements[0], measurements[1], "host-b: the same firmware, the same vCPU count, the same measurement")
	require.NotEqual(t, measurements[0], measurements[2], "host-c: 4 vCPUs, another measurement")
	require.True(t, bytes.Equal(vleks[0], vleks[1]) && bytes.Equal(vleks[1], vleks[2]), "one VLEK on three hosts in two zones: the provider's key, not a chip's")

	// snpguest's report was requested at VMPL 1 — the verifier's VMPL 0
	// policy refuses it, as it should.
	sg, err := realParseSEVSNPReport(awsCapture(t, "host-a", "snpguest/report.bin"))
	require.NoError(t, err)
	require.Equal(t, uint32(1), sg.VMPL)

	// A VCEK (the GCP capture) under the VLEK chain is refused by name.
	if vcek, err := os.ReadFile(filepath.Join(genuineEvidenceDir(t), "cert-VCEK.bin")); err == nil {
		err := realVerifyAMDChainVLEK(vcek, chain)
		require.ErrorContains(t, err, "VLEK not signed")
		require.ErrorContains(t, err, "SEV-VLEK-Milan")
		err = realVerifyAMDChain(vleks[0], vcekChain)
		require.ErrorContains(t, err, "VCEK not signed")
	}
	_, _, err = FetchAMDCertChainSigned("", "milan", "asvk")
	require.ErrorContains(t, err, "unknown AMD signer kind")
}

func TestAWSSEVSNP_CertificateTable(t *testing.T) {
	entry := func(guid string, data []byte, off uint32) []byte {
		g, _ := hex.DecodeString(guid[:8] + guid[9:13] + guid[14:18] + guid[19:23] + guid[24:])
		e := append([]byte(nil), g...)
		e = binary.LittleEndian.AppendUint32(e, off)
		return binary.LittleEndian.AppendUint32(e, uint32(len(data)))
	}
	_, err := vlekFromCertTable(nil)
	require.ErrorContains(t, err, "no certificate table")
	_, err = vlekFromCertTable(make([]byte, 24))
	require.ErrorContains(t, err, "empty")
	// VCEK and ARK, no VLEK: the table of a Compute Engine host.
	tbl := append(entry(sevGUIDVCEK, []byte("vcek"), 72), entry(sevGUIDARK, []byte("ark!"), 76)...)
	tbl = append(tbl, make([]byte, 24)...)
	tbl = append(tbl, []byte("vcekark!")...)
	_, err = vlekFromCertTable(tbl)
	require.ErrorContains(t, err, "holds VCEK, ARK and no VLEK")
	// An entry pointing outside the table.
	bad := append(entry(sevGUIDVLEK, []byte("v"), 4096), make([]byte, 24)...)
	_, err = vlekFromCertTable(bad)
	require.ErrorContains(t, err, "outside the table")
}

// awsEnvelope is an envelope of the first capture's report with REPORT_DATA
// rewritten for nonce — the signature no longer holds, so the tests that
// use it stub the signature and the chain and exercise everything else.
func awsEnvelope(t *testing.T, nonce Nonce, edit func(raw []byte)) ([]byte, []byte, Measurement) {
	t.Helper()
	raw := append([]byte(nil), awsCapture(t, "host-a", "configfs/report1.bin")...)
	prefix := computeReportDataPrefix(nonce)
	var rd [64]byte
	copy(rd[:], prefix[:])
	copy(raw[sevOffReportData:], rd[:])
	if edit != nil {
		edit(raw)
	}
	vlek, err := vlekFromCertTable(awsCapture(t, "host-a", "configfs/auxblob1.bin"))
	require.NoError(t, err)
	ev, err := json.Marshal(awsSEVSNPEvidence{Schema: AWSSEVSNPEvidenceSchema, Report: raw, VLEK: vlek})
	require.NoError(t, err)
	return ev, vlek, Measurement(raw[sevOffMeasurement : sevOffMeasurement+48])
}

func stubAWSCrypto(t *testing.T) {
	t.Helper()
	teeFakeMu.Lock()
	t.Cleanup(teeFakeMu.Unlock)
	sig, chain := verifySEVReportSignature, verifyAMDChainVLEK
	t.Cleanup(func() { verifySEVReportSignature, verifyAMDChainVLEK = sig, chain })
	verifySEVReportSignature = func(*sevSNPReport, []byte) error { return nil }
	verifyAMDChainVLEK = func([]byte, []byte) error { return nil }
}

func TestAWSSEVSNPVerifier_HoldsTheEnvelopeToThePolicy(t *testing.T) {
	stubAWSCrypto(t)
	chain := awsCapture(t, "host-a", "kds/vlek-Milan-cert_chain.pem")
	vcekChain := awsCapture(t, "host-a", "kds/vcek-Milan-cert_chain.pem")
	nonce := Nonce("a thirty-two byte challenger nonce!")
	env, vlek, measurement := awsEnvelope(t, nonce, nil)
	cfg := AWSSEVSNPVerifierConfig{SEV: GCPSEVVerifierConfig{AMDRootPEM: chain}, CSPIDs: []string{awsCaptureCSPID}, Now: awsCaptureDay}

	v, err := NewAWSSEVSNPVerifier(nil, measurement, cfg)
	require.NoError(t, err)
	m, detail, err := v.VerifyDetailed(env, nonce)
	require.NoError(t, err)
	require.True(t, m.Equal(measurement))
	require.Equal(t, ProviderAWSSEVSNP, detail.Provider)
	require.Equal(t, "Milan", detail.Product)
	require.Empty(t, detail.ChipIDHex, "no chip on the record: the report names none")
	require.Equal(t, "vlek", detail.SEVSNP.SigningKey)
	require.NotNil(t, detail.SEVSNP.VLEK)
	require.Equal(t, awsCaptureCSPID, detail.SEVSNP.VLEK.CSPID)
	require.Equal(t, "2027-10-01T05:01:23Z", detail.SEVSNP.VLEK.NotAfter)
	require.Len(t, detail.SEVSNP.ReportIDHex, 64)
	require.Contains(t, detail.SEVSNP.FloorSource, "AMD bulletins")
	any, err := NewAWSSEVSNPVerifier(nil, measurement, AWSSEVSNPVerifierConfig{SEV: GCPSEVVerifierConfig{AMDRootPEM: chain}, Now: awsCaptureDay})
	require.NoError(t, err)
	_, err = any.Verify(env, nonce)
	require.NoError(t, err, "no csp_ids: any VLEK that chains to AMD's root, on the record")

	// Refused at construction: a VCEK chain, a chip id, a VCEK cache, no chain.
	_, err = NewAWSSEVSNPVerifier(nil, measurement, AWSSEVSNPVerifierConfig{SEV: GCPSEVVerifierConfig{AMDRootPEM: vcekChain}})
	requireStructuralErr(t, err, "VCEK chain")
	_, err = NewAWSSEVSNPVerifier(nil, measurement, AWSSEVSNPVerifierConfig{SEV: GCPSEVVerifierConfig{AMDRootPEM: chain, SEVSNP: SEVSNPPolicy{ChipIDs: [][64]byte{{1}}}}})
	requireStructuralErr(t, err, "chip_ids")
	_, err = NewAWSSEVSNPVerifier(nil, measurement, AWSSEVSNPVerifierConfig{SEV: GCPSEVVerifierConfig{AMDRootPEM: chain, VCEKCacheDir: t.TempDir()}})
	requireStructuralErr(t, err, "vcek_cache_dir")
	_, err = NewAWSSEVSNPVerifier(nil, measurement, AWSSEVSNPVerifierConfig{})
	requireStructuralErr(t, err, "VLEK chain")
	_, err = NewAWSSEVSNPVerifier(nil, measurement, AWSSEVSNPVerifierConfig{SEV: GCPSEVVerifierConfig{AMDRootPEM: chain}, CSPIDs: []string{" "}})
	requireStructuralErr(t, err, "csp_ids")

	// Refused at verification, each defect by name.
	other, err := NewAWSSEVSNPVerifier(nil, measurement, AWSSEVSNPVerifierConfig{SEV: GCPSEVVerifierConfig{AMDRootPEM: chain}, CSPIDs: []string{"CN=cc-eu-west-1.amazonaws.com"}, Now: awsCaptureDay})
	require.NoError(t, err)
	_, err = other.Verify(env, nonce)
	requireIntegrityErr(t, err, "csp_ids does not name")
	_, err = v.Verify(env, Nonce("short"))
	requireStructuralErr(t, err, "nonce")
	_, err = v.Verify(env, Nonce("another thirty-two byte challenge!!"))
	requireIntegrityErr(t, err, "REPORT_DATA")
	_, err = v.Verify(Evidence(awsCapture(t, "host-a", "configfs/report1.bin")), nonce)
	requireIntegrityErr(t, err, "envelope")
	noVLEK, _ := json.Marshal(awsSEVSNPEvidence{Schema: AWSSEVSNPEvidenceSchema, Report: awsCapture(t, "host-a", "configfs/report1.bin")})
	_, err = v.Verify(Evidence(noVLEK), nonce)
	requireIntegrityErr(t, err, "no VLEK")
	stale, err := NewAWSSEVSNPVerifier(nil, measurement, AWSSEVSNPVerifierConfig{SEV: GCPSEVVerifierConfig{AMDRootPEM: chain}, Now: func() time.Time { return awsCaptureDay().AddDate(2, 0, 0) }})
	require.NoError(t, err)
	_, err = stale.Verify(env, nonce)
	requireIntegrityErr(t, err, "valid from")
	elsewhere, err := NewAWSSEVSNPVerifier(nil, Measurement(bytes.Repeat([]byte{0x5A}, 48)), cfg)
	require.NoError(t, err)
	_, err = elsewhere.Verify(env, nonce)
	requireIntegrityErr(t, err, "not in acceptable set")

	edits := []struct {
		name     string
		edit     func(raw []byte)
		fragment string
	}{
		{"signed by the chip's VCEK", func(raw []byte) { binary.LittleEndian.PutUint32(raw[sevOffFlags:], 0) }, "signed by the chip's VCEK"},
		{"no signing key", func(raw []byte) { binary.LittleEndian.PutUint32(raw[sevOffFlags:], 7<<2) }, "by the none"},
		{"another product", func(raw []byte) { raw[sevOffCPUIDFam+1] = 0x11 }, "report's chip is Genoa"},
		{"a TCB the VLEK is not for", func(raw []byte) { raw[sevOffReportedTCB+6] = 0x1E }, "the VLEK is for snp SPL 0x1f"},
		{"debuggable guest", func(raw []byte) { binary.LittleEndian.PutUint64(raw[sevOffPolicy:], 0x2030000|sevPolicyDebug) }, "DEBUG"},
		{"requested at VMPL 1", func(raw []byte) { binary.LittleEndian.PutUint32(raw[sevOffVMPL:], 1) }, "VMPL 1"},
	}
	for _, e := range edits {
		ev, _, _ := awsEnvelope(t, nonce, e.edit)
		_, err := v.Verify(ev, nonce)
		requireIntegrityErr(t, err, e.fragment)
		t.Log(e.name)
	}
	_ = vlek

	verifyAMDChainVLEK = func([]byte, []byte) error { return errors.New("not AMD's") }
	_, err = v.Verify(env, nonce)
	requireIntegrityErr(t, err, "AMD chain")
	verifyAMDChainVLEK = func([]byte, []byte) error { return nil }
	verifySEVReportSignature = func(*sevSNPReport, []byte) error { return errors.New("forged") }
	_, err = v.Verify(env, nonce)
	requireIntegrityErr(t, err, "report signature")
}

// awsHostTSM plays an EC2 host: the capture's report with the requested
// REPORT_DATA written in, and its certificate table beside it.
type awsHostTSM struct {
	raw, aux []byte
}

func (h *awsHostTSM) report(reportData [64]byte, _ uint32) ([]byte, []byte, error) {
	raw := append([]byte(nil), h.raw...)
	copy(raw[sevOffReportData:], reportData[:])
	return raw, h.aux, nil
}

func TestAWSSEVSNPProducer_CarriesTheVLEK(t *testing.T) {
	raw := awsCapture(t, "host-a", "configfs/report1.bin")
	aux := awsCapture(t, "host-a", "configfs/auxblob1.bin")
	nonce := Nonce("a thirty-two byte challenger nonce!")

	chip, err := newGCPSEVProducer(GCPSEVProducerConfig{}, &awsHostTSM{raw: raw, aux: aux})
	require.NoError(t, err)
	p, err := newAWSSEVSNPProducer(chip, awsCaptureDay)
	require.NoError(t, err)
	require.Equal(t, awsCaptureMeasurement2, hex.EncodeToString(p.Measurement()))
	require.Equal(t, uint64(0x2030000), p.Policy())
	ev, err := p.Quote(nonce)
	require.NoError(t, err)
	var env awsSEVSNPEvidence
	require.NoError(t, json.Unmarshal(ev, &env))
	require.Equal(t, AWSSEVSNPEvidenceSchema, env.Schema)
	require.Len(t, env.Report, sevReportLen)
	require.Equal(t, pemDER(t, awsCapture(t, "host-a", "snpguest/certs/vlek.pem")), env.VLEK)
	report, err := realParseSEVSNPReport(env.Report)
	require.NoError(t, err)
	require.True(t, nonceMatchesReportDataSEV(report.ReportData, nonce))
	mt, value, err := WrapEvidence(ProviderAWSSEVSNP, ev, nil)
	require.NoError(t, err)
	require.Equal(t, MediaTypeAWSSEVSNPEvidence, mt)
	back, _, err := UnwrapEvidence(ProviderAWSSEVSNP, mt, value)
	require.NoError(t, err)
	require.Equal(t, ev, back)
	_, _, err = UnwrapEvidence(ProviderAWSSEVSNP, MediaTypeTSMReportJSON, value)
	requireIntegrityErr(t, err, "reads "+MediaTypeAWSSEVSNPEvidence)
	kind, err := SealerKindFor(p, SealerModeAuto)
	require.NoError(t, err)
	require.Equal(t, SealerKindSEVDerivedKey, kind)
	_, err = SealerKindFor(p, SealerModeBoth)
	requireStructuralErr(t, err, "no sealing key of its own to nest")
	_, err = p.Quote(Nonce("short"))
	requireStructuralErr(t, err, "nonce")
	require.NoError(t, p.Close())
	_, err = p.Quote(nonce)
	requireStructuralErr(t, err, "closed")

	// A host whose reports the VCEK signs is not this family.
	vcekSigned := append([]byte(nil), raw...)
	binary.LittleEndian.PutUint32(vcekSigned[sevOffFlags:], 0)
	chip, err = newGCPSEVProducer(GCPSEVProducerConfig{}, &awsHostTSM{raw: vcekSigned, aux: aux})
	require.NoError(t, err)
	_, err = newAWSSEVSNPProducer(chip, awsCaptureDay)
	requireStructuralErr(t, err, "signed by the vcek")
	// A host that shows no certificate table, or one without a VLEK.
	chip, err = newGCPSEVProducer(GCPSEVProducerConfig{}, &awsHostTSM{raw: raw})
	require.NoError(t, err)
	_, err = newAWSSEVSNPProducer(chip, awsCaptureDay)
	requireStructuralErr(t, err, "no certificate table")
}

func TestAWSSEVSNP_RegistryAndHost(t *testing.T) {
	p, err := ParseProvider("aws-sev-snp")
	require.NoError(t, err)
	require.Equal(t, ProviderAWSSEVSNP, p)
	require.Contains(t, AllProviders(), ProviderAWSSEVSNP)
	kind, err := SealerKindForProvider(ProviderAWSSEVSNP, SealerModeTEE)
	require.NoError(t, err)
	require.Equal(t, SealerKindSEVDerivedKey, kind)
	_, err = BuildVerifier(VerifierSpec{Provider: ProviderAWSSEVSNP, ExpectedMeasurement: Measurement(bytes.Repeat([]byte{1}, 48)),
		AWSSEVSNP: AWSSEVSNPVerifierConfig{SEV: GCPSEVVerifierConfig{AMDRootPEM: awsCapture(t, "host-a", "kds/vlek-Milan-cert_chain.pem")}}})
	require.NoError(t, err)
	_, err = BuildProducer(ProducerSpec{Provider: ProviderAWSSEVSNP, AWSSEVSNP: AWSSEVSNPProducerConfig{SEV: GCPSEVProducerConfig{TSMReportDir: filepath.Join(t.TempDir(), "none")}}})
	requireStructuralErr(t, err, "configfs-tsm")

	vendor := dmiSysVendor
	t.Cleanup(func() { dmiSysVendor = vendor })
	dmiSysVendor = func() string { return "Google" }
	require.False(t, hostIsEC2())
	ok, why := Capability(ProviderAWSSEVSNP)
	require.False(t, ok)
	require.Contains(t, why, "AWS SEV-SNP")
	dmiSysVendor = func() string { return "Amazon EC2" }
	require.True(t, hostIsEC2())
}
