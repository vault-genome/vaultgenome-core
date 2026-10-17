// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// tee.provider "auto" under Azure's paravisor: no configfs-tsm, the family
// read from the HCL report in the vTPM — azure-sev-snp for an SNP report,
// another type refused by its number, a host with neither answer refused
// with both.

// hclBlob is an HCL report's shape, enough for the type to be read: the
// magic, the header, an SNP report's worth of bytes, the runtime header
// with reportType.
func hclBlob(reportType uint32) []byte {
	raw := make([]byte, hclHeaderLen+sevReportLen+hclRuntimeHeaderLen+8)
	copy(raw, hclMagic)
	rt := raw[hclHeaderLen+sevReportLen:]
	binary.LittleEndian.PutUint32(rt[4:8], hclRuntimeVersion)
	binary.LittleEndian.PutUint32(rt[8:12], reportType)
	binary.LittleEndian.PutUint32(rt[12:16], hclHashTypeSHA256)
	return raw
}

func withAzureHCL(t *testing.T, raw []byte, err error) {
	t.Helper()
	prev := readAzureHCL
	readAzureHCL = func() ([]byte, error) { return raw, err }
	t.Cleanup(func() { readAzureHCL = prev })
}

func TestDetectAzureHCL_NamesTheFamilyByTheReportsType(t *testing.T) {
	withAzureHCL(t, hclBlob(hclReportTypeSNP), nil)
	family, err := DetectAzureHCL()
	if err != nil || family != ProviderAzureSEVSNP {
		t.Fatalf("an SNP HCL report: %q %v", family, err)
	}

	withAzureHCL(t, hclBlob(4), nil)
	_, err = DetectAzureHCL()
	if err == nil || !errors.Is(err, errHCLOtherType) || !strings.Contains(err.Error(), "report type 4") {
		t.Fatalf("another report type must be refused by its number: %v", err)
	}
}

func TestDetectAzureHCL_RefusesWhatIsNotAReport(t *testing.T) {
	withAzureHCL(t, []byte("short"), nil)
	if _, err := DetectAzureHCL(); err == nil || !strings.Contains(err.Error(), "not an HCL report") {
		t.Fatalf("a short blob: %v", err)
	}
	bad := hclBlob(hclReportTypeSNP)
	copy(bad, "NOPE")
	withAzureHCL(t, bad, nil)
	if _, err := DetectAzureHCL(); err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("the wrong magic: %v", err)
	}
	withAzureHCL(t, nil, errors.New(`exec: "tpm2_nvread": executable file not found in $PATH`))
	if _, err := DetectAzureHCL(); err == nil || !strings.Contains(err.Error(), "tpm2_nvread") {
		t.Fatalf("an unreadable index names the tool: %v", err)
	}
}

func TestResolveAuto_FallsBackToTheVTPMWithoutConfigfs(t *testing.T) {
	noTSM := t.TempDir() + "/absent"

	// The kernel has nothing; the vTPM has an SNP report: azure-sev-snp.
	withAzureHCL(t, hclBlob(hclReportTypeSNP), nil)
	family, from, err := ResolveAuto(noTSM)
	if err != nil || family != ProviderAzureSEVSNP || from != AutoResolvedFromAzureHCL {
		t.Fatalf("auto under the paravisor: %q %q %v", family, from, err)
	}
	available, reason := Capability(ProviderAuto)
	if !available || !strings.Contains(reason, "HCL report") || !strings.Contains(reason, "azure-sev-snp") {
		t.Fatalf("Capability(auto) = %v %q", available, reason)
	}

	// The vTPM has a report of another type: that answer, alone.
	withAzureHCL(t, hclBlob(4), nil)
	_, from, err = ResolveAuto(noTSM)
	if err == nil || from != AutoResolvedFromAzureHCL || !strings.Contains(err.Error(), "report type 4") || strings.Contains(err.Error(), "configfs-tsm") {
		t.Fatalf("another HCL type is a definite answer: %q %v", from, err)
	}

	// Neither: refused with both answers.
	withAzureHCL(t, nil, errors.New("no such NV index"))
	_, _, err = ResolveAuto(noTSM)
	if err == nil || !strings.Contains(err.Error(), "configfs-tsm") || !strings.Contains(err.Error(), "vTPM") || !strings.Contains(err.Error(), "not a confidential VM") {
		t.Fatalf("a host with neither: %v", err)
	}

	// The kernel's answer comes first when it has one.
	fs := newFakeConfigfs("sev_guest", nil)
	name, err := detectTSMProvider("/sys/kernel/config/tsm/report", fs)
	if err != nil || name != "sev_guest" {
		t.Fatalf("configfs: %q %v", name, err)
	}
}
