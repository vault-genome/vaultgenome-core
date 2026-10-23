// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"strings"
	"testing"
)

func TestParseProvider_FamilyNamesAndAuto(t *testing.T) {
	for in, want := range map[string]Provider{
		"sev-snp": ProviderGCPSEVSNP, "SEV-SNP": ProviderGCPSEVSNP, "tdx": ProviderGCPTDX, "nitro": ProviderAWSNitro,
		"sgx-dcap": ProviderIntelSGXDCAP, "auto": ProviderAuto, " Auto ": ProviderAuto,
		"gcp-sev-snp": ProviderGCPSEVSNP, "simulated": ProviderSimulated,
	} {
		got, err := ParseProvider(in)
		if err != nil || got != want {
			t.Fatalf("ParseProvider(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	_, err := ParseProvider("cca-someday")
	if err == nil || !strings.Contains(err.Error(), "sev-snp") || !strings.Contains(err.Error(), `"auto"`) {
		t.Fatalf("an unknown name must list the family names and auto: %v", err)
	}
	for _, p := range AllProviders() {
		if p == ProviderAuto {
			t.Fatal("auto is not a provider of the wire or a registry; it must not be listed")
		}
	}
	if got := ProviderAliases(); strings.Join(got, ",") != "nitro,sev-snp,sgx-dcap,tdx" {
		t.Fatalf("ProviderAliases = %v", got)
	}
}

func TestDetectTSMProvider_ReadsTheKernelsAnswerAndCleansUp(t *testing.T) {
	fs := newFakeConfigfs("tdx_guest", nil)
	name, err := detectTSMProvider("/sys/kernel/config/tsm/report", fs)
	if err != nil || name != "tdx_guest" {
		t.Fatalf("detect: %q %v", name, err)
	}
	fs.mu.Lock()
	left := len(fs.entries)
	fs.mu.Unlock()
	if left != 0 {
		t.Fatalf("the detection entry was not removed: %d left", left)
	}
}

func TestDetectTSMProvider_NoConfigfs(t *testing.T) {
	// A plain directory makes the entry but has no provider attribute; a
	// missing directory makes no entry. Both say what the host lacks.
	if _, err := DetectTSMProvider(t.TempDir()); err == nil || !strings.Contains(err.Error(), "configfs-tsm") {
		t.Fatalf("a plain directory passed as configfs-tsm: %v", err)
	}
	if _, err := DetectTSMProvider(t.TempDir() + "/absent"); err == nil || !strings.Contains(err.Error(), "not a confidential VM") {
		t.Fatalf("a missing directory: %v", err)
	}
}

func TestFamilyForTSMProvider(t *testing.T) {
	if f, err := FamilyForTSMProvider("sev_guest"); err != nil || f != ProviderGCPSEVSNP {
		t.Fatalf("sev_guest: %q %v", f, err)
	}
	if f, err := FamilyForTSMProvider("tdx_guest"); err != nil || f != ProviderGCPTDX {
		t.Fatalf("tdx_guest: %q %v", f, err)
	}
	if _, err := FamilyForTSMProvider("arm_cca_guest"); err == nil || !strings.Contains(err.Error(), "Arm CCA") {
		t.Fatalf("arm_cca_guest must be refused by name: %v", err)
	}
	if _, err := FamilyForTSMProvider("cove_guest"); err == nil || !strings.Contains(err.Error(), `"cove_guest"`) {
		t.Fatalf("an unknown family must be refused by name: %v", err)
	}
}

func TestResolveAuto_OnThisHost(t *testing.T) {
	// Off a confidential VM the answer is a refusal that names the lack;
	// on one (the hardware kits) it is the family. Both are fine here.
	family, name, err := ResolveAuto("")
	if err == nil && family == "" {
		t.Fatalf("ResolveAuto succeeded with no family (%q)", name)
	}
	if err != nil && !strings.Contains(err.Error(), "configfs-tsm") {
		t.Fatalf("ResolveAuto failed without naming configfs-tsm: %v", err)
	}
	available, reason := Capability(ProviderAuto)
	if available != (err == nil) || !strings.HasPrefix(reason, "auto: ") {
		t.Fatalf("Capability(auto) = %v %q", available, reason)
	}
}
