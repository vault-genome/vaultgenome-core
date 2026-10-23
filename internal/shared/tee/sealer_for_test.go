// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseSealerMode(t *testing.T) {
	for in, want := range map[string]SealerMode{"": SealerModeAuto, "auto": SealerModeAuto, " TEE ": SealerModeTEE, "tpm2": SealerModeTPM2} {
		got, err := ParseSealerMode(in)
		if err != nil || got != want {
			t.Fatalf("ParseSealerMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseSealerMode("hsm"); err == nil || !strings.Contains(err.Error(), "want auto, tee or tpm2") {
		t.Fatalf("an unknown mode: %v", err)
	}
}

// The sealer by what the host has: the TEE's own key on SEV-SNP, the TPM
// 2.0 on TDX and Azure, the simulated key off hardware; tpm2 anywhere; tee
// refused where the TEE has no key of its own.
func TestSealerKindForProvider(t *testing.T) {
	for _, tc := range []struct {
		p    Provider
		mode SealerMode
		want SealerKind
		err  string
	}{
		{ProviderGCPSEVSNP, SealerModeAuto, SealerKindSEVDerivedKey, ""},
		{ProviderGCPSEVSNP, "", SealerKindSEVDerivedKey, ""},
		{ProviderGCPSEVSNP, SealerModeTEE, SealerKindSEVDerivedKey, ""},
		{ProviderGCPSEVSNP, SealerModeTPM2, SealerKindTPM2, ""},
		{ProviderGCPTDX, SealerModeAuto, SealerKindTPM2, ""},
		{ProviderGCPTDX, SealerModeTPM2, SealerKindTPM2, ""},
		{ProviderGCPTDX, SealerModeTEE, "", "no sealing key of its own"},
		{ProviderAzureCGPU, SealerModeAuto, SealerKindTPM2, ""},
		{ProviderAzureCGPU, SealerModeTEE, "", "set tee.sealer to tpm2 or auto"},
		{ProviderSimulated, SealerModeAuto, SealerKindSimulated, ""},
		{ProviderSimulated, SealerModeTEE, SealerKindSimulated, ""},
		{ProviderSimulated, SealerModeTPM2, SealerKindTPM2, ""},
		{ProviderAWSNitro, SealerModeAuto, "", "no sealer in this build"},
	} {
		got, err := SealerKindForProvider(tc.p, tc.mode)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("%s/%s: err %v, want %q", tc.p, tc.mode, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("%s/%s = %q, %v; want %q", tc.p, tc.mode, got, err, tc.want)
		}
	}
	if k, err := SealerKindFor(&GCPTDXProducer{}, SealerModeAuto); err != nil || k != SealerKindTPM2 {
		t.Fatalf("SealerKindFor(TDX producer) = %q %v", k, err)
	}
}

func TestSealerFor_ModeSelectsTheSealer(t *testing.T) {
	sim, err := NewSimulated([]byte("sealer-test"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, closer, kind, err := SealerFor(sim, SealerOptions{})
	if err != nil || kind != SealerKindSimulated || closer != nil || s != Sealer(sim) {
		t.Fatalf("auto on the simulated TEE: kind=%q closer=%v err=%v", kind, closer, err)
	}
	s, closer, kind, err = SealerFor(sim, SealerOptions{Mode: SealerModeTPM2, VTPMSealPCRs: "sha256:0,7"})
	if err != nil || kind != SealerKindTPM2 || closer != nil {
		t.Fatalf("tpm2 on any host: kind=%q closer=%v err=%v", kind, closer, err)
	}
	if _, ok := s.(*VTPMSealer); !ok {
		t.Fatalf("tpm2 mode built %T, want *VTPMSealer", s)
	}
	if _, _, _, err := SealerFor(sim, SealerOptions{Mode: SealerModeTPM2, VTPMSealPCRs: "sha1:0"}); err == nil {
		t.Fatal("a bad PCR selection was accepted")
	}
}

// A sealed file names its sealer; one named for another sealer is refused
// before the sealer is asked; a file from before tee.sealer still opens.
func TestSealedSecret_NamesItsSealer(t *testing.T) {
	sim, err := NewSimulated([]byte("sealer-test"), bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("thirty-two bytes of a signing seed!")[:32]
	m := sim.Measurement()
	raw, err := SealSecretWith(plain, sim, SealerKindSimulated, ProviderSimulated, m, "keys.authority_signing.seed_path")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseSealedSecret(raw)
	if err != nil || s.Sealer != string(SealerKindSimulated) {
		t.Fatalf("the file does not name its sealer: %+v %v", s, err)
	}
	back, err := OpenSecretWith(raw, sim, SealerKindSimulated, ProviderSimulated, "keys.authority_signing.seed_path")
	if err != nil || !bytes.Equal(back, plain) {
		t.Fatalf("open with the same sealer: %v", err)
	}
	if _, err := OpenSecretWith(raw, sim, SealerKindTPM2, ProviderSimulated, "keys.authority_signing.seed_path"); err == nil || !strings.Contains(err.Error(), "sealed with simulated; this host's sealer is tpm2") {
		t.Fatalf("a file sealed one way opened as another: %v", err)
	}
	// Legacy: no sealer named in the file, the host's kind unknown or known.
	legacy, err := SealSecret(plain, sim, ProviderSimulated, m, "keys.session_sealing.material_path")
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := ParseSealedSecret(legacy); l.Sealer != "" {
		t.Fatalf("SealSecret named a sealer: %+v", l)
	}
	for _, kind := range []SealerKind{"", SealerKindSimulated, SealerKindTPM2} {
		if back, err := OpenSecretWith(legacy, sim, kind, ProviderSimulated, "keys.session_sealing.material_path"); err != nil || !bytes.Equal(back, plain) {
			t.Fatalf("a legacy file did not open under kind %q: %v", kind, err)
		}
	}
	// The kind is bound into the seal: a file whose sealer field is edited does not open.
	tampered := bytes.Replace(raw, []byte(`"sealer": "simulated"`), []byte(`"sealer": "tpm2"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("the sealer field was not where the test expects")
	}
	if _, err := OpenSecretWith(tampered, sim, SealerKindTPM2, ProviderSimulated, "keys.authority_signing.seed_path"); err == nil {
		t.Fatal("a file with its sealer field edited opened")
	}
}
