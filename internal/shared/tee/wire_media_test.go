// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

func TestEvidenceMediaType_EveryFamilyHasOne_AutoHasNone(t *testing.T) {
	want := map[Provider]string{
		ProviderGCPSEVSNP:    MediaTypeTSMReportJSON,
		ProviderGCPTDX:       MediaTypeTSMReportJSON,
		ProviderSimulated:    MediaTypeSimulatedEvidence,
		ProviderAzureCGPU:    MediaTypeAzureCGPUEvidence,
		ProviderAzureSGX:     MediaTypeSGXQuote,
		ProviderIntelSGXDCAP: MediaTypeSGXQuote,
		ProviderAWSNitro:     MediaTypeNitroAttestationDocument,
	}
	for p, mt := range want {
		got, err := EvidenceMediaType(p)
		if err != nil || got != mt {
			t.Fatalf("%s: %q %v, want %q", p, got, err, mt)
		}
	}
	if _, err := EvidenceMediaType(ProviderAuto); err == nil {
		t.Fatal("auto has a media type")
	}
	if _, err := EvidenceMediaType(Provider("nothing")); err == nil {
		t.Fatal("an unknown provider has a media type")
	}
	// The TSM report types are ratsd's, letter for letter.
	if MediaTypeTSMReportJSON != "application/vnd.veraison.tsm-report+json" || MediaTypeTSMReportCBOR != "application/vnd.veraison.tsm-report+cbor" {
		t.Fatal("TSM report media types differ from ratsd's")
	}
}

func TestTSMReport_JSONIsRatsdsForm(t *testing.T) {
	r := TSMReport{OutBlob: []byte{0x01, 0x02, 0x03}, AuxBlob: []byte("certs"), Provider: "sev_guest"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	// Field names and base64url-without-padding as ratsd's tokens.TSMReport writes them.
	want := `{"auxblob":"Y2VydHM","outblob":"AQID","provider":"sev_guest"}`
	if string(b) != want {
		t.Fatalf("json:\n got %s\nwant %s", b, want)
	}
	var back TSMReport
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.OutBlob, r.OutBlob) || !bytes.Equal(back.AuxBlob, r.AuxBlob) || back.Provider != r.Provider {
		t.Fatalf("round trip: %+v", back)
	}
	// No auxblob: the field is omitted, as ratsd omits it.
	b2, _ := json.Marshal(TSMReport{OutBlob: []byte{9}, Provider: "tdx_guest"})
	if string(b2) != `{"outblob":"CQ","provider":"tdx_guest"}` {
		t.Fatalf("no auxblob: %s", b2)
	}
	// Mandatory fields.
	if _, err := json.Marshal(TSMReport{Provider: "sev_guest"}); err == nil {
		t.Fatal("report without outblob marshalled")
	}
	for _, in := range []string{`{"outblob":"AQ"}`, `{"provider":"sev_guest"}`, `{"outblob":"AQ==","provider":"x"}`, `[]`} {
		var x TSMReport
		if err := json.Unmarshal([]byte(in), &x); err == nil {
			t.Fatalf("%s decoded", in)
		}
	}
}

func TestWrapUnwrap_TheTwoEndsOfTheWire(t *testing.T) {
	report := []byte(strings.Repeat("r", 1184))
	aux := []byte("the certificate table")
	mt, value, err := WrapEvidence(ProviderGCPSEVSNP, Evidence(report), aux)
	if err != nil || mt != MediaTypeTSMReportJSON {
		t.Fatalf("wrap: %q %v", mt, err)
	}
	var tsm TSMReport
	if err := json.Unmarshal(value, &tsm); err != nil || tsm.Provider != "sev_guest" || !bytes.Equal(tsm.OutBlob, report) || !bytes.Equal(tsm.AuxBlob, aux) {
		t.Fatalf("the wrapped report: %+v %v", tsm, err)
	}
	ev, gotAux, err := UnwrapEvidence(ProviderGCPSEVSNP, mt, value)
	if err != nil || !bytes.Equal(ev, report) || !bytes.Equal(gotAux, aux) {
		t.Fatalf("unwrap: %v", err)
	}
	// TDX names its own provider.
	mt2, v2, err := WrapEvidence(ProviderGCPTDX, Evidence([]byte("quote")), nil)
	if err != nil || mt2 != MediaTypeTSMReportJSON || !strings.Contains(string(v2), `"provider":"tdx_guest"`) {
		t.Fatalf("tdx wrap: %s %v", v2, err)
	}
	// A TSM report from the other family is refused by name, even though the type matches.
	if _, _, err := UnwrapEvidence(ProviderGCPTDX, mt, value); err == nil || !strings.Contains(err.Error(), `from provider "sev_guest"`) || shared_errors.CodeOf(err) != shared_errors.CodeAttestationDenied {
		t.Fatalf("sev_guest report for a tdx verifier: %v", err)
	}
	// The other families pass their bytes through, under their type.
	mt3, v3, err := WrapEvidence(ProviderSimulated, Evidence([]byte("signed statement")), nil)
	if err != nil || mt3 != MediaTypeSimulatedEvidence || string(v3) != "signed statement" {
		t.Fatalf("simulated wrap: %q %s %v", mt3, v3, err)
	}
	ev3, aux3, err := UnwrapEvidence(ProviderSimulated, mt3, v3)
	if err != nil || string(ev3) != "signed statement" || aux3 != nil {
		t.Fatalf("simulated unwrap: %v", err)
	}
	// A type that is not the peer's family's is refused before anything is read.
	_, _, err = UnwrapEvidence(ProviderGCPSEVSNP, MediaTypeSimulatedEvidence, v3)
	if err == nil || !strings.Contains(err.Error(), "this peer verifier is gcp-sev-snp") || shared_errors.CodeOf(err) != shared_errors.CodeAttestationDenied {
		t.Fatalf("wrong type: %v", err)
	}
	// Empty evidence is refused on both ends.
	if _, _, err := WrapEvidence(ProviderGCPSEVSNP, nil, nil); err == nil {
		t.Fatal("wrapped nothing")
	}
	if _, _, err := UnwrapEvidence(ProviderSimulated, MediaTypeSimulatedEvidence, nil); err == nil {
		t.Fatal("unwrapped nothing")
	}
	// auto cannot be wrapped: it is not a family.
	if _, _, err := WrapEvidence(ProviderAuto, Evidence([]byte("x")), nil); err == nil {
		t.Fatal("auto wrapped")
	}
}
