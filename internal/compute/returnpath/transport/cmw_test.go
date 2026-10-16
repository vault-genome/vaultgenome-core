// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"encoding/json"
	"strings"
	"testing"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

func TestCMWRecord_RoundTripIsTheJSONRecordOfRFC9999(t *testing.T) {
	r, err := NewEvidenceRecord("application/vnd.veraison.tsm-report+json", []byte(`{"outblob":"AA","provider":"sev_guest"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	// [type, base64url(value) without padding, ind]; the evidence bit is 2 → 4.
	want := `["application/vnd.veraison.tsm-report+json","eyJvdXRibG9iIjoiQUEiLCJwcm92aWRlciI6InNldl9ndWVzdCJ9",4]`
	if string(b) != want {
		t.Fatalf("record:\n got %s\nwant %s", b, want)
	}
	var back CMWRecord
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Type != r.Type || string(back.Value) != string(r.Value) || back.Ind != CMWIndEvidence || !back.IsEvidence() {
		t.Fatalf("round trip: %+v", back)
	}
	// A record without the indicator is read, and may be Evidence by context.
	var two CMWRecord
	if err := json.Unmarshal([]byte(`["application/x-test","AQID"]`), &two); err != nil {
		t.Fatal(err)
	}
	if two.Ind != 0 || !two.IsEvidence() || string(two.Value) != "\x01\x02\x03" {
		t.Fatalf("two-member record: %+v", two)
	}
	// An indicator without the evidence bit is not Evidence.
	var rv CMWRecord
	if err := json.Unmarshal([]byte(`["application/x-test","AQID",1]`), &rv); err != nil {
		t.Fatal(err)
	}
	if rv.IsEvidence() {
		t.Fatal("reference-values indicator read as evidence")
	}
	// The record inside a frame field marshals as a nested array, not an object.
	type frame struct {
		Evidence CMWRecord `json:"server_evidence"`
	}
	fb, err := json.Marshal(frame{Evidence: r})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(fb), `{"server_evidence":["application/vnd.veraison.tsm-report+json","`) {
		t.Fatalf("frame: %s", fb)
	}
}

func TestCMWRecord_RefusesWhatIsNotARecord(t *testing.T) {
	cases := map[string]string{
		"not an array":            `{"type":"a/b","value":"AQ"}`,
		"one member":              `["a/b"]`,
		"four members":            `["a/b","AQ",4,0]`,
		"type not a string":       `[1,"AQ"]`,
		"type not a media type":   `["evidence","AQ"]`,
		"type with a space":       `["a/b c","AQ"]`,
		"value padded":            `["a/b","AQ=="]`,
		"value standard alphabet": `["a/b","+/8"]`,
		"value not base64":        `["a/b","!!!"]`,
		"value empty":             `["a/b",""]`,
		"indicator zero":          `["a/b","AQ",0]`,
		"indicator 32":            `["a/b","AQ",32]`,
		"indicator negative":      `["a/b","AQ",-1]`,
		"indicator a string":      `["a/b","AQ","4"]`,
		"raw bytes, the old wire": `"AQID"`,
	}
	for name, in := range cases {
		var r CMWRecord
		err := json.Unmarshal([]byte(in), &r)
		if err == nil {
			t.Fatalf("%s: accepted %s as %+v", name, in, r)
		}
		if shared_errors.CodeOf(err) != CodeProtocolViolation {
			t.Fatalf("%s: code %v, want CodeProtocolViolation: %v", name, shared_errors.CodeOf(err), err)
		}
	}
	if _, err := NewEvidenceRecord("", []byte{1}); err == nil {
		t.Fatal("empty type accepted")
	}
	if _, err := NewEvidenceRecord("a/b", nil); err == nil {
		t.Fatal("empty value accepted")
	}
	if _, err := json.Marshal(CMWRecord{Type: "a/b", Value: []byte{1}, Ind: 64}); err == nil {
		t.Fatal("indicator 64 marshalled")
	}
}
