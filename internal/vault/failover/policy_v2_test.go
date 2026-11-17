// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// v2Policy is testPolicy with the standby's own sentinel named: its key,
// and the simulated TEE its records must carry a report from.
func v2Policy(primarySentinel, standbySentinel, attestor crypto.SuitePublicKey) Policy {
	p := testPolicy(primarySentinel)
	p.Standby.Sentinel = &StandbySentinel{
		PublicKey:         standbySentinel.Bytes,
		Alg:               crypto.RecordAlg(standbySentinel.Suite),
		Measurements:      []string{hex.EncodeToString(bytes.Repeat([]byte{0x6b}, 32))},
		AttestorPublicKey: attestor.Bytes,
	}
	return p
}

// A policy that names the standby's sentinel is a v2 policy, the section
// under the operator's signature; one that does not is the v1 it always
// was.
func TestPolicyV2NamesTheStandbysSentinel(t *testing.T) {
	opPub, op := operatorKey(t)
	pPub, _ := operatorKey(t)
	sPub, _ := operatorKey(t)
	aPub, _ := operatorKey(t)

	signed, err := Sign(v2Policy(pPub, sPub, aPub), op)
	must(t, err)
	if signed.Schema != SchemaV2 {
		t.Fatalf("schema %q", signed.Schema)
	}
	raw, err := json.Marshal(signed)
	must(t, err)
	got, err := Parse(raw, opPub, "operator-1")
	must(t, err)
	pub, id, ok := got.StandbySentinel()
	if !ok || !bytes.Equal(pub.Bytes, sPub.Bytes) || id != sentinel.KeyID(sPub) {
		t.Fatalf("standby sentinel %v %s %v", pub, id, ok)
	}
	if _, primaryID := got.Sentinel(); primaryID == id || primaryID != sentinel.KeyID(pPub) {
		t.Fatalf("the primary's sentinel reads as %s", primaryID)
	}

	// Another key in the section is another policy: the signature is over it.
	other, _ := operatorKey(t)
	edited := signed
	section := *signed.Standby.Sentinel
	section.PublicKey = other.Bytes
	edited.Standby.Sentinel = &section
	rawEdited, err := json.Marshal(edited)
	must(t, err)
	if _, err := Parse(rawEdited, opPub, "operator-1"); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("edited standby sentinel: %v", err)
	}

	// On hardware the section holds a key and measurements, and no attestation key.
	hw := v2Policy(pPub, sPub, aPub)
	hw.Standby.Kind, hw.Standby.Measurements = string(tee.ProviderGCPSEVSNP), []string{strings.Repeat("ab", 48)}
	hw.Standby.Sentinel.Measurements, hw.Standby.Sentinel.AttestorPublicKey = []string{strings.Repeat("ab", 48)}, nil
	_, err = Sign(hw, op)
	must(t, err)

	// Without the section the policy is v1 and has no such field.
	v1, err := Sign(testPolicy(pPub), op)
	must(t, err)
	rawV1, err := json.Marshal(v1)
	must(t, err)
	if v1.Schema != Schema || bytes.Contains(rawV1, []byte(`"sentinel":`)) {
		t.Fatalf("a policy without the section: schema %q, %s", v1.Schema, rawV1)
	}
	if _, _, ok := v1.StandbySentinel(); ok {
		t.Fatal("a v1 policy names a standby sentinel")
	}
}

// The section is refused by name, when the policy is signed and when it is
// read — there before the signature is looked at.
func TestPolicyV2Validation(t *testing.T) {
	opPub, op := operatorKey(t)
	pPub, _ := operatorKey(t)
	sPub, _ := operatorKey(t)
	aPub, _ := operatorKey(t)
	onHardware := func(p *Policy) {
		p.Standby.Kind, p.Standby.Measurements = string(tee.ProviderGCPSEVSNP), []string{strings.Repeat("ab", 48)}
		p.Standby.Sentinel.Measurements = []string{strings.Repeat("ab", 48)}
	}
	for name, tc := range map[string]struct {
		mutate func(*Policy)
		want   string
	}{
		"v1 with the section":    {func(p *Policy) { p.Schema = Schema }, "standby.sentinel needs schema"},
		"v2 without the section": {func(p *Policy) { p.Schema, p.Standby.Sentinel = SchemaV2, nil }, "names the standby's sentinel in standby.sentinel"},
		"short key":              {func(p *Policy) { p.Standby.Sentinel.PublicKey = sPub.Bytes[:31] }, "public_key must be 32 bytes"},
		"the primary's key":      {func(p *Policy) { p.Standby.Sentinel.PublicKey = pPub.Bytes }, "is the primary's"},
		"unknown suite":          {func(p *Policy) { p.Standby.Sentinel.Alg = "rot13" }, "standby sentinel alg"},
		"no measurement":         {func(p *Policy) { p.Standby.Sentinel.Measurements = nil }, "a pinned standby sentinel needs at least one measurement"},
		"upper-case hex": {func(p *Policy) {
			p.Standby.Sentinel.Measurements = []string{strings.ToUpper(p.Standby.Sentinel.Measurements[0])}
		}, "standby sentinel measurement"},
		"simulated, no attestation key": {func(p *Policy) { p.Standby.Sentinel.AttestorPublicKey = nil }, "a simulated standby sentinel is pinned by its attestation key"},
		"hardware, an attestation key":  {onHardware, "standby sentinel has no attestation key to pin"},
	} {
		p := v2Policy(pPub, sPub, aPub)
		tc.mutate(&p)
		if _, err := Sign(p, op); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s, signing: %v, want %q", name, err, tc.want)
		}

		signed, err := Sign(v2Policy(pPub, sPub, aPub), op)
		must(t, err)
		tc.mutate(&signed)
		raw, err := json.Marshal(signed)
		must(t, err)
		if _, err := Parse(raw, opPub, "operator-1"); err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "does not verify") {
			t.Errorf("%s, reading: %v, want %q", name, err, tc.want)
		}
	}
}

// The policies on record were signed before v2 existed. Read by this
// build, each is still the policy its failover was recorded under: it
// hashes to the digest in the run's report.
func TestRecordedV1PoliciesAreReadAsTheyWere(t *testing.T) {
	root := filepath.Join("..", "..", "..", "scripts", "hardware-test")
	for _, run := range []string{
		"training-continuity/evidence/20261111T135725Z/standby", // the primary pinned, the gate EXACT (C61)
		"failover-region-loss/evidence/20261024T000020Z/authority",
		"failover-tdx/evidence/20261023T223033Z/authority",
		"failover-cgpu/evidence/20261023T233916Z/authority",
	} {
		dir := filepath.Join(root, filepath.FromSlash(run))
		raw, err := os.ReadFile(filepath.Join(dir, "failover-policy.json"))
		must(t, err)
		p, err := decode(raw)
		must(t, err)
		report, err := os.ReadFile(filepath.Join(dir, "report.json"))
		must(t, err)
		var recorded struct {
			PolicySHA256 string `json:"policy_sha256"`
		}
		must(t, json.Unmarshal(report, &recorded))
		if got := hex.EncodeToString(p.Digest()); recorded.PolicySHA256 == "" || got != recorded.PolicySHA256 {
			t.Errorf("%s: this build reads the policy as %s; its failover was recorded under %q", run, got, recorded.PolicySHA256)
		}
		if _, _, ok := p.StandbySentinel(); ok || p.Schema != Schema {
			t.Errorf("%s: schema %q, standby sentinel %v", run, p.Schema, ok)
		}
	}
}
