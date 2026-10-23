// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_event

import (
	"crypto/fips140"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// suiteFixture is a chain of events signed under one suite, written by
// this tree once (VG_UPDATE_FIXTURES=1) and verified from the file in
// every run: the proof that a record a release wrote is a record a
// release reads, under each suite of ADR 0031.
type suiteFixture struct {
	Suite        string       `json:"suite"`
	KeyID        string       `json:"kid"`
	PublicKeyPEM string       `json:"public_key_pem"`
	WrittenBy    string       `json:"written_by"`
	Events       []AuditEvent `json:"events"`
}

type fixtureResolver struct{ vk keys.VerifyingKey }

func (r fixtureResolver) Resolve(kid ids.KeyID, want keys.Purpose) (keys.VerifyingKey, error) {
	if kid != r.vk.KeyID || want != r.vk.Purpose {
		return keys.VerifyingKey{}, fmt.Errorf("fixture: no key %q for %s", kid, want)
	}
	return r.vk, nil
}

func fixturePath(suite crypto.SignatureSuite) string {
	return filepath.Join("testdata", "suites", string(suite)+".json")
}

func writeSuiteFixture(t *testing.T, suite crypto.SignatureSuite) {
	t.Helper()
	require.NoError(t, suite.Available(), "fixtures are written on a build that has every suite")
	ks := keys.NewInMemoryStore(nil)
	kid := ids.KeyID("audit-fixture-" + string(suite))
	vk, err := ks.GenerateSigningSuite(kid, keys.PurposeSigningAudit, suite)
	require.NoError(t, err)
	pemBytes, err := crypto.PublicKeyPEMSuite(suite, vk.PublicKey)
	require.NoError(t, err)
	prev := make([]byte, HashSize)
	var events []AuditEvent
	t0 := time.Date(2026, 10, 22, 2, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		e := AuditEvent{
			SchemaVersion: SchemaVersionCurrent,
			EventID:       ids.AuditEventID(fmt.Sprintf("evt-%04d", i+1)),
			Kind:          KindRequestReceived,
			OccurredAt:    t0.Add(time.Duration(i) * time.Second),
			SessionID:     ids.SessionID("sess-0001"),
			RequestID:     ids.RequestID(fmt.Sprintf("req-%04d", i+1)),
			Payload:       []byte(`{"fixture":"` + string(suite) + `"}`),
			PrevHash:      prev,
			SigningKeyID:  kid,
		}
		require.NoError(t, e.SignWith(ks))
		require.NoError(t, e.Validate())
		events = append(events, e)
		prev = e.Hash
	}
	fx := suiteFixture{
		Suite:        string(suite),
		KeyID:        string(kid),
		PublicKeyPEM: string(pemBytes),
		WrittenBy:    "vaultgenome-core, " + runtime.Version() + ", " + time.Now().UTC().Format("2006-01-02"),
		Events:       events,
	}
	b, err := json.MarshalIndent(fx, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(fixturePath(suite)), 0o755))
	require.NoError(t, os.WriteFile(fixturePath(suite), append(b, '\n'), 0o644))
}

func TestSuiteFixtures_VerifyFromTheFile(t *testing.T) {
	for _, suite := range crypto.Suites() {
		suite := suite
		t.Run(string(suite), func(t *testing.T) {
			if os.Getenv("VG_UPDATE_FIXTURES") == "1" {
				writeSuiteFixture(t, suite)
			}
			raw, err := os.ReadFile(fixturePath(suite))
			require.NoError(t, err)
			var fx suiteFixture
			require.NoError(t, json.Unmarshal(raw, &fx))
			require.Equal(t, string(suite), fx.Suite)
			require.Len(t, fx.Events, 3)

			// The wire form: an ed25519 record carries no alg — its bytes
			// are the ones every earlier reader verifies; the other suites
			// name theirs.
			if suite == crypto.SuiteEd25519 {
				require.NotContains(t, string(raw), `"alg"`)
			} else {
				require.Contains(t, string(raw), `"alg": "`+string(suite)+`"`)
			}

			gotSuite, pub, err := crypto.ParsePublicKeyPEM([]byte(fx.PublicKeyPEM))
			if avail := suite.Available(); avail != nil {
				// The FIPS module v1.0.0 has no ML-DSA: the fixture is
				// refused with the module's reason, never passed silently.
				require.True(t, fips140.Enabled())
				require.Contains(t, avail.Error(), "unavailable in FIPS 140-3 Go Cryptographic Module")
				if err != nil {
					return
				}
				vk := keys.VerifyingKey{KeyID: ids.KeyID(fx.KeyID), Purpose: keys.PurposeSigningAudit, Suite: gotSuite, PublicKey: pub}
				err = fx.Events[0].VerifySignature(fixtureResolver{vk: vk})
				require.Error(t, err)
				require.Contains(t, err.Error(), "unavailable in FIPS 140-3 Go Cryptographic Module")
				return
			}
			require.NoError(t, err)
			require.Equal(t, suite, gotSuite)
			r := fixtureResolver{vk: keys.VerifyingKey{KeyID: ids.KeyID(fx.KeyID), Purpose: keys.PurposeSigningAudit, Suite: suite, PublicKey: pub}}

			prev := make([]byte, HashSize)
			for i := range fx.Events {
				e := &fx.Events[i]
				require.Equal(t, prev, e.PrevHash, "event %d links to the one before", i)
				require.NoError(t, e.Validate())
				require.NoError(t, e.VerifySignature(r), "event %d", i)
				require.Equal(t, crypto.RecordAlg(suite), e.Alg)
				prev = e.Hash
			}

			// A changed payload breaks the hash; a changed signature breaks
			// the signature; a swapped alg breaks both.
			tampered := fx.Events[1]
			tampered.Payload = append([]byte(nil), tampered.Payload...)
			tampered.Payload[0] ^= 0x01
			require.Error(t, tampered.VerifySignature(r))
			forged := fx.Events[1]
			forged.Signature = append([]byte(nil), forged.Signature...)
			forged.Signature[0] ^= 0x01
			require.Error(t, forged.VerifySignature(r))
			swapped := fx.Events[1]
			if suite == crypto.SuiteEd25519 {
				swapped.Alg = crypto.SuiteECDSAP384SHA384
			} else {
				swapped.Alg = ""
			}
			require.Error(t, swapped.VerifySignature(r))
		})
	}
}
