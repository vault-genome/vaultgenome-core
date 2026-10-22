// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package release_decision

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

// suiteFixture is a release decision signed under one suite, written by
// this tree once (VG_UPDATE_FIXTURES=1) and verified from the file in
// every run (ADR 0031): the authority's record, signed over its cover
// bytes, as the audit event is signed over its hash.
type suiteFixture struct {
	Suite        string          `json:"suite"`
	KeyID        string          `json:"kid"`
	PublicKeyPEM string          `json:"public_key_pem"`
	WrittenBy    string          `json:"written_by"`
	Decision     ReleaseDecision `json:"decision"`
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
	kid := ids.KeyID("authority-fixture-" + string(suite))
	vk, err := ks.GenerateSigningSuite(kid, keys.PurposeSigningAuthority, suite)
	require.NoError(t, err)
	pemBytes, err := crypto.PublicKeyPEMSuite(suite, vk.PublicKey)
	require.NoError(t, err)
	d := validPassFixture()
	d.DecidedAt = time.Date(2026, 10, 22, 2, 0, 0, 0, time.UTC)
	d.SigningKeyID = kid
	d.Signature = nil
	require.NoError(t, d.SignWith(ks))
	require.NoError(t, d.Validate())
	fx := suiteFixture{
		Suite:        string(suite),
		KeyID:        string(kid),
		PublicKeyPEM: string(pemBytes),
		WrittenBy:    "vaultgenome-core, " + runtime.Version() + ", " + time.Now().UTC().Format("2006-01-02"),
		Decision:     d,
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
			if suite == crypto.SuiteEd25519 {
				require.NotContains(t, string(raw), `"alg"`)
			} else {
				require.Contains(t, string(raw), `"alg": "`+string(suite)+`"`)
			}

			gotSuite, pub, err := crypto.ParsePublicKeyPEM([]byte(fx.PublicKeyPEM))
			if avail := suite.Available(); avail != nil {
				require.True(t, fips140.Enabled())
				require.Contains(t, avail.Error(), "unavailable in FIPS 140-3 Go Cryptographic Module")
				if err != nil {
					return
				}
				vk := keys.VerifyingKey{KeyID: ids.KeyID(fx.KeyID), Purpose: keys.PurposeSigningAuthority, Suite: gotSuite, PublicKey: pub}
				err = fx.Decision.VerifySignature(fixtureResolver{vk: vk})
				require.Error(t, err)
				require.Contains(t, err.Error(), "unavailable in FIPS 140-3 Go Cryptographic Module")
				return
			}
			require.NoError(t, err)
			require.Equal(t, suite, gotSuite)
			r := fixtureResolver{vk: keys.VerifyingKey{KeyID: ids.KeyID(fx.KeyID), Purpose: keys.PurposeSigningAuthority, Suite: suite, PublicKey: pub}}
			require.NoError(t, fx.Decision.Validate())
			require.NoError(t, fx.Decision.VerifySignature(r))
			require.Equal(t, crypto.RecordAlg(suite), fx.Decision.Alg)

			tampered := fx.Decision
			tampered.Release = !tampered.Release
			require.Error(t, tampered.VerifySignature(r))
			swapped := fx.Decision
			if suite == crypto.SuiteEd25519 {
				swapped.Alg = crypto.SuiteMLDSA87
			} else {
				swapped.Alg = ""
			}
			require.Error(t, swapped.VerifySignature(r))
		})
	}
}
