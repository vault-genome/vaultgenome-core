// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// The destination pins only a source authority whose suite its profile
// accepts (ADR 0031, part three).
func TestSourceAuthority_TheProfileDecidesWhatIsPinned(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name string, suite crypto.SignatureSuite) string {
		key, err := crypto.GenerateSigningKey(suite, nil)
		require.NoError(t, err)
		pemBytes, err := key.Public().PEM()
		require.NoError(t, err)
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, pemBytes, 0o644))
		return p
	}
	edPath, ecPath := write("ed.pem", crypto.SuiteEd25519), write("ec.pem", crypto.SuiteECDSAP384SHA384)
	for _, tc := range []struct {
		profile string
		path    string
		ok      bool
	}{
		{"general", edPath, true}, {"general", ecPath, true},
		{"fips", edPath, true}, {"fips", ecPath, true},
		{"cnsa", edPath, false}, {"cnsa", ecPath, true},
	} {
		pol, err := kms.NewSignaturePolicyFromNames(tc.profile, "")
		require.NoError(t, err)
		_, err = loadSourceAuthorityResolver(SourceAuthorityConfig{KeyID: "authority-1", PublicKeyPath: tc.path}, pol, shared_time.NewSystemClock())
		if tc.ok {
			require.NoError(t, err, "%s %s", tc.profile, tc.path)
		} else {
			require.Error(t, err, "%s %s", tc.profile, tc.path)
			require.Contains(t, err.Error(), "source authority key authority-1 is a ed25519 key, which the cnsa profile does not accept")
		}
	}
	pol, err := CryptoConfig{Profile: "cnsa"}.SignaturePolicy()
	require.NoError(t, err)
	require.Equal(t, []string{"ecdsa-p384-sha384", "ml-dsa-87"}, pol.AcceptIDs())
}
