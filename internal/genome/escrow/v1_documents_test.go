// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package escrow

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// What 0.7.0 wrote opens on this build: the escrow envelopes, sealed key
// files and recovery envelopes in testdata/escrow-v1-documents.json were
// written by the 0.7.0 tree (b0ee2a5) under the v1 suites, with keys
// whose PEM headers say v1. This build reads those keys as the current
// suite of their family, opens every document by the suite it records,
// and writes v2 with the same key (ADR 0030, 3f). Under fips140=only the
// v1 suites name their refusal instead.
func TestV1Documents_OpenOnThisBuild(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/escrow-v1-documents.json")
	require.NoError(t, err)
	var fx []struct {
		Suite           string          `json:"suite"`
		KeyID           string          `json:"key_id"`
		DEKHex          string          `json:"dek_hex"`
		EscrowPrivPEM   string          `json:"escrow_private_pem"`
		RecoveryPrivPEM string          `json:"recovery_private_pem"`
		Envelope        json.RawMessage `json:"envelope"`
		Sealed          json.RawMessage `json:"sealed_key"`
		Recovery        json.RawMessage `json:"recovery"`
		TEEDescriptor   string          `json:"tee_descriptor"`
		TEESeedHex      string          `json:"tee_seed_hex"`
	}
	require.NoError(t, json.Unmarshal(raw, &fx))
	require.Len(t, fx, 5)
	for _, f := range fx {
		t.Run(f.Suite, func(t *testing.T) {
			t.Parallel()
			v1 := kms.Suite(f.Suite)
			require.True(t, v1.ReadOnly())
			require.Contains(t, f.EscrowPrivPEM, "Suite: "+f.Suite, "the 0.7.0 PEM names the v1 suite")
			if !v1.Latest().Available() {
				t.Skip("the family is unavailable under fips140=only (X25519 inside)")
			}
			esc, err := ParsePrivate([]byte(f.EscrowPrivPEM))
			require.NoError(t, err)
			require.Equal(t, v1.Latest(), esc.Suite(), "a key belongs to its family; this build labels it with the suite it writes")
			rec, err := ParsePrivate([]byte(f.RecoveryPrivPEM))
			require.NoError(t, err)
			dek, err := hex.DecodeString(f.DEKHex)
			require.NoError(t, err)

			var env Envelope
			require.NoError(t, json.Unmarshal(f.Envelope, &env))
			require.Equal(t, f.Suite, env.Suite, "the envelope records the suite it was wrapped under")
			got, err := Open(env, esc)
			if shared_crypto.FIPSOnly() {
				require.ErrorContains(t, err, "cannot open under fips140=only")
			} else {
				require.NoError(t, err)
				require.Equal(t, dek, got)
			}

			sealed, err := ParseSealed(f.Sealed)
			require.NoError(t, err)
			require.Equal(t, f.Suite, sealed.Suite)
			pub, err := sealed.PublicKey()
			require.NoError(t, err, "the sealed file's v1 suite is of the key's family")
			require.True(t, pub.Equal(esc.PublicKey()))
			seed, _ := hex.DecodeString(f.TEESeedHex)
			host, err := tee.NewSimulated([]byte(f.TEEDescriptor), seed)
			require.NoError(t, err)
			opened, err := sealed.Open(host, tee.ProviderSimulated, host.Measurement())
			require.NoError(t, err, "the sealed key file opens under the AAD it was sealed with (the v1 suite string)")
			require.True(t, opened.Equal(esc))

			recov, err := ParseRecovery(f.Recovery)
			require.NoError(t, err)
			require.Equal(t, f.Suite, recov.RecoverySuite)
			recovered, err := recov.Open(rec)
			if shared_crypto.FIPSOnly() {
				require.ErrorContains(t, err, "cannot open under fips140=only")
				return
			}
			require.NoError(t, err)
			require.True(t, recovered.Equal(esc))

			// the same key writes v2 — and this build never writes v1
			env2, err := Seal(dek, f.KeyID, esc.PublicKey())
			require.NoError(t, err)
			require.Equal(t, string(v1.Latest()), env2.Suite)
			got2, err := Open(env2, esc)
			require.NoError(t, err)
			require.Equal(t, dek, got2)
			require.False(t, bytes.Contains(env2.Ciphertext, dek))
			require.True(t, strings.Contains(string(PrivatePEM(esc)), "Suite: "+string(v1.Latest())), "a re-encoded key carries the current suite")
		})
	}
}
