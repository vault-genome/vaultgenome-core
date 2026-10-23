// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/fips140"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// signedChainUnder writes a bbolt audit file of n events, chain-linked
// and signed under suite, and returns the file, the audit key's PEM (as
// `sagvd identity` prints it) and its kid.
func signedChainUnder(t *testing.T, n int, suite crypto.SignatureSuite) (string, []byte, ids.KeyID) {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.bbolt")
	ks := keys.NewInMemoryStore(shared_time.NewSystemClock())
	kid := ids.KeyID("audit-" + string(suite))
	vk, err := ks.GenerateSigningSuite(kid, keys.PurposeSigningAudit, suite)
	require.NoError(t, err)
	pubPEM, err := crypto.PublicKeyPEMSuite(suite, vk.PublicKey)
	require.NoError(t, err)
	bs, err := store.Open(auditPath)
	require.NoError(t, err)
	c := chain.NewInMemoryChain()
	t0 := time.Date(2026, 10, 22, 1, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		evt := audit_event.AuditEvent{
			SchemaVersion: audit_event.SchemaVersionCurrent,
			EventID:       ids.AuditEventID(fmt.Sprintf("evt-%04d", i+1)),
			Kind:          audit_event.KindRequestReceived,
			OccurredAt:    t0.Add(time.Duration(i) * time.Second),
			SessionID:     ids.SessionID("sess-1"),
			RequestID:     ids.RequestID(fmt.Sprintf("req-%d", i)),
			Payload:       []byte(`{"suite":"` + string(suite) + `"}`),
			SigningKeyID:  kid,
		}
		signed, err := c.Append(evt, ks)
		require.NoError(t, err)
		require.NoError(t, bs.Append(signed))
	}
	require.NoError(t, bs.Close())
	return auditPath, pubPEM, kid
}

// TestAuditVerifyCmd_VerifiesUnderEverySuite replays a chain signed under
// each suite with the key's PEM alone — the third party's step — and
// refuses the chain under a key of another suite before any signature is
// checked. On the FIPS module v1.0.0 ml-dsa-87 is refused with the
// module's reason.
func TestAuditVerifyCmd_VerifiesUnderEverySuite(t *testing.T) {
	t.Parallel()
	for _, suite := range crypto.Suites() {
		suite := suite
		t.Run(string(suite), func(t *testing.T) {
			t.Parallel()
			if err := suite.Available(); err != nil {
				require.True(t, fips140.Enabled(), "only the FIPS module lacks a suite: %v", err)
				require.Contains(t, err.Error(), "unavailable in FIPS 140-3 Go Cryptographic Module")
				_, err = keys.NewInMemoryStore(nil).GenerateSigningSuite("k", keys.PurposeSigningAudit, suite)
				require.Error(t, err)
				return
			}
			auditPath, pubPEM, kid := signedChainUnder(t, 4, suite)
			dir := t.TempDir()
			pubPath := filepath.Join(dir, "audit.pem")
			require.NoError(t, os.WriteFile(pubPath, pubPEM, 0o600))

			var stdout, stderr bytes.Buffer
			rc := auditCmd([]string{"verify", "--audit", auditPath, "--audit-pubkey", pubPath, "--audit-kid", string(kid), "--json"}, &stdout, &stderr)
			require.Equal(t, 0, rc, stderr.String())
			var res auditVerifyResult
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &res))
			require.True(t, res.OK)
			require.Equal(t, string(suite), res.Suite)
			require.Equal(t, 4, res.EventCount)

			stdout.Reset()
			stderr.Reset()
			rc = auditCmd([]string{"verify", "--audit", auditPath, "--audit-pubkey", pubPath, "--audit-kid", string(kid)}, &stdout, &stderr)
			require.Equal(t, 0, rc, stderr.String())
			require.Contains(t, stdout.String(), "4 events verified under "+string(suite)+", tip ")

			// A key of another suite: the records' alg and the key's suite
			// disagree, and the chain is refused on that — not on a
			// signature that happens not to verify.
			other := crypto.SuiteEd25519
			if suite == crypto.SuiteEd25519 {
				other = crypto.SuiteECDSAP384SHA384
			}
			otherKey, err := crypto.GenerateSigningKey(other, nil)
			require.NoError(t, err)
			otherPEM, err := crypto.PublicKeyPEMSuite(other, otherKey.PublicKeyBytes())
			require.NoError(t, err)
			otherPath := filepath.Join(dir, "other.pem")
			require.NoError(t, os.WriteFile(otherPath, otherPEM, 0o600))
			stdout.Reset()
			stderr.Reset()
			rc = auditCmd([]string{"verify", "--audit", auditPath, "--audit-pubkey", otherPath, "--audit-kid", string(kid), "--json"}, &stdout, &stderr)
			require.Equal(t, 4, rc, stderr.String())
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &res))
			require.False(t, res.OK)
			require.Equal(t, string(other), res.Suite)
			require.Contains(t, res.Error, "does not match the key's suite")
		})
	}
}
