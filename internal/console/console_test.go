// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package console

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// The binding separates every input: another challenge, another listener or
// another state is another nonce.
func TestBindingNonceSeparatesItsInputs(t *testing.T) {
	a, b, c := []byte("challenge"), []byte("certificate"), []byte("state")
	base := BindingNonce(a, b, c)
	require.Len(t, []byte(base), 64)
	require.NotEqual(t, base, BindingNonce([]byte("challengX"), b, c))
	require.NotEqual(t, base, BindingNonce(a, []byte("certificatX"), c))
	require.NotEqual(t, base, BindingNonce(a, b, []byte("statX")))
	require.Equal(t, base, BindingNonce(a, b, c))
}

func simulatedChip(t *testing.T) (*tee.Simulated, tee.Verifier) {
	t.Helper()
	chip, err := tee.NewSimulated([]byte("console-test"), bytes.Repeat([]byte{7}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	return chip, tee.NewSimulatedVerifier(chip.PublicKey(), chip.Measurement())
}

// A check verifies only for the challenge, the listener and the state the
// chip signed, and only for the measurement the verifier pins.
func TestVerifyCheck(t *testing.T) {
	chip, v := simulatedChip(t)
	challenge := bytes.Repeat([]byte{1}, NonceBytes)
	cert := []byte("the listener's certificate")
	state, err := json.Marshal(State{Schema: StateSchema, Version: "v-test", Provider: "simulated"})
	require.NoError(t, err)
	ev, err := chip.Quote(BindingNonce(challenge, cert, state))
	require.NoError(t, err)
	resp := CheckResponse{State: state, Evidence: ev}

	got, err := VerifyCheck(v, challenge, cert, resp)
	require.NoError(t, err)
	require.Equal(t, "v-test", got.State.Version)
	require.True(t, got.Measurement.Equal(chip.Measurement()))

	_, err = VerifyCheck(v, bytes.Repeat([]byte{2}, NonceBytes), cert, resp)
	require.Error(t, err, "an old answer for a new question")
	_, err = VerifyCheck(v, challenge, []byte("another listener"), resp)
	require.Error(t, err, "an answer made for another listener")
	forged := append([]byte(nil), state...)
	forged[len(forged)/2] ^= 1
	_, err = VerifyCheck(v, challenge, cert, CheckResponse{State: forged, Evidence: ev})
	require.Error(t, err, "one bit of the state")
	wrong := tee.NewSimulatedVerifier(chip.PublicKey(), bytes.Repeat([]byte{0xaa}, 32))
	_, err = VerifyCheck(wrong, challenge, cert, resp)
	require.Error(t, err, "the real chip against another pin")

	other, err := json.Marshal(State{Schema: "something else"})
	require.NoError(t, err)
	ev2, err := chip.Quote(BindingNonce(challenge, cert, other))
	require.NoError(t, err)
	_, err = VerifyCheck(v, challenge, cert, CheckResponse{State: other, Evidence: ev2})
	require.Error(t, err, "a state of another schema, even signed")
}

func signedChain(t *testing.T, n int) ([]audit_event.AuditEvent, keys.Resolver) {
	t.Helper()
	clock := shared_time.NewSystemClock()
	store := keys.NewInMemoryStore(clock)
	kid := ids.KeyID("audit-test")
	_, err := store.GenerateSigning(kid, keys.PurposeSigningAudit)
	require.NoError(t, err)
	prev := make([]byte, audit_event.HashSize)
	out := make([]audit_event.AuditEvent, 0, n)
	for i := range n {
		e := audit_event.AuditEvent{
			SchemaVersion: audit_event.SchemaVersionCurrent, EventID: ids.AuditEventID(hex.EncodeToString([]byte{byte(i + 1), 0, 0, 0})),
			Kind: audit_event.KindConsoleAction, OccurredAt: time.Date(2026, 10, 30, 12, 0, i, 0, time.UTC),
			Payload: []byte(`{"action":"person_joined"}`), PrevHash: append([]byte(nil), prev...), SigningKeyID: kid,
		}
		require.NoError(t, e.SignWith(store))
		require.NoError(t, e.Validate())
		out = append(out, e)
		prev = e.Hash
	}
	return out, store
}

// A journal walk verifies signatures and links, and names the record that
// fails.
func TestVerifyEvents(t *testing.T) {
	events, resolver := signedChain(t, 4)
	tip, err := VerifyEvents(events, 10, nil, resolver)
	require.NoError(t, err)
	require.Equal(t, events[3].Hash, tip)

	changed := append([]audit_event.AuditEvent(nil), events...)
	e := changed[2]
	e.Payload = []byte(`{"action":"person_removed"}`)
	changed[2] = e
	_, err = VerifyEvents(changed, 10, nil, resolver)
	var broken *BrokenJournalError
	require.True(t, errors.As(err, &broken))
	require.Equal(t, 12, broken.Index)

	missing := append(append([]audit_event.AuditEvent(nil), events[:1]...), events[2:]...)
	_, err = VerifyEvents(missing, 0, nil, resolver)
	require.True(t, errors.As(err, &broken), "a removed record")
	require.Equal(t, 1, broken.Index)

	_, err = VerifyEvents(events[1:], 1, make([]byte, audit_event.HashSize), resolver)
	require.True(t, errors.As(err, &broken), "a walk that must continue from a known record")
}

func TestParsePass(t *testing.T) {
	_, err := ParsePass([]byte("not json"))
	require.ErrorIs(t, err, ErrNotAPass)
	_, err = ParsePass([]byte(`{"schema":"something else"}`))
	require.ErrorContains(t, err, "not a pass file")
	_, err = ParsePass([]byte(`{"schema":"` + PassSchema + `"}`))
	require.ErrorContains(t, err, "names no server")
	require.ErrorIs(t, err, ErrNotAPass)
	_, err = ParsePass([]byte(`{"schema":"` + PassSchema + `","address":"a:1","server_cert_pem":"x","audit_public_key_pem":"x","audit_key_id":"k"}`))
	require.ErrorContains(t, err, "no server certificate")
	_, err = ParsePass([]byte(`{"schema":"` + PassSchema + `","extra":1}`))
	require.Error(t, err, "unknown fields are refused")
}

func TestPinVerifierRefusesWhatItCannotCheck(t *testing.T) {
	_, _, err := Pin{Provider: "nonsense"}.Verifier("")
	require.Error(t, err)
	_, _, err = Pin{Provider: string(tee.ProviderAzureSGX), MeasurementHex: "00"}.Verifier("")
	require.ErrorContains(t, err, "does not verify")
	_, _, err = Pin{Provider: string(tee.ProviderSimulated), MeasurementHex: "zz"}.Verifier("")
	require.Error(t, err)
	_, _, err = Pin{Provider: string(tee.ProviderAzureSEVSNP), MeasurementHex: "00", PCRDigests: []string{"short"}}.Verifier("")
	require.ErrorContains(t, err, "pcr_digests")
}

func TestRoles(t *testing.T) {
	require.True(t, RoleViewer.Valid() && RoleOperator.Valid() && RoleOwner.Valid())
	require.False(t, Role("admin").Valid())
	require.False(t, RoleViewer.CanRestore())
	require.True(t, RoleOperator.CanRestore())
	require.False(t, RoleOperator.CanAdminister())
	require.True(t, RoleOwner.CanAdminister())
}
