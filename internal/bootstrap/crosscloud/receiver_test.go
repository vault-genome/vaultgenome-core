// SPDX-License-Identifier: AGPL-3.0-or-later

package crosscloud

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	stdtime "time"

	"github.com/ai-continuity-platform/core/internal/contracts/audit_event"
	cchr "github.com/ai-continuity-platform/core/internal/contracts/cross_cloud_handshake_request"
	krt "github.com/ai-continuity-platform/core/internal/contracts/key_release_token"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
	"github.com/ai-continuity-platform/core/internal/vault/kms"
	"github.com/stretchr/testify/require"
)

// --- Helpers --------------------------------------------------------

func mustRandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

// receiverFixture wires a Receiver against a real simulated TEE,
// a real keystore, and a real source-authority signer.
type receiverFixture struct {
	receiver       *Receiver
	keystore       *keys.InMemoryStore
	sourceKID      ids.KeyID
	destProducer   *tee.Simulated
	destMeasure    tee.Measurement
	sourceVerifier keys.Resolver
}

func makeReceiverFixture(t *testing.T) *receiverFixture {
	t.Helper()
	clock := shared_time.NewFakeClock(stdtime.Date(2026, 5, 9, 12, 0, 0, 0, stdtime.UTC))

	// Source-authority keystore + signing key (stand-in for the
	// pre-loaded source authority's pubkey on the destination side).
	sourceKeystore := keys.NewInMemoryStore(clock)
	sourceKID := ids.KeyID("source-auth-1")
	_, err := sourceKeystore.GenerateSigning(sourceKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	// Destination's local TEE producer.
	destDescriptor := []byte("vault-genome-receiver-test")
	destSeed := mustRandomBytes(t, 32)
	destProducer, err := tee.NewSimulated(destDescriptor, destSeed)
	require.NoError(t, err)

	// Destination's keystore (where unwrapped DEKs land).
	destKeystore := keys.NewInMemoryStore(clock)

	receiver, err := NewReceiver(Config{
		SourceAuthorityKeys: sourceKeystore,
		LocalTEE:            destProducer,
		Unwrapper:           kms.NewSimulatedKeyUnwrapper(),
		Registrar:           destKeystore,
	})
	require.NoError(t, err)

	return &receiverFixture{
		receiver:       receiver,
		keystore:       destKeystore,
		sourceKID:      sourceKID,
		destProducer:   destProducer,
		destMeasure:    destProducer.Measurement(),
		sourceVerifier: sourceKeystore,
	}
}

// signedHandshake produces a valid CrossCloudHandshakeRequest signed
// by the source authority. signer is the keystore that holds the
// source-authority private key.
func signedHandshake(
	t *testing.T,
	signer keys.Signer,
	sourceKID ids.KeyID,
	destinationKind tee.Provider,
	nonce []byte,
) cchr.CrossCloudHandshakeRequest {
	t.Helper()
	req := cchr.CrossCloudHandshakeRequest{
		SchemaVersion:       cchr.SchemaVersionCurrent,
		RequestID:           ids.RequestID("xcc-req-test-1"),
		DecisionID:          ids.DecisionID("dec-test-1"),
		DestinationTEEKind:  destinationKind,
		DestinationEndpoint: "https://acp-bootstrap.test:8443",
		HandshakeNonce:      nonce,
		InitiatedAt:         stdtime.Date(2026, 5, 9, 12, 0, 0, 0, stdtime.UTC),
		SigningKeyID:        sourceKID,
		Signature:           []byte{0x00},
		AuditEventID:        ids.AuditEventID("evt-handshake-1"),
	}
	require.NoError(t, req.SignWith(signer))
	return req
}

// signedToken produces a valid KeyReleaseToken signed by the source
// authority, with each WrappedKey produced via wrap with the given
// destination measurement.
func signedToken(
	t *testing.T,
	signer keys.Signer,
	sourceKID ids.KeyID,
	destinationMeasurement []byte,
	keyMaterials map[ids.KeyID][]byte,
) krt.KeyReleaseToken {
	t.Helper()
	tokenID := ids.DecisionID("xcc-tok-test-1")
	wrapper := kms.NewSimulatedKeyWrapper()

	wrapped := make([]krt.WrappedKey, 0, len(keyMaterials))
	for kid, plaintext := range keyMaterials {
		aad := canonicalWrapAAD(tokenID, destinationMeasurement, kid)
		ct, err := wrapper.Wrap(plaintext, destinationMeasurement, aad)
		require.NoError(t, err)
		wrapped = append(wrapped, krt.WrappedKey{
			KeyID:      kid,
			Purpose:    krt.PurposeSealing,
			Ciphertext: ct,
			AAD:        aad,
		})
	}

	tok := krt.KeyReleaseToken{
		SchemaVersion:          krt.SchemaVersionCurrent,
		TokenID:                tokenID,
		DecisionID:             ids.DecisionID("dec-test-1"),
		RequestID:              ids.RequestID("xcc-req-test-1"),
		DestinationMeasurement: destinationMeasurement,
		Wrapped:                wrapped,
		PolicyVersion:          "policy-test-v1",
		AuthorizedAt:           stdtime.Date(2026, 5, 9, 12, 5, 0, 0, stdtime.UTC),
		SigningKeyID:           sourceKID,
		Signature:              []byte{0x00},
		AuditEventID:           ids.AuditEventID("evt-release-1"),
	}
	require.NoError(t, tok.SignWith(signer))
	return tok
}

// --- Constructor tests ----------------------------------------------

func TestNewReceiver_RequiresAllFields(t *testing.T) {
	t.Parallel()
	clock := shared_time.NewFakeClock(stdtime.Now())
	sourceKeystore := keys.NewInMemoryStore(clock)
	destKeystore := keys.NewInMemoryStore(clock)
	descriptor := []byte("test")
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	prod, err := tee.NewSimulated(descriptor, seed)
	require.NoError(t, err)

	full := Config{
		SourceAuthorityKeys: sourceKeystore,
		LocalTEE:            prod,
		Unwrapper:           kms.NewSimulatedKeyUnwrapper(),
		Registrar:           destKeystore,
	}
	cases := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"SourceAuthorityKeys", func(c *Config) { c.SourceAuthorityKeys = nil }},
		{"LocalTEE", func(c *Config) { c.LocalTEE = nil }},
		{"Unwrapper", func(c *Config) { c.Unwrapper = nil }},
		{"Registrar", func(c *Config) { c.Registrar = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := full
			tc.mutate(&cp)
			_, err := NewReceiver(cp)
			require.Error(t, err)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
		})
	}
	_, err = NewReceiver(full)
	require.NoError(t, err)
}

// --- HandleHandshakeRequest tests ---------------------------------

func TestHandleHandshakeRequest_HappyPath(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	nonce := mustRandomBytes(t, tee.NonceMinBytes)
	req := signedHandshake(t, f.sourceVerifier.(keys.Signer), f.sourceKID, tee.ProviderSimulated, nonce)

	resp, err := f.receiver.HandleHandshakeRequest(req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Evidence)
	require.Equal(t, f.destMeasure[:], resp.MeasurementHint)
}

func TestHandleHandshakeRequest_RejectsBadSignature(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	nonce := mustRandomBytes(t, tee.NonceMinBytes)
	req := signedHandshake(t, f.sourceVerifier.(keys.Signer), f.sourceKID, tee.ProviderSimulated, nonce)
	// Corrupt the signature.
	req.Signature[0] ^= 0xFF
	_, err := f.receiver.HandleHandshakeRequest(req)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestHandleHandshakeRequest_RejectsStructuralInvalid(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	// Empty handshake nonce (below minimum).
	req := cchr.CrossCloudHandshakeRequest{
		SchemaVersion:       cchr.SchemaVersionCurrent,
		RequestID:           ids.RequestID("x"),
		DecisionID:          ids.DecisionID("d"),
		DestinationTEEKind:  tee.ProviderSimulated,
		DestinationEndpoint: "https://x",
		HandshakeNonce:      []byte{1, 2, 3}, // too short
		InitiatedAt:         stdtime.Now(),
		SigningKeyID:        f.sourceKID,
		Signature:           []byte{0xFF},
		AuditEventID:        ids.AuditEventID("e"),
	}
	_, err := f.receiver.HandleHandshakeRequest(req)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestHandleHandshakeRequest_LocalEvidenceVerifiableBySource(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	nonce := mustRandomBytes(t, tee.NonceMinBytes)
	req := signedHandshake(t, f.sourceVerifier.(keys.Signer), f.sourceKID, tee.ProviderSimulated, nonce)
	resp, err := f.receiver.HandleHandshakeRequest(req)
	require.NoError(t, err)

	// A source-side verifier configured with the destination's
	// pubkey + expected measurement must be able to validate the
	// returned Evidence under the source-supplied nonce.
	verifier := tee.NewSimulatedVerifier(f.destProducer.PublicKey(), f.destMeasure)
	measured, err := verifier.Verify(resp.Evidence, nonce)
	require.NoError(t, err)
	require.Equal(t, f.destMeasure, measured)
}

// --- HandleKeyReleaseToken tests ----------------------------------

func TestHandleKeyReleaseToken_HappyPath_RegistersAllKeys(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	dek1 := mustRandomBytes(t, 32)
	dek2 := mustRandomBytes(t, 32)
	keyMaterials := map[ids.KeyID][]byte{
		ids.KeyID("dek-1"): dek1,
		ids.KeyID("dek-2"): dek2,
	}
	tok := signedToken(t, f.sourceVerifier.(keys.Signer), f.sourceKID, f.destMeasure[:], keyMaterials)

	registered, err := f.receiver.HandleKeyReleaseToken(tok)
	require.NoError(t, err)
	require.Equal(t, 2, registered)

	// Both keys must be usable in the destination's keystore now.
	// keys.InMemoryStore.Seal opens against an existing sealing key
	// — round-tripping a tiny payload proves the key is registered.
	_, _, err = f.keystore.Seal(ids.KeyID("dek-1"), []byte("ping"), nil)
	require.NoError(t, err)
	_, _, err = f.keystore.Seal(ids.KeyID("dek-2"), []byte("ping"), nil)
	require.NoError(t, err)
}

func TestHandleKeyReleaseToken_RejectsBadSignature(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	keyMaterials := map[ids.KeyID][]byte{ids.KeyID("dek-1"): mustRandomBytes(t, 32)}
	tok := signedToken(t, f.sourceVerifier.(keys.Signer), f.sourceKID, f.destMeasure[:], keyMaterials)
	tok.Signature[0] ^= 0xFF

	registered, err := f.receiver.HandleKeyReleaseToken(tok)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
	require.Equal(t, 0, registered)
}

func TestHandleKeyReleaseToken_RejectsWrongMeasurement(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	keyMaterials := map[ids.KeyID][]byte{ids.KeyID("dek-1"): mustRandomBytes(t, 32)}
	wrongMeasure := bytes.Repeat([]byte{0xCC}, 32)
	tok := signedToken(t, f.sourceVerifier.(keys.Signer), f.sourceKID, wrongMeasure, keyMaterials)

	registered, err := f.receiver.HandleKeyReleaseToken(tok)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
	require.Equal(t, 0, registered)
}

func TestHandleKeyReleaseToken_RejectsTamperedAAD(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	keyMaterials := map[ids.KeyID][]byte{ids.KeyID("dek-1"): mustRandomBytes(t, 32)}
	tok := signedToken(t, f.sourceVerifier.(keys.Signer), f.sourceKID, f.destMeasure[:], keyMaterials)
	// Tamper the AAD by appending a byte.
	tok.Wrapped[0].AAD = append(tok.Wrapped[0].AAD, 0xAA)
	// The signature must be re-issued because we changed token bytes.
	tok.Signature = []byte{0x00}
	require.NoError(t, tok.SignWith(f.sourceVerifier.(keys.Signer)))

	registered, err := f.receiver.HandleKeyReleaseToken(tok)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
	require.Equal(t, 0, registered)
}

func TestHandleKeyReleaseToken_RejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	keyMaterials := map[ids.KeyID][]byte{ids.KeyID("dek-1"): mustRandomBytes(t, 32)}
	tok := signedToken(t, f.sourceVerifier.(keys.Signer), f.sourceKID, f.destMeasure[:], keyMaterials)
	// Tamper the ciphertext.
	tok.Wrapped[0].Ciphertext[len(tok.Wrapped[0].Ciphertext)-1] ^= 0x01
	tok.Signature = []byte{0x00}
	require.NoError(t, tok.SignWith(f.sourceVerifier.(keys.Signer)))

	registered, err := f.receiver.HandleKeyReleaseToken(tok)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
	require.Equal(t, 0, registered)
}

func TestHandleKeyReleaseToken_RejectsStructuralInvalid(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	tok := krt.KeyReleaseToken{} // all zero — Validate fails
	registered, err := f.receiver.HandleKeyReleaseToken(tok)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
	require.Equal(t, 0, registered)
}

func TestLocalMeasurement_DefensiveCopy(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	got := f.receiver.LocalMeasurement()
	require.Equal(t, f.destMeasure[:], got)
	// Mutating returned slice must not affect Receiver internals.
	got[0] = 0xFF
	again := f.receiver.LocalMeasurement()
	require.Equal(t, f.destMeasure[:], again)
}

// --- End-to-end round-trip with source-side Coordinator -----------

func TestEndToEnd_SourceCoordinatorToDestinationReceiver(t *testing.T) {
	t.Parallel()
	clock := shared_time.NewFakeClock(stdtime.Date(2026, 5, 9, 12, 0, 0, 0, stdtime.UTC))

	// Shared keystore acts as both source-authority signer (for the
	// Coordinator) and source-authority resolver (for the Receiver
	// to verify signatures).
	sourceKeystore := keys.NewInMemoryStore(clock)
	sourceKID := ids.KeyID("source-auth-1")
	_, err := sourceKeystore.GenerateSigning(sourceKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	// Destination TEE + keystore.
	destSeed := mustRandomBytes(t, 32)
	destProducer, err := tee.NewSimulated([]byte("e2e-test"), destSeed)
	require.NoError(t, err)
	destKeystore := keys.NewInMemoryStore(clock)
	destMeasure := destProducer.Measurement()
	destMeasureBytes := make([]byte, 32)
	copy(destMeasureBytes, destMeasure[:])

	receiver, err := NewReceiver(Config{
		SourceAuthorityKeys: sourceKeystore,
		LocalTEE:            destProducer,
		Unwrapper:           kms.NewSimulatedKeyUnwrapper(),
		Registrar:           destKeystore,
	})
	require.NoError(t, err)

	// Source-side verifier registry pointing at the destination.
	registry, err := tee.NewRegistry([]tee.RegistrySpec{{
		Provider: tee.ProviderSimulated,
		Spec: tee.VerifierSpec{
			Provider:            tee.ProviderSimulated,
			AttestorPubKey:      destProducer.PublicKey(),
			ExpectedMeasurement: destMeasure,
		},
	}})
	require.NoError(t, err)

	policy, err := kms.NewAllowListPolicy("e2e-policy-v1", map[tee.Provider][][]byte{
		tee.ProviderSimulated: {destMeasureBytes},
	})
	require.NoError(t, err)

	// Transport routes source → destination via the receiver's
	// Handle methods. This is the core of the e2e test.
	transport := &receiverBackedTransport{receiver: receiver}

	coord, err := kms.NewCoordinator(kms.Config{
		AuditChain:   &silentAudit{},
		Signer:       sourceKeystore,
		Verifiers:    registry,
		Policy:       policy,
		Wrapper:      kms.NewSimulatedKeyWrapper(),
		Transport:    transport,
		IDGenerator:  &counterIDGen{},
		NonceSource:  func(n int) ([]byte, error) { return mustRandomBytes(t, n), nil },
		Clock:        clock,
		SigningKeyID: sourceKID,
	})
	require.NoError(t, err)

	dek1 := mustRandomBytes(t, 32)
	dek2 := mustRandomBytes(t, 32)

	res, err := coord.CoordinateRestore(context.Background(), kms.CoordinationRequest{
		DecisionID:          ids.DecisionID("e2e-dec-1"),
		DestinationKind:     tee.ProviderSimulated,
		DestinationEndpoint: "https://destination.test",
		KeysToRelease: []kms.KeyMaterial{
			{KeyID: ids.KeyID("e2e-dek-1"), Purpose: krt.PurposeSealing, Plaintext: dek1},
			{KeyID: ids.KeyID("e2e-dek-2"), Purpose: krt.PurposeSealing, Plaintext: dek2},
		},
		SessionID:  ids.SessionID("e2e-sess-1"),
		ManifestID: ids.ManifestID("e2e-man-1"),
	})
	require.NoError(t, err)
	require.Equal(t, destMeasureBytes, res.DestinationMeasurement)
	require.NotEmpty(t, res.TokenID)

	// Destination keystore must now hold both DEKs registered under
	// their original KeyIDs.
	for _, kid := range []ids.KeyID{"e2e-dek-1", "e2e-dek-2"} {
		_, _, err := destKeystore.Seal(kid, []byte("ping"), nil)
		require.NoError(t, err, "DEK %s must be registered after cross-cloud restore", kid)
	}
}

// receiverBackedTransport is a kms.Transport that routes calls
// directly into a destination Receiver. Used in the end-to-end test
// to wire source coordinator and destination receiver into a single
// in-process flow.
type receiverBackedTransport struct {
	receiver *Receiver
}

func (t *receiverBackedTransport) SendHandshakeRequest(
	_ context.Context,
	_ string,
	req cchr.CrossCloudHandshakeRequest,
) (kms.HandshakeResponse, error) {
	resp, err := t.receiver.HandleHandshakeRequest(req)
	if err != nil {
		return kms.HandshakeResponse{}, err
	}
	return kms.HandshakeResponse{Evidence: resp.Evidence, MeasurementHint: resp.MeasurementHint}, nil
}

func (t *receiverBackedTransport) SendKeyReleaseToken(
	_ context.Context,
	_ string,
	tok krt.KeyReleaseToken,
) error {
	_, err := t.receiver.HandleKeyReleaseToken(tok)
	return err
}

// silentAudit accepts and discards all events — sufficient for the
// e2e test which asserts on key-registration, not audit-chain shape.
type silentAudit struct{}

func (silentAudit) Emit(_ audit_event.Kind, _ []byte, _ ids.SessionID, _ ids.ManifestID, _ ids.RequestID) (ids.AuditEventID, error) {
	return ids.AuditEventID("audit-noop"), nil
}

type counterIDGen struct{ n int }

func (g *counterIDGen) NewRequestID() (ids.RequestID, error) {
	g.n++
	return ids.RequestID("e2e-req-1"), nil
}

func (g *counterIDGen) NewDecisionID() (ids.DecisionID, error) {
	g.n++
	return ids.DecisionID("e2e-dec-tok-1"), nil
}
