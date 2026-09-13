// SPDX-License-Identifier: AGPL-3.0-or-later

package crosscloud_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	stdtime "time"

	"github.com/ai-continuity-platform/core/internal/bootstrap/crosscloud"
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

// httpFixture wires a real httptest.Server with a destination
// Receiver behind it, plus a source-side HTTPTransport pointing at
// the test server. Bearer auth optional.
type httpFixture struct {
	server           *httptest.Server
	transport        *kms.HTTPTransport
	sourceKeystore   *keys.InMemoryStore
	sourceKID        ids.KeyID
	destProducer     *tee.Simulated
	destMeasure      tee.Measurement
	destMeasureBytes []byte
	destKeystore     *keys.InMemoryStore
	bearer           string
}

func newHTTPFixture(t *testing.T, bearer string) *httpFixture {
	t.Helper()
	clock := shared_time.NewFakeClock(stdtime.Date(2026, 5, 9, 12, 0, 0, 0, stdtime.UTC))

	// Source authority signing key.
	sourceKeystore := keys.NewInMemoryStore(clock)
	sourceKID := ids.KeyID("source-auth-1")
	_, err := sourceKeystore.GenerateSigning(sourceKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	// Destination TEE + keystore.
	destDescriptor := []byte("vault-genome-http-test")
	destSeed := make([]byte, 32)
	_, err = rand.Read(destSeed)
	require.NoError(t, err)
	destProducer, err := tee.NewSimulated(destDescriptor, destSeed)
	require.NoError(t, err)
	destKeystore := keys.NewInMemoryStore(clock)
	destMeasure := destProducer.Measurement()
	destMeasureBytes := make([]byte, 32)
	copy(destMeasureBytes, destMeasure[:])

	receiver, err := crosscloud.NewReceiver(crosscloud.Config{
		SourceAuthorityKeys: sourceKeystore,
		LocalTEE:            destProducer,
		Unwrapper:           kms.NewSimulatedKeyUnwrapper(),
		Registrar:           destKeystore,
	})
	require.NoError(t, err)

	handler, err := crosscloud.NewHTTPHandler(crosscloud.HTTPHandlerConfig{
		Receiver:    receiver,
		BearerToken: bearer,
	})
	require.NoError(t, err)

	mux := http.NewServeMux()
	for path, h := range handler.Routes() {
		mux.HandleFunc(path, h)
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	transport := kms.NewHTTPTransport(kms.HTTPTransportConfig{
		HTTPClient:     server.Client(),
		BearerToken:    bearer,
		RequestTimeout: 5 * stdtime.Second,
	})

	return &httpFixture{
		server:           server,
		transport:        transport,
		sourceKeystore:   sourceKeystore,
		sourceKID:        sourceKID,
		destProducer:     destProducer,
		destMeasure:      destMeasure,
		destMeasureBytes: destMeasureBytes,
		destKeystore:     destKeystore,
		bearer:           bearer,
	}
}

// signedHandshakeForHTTP builds a valid handshake request using the
// fixture's source-authority signing key.
func signedHandshakeForHTTP(t *testing.T, f *httpFixture, nonce []byte) cchr.CrossCloudHandshakeRequest {
	t.Helper()
	req := cchr.CrossCloudHandshakeRequest{
		SchemaVersion:       cchr.SchemaVersionCurrent,
		RequestID:           ids.RequestID("xcc-http-req-1"),
		DecisionID:          ids.DecisionID("dec-http-1"),
		DestinationTEEKind:  tee.ProviderSimulated,
		DestinationEndpoint: f.server.URL,
		HandshakeNonce:      nonce,
		InitiatedAt:         stdtime.Date(2026, 5, 9, 12, 0, 0, 0, stdtime.UTC),
		SigningKeyID:        f.sourceKID,
		Signature:           []byte{0x00},
		AuditEventID:        ids.AuditEventID("evt-http-handshake-1"),
	}
	require.NoError(t, req.SignWith(f.sourceKeystore))
	return req
}

func signedTokenForHTTP(t *testing.T, f *httpFixture, keyMaterials map[ids.KeyID][]byte) krt.KeyReleaseToken {
	t.Helper()
	tokenID := ids.DecisionID("xcc-http-tok-1")
	wrapper := kms.NewSimulatedKeyWrapper()
	wrapped := make([]krt.WrappedKey, 0, len(keyMaterials))
	for kid, plain := range keyMaterials {
		aad := canonicalAADForTest(tokenID, f.destMeasureBytes, kid)
		ct, err := wrapper.Wrap(plain, f.destMeasureBytes, aad)
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
		DecisionID:             ids.DecisionID("dec-http-1"),
		RequestID:              ids.RequestID("xcc-http-req-1"),
		DestinationMeasurement: f.destMeasureBytes,
		Wrapped:                wrapped,
		PolicyVersion:          "policy-http-v1",
		AuthorizedAt:           stdtime.Date(2026, 5, 9, 12, 5, 0, 0, stdtime.UTC),
		SigningKeyID:           f.sourceKID,
		Signature:              []byte{0x00},
		AuditEventID:           ids.AuditEventID("evt-http-token-1"),
	}
	require.NoError(t, tok.SignWith(f.sourceKeystore))
	return tok
}

// canonicalAADForTest mirrors the canonical AAD derivation used by
// both source-side coordinator and destination-side receiver. Kept
// in this _test.go file (instead of importing a private helper) so
// any drift between source/destination derivation surfaces here.
func canonicalAADForTest(tokenID ids.DecisionID, destinationMeasurement []byte, keyID ids.KeyID) []byte {
	// Use the kms-package wrapper; it embeds the same canonical
	// derivation as crosscloud.canonicalWrapAAD.
	wrapper := kms.NewSimulatedKeyWrapper()
	// Try wrap+unwrap with a known AAD computation by using the
	// receiver's exported helper isn't possible (it's unexported),
	// so we replicate the canonical formula here. ANY drift from the
	// kms / crosscloud canonicals will fail the round-trip tests.
	_ = wrapper
	const nbytes = 32
	ids := []byte(tokenID)
	dm := destinationMeasurement
	kid := []byte(keyID)
	buf := make([]byte, 0, len(ids)+len(dm)+len(kid))
	buf = append(buf, ids...)
	buf = append(buf, dm...)
	buf = append(buf, kid...)
	// Use the project's canonical SHA-256.
	digest := shaTest32(buf)
	return digest[:nbytes]
}

// shaTest32 is a tiny indirection to keep the import surface in this
// _test.go small — implementation lives in http_handler_helper_test.go.

// --- Real-network round trips -------------------------------------

func TestHTTPHandshake_RealNetwork_HappyPath(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "")
	nonce := make([]byte, tee.NonceMinBytes)
	_, _ = rand.Read(nonce)
	req := signedHandshakeForHTTP(t, f, nonce)

	resp, err := f.transport.SendHandshakeRequest(context.Background(), f.server.URL, req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Evidence)
	require.Equal(t, f.destMeasureBytes, resp.MeasurementHint)

	// Verify the Evidence the destination produced is actually
	// validatable against its own pubkey + measurement.
	verifier := tee.NewSimulatedVerifier(f.destProducer.PublicKey(), f.destMeasure)
	measured, err := verifier.Verify(resp.Evidence, nonce)
	require.NoError(t, err)
	require.Equal(t, f.destMeasure, measured)
}

func TestHTTPHandshake_RealNetwork_RejectsTamperedSignature(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "")
	nonce := make([]byte, tee.NonceMinBytes)
	_, _ = rand.Read(nonce)
	req := signedHandshakeForHTTP(t, f, nonce)
	// Corrupt signature.
	req.Signature[0] ^= 0xFF

	_, err := f.transport.SendHandshakeRequest(context.Background(), f.server.URL, req)
	require.Error(t, err)
	// Source HTTPTransport classifies destination's HTTP 422 → Integrity.
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestHTTPHandshake_RealNetwork_RejectsBadJSON(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "")
	// Hand-craft a malformed POST.
	req, err := http.NewRequest(http.MethodPost, f.server.URL+"/v1/crosscloud/handshake", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.server.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHTTPHandshake_RealNetwork_RejectsWrongMethod(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "")
	resp, err := f.server.Client().Get(f.server.URL + "/v1/crosscloud/handshake")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHTTPToken_RealNetwork_HappyPath(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "")

	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	tok := signedTokenForHTTP(t, f, map[ids.KeyID][]byte{
		ids.KeyID("http-dek-1"): dek,
	})

	err := f.transport.SendKeyReleaseToken(context.Background(), f.server.URL, tok)
	require.NoError(t, err)

	// DEK is now in destination keystore.
	_, _, err = f.destKeystore.Seal(ids.KeyID("http-dek-1"), []byte("ping"), nil)
	require.NoError(t, err)
}

func TestHTTPToken_RealNetwork_RejectsTamperedSignature(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "")
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	tok := signedTokenForHTTP(t, f, map[ids.KeyID][]byte{ids.KeyID("k"): dek})
	tok.Signature[0] ^= 0xFF

	err := f.transport.SendKeyReleaseToken(context.Background(), f.server.URL, tok)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

// --- Bearer-token auth -------------------------------------------

func TestHTTPHandshake_BearerToken_AcceptedWhenValid(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "secret-bearer-2026-05-09")
	nonce := make([]byte, tee.NonceMinBytes)
	_, _ = rand.Read(nonce)
	req := signedHandshakeForHTTP(t, f, nonce)
	_, err := f.transport.SendHandshakeRequest(context.Background(), f.server.URL, req)
	require.NoError(t, err)
}

func TestHTTPHandshake_BearerToken_RejectedWhenMissing(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "secret-bearer-2026-05-09")
	// Build a transport WITHOUT the bearer token — destination must reject.
	txWithoutBearer := kms.NewHTTPTransport(kms.HTTPTransportConfig{
		HTTPClient:     f.server.Client(),
		BearerToken:    "",
		RequestTimeout: 5 * stdtime.Second,
	})
	nonce := make([]byte, tee.NonceMinBytes)
	_, _ = rand.Read(nonce)
	req := signedHandshakeForHTTP(t, f, nonce)
	_, err := txWithoutBearer.SendHandshakeRequest(context.Background(), f.server.URL, req)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryAuthority))
}

func TestHTTPHandshake_BearerToken_RejectedWhenWrong(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "secret-bearer-2026-05-09")
	txWrong := kms.NewHTTPTransport(kms.HTTPTransportConfig{
		HTTPClient:     f.server.Client(),
		BearerToken:    "wrong-token",
		RequestTimeout: 5 * stdtime.Second,
	})
	nonce := make([]byte, tee.NonceMinBytes)
	_, _ = rand.Read(nonce)
	req := signedHandshakeForHTTP(t, f, nonce)
	_, err := txWrong.SendHandshakeRequest(context.Background(), f.server.URL, req)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryAuthority))
}

// --- Full Coordinator → HTTP → Receiver round trip ---------------

func TestFullCoordinatorRoundTrip_OverRealHTTP(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "")
	clock := shared_time.NewFakeClock(stdtime.Date(2026, 5, 9, 12, 0, 0, 0, stdtime.UTC))

	registry, err := tee.NewRegistry([]tee.RegistrySpec{{
		Provider: tee.ProviderSimulated,
		Spec: tee.VerifierSpec{
			Provider:            tee.ProviderSimulated,
			AttestorPubKey:      f.destProducer.PublicKey(),
			ExpectedMeasurement: f.destMeasure,
		},
	}})
	require.NoError(t, err)

	policy, err := kms.NewAllowListPolicy("e2e-http-policy-v1", map[tee.Provider][][]byte{
		tee.ProviderSimulated: {f.destMeasureBytes},
	})
	require.NoError(t, err)

	idGen := &httpCounterIDGen{}
	coord, err := kms.NewCoordinator(kms.Config{
		AuditChain:   silentHTTPAudit{},
		Signer:       f.sourceKeystore,
		Verifiers:    registry,
		Policy:       policy,
		Wrapper:      kms.NewSimulatedKeyWrapper(),
		Transport:    f.transport,
		IDGenerator:  idGen,
		NonceSource:  func(n int) ([]byte, error) { b := make([]byte, n); _, err := rand.Read(b); return b, err },
		Clock:        clock,
		SigningKeyID: f.sourceKID,
	})
	require.NoError(t, err)

	dek1 := make([]byte, 32)
	_, _ = rand.Read(dek1)
	dek2 := make([]byte, 32)
	_, _ = rand.Read(dek2)

	res, err := coord.CoordinateRestore(context.Background(), kms.CoordinationRequest{
		DecisionID:          ids.DecisionID("e2e-http-dec-1"),
		DestinationKind:     tee.ProviderSimulated,
		DestinationEndpoint: f.server.URL,
		KeysToRelease: []kms.KeyMaterial{
			{KeyID: ids.KeyID("e2e-http-dek-1"), Purpose: krt.PurposeSealing, Plaintext: dek1},
			{KeyID: ids.KeyID("e2e-http-dek-2"), Purpose: krt.PurposeSealing, Plaintext: dek2},
		},
		SessionID:  ids.SessionID("e2e-http-sess-1"),
		ManifestID: ids.ManifestID("e2e-http-man-1"),
	})
	require.NoError(t, err)
	require.Equal(t, f.destMeasureBytes, res.DestinationMeasurement)
	require.NotEmpty(t, res.TokenID)

	for _, kid := range []ids.KeyID{"e2e-http-dek-1", "e2e-http-dek-2"} {
		_, _, err := f.destKeystore.Seal(kid, []byte("ping"), nil)
		require.NoError(t, err, "DEK %s must be in destination keystore after real-HTTP cross-cloud restore", kid)
	}
}

type silentHTTPAudit struct{}

func (silentHTTPAudit) Emit(_ audit_event.Kind, _ []byte, _ ids.SessionID, _ ids.ManifestID, _ ids.RequestID) (ids.AuditEventID, error) {
	return ids.AuditEventID("audit-noop"), nil
}

type httpCounterIDGen struct{ n int }

func (g *httpCounterIDGen) NewRequestID() (ids.RequestID, error) {
	g.n++
	return ids.RequestID("e2e-http-req-1"), nil
}
func (g *httpCounterIDGen) NewDecisionID() (ids.DecisionID, error) {
	g.n++
	return ids.DecisionID("e2e-http-tok-1"), nil
}
