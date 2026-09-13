// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
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
	"github.com/stretchr/testify/require"
)

// --- Test mocks ----------------------------------------------------

type emittedEvent struct {
	Kind       audit_event.Kind
	Payload    []byte
	SessionID  ids.SessionID
	ManifestID ids.ManifestID
	RequestID  ids.RequestID
}

type fakeAuditChain struct {
	events   []emittedEvent
	failKind audit_event.Kind // if non-empty, Emit fails for this kind
	counter  int
}

func newFakeAuditChain() *fakeAuditChain {
	return &fakeAuditChain{events: []emittedEvent{}}
}

func (f *fakeAuditChain) Emit(
	kind audit_event.Kind,
	payload []byte,
	sessionID ids.SessionID,
	manifestID ids.ManifestID,
	requestID ids.RequestID,
) (ids.AuditEventID, error) {
	if f.failKind == kind {
		return "", errors.New("audit chain emit failed (test injection)")
	}
	f.counter++
	f.events = append(f.events, emittedEvent{Kind: kind, Payload: payload, SessionID: sessionID, ManifestID: manifestID, RequestID: requestID})
	return ids.AuditEventID(fmt.Sprintf("audit-%d", f.counter)), nil
}

type fakeIDGen struct {
	reqCounter      int
	decisionCounter int
}

func (g *fakeIDGen) NewRequestID() (ids.RequestID, error) {
	g.reqCounter++
	return ids.RequestID(fmt.Sprintf("xcc-req-%04d", g.reqCounter)), nil
}

func (g *fakeIDGen) NewDecisionID() (ids.DecisionID, error) {
	g.decisionCounter++
	return ids.DecisionID(fmt.Sprintf("xcc-dec-%04d", g.decisionCounter)), nil
}

// producerBackedTransport simulates a destination by holding a real
// tee.Producer; SendHandshakeRequest returns Evidence the test's
// Verifier registry can validate.
type producerBackedTransport struct {
	producer       tee.Producer
	handshakeErr   error
	tokenErr       error
	emptyEvidence  bool // simulate destination returning no Evidence
	sentTokens     []krt.KeyReleaseToken
	sentHandshakes []cchr.CrossCloudHandshakeRequest
}

func (t *producerBackedTransport) SendHandshakeRequest(
	ctx context.Context,
	endpoint string,
	req cchr.CrossCloudHandshakeRequest,
) (HandshakeResponse, error) {
	t.sentHandshakes = append(t.sentHandshakes, req)
	if t.handshakeErr != nil {
		return HandshakeResponse{}, t.handshakeErr
	}
	if t.emptyEvidence {
		return HandshakeResponse{}, nil
	}
	evidence, err := t.producer.Quote(req.HandshakeNonce)
	if err != nil {
		return HandshakeResponse{}, err
	}
	m := t.producer.Measurement()
	return HandshakeResponse{Evidence: evidence, MeasurementHint: m[:]}, nil
}

func (t *producerBackedTransport) SendKeyReleaseToken(
	ctx context.Context,
	endpoint string,
	token krt.KeyReleaseToken,
) error {
	if t.tokenErr != nil {
		return t.tokenErr
	}
	t.sentTokens = append(t.sentTokens, token)
	return nil
}

// deterministicNonceSource returns a fixed-content nonce padded to n
// bytes; lets us assert nonce-related fields without RNG variability.
func deterministicNonceSource(seed byte) NonceSource {
	return func(n int) ([]byte, error) {
		out := make([]byte, n)
		for i := range out {
			out[i] = seed + byte(i)
		}
		return out, nil
	}
}

func failingNonceSource(_ int) ([]byte, error) {
	return nil, errors.New("rng failure (test injection)")
}

func tooShortNonceSource(_ int) ([]byte, error) {
	return []byte{1, 2, 3}, nil
}

// --- Test fixtures -------------------------------------------------

// fixture builds a fully-wired Coordinator with a destination-side
// simulated TEE producer / verifier and an allow-listed measurement.
type fixture struct {
	coord        *Coordinator
	auditChain   *fakeAuditChain
	idGen        *fakeIDGen
	transport    *producerBackedTransport
	keyStore     *keys.InMemoryStore
	sourceKID    ids.KeyID
	destKind     tee.Provider
	destMeasure  tee.Measurement
	destProducer *tee.Simulated
	registry     *tee.Registry
}

func makeFixture(t *testing.T) *fixture {
	t.Helper()
	clock := shared_time.NewFakeClock(stdtime.Date(2026, 5, 9, 12, 0, 0, 0, stdtime.UTC))

	// Source-authority signing key.
	keyStore := keys.NewInMemoryStore(clock)
	sourceKID := ids.KeyID("source-auth-1")
	_, err := keyStore.GenerateSigning(sourceKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	// Destination simulated TEE producer + matching verifier in registry.
	destDescriptor := []byte("vault-genome-destination-test")
	destSeed := make([]byte, 32)
	for i := range destSeed {
		destSeed[i] = byte(0x80 + i)
	}
	destProducer, err := tee.NewSimulated(destDescriptor, destSeed)
	require.NoError(t, err)

	destMeasurement := destProducer.Measurement()
	destMeasurementBytes := make([]byte, 32)
	copy(destMeasurementBytes, destMeasurement[:])

	registry, err := tee.NewRegistry([]tee.RegistrySpec{{
		Provider: tee.ProviderSimulated,
		Spec: tee.VerifierSpec{
			Provider:            tee.ProviderSimulated,
			AttestorPubKey:      destProducer.PublicKey(),
			ExpectedMeasurement: destMeasurement,
		},
	}})
	require.NoError(t, err)

	policy, err := NewAllowListPolicy("policy-test-v1", map[tee.Provider][][]byte{
		tee.ProviderSimulated: {destMeasurementBytes},
	})
	require.NoError(t, err)

	auditChain := newFakeAuditChain()
	idGen := &fakeIDGen{}
	transport := &producerBackedTransport{producer: destProducer}

	coord, err := NewCoordinator(Config{
		AuditChain:   auditChain,
		Signer:       keyStore,
		Verifiers:    registry,
		Policy:       policy,
		Wrapper:      NewSimulatedKeyWrapper(),
		Transport:    transport,
		IDGenerator:  idGen,
		NonceSource:  deterministicNonceSource(0xA0),
		Clock:        clock,
		SigningKeyID: sourceKID,
	})
	require.NoError(t, err)

	return &fixture{
		coord:        coord,
		auditChain:   auditChain,
		idGen:        idGen,
		transport:    transport,
		keyStore:     keyStore,
		sourceKID:    sourceKID,
		destKind:     tee.ProviderSimulated,
		destMeasure:  destMeasurement,
		destProducer: destProducer,
		registry:     registry,
	}
}

func validKeyMaterial() []KeyMaterial {
	return []KeyMaterial{
		{KeyID: ids.KeyID("dek-1"), Purpose: krt.PurposeSealing, Plaintext: []byte("super-secret-DEK-bytes-vault-001")},
		{KeyID: ids.KeyID("dek-2"), Purpose: krt.PurposeSealing, Plaintext: []byte("super-secret-DEK-bytes-vault-002")},
	}
}

func validRequest(f *fixture) CoordinationRequest {
	return CoordinationRequest{
		DecisionID:          ids.DecisionID("dec-vault-0001"),
		DestinationKind:     f.destKind,
		DestinationEndpoint: "https://acp-bootstrap.example.com:8443",
		KeysToRelease:       validKeyMaterial(),
		SessionID:           ids.SessionID("sess-0001"),
		ManifestID:          ids.ManifestID("man-0001"),
	}
}

// --- NewCoordinator constructor tests ------------------------------

func TestNewCoordinator_RequiresAllFields(t *testing.T) {
	t.Parallel()
	clock := shared_time.NewFakeClock(stdtime.Now())
	store := keys.NewInMemoryStore(clock)
	registry, err := tee.NewRegistry(nil)
	require.NoError(t, err)
	policy, err := NewAllowListPolicy("v1", nil)
	require.NoError(t, err)

	full := Config{
		AuditChain:   newFakeAuditChain(),
		Signer:       store,
		Verifiers:    registry,
		Policy:       policy,
		Wrapper:      NewSimulatedKeyWrapper(),
		Transport:    &producerBackedTransport{},
		IDGenerator:  &fakeIDGen{},
		NonceSource:  deterministicNonceSource(0),
		Clock:        clock,
		SigningKeyID: ids.KeyID("k1"),
	}

	// Each pruned field must trigger error.
	cases := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"AuditChain", func(c *Config) { c.AuditChain = nil }},
		{"Signer", func(c *Config) { c.Signer = nil }},
		{"Verifiers", func(c *Config) { c.Verifiers = nil }},
		{"Policy", func(c *Config) { c.Policy = nil }},
		{"Wrapper", func(c *Config) { c.Wrapper = nil }},
		{"Transport", func(c *Config) { c.Transport = nil }},
		{"IDGenerator", func(c *Config) { c.IDGenerator = nil }},
		{"NonceSource", func(c *Config) { c.NonceSource = nil }},
		{"Clock", func(c *Config) { c.Clock = nil }},
		{"SigningKeyID", func(c *Config) { c.SigningKeyID = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := full
			tc.mutate(&cp)
			_, err := NewCoordinator(cp)
			require.Error(t, err)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
		})
	}

	// Full config succeeds.
	_, err = NewCoordinator(full)
	require.NoError(t, err)
}

// --- CoordinateRestore happy path ----------------------------------

func TestCoordinateRestore_HappyPath(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	res, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.NoError(t, err)

	// Result fields populated.
	require.NotEmpty(t, res.HandshakeRequestID)
	require.NotEmpty(t, res.HandshakeAuditID)
	require.NotEmpty(t, res.AttestationAuditID)
	require.NotEmpty(t, res.KeyReleaseAuditID)
	require.Equal(t, []byte(f.destMeasure[:]), []byte(res.DestinationMeasurement))
	require.Equal(t, "policy-test-v1", res.PolicyVersion)
	require.NotEmpty(t, res.TokenID)

	// Three audit events emitted in strict order.
	require.Len(t, f.auditChain.events, 3)
	require.Equal(t, audit_event.KindCrossCloudHandshakeInitiated, f.auditChain.events[0].Kind)
	require.Equal(t, audit_event.KindCrossCloudAttestationVerified, f.auditChain.events[1].Kind)
	require.Equal(t, audit_event.KindKeyReleaseAuthorized, f.auditChain.events[2].Kind)

	// Each event tagged with the same RequestID correlator.
	require.Equal(t, res.HandshakeRequestID, f.auditChain.events[0].RequestID)
	require.Equal(t, res.HandshakeRequestID, f.auditChain.events[1].RequestID)
	require.Equal(t, res.HandshakeRequestID, f.auditChain.events[2].RequestID)

	// One handshake dispatched.
	require.Len(t, f.transport.sentHandshakes, 1)
	hs := f.transport.sentHandshakes[0]
	require.Equal(t, res.HandshakeRequestID, hs.RequestID)
	require.Equal(t, ids.DecisionID("dec-vault-0001"), hs.DecisionID)
	require.Equal(t, f.destKind, hs.DestinationTEEKind)
	require.GreaterOrEqual(t, len(hs.HandshakeNonce), tee.NonceMinBytes)
	require.NotEmpty(t, hs.Signature)
	require.Equal(t, res.HandshakeAuditID, hs.AuditEventID)

	// One token dispatched, with two wrapped keys.
	require.Len(t, f.transport.sentTokens, 1)
	tok := f.transport.sentTokens[0]
	require.Equal(t, res.TokenID, tok.TokenID)
	require.Equal(t, ids.DecisionID("dec-vault-0001"), tok.DecisionID)
	require.Equal(t, res.HandshakeRequestID, tok.RequestID)
	require.Equal(t, []byte(f.destMeasure[:]), []byte(tok.DestinationMeasurement))
	require.Len(t, tok.Wrapped, 2)
	for _, w := range tok.Wrapped {
		require.Equal(t, krt.PurposeSealing, w.Purpose)
		require.NotEmpty(t, w.Ciphertext)
		require.NotEmpty(t, w.AAD)
	}
	require.Equal(t, "policy-test-v1", tok.PolicyVersion)
	require.Equal(t, res.KeyReleaseAuditID, tok.AuditEventID)
	require.NotEmpty(t, tok.Signature)
}

// TestCoordinateRestore_TokenUnwrapsAtDestination exercises the full
// crypto loop: wrap on source side → unwrap on destination side using
// the destination's measurement (which is what the destination's
// Sealer would produce).
func TestCoordinateRestore_TokenUnwrapsAtDestination(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	req := validRequest(f)
	res, err := f.coord.CoordinateRestore(context.Background(), req)
	require.NoError(t, err)

	require.Len(t, f.transport.sentTokens, 1)
	tok := f.transport.sentTokens[0]
	unwrapper := NewSimulatedKeyUnwrapper()

	for i, w := range tok.Wrapped {
		plain, err := unwrapper.Unwrap(w.Ciphertext, f.destMeasure[:], w.AAD)
		require.NoError(t, err, "wrapped key #%d must unwrap under destination measurement", i)
		require.Equal(t, req.KeysToRelease[i].Plaintext, plain, "round-trip plaintext must match")
	}
	_ = res
}

// --- CoordinateRestore error paths ---------------------------------

func TestCoordinateRestore_ValidationErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mut  func(r *CoordinationRequest)
	}{
		{"DecisionID empty", func(r *CoordinationRequest) { r.DecisionID = "" }},
		{"DestinationKind empty", func(r *CoordinationRequest) { r.DestinationKind = "" }},
		{"DestinationKind unregistered", func(r *CoordinationRequest) { r.DestinationKind = tee.ProviderGCPSEVSNP }},
		{"Endpoint empty", func(r *CoordinationRequest) { r.DestinationEndpoint = "" }},
		{"KeysToRelease empty", func(r *CoordinationRequest) { r.KeysToRelease = nil }},
		{"KeyMaterial KeyID empty", func(r *CoordinationRequest) { r.KeysToRelease[0].KeyID = "" }},
		{"KeyMaterial Plaintext empty", func(r *CoordinationRequest) { r.KeysToRelease[0].Plaintext = nil }},
		{"SourceMeasurement wrong size", func(r *CoordinationRequest) { r.SourceMeasurement = []byte{1, 2, 3} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFixture(t)
			req := validRequest(f)
			tc.mut(&req)
			_, err := f.coord.CoordinateRestore(context.Background(), req)
			require.Error(t, err)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
			require.Empty(t, f.auditChain.events, "no audit emission on input validation failure")
		})
	}
}

func TestCoordinateRestore_NonceSourceFailureIsOperational(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	// Replace the coordinator with a failing nonce source.
	bad := *f.coord
	bad.nonceSource = failingNonceSource
	_, err := bad.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational))
	require.Empty(t, f.auditChain.events)
}

func TestCoordinateRestore_NonceTooShortIsStructural(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	bad := *f.coord
	bad.nonceSource = tooShortNonceSource
	_, err := bad.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestCoordinateRestore_HandshakeAuditEmitFailureStopsFlow(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	f.auditChain.failKind = audit_event.KindCrossCloudHandshakeInitiated
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.Empty(t, f.transport.sentHandshakes, "no handshake dispatched if audit emission fails")
}

func TestCoordinateRestore_HandshakeTransportFailure(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	f.transport.handshakeErr = errors.New("network unreachable")
	res, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational))
	// Handshake audit event was emitted before dispatch (audit-first-class).
	require.Len(t, f.auditChain.events, 1)
	require.Equal(t, audit_event.KindCrossCloudHandshakeInitiated, f.auditChain.events[0].Kind)
	// Handshake audit ID present in result for diagnostics.
	require.NotEmpty(t, res.HandshakeAuditID)
	// No token dispatched.
	require.Empty(t, f.transport.sentTokens)
}

func TestCoordinateRestore_DestinationReturnsEmptyEvidence(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	f.transport.emptyEvidence = true
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
	require.Len(t, f.auditChain.events, 1, "only handshake audit emitted before failure")
}

func TestCoordinateRestore_VerifierMismatchFailsAttestation(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	// Re-build registry with a verifier expecting a DIFFERENT measurement.
	wrongMeasure := makeMeasurement(0xDD)
	wrongMeasureFixed, err := tee.MeasurementFromBytes(wrongMeasure)
	require.NoError(t, err)
	registry2, err := tee.NewRegistry([]tee.RegistrySpec{{
		Provider: tee.ProviderSimulated,
		Spec: tee.VerifierSpec{
			Provider:            tee.ProviderSimulated,
			AttestorPubKey:      f.destProducer.PublicKey(),
			ExpectedMeasurement: wrongMeasureFixed,
		},
	}})
	require.NoError(t, err)
	bad := *f.coord
	bad.verifiers = registry2

	_, err = bad.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
	require.Len(t, f.auditChain.events, 1, "handshake emitted, attestation verification failed")
}

func TestCoordinateRestore_PolicyDeniesRelease(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	// Replace policy with one that denies any measurement.
	denyAll, err := NewAllowListPolicy("deny-all-v1", map[tee.Provider][][]byte{})
	require.NoError(t, err)
	bad := *f.coord
	bad.policy = denyAll

	_, err = bad.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryAuthority))
	// Both Handshake AND Attestation events emitted before policy denial;
	// no KeyReleaseAuthorized emitted.
	require.Len(t, f.auditChain.events, 2)
	require.Equal(t, audit_event.KindCrossCloudHandshakeInitiated, f.auditChain.events[0].Kind)
	require.Equal(t, audit_event.KindCrossCloudAttestationVerified, f.auditChain.events[1].Kind)
	// No token dispatched on policy denial.
	require.Empty(t, f.transport.sentTokens)
}

func TestCoordinateRestore_TokenTransportFailure(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	f.transport.tokenErr = errors.New("destination unreachable mid-flight")
	res, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational))
	// All three audits emitted before transport failure (audit-first-class).
	require.Len(t, f.auditChain.events, 3)
	// KeyReleaseAuditID present in result for diagnostics.
	require.NotEmpty(t, res.KeyReleaseAuditID)
}

func TestCoordinateRestore_AuditOrderingStrict(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.NoError(t, err)
	// Verify strict ordering: Handshake → Attestation → KeyRelease.
	require.Equal(t, []audit_event.Kind{
		audit_event.KindCrossCloudHandshakeInitiated,
		audit_event.KindCrossCloudAttestationVerified,
		audit_event.KindKeyReleaseAuthorized,
	}, []audit_event.Kind{
		f.auditChain.events[0].Kind,
		f.auditChain.events[1].Kind,
		f.auditChain.events[2].Kind,
	})
}

// --- RecordCompletion -----------------------------------------------

func TestRecordCompletion_HappyPath(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	auditID, err := f.coord.RecordCompletion(
		ids.DecisionID("dec-1"),
		ids.DecisionID("tok-1"),
		ids.RequestID("req-1"),
		[]byte("sha256-of-restored-genome"),
		"validated",
		ids.SessionID("sess-1"),
		ids.ManifestID("man-1"),
	)
	require.NoError(t, err)
	require.NotEmpty(t, auditID)
	require.Len(t, f.auditChain.events, 1)
	require.Equal(t, audit_event.KindCrossCloudRestoreCompleted, f.auditChain.events[0].Kind)
}

func TestRecordCompletion_RequiresFields(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	cases := []struct {
		name string
		call func() error
	}{
		{"missing DecisionID", func() error {
			_, err := f.coord.RecordCompletion("", "tok-1", "req-1", nil, "validated", "", "")
			return err
		}},
		{"missing TokenID", func() error {
			_, err := f.coord.RecordCompletion("dec-1", "", "req-1", nil, "validated", "", "")
			return err
		}},
		{"missing RequestID", func() error {
			_, err := f.coord.RecordCompletion("dec-1", "tok-1", "", nil, "validated", "", "")
			return err
		}},
		{"missing DestinationOutcome", func() error {
			_, err := f.coord.RecordCompletion("dec-1", "tok-1", "req-1", nil, "", "", "")
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			require.Error(t, err)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
		})
	}
}

// --- Production NonceSource sanity ---------------------------------

// Sanity check that crypto/rand-backed NonceSource yields ≥ NonceMinBytes
// of distinct entropy on consecutive calls.
func TestProductionNonceSource_FreshPerCall(t *testing.T) {
	t.Parallel()
	src := func(n int) ([]byte, error) {
		b := make([]byte, n)
		_, err := rand.Read(b)
		return b, err
	}
	a, err := src(tee.NonceMinBytes)
	require.NoError(t, err)
	b, err := src(tee.NonceMinBytes)
	require.NoError(t, err)
	require.NotEqual(t, a, b)
	require.GreaterOrEqual(t, len(a), tee.NonceMinBytes)
}
