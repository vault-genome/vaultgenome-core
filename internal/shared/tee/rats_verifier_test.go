// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee/ratstest"
)

// A simulated worker, its statement over a challenge, and a Verifier
// double that appraises it: what the bench runs before any hardware.
type ratsFixture struct {
	sim       *tee.Simulated
	nonce     tee.Nonce
	mediaType string
	value     []byte
	double    *ratstest.Server
	srv       *httptest.Server
}

func newRATSFixture(t *testing.T, appraise ratstest.Appraise) *ratsFixture {
	t.Helper()
	sim, err := tee.NewSimulated([]byte("acp-compute-worker-v1"), bytes.Repeat([]byte{0x11}, 32))
	require.NoError(t, err)
	nonce := tee.Nonce(bytes.Repeat([]byte{0x5c}, 32))
	statement, err := sim.Quote(nonce)
	require.NoError(t, err)
	mediaType, value, err := tee.WrapEvidence(tee.ProviderSimulated, statement, nil)
	require.NoError(t, err)
	double := &ratstest.Server{Submod: "SIM", PolicyID: "policy:sim", Accept: []string{mediaType}, Appraise: appraise, Build: "double-1"}
	srv := httptest.NewServer(double.Handler())
	t.Cleanup(srv.Close)
	return &ratsFixture{sim: sim, nonce: nonce, mediaType: mediaType, value: value, double: double, srv: srv}
}

func (f *ratsFixture) verifier(t *testing.T, mutate func(*tee.RATSVerifierConfig)) *tee.RATSVerifier {
	t.Helper()
	key, err := tee.ParseEARPublicKey(f.double.PublicJWK())
	require.NoError(t, err)
	cfg := tee.RATSVerifierConfig{URL: f.srv.URL, EARPublicKey: key, PolicyID: "policy:sim", Timeout: 5 * time.Second}
	if mutate != nil {
		mutate(&cfg)
	}
	v, err := tee.NewRATSVerifier(tee.ProviderSimulated, f.sim.Measurement(), cfg)
	require.NoError(t, err)
	return v
}

// The record goes to the Verifier under its type; the EAR comes back
// affirming for this session's nonce; the measurement read from the
// record matches the pin; the detail carries the EAR, re-verifiable
// under the Verifier's key.
func TestRATSVerifier_DelegatesAndKeepsThePin(t *testing.T) {
	t.Parallel()
	var sawType string
	var sawValue, sawNonce []byte
	f := newRATSFixture(t, func(mediaType string, value, nonce []byte) (string, map[string]any) {
		sawType, sawValue, sawNonce = mediaType, value, nonce
		return "affirming", map[string]any{"size": len(value)}
	})
	v := f.verifier(t, nil)
	m, detail, err := v.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.NoError(t, err)
	require.True(t, f.sim.Measurement().Equal(m))
	require.Equal(t, f.mediaType, sawType)
	require.Equal(t, f.value, sawValue, "the Verifier was handed the record's value as it travelled")
	require.Equal(t, []byte(f.nonce), sawNonce, "the simulated family's session nonce is the challenge itself")
	require.NotNil(t, detail)
	require.Equal(t, tee.ProviderSimulated, detail.Provider)
	require.NotNil(t, detail.Verifier)
	vr := detail.Verifier
	require.Equal(t, f.srv.URL, vr.URL)
	require.Equal(t, "SIM", vr.Submod)
	require.Equal(t, tee.EARStatusAffirming, vr.Status)
	require.Equal(t, "policy:sim", vr.PolicyID)
	require.Equal(t, map[string]int{"hardware": 2, "runtime-opaque": 2}, vr.TrustVector)
	require.Equal(t, "double-1", vr.VerifierBuild)
	require.Positive(t, vr.IssuedAt)
	// The audit artifact: the EAR verifies again, offline, under the Verifier's key.
	ear, err := tee.VerifyEAR(vr.EAR, f.double.PublicKey())
	require.NoError(t, err)
	require.Equal(t, []byte(f.nonce), ear.Nonce)
	// The bare-Evidence paths take the same road.
	statement, err := f.sim.Quote(f.nonce)
	require.NoError(t, err)
	m2, err := v.Verify(statement, f.nonce)
	require.NoError(t, err)
	require.True(t, m.Equal(m2))
	m3, d3, err := v.VerifyDetailed(statement, f.nonce)
	require.NoError(t, err)
	require.True(t, m.Equal(m3))
	require.NotNil(t, d3.Verifier)
	require.NotNil(t, tee.RecordVerifierOf(v))
}

// Veraison may answer the evidence with 202 and complete the session
// later: the verifier polls and takes the result.
func TestRATSVerifier_WaitsForAnAsynchronousResult(t *testing.T) {
	t.Parallel()
	f := newRATSFixture(t, nil)
	f.double.Async = true
	v := f.verifier(t, nil)
	m, detail, err := v.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.NoError(t, err)
	require.True(t, f.sim.Measurement().Equal(m))
	require.Equal(t, tee.EARStatusAffirming, detail.Verifier.Status)
}

// What the Verifier says against the peer, or against the policy, refuses the peer, naming the Verifier.
func TestRATSVerifier_TheVerdictAndThePolicyRefuse(t *testing.T) {
	t.Parallel()
	status := "contraindicated"
	f := newRATSFixture(t, func(string, []byte, []byte) (string, map[string]any) { return status, nil })
	v := f.verifier(t, nil)
	_, _, err := v.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.ErrorContains(t, err, "says SIM: contraindicated")
	require.ErrorContains(t, err, f.srv.URL)
	require.Equal(t, shared_errors.CodeAttestationDenied, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))

	// warning is refused by default and admitted only when the policy says so.
	status = "warning"
	_, _, err = v.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.ErrorContains(t, err, "says SIM: warning")
	lenient := f.verifier(t, func(c *tee.RATSVerifierConfig) { c.Accept = []string{tee.EARStatusAffirming, tee.EARStatusWarning} })
	_, detail, err := lenient.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.NoError(t, err)
	require.Equal(t, tee.EARStatusWarning, detail.Verifier.Status)

	// none never admits.
	status = "none"
	_, _, err = lenient.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.ErrorContains(t, err, "says SIM: none")

	// The policy that appraised must be the one required; the appraisal judged by must exist.
	status = "affirming"
	strict := f.verifier(t, func(c *tee.RATSVerifierConfig) { c.PolicyID = "policy:bank-2026" })
	_, _, err = strict.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.ErrorContains(t, err, `appraised under policy "policy:sim", this side requires "policy:bank-2026"`)
	named := f.verifier(t, func(c *tee.RATSVerifierConfig) { c.Submod = "TDX" })
	_, _, err = named.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.ErrorContains(t, err, `no appraisal named "TDX"`)

	// The pin is ours: an affirming Verifier does not admit a peer whose measurement is not the pinned one.
	key, err := tee.ParseEARPublicKey(f.double.PublicJWK())
	require.NoError(t, err)
	otherPin, err := tee.NewRATSVerifier(tee.ProviderSimulated, tee.Measurement(bytes.Repeat([]byte{0xee}, 32)),
		tee.RATSVerifierConfig{URL: f.srv.URL, EARPublicKey: key})
	require.NoError(t, err)
	_, _, err = otherPin.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.ErrorContains(t, err, "differs from the pin")
	require.Equal(t, shared_errors.CodeAttestationDenied, shared_errors.CodeOf(err))
}

// A record of another type is refused before any request is made; so is a message this side cannot read.
func TestRATSVerifier_RefusesBeforeAskingWhatItCannotPin(t *testing.T) {
	t.Parallel()
	f := newRATSFixture(t, nil)
	v := f.verifier(t, nil)
	_, _, err := v.VerifyRecord(tee.MediaTypeTSMReportJSON, f.value, f.nonce)
	require.ErrorContains(t, err, "this peer verifier is simulated")
	_, _, err = v.VerifyRecord(f.mediaType, []byte("not a statement"), f.nonce)
	require.ErrorContains(t, err, "not a simulated statement")
	_, _, err = v.VerifyRecord(f.mediaType, f.value, tee.Nonce("short"))
	require.ErrorContains(t, err, "NonceMinBytes")
	require.Equal(t, 0, f.double.Requests(), "no request reached the Verifier")
}

// The Verifier unreachable, refusing a session, or answering with no
// result: the peer is refused and the Verifier named — nothing is
// admitted on a missing verdict.
func TestRATSVerifier_FailsClosedWhenTheVerifierDoesNot_Answer(t *testing.T) {
	t.Parallel()
	f := newRATSFixture(t, nil)
	key, err := tee.ParseEARPublicKey(f.double.PublicJWK())
	require.NoError(t, err)
	down := httptest.NewServer(http.NotFoundHandler())
	url := down.URL
	down.Close()
	v, err := tee.NewRATSVerifier(tee.ProviderSimulated, f.sim.Measurement(), tee.RATSVerifierConfig{URL: url, EARPublicKey: key, Timeout: 2 * time.Second})
	require.NoError(t, err)
	_, _, err = v.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.ErrorContains(t, err, "the Verifier at "+url)
	require.ErrorContains(t, err, "no session")
	require.Equal(t, "verifier_unavailable", shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(broken.Close)
	v, err = tee.NewRATSVerifier(tee.ProviderSimulated, f.sim.Measurement(), tee.RATSVerifierConfig{URL: broken.URL, EARPublicKey: key})
	require.NoError(t, err)
	_, _, err = v.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.ErrorContains(t, err, "refused a session: HTTP 500")

	// A session that fails instead of completing.
	failing := newRATSFixture(t, func(string, []byte, []byte) (string, map[string]any) { return "", nil })
	fv := failing.verifier(t, nil)
	_, _, err = fv.VerifyRecord(failing.mediaType, failing.value, failing.nonce)
	require.ErrorContains(t, err, "no attestation result")
	require.Equal(t, "verifier_unavailable", shared_errors.CodeOf(err))
}

// An EAR for another session's nonce, or signed by another key, is not this appraisal.
func TestRATSVerifier_RefusesAnEARThatIsNotThisSessions(t *testing.T) {
	t.Parallel()
	f := newRATSFixture(t, nil)
	// A Verifier that signs the right claims for the wrong nonce.
	liar := &ratstest.Server{Submod: "SIM", PolicyID: "policy:sim"}
	liarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/challenge-response/v1/newSession":
			w.Header().Set("Location", "session/abc")
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost:
			ear, err := ratstest.SignEAR(liar.PublicKeyFor(), map[string]any{
				"eat_profile": tee.EARProfile, "iat": time.Now().Unix(),
				"eat_nonce":       base64.RawURLEncoding.EncodeToString([]byte("another session's nonce, 32 byte")),
				"ear.verifier-id": map[string]string{"developer": "liar", "build": "0"},
				"submods":         map[string]any{"SIM": map[string]any{"ear.status": "affirming", "ear.appraisal-policy-id": "policy:sim"}},
			})
			require.NoError(t, err)
			w.Header().Set("Content-Type", ratstest.SessionMediaType)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "complete", "result": ear})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(liarSrv.Close)
	key, err := tee.ParseEARPublicKey(liar.PublicJWK())
	require.NoError(t, err)
	v, err := tee.NewRATSVerifier(tee.ProviderSimulated, f.sim.Measurement(), tee.RATSVerifierConfig{URL: liarSrv.URL, EARPublicKey: key})
	require.NoError(t, err)
	_, _, err = v.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.ErrorContains(t, err, "eat_nonce is not this session's nonce")

	// The right Verifier, the wrong key on file.
	otherKey, err := tee.ParseEARPublicKey((&ratstest.Server{}).PublicJWK())
	require.NoError(t, err)
	wrongKey, err := tee.NewRATSVerifier(tee.ProviderSimulated, f.sim.Measurement(), tee.RATSVerifierConfig{URL: f.srv.URL, EARPublicKey: otherKey})
	require.NoError(t, err)
	_, _, err = wrongKey.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.ErrorContains(t, err, "does not verify under the Verifier's key")
}

// A Verifier is asked over TLS: its certificate must chain to the CA on
// file; plain http is for loopback only.
func TestRATSVerifier_TLSAndTheURLRules(t *testing.T) {
	t.Parallel()
	f := newRATSFixture(t, nil)
	key, err := tee.ParseEARPublicKey(f.double.PublicJWK())
	require.NoError(t, err)
	tlsSrv := httptest.NewTLSServer(f.double.Handler())
	t.Cleanup(tlsSrv.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw})

	withCA, err := tee.NewRATSVerifier(tee.ProviderSimulated, f.sim.Measurement(), tee.RATSVerifierConfig{URL: tlsSrv.URL, EARPublicKey: key, CAPEM: caPEM})
	require.NoError(t, err)
	m, _, err := withCA.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.NoError(t, err)
	require.True(t, f.sim.Measurement().Equal(m))

	withoutCA, err := tee.NewRATSVerifier(tee.ProviderSimulated, f.sim.Measurement(), tee.RATSVerifierConfig{URL: tlsSrv.URL, EARPublicKey: key})
	require.NoError(t, err)
	_, _, err = withoutCA.VerifyRecord(f.mediaType, f.value, f.nonce)
	require.ErrorContains(t, err, "no session")
	require.Equal(t, "verifier_unavailable", shared_errors.CodeOf(err))

	for _, bad := range []string{"http://verifier.bank.example", "ftp://localhost", "localhost:8080", ""} {
		_, err := tee.NewRATSVerifier(tee.ProviderSimulated, f.sim.Measurement(), tee.RATSVerifierConfig{URL: bad, EARPublicKey: key})
		require.Error(t, err, bad)
	}
	_, err = tee.NewRATSVerifier(tee.ProviderSimulated, f.sim.Measurement(), tee.RATSVerifierConfig{URL: "http://127.0.0.1:1", EARPublicKey: key})
	require.NoError(t, err, "loopback may be plain http")
	_, err = tee.NewRATSVerifier(tee.ProviderSimulated, f.sim.Measurement(), tee.RATSVerifierConfig{URL: "https://verifier.bank.example", EARPublicKey: key, CAPEM: []byte("not a certificate")})
	require.ErrorContains(t, err, "no certificate")
}

// What cannot be built: a family without a reader for the pin, a pin of
// the wrong length, a policy that would admit a contraindicated peer, no key.
func TestNewRATSVerifier_Refusals(t *testing.T) {
	t.Parallel()
	key, err := tee.ParseEARPublicKey((&ratstest.Server{}).PublicJWK())
	require.NoError(t, err)
	pin32 := tee.Measurement(bytes.Repeat([]byte{1}, 32))
	cfg := tee.RATSVerifierConfig{URL: "https://verifier.bank.example", EARPublicKey: key}
	_, err = tee.NewRATSVerifier(tee.ProviderAWSNitro, tee.Measurement(bytes.Repeat([]byte{1}, 48)), cfg)
	require.ErrorContains(t, err, "no reader for the measurement of a aws-nitro peer")
	_, err = tee.NewRATSVerifier(tee.ProviderGCPSEVSNP, pin32, cfg)
	require.ErrorContains(t, err, "the pin for gcp-sev-snp is 48 bytes, got 32")
	_, err = tee.NewRATSVerifier(tee.ProviderAuto, pin32, cfg)
	require.Error(t, err)
	bad := cfg
	bad.Accept = []string{"contraindicated"}
	_, err = tee.NewRATSVerifier(tee.ProviderSimulated, pin32, bad)
	require.ErrorContains(t, err, "only affirming and warning")
	noKey := cfg
	noKey.EARPublicKey = nil
	_, err = tee.NewRATSVerifier(tee.ProviderSimulated, pin32, noKey)
	require.ErrorContains(t, err, "EAR public key is required")
	v, err := tee.NewRATSVerifier(tee.ProviderGCPSEVSNP, tee.Measurement(bytes.Repeat([]byte{1}, 48)), cfg)
	require.NoError(t, err)
	require.Equal(t, "https://verifier.bank.example", v.URL())
}
