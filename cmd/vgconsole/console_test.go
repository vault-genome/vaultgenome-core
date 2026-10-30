// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/console"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// jargon is what a person on the page must never have to ask about.
var jargon = regexp.MustCompile(`(?i)attest|measurement|genome|sev-snp|tdx|vlek|vcek|tcb|\bgate\b|\bexact\b|\bequivalent\b|nonce|hash|token|manifest|disclosure|bbolt|fixture|кворум|аттест|геном|хеш|хэш`)

func noJargon(t *testing.T, where, text string) {
	t.Helper()
	require.Falsef(t, jargon.MatchString(text), "%s: %q", where, text)
}

func event(kind audit_event.Kind, payload any) audit_event.AuditEvent {
	raw, _ := json.Marshal(payload)
	return audit_event.AuditEvent{Kind: kind, Payload: raw, OccurredAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
}

// Every record a server can write reads in plain words, in both languages.
func TestEveryRecordReadsPlainly(t *testing.T) {
	kinds := []audit_event.Kind{
		audit_event.KindRequestReceived, audit_event.KindTrustEvaluated, audit_event.KindSessionIssued, audit_event.KindSessionInvalidated,
		audit_event.KindDisclosureAuthorized, audit_event.KindManifestIssued, audit_event.KindCandidateReceived, audit_event.KindValidationStarted,
		audit_event.KindValidationDimension, audit_event.KindValidationFinding, audit_event.KindValidationCompleted, audit_event.KindReleaseDecided,
		audit_event.KindIncidentDetected, audit_event.KindIncidentTerminated, audit_event.KindDisclosureReceived, audit_event.KindReconstitutionDecided,
		audit_event.KindRecvValidationStarted, audit_event.KindRecvValidationCompleted, audit_event.KindCrossCloudHandshakeInitiated,
		audit_event.KindCrossCloudAttestationVerified, audit_event.KindKeyReleaseAuthorized, audit_event.KindCrossCloudRestoreCompleted,
		audit_event.KindKeyReleaseDenied, audit_event.KindFailoverDecided, audit_event.KindAuditSegmentClosed,
	}
	payloads := []map[string]any{
		{}, {"requester_identity": "person:Anna"}, {"requester_identity": "operator:rest"}, {"outcome": "allow"}, {"outcome": "deny", "reason": "trust.operator_stop"},
		{"outcome": "deny", "reason": "trust.other"}, {"detail": map[string]any{"level": "EXACT", "fixtures": 6}}, {"detail": map[string]any{"level": "EQUIVALENT", "fixtures": 6}},
		{"detail": map[string]any{"level": "FAIL"}}, {"release": true}, {"release": false},
	}
	for _, lang := range []string{"ru", "en"} {
		for _, k := range kinds {
			for _, p := range payloads {
				line, ok := describe(event(k, p), 3, lang)
				require.True(t, ok, k)
				require.NotEmpty(t, line.Text, k)
				noJargon(t, string(k), line.Text)
			}
		}
		for _, a := range []string{console.ActionPersonJoined, console.ActionPersonRemoved, console.ActionInviteMade, console.ActionStopReady, console.ActionStopSet, console.ActionStopLifted, console.ActionMoveOrdered, console.ActionModelReleased, console.ActionModelSent} {
			line, ok := describe(event(audit_event.KindConsoleAction, console.ActionPayload{Action: a, Person: "Anna", Subject: "Oleg", Role: console.RoleViewer, Reason: "why"}), 3, lang)
			require.True(t, ok, a)
			require.True(t, strings.Contains(line.Text, "Anna") || strings.Contains(line.Text, "Oleg"), a)
			noJargon(t, a, line.Text)
		}
		line, ok := describe(event(audit_event.KindConsoleAction, console.ActionPayload{Action: console.ActionModelReceived, Person: "AWS Ohio (server)", Bundle: "gen.genome"}), 3, lang)
		require.True(t, ok)
		require.Contains(t, line.Text, "AWS Ohio")
		require.NotContains(t, line.Text, "(server)", "a server is not called a server twice")
		line, ok = describe(event(audit_event.KindConsoleAction, console.ActionPayload{Action: console.ActionModelReceived, Person: "AWS Ohio (server)", Bundle: "gen.genome.escrow"}), 3, lang)
		require.True(t, ok)
		require.True(t, line.Minor, "the key's arrival is a step")
		line, ok = describe(event(audit_event.KindConsoleAction, console.ActionPayload{Action: console.ActionPersonJoined, Person: "AWS Ohio (server)", Role: console.RolePeer}), 3, lang)
		require.True(t, ok)
		require.True(t, line.Minor, "a server's place on the list is a step of the move")
		for _, s := range []string{"unstarted", "request", "trust", "session", "disclosure", "external_compute", "return", "validation", "release", "audit"} {
			text, step := stageText(lang, s)
			noJargon(t, s, text)
			require.GreaterOrEqual(t, step, 1)
		}
	}
	stale, ok := describe(event(audit_event.KindTrustEvaluated, map[string]any{"outcome": "deny", "code": evidenceStaleCode}), 0, "ru")
	require.True(t, ok)
	require.True(t, stale.Minor, "a worker told to attest again is routine")
	require.NotEqual(t, toneBad, stale.Tone)
	_, ok = describe(event(audit_event.KindConsoleAction, console.ActionPayload{Action: "something new"}), 0, "ru")
	require.False(t, ok, "an unknown action is not guessed at")
}

func testOverview(t *testing.T, st console.State, provider tee.Provider, events []audit_event.AuditEvent, lang string) Overview {
	t.Helper()
	a, err := newApp(t.TempDir())
	require.NoError(t, err)
	st.People = append(st.People, console.Person{Name: "Anna", Role: console.RoleOwner, PublicKeyHex: a.publicKeyHex()})
	s := &server{id: "x", provider: provider, you: console.Person{Name: "Anna", Role: console.RoleOwner}, events: events, last: &checkResult{At: time.Now(), State: st}}
	return a.overview(s, lang)
}

// What the page says first follows from what was verified, and nothing on it
// needs a technician.
func TestOverviewVerdicts(t *testing.T) {
	for _, lang := range []string{"ru", "en"} {
		o := testOverview(t, console.State{Audit: console.AuditState{Events: 0}}, tee.ProviderAWSSEVSNP, nil, lang)
		require.Equal(t, "attention", o.Verdict, "no restore yet, no backup server, nobody holds the stop")
		require.False(t, o.CanStop)

		st := console.State{Stop: console.StopState{HolderPublicKeyHex: "will be replaced", Serial: 3, StopAll: true}}
		o = testOverview(t, st, tee.ProviderAWSSEVSNP, nil, lang)
		require.Equal(t, "stopped", o.Verdict)
		require.True(t, o.Stopped)

		for _, l := range o.Lines {
			noJargon(t, l.Title, l.Title)
			noJargon(t, l.Title, l.Text)
		}
		noJargon(t, "headline", o.Headline)
		noJargon(t, "subline", o.Subline)
		noJargon(t, "where", o.Where)
	}

	a, err := newApp(t.TempDir())
	require.NoError(t, err)
	s := &server{id: "x", provider: tee.ProviderAWSSEVSNP, unproven: http.ErrBodyNotAllowed, last: &checkResult{At: time.Now()}}
	o := a.overview(s, "ru")
	require.Equal(t, "unproven", o.Verdict, "a failed proof outranks everything remembered")
	require.Len(t, o.Lines, 1)

	s = &server{id: "x", provider: tee.ProviderAWSSEVSNP}
	require.Equal(t, "unknown", a.overview(s, "ru").Verdict)
}

// A restore's result is read from the journal: from the request to the decision.
func TestLastRestore(t *testing.T) {
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	req := audit_event.AuditEvent{Kind: audit_event.KindRequestReceived, RequestID: "r1", OccurredAt: at, Payload: []byte(`{}`)}
	gate := audit_event.AuditEvent{Kind: audit_event.KindValidationDimension, OccurredAt: at.Add(5 * time.Second), Payload: []byte(`{"detail":{"level":"EXACT","fixtures":6}}`)}
	dec := audit_event.AuditEvent{Kind: audit_event.KindReleaseDecided, RequestID: "r1", OccurredAt: at.Add(8 * time.Second), Payload: []byte(`{"release":true}`)}
	r := lastRestore([]audit_event.AuditEvent{req, gate, dec})
	require.NotNil(t, r)
	require.True(t, r.OK)
	require.Equal(t, 6, r.Matched)
	require.InDelta(t, 8.0, r.Seconds, 0.01)

	denied := audit_event.AuditEvent{Kind: audit_event.KindTrustEvaluated, RequestID: "r2", OccurredAt: at.Add(time.Minute), Payload: []byte(`{"outcome":"deny","reason":"trust.operator_stop"}`)}
	refused := audit_event.AuditEvent{Kind: audit_event.KindReleaseDecided, RequestID: "r2", OccurredAt: at.Add(time.Minute), Payload: []byte(`{"release":false,"reason":"trust_denied"}`)}
	r = lastRestore([]audit_event.AuditEvent{req, gate, dec, denied, refused})
	require.False(t, r.OK)
	require.True(t, r.Stopped, "the stop's refusal is not a failure")

	failedGate := audit_event.AuditEvent{Kind: audit_event.KindValidationDimension, OccurredAt: at.Add(5 * time.Second), Payload: []byte(`{"detail":{"level":"FAIL"}}`)}
	notAccepted := audit_event.AuditEvent{Kind: audit_event.KindReleaseDecided, RequestID: "r1", OccurredAt: at.Add(8 * time.Second), Payload: []byte(`{"release":false}`)}
	r = lastRestore([]audit_event.AuditEvent{req, failedGate, notAccepted})
	require.False(t, r.OK)
	require.False(t, r.Stopped)

	// A peer refused at its handshake is no restore that failed.
	handshake := audit_event.AuditEvent{Kind: audit_event.KindTrustEvaluated, OccurredAt: at.Add(time.Hour), Payload: []byte(`{"outcome":"deny"}`)}
	r = lastRestore([]audit_event.AuditEvent{req, gate, dec, handshake})
	require.True(t, r.OK)

	require.Nil(t, lastRestore(nil))
}

// The page opens only for the browser that was given the token, under the
// address it was given; a page from elsewhere cannot act on it.
func TestWebGuard(t *testing.T) {
	a, err := newApp(t.TempDir())
	require.NoError(t, err)
	const addr, token = "127.0.0.1:1234", "secret-token"
	h := newWeb(a, token, addr).handler()
	serve := func(method, target, host string, set func(*http.Request)) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader("{}"))
		req.Host = host
		if set != nil {
			set(req)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	cookie := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token}) }

	require.Equal(t, http.StatusForbidden, serve("GET", "/", "evil.example:1234", cookie).Code, "a name that resolves here")
	require.Equal(t, http.StatusForbidden, serve("GET", "/", addr, nil).Code, "no token")
	require.Equal(t, http.StatusForbidden, serve("GET", "/?t=wrong", addr, nil).Code)
	rec := serve("GET", "/?t="+token, addr, nil)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	c := rec.Result().Cookies()
	require.Len(t, c, 1)
	require.True(t, c[0].HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, c[0].SameSite)

	rec = serve("GET", "/", addr, cookie)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Header().Get("Content-Security-Policy"), "default-src 'none'")
	require.Contains(t, rec.Body.String(), "Vault Genome")

	require.Equal(t, http.StatusForbidden, serve("GET", "/api/servers", addr, nil).Code)
	require.Equal(t, http.StatusOK, serve("GET", "/api/servers", addr, cookie).Code)
	require.Equal(t, http.StatusForbidden, serve("POST", "/api/check", addr, cookie).Code, "a cross-site form cannot set the header")
	withHeader := func(r *http.Request) { cookie(r); r.Header.Set("X-VG-Console", "1") }
	require.Equal(t, http.StatusUnprocessableEntity, serve("POST", "/api/check", addr, withHeader).Code, "no server yet")
}

// A person's key is made once and kept.
func TestAppKeepsItsKey(t *testing.T) {
	dir := t.TempDir()
	a, err := newApp(dir)
	require.NoError(t, err)
	b, err := newApp(dir)
	require.NoError(t, err)
	require.Equal(t, a.publicKeyHex(), b.publicKeyHex())
}

func TestPlainErrors(t *testing.T) {
	for _, code := range []string{"not_listed", "role_refused", "invite_unknown", "invite_expired", "no_genome", "list_old", "list_refused", "chip_unavailable", "audit_unavailable"} {
		for _, lang := range []string{"ru", "en"} {
			text := plainError(lang, &apiError{Status: 403, ErrorBody: console.ErrorBody{Code: code, Message: "m"}})
			require.NotEqual(t, "m", text, code)
			noJargon(t, code, text)
		}
	}
	require.Contains(t, plainError("en", &console.BrokenJournalError{Index: 4}), "number 5")
	require.Contains(t, plainError("ru", console.ErrNotAPass), ".vgpass")
	require.Contains(t, plainError("ru", errString("tls: failed to verify certificate")), "не тот сервер")
	require.Contains(t, plainError("en", errString("dial tcp: connection refused")), "does not answer")
	require.Contains(t, plainError("en", errString("anything else")), "failed the check")
}

type errString string

func (e errString) Error() string { return string(e) }

// A console opened again finds the one already running, by asking it, and a
// stale address left behind is no reason to believe anything.
func TestAlreadyRunning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "running.url")
	_, ok := alreadyRunning(path)
	require.False(t, ok, "no file")

	a, err := newApp(t.TempDir())
	require.NoError(t, err)
	srv := httptest.NewServer(nil)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Config.Handler = newWeb(a, "tk", addr).handler()
	require.NoError(t, os.WriteFile(path, []byte(srv.URL+"/?t=tk"), 0o600))
	url, ok := alreadyRunning(path)
	require.True(t, ok)
	require.Equal(t, srv.URL+"/?t=tk", url)

	require.NoError(t, os.WriteFile(path, []byte(srv.URL+"/?t=wrong"), 0o600))
	_, ok = alreadyRunning(path)
	require.False(t, ok, "another console's address")

	require.NoError(t, os.WriteFile(path, []byte("http://127.0.0.1:1/?t=tk"), 0o600))
	_, ok = alreadyRunning(path)
	require.False(t, ok, "nothing answers")
}

// An order for a person's move names only what the listener allows.
func TestPeerName(t *testing.T) {
	require.Equal(t, "AWS Ohio kit (server)", peerName("AWS Ohio, kit"))
	require.Equal(t, "Server (server)", peerName("!!!"))
	long := peerName(strings.Repeat("a", 200))
	require.LessOrEqual(t, len(long), 64)
}
