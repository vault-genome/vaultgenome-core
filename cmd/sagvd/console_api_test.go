// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/console"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// consoleFixture is the listener on loopback over a simulated chip, an audit
// log and one sealed genome.
type consoleFixture struct {
	srv      *consoleServer
	fx       *testHTTPFixture
	chip     *tee.Simulated
	verifier tee.Verifier
	dir      string
	stop     OperatorStopConfig
	certDER  []byte
}

func newConsoleFixture(t *testing.T) *consoleFixture {
	t.Helper()
	fx := newTestFixture(t, "")
	dir := t.TempDir()
	chip, err := tee.NewSimulated([]byte("sagvd-console-test"), bytes.Repeat([]byte{7}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	cfg := DefaultConfig()
	cfg.Console = ConsoleConfig{ListenAddress: "127.0.0.1:0", Dir: dir}
	cfg.OperatorStop = OperatorStopConfig{KeyID: console.StopKeyID, PublicKeyPath: filepath.Join(dir, "operator_stop.pem"), ListPath: filepath.Join(dir, "stop_list.json")}
	cfg.Genome.BundleDir = fx.dir
	mat := &materials{Producer: chip, Provider: tee.ProviderSimulated, tee: cfg.TEE}
	srv, err := newConsoleServer(cfg, mat, fx.server, fx.queue, fx.audit, shared_time.NewSystemClock(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	require.NoError(t, srv.Start())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Close(ctx)
	})
	return &consoleFixture{srv: srv, fx: fx, chip: chip, verifier: tee.NewSimulatedVerifier(chip.PublicKey(), chip.Measurement()),
		dir: dir, stop: cfg.OperatorStop, certDER: srv.cert.Certificate[0]}
}

// person is one console: a key of its own and a client that pins the listener.
type consolePerson struct {
	priv   ed25519.PrivateKey
	client *http.Client
	base   string
}

func (f *consoleFixture) person(t *testing.T) *consolePerson {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(f.certDER)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &consolePerson{priv: priv, base: "https://" + f.srv.Addr(), client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: console.ServerName, MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}},
	}}}
}

func (p *consolePerson) do(t *testing.T, method, path string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, p.base+path, bytes.NewReader(body))
	require.NoError(t, err)
	resp, err := p.client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, raw
}

func (p *consolePerson) doJSON(t *testing.T, method, path string, in any) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(in)
	require.NoError(t, err)
	return p.do(t, method, path, body)
}

func errCode(t *testing.T, raw []byte) string {
	t.Helper()
	var e console.ErrorBody
	require.NoError(t, json.Unmarshal(raw, &e))
	return e.Code
}

// invite writes what `acpctl console invite` writes and returns the code.
func (f *consoleFixture) invite(t *testing.T, name string, role console.Role, ttl time.Duration) string {
	t.Helper()
	code := hex.EncodeToString(bytes.Repeat([]byte{byte(len(name)), byte(len(role)), byte(ttl / time.Hour)}, 10))
	raw, err := json.Marshal(console.Invite{Name: name, Role: role, ExpiresAt: time.Now().Add(ttl)})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.srv.invitePath(code), raw, 0o600))
	return code
}

func (f *consoleFixture) join(t *testing.T, name string, role console.Role) *consolePerson {
	t.Helper()
	p := f.person(t)
	status, raw := p.doJSON(t, http.MethodPost, "/v1/console/join", console.JoinRequest{Code: f.invite(t, name, role, time.Hour)})
	require.Equal(t, http.StatusOK, status, string(raw))
	return p
}

func (f *consoleFixture) check(t *testing.T, p *consolePerson) console.State {
	t.Helper()
	challenge := make([]byte, console.NonceBytes)
	_, err := rand.Read(challenge)
	require.NoError(t, err)
	status, raw := p.doJSON(t, http.MethodPost, "/v1/console/check", console.CheckRequest{NonceHex: hex.EncodeToString(challenge)})
	require.Equal(t, http.StatusOK, status, string(raw))
	var resp console.CheckResponse
	require.NoError(t, json.Unmarshal(raw, &resp))
	v, err := console.VerifyCheck(f.verifier, challenge, f.certDER, resp)
	require.NoError(t, err)
	return v.State
}

func (p *consolePerson) signStop(t *testing.T, serial uint64, stop bool) []byte {
	t.Helper()
	key, err := crypto.LoadSigningKey(crypto.SuiteEd25519, p.priv.Seed())
	require.NoError(t, err)
	defer key.Zeroize()
	signed, err := revocation.Sign(revocation.List{Serial: serial, IssuedAt: time.Now().UTC().Truncate(time.Second), StopAll: stop, SigningKeyID: console.StopKeyID}, key)
	require.NoError(t, err)
	raw, err := json.Marshal(signed)
	require.NoError(t, err)
	return raw
}

func (f *consoleFixture) actions() map[string]int {
	out := map[string]int{}
	for i := f.srv.audit.Base(); i < f.srv.audit.Len(); i++ {
		e, ok := f.srv.audit.EventAt(i)
		if !ok || e.Kind != audit_event.KindConsoleAction {
			continue
		}
		var p console.ActionPayload
		if json.Unmarshal(e.Payload, &p) == nil {
			out[p.Action]++
		}
	}
	return out
}

// A pass opens once, for one key, before its time is up; everything else at
// the door is refused, and a key nobody listed gets nothing past it.
func TestConsoleJoinIsSingleUse(t *testing.T) {
	f := newConsoleFixture(t)
	stranger := f.person(t)

	status, raw := stranger.doJSON(t, http.MethodPost, "/v1/console/check", console.CheckRequest{NonceHex: strings.Repeat("00", console.NonceBytes)})
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "not_listed", errCode(t, raw))
	status, raw = stranger.do(t, http.MethodGet, "/v1/console/journal", nil)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "not_listed", errCode(t, raw))

	status, raw = stranger.doJSON(t, http.MethodPost, "/v1/console/join", console.JoinRequest{Code: "made-up"})
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "invite_unknown", errCode(t, raw))
	status, raw = stranger.doJSON(t, http.MethodPost, "/v1/console/join", console.JoinRequest{})
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "invite_unknown", errCode(t, raw))

	expired := f.invite(t, "Late", console.RoleViewer, -time.Hour)
	status, raw = stranger.doJSON(t, http.MethodPost, "/v1/console/join", console.JoinRequest{Code: expired})
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "invite_expired", errCode(t, raw))
	require.NoFileExists(t, f.srv.invitePath(expired))

	code := f.invite(t, "Anna", console.RoleViewer, time.Hour)
	anna := f.person(t)
	status, raw = anna.doJSON(t, http.MethodPost, "/v1/console/join", console.JoinRequest{Code: code})
	require.Equal(t, http.StatusOK, status, string(raw))
	require.NoFileExists(t, f.srv.invitePath(code))
	status, raw = stranger.doJSON(t, http.MethodPost, "/v1/console/join", console.JoinRequest{Code: code})
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "invite_unknown", errCode(t, raw))
	// Opening the pass again on the same computer is not an error.
	status, _ = anna.doJSON(t, http.MethodPost, "/v1/console/join", console.JoinRequest{Code: code})
	require.Equal(t, http.StatusOK, status)
	st := f.check(t, anna)
	require.Equal(t, "Anna", st.You.Name)
	require.Len(t, st.People, 1)
	require.Equal(t, 1, f.actions()[console.ActionPersonJoined], "joining is on the record, once")

	// The list survives a restart of the listener's process.
	raw, err := os.ReadFile(f.srv.peoplePath())
	require.NoError(t, err)
	var people []console.Person
	require.NoError(t, json.Unmarshal(raw, &people))
	require.Equal(t, "Anna", people[0].Name)
}

// A client that does not show a key does not get in at all.
func TestConsoleRefusesAClientWithoutAKey(t *testing.T) {
	f := newConsoleFixture(t)
	p := f.person(t)
	tr := p.client.Transport.(*http.Transport)
	tr.TLSClientConfig.Certificates = nil
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, p.base+"/v1/console/check", strings.NewReader("{}"))
	require.NoError(t, err)
	resp, err := p.client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("a client with no key was served")
	}
}

// The check's answer carries the state as it stands, verified on the caller's
// side; a malformed challenge gets no report.
func TestConsoleCheck(t *testing.T) {
	f := newConsoleFixture(t)
	owner := f.join(t, "Serhii", console.RoleOwner)
	st := f.check(t, owner)
	require.Equal(t, console.StateSchema, st.Schema)
	require.Equal(t, string(tee.ProviderSimulated), st.Provider)
	require.Equal(t, hex.EncodeToString(f.chip.Measurement()), st.MeasurementHex)
	require.Equal(t, f.srv.audit.Tip(), st.Audit.TipHex)
	require.Equal(t, f.srv.audit.Len(), st.Audit.Events)
	require.NotEmpty(t, st.Genomes)
	require.Equal(t, hex.EncodeToString(owner.priv.Public().(ed25519.PublicKey)), st.Stop.HolderPublicKeyHex, "the first owner holds the stop")

	status, raw := owner.doJSON(t, http.MethodPost, "/v1/console/check", console.CheckRequest{NonceHex: "abcd"})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "nonce_invalid", errCode(t, raw))
	status, _ = owner.do(t, http.MethodPost, "/v1/console/check", []byte(`{"nonce_hex":"00","extra":1}`))
	require.Equal(t, http.StatusBadRequest, status, "unknown fields")
}

// The journal is read from the running daemon and verifies under the audit
// key on the caller's side.
func TestConsoleJournal(t *testing.T) {
	f := newConsoleFixture(t)
	owner := f.join(t, "Serhii", console.RoleOwner)
	status, raw := owner.do(t, http.MethodGet, "/v1/console/journal?from=0", nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	var page console.JournalPage
	require.NoError(t, json.Unmarshal(raw, &page))
	require.Equal(t, f.srv.audit.Len(), len(page.Events))
	tip, err := console.VerifyEvents(page.Events, page.From, nil, f.fx.audit.keys)
	require.NoError(t, err)
	require.Equal(t, f.srv.audit.Tip(), hex.EncodeToString(tip))
	status, raw = owner.do(t, http.MethodGet, "/v1/console/journal?from=abc", nil)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "from_invalid", errCode(t, raw))
	status, raw = owner.do(t, http.MethodGet, "/v1/console/journal?from=100000", nil)
	require.Equal(t, http.StatusOK, status)
	require.NoError(t, json.Unmarshal(raw, &page))
	require.Empty(t, page.Events)
}

// The stop list is only ever signed on the holder's side: the daemon verifies
// it, refuses any other signer and any list not newer than the one in force,
// and writes the change on the record first.
func TestConsoleStop(t *testing.T) {
	f := newConsoleFixture(t)
	owner := f.join(t, "Serhii", console.RoleOwner)

	status, raw := owner.do(t, http.MethodPut, "/v1/console/stop", owner.signStop(t, 1, false))
	require.Equal(t, http.StatusOK, status, string(raw))
	st := f.check(t, owner)
	require.Equal(t, uint64(1), st.Stop.Serial)
	require.False(t, st.Stop.StopAll)

	status, raw = owner.do(t, http.MethodPut, "/v1/console/stop", owner.signStop(t, 2, true))
	require.Equal(t, http.StatusOK, status, string(raw))
	st = f.check(t, owner)
	require.True(t, st.Stop.StopAll)

	status, raw = owner.do(t, http.MethodPut, "/v1/console/stop", owner.signStop(t, 2, false))
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "list_old", errCode(t, raw))

	other := f.join(t, "Second Owner", console.RoleOwner)
	status, raw = other.do(t, http.MethodPut, "/v1/console/stop", other.signStop(t, 3, false))
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "list_refused", errCode(t, raw))
	require.Equal(t, hex.EncodeToString(owner.priv.Public().(ed25519.PublicKey)), f.check(t, other).Stop.HolderPublicKeyHex, "the second owner does not take the stop")

	status, _ = owner.do(t, http.MethodPut, "/v1/console/stop", []byte("not a list"))
	require.Equal(t, http.StatusForbidden, status)

	status, raw = owner.do(t, http.MethodPut, "/v1/console/stop", owner.signStop(t, 3, false))
	require.Equal(t, http.StatusOK, status, string(raw))
	require.False(t, f.check(t, owner).Stop.StopAll)

	acts := f.actions()
	require.Equal(t, 1, acts[console.ActionStopReady])
	require.Equal(t, 1, acts[console.ActionStopSet])
	require.Equal(t, 1, acts[console.ActionStopLifted])
}

// A role is enforced by the listener, not by the page.
func TestConsoleRoles(t *testing.T) {
	f := newConsoleFixture(t)
	owner := f.join(t, "Serhii", console.RoleOwner)
	viewer := f.join(t, "Viewer", console.RoleViewer)
	operator := f.join(t, "Operator", console.RoleOperator)

	status, raw := viewer.do(t, http.MethodPost, "/v1/console/restore-check", nil)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "role_refused", errCode(t, raw))
	status, raw = viewer.do(t, http.MethodPut, "/v1/console/stop", owner.signStop(t, 1, true))
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "role_refused", errCode(t, raw))
	status, raw = operator.do(t, http.MethodPut, "/v1/console/stop", owner.signStop(t, 1, true))
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "role_refused", errCode(t, raw))
	status, raw = operator.doJSON(t, http.MethodPost, "/v1/console/invites", console.InviteRequest{Name: "X", Role: console.RoleViewer})
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "role_refused", errCode(t, raw))

	status, raw = operator.do(t, http.MethodPost, "/v1/console/restore-check", nil)
	require.Equal(t, http.StatusAccepted, status, string(raw))
	var r console.RestoreResponse
	require.NoError(t, json.Unmarshal(raw, &r))
	require.Equal(t, "gen-0.genome", r.Bundle)

	// The journal says whose request it was.
	found := false
	for i := f.srv.audit.Base(); i < f.srv.audit.Len(); i++ {
		e, ok := f.srv.audit.EventAt(i)
		if ok && e.Kind == audit_event.KindRequestReceived && strings.Contains(string(e.Payload), `"requester_identity":"person:Operator"`) {
			found = true
		}
	}
	require.True(t, found, "REQUEST_RECEIVED names the person")

	status, raw = viewer.do(t, http.MethodGet, "/v1/console/jobs/"+r.JobID, nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	require.NotContains(t, string(raw), "bytes_hex", "a job as the console shows it carries no model output")
	status, _ = viewer.do(t, http.MethodGet, "/v1/console/jobs/nope", nil)
	require.Equal(t, http.StatusNotFound, status)
}

// Inviting and removing go on the record; the holder of the stop cannot be
// removed, and a removed person is out at once.
func TestConsoleInviteAndRemove(t *testing.T) {
	f := newConsoleFixture(t)
	owner := f.join(t, "Serhii", console.RoleOwner)

	status, raw := owner.doJSON(t, http.MethodPost, "/v1/console/invites", console.InviteRequest{Name: "<script>", Role: console.RoleViewer})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invite_invalid", errCode(t, raw))
	status, raw = owner.doJSON(t, http.MethodPost, "/v1/console/invites", console.InviteRequest{Name: "Anna", Role: "admin"})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invite_invalid", errCode(t, raw))

	status, raw = owner.doJSON(t, http.MethodPost, "/v1/console/invites", console.InviteRequest{Name: "Анна К.", Role: console.RoleViewer})
	require.Equal(t, http.StatusOK, status, string(raw))
	var inv console.InviteResponse
	require.NoError(t, json.Unmarshal(raw, &inv))
	anna := f.person(t)
	status, raw = anna.doJSON(t, http.MethodPost, "/v1/console/join", console.JoinRequest{Code: inv.Code})
	require.Equal(t, http.StatusOK, status, string(raw))
	annaKey := hex.EncodeToString(anna.priv.Public().(ed25519.PublicKey))

	ownerKey := hex.EncodeToString(owner.priv.Public().(ed25519.PublicKey))
	status, raw = owner.doJSON(t, http.MethodPost, "/v1/console/people/remove", console.RemoveRequest{PublicKeyHex: ownerKey})
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "holder_not_removed", errCode(t, raw))
	status, raw = owner.doJSON(t, http.MethodPost, "/v1/console/people/remove", console.RemoveRequest{PublicKeyHex: "00"})
	require.Equal(t, http.StatusNotFound, status)
	require.Equal(t, "not_listed", errCode(t, raw))

	status, raw = owner.doJSON(t, http.MethodPost, "/v1/console/people/remove", console.RemoveRequest{PublicKeyHex: annaKey})
	require.Equal(t, http.StatusOK, status, string(raw))
	status, raw = anna.doJSON(t, http.MethodPost, "/v1/console/check", console.CheckRequest{NonceHex: strings.Repeat("00", console.NonceBytes)})
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "not_listed", errCode(t, raw))
	acts := f.actions()
	require.Equal(t, 1, acts[console.ActionInviteMade])
	require.Equal(t, 1, acts[console.ActionPersonRemoved])
}

// Nothing changes when the record cannot be written.
func TestConsoleChangesNothingOffTheRecord(t *testing.T) {
	f := newConsoleFixture(t)
	owner := f.join(t, "Serhii", console.RoleOwner)
	require.NoError(t, f.fx.audit.Close())
	status, raw := owner.do(t, http.MethodPut, "/v1/console/stop", owner.signStop(t, 1, true))
	require.Equal(t, http.StatusServiceUnavailable, status)
	require.Equal(t, "audit_unavailable", errCode(t, raw))
	require.NoFileExists(t, f.stop.ListPath)
}

// The listener's identity outlives a restart: the key is read back, and a
// pass made before the restart still pins it.
func TestConsoleCertificatePersists(t *testing.T) {
	f := newConsoleFixture(t)
	cfg := DefaultConfig()
	cfg.Console = ConsoleConfig{ListenAddress: "127.0.0.1:0", Dir: f.dir}
	cfg.OperatorStop = f.stop
	again, err := consoleTLSCertificate(cfg, f.srv.mat, shared_time.NewSystemClock())
	require.NoError(t, err)
	require.Equal(t, f.certDER, again.Certificate[0])
}

// Before the first owner has joined nobody holds the stop and nothing is
// refused for it; from the moment the key exists, ADR 0010's rule: no valid
// list, nothing released; an older serial, refused.
func TestConsoleStopSource(t *testing.T) {
	dir := t.TempDir()
	cfg := OperatorStopConfig{KeyID: "operator-test", PublicKeyPath: filepath.Join(dir, "operator.pem"), ListPath: filepath.Join(dir, "list.json")}
	src := newConsoleStopSource(cfg, kms.DefaultSignaturePolicy())
	list, err := src()
	require.NoError(t, err)
	require.False(t, list.StopAll)

	priv, err := crypto.GenerateSigningKey(crypto.SuiteEd25519, nil)
	require.NoError(t, err)
	pemKey, err := priv.Public().PEM()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfg.PublicKeyPath, pemKey, 0o644))
	_, err = src()
	require.ErrorContains(t, err, "without a valid list nothing is released")

	writeStopList(t, cfg.ListPath, priv, revocation.List{Serial: 2, StopAll: true})
	list, err = src()
	require.NoError(t, err)
	require.True(t, list.StopAll)
	writeStopList(t, cfg.ListPath, priv, revocation.List{Serial: 1})
	_, err = src()
	require.ErrorContains(t, err, "rollback refused")
}
