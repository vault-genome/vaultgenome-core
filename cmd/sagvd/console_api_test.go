// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
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

// moveFixture is two listeners: the source with a sealed model, the target with
// none of its own and an escrow key, its private half with the target.
type moveFixture struct {
	from, to *consoleFixture
	owner    *consolePerson
	toOwner  *consolePerson
	pin      console.Pin
	key      *crypto.SigningKey
	bundle   string
}

func newMoveFixture(t *testing.T) *moveFixture {
	t.Helper()
	from := newConsoleFixture(t)
	to := newConsoleFixture(t)
	require.NoError(t, os.Remove(filepath.Join(to.fx.dir, "gen-0.genome")))
	require.NoError(t, os.Remove(filepath.Join(to.fx.dir, "gen-0.key")))
	kem, err := escrow.GenerateKey(kms.SuiteHPKEX25519)
	require.NoError(t, err)
	to.srv.mat.Escrow = kem
	to.fx.server.genomes.escrow = kem
	owner := from.join(t, "Serhii", console.RoleOwner)
	status, raw := owner.do(t, http.MethodPut, "/v1/console/stop", owner.signStop(t, 1, false))
	require.Equal(t, http.StatusOK, status, string(raw))
	toOwner := to.join(t, "Serhii", console.RoleOwner)
	key, err := crypto.LoadSigningKey(crypto.SuiteEd25519, owner.priv.Seed())
	require.NoError(t, err)
	t.Cleanup(key.Zeroize)
	pin := console.Pin{Provider: string(tee.ProviderSimulated), MeasurementHex: hex.EncodeToString(to.chip.Measurement()), AttestorPublicKeyHex: hex.EncodeToString(to.chip.PublicKey())}
	return &moveFixture{from: from, to: to, owner: owner, toOwner: toOwner, pin: pin, key: key, bundle: "gen-0.genome"}
}

func (m *moveFixture) code(t *testing.T) string {
	t.Helper()
	status, raw := m.toOwner.doJSON(t, http.MethodPost, "/v1/console/invites", console.InviteRequest{Name: "Source (server)", Role: console.RolePeer, Hours: 1})
	require.Equal(t, http.StatusOK, status, string(raw))
	var inv console.InviteResponse
	require.NoError(t, json.Unmarshal(raw, &inv))
	return inv.Code
}

func (m *moveFixture) order(t *testing.T, id string, mutate func(*console.MoveOrder)) []byte {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	o := console.MoveOrder{
		OrderID: id, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), FromCertSHA256: console.CertSHA256(m.from.certDER),
		Bundle: m.bundle, SigningKeyID: console.StopKeyID,
		To: console.MoveTarget{Label: "Target", Address: m.to.srv.Addr(), ServerCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.to.certDER})), Pin: m.pin, JoinCode: m.code(t)},
	}
	if mutate != nil {
		mutate(&o)
	}
	signed, err := console.SignMoveOrder(o, m.key)
	require.NoError(t, err)
	raw, err := json.Marshal(signed)
	require.NoError(t, err)
	return raw
}

func (m *moveFixture) targetHasModel() bool {
	_, err := os.Stat(filepath.Join(m.to.fx.dir, m.bundle))
	return err == nil
}

// The move: the source verifies the target's chip itself, wraps the key to the
// key that chip named, sends the ciphertext; the target can open the model and
// the source's journal and the target's say so.
func TestConsoleMove(t *testing.T) {
	m := newMoveFixture(t)
	status, raw := m.owner.do(t, http.MethodPost, "/v1/console/move", m.order(t, "order-1", nil))
	require.Equal(t, http.StatusOK, status, string(raw))
	var resp console.MoveResponse
	require.NoError(t, json.Unmarshal(raw, &resp))
	require.Equal(t, m.bundle, resp.Bundle)
	require.Equal(t, hex.EncodeToString(m.to.chip.Measurement()), resp.TargetMeasurement)
	require.Equal(t, escrow.KeyTag(m.to.srv.mat.Escrow.PublicKey()), resp.EscrowKey)
	require.True(t, m.targetHasModel())

	got, err := os.ReadFile(filepath.Join(m.to.fx.dir, m.bundle))
	require.NoError(t, err)
	want, err := os.ReadFile(filepath.Join(m.from.fx.dir, m.bundle))
	require.NoError(t, err)
	require.Equal(t, want, got, "the bundle arrives byte for byte")

	// The target opens it with its own key, from the envelope alone.
	info, err := m.to.fx.server.genomes.inspect(genomeRef{Bundle: m.bundle})
	require.NoError(t, err)
	require.Equal(t, "escrow", info.View.KeySource)

	// The restore check on the target picks the moved model by name.
	status, raw = m.toOwner.doJSON(t, http.MethodPost, "/v1/console/restore-check", console.RestoreRequest{Bundle: m.bundle})
	require.Equal(t, http.StatusAccepted, status, string(raw))
	status, raw = m.toOwner.doJSON(t, http.MethodPost, "/v1/console/restore-check", console.RestoreRequest{Bundle: "other.genome"})
	require.Equal(t, http.StatusNotFound, status)
	require.Equal(t, "no_genome", errCode(t, raw))

	acts := m.from.actions()
	require.Equal(t, 1, acts[console.ActionMoveOrdered])
	require.Equal(t, 1, acts[console.ActionModelReleased])
	require.Equal(t, 1, acts[console.ActionModelSent])
	require.Equal(t, 2, m.to.actions()[console.ActionModelReceived], "the bundle and its envelope")

	// One order, one move.
	status, raw = m.owner.do(t, http.MethodPost, "/v1/console/move", m.order(t, "order-1", nil))
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "order_used", errCode(t, raw))
	// And a model is not replaced under its name.
	status, raw = m.owner.do(t, http.MethodPost, "/v1/console/move", m.order(t, "order-2", nil))
	require.Equal(t, http.StatusBadGateway, status)
	require.Equal(t, "move_failed", errCode(t, raw))
}

// Every way an order can be wrong is refused before anything moves.
func TestConsoleMoveRefusals(t *testing.T) {
	m := newMoveFixture(t)
	refused := func(name string, body []byte, status int, code string) {
		t.Helper()
		got, raw := m.owner.do(t, http.MethodPost, "/v1/console/move", body)
		require.Equal(t, status, got, name+": "+string(raw))
		require.Equal(t, code, errCode(t, raw), name)
		require.False(t, m.targetHasModel(), name+": nothing arrived")
	}
	stranger, err := crypto.GenerateSigningKey(crypto.SuiteEd25519, nil)
	require.NoError(t, err)
	defer stranger.Zeroize()
	now := time.Now().UTC().Truncate(time.Second)
	unsigned := console.MoveOrder{OrderID: "x", IssuedAt: now, ExpiresAt: now.Add(time.Minute), FromCertSHA256: console.CertSHA256(m.from.certDER), Bundle: m.bundle, SigningKeyID: console.StopKeyID,
		To: console.MoveTarget{Address: m.to.srv.Addr(), ServerCertPEM: "x", Pin: m.pin, JoinCode: "x"}}
	forged, err := console.SignMoveOrder(unsigned, stranger)
	require.NoError(t, err)
	rawForged, err := json.Marshal(forged)
	require.NoError(t, err)

	refused("a code the target does not know", m.order(t, "e", func(o *console.MoveOrder) { o.To.JoinCode = "made-up" }), http.StatusBadGateway, "target_refused")
	refused("not an order", []byte("{}"), http.StatusForbidden, "order_refused")
	refused("another signer", rawForged, http.StatusForbidden, "order_refused")
	refused("another server", m.order(t, "a", func(o *console.MoveOrder) { o.FromCertSHA256 = console.CertSHA256(m.to.certDER) }), http.StatusForbidden, "order_refused")
	refused("out of its time", m.order(t, "b", func(o *console.MoveOrder) {
		o.IssuedAt = now.Add(-time.Hour)
		o.ExpiresAt = now.Add(-50 * time.Minute)
	}), http.StatusForbidden, "order_refused")
	refused("no such model", m.order(t, "c", func(o *console.MoveOrder) { o.Bundle = "other.genome" }), http.StatusConflict, "no_genome")

	wrong := m.pin
	wrong.MeasurementHex = strings.Repeat("ab", 32)
	refused("the target does not show the pin", m.order(t, "d", func(o *console.MoveOrder) { o.To.Pin = wrong }), http.StatusConflict, "target_unproven")

	// The stop on the source releases nothing.
	status, raw := m.owner.do(t, http.MethodPut, "/v1/console/stop", m.owner.signStop(t, 2, true))
	require.Equal(t, http.StatusOK, status, string(raw))
	refused("the stop is on", m.order(t, "f", nil), http.StatusConflict, "stopped")
	status, raw = m.owner.do(t, http.MethodPut, "/v1/console/stop", m.owner.signStop(t, 3, false))
	require.Equal(t, http.StatusOK, status, string(raw))

	// The stop on the target: nothing is sent to it.
	status, raw = m.toOwner.do(t, http.MethodPut, "/v1/console/stop", m.toOwner.signStop(t, 1, true))
	require.Equal(t, http.StatusOK, status, string(raw))
	refused("the stop is on at the target", m.order(t, "g", nil), http.StatusConflict, "target_stopped")
	status, raw = m.toOwner.do(t, http.MethodPut, "/v1/console/stop", m.toOwner.signStop(t, 2, false))
	require.Equal(t, http.StatusOK, status, string(raw))

	// A target with no escrow key cannot receive one.
	m.to.srv.mat.Escrow = nil
	refused("no key to receive under", m.order(t, "h", nil), http.StatusConflict, "target_no_key")
	require.Zero(t, m.from.actions()[console.ActionModelSent])
}

// The door a model comes in by: a peer or an owner, a proper name, the hash the
// sender stated, and never over a file already here. A peer gets nothing else.
func TestConsoleIncoming(t *testing.T) {
	f := newConsoleFixture(t)
	peer := f.join(t, "Other (server)", console.RolePeer)
	viewer := f.join(t, "Viewer", console.RoleViewer)
	put := func(p *consolePerson, name string, body []byte, sum string) (int, []byte) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, p.base+"/v1/console/incoming/"+name, bytes.NewReader(body))
		require.NoError(t, err)
		if sum != "" {
			req.Header.Set(consoleSHA256Header, sum)
		}
		resp, err := p.client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, raw
	}
	body := []byte("ciphertext")
	digest := sha256.Sum256(body)
	sum := hex.EncodeToString(digest[:])

	status, raw := put(viewer, "new.genome", body, sum)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "role_refused", errCode(t, raw))
	status, raw = put(peer, "..%2Fescape.genome", body, sum)
	require.Equal(t, http.StatusBadRequest, status, string(raw))
	status, raw = put(peer, "notamodel.txt", body, sum)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "name_invalid", errCode(t, raw))
	status, raw = put(peer, "new.genome", body, "")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "hash_required", errCode(t, raw))
	status, raw = put(peer, "new.genome", body, strings.Repeat("0", 64))
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "hash_mismatch", errCode(t, raw))
	require.NoFileExists(t, filepath.Join(f.fx.dir, "new.genome"))

	status, raw = put(peer, "new.genome", body, sum)
	require.Equal(t, http.StatusOK, status, string(raw))
	require.FileExists(t, filepath.Join(f.fx.dir, "new.genome"))
	status, raw = put(peer, "new.genome", []byte("something else"), sum)
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "already_here", errCode(t, raw))
	status, raw = put(peer, "gen-0.genome", body, sum)
	require.Equal(t, http.StatusConflict, status, "a model already here is not replaced")
	require.Equal(t, "already_here", errCode(t, raw))

	// A peer may ask the chip and hand over a model, and nothing else.
	f.check(t, peer)
	status, raw = peer.do(t, http.MethodGet, "/v1/console/journal", nil)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "role_refused", errCode(t, raw))
	status, raw = peer.do(t, http.MethodPost, "/v1/console/restore-check", nil)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "role_refused", errCode(t, raw))
}

// A server is on another's list for the time its invite says, whatever else
// happens: a console that crashed mid-move leaves no standing door.
func TestConsolePeerExpires(t *testing.T) {
	f := newConsoleFixture(t)
	peer := f.person(t)
	code := f.invite(t, "Other (server)", console.RolePeer, time.Hour)
	status, raw := peer.doJSON(t, http.MethodPost, "/v1/console/join", console.JoinRequest{Code: code})
	require.Equal(t, http.StatusOK, status, string(raw))
	f.check(t, peer)
	f.srv.mu.Lock()
	past := time.Now().Add(-time.Minute)
	f.srv.people[0].ExpiresAt = &past
	f.srv.mu.Unlock()
	status, raw = peer.doJSON(t, http.MethodPost, "/v1/console/check", console.CheckRequest{NonceHex: strings.Repeat("00", console.NonceBytes)})
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "not_listed", errCode(t, raw))

	// A person's access does not expire with their pass.
	owner := f.join(t, "Serhii", console.RoleOwner)
	require.Nil(t, f.check(t, owner).You.ExpiresAt)
}

// A misconfigured port is refused at start, not in a crash loop.
func TestConsolePortMustBeItsOwn(t *testing.T) {
	require.True(t, sameListenPort("0.0.0.0:9443", "127.0.0.1:9443"))
	require.False(t, sameListenPort("0.0.0.0:9444", "127.0.0.1:9443", "127.0.0.1:9080"))
	require.False(t, sameListenPort("127.0.0.1:0", "127.0.0.1:0"))
	require.False(t, sameListenPort("nonsense", "127.0.0.1:9443"))
}
