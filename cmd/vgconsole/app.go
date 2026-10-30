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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/console"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// App is this person's console: their key and the servers they may reach.
type App struct {
	dir  string
	seed []byte
	priv ed25519.PrivateKey
	cert tls.Certificate

	mu      sync.Mutex
	servers map[string]*server
}

// server is one server this person reached, and what was last verified of it.
type server struct {
	id       string
	pass     console.Pass
	you      console.Person
	certDER  []byte
	client   *http.Client
	cacheDir string
	provider tee.Provider
	verifier tee.Verifier
	resolver keys.Resolver

	mu         sync.Mutex
	last       *checkResult
	lastErr    error
	unproven   error
	events     []audit_event.AuditEvent
	first      int
	journalErr error
}

// checkResult is one verified check.
type checkResult struct {
	At          time.Time
	State       console.State
	Measurement tee.Measurement
	Detail      *tee.AttestationDetail
}

// storedServer is what stays on disk: the pass without its code.
type storedServer struct {
	Pass console.Pass   `json:"pass"`
	You  console.Person `json:"you"`
}

// newApp opens or makes this person's key and reads their servers.
func newApp(dir string) (*App, error) {
	if err := os.MkdirAll(filepath.Join(dir, "servers"), 0o700); err != nil {
		return nil, err
	}
	seedPath := filepath.Join(dir, "identity.seed")
	seed, err := os.ReadFile(seedPath)
	if errors.Is(err, os.ErrNotExist) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.WriteFile(seedPath, seed, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not a key", seedPath)
	}
	a := &App{dir: dir, seed: seed, priv: ed25519.NewKeyFromSeed(seed), servers: map[string]*server{}}
	if a.cert, err = selfSigned(a.priv); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(dir, "servers"))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, "servers", e.Name()))
		if err != nil {
			return nil, err
		}
		var st storedServer
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		s, err := a.newServer(st.Pass)
		if err != nil {
			return nil, err
		}
		s.you = st.You
		a.servers[s.id] = s
	}
	return a, nil
}

// selfSigned is the certificate this person's key shows in the handshake.
// The server does not check who signed it: the key must be on its list.
func selfSigned(priv ed25519.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "vgconsole"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(20, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

func (a *App) publicKeyHex() string {
	return console.PublicKeyHex(a.priv.Public().(ed25519.PublicKey))
}

// newServer builds the connection a pass describes: the listener's
// certificate pinned, the verifier and the audit key from the pass.
func (a *App) newServer(pass console.Pass) (*server, error) {
	der, err := pass.CertDER()
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	id := hex.EncodeToString(sum[:8])
	cacheDir := filepath.Join(a.dir, "cache", id)
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, err
	}
	provider, verifier, err := pass.Pin.Verifier(cacheDir)
	if err != nil {
		return nil, err
	}
	resolver, err := console.NewAuditResolver(pass.AuditKeyID, []byte(pass.AuditPublicKeyPEM))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	client := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, ServerName: console.ServerName, Certificates: []tls.Certificate{a.cert}, MinVersion: tls.VersionTLS13},
		TLSHandshakeTimeout: 15 * time.Second,
	}}
	return &server{id: id, pass: pass, certDER: der, client: client, cacheDir: cacheDir, provider: provider, verifier: verifier, resolver: resolver}, nil
}

// apiError is the listener saying no.
type apiError struct {
	Status int
	console.ErrorBody
}

func (e *apiError) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Message) }

// call makes one request of the listener.
func (s *server) call(ctx context.Context, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, "https://"+s.pass.Address+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		e := &apiError{Status: resp.StatusCode}
		_ = json.Unmarshal(raw, &e.ErrorBody)
		return e
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (s *server) callJSON(ctx context.Context, method, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return s.call(ctx, method, path, body, out)
}

// Join redeems a pass: this person's key goes on the server's list, and the
// pass is kept without its code. The first owner then signs the first stop
// list, which stops nothing and takes the stop into their hands.
func (a *App) Join(raw []byte) (*server, error) {
	pass, err := console.ParsePass(raw)
	if err != nil {
		return nil, err
	}
	s, err := a.newServer(pass)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var you console.Person
	if err := s.callJSON(ctx, http.MethodPost, "/v1/console/join", console.JoinRequest{Code: pass.InviteCode}, &you); err != nil {
		return nil, err
	}
	s.you = you
	s.pass.InviteCode, s.pass.InviteName, s.pass.InviteRole, s.pass.ExpiresAt = "", "", "", time.Time{}
	if err := a.save(s); err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.servers[s.id] = s
	a.mu.Unlock()
	res, err := s.check(ctx)
	if err != nil {
		return s, err
	}
	if res.State.Stop.HolderPublicKeyHex == a.publicKeyHex() && res.State.Stop.Serial == 0 {
		if err := a.setStop(ctx, s, res.State.Stop, false, ""); err != nil {
			return s, err
		}
		if _, err := s.check(ctx); err != nil {
			return s, err
		}
	}
	if err := s.refreshJournal(ctx); err != nil {
		return s, err
	}
	return s, nil
}

func (a *App) save(s *server) error {
	raw, err := json.MarshalIndent(storedServer{Pass: s.pass, You: s.you}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.dir, "servers", s.id+".json"), raw, 0o600)
}

// Servers lists the servers by label.
func (a *App) Servers() []*server {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*server, 0, len(a.servers))
	for _, s := range a.servers {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pass.ServerLabel < out[j].pass.ServerLabel })
	return out
}

// Server finds one server; empty id means the first.
func (a *App) Server(id string) (*server, error) {
	all := a.Servers()
	for _, s := range all {
		if id == "" || s.id == id {
			return s, nil
		}
	}
	return nil, errors.New("no such server")
}

// check asks the chip now: a fresh challenge made here, the answer verified
// here. A failed verification is remembered: nothing this server says is
// believed until a check passes again.
func (s *server) check(ctx context.Context) (*checkResult, error) {
	challenge := make([]byte, console.NonceBytes)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	var resp console.CheckResponse
	if err := s.callJSON(ctx, http.MethodPost, "/v1/console/check", console.CheckRequest{NonceHex: hex.EncodeToString(challenge)}, &resp); err != nil {
		s.mu.Lock()
		s.lastErr = err
		s.mu.Unlock()
		return nil, err
	}
	verdict, err := console.VerifyCheck(s.verifier, challenge, s.certDER, resp)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = nil
	if err != nil {
		s.unproven = err
		return nil, err
	}
	s.unproven = nil
	s.last = &checkResult{At: time.Now(), State: verdict.State, Measurement: verdict.Measurement, Detail: verdict.Detail}
	return s.last, nil
}

// journalWindow is how many of the newest records a console keeps and shows.
const journalWindow = 2000

// refreshJournal reads what is new in the journal and verifies every record
// here: its signature under the pass's audit key, its link to the one before.
// The last record must be the one the chip's last answer named.
func (s *server) refreshJournal(ctx context.Context) error {
	s.mu.Lock()
	events := append([]audit_event.AuditEvent(nil), s.events...)
	first := s.first
	last := s.last
	s.mu.Unlock()
	if last == nil {
		return errors.New("no verified check yet")
	}
	next := first + len(events)
	if len(events) == 0 {
		next = last.State.Audit.Events - journalWindow
		if next < last.State.Audit.Base {
			next = last.State.Audit.Base
		}
		first = next
	}
	var prev []byte
	if len(events) > 0 {
		prev = events[len(events)-1].Hash
	}
	for {
		var page console.JournalPage
		if err := s.call(ctx, http.MethodGet, fmt.Sprintf("/v1/console/journal?from=%d", next), nil, &page); err != nil {
			return err
		}
		if len(page.Events) == 0 {
			break
		}
		tip, err := console.VerifyEvents(page.Events, next, prev, s.resolver)
		if err != nil {
			s.mu.Lock()
			s.journalErr = err
			s.mu.Unlock()
			return err
		}
		prev = tip
		events = append(events, page.Events...)
		next += len(page.Events)
		if next >= page.Total {
			break
		}
	}
	// The chip's answer named the tip at its own moment; that record must be
	// the one the walk found there.
	if idx := last.State.Audit.Events - 1 - first; idx >= 0 && idx < len(events) {
		if hex.EncodeToString(events[idx].Hash) != last.State.Audit.TipHex {
			err := &console.BrokenJournalError{Index: last.State.Audit.Events - 1, Err: errors.New("it is not the record the chip's answer named")}
			s.mu.Lock()
			s.journalErr = err
			s.mu.Unlock()
			return err
		}
	}
	s.mu.Lock()
	s.events, s.first, s.journalErr = events, first, nil
	s.mu.Unlock()
	return nil
}

// RestoreCheck starts a restore check on the server.
func (s *server) restoreCheck(ctx context.Context) (console.RestoreResponse, error) {
	var out console.RestoreResponse
	err := s.call(ctx, http.MethodPost, "/v1/console/restore-check", nil, &out)
	return out, err
}

func (s *server) job(ctx context.Context, id string) (console.JobSummary, error) {
	var out console.JobSummary
	err := s.call(ctx, http.MethodGet, "/v1/console/jobs/"+id, nil, &out)
	return out, err
}

// setStop signs a stop list here, with this person's key, and hands it over.
// The server can verify such a list and cannot make one.
func (a *App) setStop(ctx context.Context, s *server, cur console.StopState, stop bool, reason string) error {
	key, err := crypto.LoadSigningKey(crypto.SuiteEd25519, a.seed)
	if err != nil {
		return err
	}
	defer key.Zeroize()
	signed, err := revocation.Sign(revocation.List{
		Serial: cur.Serial + 1, IssuedAt: time.Now().UTC().Truncate(time.Second), StopAll: stop, Reason: reason, SigningKeyID: cur.KeyID,
	}, key)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	return s.call(ctx, http.MethodPut, "/v1/console/stop", raw, nil)
}

// Invite asks the server for a code and writes a pass from this one: the
// server, its pin and its audit key as this console holds them.
func (a *App) Invite(ctx context.Context, s *server, name string, role console.Role) ([]byte, error) {
	var resp console.InviteResponse
	if err := s.callJSON(ctx, http.MethodPost, "/v1/console/invites", console.InviteRequest{Name: name, Role: role}, &resp); err != nil {
		return nil, err
	}
	pass := s.pass
	pass.InviteCode, pass.InviteName, pass.InviteRole, pass.ExpiresAt = resp.Code, name, role, resp.ExpiresAt
	return json.MarshalIndent(pass, "", "  ")
}
