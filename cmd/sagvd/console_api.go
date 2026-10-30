// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/console"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
	"github.com/vault-genome/vaultgenome-core/internal/vault/trust"
)

// The console's listener (ADR 0039). A person's console reaches the
// authority here and nowhere else: mutual TLS 1.3, the server's certificate
// pinned by the pass, the person's key listed in console.dir/people.json. A
// check is answered with the state and the chip's evidence over the person's
// challenge, this listener's certificate and the state, verified on the
// person's computer. The journal is read from the daemon's own open log, so
// the services do not pause for it (ADR 0027 stays true of acpctl). Whatever
// a person changes goes on the audit chain before it takes effect.

// ConsoleConfig is the console's listener. Empty ListenAddress: no listener.
type ConsoleConfig struct {
	// ListenAddress is where consoles connect. It may be off loopback:
	// the listener admits only keys on the people list and what an
	// invite's single-use code adds to it.
	ListenAddress string `json:"listen_address,omitempty"`
	// Dir holds the listener's certificate and sealed key, people.json and
	// the invites/ the operator made.
	Dir string `json:"dir,omitempty"`
}

// Enabled reports whether the listener is configured.
func (c ConsoleConfig) Enabled() bool { return c.ListenAddress != "" }

const (
	consoleKeyName     = "console.tls_key"
	consoleMaxBody     = 64 << 10
	consoleJournalPage = 500
	consoleInviteHours = 72
)

var consoleNameRE = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._'()-]{0,63}$`)

type consoleServer struct {
	cfg       ConsoleConfig
	stop      OperatorStopConfig
	sigPol    kms.SignaturePolicy
	genomeDir string
	mat       *materials
	api       *HTTPAPIServer
	queue     *JobQueue
	audit     *returnPathAudit
	clock     shared_time.Clock
	log       *slog.Logger
	started   time.Time

	mu     sync.Mutex // the people file, the invites, the stop list
	people []console.Person

	moveMu    sync.Mutex // one move at a time
	movesDone map[string]bool
	cacheDir  string

	cert     tls.Certificate
	listener net.Listener
	server   *http.Server
}

// newConsoleServer loads or makes the listener's certificate and reads the
// people list. The daemon does not start on a listener it cannot serve.
func newConsoleServer(cfg Config, mat *materials, api *HTTPAPIServer, queue *JobQueue, audit *returnPathAudit, clock shared_time.Clock, logger *slog.Logger) (*consoleServer, error) {
	if audit == nil {
		return nil, errors.New("sagvd: console.listen_address needs the audit log (audit.log_path): what a person does goes on the record")
	}
	sigPol, err := cfg.Crypto.SignaturePolicy()
	if err != nil {
		return nil, fmt.Errorf("sagvd: crypto: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.Console.Dir, "invites"), 0o700); err != nil {
		return nil, fmt.Errorf("sagvd: console.dir: %w", err)
	}
	s := &consoleServer{
		cfg: cfg.Console, stop: cfg.OperatorStop, sigPol: sigPol, genomeDir: cfg.Genome.BundleDir,
		mat: mat, api: api, queue: queue, audit: audit, clock: clock, log: logger, started: clock.Now(),
		movesDone: map[string]bool{}, cacheDir: filepath.Join(cfg.Console.Dir, "cache"),
	}
	s.cert, err = consoleTLSCertificate(cfg, mat, clock)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(s.peoplePath())
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("sagvd: console people list: %w", err)
	default:
		if err := json.Unmarshal(raw, &s.people); err != nil {
			return nil, fmt.Errorf("sagvd: console people list: %w", err)
		}
	}
	return s, nil
}

func (s *consoleServer) peoplePath() string { return filepath.Join(s.cfg.Dir, "people.json") }

func (s *consoleServer) invitePath(code string) string {
	return filepath.Join(s.cfg.Dir, "invites", console.InviteKey(code)+".json")
}

// consoleTLSCertificate reads the listener's certificate and key, or makes
// them on the first start: an Ed25519 key sealed to this host (ADR 0023) and
// a certificate the passes pin, so its identity outlives a restart.
func consoleTLSCertificate(cfg Config, mat *materials, clock shared_time.Clock) (tls.Certificate, error) {
	certPath := filepath.Join(cfg.Console.Dir, "tls.crt")
	keyPath := filepath.Join(cfg.Console.Dir, "tls.key")
	if _, err := os.Stat(certPath); err == nil {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("sagvd: console certificate: %w", err)
		}
		keyPEM, err := readSecret(cfg.TEE, keyPath, 0, consoleKeyName)
		if err != nil {
			return tls.Certificate{}, err
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("sagvd: console certificate: %w", err)
		}
		return pair, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sagvd: console key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sagvd: console certificate: %w", err)
	}
	now := clock.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: console.ServerName}, DNSNames: []string{console.ServerName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(20, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sagvd: console certificate: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sagvd: console key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	stored := keyPEM
	if kind, err := mat.SealerKind(); err == nil && kind != tee.SealerKindSimulated {
		sealer, err := mat.TEESealer()
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("sagvd: console key: %w", err)
		}
		stored, err = tee.SealSecretWith(keyPEM, sealer, kind, mat.Provider, mat.Producer.Measurement(), consoleKeyName)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("sagvd: console key: %w", err)
		}
	}
	if err := writeConsoleFile(keyPath, stored, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeConsoleFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// writeConsoleFile writes a file whole or not at all.
func writeConsoleFile(path string, data []byte, mode os.FileMode) error {
	if err := replaceFile(path, data); err != nil {
		return fmt.Errorf("sagvd: console: write %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("sagvd: console: chmod %s: %w", path, err)
	}
	return nil
}

// Start binds the listener.
func (s *consoleServer) Start() error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("sagvd: console listen %q: %w", s.cfg.ListenAddress, err)
	}
	s.listener = tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/console/join", s.handleJoin)
	mux.HandleFunc("POST /v1/console/check", s.listed(console.RolePeer, s.handleCheck))
	mux.HandleFunc("GET /v1/console/journal", s.listed(console.RoleViewer, s.handleJournal))
	mux.HandleFunc("GET /v1/console/jobs/{id}", s.listed(console.RoleViewer, s.handleJob))
	mux.HandleFunc("POST /v1/console/restore-check", s.listed(console.RoleOperator, s.handleRestoreCheck))
	mux.HandleFunc("PUT /v1/console/stop", s.listed(console.RoleOwner, s.handleStop))
	mux.HandleFunc("POST /v1/console/invites", s.listed(console.RoleOwner, s.handleInvite))
	mux.HandleFunc("POST /v1/console/people/remove", s.listed(console.RoleOwner, s.handleRemove))
	mux.HandleFunc("POST /v1/console/move", s.listed(console.RoleOwner, s.handleMove))
	mux.HandleFunc("PUT /v1/console/incoming/{name}", s.listed(console.RolePeer, s.handleIncoming))
	s.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}
	go func() {
		if err := s.server.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("sagvd console listener stopped", "err", err.Error())
		}
	}()
	s.log.Info("sagvd console listener", "address", s.listener.Addr().String(), "people", len(s.people))
	return nil
}

// Addr is the bound address.
func (s *consoleServer) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Close stops the listener.
func (s *consoleServer) Close(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

func consoleError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, console.ErrorBody{Code: code, Message: message})
}

// callerKey is the Ed25519 key the caller proved it holds in the handshake.
func callerKey(r *http.Request) (ed25519.PublicKey, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, false
	}
	pub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	return pub, ok
}

func (s *consoleServer) lookup(pub ed25519.PublicKey) (console.Person, bool) {
	want := console.PublicKeyHex(pub)
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.people {
		if p.PublicKeyHex == want {
			if p.ExpiresAt != nil && now.After(*p.ExpiresAt) {
				return console.Person{}, false
			}
			return p, true
		}
	}
	return console.Person{}, false
}

// listed admits a caller whose key is on the people list with at least min.
func (s *consoleServer) listed(min console.Role, h func(http.ResponseWriter, *http.Request, console.Person)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pub, ok := callerKey(r)
		if !ok {
			consoleError(w, http.StatusForbidden, "key_required", "this console needs an Ed25519 key")
			return
		}
		p, ok := s.lookup(pub)
		if !ok {
			consoleError(w, http.StatusForbidden, "not_listed", "this key is not on the people list")
			return
		}
		if !p.Role.Allows(min) {
			consoleError(w, http.StatusForbidden, "role_refused", "this person's role does not allow it")
			return
		}
		h(w, r, p)
	}
}

func decodeConsole(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, consoleMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		consoleError(w, http.StatusBadRequest, "decode_body", "not one JSON object of this request's shape")
		return false
	}
	return true
}

// handleJoin redeems a pass: the caller's key goes on the list under the
// name and role the invite says, and the code is dead. The first owner's key
// becomes the operator key that signs the stop list; it was made on their
// computer and has never been anywhere else.
func (s *consoleServer) handleJoin(w http.ResponseWriter, r *http.Request) {
	pub, ok := callerKey(r)
	if !ok {
		consoleError(w, http.StatusForbidden, "key_required", "this console needs an Ed25519 key")
		return
	}
	var req console.JoinRequest
	if !decodeConsole(w, r, &req) {
		return
	}
	if req.Code == "" {
		consoleError(w, http.StatusForbidden, "invite_unknown", "this pass is not known or was used already")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keyHex := console.PublicKeyHex(pub)
	for _, p := range s.people {
		if p.PublicKeyHex == keyHex {
			writeJSON(w, http.StatusOK, p)
			return
		}
	}
	path := s.invitePath(req.Code)
	raw, err := os.ReadFile(path)
	if err != nil {
		consoleError(w, http.StatusForbidden, "invite_unknown", "this pass is not known or was used already")
		return
	}
	var inv console.Invite
	if err := json.Unmarshal(raw, &inv); err != nil || !inv.Role.Valid() {
		consoleError(w, http.StatusInternalServerError, "invite_unreadable", "the invite on the server cannot be read")
		return
	}
	now := s.clock.Now()
	if now.After(inv.ExpiresAt) {
		_ = os.Remove(path)
		consoleError(w, http.StatusForbidden, "invite_expired", "this pass has expired")
		return
	}
	holdsStop := false
	if inv.Role == console.RoleOwner && s.stop.PublicKeyPath != "" {
		if _, err := os.Stat(s.stop.PublicKeyPath); errors.Is(err, fs.ErrNotExist) {
			holdsStop = true
		}
	}
	person := console.Person{Name: inv.Name, Role: inv.Role, PublicKeyHex: keyHex, AddedAt: now.UTC()}
	if inv.Role == console.RolePeer {
		expires := inv.ExpiresAt
		person.ExpiresAt = &expires
	}
	if err := s.audit.emit(audit_event.KindConsoleAction, console.ActionPayload{
		Schema: console.ActionSchema, Action: console.ActionPersonJoined, Person: person.Name,
		Role: person.Role, PublicKeyHex: keyHex, HoldsStop: holdsStop,
	}); err != nil {
		consoleError(w, http.StatusServiceUnavailable, "audit_unavailable", "the record could not be written, so nothing was changed")
		return
	}
	if err := os.Remove(path); err != nil {
		consoleError(w, http.StatusInternalServerError, "invite_not_consumed", "the pass could not be used up")
		return
	}
	if holdsStop {
		pemKey, err := publicKeyPEM(pub)
		if err == nil {
			err = writeConsoleFile(s.stop.PublicKeyPath, pemKey, 0o644)
		}
		if err != nil {
			s.log.Error("sagvd console: the operator key was not written", "err", err.Error())
			consoleError(w, http.StatusInternalServerError, "stop_key_not_written", "the emergency stop could not be given to this person")
			return
		}
	}
	people := append(append([]console.Person(nil), s.people...), person)
	if err := s.savePeople(people); err != nil {
		consoleError(w, http.StatusInternalServerError, "people_not_written", "the people list could not be written")
		return
	}
	s.people = people
	s.log.Info("sagvd console: a person joined", "name", logSafe(person.Name), "role", string(person.Role), "holds_stop", holdsStop)
	writeJSON(w, http.StatusOK, person)
}

func publicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func (s *consoleServer) savePeople(people []console.Person) error {
	raw, err := json.MarshalIndent(people, "", "  ")
	if err != nil {
		return err
	}
	return writeConsoleFile(s.peoplePath(), append(raw, '\n'), 0o600)
}

// handleCheck is the check: the state as it stands, and the chip's evidence
// over the person's challenge, this listener's certificate and that state.
func (s *consoleServer) handleCheck(w http.ResponseWriter, r *http.Request, p console.Person) {
	var req console.CheckRequest
	if !decodeConsole(w, r, &req) {
		return
	}
	challenge, err := hex.DecodeString(req.NonceHex)
	if err != nil || len(challenge) != console.NonceBytes {
		consoleError(w, http.StatusBadRequest, "nonce_invalid", "the challenge must be 32 bytes of hex")
		return
	}
	state, err := json.Marshal(s.buildState(p))
	if err != nil {
		consoleError(w, http.StatusInternalServerError, "state_unreadable", "the state could not be encoded")
		return
	}
	evidence, err := s.mat.Producer.Quote(console.BindingNonce(challenge, s.cert.Certificate[0], state))
	if err != nil {
		s.log.Error("sagvd console: the chip did not answer", "err", err.Error())
		consoleError(w, http.StatusServiceUnavailable, "chip_unavailable", "the chip did not answer")
		return
	}
	writeJSON(w, http.StatusOK, console.CheckResponse{State: state, Evidence: evidence})
}

func (s *consoleServer) buildState(p console.Person) console.State {
	st := console.State{
		Schema: console.StateSchema, At: s.clock.Now().UTC(), StartedAt: s.started.UTC(),
		Version: version, Commit: commit, Provider: string(s.mat.Provider),
		MeasurementHex: hex.EncodeToString(s.mat.Producer.Measurement()), You: p,
		QueueDepth: s.queue.Depth(), Genomes: s.bundles(),
	}
	s.mu.Lock()
	st.People = append(st.People, s.people...)
	s.mu.Unlock()
	st.Audit = console.AuditState{Events: s.audit.Len(), Base: s.audit.Base(), TipHex: s.audit.Tip(), KeyID: string(s.audit.KeyID())}
	st.Stop = s.stopState()
	if s.mat.Escrow != nil {
		if raw, err := escrow.PublicPEM(s.mat.Escrow.PublicKey()); err == nil {
			st.EscrowPublicKeyPEM = string(raw)
		}
	}
	return st
}

// stopState reads the stop list as Trust Admission will read it.
func (s *consoleServer) stopState() console.StopState {
	out := console.StopState{KeyID: s.stop.KeyID}
	if s.stop.PublicKeyPath == "" {
		return out
	}
	pub, err := loadSigningPublicKey(s.stop.PublicKeyPath)
	if errors.Is(err, fs.ErrNotExist) {
		return out
	}
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.HolderPublicKeyHex = hex.EncodeToString(pub.Bytes)
	list, err := loadOperatorStop(s.stop, s.sigPol)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Serial, out.StopAll, out.Reason, out.IssuedAt = list.Serial, list.StopAll, list.Reason, list.IssuedAt
	return out
}

// bundles lists the sealed genomes, newest first.
func (s *consoleServer) bundles() []string {
	entries, err := os.ReadDir(s.genomeDir)
	if err != nil {
		return nil
	}
	type bundle struct {
		name string
		at   time.Time
	}
	var found []bundle
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".genome") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		found = append(found, bundle{e.Name(), info.ModTime()})
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].at.After(found[j].at) })
	out := make([]string, 0, len(found))
	for _, b := range found {
		out = append(out, b.name)
	}
	return out
}

// handleJournal serves a run of the live segment: events as they were
// signed. from is an index of the whole log; older events are in closed
// segments, read with acpctl.
func (s *consoleServer) handleJournal(w http.ResponseWriter, r *http.Request, _ console.Person) {
	base, total := s.audit.Base(), s.audit.Len()
	from := base
	if v := r.URL.Query().Get("from"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			consoleError(w, http.StatusBadRequest, "from_invalid", "from must be a record's index")
			return
		}
		from = n
	}
	if from < base {
		from = base
	}
	page := console.JournalPage{Base: base, Total: total, From: from, Events: []audit_event.AuditEvent{}}
	for i := from; i < total && len(page.Events) < consoleJournalPage; i++ {
		evt, ok := s.audit.EventAt(i)
		if !ok {
			break
		}
		page.Events = append(page.Events, evt)
	}
	writeJSON(w, http.StatusOK, page)
}

// handleJob shows a job without its model output.
func (s *consoleServer) handleJob(w http.ResponseWriter, r *http.Request, _ console.Person) {
	raw, ok := s.queue.GetRaw(r.PathValue("id"))
	if !ok {
		consoleError(w, http.StatusNotFound, "job_not_found", "no such job")
		return
	}
	var view JobView
	if err := json.Unmarshal(raw, &view); err != nil {
		consoleError(w, http.StatusInternalServerError, "job_unreadable", "the job could not be read")
		return
	}
	out := console.JobSummary{
		JobID: view.ID, RequestID: view.RequestID, Status: string(view.Status), State: view.State,
		SubmittedAt: view.SubmittedAt, StartedAt: view.StartedAt, CompletedAt: view.CompletedAt,
	}
	if view.Genome != nil {
		out.Bundle = view.Genome.Bundle
	}
	if view.Gate != nil {
		out.GateLevel, out.Fixtures = view.Gate.Level, view.Gate.Fixtures
	}
	if view.Error != nil {
		out.ErrorCode, out.ErrorMessage = view.Error.Code, view.Error.Message
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRestoreCheck starts a gate job on the newest sealed genome, the same
// job the REST API takes, under the person's name.
func (s *consoleServer) handleRestoreCheck(w http.ResponseWriter, r *http.Request, p console.Person) {
	bundles := s.bundles()
	if len(bundles) == 0 {
		consoleError(w, http.StatusConflict, "no_genome", "there is no sealed model on this server yet")
		return
	}
	bundle := bundles[0]
	var req console.RestoreRequest
	if raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, consoleMaxBody)); err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			consoleError(w, http.StatusBadRequest, "decode_body", "not one JSON object of this request's shape")
			return
		}
	}
	if req.Bundle != "" {
		i := slices.Index(bundles, req.Bundle)
		if i < 0 {
			consoleError(w, http.StatusNotFound, "no_genome", "this sealed model is not on this server")
			return
		}
		bundle = bundles[i] // the name as this server's directory has it
	}
	ref := genomeRef{Bundle: bundle}
	keyFile := strings.TrimSuffix(bundle, ".genome") + ".key"
	if _, err := os.Stat(filepath.Join(s.genomeDir, keyFile)); err == nil {
		ref.KeyFile = keyFile
	}
	res, aerr := s.api.admit(submitRequest{Genome: ref, RequesterIdentity: "person:" + p.Name}, admitOptions{})
	if aerr != nil {
		consoleError(w, aerr.status, aerr.code, aerr.message)
		return
	}
	s.api.metrics.jobsSubmitted.Inc()
	writeJSON(w, http.StatusAccepted, console.RestoreResponse{JobID: res.jobID, RequestID: res.requestID, Bundle: bundle})
}

// handleStop takes a stop list the holder signed on their own computer: the
// daemon verifies it under the operator key, puts the change on the record,
// and writes it where Trust Admission reads it at every job. The daemon
// cannot make such a list itself (ADR 0010).
func (s *consoleServer) handleStop(w http.ResponseWriter, r *http.Request, p console.Person) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, consoleMaxBody))
	if err != nil {
		consoleError(w, http.StatusBadRequest, "decode_body", "the list is too long")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pub, err := loadSigningPublicKey(s.stop.PublicKeyPath)
	if err != nil {
		consoleError(w, http.StatusConflict, "stop_not_held", "nobody holds the emergency stop on this server yet")
		return
	}
	if err := s.sigPol.CheckAcceptedKey("operator key "+s.stop.KeyID, pub.Suite); err != nil {
		consoleError(w, http.StatusConflict, "stop_key_refused", err.Error())
		return
	}
	list, err := revocation.Parse(raw, pub, s.stop.KeyID)
	if err != nil {
		consoleError(w, http.StatusForbidden, "list_refused", "this list is not signed by the holder of the emergency stop")
		return
	}
	var current uint64
	if cur, err := loadOperatorStop(s.stop, s.sigPol); err == nil {
		current = cur.Serial
	}
	if list.Serial <= current {
		consoleError(w, http.StatusConflict, "list_old", fmt.Sprintf("this list's number %d is not newer than the one in force (%d)", list.Serial, current))
		return
	}
	action := console.ActionStopLifted
	switch {
	case list.StopAll:
		action = console.ActionStopSet
	case current == 0:
		action = console.ActionStopReady
	}
	sum := sha256.Sum256(raw)
	if err := s.audit.emit(audit_event.KindConsoleAction, console.ActionPayload{
		Schema: console.ActionSchema, Action: action, Person: p.Name, Role: p.Role,
		Serial: list.Serial, StopAll: list.StopAll, Reason: list.Reason, ListSHA256: hex.EncodeToString(sum[:]),
	}); err != nil {
		consoleError(w, http.StatusServiceUnavailable, "audit_unavailable", "the record could not be written, so nothing was changed")
		return
	}
	if err := writeConsoleFile(s.stop.ListPath, raw, 0o644); err != nil {
		consoleError(w, http.StatusInternalServerError, "list_not_written", "the list could not be written")
		return
	}
	now := s.stopState()
	s.log.Info("sagvd console: the stop list changed", "person", logSafe(p.Name), "serial", now.Serial, "stop_all", now.StopAll)
	writeJSON(w, http.StatusOK, now)
}

// handleInvite makes a single-use code for a new person.
func (s *consoleServer) handleInvite(w http.ResponseWriter, r *http.Request, p console.Person) {
	var req console.InviteRequest
	if !decodeConsole(w, r, &req) {
		return
	}
	if !consoleNameRE.MatchString(req.Name) || !req.Role.Valid() {
		consoleError(w, http.StatusBadRequest, "invite_invalid", "a name of up to 64 letters and a role of viewer, operator or owner")
		return
	}
	hours := req.Hours
	if hours <= 0 || hours > 24*30 {
		hours = consoleInviteHours
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		consoleError(w, http.StatusInternalServerError, "invite_not_made", "no randomness")
		return
	}
	code := hex.EncodeToString(buf)
	inv := console.Invite{Name: req.Name, Role: req.Role, ExpiresAt: s.clock.Now().UTC().Add(time.Duration(hours) * time.Hour)}
	raw, err := json.Marshal(inv)
	if err != nil {
		consoleError(w, http.StatusInternalServerError, "invite_not_made", "the invite could not be encoded")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.audit.emit(audit_event.KindConsoleAction, console.ActionPayload{
		Schema: console.ActionSchema, Action: console.ActionInviteMade, Person: p.Name, Role: req.Role, Subject: req.Name,
	}); err != nil {
		consoleError(w, http.StatusServiceUnavailable, "audit_unavailable", "the record could not be written, so nothing was changed")
		return
	}
	if err := writeConsoleFile(s.invitePath(code), raw, 0o600); err != nil {
		consoleError(w, http.StatusInternalServerError, "invite_not_made", "the invite could not be written")
		return
	}
	writeJSON(w, http.StatusOK, console.InviteResponse{Code: code, ExpiresAt: inv.ExpiresAt})
}

// handleRemove takes a person off the list. The holder of the emergency stop
// cannot be removed here: their key signs the stop list.
func (s *consoleServer) handleRemove(w http.ResponseWriter, r *http.Request, p console.Person) {
	var req console.RemoveRequest
	if !decodeConsole(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if holder := s.stopHolderLocked(); holder != "" && holder == req.PublicKeyHex {
		consoleError(w, http.StatusConflict, "holder_not_removed", "this person holds the emergency stop")
		return
	}
	idx := -1
	for i, q := range s.people {
		if q.PublicKeyHex == req.PublicKeyHex {
			idx = i
		}
	}
	if idx < 0 {
		consoleError(w, http.StatusNotFound, "not_listed", "no such person")
		return
	}
	if err := s.audit.emit(audit_event.KindConsoleAction, console.ActionPayload{
		Schema: console.ActionSchema, Action: console.ActionPersonRemoved, Person: p.Name, Role: s.people[idx].Role, Subject: s.people[idx].Name, PublicKeyHex: req.PublicKeyHex,
	}); err != nil {
		consoleError(w, http.StatusServiceUnavailable, "audit_unavailable", "the record could not be written, so nothing was changed")
		return
	}
	people := append(append([]console.Person(nil), s.people[:idx]...), s.people[idx+1:]...)
	if err := s.savePeople(people); err != nil {
		consoleError(w, http.StatusInternalServerError, "people_not_written", "the people list could not be written")
		return
	}
	s.people = people
	writeJSON(w, http.StatusOK, map[string]int{"people": len(people)})
}

func (s *consoleServer) stopHolderLocked() string {
	pub, err := loadSigningPublicKey(s.stop.PublicKeyPath)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(pub.Bytes)
}

// newConsoleStopSource is the stop list where the console gives out the
// operator key: before the first owner has joined nobody holds the stop and
// nothing is refused for it. From the moment the key exists the rule is ADR
// 0010's: without a valid list nothing is released, and an older serial is
// refused.
func newConsoleStopSource(cfg OperatorStopConfig, pol kms.SignaturePolicy) trust.StopListSource {
	var (
		mu    sync.Mutex
		inner trust.StopListSource
	)
	return func() (revocation.List, error) {
		mu.Lock()
		defer mu.Unlock()
		if inner == nil {
			if _, err := os.Stat(cfg.PublicKeyPath); errors.Is(err, fs.ErrNotExist) {
				return revocation.List{}, nil
			}
			src, _, err := newOperatorStopSource(cfg, pol)
			if err != nil {
				return revocation.List{}, err
			}
			inner = src
		}
		return inner()
	}
}
