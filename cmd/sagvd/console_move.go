// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/console"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
)

// Moving a model (ADR 0039, the planned move). The holder of the stop signs an
// order on their computer: this server, this sealed model, that server, and
// the pin that server must show. This server carries it out itself: it asks
// that server's chip with a challenge of its own and verifies the answer here,
// so a move does not rest on the console's word about the target; it wraps the
// model's key to the escrow key that chip named (its private half sealed to
// that chip, ADR 0016) and sends the bundle, which is ciphertext, and the
// envelope. Nothing is released while the stop is on. The target then proves
// the model comes back, by its own worker, under its own gate and record.

const (
	consoleMoveTimeout = 6 * time.Hour
	consoleBundleLimit = 1 << 40 // 1 TiB
)

type moveFailure struct {
	status        int
	code, message string
}

func (f *moveFailure) Error() string { return f.code + ": " + f.message }

func moveRefused(code, message string) *moveFailure {
	return &moveFailure{status: http.StatusConflict, code: code, message: message}
}

// handleMove carries out a signed order.
func (s *consoleServer) handleMove(w http.ResponseWriter, r *http.Request, p console.Person) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, consoleMaxBody))
	if err != nil {
		consoleError(w, http.StatusBadRequest, "decode_body", "the order is too long")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(s.clock.Now().Add(consoleMoveTimeout))
	_ = rc.SetReadDeadline(s.clock.Now().Add(consoleMoveTimeout))
	s.moveMu.Lock()
	defer s.moveMu.Unlock()

	pub, err := loadSigningPublicKey(s.stop.PublicKeyPath)
	if err != nil {
		consoleError(w, http.StatusConflict, "stop_not_held", "nobody holds the operator key on this server yet")
		return
	}
	order, err := console.ParseMoveOrder(raw, pub, s.stop.KeyID, s.cert.Certificate[0], s.clock.Now())
	if err != nil {
		s.log.Warn("sagvd console: a move order was refused", "person", logSafe(p.Name), "err", err.Error())
		consoleError(w, http.StatusForbidden, "order_refused", "this order is not one the holder of the operator key signed for this server, now")
		return
	}
	if s.movesDone[order.OrderID] {
		consoleError(w, http.StatusConflict, "order_used", "this order was carried out already")
		return
	}
	if stop := s.stopState(); stop.StopAll || stop.Error != "" {
		consoleError(w, http.StatusConflict, "stopped", "the emergency stop is on: this server releases nothing")
		return
	}
	if err := s.audit.emit(audit_event.KindConsoleAction, console.ActionPayload{
		Schema: console.ActionSchema, Action: console.ActionMoveOrdered, Person: p.Name, Role: p.Role,
		Subject: order.To.Label, OrderID: order.OrderID, Bundle: order.Bundle,
	}); err != nil {
		consoleError(w, http.StatusServiceUnavailable, "audit_unavailable", "the record could not be written, so nothing was changed")
		return
	}
	s.movesDone[order.OrderID] = true
	ctx, cancel := context.WithTimeout(r.Context(), consoleMoveTimeout)
	defer cancel()
	resp, err := s.carryOut(ctx, order, p)
	if err != nil {
		var f *moveFailure
		if errors.As(err, &f) {
			s.log.Warn("sagvd console: the move did not happen", "order", logSafe(order.OrderID), "code", f.code, "detail", logSafe(f.message))
			consoleError(w, f.status, f.code, f.message)
			return
		}
		s.log.Error("sagvd console: the move failed", "order", logSafe(order.OrderID), "err", err.Error())
		consoleError(w, http.StatusBadGateway, "move_failed", "the move did not finish: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// carryOut is the move itself, in the order it must happen.
func (s *consoleServer) carryOut(ctx context.Context, order console.MoveOrder, p console.Person) (console.MoveResponse, error) {
	start := s.clock.Now()
	var out console.MoveResponse
	if !s.bundleHere(order.Bundle) {
		return out, moveRefused("no_genome", "this sealed model is not on this server")
	}
	if s.api == nil || s.api.genomes == nil {
		return out, moveRefused("no_genome", "this server has no sealed models")
	}
	peer, err := s.dialTarget(order.To)
	if err != nil {
		return out, &moveFailure{status: http.StatusBadRequest, code: "target_unreadable", message: err.Error()}
	}
	if bytes.Equal(peer.certDER, s.cert.Certificate[0]) {
		return out, moveRefused("target_is_source", "a server cannot move a model to itself")
	}
	// On the target's list for this move.
	if err := peer.call(ctx, http.MethodPost, "/v1/console/join", jsonBody(console.JoinRequest{Code: order.To.JoinCode}), nil); err != nil {
		return out, &moveFailure{status: http.StatusBadGateway, code: "target_refused", message: "the new server did not let this one in: " + err.Error()}
	}

	// The target's chip, asked and verified here.
	verdict, err := peer.check(ctx, order.To, s.cacheDir)
	if err != nil {
		return out, &moveFailure{status: http.StatusConflict, code: "target_unproven", message: "the new server did not prove itself to this one: " + err.Error()}
	}
	if verdict.State.Stop.StopAll {
		return out, moveRefused("target_stopped", "the emergency stop is on at the new server")
	}
	if slices.Contains(verdict.State.Genomes, order.Bundle) {
		return out, moveRefused("already_here", "this model is on the new server already")
	}
	if verdict.State.EscrowPublicKeyPEM == "" {
		return out, moveRefused("target_no_key", "the new server has no key to receive a model under")
	}
	targetKey, err := escrow.ParsePublicPEM([]byte(verdict.State.EscrowPublicKeyPEM))
	if err != nil {
		return out, moveRefused("target_no_key", "the new server's key does not read: "+err.Error())
	}
	out.Bundle = order.Bundle
	out.TargetMeasurement = hex.EncodeToString(verdict.Measurement)
	out.EscrowKey = escrow.KeyTag(targetKey)

	envelope, err := s.envelopeFor(order.Bundle, targetKey)
	if err != nil {
		return out, &moveFailure{status: http.StatusInternalServerError, code: "key_unavailable", message: "this server could not open the model's key: " + err.Error()}
	}

	// On the record before the key leaves.
	if err := s.audit.emit(audit_event.KindConsoleAction, console.ActionPayload{
		Schema: console.ActionSchema, Action: console.ActionModelReleased, Person: p.Name, Subject: order.To.Label,
		OrderID: order.OrderID, Bundle: order.Bundle, Measurement: out.TargetMeasurement, EscrowKey: out.EscrowKey,
	}); err != nil {
		return out, &moveFailure{status: http.StatusServiceUnavailable, code: "audit_unavailable", message: "the record could not be written, so nothing was sent"}
	}

	path := filepath.Join(s.genomeDir, order.Bundle)
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer func() { _ = f.Close() }()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return out, err
	}
	out.BundleSHA256 = hex.EncodeToString(sum.Sum(nil))
	info, err := f.Stat()
	if err != nil {
		return out, err
	}
	out.Bytes = info.Size()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return out, err
	}
	if err := peer.put(ctx, order.Bundle, f, out.Bytes, out.BundleSHA256); err != nil {
		return out, fmt.Errorf("sending the model: %w", err)
	}
	envSum := sha256.Sum256(envelope)
	if err := peer.put(ctx, order.Bundle+".escrow", bytes.NewReader(envelope), int64(len(envelope)), hex.EncodeToString(envSum[:])); err != nil {
		return out, fmt.Errorf("sending the model's key: %w", err)
	}
	out.Seconds = s.clock.Now().Sub(start).Seconds()
	if err := s.audit.emit(audit_event.KindConsoleAction, console.ActionPayload{
		Schema: console.ActionSchema, Action: console.ActionModelSent, Person: p.Name, Subject: order.To.Label,
		OrderID: order.OrderID, Bundle: order.Bundle, SHA256: out.BundleSHA256, Bytes: out.Bytes,
	}); err != nil {
		return out, &moveFailure{status: http.StatusServiceUnavailable, code: "audit_unavailable", message: "the model was sent and the record of it could not be written"}
	}
	s.log.Info("sagvd console: a model was handed over", "order", logSafe(order.OrderID), "bundle", logSafe(order.Bundle), "bytes", out.Bytes, "seconds", out.Seconds)
	return out, nil
}

func (s *consoleServer) bundleHere(name string) bool {
	return console.ValidBundleName(name) && slices.Contains(s.bundles(), name)
}

// envelopeFor opens the model's key here, by the key file or this server's
// own envelope, and wraps it to the target's escrow key. The opened key is
// wiped before this returns.
func (s *consoleServer) envelopeFor(bundleName string, target escrow.PublicKey) ([]byte, error) {
	ref := genomeRef{Bundle: bundleName}
	keyFile := strings.TrimSuffix(bundleName, ".genome") + ".key"
	if _, err := os.Stat(filepath.Join(s.genomeDir, keyFile)); err == nil {
		ref.KeyFile = keyFile
	}
	root, err := os.OpenRoot(s.genomeDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	// Only the header: a model of any size moves, and nothing of it is opened here.
	f, err := root.Open(bundleName)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	rd, err := bundle.NewReader(f)
	if err != nil {
		return nil, err
	}
	keyID := rd.Header.KeyID
	dek, _, err := s.api.genomes.openKey(root, ref, bundleName, keyID)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	env, err := escrow.Seal(dek, keyID, target)
	if err != nil {
		return nil, err
	}
	return env.Marshal()
}

func jsonBody(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}

// consolePeer is this listener as a client of another: the target's
// certificate pinned, this listener's key its identity there.
type consolePeer struct {
	base    string
	certDER []byte
	client  *http.Client
}

func (s *consoleServer) dialTarget(to console.MoveTarget) (*consolePeer, error) {
	pass := console.Pass{ServerCertPEM: to.ServerCertPEM}
	der, err := pass.CertDER()
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &consolePeer{base: "https://" + to.Address, certDER: der, client: &http.Client{Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, ServerName: console.ServerName, Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS13},
		TLSHandshakeTimeout: 30 * time.Second,
	}}}, nil
}

func (c *consolePeer) call(ctx context.Context, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e console.ErrorBody
		_ = json.Unmarshal(raw, &e)
		return fmt.Errorf("%d %s: %s", resp.StatusCode, e.Code, e.Message)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// check asks the target's chip a question made here and verifies the answer
// here, with the pin the order carries.
func (c *consolePeer) check(ctx context.Context, to console.MoveTarget, cacheDir string) (console.Verdict, error) {
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return console.Verdict{}, err
	}
	_, verifier, err := to.Pin.Verifier(cacheDir)
	if err != nil {
		return console.Verdict{}, err
	}
	challenge := make([]byte, console.NonceBytes)
	if _, err := rand.Read(challenge); err != nil {
		return console.Verdict{}, err
	}
	var resp console.CheckResponse
	if err := c.call(ctx, http.MethodPost, "/v1/console/check", jsonBody(console.CheckRequest{NonceHex: hex.EncodeToString(challenge)}), &resp); err != nil {
		return console.Verdict{}, err
	}
	return console.VerifyCheck(verifier, challenge, c.certDER, resp)
}

// put hands one file over, streamed.
func (c *consolePeer) put(ctx context.Context, name string, body io.Reader, size int64, sum string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base+"/v1/console/incoming/"+name, body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set(consoleSHA256Header, sum)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e console.ErrorBody
		_ = json.Unmarshal(raw, &e)
		return fmt.Errorf("%d %s: %s", resp.StatusCode, e.Code, e.Message)
	}
	return nil
}

const consoleSHA256Header = "X-Content-SHA256"

// handleIncoming takes a sealed model's bundle or its envelope from a server
// on the list. Both are ciphertext; the bundle is checked against the hash the
// sender states, and a name already here is refused, so a model cannot be
// replaced under a name by whoever reaches this door.
func (s *consoleServer) handleIncoming(w http.ResponseWriter, r *http.Request, p console.Person) {
	if p.Role != console.RolePeer && p.Role != console.RoleOwner {
		consoleError(w, http.StatusForbidden, "role_refused", "this person's role does not allow it")
		return
	}
	name := r.PathValue("name")
	bundleName := strings.TrimSuffix(name, ".escrow")
	if !console.ValidBundleName(bundleName) {
		consoleError(w, http.StatusBadRequest, "name_invalid", "this is not a sealed model's file name")
		return
	}
	want := r.Header.Get(consoleSHA256Header)
	if want == "" {
		consoleError(w, http.StatusBadRequest, "hash_required", "the sender must state the file's hash")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(s.clock.Now().Add(consoleMoveTimeout))
	_ = rc.SetWriteDeadline(s.clock.Now().Add(consoleMoveTimeout))
	limit := int64(consoleBundleLimit)
	if name != bundleName {
		limit = maxEnvelopeBytes
	}
	s.moveMu.Lock()
	defer s.moveMu.Unlock()
	path := filepath.Join(s.genomeDir, name)
	if _, err := os.Stat(path); err == nil {
		consoleError(w, http.StatusConflict, "already_here", "a file of this name is on this server already")
		return
	}
	tmp, err := os.CreateTemp(s.genomeDir, ".incoming-*")
	if err != nil {
		consoleError(w, http.StatusInternalServerError, "not_written", "the file could not be written")
		return
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, sum), http.MaxBytesReader(w, r.Body, limit))
	if err == nil {
		err = tmp.Close()
	} else {
		_ = tmp.Close()
	}
	if err != nil {
		consoleError(w, http.StatusBadRequest, "not_received", "the file did not arrive whole")
		return
	}
	got := hex.EncodeToString(sum.Sum(nil))
	if got != strings.ToLower(want) {
		consoleError(w, http.StatusBadRequest, "hash_mismatch", "the file is not what the sender said it was")
		return
	}
	if err := s.audit.emit(audit_event.KindConsoleAction, console.ActionPayload{
		Schema: console.ActionSchema, Action: console.ActionModelReceived, Person: p.Name, Role: p.Role, Bundle: name, SHA256: got, Bytes: n,
	}); err != nil {
		consoleError(w, http.StatusServiceUnavailable, "audit_unavailable", "the record could not be written, so nothing was kept")
		return
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		consoleError(w, http.StatusInternalServerError, "not_written", "the file could not be written")
		return
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		consoleError(w, http.StatusInternalServerError, "not_written", "the file could not be written")
		return
	}
	s.log.Info("sagvd console: a sealed model arrived", "name", logSafe(name), "bytes", strconv.FormatInt(n, 10), "from", logSafe(p.Name))
	writeJSON(w, http.StatusOK, console.IncomingResponse{Name: name, SHA256: got, Bytes: n})
}
