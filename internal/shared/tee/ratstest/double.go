// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ratstest is a RATS Verifier for tests: the subset of Veraison's
// challenge-response API the delegated verifier uses (ADR 0025, step
// 2b), the sessions, the EAR signed ES256 under its own key. The
// appraisal is the test's: a function judging the posted message for
// the session's nonce. Shaped after the bench's verifierapi, so what
// passes here is what the bench's TDX verifier and Veraison answer.
package ratstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// SessionMediaType is the session document's media type.
const SessionMediaType = "application/vnd.veraison.challenge-response-session+json"

// Appraise judges one posted message for a session's nonce: the status
// the EAR reports (affirming, warning, contraindicated, none) with the
// annotated evidence; an empty status means the request itself is
// malformed (HTTP 400, no EAR).
type Appraise func(mediaType string, value, nonce []byte) (status string, annotated map[string]any)

// Server is one Verifier.
type Server struct {
	// Key signs the EARs; nil means one is generated at first use.
	Key *ecdsa.PrivateKey
	// Submod is the appraisal's name (the attester component).
	Submod string
	// PolicyID is ear.appraisal-policy-id.
	PolicyID string
	// Developer and Build are ear.verifier-id.
	Developer, Build string
	// Accept are the media types newSession advertises.
	Accept []string
	// Appraise judges; nil affirms everything.
	Appraise Appraise
	// Async, when set, answers the evidence with 202 processing and
	// completes on the next GET (Veraison's asynchronous form).
	Async bool
	// TrustVector is the vector of an affirming result; nil gives
	// hardware and runtime-opaque 2 (genuine, encrypted).
	TrustVector map[string]int
	// Clock is the Verifier's clock (sessions' expiry, the EAR's iat);
	// nil means the system clock. A test advances it to expire sessions.
	Clock shared_time.Clock

	mu       sync.Mutex
	sessions map[string]*session
	requests int
}

// Requests is how many requests the Verifier served, for a test that
// asserts none reached it, or that a session did.
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

type session struct {
	nonce   []byte
	expires time.Time
	pending *string // the EAR, when the session answered 202 and waits for the GET
}

// PublicKey is the key the EARs verify under.
func (s *Server) PublicKey() *ecdsa.PublicKey {
	s.ensureKey()
	return &s.Key.PublicKey
}

// PublicKeyFor is the signing key itself, for a test that signs claims by hand.
func (s *Server) PublicKeyFor() *ecdsa.PrivateKey {
	s.ensureKey()
	return s.Key
}

// PublicJWK is the public key as Veraison's well-known document gives it.
func (s *Server) PublicJWK() []byte {
	point, err := s.PublicKey().Bytes() // 0x04 || x || y
	if err != nil {
		panic(err)
	}
	b, _ := json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(point[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(point[33:65]),
	})
	return b
}

func (s *Server) now() time.Time {
	if s.Clock == nil {
		return shared_time.NewSystemClock().Now()
	}
	return s.Clock.Now()
}

func (s *Server) ensureKey() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		s.Key = k
	}
}

// Handler is the HTTP API.
func (s *Server) Handler() http.Handler {
	s.ensureKey()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/veraison/verification", func(w http.ResponseWriter, r *http.Request) {
		s.count()
		var key json.RawMessage = s.PublicJWK()
		writeJSON(w, http.StatusOK, map[string]any{"ear-verification-key": key, "media-types": s.Accept, "service-state": "READY"})
	})
	mux.HandleFunc("POST /challenge-response/v1/newSession", func(w http.ResponseWriter, r *http.Request) {
		s.count()
		nonce, err := base64.URLEncoding.DecodeString(r.URL.Query().Get("nonce"))
		if err != nil || len(nonce) < 8 || len(nonce) > 64 {
			http.Error(w, "nonce must be 8 to 64 octets, base64url", http.StatusBadRequest)
			return
		}
		id := make([]byte, 16)
		_, _ = rand.Read(id)
		sid := hex.EncodeToString(id)
		s.mu.Lock()
		if s.sessions == nil {
			s.sessions = map[string]*session{}
		}
		now := s.now()
		s.sessions[sid] = &session{nonce: nonce, expires: now.Add(5 * time.Minute)}
		s.mu.Unlock()
		w.Header().Set("Location", "session/"+sid)
		writeJSON(w, http.StatusCreated, map[string]any{"status": "waiting", "nonce": base64.URLEncoding.EncodeToString(nonce), "accept": s.Accept,
			"expiry": now.Add(5 * time.Minute).UTC().Format(time.RFC3339)})
	})
	mux.HandleFunc("POST /challenge-response/v1/session/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.count()
		se := s.lookup(r.PathValue("id"))
		if se == nil {
			http.Error(w, "no such session", http.StatusNotFound)
			return
		}
		if r.Header.Get("Accept") != SessionMediaType {
			http.Error(w, "the only output format is "+SessionMediaType, http.StatusNotAcceptable)
			return
		}
		mediaType := r.Header.Get("Content-Type")
		if mediaType == "" {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		value, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		status, annotated := EARStatusAffirmingAll(mediaType, value, se.nonce)
		if s.Appraise != nil {
			status, annotated = s.Appraise(mediaType, value, se.nonce)
		}
		if status == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": "failed"})
			return
		}
		ear := s.signEAR(status, annotated, se.nonce)
		if s.Async {
			s.mu.Lock()
			se.pending = &ear
			s.mu.Unlock()
			writeJSON(w, http.StatusAccepted, map[string]any{"status": "processing", "nonce": base64.URLEncoding.EncodeToString(se.nonce)})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "complete", "nonce": base64.URLEncoding.EncodeToString(se.nonce), "result": ear})
	})
	mux.HandleFunc("GET /challenge-response/v1/session/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.count()
		se := s.lookup(r.PathValue("id"))
		if se == nil {
			http.Error(w, "no such session", http.StatusNotFound)
			return
		}
		s.mu.Lock()
		pending := se.pending
		s.mu.Unlock()
		if pending == nil {
			writeJSON(w, http.StatusOK, map[string]any{"status": "waiting"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "complete", "result": *pending})
	})
	mux.HandleFunc("DELETE /challenge-response/v1/session/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.count()
		s.mu.Lock()
		delete(s.sessions, r.PathValue("id"))
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// EARStatusAffirmingAll is the default appraisal: affirming, with the
// message's size as the only annotation.
func EARStatusAffirmingAll(mediaType string, value, _ []byte) (string, map[string]any) {
	return "affirming", map[string]any{"media-type": mediaType, "size": len(value)}
}

func (s *Server) count() {
	s.mu.Lock()
	s.requests++
	s.mu.Unlock()
}

func (s *Server) lookup(id string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	se, ok := s.sessions[id]
	if !ok || s.now().After(se.expires) {
		return nil
	}
	return se
}

func (s *Server) signEAR(status string, annotated map[string]any, nonce []byte) string {
	tv := s.TrustVector
	if tv == nil {
		tv = map[string]int{"hardware": 2, "runtime-opaque": 2}
	}
	if status != "affirming" {
		tv = map[string]int{"hardware": 97, "runtime-opaque": 97}
	}
	sub := map[string]any{"ear.status": status, "ear.appraisal-policy-id": s.PolicyID, "ear.trustworthiness-vector": tv,
		"ear.veraison.annotated-evidence": annotated}
	dev, build := s.Developer, s.Build
	if dev == "" {
		dev = "ratstest"
	}
	ear, err := SignEAR(s.Key, map[string]any{
		"eat_profile": "tag:github.com,2023:veraison/ear", "iat": s.now().Unix(),
		"eat_nonce":       base64.RawURLEncoding.EncodeToString(nonce),
		"ear.verifier-id": map[string]string{"developer": dev, "build": build},
		"submods":         map[string]any{s.Submod: sub},
	})
	if err != nil {
		panic(err)
	}
	return ear
}

// SignEAR signs claims as a compact JWS, ES256 (the signature r||s).
func SignEAR(key *ecdsa.PrivateKey, claims map[string]any) (string, error) {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	d := sha256.Sum256([]byte(signing))
	r, sv, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return signing + "." + enc.EncodeToString(sig), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", SessionMediaType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
