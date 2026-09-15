// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sentinel keeps a running model's state sealed while it runs, and
// says when the machine it runs on can no longer be trusted (ADR 0012).
//
// The sentinel runs beside the workload on the primary. Whenever the state
// it watches settles into something new, it seals it as the next
// generation of a genome chain — the key encapsulated to the release
// authority's escrow key, so the primary keeps nothing that opens what it
// sealed — and signs a seal record for it. Every tick it also checks its
// tripwires and writes a signed heartbeat. When a tripwire fires it stops
// sealing, writes a signed compromise report naming the last genome sealed
// before it, and exits.
//
// Everything it writes goes to an outbox directory, replicated wherever the
// operator likes: bundles and escrow envelopes are ciphertext, and records
// are public statements. The release authority reads the outbox with the
// sentinel's public key, which the operator pins in a signed failover
// policy (internal/vault/failover); a record that does not verify under it
// is ignored, so whoever can write to the outbox can hide genomes but never
// add one.
package sentinel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/ai-continuity-platform/core/internal/genome/bundle"
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
)

// Schemas of the three records a sentinel signs.
const (
	SealSchema       = "vault-genome/seal-record/v1"
	HeartbeatSchema  = "vault-genome/heartbeat/v1"
	CompromiseSchema = "vault-genome/compromise/v1"
)

// Heartbeat statuses.
const (
	StatusWatching    = "watching"    // alive, sealing, wires clean
	StatusStopped     = "stopped"     // stopped by its operator: no failover
	StatusCompromised = "compromised" // a wire fired: see the compromise report
)

// Outbox file names.
const (
	HeartbeatFile  = "heartbeat.json"
	CompromiseFile = "compromise.json"
)

// BundleName, EscrowName and RecordName are the outbox files of generation g.
func BundleName(g uint64) string { return fmt.Sprintf("gen-%06d.genome", g) }
func EscrowName(g uint64) string { return BundleName(g) + ".escrow" }
func RecordName(g uint64) string { return fmt.Sprintf("gen-%06d.seal.json", g) }

var (
	recordNameRE = regexp.MustCompile(`^gen-([0-9]{6,})\.seal\.json$`)
	sentinelIDRE = regexp.MustCompile(`^sentinel-[0-9a-f]{16}$`)
	hexDigestRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// KeyID names a sentinel key: "sentinel-" and the first 16 hex digits of the
// SHA-256 of its public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sentinel-" + hex.EncodeToString(sum[:8])
}

// Link points at one sealed generation.
type Link struct {
	Generation   uint64    `json:"generation"`
	BundleSHA256 string    `json:"bundle_sha256"`
	SealedAt     time.Time `json:"sealed_at"`
}

func (l *Link) validate() error {
	if l == nil {
		return nil
	}
	if !hexDigestRE.MatchString(l.BundleSHA256) || l.SealedAt.IsZero() {
		return errors.New("sentinel: malformed link")
	}
	return nil
}

// SealRecord is the sentinel's signed statement that it sealed a
// generation: which files hold it, what they hash to, which key opens it
// (by ID) and that the key went to escrow, and the generation before it.
type SealRecord struct {
	Schema             string    `json:"schema"`
	Sentinel           string    `json:"sentinel"`
	Generation         uint64    `json:"generation"`
	Bundle             string    `json:"bundle"`
	BundleSHA256       string    `json:"bundle_sha256"`
	BundleBytes        int64     `json:"bundle_bytes"`
	KeyID              string    `json:"key_id"`
	Escrow             string    `json:"escrow"`
	EscrowKey          string    `json:"escrow_key"`
	PayloadSHA256      string    `json:"payload_sha256"`
	ParentBundleSHA256 string    `json:"parent_bundle_sha256,omitempty"`
	SealedAt           time.Time `json:"sealed_at"`
	Signature          []byte    `json:"signature,omitempty"`
}

// Link returns the record's link.
func (r SealRecord) Link() Link {
	return Link{Generation: r.Generation, BundleSHA256: r.BundleSHA256, SealedAt: r.SealedAt}
}

func (r SealRecord) validate() error {
	switch {
	case r.Schema != SealSchema:
		return fmt.Errorf("sentinel: schema %q, want %q", r.Schema, SealSchema)
	case !sentinelIDRE.MatchString(r.Sentinel):
		return fmt.Errorf("sentinel: %q is not a sentinel key id", r.Sentinel)
	case r.Bundle != BundleName(r.Generation) || r.Escrow != EscrowName(r.Generation):
		return fmt.Errorf("sentinel: generation %d names files %q and %q", r.Generation, r.Bundle, r.Escrow)
	case !hexDigestRE.MatchString(r.BundleSHA256) || r.BundleBytes <= 0:
		return errors.New("sentinel: bundle digest and size required")
	case !bundle.IsKeyID(r.KeyID):
		return fmt.Errorf("sentinel: %q is not a genome key id", r.KeyID)
	case r.EscrowKey == "":
		return errors.New("sentinel: escrow key tag required")
	case len(r.PayloadSHA256) != len("sha256:")+64:
		return errors.New("sentinel: payload digest required")
	case (r.Generation > 0) != (r.ParentBundleSHA256 != ""):
		return errors.New("sentinel: a parent is named exactly when the generation is above 0")
	case r.ParentBundleSHA256 != "" && !hexDigestRE.MatchString(r.ParentBundleSHA256):
		return errors.New("sentinel: malformed parent digest")
	case r.SealedAt.IsZero():
		return errors.New("sentinel: sealed_at required")
	}
	return nil
}

// Heartbeat is the sentinel's signed statement that it is alive, what it
// last sealed, and whether its wires are clean. Seq rises with every one.
type Heartbeat struct {
	Schema    string    `json:"schema"`
	Sentinel  string    `json:"sentinel"`
	Seq       uint64    `json:"seq"`
	At        time.Time `json:"at"`
	StartedAt time.Time `json:"started_at"`
	Status    string    `json:"status"`
	// Last is the newest generation sealed, nil before the first.
	Last *Link `json:"last,omitempty"`
	// Wires is how many tripwires are armed.
	Wires     int    `json:"wires"`
	Signature []byte `json:"signature,omitempty"`
}

func (h Heartbeat) validate() error {
	switch {
	case h.Schema != HeartbeatSchema:
		return fmt.Errorf("sentinel: schema %q, want %q", h.Schema, HeartbeatSchema)
	case !sentinelIDRE.MatchString(h.Sentinel):
		return fmt.Errorf("sentinel: %q is not a sentinel key id", h.Sentinel)
	case h.Seq == 0 || h.At.IsZero() || h.StartedAt.IsZero():
		return errors.New("sentinel: heartbeat seq, at and started_at required")
	case h.Status != StatusWatching && h.Status != StatusStopped && h.Status != StatusCompromised:
		return fmt.Errorf("sentinel: heartbeat status %q", h.Status)
	}
	return h.Last.validate()
}

// Trip is one tripwire that fired.
type Trip struct {
	// Wire is "path" or "probe".
	Wire   string `json:"wire"`
	Target string `json:"target"`
	// Want is the baseline a path wire was armed with.
	Want string `json:"want,omitempty"`
	// Got is what the wire found: a path's digest now, "missing", or a
	// probe's exit status.
	Got    string `json:"got"`
	Detail string `json:"detail,omitempty"`
}

// Compromise is the sentinel's signed report that a tripwire fired. It
// names the newest generation sealed before detection; the sentinel sealed
// nothing after.
type Compromise struct {
	Schema     string    `json:"schema"`
	Sentinel   string    `json:"sentinel"`
	DetectedAt time.Time `json:"detected_at"`
	Tripped    []Trip    `json:"tripped"`
	Last       *Link     `json:"last,omitempty"`
	Signature  []byte    `json:"signature,omitempty"`
}

func (c Compromise) validate() error {
	switch {
	case c.Schema != CompromiseSchema:
		return fmt.Errorf("sentinel: schema %q, want %q", c.Schema, CompromiseSchema)
	case !sentinelIDRE.MatchString(c.Sentinel):
		return fmt.Errorf("sentinel: %q is not a sentinel key id", c.Sentinel)
	case c.DetectedAt.IsZero() || len(c.Tripped) == 0:
		return errors.New("sentinel: a compromise report names when and which wires")
	}
	return c.Last.validate()
}

// signable is a record that signs over its canonical form without its
// signature.
type signable interface {
	validate() error
	unsigned() any
	signature() []byte
	sentinel() string
}

func (r SealRecord) unsigned() any     { r.Signature = nil; return r }
func (r SealRecord) signature() []byte { return r.Signature }
func (r SealRecord) sentinel() string  { return r.Sentinel }
func (h Heartbeat) unsigned() any      { h.Signature = nil; return h }
func (h Heartbeat) signature() []byte  { return h.Signature }
func (h Heartbeat) sentinel() string   { return h.Sentinel }
func (c Compromise) unsigned() any     { c.Signature = nil; return c }
func (c Compromise) signature() []byte { return c.Signature }
func (c Compromise) sentinel() string  { return c.Sentinel }

func signatureOver(v signable, priv ed25519.PrivateKey) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	if v.sentinel() != KeyID(priv.Public().(ed25519.PublicKey)) {
		return nil, fmt.Errorf("sentinel: record names %s, the key is %s", v.sentinel(), KeyID(priv.Public().(ed25519.PublicKey)))
	}
	msg, err := crypto.CanonicalJSON(v.unsigned())
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, msg), nil
}

func verify(v signable, pub ed25519.PublicKey) error {
	if err := v.validate(); err != nil {
		return err
	}
	if v.sentinel() != KeyID(pub) {
		return fmt.Errorf("sentinel: signed by %s, the pinned sentinel is %s", v.sentinel(), KeyID(pub))
	}
	msg, err := crypto.CanonicalJSON(v.unsigned())
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, v.signature()) {
		return errors.New("sentinel: signature does not verify under the pinned sentinel key")
	}
	return nil
}

// SignRecord, SignHeartbeat and SignCompromise sign with the sentinel key.
func SignRecord(r SealRecord, priv ed25519.PrivateKey) (SealRecord, error) {
	r.Schema = SealSchema
	sig, err := signatureOver(r, priv)
	r.Signature = sig
	return r, err
}

func SignHeartbeat(h Heartbeat, priv ed25519.PrivateKey) (Heartbeat, error) {
	h.Schema = HeartbeatSchema
	sig, err := signatureOver(h, priv)
	h.Signature = sig
	return h, err
}

func SignCompromise(c Compromise, priv ed25519.PrivateKey) (Compromise, error) {
	c.Schema = CompromiseSchema
	sig, err := signatureOver(c, priv)
	c.Signature = sig
	return c, err
}

func decode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("sentinel: decode: %w", err)
	}
	if dec.More() {
		return errors.New("sentinel: trailing data")
	}
	return nil
}

// ParseRecord, ParseHeartbeat and ParseCompromise decode a record and
// accept it only if it is well formed and verifies under pub.
func ParseRecord(raw []byte, pub ed25519.PublicKey) (SealRecord, error) {
	var r SealRecord
	if err := decode(raw, &r); err != nil {
		return SealRecord{}, err
	}
	return r, verify(r, pub)
}

func ParseHeartbeat(raw []byte, pub ed25519.PublicKey) (Heartbeat, error) {
	var h Heartbeat
	if err := decode(raw, &h); err != nil {
		return Heartbeat{}, err
	}
	return h, verify(h, pub)
}

func ParseCompromise(raw []byte, pub ed25519.PublicKey) (Compromise, error) {
	var c Compromise
	if err := decode(raw, &c); err != nil {
		return Compromise{}, err
	}
	return c, verify(c, pub)
}

func encode(v any) ([]byte, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
