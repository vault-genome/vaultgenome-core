// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package escrow hands a genome's key to the release authority at the
// moment it is sealed, so the machine that sealed it keeps nothing secret.
//
// The authority publishes an escrow public key under a KEM suite (ADR
// 0029). `acpctl genome seal --escrow-to` encapsulates the fresh DEK to
// it (RFC 9180 HPKE under that suite) and writes the result beside the
// bundle; the plaintext key is never written. The escrow envelope names
// the key ID, the suite and the escrow key's tag, and is bound to the key
// ID, so it can travel with its bundle — to object storage, another cloud
// — and is useless to anyone but the authority. The authority opens it
// only to release the key, by operator policy, to an attested destination
// (`sagvd crosscloud-restore -key-escrow`), or to run a gate job.
//
// Envelopes of releases before ADR 0029 (schema v1: the ECIES of ADR 0009
// to an X25519 key) still open, with the same X25519 key, now
// hpke-x25519-v1; nothing writes v1 any more.
package escrow

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// Schema names the escrow envelope of releases before ADR 0029; SchemaV2
// the one written now, which names its suite.
const (
	Schema   = "vault-genome/key-escrow/v1"
	SchemaV2 = "vault-genome/key-escrow/v2"
)

const (
	aadLabel   = "vault-genome key-escrow v1\x00"
	aadLabelV2 = "vault-genome key-escrow v2\x00"
)

// Envelope is a genome key encapsulated to the release authority.
type Envelope struct {
	Schema string `json:"schema"`
	// KeyID is the genome key inside; its tag lets the authority check the
	// key it unwraps is the one named.
	KeyID string `json:"key_id"`
	// EscrowKey is the tag of the escrow public key it was sealed to, so an
	// envelope for another authority is refused before any decryption.
	EscrowKey string `json:"escrow_key"`
	// Suite is the KEM suite the key is encapsulated under (v2); a v1
	// envelope names none and is the ECIES of ADR 0009 to an X25519 key.
	Suite      string `json:"suite,omitempty"`
	Ciphertext []byte `json:"ciphertext"`
}

func aad(keyID string) []byte   { return append([]byte(aadLabel), keyID...) }
func aadV2(keyID string) []byte { return append([]byte(aadLabelV2), keyID...) }

// Seal encapsulates dek, the key keyID names, to the escrow public key,
// under the key's suite.
func Seal(dek []byte, keyID string, escrowPub PublicKey) (Envelope, error) {
	if err := bundle.CheckKey(keyID, dek); err != nil {
		return Envelope{}, err
	}
	if escrowPub.IsZero() {
		return Envelope{}, fmt.Errorf("escrow: seal: no escrow public key")
	}
	ct, err := escrowPub.Suite().Wrap(kms.PurposeEscrowDEK, dek, escrowPub.Bytes(), aadV2(keyID))
	if err != nil {
		return Envelope{}, fmt.Errorf("escrow: seal: %w", err)
	}
	return Envelope{Schema: SchemaV2, KeyID: keyID, EscrowKey: KeyTag(escrowPub), Suite: string(escrowPub.Suite()), Ciphertext: ct}, nil
}

// Open recovers the genome key from env with the escrow private key, and
// checks it is the key the envelope names. A v2 envelope opens under its
// suite, which must be the key's; a v1 envelope opens with an X25519 key
// through the ECIES it was written with.
func Open(env Envelope, key *PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("escrow: no escrow private key to open %s with", env.KeyID)
	}
	if !bundle.IsKeyID(env.KeyID) {
		return nil, fmt.Errorf("escrow: %q is not a genome key id", env.KeyID)
	}
	if env.EscrowKey != KeyTag(key.PublicKey()) {
		return nil, fmt.Errorf("escrow: sealed to escrow key %s, this authority holds %s", env.EscrowKey, KeyTag(key.PublicKey()))
	}
	var dek []byte
	var err error
	switch env.Schema {
	case SchemaV2:
		// The envelope names the suite it was wrapped under — a v1 suite
		// of 0.7.0 or a v2 one (ADR 0030); the key must be of that
		// suite's family, and the envelope opens under its own suite.
		envSuite := kms.Suite(env.Suite)
		if !envSuite.SameFamily(key.Suite()) {
			return nil, fmt.Errorf("escrow: %s is under KEM suite %q, this authority's escrow key is under %q", env.KeyID, env.Suite, key.Suite())
		}
		dek, err = envSuite.Unwrap(kms.PurposeEscrowDEK, env.Ciphertext, key.Bytes(), aadV2(env.KeyID))
	case Schema:
		if key.Suite() != LegacySuite {
			return nil, fmt.Errorf("escrow: %s is a v1 envelope (X25519), this authority's escrow key is under %q", env.KeyID, key.Suite())
		}
		if env.Suite != "" {
			return nil, fmt.Errorf("escrow: a v1 envelope names no suite; %s names %q", env.KeyID, env.Suite)
		}
		dek, err = kms.X25519KeyUnwrapper{}.Unwrap(env.Ciphertext, key.Bytes(), aad(env.KeyID))
	default:
		return nil, fmt.Errorf("escrow: schema %q, want %q or %q", env.Schema, SchemaV2, Schema)
	}
	if err != nil {
		return nil, fmt.Errorf("escrow: open %s: %w", env.KeyID, err)
	}
	if err := bundle.CheckKey(env.KeyID, dek); err != nil {
		return nil, err
	}
	return dek, nil
}

// Marshal encodes env.
func (env Envelope) Marshal() ([]byte, error) { return json.MarshalIndent(env, "", "  ") }

// Parse decodes an envelope, refusing unknown fields.
func Parse(b []byte) (Envelope, error) {
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return Envelope{}, fmt.Errorf("escrow: %w", err)
	}
	return env, nil
}
