// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package escrow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// RecoverySchema names the recovery envelope of releases before ADR
// 0029, RecoverySchemaV2 the one written now: the escrow private key
// encapsulated to the operator's recovery public key, so a sealed escrow
// key survives the chip it was sealed to. The operator's recovery private
// key lives off the release host; opening the envelope is a ceremony, and
// the key is resealed on the new host without touching its disk in the
// clear (ADR 0016).
const (
	RecoverySchema   = "vault-genome/escrow-recovery/v1"
	RecoverySchemaV2 = "vault-genome/escrow-recovery/v2"
)

const (
	recoveryAADLabel   = "vault-genome escrow-recovery v1\x00"
	recoveryAADLabelV2 = "vault-genome escrow-recovery v2\x00"
)

// Recovery is an escrow private key wrapped to a recovery public key.
type Recovery struct {
	Schema string `json:"schema"`
	// EscrowKey is the tag of the escrow key inside.
	EscrowKey string `json:"escrow_key"`
	// RecoveryKey is the tag of the recovery public key it is wrapped to.
	RecoveryKey string `json:"recovery_key"`
	// Suite is the escrow key's KEM suite and RecoverySuite the recovery
	// key's (v2); a v1 envelope names neither: both X25519, the ECIES of
	// ADR 0009.
	Suite         string `json:"suite,omitempty"`
	RecoverySuite string `json:"recovery_suite,omitempty"`
	// PublicKeyPEM is the escrow public key, so the envelope says what it
	// holds without being opened.
	PublicKeyPEM string `json:"public_key_pem"`
	Ciphertext   []byte `json:"ciphertext"`
}

func recoveryAAD(escrowTag, recoveryTag string) []byte {
	return []byte(recoveryAADLabel + escrowTag + "\x00" + recoveryTag)
}

func recoveryAADV2(escrowTag, recoveryTag string) []byte {
	return []byte(recoveryAADLabelV2 + escrowTag + "\x00" + recoveryTag)
}

// WrapRecovery encapsulates key to recoveryPub, under the recovery key's suite.
func WrapRecovery(key *PrivateKey, recoveryPub PublicKey) (Recovery, error) {
	if key == nil || recoveryPub.IsZero() {
		return Recovery{}, errors.New("escrow: escrow key and recovery public key required")
	}
	pemBytes, err := PublicPEM(key.PublicKey())
	if err != nil {
		return Recovery{}, err
	}
	escrowTag, recoveryTag := KeyTag(key.PublicKey()), KeyTag(recoveryPub)
	ct, err := recoveryPub.Suite().Wrap(kms.PurposeEscrowRecovery, key.Bytes(), recoveryPub.Bytes(), recoveryAADV2(escrowTag, recoveryTag))
	if err != nil {
		return Recovery{}, fmt.Errorf("escrow: wrap for recovery: %w", err)
	}
	return Recovery{
		Schema: RecoverySchemaV2, EscrowKey: escrowTag, RecoveryKey: recoveryTag,
		Suite: string(key.Suite()), RecoverySuite: string(recoveryPub.Suite()),
		PublicKeyPEM: string(pemBytes), Ciphertext: ct,
	}, nil
}

// Open recovers the escrow private key with the operator's recovery
// private key, and checks it is the key the envelope names.
func (r Recovery) Open(recoveryPriv *PrivateKey) (*PrivateKey, error) {
	if recoveryPriv == nil {
		return nil, errors.New("escrow: recovery private key required")
	}
	if tag := KeyTag(recoveryPriv.PublicKey()); tag != r.RecoveryKey {
		return nil, fmt.Errorf("escrow: the envelope is wrapped to recovery key %s; this key is %s", r.RecoveryKey, tag)
	}
	pub, err := ParsePublicPEM([]byte(r.PublicKeyPEM))
	if err != nil {
		return nil, err
	}
	if KeyTag(pub) != r.EscrowKey {
		return nil, fmt.Errorf("escrow: the envelope's public key is %s, its tag says %s", KeyTag(pub), r.EscrowKey)
	}
	var raw []byte
	var suite kms.Suite
	switch r.Schema {
	case RecoverySchemaV2:
		// The envelope names the suites it was written under (v1 of 0.7.0
		// or v2, ADR 0030); the keys must be of those families, and the
		// envelope opens under the suite it names.
		recoverySuite := kms.Suite(r.RecoverySuite)
		if !recoverySuite.SameFamily(recoveryPriv.Suite()) {
			return nil, fmt.Errorf("escrow: the envelope is wrapped under KEM suite %q; this recovery key is under %q", r.RecoverySuite, recoveryPriv.Suite())
		}
		if !kms.Suite(r.Suite).SameFamily(pub.Suite()) {
			return nil, fmt.Errorf("escrow: the envelope says its escrow key is under %q, its public key is under %q", r.Suite, pub.Suite())
		}
		suite = pub.Suite()
		raw, err = recoverySuite.Unwrap(kms.PurposeEscrowRecovery, r.Ciphertext, recoveryPriv.Bytes(), recoveryAADV2(r.EscrowKey, r.RecoveryKey))
	case RecoverySchema:
		if recoveryPriv.Suite() != LegacySuite || pub.Suite() != LegacySuite {
			return nil, errors.New("escrow: a v1 recovery envelope holds an X25519 escrow key wrapped to an X25519 recovery key")
		}
		if r.Suite != "" || r.RecoverySuite != "" {
			return nil, errors.New("escrow: a v1 recovery envelope names no suite")
		}
		suite = LegacySuite
		raw, err = kms.X25519KeyUnwrapper{}.Unwrap(r.Ciphertext, recoveryPriv.Bytes(), recoveryAAD(r.EscrowKey, r.RecoveryKey))
	default:
		return nil, fmt.Errorf("escrow: recovery schema %q, want %q or %q", r.Schema, RecoverySchemaV2, RecoverySchema)
	}
	if err != nil {
		return nil, fmt.Errorf("escrow: open recovery envelope: %w", err)
	}
	defer clear(raw)
	key, err := NewPrivateKey(suite, raw)
	if err != nil {
		return nil, fmt.Errorf("escrow: recovered bytes are not a %s key: %w", suite, err)
	}
	if !key.PublicKey().Equal(pub) {
		key.Clear()
		return nil, errors.New("escrow: the recovered key is not the private half of the public key the envelope names")
	}
	return key, nil
}

// Marshal encodes r.
func (r Recovery) Marshal() ([]byte, error) {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// ParseRecovery decodes a recovery envelope, refusing unknown fields.
func ParseRecovery(raw []byte) (Recovery, error) {
	var r Recovery
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Recovery{}, fmt.Errorf("escrow: recovery envelope: %w", err)
	}
	if r.Schema != RecoverySchema && r.Schema != RecoverySchemaV2 {
		return Recovery{}, fmt.Errorf("escrow: recovery envelope schema %q, want %q or %q", r.Schema, RecoverySchemaV2, RecoverySchema)
	}
	if r.EscrowKey == "" || r.RecoveryKey == "" || r.PublicKeyPEM == "" || len(r.Ciphertext) == 0 {
		return Recovery{}, errors.New("escrow: recovery envelope is incomplete")
	}
	if r.Schema == RecoverySchemaV2 && (r.Suite == "" || r.RecoverySuite == "") {
		return Recovery{}, errors.New("escrow: a v2 recovery envelope names its suites")
	}
	return r, nil
}
