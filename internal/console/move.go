// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package console

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
)

// MoveOrderSchema names a signed order to move a model.
const MoveOrderSchema = "vault-genome/console-move-order/v1"

// MoveOrderMaxAge is how long an order may be carried out after it is signed.
const MoveOrderMaxAge = 15 * time.Minute

// MoveOrder is the holder's written order: this server shall hand this model
// to that server, which must prove itself by this pin. It is signed on the
// holder's computer with the key that signs the stop list, so the people who
// hold that key, and not the server or anyone who reaches it, decide where a
// model goes (ADR 0012's answer, given at the moment of the move).
type MoveOrder struct {
	Schema         string                `json:"schema"`
	OrderID        string                `json:"order_id"`
	IssuedAt       time.Time             `json:"issued_at"`
	ExpiresAt      time.Time             `json:"expires_at"`
	FromCertSHA256 string                `json:"from_cert_sha256"`
	Bundle         string                `json:"bundle"`
	To             MoveTarget            `json:"to"`
	SigningKeyID   string                `json:"signing_key_id"`
	Alg            crypto.SignatureSuite `json:"alg,omitempty"`
	Signature      []byte                `json:"signature,omitempty"`
}

// MoveTarget is where the model goes and what that server must show.
type MoveTarget struct {
	Label         string `json:"label"`
	Address       string `json:"address"`
	ServerCertPEM string `json:"server_cert_pem"`
	Pin           Pin    `json:"pin"`
	// JoinCode is a single-use code of the target's, for the peer role: the
	// source's listener key goes on the target's list for this move only.
	JoinCode string `json:"join_code"`
}

func (o MoveOrder) signedBytes() ([]byte, error) {
	o.Signature = nil
	return crypto.CanonicalJSON(o)
}

var bundleNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.genome$`)

// ValidBundleName reports whether name is a sealed genome's file name.
func ValidBundleName(name string) bool { return bundleNameRE.MatchString(name) }

func (o MoveOrder) validate() error {
	switch {
	case o.Schema != MoveOrderSchema:
		return fmt.Errorf("console: the order's schema is %q", o.Schema)
	case o.OrderID == "":
		return errors.New("console: the order has no id")
	case o.IssuedAt.IsZero() || o.ExpiresAt.IsZero():
		return errors.New("console: the order has no time")
	case o.ExpiresAt.Sub(o.IssuedAt) > MoveOrderMaxAge:
		return errors.New("console: the order is good for too long")
	case o.FromCertSHA256 == "":
		return errors.New("console: the order names no source")
	case !ValidBundleName(o.Bundle):
		return errors.New("console: the order names no sealed model")
	case o.To.Address == "" || o.To.ServerCertPEM == "" || o.To.Pin.Provider == "" || o.To.JoinCode == "":
		return errors.New("console: the order names no target")
	case o.SigningKeyID == "":
		return errors.New("console: the order names no signer")
	}
	if _, err := crypto.RecordSuite(o.Alg); err != nil {
		return fmt.Errorf("console: the order's alg: %w", err)
	}
	return nil
}

// SignMoveOrder validates and signs an order. Schema is filled in when empty.
func SignMoveOrder(o MoveOrder, key *crypto.SigningKey) (MoveOrder, error) {
	if key == nil {
		return MoveOrder{}, errors.New("console: the operator key is required")
	}
	if o.Schema == "" {
		o.Schema = MoveOrderSchema
	}
	o.Alg = crypto.RecordAlg(key.Suite())
	if err := o.validate(); err != nil {
		return MoveOrder{}, err
	}
	msg, err := o.signedBytes()
	if err != nil {
		return MoveOrder{}, err
	}
	o.Signature, err = key.Sign(msg)
	if err != nil {
		return MoveOrder{}, err
	}
	return o, nil
}

// ParseMoveOrder accepts an order only if it is well formed, signed under pub
// as kid, addressed to the listener with this certificate, and in its time.
func ParseMoveOrder(raw []byte, pub crypto.SuitePublicKey, kid string, certDER []byte, now time.Time) (MoveOrder, error) {
	var o MoveOrder
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return MoveOrder{}, fmt.Errorf("console: the order does not read: %w", err)
	}
	if err := o.validate(); err != nil {
		return MoveOrder{}, err
	}
	if o.SigningKeyID != kid {
		return MoveOrder{}, fmt.Errorf("console: the order is signed by %q, this server trusts %q", o.SigningKeyID, kid)
	}
	msg, err := o.signedBytes()
	if err != nil {
		return MoveOrder{}, err
	}
	if err := pub.VerifyRecord(o.Alg, msg, o.Signature); err != nil {
		return MoveOrder{}, fmt.Errorf("console: the order's signature does not verify: %w", err)
	}
	if o.FromCertSHA256 != CertSHA256(certDER) {
		return MoveOrder{}, errors.New("console: the order is addressed to another server")
	}
	if now.After(o.ExpiresAt) || now.Before(o.IssuedAt.Add(-5*time.Minute)) {
		return MoveOrder{}, errors.New("console: the order is out of its time")
	}
	return o, nil
}

// CertSHA256 is how an order names a listener.
func CertSHA256(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:])
}

// MoveResponse is what the source reports when the model is on its way's end.
type MoveResponse struct {
	Bundle            string  `json:"bundle"`
	BundleSHA256      string  `json:"bundle_sha256"`
	Bytes             int64   `json:"bytes"`
	TargetMeasurement string  `json:"target_measurement_hex"`
	EscrowKey         string  `json:"escrow_key"`
	Seconds           float64 `json:"seconds"`
}

// RestoreRequest names which sealed model a restore check is for; empty means
// the newest.
type RestoreRequest struct {
	Bundle string `json:"bundle,omitempty"`
}

// IncomingResponse is the target's receipt for one file.
type IncomingResponse struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// The actions of a move, on each server's own record.
const (
	ActionMoveOrdered   = "move_ordered"
	ActionModelReleased = "model_released"
	ActionModelSent     = "model_sent"
	ActionModelReceived = "model_received"
)
