// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package escrow

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// SealedSchema names the file `sagvd escrow-provision` wrote before ADR
// 0029, SealedSchemaV2 the one it writes now: the authority's escrow
// private key sealed to the release host's TEE. The key exists in the
// clear only inside the process that generated it and the process that
// unseals it; on disk it opens only for the same code, on the same chip,
// at the same measurement (ADR 0016).
const (
	SealedSchema   = "vault-genome/sealed-escrow-key/v1"
	SealedSchemaV2 = "vault-genome/sealed-escrow-key/v2"
)

const (
	sealedAADLabel   = "vault-genome sealed-escrow-key v1\x00"
	sealedAADLabelV2 = "vault-genome sealed-escrow-key v2\x00"
)

// SealedKey is the escrow private key, sealed. Everything but Sealed is
// public and bound into the seal's AAD, so a field changed on disk fails
// to open rather than opening as something else.
type SealedKey struct {
	Schema string `json:"schema"`
	// TEE names the sealer: gcp-sev-snp (the chip's derived key) or
	// simulated (a key from the simulated measurement; development only).
	TEE string `json:"tee"`
	// MeasurementHex is the launch measurement the key was sealed at.
	MeasurementHex string `json:"measurement_hex"`
	// EscrowKey is the tag of the public key inside (KeyTag).
	EscrowKey string `json:"escrow_key"`
	// Suite is the key's KEM suite (v2); a v1 file holds an X25519 key.
	Suite string `json:"suite,omitempty"`
	// PublicKeyPEM is the escrow public key, readable without unsealing:
	// what `sagvd identity` prints and sealers pin.
	PublicKeyPEM string `json:"public_key_pem"`
	Sealed       []byte `json:"sealed"`
}

func sealedAAD(provider tee.Provider, measurement tee.Measurement, tag string) []byte {
	aad := []byte(sealedAADLabel)
	aad = append(aad, provider...)
	aad = append(aad, 0)
	aad = append(aad, hex.EncodeToString(measurement)...)
	aad = append(aad, 0)
	return append(aad, tag...)
}

func sealedAADV2(provider tee.Provider, measurement tee.Measurement, tag string, suite kms.Suite) []byte {
	aad := []byte(sealedAADLabelV2)
	aad = append(aad, provider...)
	aad = append(aad, 0)
	aad = append(aad, hex.EncodeToString(measurement)...)
	aad = append(aad, 0)
	aad = append(aad, tag...)
	aad = append(aad, 0)
	return append(aad, suite...)
}

// SealKey seals key to the TEE behind sealer, recording the provider and
// measurement it was sealed at, and the key's suite.
func SealKey(key *PrivateKey, sealer tee.Sealer, provider tee.Provider, measurement tee.Measurement) (SealedKey, error) {
	if key == nil || sealer == nil || provider == "" || measurement.IsZero() {
		return SealedKey{}, errors.New("escrow: key, sealer, provider and measurement required")
	}
	pemBytes, err := PublicPEM(key.PublicKey())
	if err != nil {
		return SealedKey{}, err
	}
	tag := KeyTag(key.PublicKey())
	sealed, err := sealer.Seal(key.Bytes(), sealedAADV2(provider, measurement, tag, key.Suite()))
	if err != nil {
		return SealedKey{}, fmt.Errorf("escrow: seal to %s: %w", provider, err)
	}
	return SealedKey{
		Schema:         SealedSchemaV2,
		TEE:            string(provider),
		MeasurementHex: hex.EncodeToString(measurement),
		EscrowKey:      tag,
		Suite:          string(key.Suite()),
		PublicKeyPEM:   string(pemBytes),
		Sealed:         sealed,
	}, nil
}

// PublicKey returns the escrow public key the file carries in the clear,
// checked against its tag and, for a v2 file, its suite.
func (s SealedKey) PublicKey() (PublicKey, error) {
	if s.Schema != SealedSchema && s.Schema != SealedSchemaV2 {
		return PublicKey{}, fmt.Errorf("escrow: schema %q, want %q or %q", s.Schema, SealedSchemaV2, SealedSchema)
	}
	pub, err := ParsePublicPEM([]byte(s.PublicKeyPEM))
	if err != nil {
		return PublicKey{}, err
	}
	if KeyTag(pub) != s.EscrowKey {
		return PublicKey{}, fmt.Errorf("escrow: the sealed file's public key is %s, its tag says %s", KeyTag(pub), s.EscrowKey)
	}
	switch s.Schema {
	case SealedSchemaV2:
		if s.Suite != string(pub.Suite()) {
			return PublicKey{}, fmt.Errorf("escrow: the sealed file says suite %q, its public key is under %q", s.Suite, pub.Suite())
		}
	case SealedSchema:
		if s.Suite != "" || pub.Suite() != LegacySuite {
			return PublicKey{}, errors.New("escrow: a v1 sealed file holds an X25519 key and names no suite")
		}
	}
	return pub, nil
}

// Open unseals the private key on the TEE behind sealer. The live
// provider and measurement must be the ones the key was sealed at — said
// plainly before the AEAD is asked — and the key that comes out must be
// the public key's private half.
func (s SealedKey) Open(sealer tee.Sealer, provider tee.Provider, measurement tee.Measurement) (*PrivateKey, error) {
	pub, err := s.PublicKey()
	if err != nil {
		return nil, err
	}
	if sealer == nil {
		return nil, errors.New("escrow: no TEE sealer to open the sealed escrow key with")
	}
	if s.TEE != string(provider) {
		return nil, fmt.Errorf("escrow: the escrow key was sealed to %s; this host's TEE is %s", s.TEE, provider)
	}
	if s.MeasurementHex != hex.EncodeToString(measurement) {
		return nil, fmt.Errorf("escrow: the escrow key was sealed at measurement %s; this host runs at %s (another image, or another build: re-provision it from its recovery envelope)", short(s.MeasurementHex), short(hex.EncodeToString(measurement)))
	}
	aad := sealedAAD(provider, measurement, s.EscrowKey)
	if s.Schema == SealedSchemaV2 {
		aad = sealedAADV2(provider, measurement, s.EscrowKey, pub.Suite())
	}
	raw, err := sealer.Unseal(s.Sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("escrow: unseal on %s: %w (another chip, or a changed file: re-provision it from its recovery envelope)", provider, err)
	}
	defer clear(raw)
	key, err := NewPrivateKey(pub.Suite(), raw)
	if err != nil {
		return nil, fmt.Errorf("escrow: unsealed bytes are not a %s key: %w", pub.Suite(), err)
	}
	if !key.PublicKey().Equal(pub) {
		key.Clear()
		return nil, errors.New("escrow: the unsealed key is not the private half of the public key the file carries")
	}
	return key, nil
}

func short(hexDigest string) string {
	if len(hexDigest) > 12 {
		return hexDigest[:12] + "…"
	}
	return hexDigest
}

// Marshal encodes s.
func (s SealedKey) Marshal() ([]byte, error) {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// ParseSealed decodes a sealed escrow key file, refusing unknown fields.
func ParseSealed(raw []byte) (SealedKey, error) {
	var s SealedKey
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return SealedKey{}, fmt.Errorf("escrow: sealed key: %w", err)
	}
	if s.Schema != SealedSchema && s.Schema != SealedSchemaV2 {
		return SealedKey{}, fmt.Errorf("escrow: sealed key schema %q, want %q or %q", s.Schema, SealedSchemaV2, SealedSchema)
	}
	if s.TEE == "" || s.MeasurementHex == "" || s.EscrowKey == "" || s.PublicKeyPEM == "" || len(s.Sealed) == 0 {
		return SealedKey{}, errors.New("escrow: sealed key file is incomplete")
	}
	if s.Schema == SealedSchemaV2 && s.Suite == "" {
		return SealedKey{}, errors.New("escrow: a v2 sealed key file names its suite")
	}
	return s, nil
}

// IsSealed reports whether raw is a sealed escrow key file rather than a
// key file: anything but a raw 32-byte X25519 key or a PEM that reads as
// a JSON object. (A raw key may well begin with '{'; its length decides.)
func IsSealed(raw []byte) bool {
	if len(raw) == legacyKeySize {
		return false
	}
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}
