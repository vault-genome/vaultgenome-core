// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
)

// authorityIdentity is what other hosts pin for this authority: the
// signing key a cross-cloud destination verifies every handshake and
// key-release token against, and this vault's TEE identity for the
// workers' pins.
type authorityIdentity struct {
	AuthorityKID          string `json:"authority_kid"`
	AuthorityPublicKeyPEM string `json:"authority_public_key_pem"`
	TEEMeasurementHex     string `json:"tee_measurement_hex"`
	TEEPublicKeyPEM       string `json:"tee_public_key_pem,omitempty"`
	// The key auditors verify the cross-cloud audit log with, when
	// keys.audit_signing is configured.
	AuditKID          string `json:"audit_kid,omitempty"`
	AuditPublicKeyPEM string `json:"audit_public_key_pem,omitempty"`
}

// runIdentityCmd implements `sagvd identity -config <path>`: it loads the
// configured key material and prints the public half as JSON, without
// opening any listener.
func runIdentityCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("sagvd identity", flag.ContinueOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to sagvd JSON config (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("identity: -config required")
	}
	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("identity: config validation: %w", err)
	}
	mat, err := LoadMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		return err
	}
	defer mat.Store.Zeroize()

	authPEM, err := crypto.PublicKeyPEM(mat.AuthoritySigningPublicKey)
	if err != nil {
		return err
	}
	id := authorityIdentity{
		AuthorityKID:          string(mat.AuthoritySigningKeyID),
		AuthorityPublicKeyPEM: string(authPEM),
		TEEMeasurementHex:     hex.EncodeToString(mat.Producer.Measurement()),
	}
	if sim, ok := mat.Producer.(*tee.Simulated); ok {
		teePEM, err := crypto.PublicKeyPEM(sim.PublicKey())
		if err != nil {
			return err
		}
		id.TEEPublicKeyPEM = string(teePEM)
	}
	if a := cfg.Keys.AuditSigning; a.KeyID != "" && a.SeedPath != "" {
		seed, err := readExactly(a.SeedPath, crypto.Ed25519SeedSize, "keys.audit_signing.seed_path")
		if err != nil {
			return err
		}
		pub, _, err := crypto.Ed25519FromSeed(seed)
		if err != nil {
			return err
		}
		auditPEM, err := crypto.PublicKeyPEM(pub)
		if err != nil {
			return err
		}
		id.AuditKID, id.AuditPublicKeyPEM = a.KeyID, string(auditPEM)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(id)
}
