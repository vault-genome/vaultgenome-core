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

// workerIdentity is what sagvd pins for this worker: the key it signs
// every CandidateOutputFrame with (workers.registry_path), and the TEE
// identity its Return Path Evidence must carry (tee.peer).
type workerIdentity struct {
	SigningKID          string `json:"signing_kid"`
	SigningPublicKeyHex string `json:"signing_public_key_hex"`
	SigningPublicKeyPEM string `json:"signing_public_key_pem"`
	// TEEProvider names what attests for this worker: gcp-sev-snp (the
	// measurement is the chip's launch measurement, 48 bytes) or
	// simulated (the key below signs).
	TEEProvider       string `json:"tee_provider"`
	TEEMeasurementHex string `json:"tee_measurement_hex"`
	TEEPublicKeyPEM   string `json:"tee_public_key_pem,omitempty"`
}

// runIdentityCmd implements `acp-compute identity -config <path>`: it
// loads the configured key material and prints the public half as JSON,
// without dialling anything.
func runIdentityCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("acp-compute identity", flag.ContinueOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to acp-compute JSON config (required)")
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

	signPEM, err := crypto.PublicKeyPEM(mat.SigningPublicKey)
	if err != nil {
		return err
	}
	id := workerIdentity{
		SigningKID:          string(mat.SigningKeyID),
		SigningPublicKeyHex: hex.EncodeToString(mat.SigningPublicKey),
		SigningPublicKeyPEM: string(signPEM),
		TEEProvider:         string(mat.Provider),
		TEEMeasurementHex:   hex.EncodeToString(mat.Producer.Measurement()),
	}
	if sim, ok := mat.Producer.(*tee.Simulated); ok {
		teePEM, err := crypto.PublicKeyPEM(sim.PublicKey())
		if err != nil {
			return err
		}
		id.TEEPublicKeyPEM = string(teePEM)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(id)
}
