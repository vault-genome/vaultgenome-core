// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
)

// sealKeysOutput is what `sagvd seal-keys` prints.
type sealKeysOutput struct {
	TEE            string           `json:"tee"`
	MeasurementHex string           `json:"measurement_hex"`
	Sealed         []sealedKeyEntry `json:"sealed"`
	AlreadySealed  []sealedKeyEntry `json:"already_sealed,omitempty"`
}

type sealedKeyEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// keyFiles are the daemon's key files that seal-keys seals and the daemon
// opens: name (the config field), path, and the bare length.
func keyFiles(cfg Config) []struct {
	name string
	path string
	n    int
} {
	files := []struct {
		name string
		path string
		n    int
	}{
		{"keys.authority_signing.seed_path", cfg.Keys.AuthoritySigning.SeedPath, crypto.Ed25519SeedSize},
		{"keys.session_sealing.material_path", cfg.Keys.SessionSealing.MaterialPath, crypto.AES256KeySize},
	}
	if cfg.Keys.AuditSigning.SeedPath != "" {
		files = append(files, struct {
			name string
			path string
			n    int
		}{"keys.audit_signing.seed_path", cfg.Keys.AuditSigning.SeedPath, crypto.Ed25519SeedSize})
	}
	return files
}

// runSealKeysCmd implements `sagvd seal-keys -config <path>`: every key
// file the config names — the authority's signing seed, the session
// sealing key, the audit seed — is read once as bare bytes, sealed to this
// host's TEE under its own name (ADR 0023), and written back in place, so
// the daemon reads it through the same path and the plaintext is no longer
// on disk. A file already sealed is left as it is. The TEE's own identity
// (tee.seed_path on the simulated provider) is not a key file and is not
// touched.
func runSealKeysCmd(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sagvd seal-keys", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to sagvd JSON config (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("seal-keys: -config required")
	}
	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("seal-keys: config validation: %w", err)
	}
	mat, err := LoadMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		return err
	}
	defer func() { mat.Store.Zeroize(); _ = mat.Close() }()
	sealer, err := mat.TEESealer()
	if err != nil {
		return err
	}
	if mat.Provider == tee.ProviderSimulated {
		fmt.Fprintln(stderr, "seal-keys: SIMULATED TEE: the keys are sealed under a key derived from the simulated measurement, with no hardware behind it; development and tests only")
	}
	measurement := mat.Producer.Measurement()
	out := sealKeysOutput{TEE: string(mat.Provider), MeasurementHex: hex.EncodeToString(measurement)}
	for _, f := range keyFiles(cfg) {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			return fmt.Errorf("seal-keys: read %s (%q): %w", f.name, f.path, err)
		}
		if tee.IsSealedSecret(raw) {
			out.AlreadySealed = append(out.AlreadySealed, sealedKeyEntry{Name: f.name, Path: f.path})
			continue
		}
		if len(raw) != f.n {
			return fmt.Errorf("seal-keys: %s (%q) must be exactly %d bytes (got %d)", f.name, f.path, f.n, len(raw))
		}
		sealed, err := tee.SealSecret(raw, sealer, mat.Provider, measurement, f.name)
		for i := range raw {
			raw[i] = 0
		}
		if err != nil {
			return fmt.Errorf("seal-keys: %s: %w", f.name, err)
		}
		// The sealed file must open here before the bare one is gone.
		if _, err := tee.OpenSecret(sealed, sealer, mat.Provider, f.name); err != nil {
			return fmt.Errorf("seal-keys: %s: the sealed key does not open on this host: %w", f.name, err)
		}
		if err := replaceFile(f.path, sealed); err != nil {
			return fmt.Errorf("seal-keys: write %s (%q): %w", f.name, f.path, err)
		}
		out.Sealed = append(out.Sealed, sealedKeyEntry{Name: f.name, Path: f.path})
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// replaceFile writes data over path atomically, mode 0600.
func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".seal-keys-*")
	if err != nil {
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
