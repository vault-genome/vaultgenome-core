// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// Config is the full on-disk configuration for the acp-compute
// worker daemon. Every field is frozen for the Phase-1 investor
// demo; additions are a minor-version change and must update
// `cmd/acp-compute/doc.go`.
type Config struct {
	// Vault is where to dial sagvd and how.
	Vault VaultConfig `json:"vault"`

	// TEE configures the simulated TEE the worker presents during
	// the Return-Path handshake. In Phase 3 this section is replaced
	// by a hardware-backed backend with identical surface.
	TEE TEEConfig `json:"tee"`

	// Keys points at the on-disk material the worker uses to sign
	// CandidateOutputFrame and to unseal SealedMaterial.
	Keys KeysConfig `json:"keys"`

	// Runtime tunables for the dial/serve loop.
	Runtime RuntimeConfig `json:"runtime"`

	// Health controls the local HTTP server that exposes /healthz,
	// /readyz and /metrics. Empty ListenAddress disables the server
	// (useful in tests).
	Health HealthConfig `json:"health"`

	// Log controls structured-logging format and verbosity.
	Log LogConfig `json:"log"`
}

// VaultConfig aggregates how the worker reaches sagvd.
type VaultConfig struct {
	// Address is the host:port the worker dials (outbound only).
	Address string `json:"address"`

	// TLS configures mutual TLS. When Enabled=false the worker dials
	// plain TCP — permitted only for loopback / demo use.
	TLS TLSConfig `json:"tls"`
}

// TLSConfig holds client-side mTLS material. All file paths are
// resolved relative to the process working directory.
type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	CABundle   string `json:"ca_bundle"`
	ServerName string `json:"server_name"`
}

// TEEConfig holds the local simulated TEE seed plus the peer's
// expected public key and measurement.
type TEEConfig struct {
	// WorkloadDescriptor is hashed to derive the local measurement.
	// Must match what the operator provisioned on the vault side
	// (otherwise the vault's Verifier will reject this worker's
	// evidence).
	WorkloadDescriptor string `json:"workload_descriptor"`

	// SeedPath is a 32-byte file holding the Ed25519 seed used to
	// derive this worker's attestation key. Sensitive — chmod 0600.
	SeedPath string `json:"seed_path"`

	// Peer holds the trust-anchor material for sagvd's side.
	Peer PeerTEEConfig `json:"peer"`
}

// PeerTEEConfig pins the vault-side TEE the worker will accept.
type PeerTEEConfig struct {
	// PublicKeyPath is a 32-byte raw Ed25519 public key.
	PublicKeyPath string `json:"public_key_path"`

	// MeasurementPath is a 32-byte raw SHA-256 measurement.
	MeasurementPath string `json:"measurement_path"`
}

// KeysConfig bundles the two key-material slots the worker uses.
type KeysConfig struct {
	// WorkerSigning is the Ed25519 key the worker uses to sign each
	// CandidateOutputFrame. The public half MUST be registered with
	// sagvd's PublicKeyResolver out-of-band (operator config in
	// Phase 1; attestation-bound in Phase 3).
	WorkerSigning SigningKeyConfig `json:"worker_signing"`

	// SessionSealing is the AES-256 key pre-shared between sagvd and
	// this worker, used to unseal SealedMaterial carried inside
	// JobRequest.
	SessionSealing SealingKeyConfig `json:"session_sealing"`
}

// SigningKeyConfig points at a 32-byte Ed25519 seed file.
type SigningKeyConfig struct {
	KeyID    string `json:"kid"`
	SeedPath string `json:"seed_path"`
}

// SealingKeyConfig points at a 32-byte AES-256 key-material file.
type SealingKeyConfig struct {
	KeyID        string `json:"kid"`
	MaterialPath string `json:"material_path"`
}

// RuntimeConfig bounds the dial and serve loop timings.
type RuntimeConfig struct {
	JobTimeoutSeconds       int `json:"job_timeout_seconds"`
	HandshakeTimeoutSeconds int `json:"handshake_timeout_seconds"`
	DialBackoffInitialMs    int `json:"dial_backoff_initial_ms"`
	DialBackoffMaxMs        int `json:"dial_backoff_max_ms"`
	// IdleBetweenJobsMs is a brief pause after a successful job
	// before the next dial attempt, bounding reconnect churn.
	IdleBetweenJobsMs int `json:"idle_between_jobs_ms"`
}

// JobTimeout returns RuntimeConfig.JobTimeoutSeconds as a Duration.
func (r RuntimeConfig) JobTimeout() time.Duration {
	return time.Duration(r.JobTimeoutSeconds) * time.Second
}

// HandshakeTimeout returns RuntimeConfig.HandshakeTimeoutSeconds as
// a Duration.
func (r RuntimeConfig) HandshakeTimeout() time.Duration {
	return time.Duration(r.HandshakeTimeoutSeconds) * time.Second
}

// DialBackoffInitial returns the initial backoff as a Duration.
func (r RuntimeConfig) DialBackoffInitial() time.Duration {
	return time.Duration(r.DialBackoffInitialMs) * time.Millisecond
}

// DialBackoffMax returns the cap on backoff as a Duration.
func (r RuntimeConfig) DialBackoffMax() time.Duration {
	return time.Duration(r.DialBackoffMaxMs) * time.Millisecond
}

// IdleBetweenJobs returns the post-success pause as a Duration.
func (r RuntimeConfig) IdleBetweenJobs() time.Duration {
	return time.Duration(r.IdleBetweenJobsMs) * time.Millisecond
}

// HealthConfig controls the local /healthz /readyz /metrics server.
type HealthConfig struct {
	ListenAddress string `json:"listen_address"`
}

// LogConfig picks log verbosity and format.
type LogConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// DefaultConfig returns a Config populated with sensible defaults.
// Callers typically decode a JSON file over this so that operators
// only need to specify fields they want to override.
func DefaultConfig() Config {
	return Config{
		Vault: VaultConfig{
			Address: "127.0.0.1:9443",
			TLS: TLSConfig{
				Enabled: false,
			},
		},
		TEE: TEEConfig{
			WorkloadDescriptor: "acp-compute-worker-v1",
		},
		Runtime: RuntimeConfig{
			JobTimeoutSeconds:       120,
			HandshakeTimeoutSeconds: 10,
			DialBackoffInitialMs:    500,
			DialBackoffMaxMs:        30000,
			IdleBetweenJobsMs:       100,
		},
		Health: HealthConfig{
			ListenAddress: "127.0.0.1:9091",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// LoadConfigFile reads and decodes a JSON configuration file on top
// of DefaultConfig(). Unknown JSON fields are rejected to catch
// typos in operator config during provisioning.
func LoadConfigFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("acp-compute: open config %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return DecodeConfig(f)
}

// DecodeConfig decodes JSON from r into a Config, applied on top of
// DefaultConfig. Rejects unknown fields.
func DecodeConfig(r io.Reader) (Config, error) {
	c := DefaultConfig()
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("acp-compute: decode config: %w", err)
	}
	return c, nil
}

// Validate performs structural checks that do not require filesystem
// access. Returns a joined error listing every problem so operators
// see the full punch-list in one run.
func (c Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.Vault.Address) == "" {
		errs = append(errs, errors.New("vault.address required"))
	} else if _, _, err := net.SplitHostPort(c.Vault.Address); err != nil {
		errs = append(errs, fmt.Errorf("vault.address invalid: %w", err))
	}

	if c.Vault.TLS.Enabled {
		if c.Vault.TLS.ClientCert == "" {
			errs = append(errs, errors.New("vault.tls.client_cert required when TLS enabled"))
		}
		if c.Vault.TLS.ClientKey == "" {
			errs = append(errs, errors.New("vault.tls.client_key required when TLS enabled"))
		}
		if c.Vault.TLS.CABundle == "" {
			errs = append(errs, errors.New("vault.tls.ca_bundle required when TLS enabled"))
		}
		if c.Vault.TLS.ServerName == "" {
			errs = append(errs, errors.New("vault.tls.server_name required when TLS enabled"))
		}
	}

	if strings.TrimSpace(c.TEE.WorkloadDescriptor) == "" {
		errs = append(errs, errors.New("tee.workload_descriptor required"))
	}
	if c.TEE.SeedPath == "" {
		errs = append(errs, errors.New("tee.seed_path required"))
	}
	if c.TEE.Peer.PublicKeyPath == "" {
		errs = append(errs, errors.New("tee.peer.public_key_path required"))
	}
	if c.TEE.Peer.MeasurementPath == "" {
		errs = append(errs, errors.New("tee.peer.measurement_path required"))
	}

	if c.Keys.WorkerSigning.KeyID == "" {
		errs = append(errs, errors.New("keys.worker_signing.kid required"))
	}
	if c.Keys.WorkerSigning.SeedPath == "" {
		errs = append(errs, errors.New("keys.worker_signing.seed_path required"))
	}
	if c.Keys.SessionSealing.KeyID == "" {
		errs = append(errs, errors.New("keys.session_sealing.kid required"))
	}
	if c.Keys.SessionSealing.MaterialPath == "" {
		errs = append(errs, errors.New("keys.session_sealing.material_path required"))
	}

	if c.Runtime.JobTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.job_timeout_seconds must be > 0"))
	}
	if c.Runtime.HandshakeTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.handshake_timeout_seconds must be > 0"))
	}
	if c.Runtime.DialBackoffInitialMs <= 0 {
		errs = append(errs, errors.New("runtime.dial_backoff_initial_ms must be > 0"))
	}
	if c.Runtime.DialBackoffMaxMs < c.Runtime.DialBackoffInitialMs {
		errs = append(errs, errors.New("runtime.dial_backoff_max_ms must be >= dial_backoff_initial_ms"))
	}
	if c.Runtime.IdleBetweenJobsMs < 0 {
		errs = append(errs, errors.New("runtime.idle_between_jobs_ms must be >= 0"))
	}

	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level %q invalid (want debug|info|warn|error)", c.Log.Level))
	}
	switch strings.ToLower(c.Log.Format) {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("log.format %q invalid (want json|text)", c.Log.Format))
	}

	return errors.Join(errs...)
}
