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

// Config is the on-disk JSON configuration for acp-bootstrap.
//
// Operators construct one config file per destination deployment.
// Defaults exist for almost every field — only the security-critical
// material paths must be specified.
type Config struct {
	// HTTP controls the cross-cloud listener (handshake + token
	// endpoints). At least ListenAddress is required.
	HTTP HTTPConfig `json:"http"`

	// TEE configures the destination's local TEE producer. The
	// MVP/demo build uses tee.ProviderSimulated with a configured
	// seed file; production builds will swap to a hardware Provider
	// without changing this section.
	TEE TEEConfig `json:"tee"`

	// SourceAuthority points at the source authority's signing
	// public key. Loaded once at startup; the receiver verifies
	// every incoming handshake + token signature against it.
	SourceAuthority SourceAuthorityConfig `json:"source_authority"`

	// Health controls the local /healthz /readyz /metrics listener.
	// Empty disables the health listener.
	Health HealthConfig `json:"health,omitempty"`

	// Log controls structured-logging format and verbosity.
	Log LogConfig `json:"log"`
}

// HTTPConfig controls the destination's HTTP listener.
type HTTPConfig struct {
	// ListenAddress is the host:port the daemon binds to accept
	// /v1/crosscloud/handshake and /v1/crosscloud/token requests.
	ListenAddress string `json:"listen_address"`

	// BearerToken, if non-empty, is enforced on every incoming
	// request via constant-time compare. Defence-in-depth alongside
	// cryptographic signatures.
	BearerToken string `json:"bearer_token,omitempty"`

	// TLS configures the inbound mTLS material. When Enabled is
	// false the listener is plain HTTP — permitted only for
	// loopback / trusted-LAN demo. Production deployments MUST
	// enable TLS.
	TLS TLSServerConfig `json:"tls,omitempty"`

	// ReadHeaderTimeoutSeconds bounds HTTP request header reads
	// (slow-loris defense). Defaults to 5s.
	ReadHeaderTimeoutSeconds int `json:"read_header_timeout_seconds,omitempty"`

	// WriteTimeoutSeconds bounds full response write duration.
	// Defaults to 30s.
	WriteTimeoutSeconds int `json:"write_timeout_seconds,omitempty"`
}

// TLSServerConfig holds the inbound mTLS material for the HTTP
// listener.
type TLSServerConfig struct {
	Enabled    bool   `json:"enabled"`
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
	ClientCAs  string `json:"client_cas"`
}

// TEEConfig holds the destination's local TEE producer
// configuration.
type TEEConfig struct {
	// Provider names the TEE backend (one of the tee.Provider
	// constants). MVP/demo: "simulated".
	Provider string `json:"provider"`

	// WorkloadDescriptor is hashed into the local measurement for
	// the simulated backend. For real backends, this is
	// informational; the measurement comes from the chip.
	WorkloadDescriptor string `json:"workload_descriptor"`

	// SeedPath is a 32-byte file holding the Ed25519 seed used to
	// derive this destination's attestation key. Required for the
	// simulated backend. Sensitive — chmod 0600.
	SeedPath string `json:"seed_path"`
}

// SourceAuthorityConfig points at the source-authority signing
// public key file. Used by the receiver to verify every handshake +
// token signature.
type SourceAuthorityConfig struct {
	// KeyID is the kid the source authority uses when signing.
	// Embedded in every CrossCloudHandshakeRequest and
	// KeyReleaseToken; the receiver looks up the pubkey by this
	// kid.
	KeyID string `json:"kid"`

	// PublicKeyPath holds the source authority's Ed25519 public key.
	// Accepts either:
	//   * a raw 32-byte file, or
	//   * a PEM-encoded SubjectPublicKeyInfo.
	// The format is auto-detected from the leading bytes.
	PublicKeyPath string `json:"public_key_path"`
}

// HealthConfig controls /healthz /readyz /metrics.
type HealthConfig struct {
	ListenAddress string `json:"listen_address"`
}

// LogConfig picks log verbosity and format.
type LogConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// ReadHeaderTimeout returns HTTPConfig.ReadHeaderTimeoutSeconds as a
// Duration with a 5s default.
func (h HTTPConfig) ReadHeaderTimeout() time.Duration {
	if h.ReadHeaderTimeoutSeconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(h.ReadHeaderTimeoutSeconds) * time.Second
}

// WriteTimeout returns HTTPConfig.WriteTimeoutSeconds as a Duration
// with a 30s default.
func (h HTTPConfig) WriteTimeout() time.Duration {
	if h.WriteTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(h.WriteTimeoutSeconds) * time.Second
}

// DefaultConfig returns sensible defaults that operators can
// override field-by-field via JSON.
func DefaultConfig() Config {
	return Config{
		HTTP: HTTPConfig{
			ListenAddress: "127.0.0.1:8443",
		},
		TEE: TEEConfig{
			Provider:           "simulated",
			WorkloadDescriptor: "acp-bootstrap-destination-v1",
		},
		Health: HealthConfig{
			ListenAddress: "127.0.0.1:8444",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// LoadConfigFile reads and decodes a JSON file on top of
// DefaultConfig(). Unknown fields are rejected to catch operator
// typos at startup.
func LoadConfigFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("acp-bootstrap: open config %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return DecodeConfig(f)
}

// DecodeConfig decodes JSON from r into a Config on top of
// DefaultConfig.
func DecodeConfig(r io.Reader) (Config, error) {
	c := DefaultConfig()
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("acp-bootstrap: decode config: %w", err)
	}
	return c, nil
}

// Validate enforces structural checks. Returns a joined error so
// operators see the full punch-list per run.
func (c Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.HTTP.ListenAddress) == "" {
		errs = append(errs, errors.New("http.listen_address required"))
	} else if _, _, err := net.SplitHostPort(c.HTTP.ListenAddress); err != nil {
		errs = append(errs, fmt.Errorf("http.listen_address invalid: %w", err))
	}

	if c.HTTP.TLS.Enabled {
		if c.HTTP.TLS.ServerCert == "" {
			errs = append(errs, errors.New("http.tls.server_cert required when http.tls.enabled=true"))
		}
		if c.HTTP.TLS.ServerKey == "" {
			errs = append(errs, errors.New("http.tls.server_key required when http.tls.enabled=true"))
		}
		// client_cas is optional — operators may want server-auth-only
		// for early demos and add mTLS client cert pinning later.
	}

	if strings.TrimSpace(c.TEE.Provider) == "" {
		errs = append(errs, errors.New("tee.provider required"))
	}
	if strings.TrimSpace(c.TEE.WorkloadDescriptor) == "" {
		errs = append(errs, errors.New("tee.workload_descriptor required"))
	}
	if c.TEE.Provider == "simulated" && c.TEE.SeedPath == "" {
		errs = append(errs, errors.New("tee.seed_path required when tee.provider=simulated"))
	}

	if c.SourceAuthority.KeyID == "" {
		errs = append(errs, errors.New("source_authority.kid required"))
	}
	if c.SourceAuthority.PublicKeyPath == "" {
		errs = append(errs, errors.New("source_authority.public_key_path required"))
	}

	if c.Health.ListenAddress != "" {
		if _, _, err := net.SplitHostPort(c.Health.ListenAddress); err != nil {
			errs = append(errs, fmt.Errorf("health.listen_address invalid: %w", err))
		}
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
