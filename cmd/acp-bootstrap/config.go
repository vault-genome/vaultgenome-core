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

	"github.com/ai-continuity-platform/core/internal/shared/exposure"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
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

	// TEE configures the destination's local TEE producer. This build
	// runs tee.ProviderSimulated with a configured seed file; the
	// hardware producers slot into the same section.
	TEE TEEConfig `json:"tee"`

	// SourceAuthority points at the source authority's signing
	// public key. Loaded once at startup; the receiver verifies
	// every incoming handshake + token signature against it.
	SourceAuthority SourceAuthorityConfig `json:"source_authority"`

	// Health controls the /healthz and /readyz listener. Empty
	// disables it. It answers liveness only and exposes nothing else.
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
	// the source authority's signatures on every payload. On a
	// non-loopback listener without mTLS it is required and must be at
	// least exposure.MinBearerTokenLen characters.
	BearerToken string `json:"bearer_token,omitempty"`

	// BearerTokenFile is the path to a file holding the bearer token
	// (surrounding whitespace is trimmed). Prefer it over BearerToken
	// so the secret lives with the other key material rather than in
	// the config file. Mutually exclusive with BearerToken; resolved at
	// startup by ResolveSecrets().
	BearerTokenFile string `json:"bearer_token_file,omitempty"`

	// TLS configures the inbound TLS / mTLS material. Plain HTTP is
	// accepted only on a loopback listen address; Validate() refuses a
	// non-loopback listener without TLS.
	TLS TLSServerConfig `json:"tls,omitempty"`

	// ReadHeaderTimeoutSeconds bounds HTTP request header reads
	// (slow-loris defense). Defaults to 5s.
	ReadHeaderTimeoutSeconds int `json:"read_header_timeout_seconds,omitempty"`

	// WriteTimeoutSeconds bounds full response write duration.
	// Defaults to 30s.
	WriteTimeoutSeconds int `json:"write_timeout_seconds,omitempty"`
}

// TLSServerConfig holds the inbound TLS material for the HTTP
// listener. The listener speaks TLS 1.3 only. ClientCAs, when set,
// makes it require and verify a client certificate (mTLS).
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
	// constants). This build can run "simulated" only; the hardware
	// producers are wired in with the Continuity Drill (Phase 1). The
	// provider is also the destination_tee_kind every handshake must
	// declare.
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

// HealthConfig controls /healthz and /readyz.
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

// ResolveSecrets loads secret values that the config references by
// path rather than inline — today the bearer token
// (http.bearer_token_file). Call it after Validate().
func (c *Config) ResolveSecrets() error {
	if c.HTTP.BearerTokenFile == "" {
		return nil
	}
	token, err := exposure.ReadTokenFile(c.HTTP.BearerTokenFile)
	if err != nil {
		return fmt.Errorf("acp-bootstrap: http.bearer_token_file: %w", err)
	}
	if !exposure.IsLoopback(c.HTTP.ListenAddress) && len(token) < exposure.MinBearerTokenLen {
		return fmt.Errorf("acp-bootstrap: token in %q too short for non-loopback listen_address %q (need >= %d characters)",
			c.HTTP.BearerTokenFile, c.HTTP.ListenAddress, exposure.MinBearerTokenLen)
	}
	c.HTTP.BearerToken = token
	return nil
}

// Validate enforces structural checks. Returns a joined error so
// operators see the full punch-list per run.
//
// Network exposure fails closed: plain HTTP and unauthenticated
// callers are accepted only on a loopback listen address. Beyond it
// the listener must speak TLS, and callers must present either a
// client certificate (http.tls.client_cas) or a bearer token of at
// least exposure.MinBearerTokenLen characters.
func (c Config) Validate() error {
	var errs []error

	listenOK := false
	if strings.TrimSpace(c.HTTP.ListenAddress) == "" {
		errs = append(errs, errors.New("http.listen_address required"))
	} else if _, _, err := net.SplitHostPort(c.HTTP.ListenAddress); err != nil {
		errs = append(errs, fmt.Errorf("http.listen_address invalid: %w", err))
	} else {
		listenOK = true
	}

	if c.HTTP.TLS.Enabled {
		if c.HTTP.TLS.ServerCert == "" {
			errs = append(errs, errors.New("http.tls.server_cert required when http.tls.enabled=true"))
		}
		if c.HTTP.TLS.ServerKey == "" {
			errs = append(errs, errors.New("http.tls.server_key required when http.tls.enabled=true"))
		}
	} else if c.HTTP.TLS.ClientCAs != "" {
		errs = append(errs, errors.New("http.tls.client_cas set but http.tls.enabled=false"))
	}
	if c.HTTP.BearerToken != "" && c.HTTP.BearerTokenFile != "" {
		errs = append(errs, errors.New("http: set only one of bearer_token and bearer_token_file"))
	}
	if listenOK && !exposure.IsLoopback(c.HTTP.ListenAddress) {
		if !c.HTTP.TLS.Enabled {
			errs = append(errs, fmt.Errorf(
				"http.tls.enabled required: listen_address %q is not loopback (key-release traffic across a network must be encrypted)",
				c.HTTP.ListenAddress))
		}
		hasToken := c.HTTP.BearerToken != "" || c.HTTP.BearerTokenFile != ""
		if c.HTTP.TLS.ClientCAs == "" && !hasToken {
			errs = append(errs, fmt.Errorf(
				"http.tls.client_cas or http.bearer_token(_file) required: listen_address %q is not loopback",
				c.HTTP.ListenAddress))
		}
		if c.HTTP.BearerToken != "" && len(c.HTTP.BearerToken) < exposure.MinBearerTokenLen {
			errs = append(errs, fmt.Errorf(
				"http.bearer_token too short for non-loopback listen_address %q (need >= %d characters)",
				c.HTTP.ListenAddress, exposure.MinBearerTokenLen))
		}
	}

	if strings.TrimSpace(c.TEE.Provider) == "" {
		errs = append(errs, errors.New("tee.provider required"))
	} else if _, err := tee.ParseProvider(c.TEE.Provider); err != nil {
		errs = append(errs, fmt.Errorf("tee.provider invalid: %w", err))
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
