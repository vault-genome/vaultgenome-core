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
)

// Config is the full on-disk configuration for the sagvd authority
// daemon. Every field is frozen for the Phase-1 investor demo;
// additions are a minor-version change and must update
// `cmd/sagvd/doc.go`.
type Config struct {
	// Vault controls the Return Path TCP listener (where acp-compute
	// workers dial in).
	Vault VaultConfig `json:"vault"`

	// HTTPAPI controls the operator REST API listener (POST /v1/jobs,
	// GET /v1/jobs/{id}).
	HTTPAPI HTTPAPIConfig `json:"http_api"`

	// TEE configures the simulated TEE the vault presents during the
	// Return Path handshake. In Phase 3 this section is replaced by a
	// hardware-backed backend with identical surface.
	TEE TEEConfig `json:"tee"`

	// Keys points at the on-disk material the vault uses to sign
	// authority artifacts and to seal SealedMaterial for JobRequest.
	Keys KeysConfig `json:"keys"`

	// Workers points at the static JSON registry of known worker
	// signing public keys. See workers.go.
	Workers WorkersConfig `json:"workers"`

	// Runtime tunables for the accept / dispatch loop and HTTP timeouts.
	Runtime RuntimeConfig `json:"runtime"`

	// Health controls the local HTTP server that exposes /healthz,
	// /readyz and /metrics. Empty ListenAddress disables the server
	// (useful in tests).
	Health HealthConfig `json:"health"`

	// Log controls structured-logging format and verbosity.
	Log LogConfig `json:"log"`

	// CrossCloud configures cross-cloud key release, run by the
	// `sagvd crosscloud-restore` subcommand (the daemon itself serves
	// no cross-cloud requests). When CrossCloud.Enabled is false (the
	// default) every other field in this section is ignored.
	//
	// See ADR 0006, ADR 0009 and docs/operator/06_cross_cloud_restore.md.
	CrossCloud CrossCloudConfig `json:"crosscloud,omitempty"`
}

// VaultConfig aggregates how sagvd accepts Return Path connections.
type VaultConfig struct {
	// ListenAddress is the host:port the vault binds for Return Path
	// inbound sessions. Workers dial this address.
	ListenAddress string `json:"listen_address"`

	// TLS configures mutual TLS for the Return Path listener. When
	// Enabled=false the listener is plain TCP. Validate() refuses a
	// plain-TCP listener on any non-loopback address: workers across a
	// network must authenticate with mTLS.
	TLS TLSConfig `json:"tls"`
}

// HTTPAPIConfig controls the operator REST API.
type HTTPAPIConfig struct {
	// ListenAddress is the host:port the REST API binds. An empty
	// value disables the REST API (tests and loopback-only demos
	// can dispatch jobs in-process through the JobQueue).
	ListenAddress string `json:"listen_address"`

	// BearerToken, if non-empty, is compared (constant-time) against
	// the client-supplied "Authorization: Bearer <token>" header on
	// every endpoint. An unauthenticated REST API is only accepted on a
	// loopback bind; Validate() refuses a non-loopback bind without a
	// token, and requires at least MinNonLoopbackTokenLen characters.
	BearerToken string `json:"bearer_token,omitempty"`

	// BearerTokenFile is the path to a file holding the bearer token
	// (surrounding whitespace is trimmed). Prefer it over BearerToken
	// so the secret lives with the other key material rather than in
	// the config file. Mutually exclusive with BearerToken; resolved at
	// startup by ResolveSecrets().
	BearerTokenFile string `json:"bearer_token_file,omitempty"`
}

// MinNonLoopbackTokenLen is the minimum bearer-token length accepted
// for a REST API reachable beyond the local host.
const MinNonLoopbackTokenLen = exposure.MinBearerTokenLen

// TLSConfig holds server-side mTLS material. All file paths are
// resolved relative to the process working directory.
type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
	ClientCAs  string `json:"client_cas"`
}

// TEEConfig holds the local simulated TEE seed plus the peer's
// (worker's) expected public key and measurement.
type TEEConfig struct {
	// WorkloadDescriptor is hashed to derive the local measurement.
	// Workers' Verifiers pin this through their operator config.
	WorkloadDescriptor string `json:"workload_descriptor"`

	// SeedPath is a 32-byte file holding the Ed25519 seed used to
	// derive this vault's attestation key. Sensitive — chmod 0600.
	SeedPath string `json:"seed_path"`

	// Peer holds the trust-anchor material for the worker's TEE
	// side: pubkey + measurement. In Phase 1 the vault accepts
	// exactly one expected worker measurement; Phase 2 extends to a
	// policy set pulling from Workers.RegistryPath.
	Peer PeerTEEConfig `json:"peer"`

	// InsecureSimulation must be true: this build's vault attests with
	// the simulated TEE only — Evidence signed by a key read from
	// SeedPath, no hardware isolation. The flag puts that in the config
	// itself; the release-side cross-cloud path does not depend on it.
	InsecureSimulation bool `json:"insecure_simulation"`
}

// PeerTEEConfig pins the worker-side TEE the vault will accept.
type PeerTEEConfig struct {
	// PublicKeyPath is a 32-byte raw Ed25519 public key.
	PublicKeyPath string `json:"public_key_path"`

	// MeasurementPath is a 32-byte raw SHA-256 measurement.
	MeasurementPath string `json:"measurement_path"`
}

// KeysConfig bundles the key-material slots sagvd uses.
type KeysConfig struct {
	// AuthoritySigning is the Ed25519 key sagvd uses to sign
	// authority artifacts (ReconstructionJobManifest signatures,
	// ReleaseDecision, AttestationResult). Phase 1 uses it only for
	// provisioning parity with Phase 3; the investor demo does not
	// exercise authority signing on the hot path.
	AuthoritySigning SigningKeyConfig `json:"authority_signing"`

	// SessionSealing is the AES-256 key pre-shared between sagvd and
	// acp-compute. sagvd uses it to Seal SealedMaterial into
	// JobRequest; the worker uses it to Open the SealedMaterialRef
	// and extract the plaintext it will operate on.
	SessionSealing SealingKeyConfig `json:"session_sealing"`

	// AuditSigning is the Ed25519 key that signs the cross-cloud audit
	// log (keys.PurposeSigningAudit). It must stay the same across runs:
	// the log is one hash-linked chain, verified end to end whenever it
	// is opened. Required when crosscloud.enabled=true; its public half
	// (`sagvd identity`) is what auditors verify the log with.
	AuditSigning SigningKeyConfig `json:"audit_signing,omitempty"`
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

// WorkersConfig points at the JSON registry of known worker signing
// public keys. See workers.go for the file schema.
type WorkersConfig struct {
	// RegistryPath is a JSON file listing {kid, signing_pubkey_hex}
	// for every worker this vault will accept a CandidateOutputFrame
	// from. Out-of-band provisioning in Phase 1; attestation-bound
	// in Phase 3.
	RegistryPath string `json:"registry_path"`
}

// RuntimeConfig bounds the accept / dispatch / HTTP timings.
type RuntimeConfig struct {
	// JobTimeoutSeconds caps the total wall-clock duration for a
	// single Return Path session from accept() to close. Guards
	// against a slow or wedged worker holding the dispatcher.
	JobTimeoutSeconds int `json:"job_timeout_seconds"`

	// HandshakeTimeoutSeconds caps the 4-frame handshake phase.
	HandshakeTimeoutSeconds int `json:"handshake_timeout_seconds"`

	// QueuePollMs is how long the dispatcher blocks waiting for the
	// next queued job before re-checking shutdown. Trades demo
	// responsiveness against idle CPU.
	QueuePollMs int `json:"queue_poll_ms"`

	// HTTPReadHeaderTimeoutSeconds bounds HTTP request header read
	// time (guards against slow-loris on the operator REST API).
	HTTPReadHeaderTimeoutSeconds int `json:"http_read_header_timeout_seconds"`

	// HTTPWriteTimeoutSeconds bounds the full response write
	// duration.
	HTTPWriteTimeoutSeconds int `json:"http_write_timeout_seconds"`

	// DefaultJobDeadlineSeconds is the default value when a POST
	// /v1/jobs body omits deadline_seconds_from_now. Also the
	// ceiling: submissions asking for longer are Structurally
	// rejected with 400.
	DefaultJobDeadlineSeconds int `json:"default_job_deadline_seconds"`

	// MaxPayloadBytes caps base64-decoded POST /v1/jobs payload
	// size. Prevents a single client from exhausting vault memory.
	MaxPayloadBytes uint64 `json:"max_payload_bytes"`
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

// QueuePoll returns RuntimeConfig.QueuePollMs as a Duration.
func (r RuntimeConfig) QueuePoll() time.Duration {
	return time.Duration(r.QueuePollMs) * time.Millisecond
}

// HTTPReadHeaderTimeout returns the HTTP read-header bound.
func (r RuntimeConfig) HTTPReadHeaderTimeout() time.Duration {
	return time.Duration(r.HTTPReadHeaderTimeoutSeconds) * time.Second
}

// HTTPWriteTimeout returns the HTTP write bound.
func (r RuntimeConfig) HTTPWriteTimeout() time.Duration {
	return time.Duration(r.HTTPWriteTimeoutSeconds) * time.Second
}

// DefaultJobDeadline returns the default per-job deadline.
func (r RuntimeConfig) DefaultJobDeadline() time.Duration {
	return time.Duration(r.DefaultJobDeadlineSeconds) * time.Second
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

// CrossCloudConfig holds the operator-supplied configuration for the
// Phase 4 cross-cloud KMS-mediated restore capability. The whole
// block is optional (Enabled=false skips loading; Phase 1-3 daemons
// behave identically). When Enabled=true, the daemon's startup path
// loads:
//
//   - VerifierRegistryPath into a tee.Registry holding one Verifier
//     per cross-cloud destination this authority may target. Each
//     entry pins the destination's TEE family + attestor pubkey +
//     expected measurement.
//
//   - PolicyAllowListPath into a kms.AllowListPolicy. Entries are
//     (Provider, hex-encoded measurement) pairs. PolicyVersion is
//     recorded in the audit payload of every KEY_RELEASE_AUTHORIZED
//     event so historical decisions can be replayed against the
//     policy snapshot in force at the time.
//
//   - TransportTLS material into the http.Client passed to the
//     HTTPTransport. mTLS is required for production deployments;
//     the no-TLS path is permitted only for loopback/demo tests.
//
// The destination side (acp-bootstrap daemon) is configured
// independently — see cmd/acp-bootstrap/config.go.
type CrossCloudConfig struct {
	// Enabled gates the entire cross-cloud subsystem. When false,
	// every other field is ignored and the daemon behaves exactly
	// as a Phase 1-3 build.
	Enabled bool `json:"enabled"`

	// PolicyVersion is the operator-supplied identifier for the
	// current allow-list snapshot, recorded verbatim in audit
	// payloads. Bump it when the allow-list changes so auditors can
	// correlate decisions to policy state. Required when Enabled.
	PolicyVersion string `json:"policy_version,omitempty"`

	// PolicyAllowListPath is the JSON file describing the
	// (Provider, Measurement) pairs the policy authorises.
	// File schema:
	//
	//   {
	//     "version": "xcc-2026-05-09",
	//     "allowed": {
	//       "aws-nitro":  ["<64-hex>", "<64-hex>"],
	//       "azure-sgx":  ["<64-hex>"],
	//       "gcp-sev-snp": []
	//     }
	//   }
	//
	// Required when Enabled.
	PolicyAllowListPath string `json:"policy_allow_list_path,omitempty"`

	// VerifierRegistryPath is the JSON file describing the verifiers
	// to instantiate at startup, one per cross-cloud destination.
	// File schema:
	//
	//   {
	//     "verifiers": [
	//       {
	//         "provider": "aws-nitro",
	//         "attestor_pubkey_path": "/etc/vg/aws-pca-root.pem",
	//         "expected_measurement_hex": "<64-hex>"
	//       },
	//       {
	//         "provider": "azure-sgx",
	//         "attestor_pubkey_path": "/etc/vg/azure-sgx-pubkey.pem",
	//         "expected_measurement_hex": "<64-hex>"
	//       }
	//     ]
	//   }
	//
	// Required when Enabled.
	VerifierRegistryPath string `json:"verifier_registry_path,omitempty"`

	// TransportBearerToken, if non-empty, is sent as
	// "Authorization: Bearer <token>" on every outbound handshake +
	// token request. Defence-in-depth alongside cryptographic
	// signatures; pair with mTLS in production.
	TransportBearerToken string `json:"transport_bearer_token,omitempty"`

	// RequestTimeoutSeconds caps each individual handshake / token
	// round trip. Zero defers to context cancellation (no per-request
	// timeout). Defaults to 30 when Enabled and unset.
	RequestTimeoutSeconds int `json:"request_timeout_seconds,omitempty"`

	// TransportTLS configures mTLS for the HTTPTransport's
	// http.Client. Strongly recommended for production.
	TransportTLS TLSClientConfig `json:"transport_tls,omitempty"`

	// AuditLogPath is the append-only audit log (a bbolt file) every
	// release decision is written to — handshake, attestation verified,
	// release authorised — before the step it records is taken. The log
	// is verified end to end when it is opened; a log that does not
	// verify stops all releases. Required when enabled. One
	// crosscloud-restore run holds its lock at a time.
	AuditLogPath string `json:"audit_log_path,omitempty"`

	// KeyEscrowPath is the release authority's key-escrow private key
	// (acpctl escrow keygen; 32 raw bytes, mode 0600). Sealers
	// encapsulate genome keys to its public half, which `sagvd identity`
	// prints; `crosscloud-restore -key-escrow` opens an envelope with it
	// only to release the key. Optional.
	KeyEscrowPath string `json:"key_escrow_path,omitempty"`

	// InsecureSimulatedDestinations must be true for the verifier
	// registry to hold a "simulated" entry. A simulated destination's
	// Evidence is signed by a key from a file, so releasing keys to it
	// proves the protocol and nothing about hardware; development and
	// tests only.
	InsecureSimulatedDestinations bool `json:"insecure_simulated_destinations,omitempty"`

	// OperatorStop is the operator's signed stop list (ADR 0010):
	// every release is checked against it, and without a valid one
	// nothing is released. Required when enabled.
	OperatorStop OperatorStopConfig `json:"operator_stop,omitempty"`
}

// OperatorStopConfig points at the operator's stop list and the public
// key it must verify under. The matching private key stays with the
// operator (`acpctl stop keygen`), never on this host.
type OperatorStopConfig struct {
	KeyID         string `json:"kid"`
	PublicKeyPath string `json:"public_key_path"`
	ListPath      string `json:"list_path"`
}

// TLSClientConfig holds the source-side outbound mTLS material the
// HTTPTransport uses to authenticate to destination acp-bootstrap
// servers. All file paths are resolved relative to the process
// working directory.
type TLSClientConfig struct {
	Enabled    bool   `json:"enabled"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	CABundle   string `json:"ca_bundle"`
}

// RequestTimeout returns CrossCloudConfig.RequestTimeoutSeconds as a
// Duration. Returns the documented default (30s) if unset.
func (c CrossCloudConfig) RequestTimeout() time.Duration {
	if c.RequestTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.RequestTimeoutSeconds) * time.Second
}

// DefaultConfig returns a Config populated with sensible defaults.
// Callers typically decode a JSON file over this so that operators
// only need to specify fields they want to override.
func DefaultConfig() Config {
	return Config{
		Vault: VaultConfig{
			ListenAddress: "127.0.0.1:9443",
			TLS: TLSConfig{
				Enabled: false,
			},
		},
		HTTPAPI: HTTPAPIConfig{
			ListenAddress: "127.0.0.1:9080",
		},
		TEE: TEEConfig{
			WorkloadDescriptor: "sagvd-authority-v1",
		},
		Runtime: RuntimeConfig{
			JobTimeoutSeconds:            120,
			HandshakeTimeoutSeconds:      10,
			QueuePollMs:                  250,
			HTTPReadHeaderTimeoutSeconds: 5,
			HTTPWriteTimeoutSeconds:      30,
			DefaultJobDeadlineSeconds:    60,
			MaxPayloadBytes:              4 * 1024 * 1024, // 4 MiB
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
		return Config{}, fmt.Errorf("sagvd: open config %q: %w", path, err)
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
		return Config{}, fmt.Errorf("sagvd: decode config: %w", err)
	}
	return c, nil
}

// ResolveSecrets loads secret values that the config references by
// path rather than inline. Call it after Validate(). Today that is the
// REST API bearer token (http_api.bearer_token_file): the file is read,
// surrounding whitespace trimmed, and the result must be non-empty — and
// at least MinNonLoopbackTokenLen characters when the REST API is
// reachable beyond the local host.
func (c *Config) ResolveSecrets() error {
	if c.HTTPAPI.BearerTokenFile == "" {
		return nil
	}
	token, err := exposure.ReadTokenFile(c.HTTPAPI.BearerTokenFile)
	if err != nil {
		return fmt.Errorf("sagvd: http_api.bearer_token_file: %w", err)
	}
	if c.HTTPAPI.ListenAddress != "" && !exposure.IsLoopback(c.HTTPAPI.ListenAddress) &&
		len(token) < MinNonLoopbackTokenLen {
		return fmt.Errorf("sagvd: token in %q too short for non-loopback listen_address %q (need >= %d characters)",
			c.HTTPAPI.BearerTokenFile, c.HTTPAPI.ListenAddress, MinNonLoopbackTokenLen)
	}
	c.HTTPAPI.BearerToken = token
	return nil
}

// Validate performs structural checks that do not require filesystem
// access. Returns a joined error listing every problem so operators
// see the full punch-list in one run.
func (c Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.Vault.ListenAddress) == "" {
		errs = append(errs, errors.New("vault.listen_address required"))
	} else if _, _, err := net.SplitHostPort(c.Vault.ListenAddress); err != nil {
		errs = append(errs, fmt.Errorf("vault.listen_address invalid: %w", err))
	}

	if c.Vault.TLS.Enabled {
		if c.Vault.TLS.ServerCert == "" {
			errs = append(errs, errors.New("vault.tls.server_cert required when TLS enabled"))
		}
		if c.Vault.TLS.ServerKey == "" {
			errs = append(errs, errors.New("vault.tls.server_key required when TLS enabled"))
		}
		if c.Vault.TLS.ClientCAs == "" {
			errs = append(errs, errors.New("vault.tls.client_cas required when TLS enabled"))
		}
	} else if _, _, err := net.SplitHostPort(c.Vault.ListenAddress); err == nil &&
		!exposure.IsLoopback(c.Vault.ListenAddress) {
		// Fail closed: a Return Path listener reachable from the
		// network must authenticate workers with mTLS.
		errs = append(errs, fmt.Errorf(
			"vault.tls.enabled required: listen_address %q is not loopback (workers across a network must use mTLS)",
			c.Vault.ListenAddress))
	}

	// http_api.listen_address is optional (empty → disabled); when
	// present it must parse as host:port.
	if c.HTTPAPI.BearerToken != "" && c.HTTPAPI.BearerTokenFile != "" {
		errs = append(errs, errors.New("http_api: set only one of bearer_token and bearer_token_file"))
	}
	if c.HTTPAPI.ListenAddress != "" {
		if _, _, err := net.SplitHostPort(c.HTTPAPI.ListenAddress); err != nil {
			errs = append(errs, fmt.Errorf("http_api.listen_address invalid: %w", err))
		} else if !exposure.IsLoopback(c.HTTPAPI.ListenAddress) {
			// Fail closed: an operator REST API reachable from the
			// network must require a bearer token.
			switch {
			case c.HTTPAPI.BearerToken == "" && c.HTTPAPI.BearerTokenFile == "":
				errs = append(errs, fmt.Errorf(
					"http_api.bearer_token or bearer_token_file required: listen_address %q is not loopback",
					c.HTTPAPI.ListenAddress))
			case c.HTTPAPI.BearerToken != "" && len(c.HTTPAPI.BearerToken) < MinNonLoopbackTokenLen:
				errs = append(errs, fmt.Errorf(
					"http_api.bearer_token too short for non-loopback listen_address %q (need >= %d characters)",
					c.HTTPAPI.ListenAddress, MinNonLoopbackTokenLen))
			}
		}
	}

	if strings.TrimSpace(c.TEE.WorkloadDescriptor) == "" {
		errs = append(errs, errors.New("tee.workload_descriptor required"))
	}
	if c.TEE.SeedPath == "" {
		errs = append(errs, errors.New("tee.seed_path required"))
	}
	if !c.TEE.InsecureSimulation {
		errs = append(errs, errors.New("tee.insecure_simulation must be true: this build's vault attests with the simulated TEE only (no hardware isolation) — set it to acknowledge that"))
	}
	if c.TEE.Peer.PublicKeyPath == "" {
		errs = append(errs, errors.New("tee.peer.public_key_path required"))
	}
	if c.TEE.Peer.MeasurementPath == "" {
		errs = append(errs, errors.New("tee.peer.measurement_path required"))
	}

	if c.Keys.AuthoritySigning.KeyID == "" {
		errs = append(errs, errors.New("keys.authority_signing.kid required"))
	}
	if c.Keys.AuthoritySigning.SeedPath == "" {
		errs = append(errs, errors.New("keys.authority_signing.seed_path required"))
	}
	if c.Keys.SessionSealing.KeyID == "" {
		errs = append(errs, errors.New("keys.session_sealing.kid required"))
	}
	if c.Keys.SessionSealing.MaterialPath == "" {
		errs = append(errs, errors.New("keys.session_sealing.material_path required"))
	}

	if c.Workers.RegistryPath == "" {
		errs = append(errs, errors.New("workers.registry_path required"))
	}

	if c.Runtime.JobTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.job_timeout_seconds must be > 0"))
	}
	if c.Runtime.HandshakeTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.handshake_timeout_seconds must be > 0"))
	}
	if c.Runtime.QueuePollMs <= 0 {
		errs = append(errs, errors.New("runtime.queue_poll_ms must be > 0"))
	}
	if c.Runtime.HTTPReadHeaderTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.http_read_header_timeout_seconds must be > 0"))
	}
	if c.Runtime.HTTPWriteTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.http_write_timeout_seconds must be > 0"))
	}
	if c.Runtime.DefaultJobDeadlineSeconds <= 0 {
		errs = append(errs, errors.New("runtime.default_job_deadline_seconds must be > 0"))
	}
	if c.Runtime.MaxPayloadBytes == 0 {
		errs = append(errs, errors.New("runtime.max_payload_bytes must be > 0"))
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

	// CrossCloud is opt-in; only validate fields when enabled.
	if c.CrossCloud.Enabled {
		if strings.TrimSpace(c.CrossCloud.PolicyVersion) == "" {
			errs = append(errs, errors.New("crosscloud.policy_version required when crosscloud.enabled=true"))
		}
		if c.CrossCloud.PolicyAllowListPath == "" {
			errs = append(errs, errors.New("crosscloud.policy_allow_list_path required when crosscloud.enabled=true"))
		}
		if c.CrossCloud.VerifierRegistryPath == "" {
			errs = append(errs, errors.New("crosscloud.verifier_registry_path required when crosscloud.enabled=true"))
		}
		if c.CrossCloud.AuditLogPath == "" {
			errs = append(errs, errors.New("crosscloud.audit_log_path required when crosscloud.enabled=true (no key is released without a durable audit record)"))
		}
		if c.Keys.AuditSigning.KeyID == "" || c.Keys.AuditSigning.SeedPath == "" {
			errs = append(errs, errors.New("keys.audit_signing.kid and seed_path required when crosscloud.enabled=true"))
		}
		if s := c.CrossCloud.OperatorStop; s.KeyID == "" || s.PublicKeyPath == "" || s.ListPath == "" {
			errs = append(errs, errors.New("crosscloud.operator_stop.kid, public_key_path and list_path required when crosscloud.enabled=true (the operator must be able to stop every release)"))
		}
		if c.CrossCloud.RequestTimeoutSeconds < 0 {
			errs = append(errs, errors.New("crosscloud.request_timeout_seconds must be >= 0 (0 = no per-request timeout)"))
		}
		if c.CrossCloud.TransportTLS.Enabled {
			if c.CrossCloud.TransportTLS.ClientCert == "" {
				errs = append(errs, errors.New("crosscloud.transport_tls.client_cert required when transport_tls.enabled=true"))
			}
			if c.CrossCloud.TransportTLS.ClientKey == "" {
				errs = append(errs, errors.New("crosscloud.transport_tls.client_key required when transport_tls.enabled=true"))
			}
			if c.CrossCloud.TransportTLS.CABundle == "" {
				errs = append(errs, errors.New("crosscloud.transport_tls.ca_bundle required when transport_tls.enabled=true"))
			}
		}
	}

	return errors.Join(errs...)
}
