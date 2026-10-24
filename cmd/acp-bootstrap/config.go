// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/exposure"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
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

	// Genome, when set, makes this destination restore the genomes
	// whose keys are released to it (ADR 0011). Omitted, the daemon only
	// receives keys.
	Genome GenomeConfig `json:"genome,omitempty"`

	// Health controls the /healthz and /readyz listener. Empty
	// disables it. It answers liveness only and exposes nothing else.
	Health HealthConfig `json:"health,omitempty"`

	// Log controls structured-logging format and verbosity.
	Log LogConfig `json:"log"`

	// Crypto is the cryptographic profile (ADR 0029): the KEM suites this
	// destination generates a handshake key under, chosen in the source's
	// order of preference from what the source offers. Omitted, the
	// general profile.
	Crypto CryptoConfig `json:"crypto,omitempty"`
}

// CryptoConfig is the deployment's cryptographic profile (ADR 0029): the
// KEM suite this daemon encapsulates under and the suites it accepts.
type CryptoConfig struct {
	// Profile is "general" (the default: X25519 written, every suite of
	// the build accepted), "fips" (P-384 written; P-384, ML-KEM-768 and
	// the MLKEM1024-P384 hybrid accepted — the primitives the Go
	// Cryptographic Module lists as approved) or "cnsa" (the
	// MLKEM1024-P384 hybrid only).
	Profile string `json:"profile,omitempty"`

	// KEMSuites narrows the profile's list to these suites, in this
	// order of preference (the first is written). Every name must be
	// one the profile accepts; a profile is never widened here.
	KEMSuites []string `json:"kem_suites,omitempty"`
}

// Policy returns the configuration as the policy the kms package applies.
func (c CryptoConfig) Policy() (kms.SuitePolicy, error) {
	return kms.NewSuitePolicyFromNames(c.Profile, c.KEMSuites)
}

// SignaturePolicy returns the profile's signature policy (ADR 0031): the
// suites this destination accepts the source authority's signatures
// under. The destination signs nothing under a suite of its own — its
// receipts are the chip's — so the profile's own pick stands.
func (c CryptoConfig) SignaturePolicy() (kms.SignaturePolicy, error) {
	return kms.NewSignaturePolicyFromNames(c.Profile, "")
}

// HTTPConfig controls the destination's HTTP listener.
type HTTPConfig struct {
	// ListenAddress is the host:port the daemon binds to accept
	// /v1/crosscloud/handshake and /v1/crosscloud/token requests.
	ListenAddress string `json:"listen_address"`

	// ListenVsockPort is the AF_VSOCK port to listen on instead of
	// ListenAddress: the only channel into a Nitro enclave, which has no
	// network interface at all (ADR 0036). The parent instance forwards
	// bytes to it and sees ciphertext. A vsock listener is exposed like a
	// non-loopback address: TLS and client authentication are required.
	ListenVsockPort uint32 `json:"listen_vsock_port,omitempty"`

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
	// Provider names the TEE backend: "auto" (the family the kernel's
	// configfs-tsm serves on this host, resolved when the file is loaded,
	// ADR 0025), "gcp-sev-snp" (AMD SEV-SNP
	// reports through the kernel's configfs-tsm, on any SEV-SNP
	// Confidential VM running Linux 6.7 or later) or "simulated" (a
	// seed-derived stand-in for development and tests). The provider is
	// also the destination_tee_kind every handshake must declare.
	Provider string `json:"provider"`

	// WorkloadDescriptor is hashed into the local measurement for
	// the simulated backend. For real backends, this is
	// informational; the measurement comes from the chip.
	WorkloadDescriptor string `json:"workload_descriptor"`

	// SeedPath is a 32-byte file holding the Ed25519 seed used to
	// derive this destination's attestation key. Simulated backend
	// only. Sensitive — chmod 0600.
	SeedPath string `json:"seed_path,omitempty"`

	// TSMReportDir overrides the configfs-tsm report directory
	// (default /sys/kernel/config/tsm/report). gcp-sev-snp only.
	TSMReportDir string `json:"tsm_report_dir,omitempty"`

	// InsecureSimulation must be true to run the simulated provider,
	// and only then: it says, in the config itself, that this
	// destination has no hardware isolation — its "Evidence" is signed
	// by a key read from a file — and is for development and tests.
	InsecureSimulation bool `json:"insecure_simulation,omitempty"`

	// Sealer is how the daemon seals its key files to this host (ADR 0025,
	// step 1b): "auto" (the TEE's own key where it has one — SEV-SNP's
	// derived key — else the host's TPM 2.0, else the simulated key),
	// "tee" (the TEE's own key only; refused on TDX and Azure, which have
	// none), "tpm2" (the host's TPM 2.0 through tpm2-tools, whatever
	// the TEE), or "both" (SEV-SNP's derived key nested inside the TPM's
	// sealed object, ADR 0037: this chip and the boot the PCR policy names).
	// Every sealed file names the sealer it was made with.
	Sealer string `json:"sealer,omitempty"`

	// AutoResolvedFrom is set by ResolveAuto when Provider was "auto": the
	// configfs-tsm provider name the family was taken from (ADR 0025).
	// Not read from the file.
	AutoResolvedFrom string `json:"-"`

	// GPUAttestCommand, TPM2ToolsDir and AKHandle configure the
	// azure-cgpu producer: the command that obtains NVIDIA's signed
	// attestation tokens for a nonce (the nonce is appended; required),
	// where tpm2-tools live (default PATH), and the vTPM handle of the
	// HCL attestation key (default: found by its public key). azure-cgpu
	// only.
	GPUAttestCommand []string `json:"gpu_attest_command,omitempty"`
	TPM2ToolsDir     string   `json:"tpm2_tools_dir,omitempty"`
	AKHandle         string   `json:"ak_handle,omitempty"`

	// SEVGuestDevice is the sev-guest device this host's sealing key is
	// derived through (`acp-bootstrap seal-keys`, ADR 0023; default
	// /dev/sev-guest). gcp-sev-snp only.
	SEVGuestDevice string `json:"sev_guest_device,omitempty"`
	// VTPMSealPCRs is the PCR selection the secret files are sealed to on
	// a gcp-tdx or azure-cgpu host (ADR 0022; default sha256:0-14, the
	// boot the operator pins). Those providers only.
	VTPMSealPCRs string `json:"vtpm_seal_pcrs,omitempty"`

	// VTPMQuotePCRs is the PCR selection a gcp-sev-snp-vtpm destination's
	// vTPM quotes (ADR 0037; default sha256:0-9); AKIntermediatesPath a PEM
	// file of the certificates between its attestation-key certificate and
	// Google's EK/AK root (default: the one the certificate's issuer URL
	// serves). gcp-sev-snp-vtpm only.
	VTPMQuotePCRs       string `json:"vtpm_quote_pcrs,omitempty"`
	AKIntermediatesPath string `json:"ak_intermediates_path,omitempty"`

	// AWSKMS is the KMS key a Nitro enclave's key files are sealed under,
	// and the vsock ports of the parent's forwarders to KMS and to the
	// instance metadata service (ADR 0036): the enclave has no network of
	// its own. aws-nitro only, and required there.
	AWSKMS *AWSKMSConfig `json:"aws_kms,omitempty"`

	// SecretFilesVsockPort is the parent's vsock port the enclave takes its
	// key files from at start (ADR 0036): they are sealed to the image's
	// PCR0, which the image itself makes, so they cannot be in it. Only the
	// paths this config names as key files are written, in the enclave's
	// memory. aws-nitro only, and required there.
	SecretFilesVsockPort uint32 `json:"secret_files_vsock_port,omitempty"`
}

// AWSKMSConfig names a Nitro enclave's KMS key and the parent's vsock
// ports that carry the enclave to KMS and to the instance metadata
// service.
type AWSKMSConfig struct {
	// KeyARN is the key the operator sealed the key files under.
	KeyARN string `json:"key_arn"`
	// Endpoint is KMS's host; empty means kms.<the key's Region>.amazonaws.com.
	Endpoint      string `json:"endpoint,omitempty"`
	KMSVsockPort  uint32 `json:"kms_vsock_port"`
	IMDSVsockPort uint32 `json:"imds_vsock_port"`
}

// sealerOptions is the configuration as the sealer's options; nil when
// the section is absent.
func (k *AWSKMSConfig) sealerOptions() *tee.AWSKMSSealerOptions {
	if k == nil {
		return nil
	}
	return &tee.AWSKMSSealerOptions{KeyARN: k.KeyARN, Endpoint: k.Endpoint, KMSVsockPort: k.KMSVsockPort, IMDSVsockPort: k.IMDSVsockPort}
}

// nitroHeartbeatPort is the parent's vsock port the enclave's init sends
// its boot heartbeat to; nitro-cli listens there, so no forwarder can.
const nitroHeartbeatPort = 9000

// DefaultSEVGuestDevice is where the Linux sev-guest driver appears.
const DefaultSEVGuestDevice = "/dev/sev-guest"

// SEVDevice is the sev-guest device to derive the sealing key through.
func (t TEEConfig) SEVDevice() string {
	if t.SEVGuestDevice != "" {
		return t.SEVGuestDevice
	}
	return DefaultSEVGuestDevice
}

// supportedProviders are the TEE backends this build can run.
var supportedProviders = []tee.Provider{tee.ProviderGCPSEVSNP, tee.ProviderGCPSEVSNPVTPM, tee.ProviderGCPTDX, tee.ProviderAzureCGPU, tee.ProviderAzureSEVSNP, tee.ProviderAWSNitro, tee.ProviderSimulated, tee.ProviderAuto}

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

// GenomeConfig points the restorer at its directories.
type GenomeConfig struct {
	// BundleDir holds sealed .genome bundles waiting for their keys.
	// A bundle is opaque without its key, so bundles can be replicated
	// here from anywhere, ahead of any release. Copy them in under
	// another name and rename them to *.genome, so the restorer never
	// reads a half-written bundle.
	BundleDir string `json:"bundle_dir"`

	// RestoreDir receives each restored genome at <restore_dir>/<key
	// id>/ and its signed receipt at <restore_dir>/<key id>.receipt.json.
	RestoreDir string `json:"restore_dir"`

	// RescanSeconds is how often to look again for the bundle of a key
	// that arrived first. Defaults to 5.
	RescanSeconds int `json:"rescan_seconds,omitempty"`

	// MaxBundleBytes bounds a bundle received over the API (POST
	// /v1/genome/bundles, ADR 0036) — the way into a destination with no
	// disk of its own, such as a Nitro enclave, where the bundle lives in
	// memory. Defaults to 1 GiB. A large bundle also needs
	// http.write_timeout_seconds long enough to receive it.
	MaxBundleBytes int64 `json:"max_bundle_bytes,omitempty"`

	// Gate, when set, proves each restored model works before the
	// receipt is signed: Command (the vg_genome door) recomputes the
	// genome's sealed fixtures here and the equivalence gate holds the
	// outputs to their references. The verdict goes into the receipt.
	Gate *GateConfig `json:"gate,omitempty"`
}

// GateConfig configures the restored-model gate.
type GateConfig struct {
	// Command runs the gate backend; "{genome}" in an argument is the
	// restored genome's directory. For example:
	// ["python3", "-m", "vg_genome", "door", "--genome", "{genome}",
	//  "--base", "/var/lib/acp/base/qwen2.5-0.5b", "--device", "cuda"]
	Command []string `json:"command"`
	// Env adds KEY=VALUE pairs to the backend's environment.
	Env []string `json:"env,omitempty"`
	// Atol and Rtol bound the float door: |a-e| <= atol + rtol*|e|.
	Atol float64 `json:"atol"`
	Rtol float64 `json:"rtol"`
	// MaxOutliers non-critical fixtures may miss; critical ones never.
	MaxOutliers int `json:"max_outliers,omitempty"`
	// TimeoutSeconds bounds a gate run. Defaults to 1800.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// Required fails a restore that cannot be gated rather than signing
	// for it without a verdict.
	Required bool `json:"required,omitempty"`
}

// Enabled reports whether genome restore is configured.
func (g GenomeConfig) Enabled() bool { return g.BundleDir != "" || g.RestoreDir != "" }

// HealthConfig controls /healthz and /readyz.
type HealthConfig struct {
	ListenAddress string `json:"listen_address"`
}

// LogConfig picks log verbosity and format.
type LogConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
	// VsockPort sends the log to the parent on this vsock port instead of
	// stderr: a production-mode Nitro enclave has no console anyone can
	// read (ADR 0036). aws-nitro only.
	VsockPort uint32 `json:"vsock_port,omitempty"`
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
// SealerMode is tee.sealer with the default applied.
func (t TEEConfig) SealerMode() tee.SealerMode {
	m, err := tee.ParseSealerMode(t.Sealer)
	if err != nil {
		return tee.SealerModeAuto
	}
	return m
}

// ResolveAuto replaces tee.provider "auto" with the family the kernel's
// configfs-tsm serves on this host (ADR 0025), keeping the kernel's name
// in AutoResolvedFrom; any other provider is left as it is. It runs when
// the file is loaded, before validation, so that the family's own rules
// apply to the rest of the section.
func (t *TEEConfig) ResolveAuto() error {
	p, err := tee.ParseProvider(t.Provider)
	if err != nil || p != tee.ProviderAuto {
		return nil
	}
	family, name, err := tee.ResolveAuto(t.TSMReportDir)
	if err != nil {
		return fmt.Errorf("tee.provider=auto: %w", err)
	}
	t.Provider, t.AutoResolvedFrom = string(family), name
	return nil
}

func DefaultConfig() Config {
	return Config{
		HTTP: HTTPConfig{
			ListenAddress: "127.0.0.1:8443",
		},
		TEE: TEEConfig{
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
	c, err := DecodeConfig(f)
	if err != nil {
		return Config{}, err
	}
	if err := c.TEE.ResolveAuto(); err != nil {
		return Config{}, fmt.Errorf("acp-bootstrap: %w", err)
	}
	return c, nil
}

// DecodeConfig decodes JSON from r into a Config on top of
// DefaultConfig. The two listen addresses have defaults for a host with
// a network; a file that names a vsock port, or the aws-nitro provider,
// is an enclave's, and a default the file did not write yields to it —
// an enclave has no address to listen on, not even loopback (ADR 0036).
// What the file wrote stands, and Validate judges it.
func DecodeConfig(r io.Reader) (Config, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return Config{}, fmt.Errorf("acp-bootstrap: read config: %w", err)
	}
	c := DefaultConfig()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("acp-bootstrap: decode config: %w", err)
	}
	var written struct {
		HTTP struct {
			ListenAddress *string `json:"listen_address"`
		} `json:"http"`
		Health struct {
			ListenAddress *string `json:"listen_address"`
		} `json:"health"`
	}
	_ = json.Unmarshal(raw, &written) // the strict decode above already accepted raw
	if c.HTTP.ListenVsockPort != 0 && written.HTTP.ListenAddress == nil {
		c.HTTP.ListenAddress = ""
	}
	if p, err := tee.ParseProvider(c.TEE.Provider); err == nil && p == tee.ProviderAWSNitro && written.Health.ListenAddress == nil {
		c.Health.ListenAddress = ""
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
	// The file may be sealed to this host (`acp-bootstrap seal-keys`, ADR 0023).
	raw, err := readSecret(c.TEE, c.HTTP.BearerTokenFile, 0, "http.bearer_token_file")
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return fmt.Errorf("acp-bootstrap: http.bearer_token_file %q is empty", c.HTTP.BearerTokenFile)
	}
	if (c.HTTP.ListenVsockPort != 0 || !exposure.IsLoopback(c.HTTP.ListenAddress)) && len(token) < exposure.MinBearerTokenLen {
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

	if _, err := c.Crypto.Policy(); err != nil {
		errs = append(errs, fmt.Errorf("crypto: %w", err))
	}

	// exposed: the listener is reachable from outside this host — a
	// non-loopback address, or vsock (the parent instance's side).
	listenOK, exposed, where := false, false, fmt.Sprintf("listen_address %q", c.HTTP.ListenAddress)
	switch {
	case c.HTTP.ListenVsockPort != 0 && strings.TrimSpace(c.HTTP.ListenAddress) != "":
		errs = append(errs, errors.New("http: set only one of listen_address and listen_vsock_port"))
	case c.HTTP.ListenVsockPort == 0xFFFFFFFF:
		errs = append(errs, errors.New("http.listen_vsock_port 4294967295 is VMADDR_PORT_ANY, not a port"))
	case c.HTTP.ListenVsockPort != 0:
		listenOK, exposed, where = true, true, fmt.Sprintf("listen_vsock_port %d", c.HTTP.ListenVsockPort)
	case strings.TrimSpace(c.HTTP.ListenAddress) == "":
		errs = append(errs, errors.New("http.listen_address or http.listen_vsock_port required"))
	default:
		if _, _, err := net.SplitHostPort(c.HTTP.ListenAddress); err != nil {
			errs = append(errs, fmt.Errorf("http.listen_address invalid: %w", err))
		} else {
			listenOK, exposed = true, !exposure.IsLoopback(c.HTTP.ListenAddress)
		}
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
	if listenOK && exposed {
		if !c.HTTP.TLS.Enabled {
			errs = append(errs, fmt.Errorf(
				"http.tls.enabled required: %s is not loopback (key-release traffic across a network must be encrypted)", where))
		}
		hasToken := c.HTTP.BearerToken != "" || c.HTTP.BearerTokenFile != ""
		if c.HTTP.TLS.ClientCAs == "" && !hasToken {
			errs = append(errs, fmt.Errorf(
				"http.tls.client_cas or http.bearer_token(_file) required: %s is not loopback", where))
		}
		if c.HTTP.BearerToken != "" && len(c.HTTP.BearerToken) < exposure.MinBearerTokenLen {
			errs = append(errs, fmt.Errorf(
				"http.bearer_token too short for non-loopback %s (need >= %d characters)", where, exposure.MinBearerTokenLen))
		}
	}

	if _, err := tee.ParseSealerMode(c.TEE.Sealer); err != nil {
		errs = append(errs, err)
	}
	switch provider, err := tee.ParseProvider(c.TEE.Provider); {
	case strings.TrimSpace(c.TEE.Provider) == "":
		errs = append(errs, errors.New("tee.provider required"))
	case err != nil:
		errs = append(errs, fmt.Errorf("tee.provider invalid: %w", err))
	case !slices.Contains(supportedProviders, provider):
		errs = append(errs, fmt.Errorf("tee.provider %q is not available in this build (supported: %v)", provider, supportedProviders))
	case provider == tee.ProviderSimulated:
		if !c.TEE.InsecureSimulation {
			errs = append(errs, errors.New("tee.provider=simulated has no hardware isolation: set tee.insecure_simulation=true to run it, for development and tests only"))
		}
		if c.TEE.SeedPath == "" {
			errs = append(errs, errors.New("tee.seed_path required when tee.provider=simulated"))
		}
		if c.TEE.TSMReportDir != "" {
			errs = append(errs, errors.New("tee.tsm_report_dir applies to gcp-sev-snp and gcp-tdx only"))
		}
	case provider == tee.ProviderAuto:
		if c.TEE.SeedPath != "" || c.TEE.InsecureSimulation {
			errs = append(errs, errors.New("tee.seed_path and tee.insecure_simulation apply to the simulated provider only; tee.provider=auto runs the family configfs-tsm serves"))
		}
		if c.TEE.VTPMSealPCRs != "" {
			if err := tee.ValidatePCRSelection(c.TEE.VTPMSealPCRs); err != nil {
				errs = append(errs, fmt.Errorf("tee.vtpm_seal_pcrs: %w", err))
			}
		}
	case provider == tee.ProviderGCPSEVSNP || provider == tee.ProviderGCPTDX || provider == tee.ProviderGCPSEVSNPVTPM:
		if c.TEE.SeedPath != "" {
			errs = append(errs, errors.New("tee.seed_path applies to the simulated provider only; a hardware TEE signs with its own key"))
		}
		if c.TEE.InsecureSimulation {
			errs = append(errs, errors.New("tee.insecure_simulation applies to the simulated provider only"))
		}
	case provider == tee.ProviderAzureSEVSNP:
		if c.TEE.SeedPath != "" || c.TEE.InsecureSimulation {
			errs = append(errs, errors.New("tee.seed_path and tee.insecure_simulation apply to the simulated provider only"))
		}
		if c.TEE.TSMReportDir != "" {
			errs = append(errs, errors.New("tee.tsm_report_dir does not apply to azure-sev-snp (the report comes from the vTPM)"))
		}
		if len(c.TEE.GPUAttestCommand) > 0 {
			errs = append(errs, errors.New("tee.gpu_attest_command applies to azure-cgpu only (azure-sev-snp has no GPU)"))
		}
	case provider == tee.ProviderAzureCGPU:
		if c.TEE.SeedPath != "" || c.TEE.InsecureSimulation {
			errs = append(errs, errors.New("tee.seed_path and tee.insecure_simulation apply to the simulated provider only"))
		}
		if c.TEE.TSMReportDir != "" {
			errs = append(errs, errors.New("tee.tsm_report_dir does not apply to azure-cgpu (the report comes from the vTPM)"))
		}
		if len(c.TEE.GPUAttestCommand) == 0 {
			errs = append(errs, errors.New("tee.gpu_attest_command required when tee.provider=azure-cgpu (the command that obtains NVIDIA's attestation tokens for a nonce)"))
		}
	case provider == tee.ProviderAWSNitro:
		errs = append(errs, c.validateNitro()...)
	}
	if provider, err := tee.ParseProvider(c.TEE.Provider); err == nil && provider != tee.ProviderAWSNitro &&
		(c.TEE.AWSKMS != nil || c.TEE.SecretFilesVsockPort != 0 || c.Log.VsockPort != 0) {
		errs = append(errs, errors.New("tee.aws_kms, tee.secret_files_vsock_port and log.vsock_port apply to aws-nitro only"))
	}
	if lp, _ := tee.ParseProvider(c.TEE.Provider); lp != tee.ProviderAzureCGPU && lp != tee.ProviderAzureSEVSNP && (len(c.TEE.GPUAttestCommand) > 0 || c.TEE.AKHandle != "" ||
		(c.TEE.TPM2ToolsDir != "" && lp != tee.ProviderGCPSEVSNPVTPM)) {
		errs = append(errs, errors.New("tee.gpu_attest_command and ak_handle apply to azure-cgpu and azure-sev-snp only, and tpm2_tools_dir to those and gcp-sev-snp-vtpm"))
	}
	if lp, _ := tee.ParseProvider(c.TEE.Provider); lp != tee.ProviderGCPSEVSNPVTPM && (c.TEE.VTPMQuotePCRs != "" || c.TEE.AKIntermediatesPath != "") {
		errs = append(errs, errors.New("tee.vtpm_quote_pcrs and ak_intermediates_path apply to gcp-sev-snp-vtpm only"))
	} else if c.TEE.VTPMQuotePCRs != "" {
		if err := tee.ValidatePCRSelection(c.TEE.VTPMQuotePCRs); err != nil {
			errs = append(errs, fmt.Errorf("tee.vtpm_quote_pcrs: %w", err))
		}
	}
	if strings.TrimSpace(c.TEE.WorkloadDescriptor) == "" {
		errs = append(errs, errors.New("tee.workload_descriptor required"))
	}

	if c.SourceAuthority.KeyID == "" {
		errs = append(errs, errors.New("source_authority.kid required"))
	}
	if c.SourceAuthority.PublicKeyPath == "" {
		errs = append(errs, errors.New("source_authority.public_key_path required"))
	}

	if c.Genome.Enabled() {
		errs = append(errs, c.Genome.validate()...)
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

	if provider, err := tee.ParseProvider(c.TEE.Provider); err == nil {
		if c.TEE.SEVGuestDevice != "" && provider != tee.ProviderGCPSEVSNP && provider != tee.ProviderGCPSEVSNPVTPM {
			errs = append(errs, errors.New("tee.sev_guest_device applies to gcp-sev-snp and gcp-sev-snp-vtpm only"))
		}
		if c.TEE.VTPMSealPCRs != "" {
			switch {
			case provider == tee.ProviderGCPTDX || provider == tee.ProviderAzureCGPU || provider == tee.ProviderAzureSEVSNP || provider == tee.ProviderGCPSEVSNPVTPM,
				provider == tee.ProviderGCPSEVSNP && (c.TEE.SealerMode() == tee.SealerModeBoth || c.TEE.SealerMode() == tee.SealerModeTPM2):
				if err := tee.ValidatePCRSelection(c.TEE.VTPMSealPCRs); err != nil {
					errs = append(errs, fmt.Errorf("tee.vtpm_seal_pcrs: %w", err))
				}
			default:
				errs = append(errs, errors.New("tee.vtpm_seal_pcrs applies where a vTPM seals: gcp-tdx, azure-cgpu, azure-sev-snp, gcp-sev-snp-vtpm, and gcp-sev-snp under tee.sealer both or tpm2"))
			}
		}
	}
	return errors.Join(errs...)
}

// validateNitro holds a Nitro enclave's configuration to what an enclave
// is (ADR 0036): no network but vsock, so the API listens on a vsock port
// and there is no health listener; the key files come from the parent and
// open only through KMS, released to the enclave's attestation; the
// parent's vsock ports it dials are distinct, and none is nitro-cli's
// boot heartbeat.
func (c Config) validateNitro() []error {
	var errs []error
	if c.TEE.SeedPath != "" || c.TEE.InsecureSimulation {
		errs = append(errs, errors.New("tee.seed_path and tee.insecure_simulation apply to the simulated provider only"))
	}
	if c.TEE.TSMReportDir != "" {
		errs = append(errs, errors.New("tee.tsm_report_dir does not apply to aws-nitro (the document comes from the NSM)"))
	}
	if _, err := tee.SealerKindForProvider(tee.ProviderAWSNitro, c.TEE.SealerMode()); err != nil {
		errs = append(errs, err)
	}
	if c.HTTP.ListenVsockPort == 0 {
		errs = append(errs, errors.New("tee.provider=aws-nitro: http.listen_vsock_port required (an enclave has no network interface; its parent forwards to the port)"))
	}
	if strings.TrimSpace(c.Health.ListenAddress) != "" {
		errs = append(errs, errors.New(`tee.provider=aws-nitro: health.listen_address must be "" (an enclave has no network interface, not even loopback)`))
	}
	if c.TEE.SecretFilesVsockPort == 0 {
		errs = append(errs, errors.New("tee.provider=aws-nitro: tee.secret_files_vsock_port required (the key files are sealed to the image, so they come from the parent, not in the image)"))
	}
	k := c.TEE.AWSKMS
	if k == nil {
		errs = append(errs, errors.New("tee.provider=aws-nitro: tee.aws_kms required (the key the files are sealed under, and the parent's vsock ports to KMS and the instance metadata service)"))
	} else {
		if _, err := tee.ParseAWSKMSKeyARN(k.KeyARN); err != nil {
			errs = append(errs, fmt.Errorf("tee.aws_kms.key_arn: %w", err))
		}
		if k.KMSVsockPort == 0 || k.IMDSVsockPort == 0 {
			errs = append(errs, errors.New("tee.aws_kms.kms_vsock_port and tee.aws_kms.imds_vsock_port required"))
		}
	}
	dialed := map[string]uint32{"tee.secret_files_vsock_port": c.TEE.SecretFilesVsockPort, "log.vsock_port": c.Log.VsockPort}
	if k != nil {
		dialed["tee.aws_kms.kms_vsock_port"], dialed["tee.aws_kms.imds_vsock_port"] = k.KMSVsockPort, k.IMDSVsockPort
	}
	names := make([]string, 0, len(dialed))
	for name := range dialed {
		names = append(names, name)
	}
	slices.Sort(names)
	seen := map[uint32]string{}
	for _, name := range names {
		port := dialed[name]
		switch {
		case port == 0:
		case port == nitroHeartbeatPort:
			errs = append(errs, fmt.Errorf("%s %d is the parent's port nitro-cli receives the enclave's boot heartbeat on; a forwarder cannot listen there", name, port))
		case port == 0xFFFFFFFF:
			errs = append(errs, fmt.Errorf("%s 4294967295 is VMADDR_PORT_ANY, not a port", name))
		case seen[port] != "":
			errs = append(errs, fmt.Errorf("%s and %s are the same vsock port %d; each forwarder on the parent has its own", seen[port], name, port))
		default:
			seen[port] = name
		}
	}
	return errs
}

func (g GenomeConfig) validate() []error {
	var errs []error
	for name, dir := range map[string]string{"genome.bundle_dir": g.BundleDir, "genome.restore_dir": g.RestoreDir} {
		if dir == "" {
			errs = append(errs, fmt.Errorf("%s required when genome restore is configured", name))
		} else if !filepath.IsAbs(dir) {
			errs = append(errs, fmt.Errorf("%s %q must be an absolute path", name, dir))
		}
	}
	if g.BundleDir != "" && g.RestoreDir != "" {
		b, r := filepath.Clean(g.BundleDir), filepath.Clean(g.RestoreDir)
		if b == r || strings.HasPrefix(r+string(filepath.Separator), b+string(filepath.Separator)) || strings.HasPrefix(b+string(filepath.Separator), r+string(filepath.Separator)) {
			errs = append(errs, errors.New("genome.bundle_dir and genome.restore_dir must be separate directories, neither inside the other"))
		}
	}
	if g.RescanSeconds < 0 {
		errs = append(errs, errors.New("genome.rescan_seconds must not be negative"))
	}
	if g.MaxBundleBytes < 0 {
		errs = append(errs, errors.New("genome.max_bundle_bytes must not be negative"))
	}
	if gate := g.Gate; gate != nil {
		if len(gate.Command) == 0 || strings.TrimSpace(gate.Command[0]) == "" {
			errs = append(errs, errors.New("genome.gate.command required"))
		}
		if gate.Atol < 0 || gate.Rtol < 0 || gate.MaxOutliers < 0 || gate.TimeoutSeconds < 0 {
			errs = append(errs, errors.New("genome.gate: atol, rtol, max_outliers and timeout_seconds must not be negative"))
		}
		for _, kv := range gate.Env {
			if k, _, ok := strings.Cut(kv, "="); !ok || k == "" {
				errs = append(errs, fmt.Errorf("genome.gate.env %q is not KEY=VALUE", kv))
			}
		}
	}
	return errs
}
