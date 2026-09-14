// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig_Listeners(t *testing.T) {
	c := DefaultConfig()
	if c.Vault.ListenAddress != "127.0.0.1:9443" {
		t.Errorf("default vault listen = %q", c.Vault.ListenAddress)
	}
	if c.HTTPAPI.ListenAddress != "127.0.0.1:9080" {
		t.Errorf("default http_api listen = %q", c.HTTPAPI.ListenAddress)
	}
	if c.Health.ListenAddress != "127.0.0.1:9091" {
		t.Errorf("default health listen = %q", c.Health.ListenAddress)
	}
}

// minimalValidConfig returns a Config that passes Validate(). Used
// as the base for Validate() tests that want to flip one field at
// a time.
func minimalValidConfig() Config {
	c := DefaultConfig()
	c.TEE.SeedPath = "/tmp/tee.seed"
	c.TEE.Peer.PublicKeyPath = "/tmp/peer.pub"
	c.TEE.Peer.MeasurementPath = "/tmp/peer.meas"
	c.Keys.AuthoritySigning = SigningKeyConfig{KeyID: "auth-1", SeedPath: "/tmp/auth.seed"}
	c.Keys.SessionSealing = SealingKeyConfig{KeyID: "seal-1", MaterialPath: "/tmp/seal.key"}
	c.Workers.RegistryPath = "/tmp/workers.json"
	return c
}

func TestValidate_Happy(t *testing.T) {
	if err := minimalValidConfig().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_FlagsEveryMissingField(t *testing.T) {
	// An empty Config triggers multiple errors; Validate must
	// surface them all via errors.Join so operators see the full
	// punch-list in one run.
	err := Config{}.Validate()
	if err == nil {
		t.Fatal("Validate(zero Config) returned nil")
	}
	msg := err.Error()
	for _, want := range []string{
		"vault.listen_address required",
		"tee.workload_descriptor required",
		"tee.seed_path required",
		"tee.peer.public_key_path required",
		"tee.peer.measurement_path required",
		"keys.authority_signing.kid required",
		"keys.authority_signing.seed_path required",
		"keys.session_sealing.kid required",
		"keys.session_sealing.material_path required",
		"workers.registry_path required",
		"runtime.job_timeout_seconds",
		"runtime.handshake_timeout_seconds",
		"runtime.queue_poll_ms",
		"runtime.http_read_header_timeout_seconds",
		"runtime.http_write_timeout_seconds",
		"runtime.default_job_deadline_seconds",
		"runtime.max_payload_bytes",
		"log.level",
		"log.format",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("Validate error missing field: %q\nfull: %s", want, msg)
		}
	}
}

func TestValidate_TLSRequiresPaths(t *testing.T) {
	c := minimalValidConfig()
	c.Vault.TLS.Enabled = true
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate: want error when TLS enabled but paths empty")
	}
	for _, want := range []string{"server_cert", "server_key", "client_cas"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("TLS error missing %q: %s", want, err.Error())
		}
	}
}

func TestValidate_HTTPAPIListenOptional(t *testing.T) {
	c := minimalValidConfig()
	c.HTTPAPI.ListenAddress = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate with empty http_api.listen_address: %v (want nil: empty is disabled)", err)
	}
}

func TestValidate_InvalidHostPort(t *testing.T) {
	c := minimalValidConfig()
	c.Vault.ListenAddress = "not-a-host-port"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "vault.listen_address invalid") {
		t.Fatalf("Validate(bad vault listen): err = %v", err)
	}
}

// --- fail-closed network exposure ------------------------------------

func TestValidate_NonLoopbackVaultRequiresTLS(t *testing.T) {
	c := minimalValidConfig()
	c.Vault.ListenAddress = "0.0.0.0:9443"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "vault.tls.enabled required") {
		t.Fatalf("Validate(non-loopback vault, no TLS): err = %v", err)
	}

	c.Vault.TLS = TLSConfig{Enabled: true, ServerCert: "s.crt", ServerKey: "s.key", ClientCAs: "ca.crt"}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(non-loopback vault, mTLS): %v", err)
	}
}

func TestValidate_NonLoopbackHTTPRequiresToken(t *testing.T) {
	c := minimalValidConfig()
	c.HTTPAPI.ListenAddress = "0.0.0.0:9080"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "bearer_token or bearer_token_file required") {
		t.Fatalf("Validate(non-loopback REST, no token): err = %v", err)
	}
}

func TestValidate_NonLoopbackHTTPShortTokenRejected(t *testing.T) {
	c := minimalValidConfig()
	c.HTTPAPI.ListenAddress = "0.0.0.0:9080"
	c.HTTPAPI.BearerToken = "short"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("Validate(non-loopback REST, short token): err = %v", err)
	}

	c.HTTPAPI.BearerToken = strings.Repeat("a", MinNonLoopbackTokenLen)
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(non-loopback REST, strong token): %v", err)
	}
}

func TestValidate_NonLoopbackHTTPTokenFileAccepted(t *testing.T) {
	c := minimalValidConfig()
	c.HTTPAPI.ListenAddress = "0.0.0.0:9080"
	c.HTTPAPI.BearerTokenFile = "/etc/acp/secrets/sagvd/api_token"
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(non-loopback REST, token file): %v", err)
	}
}

func TestValidate_TokenAndTokenFileMutuallyExclusive(t *testing.T) {
	c := minimalValidConfig()
	c.HTTPAPI.BearerToken = "inline"
	c.HTTPAPI.BearerTokenFile = "/tmp/token"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "only one of bearer_token and bearer_token_file") {
		t.Fatalf("Validate(both token sources): err = %v", err)
	}
}

func TestResolveSecrets_ReadsAndTrimsTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api_token")
	want := strings.Repeat("f", MinNonLoopbackTokenLen)
	if err := os.WriteFile(path, []byte("  "+want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := minimalValidConfig()
	c.HTTPAPI.ListenAddress = "0.0.0.0:9080"
	c.HTTPAPI.BearerTokenFile = path
	if err := c.ResolveSecrets(); err != nil {
		t.Fatalf("ResolveSecrets: %v", err)
	}
	if c.HTTPAPI.BearerToken != want {
		t.Fatalf("BearerToken = %q, want %q", c.HTTPAPI.BearerToken, want)
	}
}

func TestResolveSecrets_RejectsEmptyShortOrMissingFile(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(short, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"empty":   empty,
		"short":   short,
		"missing": filepath.Join(dir, "nope"),
	} {
		c := minimalValidConfig()
		c.HTTPAPI.ListenAddress = "0.0.0.0:9080"
		c.HTTPAPI.BearerTokenFile = path
		if err := c.ResolveSecrets(); err == nil {
			t.Errorf("ResolveSecrets(%s token file) = nil, want error", name)
		}
	}
}

func TestResolveSecrets_NoTokenFileIsNoop(t *testing.T) {
	c := minimalValidConfig()
	c.HTTPAPI.BearerToken = "inline"
	if err := c.ResolveSecrets(); err != nil {
		t.Fatalf("ResolveSecrets: %v", err)
	}
	if c.HTTPAPI.BearerToken != "inline" {
		t.Fatalf("inline token altered: %q", c.HTTPAPI.BearerToken)
	}
}

// --- Phase 4 cross-cloud config tests --------------------------------

func TestValidate_CrossCloudDisabledByDefault(t *testing.T) {
	// minimalValidConfig() does not set CrossCloud — Phase 4 must not
	// regress Phase 1-3 default behaviour.
	c := minimalValidConfig()
	if c.CrossCloud.Enabled {
		t.Fatal("CrossCloud.Enabled must default to false")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(crosscloud disabled): %v", err)
	}
}

func TestValidate_CrossCloudEnabledRequiresFields(t *testing.T) {
	c := minimalValidConfig()
	c.CrossCloud.Enabled = true
	// All required fields empty.
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate: want error when crosscloud.enabled but required fields empty")
	}
	for _, want := range []string{
		"crosscloud.policy_version required",
		"crosscloud.policy_allow_list_path required",
		"crosscloud.verifier_registry_path required",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CrossCloud error missing %q: %s", want, err.Error())
		}
	}
}

func TestValidate_CrossCloudHappyPath(t *testing.T) {
	c := minimalValidConfig()
	c.CrossCloud = CrossCloudConfig{
		Enabled:               true,
		PolicyVersion:         "xcc-2026-05-09",
		PolicyAllowListPath:   "/etc/vg/allow-list.json",
		VerifierRegistryPath:  "/etc/vg/verifier-registry.json",
		RequestTimeoutSeconds: 30,
		AuditLogPath:          "/var/lib/vg/xcc-audit.db",
	}
	c.Keys.AuditSigning = SigningKeyConfig{KeyID: "xcc-audit-1", SeedPath: "/etc/vg/audit_signing_seed"}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(crosscloud happy): %v", err)
	}
}

// No key is released without a durable audit record: the log and its
// signing key are required whenever cross-cloud release is enabled.
func TestValidate_CrossCloudRequiresDurableAudit(t *testing.T) {
	c := minimalValidConfig()
	c.CrossCloud = CrossCloudConfig{
		Enabled:              true,
		PolicyVersion:        "v1",
		PolicyAllowListPath:  "/a",
		VerifierRegistryPath: "/r",
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "crosscloud.audit_log_path required") ||
		!strings.Contains(err.Error(), "keys.audit_signing.kid and seed_path required") {
		t.Fatalf("Validate(crosscloud without audit): %v", err)
	}
}

func TestValidate_CrossCloudTLSRequiresPaths(t *testing.T) {
	c := minimalValidConfig()
	c.CrossCloud = CrossCloudConfig{
		Enabled:              true,
		PolicyVersion:        "xcc-2026-05-09",
		PolicyAllowListPath:  "/etc/vg/allow-list.json",
		VerifierRegistryPath: "/etc/vg/verifier-registry.json",
		TransportTLS:         TLSClientConfig{Enabled: true},
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate: want error when transport_tls.enabled but client_cert/key/ca_bundle empty")
	}
	for _, want := range []string{"client_cert", "client_key", "ca_bundle"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CrossCloud TLS error missing %q: %s", want, err.Error())
		}
	}
}

func TestValidate_CrossCloudNegativeTimeoutRejected(t *testing.T) {
	c := minimalValidConfig()
	c.CrossCloud = CrossCloudConfig{
		Enabled:               true,
		PolicyVersion:         "xcc-2026-05-09",
		PolicyAllowListPath:   "/etc/vg/allow-list.json",
		VerifierRegistryPath:  "/etc/vg/verifier-registry.json",
		RequestTimeoutSeconds: -5,
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "request_timeout_seconds") {
		t.Fatalf("Validate(negative timeout): err = %v", err)
	}
}

func TestCrossCloudConfig_RequestTimeoutDefault(t *testing.T) {
	// Zero -> default 30s.
	c := CrossCloudConfig{}
	if got := c.RequestTimeout(); got.Seconds() != 30 {
		t.Errorf("RequestTimeout() default = %v; want 30s", got)
	}
	// Custom -> respected.
	c.RequestTimeoutSeconds = 60
	if got := c.RequestTimeout(); got.Seconds() != 60 {
		t.Errorf("RequestTimeout(60) = %v; want 60s", got)
	}
}

func TestValidate_LogValuesGated(t *testing.T) {
	c := minimalValidConfig()
	c.Log.Level = "trace"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "log.level") {
		t.Fatalf("Validate(bad log level): err = %v", err)
	}

	c = minimalValidConfig()
	c.Log.Format = "xml"
	err = c.Validate()
	if err == nil || !strings.Contains(err.Error(), "log.format") {
		t.Fatalf("Validate(bad log format): err = %v", err)
	}
}

func TestLoadConfigFile_OverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sagvd.json")
	// Supply only a subset; LoadConfigFile applies the override on
	// top of DefaultConfig().
	body := `{
		"vault": {"listen_address": "127.0.0.1:19443"},
		"http_api": {"listen_address": "127.0.0.1:19080", "bearer_token": "supersecret"},
		"tee": {
			"workload_descriptor": "sagvd-test",
			"seed_path": "/tmp/tee.seed",
			"peer": {"public_key_path": "/tmp/peer.pub", "measurement_path": "/tmp/peer.meas"}
		},
		"keys": {
			"authority_signing": {"kid": "auth-1", "seed_path": "/tmp/auth.seed"},
			"session_sealing":   {"kid": "seal-1", "material_path": "/tmp/seal.key"}
		},
		"workers": {"registry_path": "/tmp/workers.json"}
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if cfg.Vault.ListenAddress != "127.0.0.1:19443" {
		t.Errorf("vault listen = %q", cfg.Vault.ListenAddress)
	}
	if cfg.HTTPAPI.BearerToken != "supersecret" {
		t.Errorf("bearer_token = %q", cfg.HTTPAPI.BearerToken)
	}
	if cfg.Runtime.JobTimeoutSeconds != 120 {
		t.Errorf("default JobTimeoutSeconds not preserved, got %d", cfg.Runtime.JobTimeoutSeconds)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate(loaded): %v", err)
	}
}

func TestLoadConfigFile_RejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sagvd.json")
	body := `{"vault": {"listen_address": "127.0.0.1:9443"}, "typo_here": true}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadConfigFile(path)
	if err == nil || !strings.Contains(err.Error(), "typo_here") {
		t.Fatalf("LoadConfigFile(unknown field): err = %v", err)
	}
}

func TestLoadConfigFile_MissingFile(t *testing.T) {
	_, err := LoadConfigFile("/does/not/exist/sagvd.json")
	if err == nil {
		t.Fatal("LoadConfigFile(missing): want error")
	}
}

func TestRuntimeConfig_DurationAccessors(t *testing.T) {
	r := DefaultConfig().Runtime
	if r.JobTimeout().Seconds() != 120 {
		t.Errorf("JobTimeout = %v", r.JobTimeout())
	}
	if r.HandshakeTimeout().Seconds() != 10 {
		t.Errorf("HandshakeTimeout = %v", r.HandshakeTimeout())
	}
	if r.QueuePoll().Milliseconds() != 250 {
		t.Errorf("QueuePoll = %v", r.QueuePoll())
	}
	if r.DefaultJobDeadline().Seconds() != 60 {
		t.Errorf("DefaultJobDeadline = %v", r.DefaultJobDeadline())
	}
}
