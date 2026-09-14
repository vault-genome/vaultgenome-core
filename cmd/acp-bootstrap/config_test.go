// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ai-continuity-platform/core/internal/shared/exposure"
)

// minimalValidConfig is a loopback-only destination: the one shape that
// may run without TLS or caller authentication.
func minimalValidConfig() Config {
	c := DefaultConfig()
	c.TEE.SeedPath = "/etc/acp/secrets/acp-bootstrap/tee_seed"
	c.SourceAuthority = SourceAuthorityConfig{KeyID: "authority-1", PublicKeyPath: "/etc/acp/secrets/authority.pub"}
	return c
}

func strongToken() string { return strings.Repeat("a", exposure.MinBearerTokenLen) }

func requireValid(t *testing.T, c Config) {
	t.Helper()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func requireInvalid(t *testing.T, c Config, want string) {
	t.Helper()
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate: err = %v, want it to mention %q", err, want)
	}
}

func TestDecodeConfig_DefaultsAndStrictness(t *testing.T) {
	c, err := DecodeConfig(strings.NewReader(`{"source_authority":{"kid":"k","public_key_path":"/p"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTP.ListenAddress != "127.0.0.1:8443" || c.TEE.Provider != "simulated" || c.Log.Level != "info" {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if _, err := DecodeConfig(strings.NewReader(`{"http":{"listen_adress":"0.0.0.0:1"}}`)); err == nil {
		t.Fatal("a misspelt field was accepted; operator typos must fail at startup")
	}
	if _, err := LoadConfigFile(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("LoadConfigFile of a missing file succeeded")
	}
}

func TestValidate_LoopbackNeedsNoTLSOrToken(t *testing.T) {
	requireValid(t, minimalValidConfig())
	c := minimalValidConfig()
	c.HTTP.ListenAddress = "[::1]:8443"
	requireValid(t, c)
}

// --- fail-closed network exposure ------------------------------------

func TestValidate_NonLoopbackRequiresTLS(t *testing.T) {
	c := minimalValidConfig()
	c.HTTP.ListenAddress = "0.0.0.0:8443"
	c.HTTP.BearerToken = strongToken()
	requireInvalid(t, c, "http.tls.enabled required")
}

func TestValidate_NonLoopbackRequiresCallerAuthentication(t *testing.T) {
	c := minimalValidConfig()
	c.HTTP.ListenAddress = "10.0.0.5:8443"
	c.HTTP.TLS = TLSServerConfig{Enabled: true, ServerCert: "/s.crt", ServerKey: "/s.key"}
	requireInvalid(t, c, "http.tls.client_cas or http.bearer_token(_file) required")
}

func TestValidate_NonLoopbackAcceptsMTLSOrStrongToken(t *testing.T) {
	base := minimalValidConfig()
	base.HTTP.ListenAddress = "0.0.0.0:8443"
	base.HTTP.TLS = TLSServerConfig{Enabled: true, ServerCert: "/s.crt", ServerKey: "/s.key"}

	mtls := base
	mtls.HTTP.TLS.ClientCAs = "/ca.crt"
	requireValid(t, mtls)

	token := base
	token.HTTP.BearerToken = strongToken()
	requireValid(t, token)

	file := base
	file.HTTP.BearerTokenFile = "/etc/acp/secrets/acp-bootstrap/api_token"
	requireValid(t, file)
}

func TestValidate_ShortTokenRejectedBeyondLoopback(t *testing.T) {
	c := minimalValidConfig()
	c.HTTP.ListenAddress = "0.0.0.0:8443"
	c.HTTP.TLS = TLSServerConfig{Enabled: true, ServerCert: "/s.crt", ServerKey: "/s.key"}
	c.HTTP.BearerToken = "hunter2"
	requireInvalid(t, c, "too short")

	loop := minimalValidConfig()
	loop.HTTP.BearerToken = "hunter2" // loopback: any token is extra, not required
	requireValid(t, loop)
}

func TestValidate_TokenSourcesAreExclusive(t *testing.T) {
	c := minimalValidConfig()
	c.HTTP.BearerToken = strongToken()
	c.HTTP.BearerTokenFile = "/token"
	requireInvalid(t, c, "set only one of bearer_token and bearer_token_file")
}

func TestValidate_TLSMaterial(t *testing.T) {
	c := minimalValidConfig()
	c.HTTP.TLS.Enabled = true
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "server_cert required") || !strings.Contains(err.Error(), "server_key required") {
		t.Fatalf("Validate(TLS without material): %v", err)
	}
	c = minimalValidConfig()
	c.HTTP.TLS.ClientCAs = "/ca.crt"
	requireInvalid(t, c, "client_cas set but http.tls.enabled=false")
}

func TestValidate_ReportsEveryProblem(t *testing.T) {
	c := Config{HTTP: HTTPConfig{ListenAddress: "no-port"}, Health: HealthConfig{ListenAddress: "nope"}, Log: LogConfig{Level: "loud", Format: "xml"}}
	err := c.Validate()
	if err == nil {
		t.Fatal("an empty config validated")
	}
	for _, want := range []string{
		"http.listen_address invalid", "tee.provider required", "tee.workload_descriptor required",
		"source_authority.kid required", "source_authority.public_key_path required",
		"health.listen_address invalid", `log.level "loud" invalid`, `log.format "xml" invalid`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("punch-list lacks %q:\n%v", want, err)
		}
	}
	c = minimalValidConfig()
	c.HTTP.ListenAddress = ""
	requireInvalid(t, c, "http.listen_address required")
}

func TestValidate_TEEProvider(t *testing.T) {
	c := minimalValidConfig()
	c.TEE.Provider = "my-own-enclave"
	requireInvalid(t, c, "tee.provider invalid")

	c = minimalValidConfig()
	c.TEE.SeedPath = ""
	requireInvalid(t, c, "tee.seed_path required when tee.provider=simulated")

	c = minimalValidConfig()
	c.TEE.TSMReportDir = "/sys/kernel/config/tsm/report"
	requireInvalid(t, c, "tee.tsm_report_dir applies to gcp-sev-snp only")

	// Real SEV-SNP: the chip signs; there is no seed to configure.
	c = minimalValidConfig()
	c.TEE.Provider = "gcp-sev-snp"
	c.TEE.SeedPath = ""
	requireValid(t, c)
	c.TEE.SeedPath = "/etc/acp/tee_seed"
	requireInvalid(t, c, "tee.seed_path applies to the simulated provider only")

	// Families whose producer this build does not run are refused up front.
	c = minimalValidConfig()
	c.TEE.Provider = "aws-nitro"
	requireInvalid(t, c, `tee.provider "aws-nitro" is not available in this build`)
}

func TestResolveSecrets(t *testing.T) {
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	c := minimalValidConfig()
	if err := c.ResolveSecrets(); err != nil || c.HTTP.BearerToken != "" {
		t.Fatalf("no token file: err=%v token=%q", err, c.HTTP.BearerToken)
	}

	c.HTTP.ListenAddress = "0.0.0.0:8443"
	c.HTTP.BearerTokenFile = write("good", strongToken()+"\n")
	if err := c.ResolveSecrets(); err != nil || c.HTTP.BearerToken != strongToken() {
		t.Fatalf("token file: err=%v token=%q", err, c.HTTP.BearerToken)
	}

	c.HTTP.BearerToken = ""
	c.HTTP.BearerTokenFile = write("short", "hunter2")
	if err := c.ResolveSecrets(); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("short token beyond loopback: %v", err)
	}
	c.HTTP.BearerTokenFile = write("empty", "\n")
	if err := c.ResolveSecrets(); err == nil {
		t.Fatal("an empty token file was accepted")
	}
}

func TestHTTPTimeouts(t *testing.T) {
	var h HTTPConfig
	if h.ReadHeaderTimeout() != 5*time.Second || h.WriteTimeout() != 30*time.Second {
		t.Fatalf("defaults: %v %v", h.ReadHeaderTimeout(), h.WriteTimeout())
	}
	h = HTTPConfig{ReadHeaderTimeoutSeconds: 2, WriteTimeoutSeconds: 9}
	if h.ReadHeaderTimeout() != 2*time.Second || h.WriteTimeout() != 9*time.Second {
		t.Fatalf("overrides: %v %v", h.ReadHeaderTimeout(), h.WriteTimeout())
	}
}

// --- genome restore ----------------------------------------------------

func TestValidate_GenomeRestoreDirectories(t *testing.T) {
	c := minimalValidConfig()
	c.Genome = GenomeConfig{BundleDir: "/var/lib/vg/bundles", RestoreDir: "/var/lib/vg/restored", RescanSeconds: 2}
	requireValid(t, c)

	for name, tc := range map[string]struct {
		g    GenomeConfig
		want string
	}{
		"bundles only":      {GenomeConfig{BundleDir: "/var/lib/vg/bundles"}, "genome.restore_dir required"},
		"restores only":     {GenomeConfig{RestoreDir: "/var/lib/vg/restored"}, "genome.bundle_dir required"},
		"relative":          {GenomeConfig{BundleDir: "bundles", RestoreDir: "/var/lib/vg/restored"}, "must be an absolute path"},
		"same directory":    {GenomeConfig{BundleDir: "/var/lib/vg", RestoreDir: "/var/lib/vg/"}, "separate directories"},
		"restores inside":   {GenomeConfig{BundleDir: "/var/lib/vg", RestoreDir: "/var/lib/vg/restored"}, "separate directories"},
		"bundles inside":    {GenomeConfig{BundleDir: "/var/lib/vg/restored/b", RestoreDir: "/var/lib/vg/restored"}, "separate directories"},
		"negative interval": {GenomeConfig{BundleDir: "/a", RestoreDir: "/b", RescanSeconds: -1}, "rescan_seconds"},
	} {
		t.Run(name, func(t *testing.T) {
			c := minimalValidConfig()
			c.Genome = tc.g
			requireInvalid(t, c, tc.want)
		})
	}

	// Sibling directories that share a name prefix are separate.
	c.Genome = GenomeConfig{BundleDir: "/var/lib/vg/b", RestoreDir: "/var/lib/vg/bb"}
	requireValid(t, c)
}
