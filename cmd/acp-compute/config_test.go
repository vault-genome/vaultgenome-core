// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// goodConfig returns a minimal Config that passes Validate. Every
// test below starts from this and mutates the one field it wants to
// exercise, ensuring that no test accidentally fails on an unrelated
// validation rule.
func goodConfig() Config {
	c := DefaultConfig()
	c.TEE.SeedPath = "/tmp/acp-compute-test/tee.seed"
	c.TEE.Peer.PublicKeyPath = "/tmp/acp-compute-test/peer.pub"
	c.TEE.Peer.MeasurementPath = "/tmp/acp-compute-test/peer.meas"
	c.Keys.WorkerSigning.KeyID = "worker-sign-1"
	c.Keys.WorkerSigning.SeedPath = "/tmp/acp-compute-test/worker.seed"
	c.Keys.SessionSealing.KeyID = "session-seal-1"
	c.Keys.SessionSealing.MaterialPath = "/tmp/acp-compute-test/session.key"
	return c
}

func TestDefaultConfig_IsSelfConsistent(t *testing.T) {
	t.Parallel()
	c := DefaultConfig()
	// Default is partial; it is specifically meant as an overlay
	// target for JSON decoding, and expectedly fails Validate because
	// path fields are empty.
	err := c.Validate()
	require.Error(t, err, "DefaultConfig alone must not validate")
	require.Contains(t, err.Error(), "tee.seed_path")
}

func TestConfig_Validate_Happy(t *testing.T) {
	t.Parallel()
	require.NoError(t, goodConfig().Validate())
}

func TestConfig_Validate_RejectsEmptyVaultAddress(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Vault.Address = ""
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault.address required")
}

func TestConfig_Validate_RejectsMalformedVaultAddress(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Vault.Address = "not-a-host-port"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault.address invalid")
}

func TestConfig_Validate_TLSFieldsRequiredWhenEnabled(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Vault.TLS.Enabled = true
	err := c.Validate()
	require.Error(t, err)
	for _, want := range []string{
		"vault.tls.client_cert",
		"vault.tls.client_key",
		"vault.tls.ca_bundle",
		"vault.tls.server_name",
	} {
		require.Contains(t, err.Error(), want, "expected missing-field complaint: %s", want)
	}
}

func TestConfig_Validate_TLSIgnoredWhenDisabled(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Vault.TLS.Enabled = false
	c.Vault.TLS.ClientCert = "" // still empty — must not complain
	require.NoError(t, c.Validate())
}

func TestConfig_Validate_RejectsEmptyWorkloadDescriptor(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.TEE.WorkloadDescriptor = ""
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "tee.workload_descriptor required")
}

func TestConfig_Validate_RejectsEmptyKeyIDs(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Keys.WorkerSigning.KeyID = ""
	c.Keys.SessionSealing.KeyID = ""
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "keys.worker_signing.kid required")
	require.Contains(t, err.Error(), "keys.session_sealing.kid required")
}

func TestConfig_Validate_RejectsNonPositiveTimeouts(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Runtime.JobTimeoutSeconds = 0
	c.Runtime.HandshakeTimeoutSeconds = -5
	c.Runtime.DialBackoffInitialMs = 0
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "job_timeout_seconds")
	require.Contains(t, err.Error(), "handshake_timeout_seconds")
	require.Contains(t, err.Error(), "dial_backoff_initial_ms")
}

func TestConfig_Validate_RejectsBackoffInversion(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Runtime.DialBackoffInitialMs = 1000
	c.Runtime.DialBackoffMaxMs = 500
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "dial_backoff_max_ms")
}

func TestConfig_Validate_RejectsNegativeIdle(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Runtime.IdleBetweenJobsMs = -1
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "idle_between_jobs_ms")
}

func TestConfig_Validate_RejectsInvalidLogLevel(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Log.Level = "louder"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "log.level")
}

func TestConfig_Validate_RejectsInvalidLogFormat(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Log.Format = "xml"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "log.format")
}

func TestConfig_Validate_AggregatesAllProblems(t *testing.T) {
	t.Parallel()
	// Intentionally break two unrelated rules and assert BOTH appear.
	c := goodConfig()
	c.Vault.Address = ""
	c.Log.Level = "shouting"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault.address required")
	require.Contains(t, err.Error(), "log.level")
}

func TestRuntime_DurationAccessors(t *testing.T) {
	t.Parallel()
	r := RuntimeConfig{
		JobTimeoutSeconds:       5,
		HandshakeTimeoutSeconds: 7,
		DialBackoffInitialMs:    250,
		DialBackoffMaxMs:        9000,
		IdleBetweenJobsMs:       42,
	}
	require.Equal(t, 5*time.Second, r.JobTimeout())
	require.Equal(t, 7*time.Second, r.HandshakeTimeout())
	require.Equal(t, 250*time.Millisecond, r.DialBackoffInitial())
	require.Equal(t, 9*time.Second, r.DialBackoffMax())
	require.Equal(t, 42*time.Millisecond, r.IdleBetweenJobs())
}

func TestDecodeConfig_OverlaysDefaults(t *testing.T) {
	t.Parallel()
	// Only set a few overrides; everything else must come from
	// DefaultConfig. We verify by asserting an unset runtime knob keeps
	// its default value.
	jsonBody := `{
		"vault": {"address": "10.0.0.5:7443"},
		"tee":   {"workload_descriptor": "custom-worker-v2"}
	}`
	c, err := DecodeConfig(strings.NewReader(jsonBody))
	require.NoError(t, err)
	require.Equal(t, "10.0.0.5:7443", c.Vault.Address)
	require.Equal(t, "custom-worker-v2", c.TEE.WorkloadDescriptor)
	require.Equal(t, 120, c.Runtime.JobTimeoutSeconds, "default must survive partial override")
	require.Equal(t, "info", c.Log.Level)
}

func TestDecodeConfig_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	// An operator typo — `vault.addres` (missing 's') — must fail loud
	// at startup, not silently ignore the key and use the default.
	jsonBody := `{"vault": {"addres": "x:1"}}`
	_, err := DecodeConfig(strings.NewReader(jsonBody))
	require.Error(t, err)
}

func TestLoadConfigFile_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "acp-compute.json")
	body := `{
		"vault":   {"address": "127.0.0.1:6443"},
		"tee":     {
			"workload_descriptor": "test-worker",
			"seed_path": "/x/tee.seed",
			"peer": {"public_key_path": "/x/peer.pub", "measurement_path": "/x/peer.meas"}
		},
		"keys": {
			"worker_signing":  {"kid": "wk-1", "seed_path": "/x/w.seed"},
			"session_sealing": {"kid": "ss-1", "material_path": "/x/ss.key"}
		}
	}`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	c, err := LoadConfigFile(path)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:6443", c.Vault.Address)
	require.Equal(t, "wk-1", c.Keys.WorkerSigning.KeyID)

	// End-to-end with validation: default timeouts + supplied paths
	// must pass the full check.
	require.NoError(t, c.Validate())
}

func TestLoadConfigFile_MissingFileErrors(t *testing.T) {
	t.Parallel()
	_, err := LoadConfigFile("/no/such/path/acp-compute.json")
	require.Error(t, err)
}
