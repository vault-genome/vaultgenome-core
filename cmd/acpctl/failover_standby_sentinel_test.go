// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/vault/failover"
)

// The operator names the standby's own sentinel in the policy, before the
// failure (ADR 0041): its key, and the measurement its records must be
// attested at. Without the flags the policy is the v1 it always was.
func TestFailover_IssueNamesTheStandbySentinel(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	opSeed, opPub := operatorKey(t, dir)
	primaryDir, standbyDir := filepath.Join(dir, "primary"), filepath.Join(dir, "standby")
	require.NoError(t, os.Mkdir(primaryDir, 0o755))
	require.NoError(t, os.Mkdir(standbyDir, 0o755))
	_, primaryPub, _ := sentinelKeys(t, primaryDir)
	_, standbyPub, _ := sentinelKeys(t, standbyDir)
	measurement := strings.Repeat("ab", 48)
	policy := filepath.Join(dir, "failover.json")
	issue := []string{"issue", "--key", opSeed, "--kid", "operator-1", "--serial", "5", "--sentinel-pub", primaryPub,
		"--standby-kind", "gcp-sev-snp", "--standby-endpoint", "https://standby.example:8443", "--standby-measurement", measurement,
		"--heartbeat-timeout", "90s", "--out", policy}
	named := append(append([]string{}, issue...), "--standby-sentinel-pub", standbyPub, "--standby-sentinel-measurement", strings.ToUpper(measurement))

	code, stdout, stderr := runCmd(failoverRun, named...)
	require.Equal(t, 0, code, stderr)
	require.Regexp(t, `-> gcp-sev-snp https://standby\.example:8443 \(its own sentinel: sentinel-[0-9a-f]{16}, ed25519\), until `, stdout)

	code, stdout, stderr = runCmd(failoverRun, "verify", "--in", policy, "--pubkey", opPub, "--kid", "operator-1")
	require.Equal(t, 0, code, stderr)
	require.Regexp(t, `(?m)^  standby sentinel: sentinel-[0-9a-f]{16} \(ed25519\), measurements `+measurement+` \(every record must carry its report\)$`, stdout)

	code, stdout, _ = runCmd(failoverRun, "verify", "--in", policy, "--pubkey", opPub, "--kid", "operator-1", "--json")
	require.Equal(t, 0, code)
	var v struct {
		Policy          failover.Policy `json:"policy"`
		Sentinel        string          `json:"sentinel"`
		StandbySentinel string          `json:"standby_sentinel"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &v))
	require.Equal(t, failover.SchemaV2, v.Policy.Schema)
	require.NotNil(t, v.Policy.Standby.Sentinel)
	require.Equal(t, []string{measurement}, v.Policy.Standby.Sentinel.Measurements)
	require.Empty(t, v.Policy.Standby.Sentinel.AttestorPublicKey)
	require.Regexp(t, `^sentinel-[0-9a-f]{16}$`, v.StandbySentinel)
	require.NotEqual(t, v.Sentinel, v.StandbySentinel, "each machine's sentinel has its own key")

	// Without the flags: schema v1, no such field, and verify says so.
	v1 := filepath.Join(dir, "v1.json")
	code, stdout, stderr = runCmd(failoverRun, replace(issue, policy, v1)...)
	require.Equal(t, 0, code, stderr)
	require.NotContains(t, stdout, "its own sentinel")
	raw, err := os.ReadFile(v1)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"schema": "`+failover.Schema+`"`)
	require.NotContains(t, string(raw), `"sentinel":`)
	code, stdout, _ = runCmd(failoverRun, "verify", "--in", v1, "--pubkey", opPub, "--kid", "operator-1")
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "  standby sentinel: not named\n")
	code, stdout, _ = runCmd(failoverRun, "verify", "--in", v1, "--pubkey", opPub, "--kid", "operator-1", "--json")
	require.Equal(t, 0, code)
	require.NotContains(t, stdout, "standby_sentinel")

	// A simulated standby's sentinel is pinned by its attestation key too.
	simulated := func(args []string) []string {
		return replace(replace(replace(args, "gcp-sev-snp", "simulated"), measurement, strings.Repeat("ab", 32)), strings.ToUpper(measurement), strings.Repeat("cd", 32))
	}
	sim := filepath.Join(dir, "sim.json")
	code, _, stderr = runCmd(failoverRun, append(simulated(replace(named, policy, sim)), "--standby-sentinel-attestor-pub", opPub)...)
	require.Equal(t, 0, code, stderr)
	code, stdout, _ = runCmd(failoverRun, "verify", "--in", sim, "--pubkey", opPub, "--kid", "operator-1", "--json")
	require.Equal(t, 0, code)
	require.NoError(t, json.Unmarshal([]byte(stdout), &v))
	require.Len(t, v.Policy.Standby.Sentinel.AttestorPublicKey, 32)

	// Refused before anything is signed or written.
	absent := filepath.Join(dir, "absent.pem")
	for name, tc := range map[string]struct {
		args []string
		code int
		want string
	}{
		"a key without a measurement":   {append(append([]string{}, issue...), "--standby-sentinel-pub", standbyPub), 2, "--standby-sentinel-pub and --standby-sentinel-measurement go together"},
		"a measurement without a key":   {append(append([]string{}, issue...), "--standby-sentinel-measurement", measurement), 2, "go together"},
		"an attestation key alone":      {append(append([]string{}, issue...), "--standby-sentinel-attestor-pub", opPub), 2, "--standby-sentinel-attestor-pub goes with --standby-sentinel-pub"},
		"the primary's sentinel key":    {replace(named, standbyPub, primaryPub), 1, "the standby's sentinel key is the primary's"},
		"simulated, no attestation key": {simulated(named), 1, "a simulated standby sentinel is pinned by its attestation key"},
		"hardware, an attestation key":  {append(append([]string{}, named...), "--standby-sentinel-attestor-pub", opPub), 1, "standby sentinel has no attestation key to pin"},
		"no such key file":              {replace(named, standbyPub, absent), 1, "--standby-sentinel-pub: read pubkey"},
		"no such attestation key file":  {append(simulated(named), "--standby-sentinel-attestor-pub", absent), 1, "--standby-sentinel-attestor-pub: read pubkey"},
		"a measurement that is not hex": {replace(named, strings.ToUpper(measurement), "not-hex"), 1, "standby sentinel measurement"},
	} {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "refused.json")
			code, _, stderr := runCmd(failoverRun, replace(tc.args, policy, out)...)
			require.Equal(t, tc.code, code, stderr)
			require.Contains(t, stderr, tc.want)
			require.NoFileExists(t, out)
		})
	}
}
