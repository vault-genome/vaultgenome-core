// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/console"
)

const testConsoleCert = `-----BEGIN CERTIFICATE-----
MIIBTDCB/6ADAgECAgEBMAUGAytlcDAmMSQwIgYDVQQDExtjb25zb2xlLnZhdWx0
Z2Vub21lLmludmFsaWQwHhcNMjYxMDMwMDAwMDAwWhcNNDYxMDMwMDAwMDAwWjAm
MSQwIgYDVQQDExtjb25zb2xlLnZhdWx0Z2Vub21lLmludmFsaWQwKjAFBgMrZXAD
IQDGkKw8wO+6dS7wzZ5fI6U3s+o6n2eC1wG1X9f6p1vZ3qNSMFAwDgYDVR0PAQH/
BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMCkGA1UdEQQiMCCCHmNvbnNvbGUu
dmF1bHRnZW5vbWUuaW52YWxpZDAFBgMrZXADQQA=
-----END CERTIFICATE-----
`

// consoleDeployment writes what `acpctl console invite` reads of a deployment.
func consoleDeployment(t *testing.T, withConsole bool) (sagvd, worker, dir string) {
	t.Helper()
	dir = t.TempDir()
	cfg := map[string]any{"keys": map[string]any{"audit_signing": map[string]any{"kid": "audit-kid"}}}
	if withConsole {
		cfg["console"] = map[string]any{"dir": filepath.Join(dir, "console"), "listen_address": "0.0.0.0:9444"}
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "console"), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "console", "tls.crt"), []byte(testConsoleCert), 0o644))
	}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	sagvd = filepath.Join(dir, "sagvd.json")
	require.NoError(t, os.WriteFile(sagvd, raw, 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "operator"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "operator", "audit_public_key.pem"), []byte("audit key"), 0o644))
	measurement := filepath.Join(dir, "vault.measurement")
	require.NoError(t, os.WriteFile(measurement, bytes.Repeat([]byte{0xab}, 48), 0o600))
	chain := filepath.Join(dir, "chain.pem")
	require.NoError(t, os.WriteFile(chain, []byte("the AMD chain"), 0o600))
	roots := filepath.Join(dir, "roots.pem")
	require.NoError(t, os.WriteFile(roots, []byte("the roots"), 0o600))
	attestor := filepath.Join(dir, "attestor")
	require.NoError(t, os.WriteFile(attestor, bytes.Repeat([]byte{1}, 32), 0o600))
	workerCfg, err := json.Marshal(map[string]any{"tee": map[string]any{"peer": map[string]any{
		"provider": "aws-sev-snp", "measurement_path": measurement, "amd_cert_chain_path": chain, "gce_ek_ak_roots_path": roots, "public_key_path": attestor,
		"csp_ids": []string{"CN=cc-us-east-2.amazonaws.com"}, "pcr_digests": []string{strings.Repeat("00", 32)}, "min_reported_tcb": 7,
	}}})
	require.NoError(t, err)
	worker = filepath.Join(dir, "acp-compute.json")
	require.NoError(t, os.WriteFile(worker, workerCfg, 0o600))
	return sagvd, worker, dir
}

// A pass carries the deployment's own pin with its files inline and a code whose
// hash alone stays on the server.
func TestConsoleInvite(t *testing.T) {
	sagvd, worker, dir := consoleDeployment(t, true)
	out := filepath.Join(t.TempDir(), "anna.vgpass")
	var stdout, stderr bytes.Buffer
	rc := consoleCmd([]string{"invite", "--sagvd-config", sagvd, "--worker-config", worker, "--address", "203.0.113.10:9444", "--name", "Anna", "--role", "owner", "--valid", "2h", "--out", out}, &stdout, &stderr)
	require.Equal(t, 0, rc, stderr.String())
	require.Contains(t, stdout.String(), "it works once")

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	var pass console.Pass
	require.NoError(t, json.Unmarshal(raw, &pass))
	require.Equal(t, console.PassSchema, pass.Schema)
	require.Equal(t, "203.0.113.10:9444", pass.ServerLabel, "the address unless a label is given")
	require.Equal(t, "audit-kid", pass.AuditKeyID)
	require.Equal(t, "audit key", pass.AuditPublicKeyPEM)
	require.Equal(t, testConsoleCert, pass.ServerCertPEM)
	require.Equal(t, "aws-sev-snp", pass.Pin.Provider)
	require.Equal(t, hex.EncodeToString(bytes.Repeat([]byte{0xab}, 48)), pass.Pin.MeasurementHex)
	require.Equal(t, "the AMD chain", pass.Pin.AMDCertChainPEM)
	require.Equal(t, "the roots", pass.Pin.GCEEKAKRootsPEM)
	require.Equal(t, hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), pass.Pin.AttestorPublicKeyHex)
	require.Equal(t, []string{"CN=cc-us-east-2.amazonaws.com"}, pass.Pin.CSPIDs)
	require.Equal(t, uint64(7), pass.Pin.MinReportedTCB)
	require.Len(t, pass.InviteCode, 64)
	require.WithinDuration(t, time.Now().Add(2*time.Hour), pass.ExpiresAt, time.Minute)

	stored := filepath.Join(dir, "console", "invites", console.InviteKey(pass.InviteCode)+".json")
	inviteRaw, err := os.ReadFile(stored)
	require.NoError(t, err)
	require.NotContains(t, string(inviteRaw), pass.InviteCode, "the server keeps the hash, not the code")
	var inv console.Invite
	require.NoError(t, json.Unmarshal(inviteRaw, &inv))
	require.Equal(t, "Anna", inv.Name)
	require.Equal(t, console.RoleOwner, inv.Role)

	// Never over a file already there.
	rc = consoleCmd([]string{"invite", "--sagvd-config", sagvd, "--worker-config", worker, "--address", "a:1", "--name", "Anna", "--out", out}, &stdout, &stderr)
	require.Equal(t, 1, rc)
}

func TestConsoleInviteRefusals(t *testing.T) {
	sagvd, worker, dir := consoleDeployment(t, true)
	noConsole, _, _ := consoleDeployment(t, false)
	out := func() string { return filepath.Join(t.TempDir(), "p.vgpass") }
	badJSON := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(badJSON, []byte("not json"), 0o600))
	peerless := filepath.Join(dir, "peerless.json")
	require.NoError(t, os.WriteFile(peerless, []byte(`{"tee":{"peer":{"provider":"aws-sev-snp","measurement_path":"/no/such"}}}`), 0o600))
	cases := []struct {
		name string
		args []string
		rc   int
		want string
	}{
		{"nothing", nil, 2, "usage"},
		{"unknown", []string{"nonsense"}, 2, "unknown subcommand"},
		{"no flags", []string{"invite"}, 2, "required"},
		{"bad flag", []string{"invite", "--nope"}, 2, ""},
		{"bad role", []string{"invite", "--sagvd-config", sagvd, "--worker-config", worker, "--address", "a:1", "--name", "A", "--role", "admin", "--out", out()}, 2, "--role"},
		{"no daemon config", []string{"invite", "--sagvd-config", "/no/such", "--worker-config", worker, "--address", "a:1", "--name", "A", "--out", out()}, 1, "--sagvd-config"},
		{"bad daemon config", []string{"invite", "--sagvd-config", badJSON, "--worker-config", worker, "--address", "a:1", "--name", "A", "--out", out()}, 1, "--sagvd-config"},
		{"no console", []string{"invite", "--sagvd-config", noConsole, "--worker-config", worker, "--address", "a:1", "--name", "A", "--out", out()}, 1, "no console listener"},
		{"no worker config", []string{"invite", "--sagvd-config", sagvd, "--worker-config", "/no/such", "--address", "a:1", "--name", "A", "--out", out()}, 1, "--worker-config"},
		{"bad worker config", []string{"invite", "--sagvd-config", sagvd, "--worker-config", badJSON, "--address", "a:1", "--name", "A", "--out", out()}, 1, "--worker-config"},
		{"no pin", []string{"invite", "--sagvd-config", sagvd, "--worker-config", peerless, "--address", "a:1", "--name", "A", "--out", out()}, 1, "measurement_path"},
		{"no audit key", []string{"invite", "--sagvd-config", sagvd, "--worker-config", worker, "--audit-pubkey", "/no/such", "--address", "a:1", "--name", "A", "--out", out()}, 1, "--audit-pubkey"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			rc := consoleCmd(c.args, &stdout, &stderr)
			require.Equal(t, c.rc, rc, stderr.String())
			require.Contains(t, stderr.String(), c.want)
		})
	}
	var stdout, stderr bytes.Buffer
	require.Equal(t, 0, consoleCmd([]string{"help"}, &stdout, &stderr))
	require.Contains(t, stdout.String(), "invite")

	// Before sagvd has started there is no certificate to pin.
	fresh, freshWorker, freshDir := consoleDeployment(t, true)
	require.NoError(t, os.Remove(filepath.Join(freshDir, "console", "tls.crt")))
	rc := consoleCmd([]string{"invite", "--sagvd-config", fresh, "--worker-config", freshWorker, "--address", "a:1", "--name", "A", "--out", out()}, &stdout, &stderr)
	require.Equal(t, 1, rc)
	require.Contains(t, stderr.String(), "first starts")
}

// The pin refuses a file it cannot read, one by one.
func TestConsolePinOf(t *testing.T) {
	dir := t.TempDir()
	m := filepath.Join(dir, "m")
	require.NoError(t, os.WriteFile(m, []byte{1, 2}, 0o600))
	_, err := consolePinOf(consolePeer{Provider: "x", MeasurementPath: m, AMDCertChainPath: "/no/such"})
	require.ErrorContains(t, err, "amd_cert_chain_path")
	_, err = consolePinOf(consolePeer{Provider: "x", MeasurementPath: m, GCEEKAKRootsPath: "/no/such"})
	require.ErrorContains(t, err, "gce_ek_ak_roots_path")
	_, err = consolePinOf(consolePeer{Provider: "x", MeasurementPath: m, PublicKeyPath: "/no/such"})
	require.ErrorContains(t, err, "public_key_path")
}
