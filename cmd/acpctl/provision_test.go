// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// stubRelease is a bin directory with the three binaries provision runs,
// as shell scripts that record their arguments and answer what the real
// ones answer: keygen writes the files the configurations name, identity
// prints a measurement of the family's length, seal-keys lists what it
// sealed. The test reads the record afterwards.
func stubRelease(t *testing.T, measurementBytes int, identityProvider string) (binDir, record string) {
	t.Helper()
	return stubReleaseBoot(t, measurementBytes, identityProvider, "cafe")
}

// stubReleaseBoot is stubRelease whose identity prints boot as the vTPM's
// PCR digest.
func stubReleaseBoot(t *testing.T, measurementBytes int, identityProvider, boot string) (binDir, record string) {
	t.Helper()
	binDir = t.TempDir()
	record = filepath.Join(binDir, "calls.log")
	m := strings.Repeat("ab", measurementBytes)
	keygen := `#!/bin/sh
echo "keygen $*" >> ` + record + `
out=""; while [ $# -gt 0 ]; do case "$1" in -out) out="$2"; shift;; esac; shift; done
mkdir -p "$out/sagvd/tls" "$out/acp-compute/tls" "$out/shared/tls"
for f in sagvd/api_token sagvd/tee_seed sagvd/authority_signing_seed sagvd/audit_signing_seed sagvd/peer_worker_pubkey sagvd/tls/server.crt sagvd/tls/server.key \
         acp-compute/tee_seed acp-compute/worker_signing_seed acp-compute/peer_vault_pubkey acp-compute/tls/client.crt acp-compute/tls/client.key shared/sealing.key shared/workers.json shared/tls/ca.crt; do
  echo "secret-$f" > "$out/$f"
done
echo "the-bearer-token-0123456789abcdef" > "$out/sagvd/api_token"
`
	daemon := func(name string) string {
		return `#!/bin/sh
echo "` + name + ` $*" >> ` + record + `
case "$1" in
  identity) printf '%s\n' '{"tee_provider":"` + identityProvider + `","tee_measurement_hex":"` + m + `","sealer":"stub","audit_kid":"sagvd-audit-demo","audit_public_key_pem":"-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----\n","authority_kid":"sagvd-authority-demo","vtpm":{"pcr_digest_hex":"` + boot + `"}}' ;;
  seal-keys) printf '%s\n' '{"tee":"` + identityProvider + `","measurement_hex":"` + m + `","sealer":"stub","sealed":[{"name":"keys.one","path":"/x"},{"name":"keys.two","path":"/y"}]}' ;;
  *) echo "unknown $1" >&2; exit 2 ;;
esac
`
	}
	for name, body := range map[string]string{"acp-keygen": keygen, "sagvd": daemon("sagvd"), "acp-compute": daemon("acp-compute")} {
		require.NoError(t, os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o755))
	}
	return binDir, record
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var v map[string]any
	require.NoError(t, json.Unmarshal(raw, &v))
	return v
}

func TestProvision_SimulatedDeploymentEndToEnd(t *testing.T) {
	binDir, record := stubRelease(t, 32, "simulated")
	out := filepath.Join(t.TempDir(), "deploy")
	var stdout, stderr bytes.Buffer
	code := provisionCmd([]string{"--out", out, "--bin-dir", binDir, "--provider", "simulated", "--insecure-simulation",
		"--door-command", "/opt/door", "--door-command", "--flag", "--vault-listen", "127.0.0.1:19443", "--max-sessions", "3"}, &stdout, &stderr)
	require.Equal(t, 0, code, stderr.String())
	require.NotContains(t, stdout.String(), "the-bearer-token", "the REST token is never printed")

	calls, err := os.ReadFile(record)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	require.Len(t, lines, 5)
	require.Contains(t, lines[0], "keygen -out "+filepath.Join(out, "secrets")+" -private -quiet")
	require.Contains(t, lines[1], "sagvd identity -config "+filepath.Join(out, "sagvd.json"))
	require.Contains(t, lines[2], "acp-compute identity -config "+filepath.Join(out, "acp-compute.json"))
	require.Contains(t, lines[3], "sagvd seal-keys -config")
	require.Contains(t, lines[4], "acp-compute seal-keys -config")

	sagvd := readJSON(t, filepath.Join(out, "sagvd.json"))
	teeCfg := sagvd["tee"].(map[string]any)
	require.Equal(t, "simulated", teeCfg["provider"])
	require.Equal(t, true, teeCfg["insecure_simulation"])
	require.Equal(t, filepath.Join(out, "secrets", "sagvd", "tee_seed"), teeCfg["seed_path"])
	peer := teeCfg["peer"].(map[string]any)
	require.Equal(t, "simulated", peer["provider"])
	require.Equal(t, filepath.Join(out, "pins", "worker.measurement"), peer["measurement_path"])
	require.Equal(t, filepath.Join(out, "secrets", "sagvd", "peer_worker_pubkey"), peer["public_key_path"])
	require.Equal(t, "127.0.0.1:19443", sagvd["vault"].(map[string]any)["listen_address"])
	require.EqualValues(t, 3, sagvd["runtime"].(map[string]any)["max_sessions"])
	require.Equal(t, filepath.Join(out, "queue", "sagvd-jobs.db"), sagvd["queue"].(map[string]any)["path"])
	// A bounded deployment (ADR 0027): segments of 100 000 events or a
	// day, finished jobs kept thirty days.
	require.Equal(t, float64(100000), sagvd["audit"].(map[string]any)["segment_events"])
	require.Equal(t, float64(86400), sagvd["audit"].(map[string]any)["segment_max_age_seconds"])
	require.Equal(t, float64(30*86400), sagvd["queue"].(map[string]any)["retain_finished_seconds"])
	worker := readJSON(t, filepath.Join(out, "acp-compute.json"))
	require.Equal(t, "127.0.0.1:19443", worker["vault"].(map[string]any)["address"])
	door := worker["genome"].(map[string]any)["door"].(map[string]any)
	require.Equal(t, []any{"/opt/door", "--flag"}, door["command"])
	require.Equal(t, filepath.Join(out, "pins", "vault.measurement"), worker["tee"].(map[string]any)["peer"].(map[string]any)["measurement_path"])
	require.Equal(t, filepath.Join(out, "secrets", "acp-compute", "sealing.key"), worker["keys"].(map[string]any)["session_sealing"].(map[string]any)["material_path"], "the worker seals its own copy")
	wk, err := os.ReadFile(filepath.Join(out, "secrets", "acp-compute", "sealing.key"))
	require.NoError(t, err)
	sk, _ := os.ReadFile(filepath.Join(out, "secrets", "shared", "sealing.key"))
	require.Equal(t, sk, wk)

	pin, err := os.ReadFile(filepath.Join(out, "pins", "vault.measurement"))
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("ab", 32), hex.EncodeToString(pin), "the pin is what identity printed, raw")
	token, err := os.ReadFile(filepath.Join(out, "operator", "api_token"))
	require.NoError(t, err)
	require.Contains(t, string(token), "the-bearer-token")
	auditPub, err := os.ReadFile(filepath.Join(out, "operator", "audit_public_key.pem"))
	require.NoError(t, err)
	require.Contains(t, string(auditPub), "BEGIN PUBLIC KEY")

	res := readJSON(t, filepath.Join(out, "provision.json"))
	require.Equal(t, "vault-genome/acpctl-provision/v1", res["schema"])
	require.Equal(t, "simulated", res["peer_provider"])
	require.Equal(t, strings.Repeat("ab", 32), res["vault"].(map[string]any)["measurement_hex"])
	require.Equal(t, "cafe", res["worker"].(map[string]any)["vtpm_pcr_digest_hex"])
	require.Equal(t, []any{"keys.one", "keys.two"}, res["sealed"].(map[string]any)["sagvd"])
	require.Len(t, res["configs_sha256"].(map[string]any), 2)
	next := res["next"].([]any)
	require.Contains(t, next[0], "sagvd -config")
	for _, f := range []string{"sagvd.json", "acp-compute.json", "provision.json", filepath.Join("operator", "api_token")} {
		st, err := os.Stat(filepath.Join(out, f))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), st.Mode().Perm(), f)
	}
}

func TestProvision_HardwareFamilyPinsTheChainAndTheMeasurement(t *testing.T) {
	binDir, record := stubRelease(t, 48, "gcp-sev-snp")
	out := filepath.Join(t.TempDir(), "deploy")
	chain := filepath.Join(t.TempDir(), "amd-milan-cert_chain.pem")
	require.NoError(t, os.WriteFile(chain, []byte("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n"), 0o644))
	var stdout, stderr bytes.Buffer
	code := provisionCmd([]string{"--out", out, "--bin-dir", binDir, "--provider", "gcp-sev-snp", "--amd-cert-chain", chain,
		"--door-python", "/opt/vg/bin/python3", "--base-model", "/opt/base", "--worker-package", "/opt/worker", "--sealer", "tpm2", "--skip-seal"}, &stdout, &stderr)
	require.Equal(t, 0, code, stderr.String())
	sagvd := readJSON(t, filepath.Join(out, "sagvd.json"))
	teeCfg := sagvd["tee"].(map[string]any)
	require.Equal(t, "gcp-sev-snp", teeCfg["provider"])
	require.Equal(t, "tpm2", teeCfg["sealer"])
	require.Nil(t, teeCfg["seed_path"], "no seed for a hardware family")
	peer := teeCfg["peer"].(map[string]any)
	require.Equal(t, chain, peer["amd_cert_chain_path"])
	require.Equal(t, filepath.Join(out, "vcek-cache"), peer["vcek_cache_dir"])
	require.Nil(t, peer["public_key_path"])
	worker := readJSON(t, filepath.Join(out, "acp-compute.json"))
	door := worker["genome"].(map[string]any)["door"].(map[string]any)
	require.Equal(t, []any{"/opt/vg/bin/python3", "-m", "vg_genome", "door", "--stdin-genome", "--base", "/opt/base", "--device", "cpu"}, door["command"])
	require.Equal(t, []any{"PYTHONPATH=/opt/worker", "TOKENIZERS_PARALLELISM=false"}, door["env"])
	pin, err := os.ReadFile(filepath.Join(out, "pins", "worker.measurement"))
	require.NoError(t, err)
	require.Len(t, pin, 48)
	calls, _ := os.ReadFile(record)
	require.NotContains(t, string(calls), "seal-keys", "--skip-seal leaves the sealing to the operator")
	res := readJSON(t, filepath.Join(out, "provision.json"))
	next := res["next"].([]any)
	require.Contains(t, next[0], "sagvd seal-keys -config")
	require.Equal(t, chain, res["amd_cert_chain"])
}

// Under Azure's paravisor the launch measurement says nothing of the OS:
// each side pins the other's boot as well, from the identity, in place of
// the placeholder the configurations start with (ADR 0037).
func TestProvision_AzurePinsEachSidesBoot(t *testing.T) {
	boot := strings.Repeat("5e", 32)
	binDir, _ := stubReleaseBoot(t, 48, "azure-sev-snp", boot)
	out := filepath.Join(t.TempDir(), "deploy")
	chain := filepath.Join(t.TempDir(), "amd-genoa-cert_chain.pem")
	require.NoError(t, os.WriteFile(chain, []byte("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n"), 0o644))
	args := []string{"--out", out, "--bin-dir", binDir, "--provider", "azure-sev-snp", "--amd-cert-chain", chain,
		"--door-python", "/opt/vg/bin/python3", "--base-model", "/opt/base", "--worker-package", "/opt/worker", "--skip-seal"}
	var stdout, stderr bytes.Buffer
	require.Equal(t, 0, provisionCmd(args, &stdout, &stderr), stderr.String())
	for _, name := range []string{"sagvd.json", "acp-compute.json"} {
		peer := readJSON(t, filepath.Join(out, name))["tee"].(map[string]any)["peer"].(map[string]any)
		require.Equal(t, "azure-sev-snp", peer["provider"], name)
		require.Equal(t, []any{boot}, peer["pcr_digests"], name)
	}
	require.Contains(t, stdout.String(), "sagvd pins acp-compute's boot: "+boot)
	require.Contains(t, stdout.String(), "acp-compute pins sagvd's boot: "+boot)
	res := readJSON(t, filepath.Join(out, "provision.json"))
	for key, path := range res["configs"].(map[string]any) {
		raw, err := os.ReadFile(path.(string))
		require.NoError(t, err)
		sum := sha256.Sum256(raw)
		require.Equal(t, hex.EncodeToString(sum[:]), res["configs_sha256"].(map[string]any)[key], "the digest of %s as it stands", key)
	}
	require.Equal(t, boot, res["worker"].(map[string]any)["vtpm_pcr_digest_hex"])

	// An identity whose vTPM digest is not a digest pins nothing.
	binDir, _ = stubRelease(t, 48, "azure-sev-snp")
	stdout.Reset()
	stderr.Reset()
	args[1], args[3] = filepath.Join(t.TempDir(), "deploy"), binDir
	require.Equal(t, 1, provisionCmd(args, &stdout, &stderr))
	require.Contains(t, stderr.String(), `vtpm.pcr_digest_hex "cafe" is not a 32-byte digest`)
}

func TestProvision_Refusals(t *testing.T) {
	binDir, _ := stubRelease(t, 32, "simulated")
	base := func(extra ...string) []string {
		return append([]string{"--out", filepath.Join(t.TempDir(), "d"), "--bin-dir", binDir, "--door-command", "/opt/door"}, extra...)
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"simulated without the flag":     {base("--provider", "simulated"), "--insecure-simulation"},
		"the GPU family":                 {base("--provider", "azure-cgpu", "--insecure-simulation"), "runbook"},
		"an unknown family":              {base("--provider", "mainframe"), "--provider"},
		"a simulated peer of hardware":   {base("--provider", "gcp-sev-snp", "--peer-provider", "simulated", "--insecure-simulation", "--amd-cert-chain", "/nonexistent"), "both sides are simulated or neither"},
		"a SEV-SNP peer without a chain": {base("--provider", "gcp-sev-snp"), "AMD chain"},
		"an auto peer":                   {base("--provider", "simulated", "--insecure-simulation", "--peer-provider", "auto"), "cannot be auto"},
		"a bad sealer":                   {base("--provider", "simulated", "--insecure-simulation", "--sealer", "hsm"), "--sealer"},
		"no door":                        {[]string{"--out", filepath.Join(t.TempDir(), "d"), "--bin-dir", binDir, "--provider", "simulated", "--insecure-simulation"}, "door"},
		"no out":                         {[]string{"--provider", "simulated"}, "required"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := provisionCmd(tc.args, &stdout, &stderr)
			require.NotEqual(t, 0, code)
			require.Contains(t, stderr.String(), tc.want)
		})
	}
	t.Run("a missing binary", func(t *testing.T) {
		empty := t.TempDir()
		var stdout, stderr bytes.Buffer
		code := provisionCmd([]string{"--out", filepath.Join(t.TempDir(), "d"), "--bin-dir", empty, "--provider", "simulated", "--insecure-simulation", "--door-command", "/opt/door"}, &stdout, &stderr)
		_ = code
		if !strings.Contains(stderr.String(), "was not found") {
			t.Skip("a release's binaries are on PATH on this machine; the lookup fell through to them")
		}
	})
	t.Run("a non-empty directory without --force", func(t *testing.T) {
		out := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(out, "something"), []byte("x"), 0o600))
		var stdout, stderr bytes.Buffer
		code := provisionCmd([]string{"--out", out, "--bin-dir", binDir, "--provider", "simulated", "--insecure-simulation", "--door-command", "/opt/door"}, &stdout, &stderr)
		require.Equal(t, 1, code)
		require.Contains(t, stderr.String(), "--force")
	})
	t.Run("an identity of another family is a warning on the record", func(t *testing.T) {
		otherBin, _ := stubRelease(t, 48, "gcp-tdx")
		chain := filepath.Join(t.TempDir(), "chain.pem")
		require.NoError(t, os.WriteFile(chain, []byte("x"), 0o644))
		out := filepath.Join(t.TempDir(), "d")
		var stdout, stderr bytes.Buffer
		code := provisionCmd([]string{"--out", out, "--bin-dir", otherBin, "--provider", "gcp-sev-snp", "--amd-cert-chain", chain, "--door-command", "/opt/door"}, &stdout, &stderr)
		require.Equal(t, 0, code, stderr.String())
		res := readJSON(t, filepath.Join(out, "provision.json"))
		warnings := res["vault"].(map[string]any)["warnings"].([]any)
		require.Contains(t, warnings[0], "attests as gcp-tdx")
	})
}
