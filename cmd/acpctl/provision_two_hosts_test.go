// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Provisioning across two hosts (ADR 0028): the authority writes the
// worker's bundle and keeps none of the worker's secrets; the worker
// joins from the bundle and writes its identity; the authority pins it.

// authorityStep runs provision authority over a stub release into out and
// returns the bundle's path.
func authorityStep(t *testing.T, binDir, out string, extra ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := append([]string{"authority", "--out", out, "--bin-dir", binDir, "--provider", "simulated", "--insecure-simulation",
		"--vault-listen", "0.0.0.0:19443", "--vault-address", "10.0.0.5:19443"}, extra...)
	code := provisionCmd(args, &stdout, &stderr)
	require.Equal(t, 0, code, stderr.String())
	require.NotContains(t, stdout.String(), "the-bearer-token")
	return filepath.Join(out, bundleName)
}

func TestProvisionAuthority_WritesTheBundleAndKeepsNoWorkerSecret(t *testing.T) {
	binDir, record := stubRelease(t, 32, "simulated")
	out := filepath.Join(t.TempDir(), "authority")

	// A listener on every interface needs the address the worker dials.
	var stdout, stderr bytes.Buffer
	code := provisionCmd([]string{"authority", "--out", out, "--bin-dir", binDir, "--provider", "simulated", "--insecure-simulation", "--vault-listen", "0.0.0.0:19443"}, &stdout, &stderr)
	require.Equal(t, 1, code)
	require.Contains(t, stderr.String(), "--vault-address")

	bundle := authorityStep(t, binDir, out, "--worker-descriptor", "acp-compute-two-hosts-v1", "--max-sessions", "2")

	// The authority's host ran keygen, its own identity and its own
	// sealing — nothing of the worker's.
	calls, err := os.ReadFile(record)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	require.Len(t, lines, 3, string(calls))
	require.Contains(t, lines[0], "keygen -out "+filepath.Join(out, "secrets"))
	require.Contains(t, lines[1], "sagvd identity -config "+filepath.Join(out, "sagvd.json"))
	require.Contains(t, lines[2], "sagvd seal-keys -config")

	// The worker's secrets are in the bundle and gone from this host.
	_, err = os.Stat(filepath.Join(out, "secrets", "acp-compute"))
	require.True(t, os.IsNotExist(err), "the worker's secrets stayed on the authority's host")
	_, err = os.Stat(filepath.Join(out, "acp-compute.json"))
	require.True(t, os.IsNotExist(err), "no worker configuration on the authority's host")
	st, err := os.Stat(bundle)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	m, files, err := readWorkerBundle(bundle)
	require.NoError(t, err)
	require.Equal(t, workerBundleSchema, m.Schema)
	require.Equal(t, "simulated", m.Authority.Provider)
	require.Equal(t, strings.Repeat("ab", 32), m.Authority.MeasurementHex)
	require.Equal(t, "10.0.0.5:19443", m.Authority.VaultAddress)
	require.Equal(t, "localhost", m.Authority.VaultServerName)
	require.Empty(t, m.Authority.AMDCertChain)
	require.Equal(t, "simulated", m.Worker.Provider)
	require.Equal(t, "acp-compute-two-hosts-v1", m.Worker.Descriptor)
	require.True(t, m.Worker.Simulated)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	require.ElementsMatch(t, []string{
		"secrets/acp-compute/worker_signing_seed", "secrets/acp-compute/sealing.key",
		"secrets/acp-compute/tls/client.crt", "secrets/acp-compute/tls/client.key",
		"secrets/acp-compute/tee_seed", "secrets/acp-compute/peer_vault_pubkey",
		"secrets/shared/tls/ca.crt", "pins/vault.measurement",
	}, names)
	require.Equal(t, "secret-shared/sealing.key\n", string(files["secrets/acp-compute/sealing.key"]), "the worker's copy of the session sealing key")
	require.Equal(t, strings.Repeat("ab", 32), hex.EncodeToString(files["pins/vault.measurement"]), "the authority's measurement is the worker's pin")
	for name, data := range files {
		require.Equal(t, m.Files[name], sha256Hex(data), name)
	}
	// Nothing of the authority's travels.
	for name := range files {
		require.False(t, strings.HasPrefix(name, "secrets/sagvd/"), name)
	}

	sagvd := readJSON(t, filepath.Join(out, "sagvd.json"))
	require.Equal(t, "0.0.0.0:19443", sagvd["vault"].(map[string]any)["listen_address"])
	require.EqualValues(t, 2, sagvd["runtime"].(map[string]any)["max_sessions"])
	peer := sagvd["tee"].(map[string]any)["peer"].(map[string]any)
	require.Equal(t, filepath.Join(out, "pins", "worker.measurement"), peer["measurement_path"])
	pin, err := os.ReadFile(filepath.Join(out, "pins", "worker.measurement"))
	require.NoError(t, err)
	require.Equal(t, make([]byte, 32), pin, "the worker's pin waits for pin-worker")

	res := readJSON(t, filepath.Join(out, "provision.json"))
	require.Equal(t, "authority", res["role"])
	require.Equal(t, "awaiting-worker", res["phase"])
	require.Equal(t, bundle, res["worker_bundle"])
	require.Equal(t, sha256File(t, bundle), res["worker_bundle_sha256"])
	require.Equal(t, "10.0.0.5:19443", res["vault_address"])
	require.Equal(t, "simulated", res["worker"].(map[string]any)["provider"])
	require.Equal(t, "", res["worker"].(map[string]any)["measurement_hex"])
	next := strings.Join(anyStrings(res["next"]), "\n")
	require.Contains(t, next, "provision join --bundle")
	require.Contains(t, next, "provision pin-worker --out "+out)
	require.Contains(t, next, "pins are read at start")
	auditPub, err := os.ReadFile(filepath.Join(out, "operator", "audit_public_key.pem"))
	require.NoError(t, err)
	require.Contains(t, string(auditPub), "BEGIN PUBLIC KEY")
}

func TestProvisionJoin_UnpacksConfiguresIdentifiesAndSeals(t *testing.T) {
	binDir, record := stubRelease(t, 32, "simulated")
	bundle := authorityStep(t, binDir, filepath.Join(t.TempDir(), "authority"), "--worker-descriptor", "acp-compute-two-hosts-v1")
	require.NoError(t, os.WriteFile(record, nil, 0o600))
	// Carried to the worker's host.
	carried := filepath.Join(t.TempDir(), "carried.tar")
	require.NoError(t, copyFile(bundle, carried, 0o600))

	out := filepath.Join(t.TempDir(), "worker")
	var stdout, stderr bytes.Buffer
	code := provisionCmd([]string{"join", "--bundle", carried, "--out", out, "--bin-dir", binDir, "--provider", "simulated", "--insecure-simulation",
		"--door-command", "/opt/door", "--door-command", "--flag", "--worker-health", "127.0.0.1:19082", "--log-level", "debug"}, &stdout, &stderr)
	require.Equal(t, 0, code, stderr.String())

	calls, err := os.ReadFile(record)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	require.Len(t, lines, 2, string(calls))
	require.Contains(t, lines[0], "acp-compute identity -config "+filepath.Join(out, "acp-compute.json"))
	require.Contains(t, lines[1], "acp-compute seal-keys -config "+filepath.Join(out, "acp-compute.json"))

	for _, f := range []string{"secrets/acp-compute/worker_signing_seed", "secrets/acp-compute/sealing.key", "secrets/acp-compute/tls/client.crt",
		"secrets/acp-compute/tls/client.key", "secrets/acp-compute/tee_seed", "secrets/acp-compute/peer_vault_pubkey", "secrets/shared/tls/ca.crt", "pins/vault.measurement"} {
		st, err := os.Stat(filepath.Join(out, f))
		require.NoError(t, err, f)
		require.Equal(t, os.FileMode(0o600), st.Mode().Perm(), f)
	}
	_, err = os.Stat(filepath.Join(out, "secrets", "sagvd"))
	require.True(t, os.IsNotExist(err), "nothing of the authority's on the worker's host")

	worker := readJSON(t, filepath.Join(out, "acp-compute.json"))
	vault := worker["vault"].(map[string]any)
	require.Equal(t, "10.0.0.5:19443", vault["address"])
	require.Equal(t, "localhost", vault["tls"].(map[string]any)["server_name"])
	require.Equal(t, filepath.Join(out, "secrets", "shared", "tls", "ca.crt"), vault["tls"].(map[string]any)["ca_bundle"])
	teeCfg := worker["tee"].(map[string]any)
	require.Equal(t, "acp-compute-two-hosts-v1", teeCfg["workload_descriptor"])
	require.Equal(t, filepath.Join(out, "secrets", "acp-compute", "tee_seed"), teeCfg["seed_path"])
	peer := teeCfg["peer"].(map[string]any)
	require.Equal(t, "simulated", peer["provider"])
	require.Equal(t, filepath.Join(out, "pins", "vault.measurement"), peer["measurement_path"])
	require.Equal(t, filepath.Join(out, "secrets", "acp-compute", "peer_vault_pubkey"), peer["public_key_path"])
	require.Equal(t, filepath.Join(out, "secrets", "acp-compute", "sealing.key"), worker["keys"].(map[string]any)["session_sealing"].(map[string]any)["material_path"])
	require.Equal(t, []any{"/opt/door", "--flag"}, worker["genome"].(map[string]any)["door"].(map[string]any)["command"])
	require.Equal(t, "127.0.0.1:19082", worker["health"].(map[string]any)["listen_address"])

	res := readJSON(t, filepath.Join(out, "provision.json"))
	require.Equal(t, "worker", res["role"])
	require.Equal(t, "joined", res["phase"])
	require.Equal(t, "10.0.0.5:19443", res["vault_address"])
	require.Equal(t, strings.Repeat("ab", 32), res["vault"].(map[string]any)["measurement_hex"], "what this worker pins")
	require.Equal(t, strings.Repeat("ab", 32), res["worker"].(map[string]any)["measurement_hex"])
	require.Equal(t, filepath.Join(out, "acp-compute-identity.json"), res["worker"].(map[string]any)["identity_file"])
	_, err = os.Stat(filepath.Join(out, "acp-compute-identity.json"))
	require.NoError(t, err)
	require.Equal(t, []any{"keys.one", "keys.two"}, res["sealed"].(map[string]any)["acp-compute"])
	next := strings.Join(anyStrings(res["next"]), "\n")
	require.Contains(t, next, "delete "+carried)
	require.Contains(t, next, "pin-worker")
	require.Contains(t, stdout.String(), "identity for the authority: "+filepath.Join(out, "acp-compute-identity.json"))
}

func TestProvisionJoin_Refusals(t *testing.T) {
	binDir, _ := stubRelease(t, 32, "simulated")
	bundle := authorityStep(t, binDir, filepath.Join(t.TempDir(), "authority"))
	m, files, err := readWorkerBundle(bundle)
	require.NoError(t, err)
	join := func(bundlePath string, extra ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		args := append([]string{"join", "--bundle", bundlePath, "--out", filepath.Join(t.TempDir(), "w"), "--bin-dir", binDir, "--door-command", "/opt/door"}, extra...)
		return provisionCmd(args, &stdout, &stderr), stderr.String()
	}

	// A file changed on the way: the hash in the manifest says so.
	tampered := rewriteBundle(t, m, files, func(f map[string][]byte) { f["secrets/acp-compute/worker_signing_seed"] = []byte("another seed") })
	code, msg := join(tampered, "--provider", "simulated", "--insecure-simulation")
	require.Equal(t, 1, code)
	require.Contains(t, msg, "does not hash to what the manifest says")

	// A file the manifest does not list.
	extra := rewriteBundle(t, m, files, func(f map[string][]byte) { f["secrets/acp-compute/extra"] = []byte("x") })
	code, msg = join(extra, "--provider", "simulated", "--insecure-simulation")
	require.Equal(t, 1, code)
	require.Contains(t, msg, "not in its manifest")

	// A file the manifest lists but the bundle lacks.
	missing := rewriteBundle(t, m, files, func(f map[string][]byte) { delete(f, "secrets/shared/tls/ca.crt") })
	code, msg = join(missing, "--provider", "simulated", "--insecure-simulation")
	require.Equal(t, 1, code)
	require.Contains(t, msg, "not in the bundle")

	// Another family than the authority provisioned the worker for.
	hwBin, _ := stubRelease(t, 48, "gcp-sev-snp")
	var stdout, stderr bytes.Buffer
	code = provisionCmd([]string{"join", "--bundle", bundle, "--out", filepath.Join(t.TempDir(), "w"), "--bin-dir", hwBin, "--provider", "gcp-sev-snp", "--door-command", "/opt/door"}, &stdout, &stderr)
	require.Equal(t, 1, code)
	require.Contains(t, stderr.String(), "provisioned the worker as simulated")

	// The simulated family without the flag; no door; no bundle; not a bundle.
	code, msg = join(bundle, "--provider", "simulated")
	require.Equal(t, 1, code)
	require.Contains(t, msg, "--insecure-simulation")
	stdout.Reset()
	stderr.Reset()
	code = provisionCmd([]string{"join", "--bundle", bundle, "--out", filepath.Join(t.TempDir(), "w"), "--bin-dir", binDir, "--provider", "simulated", "--insecure-simulation"}, &stdout, &stderr)
	require.Equal(t, 1, code)
	require.Contains(t, stderr.String(), "door")
	stderr.Reset()
	require.Equal(t, 2, provisionCmd([]string{"join", "--out", "x"}, &stdout, &stderr))
	require.Contains(t, stderr.String(), "--bundle are required")
	notTar := filepath.Join(t.TempDir(), "not.tar")
	require.NoError(t, os.WriteFile(notTar, []byte("hello"), 0o600))
	code, msg = join(notTar, "--provider", "simulated", "--insecure-simulation")
	require.Equal(t, 1, code)
	require.Contains(t, msg, "--bundle")
}

func TestProvisionPinWorker_CompletesTheDeployment(t *testing.T) {
	binDir, _ := stubRelease(t, 32, "simulated")
	out := filepath.Join(t.TempDir(), "authority")
	authorityStep(t, binDir, out)
	identity := func(provider, measurementHex string) string {
		p := filepath.Join(t.TempDir(), "acp-compute-identity.json")
		require.NoError(t, os.WriteFile(p, []byte(`{"tee_provider":"`+provider+`","tee_measurement_hex":"`+measurementHex+`","sealer":"stub","vtpm":{"pcr_digest_hex":"beef"}}`), 0o600))
		return p
	}
	pin := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := provisionCmd(append([]string{"pin-worker", "--out", out}, args...), &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}

	// The wrong length, then another family, are refused before anything
	// is written.
	code, _, msg := pin("--identity", identity("simulated", strings.Repeat("cd", 48)))
	require.Equal(t, 1, code)
	require.Contains(t, msg, "not a 32-byte measurement")
	code, _, msg = pin("--identity", identity("gcp-tdx", strings.Repeat("cd", 32)))
	require.Equal(t, 1, code)
	require.Contains(t, msg, "attests as gcp-tdx")
	got, err := os.ReadFile(filepath.Join(out, "pins", "worker.measurement"))
	require.NoError(t, err)
	require.Equal(t, make([]byte, 32), got, "nothing pinned by a refusal")

	code, stdout, msg := pin("--identity", identity("simulated", strings.Repeat("cd", 32)))
	require.Equal(t, 0, code, msg)
	require.Contains(t, stdout, "pins the worker "+strings.Repeat("cd", 32))
	got, err = os.ReadFile(filepath.Join(out, "pins", "worker.measurement"))
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("cd", 32), hex.EncodeToString(got))
	res := readJSON(t, filepath.Join(out, "provision.json"))
	require.Equal(t, "complete", res["phase"])
	require.Equal(t, "authority", res["role"])
	worker := res["worker"].(map[string]any)
	require.Equal(t, strings.Repeat("cd", 32), worker["measurement_hex"])
	require.Equal(t, "beef", worker["vtpm_pcr_digest_hex"])
	require.Equal(t, filepath.Join(out, "acp-compute-identity.json"), worker["identity_file"])
	require.Nil(t, worker["warnings"])
	next := strings.Join(anyStrings(res["next"]), "\n")
	require.Contains(t, next, "pins are read at start")
	require.Equal(t, res["vault"].(map[string]any)["measurement_hex"], strings.Repeat("ab", 32), "the authority's side stays")

	// Pinned already: --force pins another, and records a family mismatch
	// as a warning.
	code, _, msg = pin("--identity", identity("simulated", strings.Repeat("ef", 32)))
	require.Equal(t, 1, code)
	require.Contains(t, msg, "already")
	code, _, msg = pin("--identity", identity("gcp-tdx", strings.Repeat("ef", 32)), "--force")
	require.Equal(t, 0, code, msg)
	res = readJSON(t, filepath.Join(out, "provision.json"))
	require.Contains(t, res["worker"].(map[string]any)["warnings"].([]any)[0], "attests as gcp-tdx")

	// Not an authority's deployment.
	var stdout2, stderr2 bytes.Buffer
	require.Equal(t, 1, provisionCmd([]string{"pin-worker", "--out", t.TempDir(), "--identity", identity("simulated", strings.Repeat("cd", 32))}, &stdout2, &stderr2))
	require.Contains(t, stderr2.String(), "provision authority wrote")
	require.Equal(t, 2, provisionCmd([]string{"pin-worker", "--out", out}, &stdout2, &stderr2))
}

func TestProvisionCmd_HelpNamesTheThreeSteps(t *testing.T) {
	var stdout, stderr bytes.Buffer
	require.Equal(t, 0, provisionCmd([]string{"help"}, &stdout, &stderr))
	for _, want := range []string{"provision authority", "provision join --bundle", "provision pin-worker --out"} {
		require.Contains(t, stderr.String(), want)
	}
	stderr.Reset()
	require.Equal(t, 2, provisionCmd([]string{"authority", "--provider", "simulated"}, &stdout, &stderr))
	require.Contains(t, stderr.String(), "--out and --provider are required")
}

// rewriteBundle writes m and files as a bundle after mutate edited the
// files, leaving the manifest as it was: what a bundle changed on the way
// looks like.
func rewriteBundle(t *testing.T, m workerBundle, files map[string][]byte, mutate func(map[string][]byte)) string {
	t.Helper()
	edited := map[string][]byte{}
	for k, v := range files {
		edited[k] = v
	}
	mutate(edited)
	manifest, err := json.Marshal(m)
	require.NoError(t, err)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name string, data []byte) {
		require.NoError(t, tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Unix(0, 0), Format: tar.FormatPAX}))
		_, err := tw.Write(data)
		require.NoError(t, err)
	}
	write("bundle.json", manifest)
	for name, data := range edited {
		write(name, data)
	}
	require.NoError(t, tw.Close())
	p := filepath.Join(t.TempDir(), "bundle.tar")
	require.NoError(t, os.WriteFile(p, buf.Bytes(), 0o600))
	return p
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
