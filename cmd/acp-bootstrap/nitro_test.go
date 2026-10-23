// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/awskms"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// nitroFilesConfig is nitroConfig with its key files under dir.
func nitroFilesConfig(dir string) Config {
	c := nitroConfig()
	c.HTTP.TLS.ServerKey = filepath.Join(dir, "run/vg/keys/server.key")
	c.HTTP.BearerTokenFile = filepath.Join(dir, "run/vg/keys/token")
	return c
}

// standInParent replaces the parent for the test: each dial gets answer,
// and the parent waits for the enclave to close, as the kit's does.
func standInParent(t *testing.T, answer string, dialErr error) *[]uint32 {
	t.Helper()
	var mu sync.Mutex
	var dialed []uint32
	prev := dialParent
	t.Cleanup(func() { dialParent = prev })
	dialParent = func(_ context.Context, port uint32) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, port)
		mu.Unlock()
		if dialErr != nil {
			return nil, dialErr
		}
		enclave, parent := net.Pipe()
		go func() {
			_, _ = parent.Write([]byte(answer))
			_, _ = io.Copy(io.Discard, parent)
			_ = parent.Close()
		}()
		return enclave, nil
	}
	return &dialed
}

func filesAnswer(t *testing.T, files map[string][]byte) string {
	t.Helper()
	enc := map[string]string{}
	for p, b := range files {
		enc[p] = base64.StdEncoding.EncodeToString(b)
	}
	raw, err := json.Marshal(secretFilesAnswer{Files: enc})
	require.NoError(t, err)
	return string(raw)
}

// TestFetchSecretFiles: the parent hands in exactly the key files the
// config names; they land at their paths, mode 0600. Anything else is
// refused before a byte is written.
func TestFetchSecretFiles(t *testing.T) {
	dir := t.TempDir()
	c := nitroFilesConfig(dir)
	key, token := []byte(`{"schema":"sealed tls key"}`), []byte(`{"schema":"sealed token"}`)
	dialed := standInParent(t, filesAnswer(t, map[string][]byte{c.HTTP.TLS.ServerKey: key, c.HTTP.BearerTokenFile: token}), nil)
	require.NoError(t, fetchSecretFiles(c))
	require.Equal(t, []uint32{7000}, *dialed, "the key files' port of the config")
	for p, want := range map[string][]byte{c.HTTP.TLS.ServerKey: key, c.HTTP.BearerTokenFile: token} {
		got, err := os.ReadFile(p)
		require.NoError(t, err)
		require.Equal(t, want, got)
		st, err := os.Stat(p)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	}

	for name, tc := range map[string]struct {
		answer func(c Config) string
		err    error
		want   string
	}{
		"a file the config does not name": {func(c Config) string {
			return filesAnswer(t, map[string][]byte{c.HTTP.TLS.ServerKey: key, c.HTTP.BearerTokenFile: token, "/etc/vg/source.pem": []byte("planted")})
		}, nil, `the parent handed in "/etc/vg/source.pem", which this config does not name as a key file`},
		"a key file missing": {func(c Config) string { return filesAnswer(t, map[string][]byte{c.HTTP.TLS.ServerKey: key}) }, nil, "the parent did not hand in http.bearer_token_file"},
		"not base64": {func(c Config) string {
			return `{"files":{"` + c.HTTP.TLS.ServerKey + `":"%%%","` + c.HTTP.BearerTokenFile + `":"AA=="}}`
		}, nil, "http.tls.server_key"},
		"not the answer's form": {func(Config) string { return `{"file":{}}` }, nil, "the parent's answer does not decode"},
		"too large":             {func(Config) string { return `{"files":{"x":"` + strings.Repeat("A", maxSecretFilesBytes) + `"}}` }, nil, "at most 1048576 bytes"},
		"the parent is silent":  {func(Config) string { return "" }, errors.New("connection refused"), "tee.secret_files_vsock_port 7000: the parent does not answer"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			c := nitroFilesConfig(dir)
			standInParent(t, tc.answer(c), tc.err)
			err := fetchSecretFiles(c)
			require.ErrorContains(t, err, tc.want)
			if tc.err == nil {
				_, statErr := os.Stat(c.HTTP.TLS.ServerKey)
				require.True(t, errors.Is(statErr, os.ErrNotExist), "nothing is written when the answer is refused")
			}
		})
	}
}

// TestLogToParent: the log goes to the parent's port, line by line.
func TestLogToParent(t *testing.T) {
	prev := dialParent
	t.Cleanup(func() { dialParent = prev })
	got := make(chan string, 1)
	dialParent = func(_ context.Context, port uint32) (net.Conn, error) {
		require.Equal(t, uint32(7001), port)
		enclave, parent := net.Pipe()
		go func() { b, _ := io.ReadAll(parent); got <- string(b) }()
		return enclave, nil
	}
	w, err := logToParent(7001)
	require.NoError(t, err)
	buildLoggerTo(LogConfig{Level: "info", Format: "json"}, w).Info("acp-bootstrap ready", "tee_provider", "aws-nitro")
	require.NoError(t, w.Close())
	line := <-got
	require.Contains(t, line, `"msg":"acp-bootstrap ready"`)
	require.Contains(t, line, `"tee_provider":"aws-nitro"`)

	dialParent = func(context.Context, uint32) (net.Conn, error) { return nil, errors.New("no listener") }
	_, err = logToParent(7001)
	require.ErrorContains(t, err, "log.vsock_port 7001: the parent does not answer")
}

// standInKMS is KMS's GenerateDataKey over TLS, recording what it was asked.
func standInKMS(t *testing.T) *[]map[string]any {
	t.Helper()
	var mu sync.Mutex
	var asked []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || r.Header.Get("X-Amz-Target") != "TrentService.GenerateDataKey" {
			http.Error(w, `{"__type":"ValidationException"}`, http.StatusBadRequest)
			return
		}
		mu.Lock()
		asked = append(asked, in)
		mu.Unlock()
		pt := make([]byte, 32)
		_, _ = rand.Read(pt)
		w.Header().Set("x-amzn-RequestId", "req-1")
		_ = json.NewEncoder(w).Encode(map[string]any{"CiphertextBlob": append([]byte("wrapped:"), pt[:8]...), "Plaintext": pt, "KeyId": in["KeyId"]})
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	prev := operatorKMS
	t.Cleanup(func() { operatorKMS = prev })
	operatorKMS = func(region, _ string, creds awskms.Credentials) (*awskms.Client, error) {
		return awskms.New(awskms.Config{Region: region, Endpoint: "example.com", Credentials: creds, RootCAs: pool,
			Dial: func(ctx context.Context) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
			}})
	}
	return &asked
}

// TestSealKeys_Nitro: a Nitro enclave's key files sealed outside it, for
// its image: under -root, in place, each under its name, the data key
// asked of KMS under the context that names the image's PCR0; sealed
// again, the files are kept; a file sealed for another image is refused.
func TestSealKeys_Nitro(t *testing.T) {
	asked := standInKMS(t)
	root := t.TempDir()
	c := nitroConfig()
	c.HTTP.TLS.ServerKey, c.HTTP.BearerTokenFile = "/run/vg/keys/server.key", "/run/vg/keys/token"
	for p, b := range map[string]string{c.HTTP.TLS.ServerKey: "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n", c.HTTP.BearerTokenFile: strongToken() + "\n"} {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o700))
		writeFile(t, filepath.Join(root, p), []byte(b))
	}
	cfgPath := writeConfigFile(t, t.TempDir(), c)
	pcr0 := strings.Repeat("9a", 48)
	creds := awskms.StaticCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}

	var stdout, stderr bytes.Buffer
	require.NoError(t, runSealKeys([]string{"-config", cfgPath, "-pcr0", pcr0, "-root", root}, &stdout, &stderr, creds), stderr.String())
	var out sealKeysOutput
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	require.Equal(t, "aws-nitro", out.TEE)
	require.Equal(t, "aws-kms-attested", out.Sealer)
	require.Equal(t, pcr0, out.MeasurementHex)
	require.Len(t, out.Sealed, 2)
	require.Contains(t, stderr.String(), "the files open only in its enclave, through KMS")
	for _, f := range secretFiles(c) {
		raw, err := os.ReadFile(filepath.Join(root, f.Path))
		require.NoError(t, err)
		s, err := tee.ParseSealedSecret(raw)
		require.NoError(t, err)
		require.Equal(t, "aws-nitro", s.TEE)
		require.Equal(t, "aws-kms-attested", s.Sealer)
		require.Equal(t, pcr0, s.MeasurementHex)
		require.Equal(t, f.Name, s.Name)
		require.NotContains(t, string(raw), strongToken(), "the token is not in the sealed file")
	}
	require.Len(t, *asked, 2)
	for _, in := range *asked {
		require.Equal(t, c.TEE.AWSKMS.KeyARN, in["KeyId"])
		ec, _ := in["EncryptionContext"].(map[string]any)
		require.Equal(t, pcr0, ec["vault-genome:pcr0"], "the data key is asked under the image's PCR0")
		require.Equal(t, "v1", ec["vault-genome:sealed-secret"])
	}

	// Again: both already sealed for this image; KMS is not asked.
	stdout.Reset()
	require.NoError(t, runSealKeys([]string{"-config", cfgPath, "-pcr0", pcr0, "-root", root}, &stdout, &stderr, creds))
	out = sealKeysOutput{}
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	require.Empty(t, out.Sealed)
	require.Len(t, out.AlreadySealed, 2)
	require.Len(t, *asked, 2)

	// For another image: refused, by what the file names.
	err := runSealKeys([]string{"-config", cfgPath, "-pcr0", strings.Repeat("9b", 48), "-root", root}, &stdout, &stderr, creds)
	require.ErrorContains(t, err, "is already sealed, but on aws-nitro for 9a9a9a9a9a9a9a9a…")

	for name, tc := range map[string]struct {
		args  []string
		creds awskms.StaticCredentials
		want  string
	}{
		"no PCR0":       {[]string{"-config", cfgPath, "-root", root}, creds, "sealed outside the enclave, for its image: -pcr0"},
		"not hex":       {[]string{"-config", cfgPath, "-pcr0", "xyz"}, creds, "-pcr0 is the image's PCR0: a SHA-384"},
		"a SHA-256":     {[]string{"-config", cfgPath, "-pcr0", strings.Repeat("9a", 32)}, creds, "96 hex characters"},
		"debug mode":    {[]string{"-config", cfgPath, "-pcr0", hex.EncodeToString(make([]byte, 48))}, creds, "a debug-mode enclave's"},
		"no credential": {[]string{"-config", cfgPath, "-pcr0", pcr0}, awskms.StaticCredentials{}, "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runSealKeys(tc.args, &stdout, &stderr, tc.creds)
			require.ErrorContains(t, err, tc.want)
		})
	}

	// -pcr0 on another family is refused by name.
	dst := newDestination(t)
	err = runSealKeys([]string{"-config", writeConfigFile(t, dst.dir, dst.config()), "-pcr0", pcr0}, &stdout, &stderr, creds)
	require.ErrorContains(t, err, "-pcr0 and -root seal a Nitro enclave's key files; this config's tee.provider is simulated")
}
