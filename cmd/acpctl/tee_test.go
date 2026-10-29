// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func kdsChainFixture(t *testing.T, product string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "shared", "tee", "testdata", "amd", "kds-"+product+"-cert_chain.pem"))
	require.NoError(t, err)
	return b
}

func kdsTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for _, p := range []string{"Milan", "Genoa", "Turin"} {
		p := p
		mux.HandleFunc("/vcek/v1/"+p+"/cert_chain", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(kdsChainFixture(t, p))
		})
	}
	mux.HandleFunc("/swapped/vcek/v1/Milan/cert_chain", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(kdsChainFixture(t, "Genoa"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestTeeFetchAMDChain_WritesTheVerifiedChain(t *testing.T) {
	srv := kdsTestServer(t)
	out := filepath.Join(t.TempDir(), "amd-genoa-cert_chain.pem")
	var stdout, stderr bytes.Buffer
	code := teeCmd([]string{"fetch-amd-chain", "--product", "genoa", "--out", out, "--kds-url", srv.URL}, &stdout, &stderr)
	require.Equal(t, 0, code, stderr.String())
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Equal(t, kdsChainFixture(t, "Genoa"), got, "written byte for byte as KDS served it")
	require.Contains(t, stdout.String(), "the Genoa VCEK chain")
	require.Contains(t, stdout.String(), "CN=ARK-Genoa, sha256 4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1")

	// An existing file is kept unless --force.
	code = teeCmd([]string{"fetch-amd-chain", "--product", "milan", "--out", out, "--kds-url", srv.URL}, &stdout, &stderr)
	require.Equal(t, 2, code)
	require.Contains(t, stderr.String(), "exists; pass --force")
	stderr.Reset()
	code = teeCmd([]string{"fetch-amd-chain", "--product", "milan", "--out", out, "--kds-url", srv.URL, "--force"}, &stdout, &stderr)
	require.Equal(t, 0, code, stderr.String())
	got, err = os.ReadFile(out)
	require.NoError(t, err)
	require.Equal(t, kdsChainFixture(t, "Milan"), got)
}

func TestTeeFetchAMDChain_Refusals(t *testing.T) {
	srv := kdsTestServer(t)
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	// Missing flags.
	require.Equal(t, 2, teeCmd([]string{"fetch-amd-chain", "--product", "milan"}, &stdout, &stderr))
	require.Equal(t, 2, teeCmd([]string{"fetch-amd-chain"}, &stdout, &stderr))
	require.Equal(t, 2, teeCmd(nil, &stdout, &stderr))
	require.Equal(t, 2, teeCmd([]string{"nonsense"}, &stdout, &stderr))
	require.Equal(t, 0, teeCmd([]string{"help"}, &stdout, &stderr))

	// A product line this build has no root for.
	stderr.Reset()
	out := filepath.Join(dir, "rome.pem")
	require.Equal(t, 1, teeCmd([]string{"fetch-amd-chain", "--product", "rome", "--out", out, "--kds-url", srv.URL}, &stdout, &stderr))
	require.Contains(t, stderr.String(), "unknown AMD product line")
	_, err := os.Stat(out)
	require.True(t, os.IsNotExist(err), "nothing is written on refusal")

	// The server answers the Milan path with the Genoa chain.
	stderr.Reset()
	out = filepath.Join(dir, "milan.pem")
	require.Equal(t, 1, teeCmd([]string{"fetch-amd-chain", "--product", "milan", "--out", out, "--kds-url", srv.URL + "/swapped"}, &stdout, &stderr))
	require.Contains(t, stderr.String(), "returned a Genoa chain for Milan")
	_, err = os.Stat(out)
	require.True(t, os.IsNotExist(err))

	// Unreachable.
	stderr.Reset()
	require.Equal(t, 1, teeCmd([]string{"fetch-amd-chain", "--product", "milan", "--out", out, "--kds-url", srv.URL + "/missing"}, &stdout, &stderr))
	require.Contains(t, stderr.String(), "fetch Milan vcek chain")
}
