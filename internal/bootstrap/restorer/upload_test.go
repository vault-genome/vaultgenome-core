// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package restorer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// uploader posts bodies to POST /v1/genome/bundles through the Restorer's
// routes behind a real HTTP server, as acp-bootstrap serves them.
func uploader(t *testing.T, r *Restorer, token string) func(body io.Reader, contentLength int64, bearer, method string) (int, map[string]any) {
	t.Helper()
	mux := http.NewServeMux()
	for p, h := range r.Routes(token) {
		mux.HandleFunc(p, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return func(body io.Reader, contentLength int64, bearer, method string) (int, map[string]any) {
		req, err := http.NewRequest(method, srv.URL+"/v1/genome/bundles", body)
		require.NoError(t, err)
		if contentLength >= 0 {
			req.ContentLength = contentLength
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
}

// staged lists what the upload left in BundleDir besides stored bundles.
func staged(t *testing.T, dir string) []string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, ".upload-*"))
	require.NoError(t, err)
	return names
}

// A bundle posted to a destination with no disk of its own (ADR 0036)
// lands as <sha256>.genome; a key released for it restores it.
func TestUpload_StoresTheBundleAndTheReleaseRestoresIt(t *testing.T) {
	f := newFixture(t)
	blob, dek, kid := f.seal(adapter)
	token := strings.Repeat("u", 32)
	post := uploader(t, f.r, token)

	code, out := post(bytes.NewReader(blob), int64(len(blob)), token, http.MethodPost)
	require.Equal(t, http.StatusCreated, code, out)
	sum := sha256.Sum256(blob)
	require.Equal(t, hex.EncodeToString(sum[:]), out["bundle_sha256"])
	require.Equal(t, kid, out["key_id"])
	require.EqualValues(t, len(blob), out["bytes"])
	stored, err := os.ReadFile(filepath.Join(f.bundles, hex.EncodeToString(sum[:])+".genome"))
	require.NoError(t, err)
	require.Equal(t, blob, stored)
	require.Empty(t, staged(t, f.bundles))

	f.release(kid, dek, "upload")
	f.r.work(context.Background())
	require.Equal(t, StateRestored, f.record(kid).State)

	// The same bytes again: already here, nothing new stored.
	code, out = post(bytes.NewReader(blob), int64(len(blob)), token, http.MethodPost)
	require.Equal(t, http.StatusOK, code, out)
	require.Equal(t, true, out["already_here"])
	require.Empty(t, staged(t, f.bundles))
}

// Another bundle for a key that already has one is refused: one key, one
// bundle, so the receipt's digest names the only candidate.
func TestUpload_RefusesASecondBundleForTheSameKey(t *testing.T) {
	f := newFixture(t)
	blob, _, kid := f.seal(adapter)
	post := uploader(t, f.r, "")
	code, _ := post(bytes.NewReader(blob), int64(len(blob)), "", http.MethodPost)
	require.Equal(t, http.StatusCreated, code)
	// The same header, other bytes after it.
	other := append(append([]byte(nil), blob...), 0x00)
	code, out := post(bytes.NewReader(other), int64(len(other)), "", http.MethodPost)
	require.Equal(t, http.StatusConflict, code, out)
	require.Contains(t, out["error"], "another bundle for key "+kid)
	require.Empty(t, staged(t, f.bundles))
}

func TestUpload_Refusals(t *testing.T) {
	f := newFixture(t)
	f.r.cfg.MaxBundleBytes = 64 << 10
	blob, _, _ := f.seal(map[string]string{"small.txt": "a genome small enough to pass the bound"})
	token := strings.Repeat("u", 32)
	post := uploader(t, f.r, token)

	for _, tc := range []struct {
		name     string
		body     []byte
		length   int64
		bearer   string
		method   string
		code     int
		contains string
	}{
		{"no_token", blob, int64(len(blob)), "", http.MethodPost, http.StatusUnauthorized, "bearer token"},
		{"wrong_token", blob, int64(len(blob)), strings.Repeat("x", 32), http.MethodPost, http.StatusUnauthorized, "bearer token"},
		{"get", nil, -1, token, http.MethodGet, http.StatusMethodNotAllowed, "method not allowed"},
		{"not_a_bundle", []byte("these bytes are not a sealed genome bundle"), -1, token, http.MethodPost, http.StatusBadRequest, "not a v3 genome bundle"},
		{"empty", []byte{}, 0, token, http.MethodPost, http.StatusBadRequest, "empty body"},
		{"declared_too_large", blob, 1 << 20, token, http.MethodPost, http.StatusRequestEntityTooLarge, "exceeds"},
		{"streamed_too_large", bytes.Repeat([]byte{1}, 65<<10), -1, token, http.MethodPost, http.StatusRequestEntityTooLarge, "exceeds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.body != nil {
				body = bytes.NewReader(tc.body)
			}
			length := tc.length
			if tc.name == "streamed_too_large" {
				// No Content-Length: the bound is enforced on the bytes read.
				body = io.MultiReader(bytes.NewReader(tc.body))
				length = -1
			}
			if tc.name == "declared_too_large" {
				body = io.MultiReader(bytes.NewReader(tc.body), bytes.NewReader(make([]byte, (1<<20)-len(tc.body))))
			}
			code, out := post(body, length, tc.bearer, tc.method)
			require.Equal(t, tc.code, code, out)
			require.Contains(t, out["error"], tc.contains)
			require.Empty(t, staged(t, f.bundles), "nothing is left half-written")
			names, _ := filepath.Glob(filepath.Join(f.bundles, "*.genome"))
			require.Empty(t, names, "nothing refused is stored")
		})
	}
}

func TestNew_RefusesANegativeBundleBound(t *testing.T) {
	f := newFixture(t)
	cfg := f.r.cfg
	cfg.MaxBundleBytes = -1
	_, err := New(cfg)
	require.ErrorContains(t, err, "MaxBundleBytes")
}
