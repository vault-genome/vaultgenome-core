// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux && (amd64 || arm64)

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/vsock"
)

// The daemon's API server on a vsock port, the way it serves inside a
// Nitro enclave (ADR 0036): TLS 1.3 terminates in the daemon, a client
// dials the port and gets its answer. Skipped where the kernel has no
// vsock loopback transport (the hardware kit is the proof in an enclave).
func TestBuildHTTPServer_ServesOverVsock(t *testing.T) {
	const port = 47101
	dir := t.TempDir()
	certPath, keyPath, pool := writeServerCert(t, dir)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	srv, ln, err := buildHTTPServer(TEEConfig{}, HTTPConfig{
		ListenVsockPort: port,
		TLS:             TLSServerConfig{Enabled: true, ServerCert: certPath, ServerKey: keyPath},
	}, mux, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Skipf("no AF_VSOCK listener on this kernel: %v", err)
	}
	defer srv.Close()
	go func() { _ = srv.Serve(ln) }()
	if got := ln.Addr().String(); got != "vsock://any:47101" {
		t.Fatalf("listener address %q", got)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "enclave"},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return vsock.Dial(ctx, vsock.CIDLocal, port)
		},
	}}
	resp, err := client.Get("https://enclave/healthz")
	if err != nil {
		t.Skipf("no vsock loopback transport on this kernel: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" || resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("over vsock: %d %q tls=%v", resp.StatusCode, body, resp.TLS)
	}
}

func writeServerCert(t *testing.T, dir string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "enclave"}, DNSNames: []string{"enclave"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return certPath, keyPath, pool
}
