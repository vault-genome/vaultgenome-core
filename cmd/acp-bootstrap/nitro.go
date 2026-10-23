// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/vsock"
)

// A Nitro enclave has no disk, no network and no console anyone can read
// in production mode (ADR 0036): its key files come from the parent over
// vsock, sealed to the image, and its log goes back the same way.

// maxSecretFilesBytes bounds what the parent may hand in: two key files,
// sealed, are a few kilobytes.
const maxSecretFilesBytes = 1 << 20

// secretFilesTimeout bounds the exchange with the parent at start.
const secretFilesTimeout = 30 * time.Second

// dialParent reaches the parent instance (CID 3) on a vsock port; a
// variable so the tests stand in for the parent.
var dialParent = func(ctx context.Context, port uint32) (net.Conn, error) {
	return vsock.Dial(ctx, vsock.CIDNitroParent, port)
}

// secretFilesAnswer is what the parent writes on secret_files_vsock_port:
// each key file the config names, by its path, in base64.
type secretFilesAnswer struct {
	Files map[string]string `json:"files"`
}

// fetchSecretFiles takes the enclave's key files from its parent and
// writes them, mode 0600, at the paths the config names — in the
// enclave's memory, since its root file system is. Every key file the
// config names must come and nothing else may: a parent cannot plant a
// file the daemon would read. Nothing is written unless all of them came. What arrives is ciphertext when the
// operator sealed it (`acp-bootstrap seal-keys -pcr0`), and opening it is
// KMS's to allow, to this image's attestation only. The enclave reads one
// answer and closes first, so the parent, waiting for that close, never
// cuts the answer short.
func fetchSecretFiles(cfg Config) error {
	want := secretFiles(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), secretFilesTimeout)
	defer cancel()
	conn, err := dialParent(ctx, cfg.TEE.SecretFilesVsockPort)
	if err != nil {
		return fmt.Errorf("acp-bootstrap: tee.secret_files_vsock_port %d: the parent does not answer: %w", cfg.TEE.SecretFilesVsockPort, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	}
	var answer secretFilesAnswer
	dec := json.NewDecoder(io.LimitReader(conn, maxSecretFilesBytes+1))
	dec.DisallowUnknownFields()
	err = dec.Decode(&answer)
	_ = conn.Close()
	if err != nil {
		return fmt.Errorf("acp-bootstrap: tee.secret_files_vsock_port %d: the parent's answer does not decode (it is {\"files\": {path: base64}}, at most %d bytes): %w",
			cfg.TEE.SecretFilesVsockPort, maxSecretFilesBytes, err)
	}
	paths := make([]string, 0, len(want))
	for _, f := range want {
		paths = append(paths, f.Path)
	}
	offered := make([]string, 0, len(answer.Files))
	for p := range answer.Files {
		offered = append(offered, p)
	}
	slices.Sort(offered)
	for _, p := range offered {
		if !slices.Contains(paths, p) {
			return fmt.Errorf("acp-bootstrap: the parent handed in %q, which this config does not name as a key file", p)
		}
	}
	// All or nothing: every file is read before one is written.
	data := make([][]byte, len(want))
	for i, f := range want {
		b64, ok := answer.Files[f.Path]
		if !ok {
			return fmt.Errorf("acp-bootstrap: the parent did not hand in %s (%q)", f.Name, f.Path)
		}
		if data[i], err = base64.StdEncoding.DecodeString(b64); err != nil {
			return fmt.Errorf("acp-bootstrap: the parent's %s (%q) is not base64: %w", f.Name, f.Path, err)
		}
	}
	for i, f := range want {
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
			return fmt.Errorf("acp-bootstrap: %s (%q): %w", f.Name, f.Path, err)
		}
		if err := os.WriteFile(f.Path, data[i], 0o600); err != nil {
			return fmt.Errorf("acp-bootstrap: %s (%q): %w", f.Name, f.Path, err)
		}
	}
	return nil
}

// logToParent opens the log's vsock connection to the parent.
func logToParent(port uint32) (io.WriteCloser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), secretFilesTimeout)
	defer cancel()
	conn, err := dialParent(ctx, port)
	if err != nil {
		return nil, fmt.Errorf("acp-bootstrap: log.vsock_port %d: the parent does not answer: %w", port, err)
	}
	if conn == nil {
		return nil, errors.New("acp-bootstrap: log.vsock_port: no connection")
	}
	return conn, nil
}
