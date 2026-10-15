// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// genuineAMDChain returns the ASK+ARK chain AMD KDS serves for a product
// line, from the attestation package's fixtures: what amd_cert_chain_path
// holds in a deployment, and the only kind of chain a verifier is built
// from since ADR 0024.
func genuineAMDChain(t *testing.T, product string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "shared", "tee", "testdata", "amd", "kds-"+product+"-cert_chain.pem"))
	if err != nil {
		t.Fatalf("read the %s chain fixture: %v", product, err)
	}
	return b
}
