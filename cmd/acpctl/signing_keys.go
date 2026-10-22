// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
)

// The operator's and the sentinel's keys follow the signature suite of
// ADR 0031 the way the daemons' keys do: the key file is the suite's
// file form — the 32-byte seed of an ed25519 or ml-dsa-87 key, the
// PKCS#8 PEM of an ecdsa-p384-sha384 key — read under the suite the
// operator names (--signature-suite, ed25519 by default), never guessed
// from its length; the public key is PEM, whose algorithm names the
// suite, and a verifier reads the suite from the PEM.

// suiteFlagUsage is the --signature-suite help text.
const suiteFlagUsage = "Signature suite of the key (ADR 0031): ed25519, ecdsa-p384-sha384 or ml-dsa-87"

// addSuiteFlag registers --signature-suite on fs, ed25519 by default.
func addSuiteFlag(fs *flag.FlagSet) *string {
	return fs.String("signature-suite", string(crypto.SuiteEd25519), suiteFlagUsage)
}

// parseSuiteFlag resolves a --signature-suite value.
func parseSuiteFlag(v string) (crypto.SignatureSuite, error) {
	suite, err := crypto.SuiteOrDefault(v)
	if err != nil {
		return "", fmt.Errorf("--signature-suite: %w", err)
	}
	if err := suite.Available(); err != nil {
		return "", fmt.Errorf("--signature-suite %s: %w", suite, err)
	}
	return suite, nil
}

// generateSigningKeyFiles makes a key of suite and writes its file form to
// keyPath (created 0600, never overwritten) and its PEM public key to
// pubPath (0644).
func generateSigningKeyFiles(suite crypto.SignatureSuite, keyPath, pubPath string) (*crypto.SigningKey, error) {
	key, err := crypto.GenerateSigningKey(suite, nil)
	if err != nil {
		return nil, err
	}
	file, err := key.KeyFileBytes()
	if err != nil {
		return nil, err
	}
	if err := writeKeyFile(keyPath, file, false); err != nil {
		return nil, fmt.Errorf("write key file: %w", err)
	}
	pemBytes, err := key.Public().PEM()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(pubPath, pemBytes, 0o644); err != nil {
		return nil, fmt.Errorf("write public key: %w", err)
	}
	return key, nil
}

// readSigningKeyFile reads a bare key file (mode 0600) under suite.
func readSigningKeyFile(path string, suite crypto.SignatureSuite) (*crypto.SigningKey, error) {
	raw, err := readPrivateFile(path)
	if err != nil {
		return nil, err
	}
	defer zero(raw)
	key, err := crypto.LoadSigningKey(suite, raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// readSigningPublicKey reads a public key file: a PEM "PUBLIC KEY" block,
// whose algorithm names the suite (Ed25519, ECDSA P-384 or ML-DSA-87),
// or the raw 32 bytes of an Ed25519 key.
func readSigningPublicKey(path string) (crypto.SuitePublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return crypto.SuitePublicKey{}, fmt.Errorf("read pubkey: %w", err)
	}
	pub, err := crypto.ParsePublicKeyFile(data)
	if err != nil {
		return crypto.SuitePublicKey{}, fmt.Errorf("parse pubkey: %w", err)
	}
	return pub, nil
}

// readEd25519PublicKey reads a public key file that must be Ed25519: the
// simulated TEE's attestation key, which is not on the signature suite.
func readEd25519PublicKey(path string) ([]byte, error) {
	pub, err := readSigningPublicKey(path)
	if err != nil {
		return nil, err
	}
	if pub.Suite != crypto.SuiteEd25519 {
		return nil, errors.New("pubkey is " + string(pub.Suite) + ", want an Ed25519 key")
	}
	return pub.Bytes, nil
}
