// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// The worker's key files — its signing seed, the session sealing key —
// are read through here: bare bytes of the expected length, or a file
// `acp-compute seal-keys` sealed to this host's TEE (ADR 0023), opened
// with the host's sealer at read time.

// hostSealer builds this host's sealer from the TEE config alone. A vTPM
// sealer needs no producer; the others need the host's identity.
func hostSealer(cfg TEEConfig) (tee.Sealer, io.Closer, tee.Provider, tee.SealerKind, error) {
	provider, err := cfg.ProviderKind()
	if err != nil {
		return nil, nil, "", "", err
	}
	kind, err := tee.SealerKindForProvider(provider, cfg.SealerMode())
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("acp-compute: %w", err)
	}
	if kind == tee.SealerKindTPM2 {
		// The TPM needs no producer (ADR 0022).
		s, err := tee.NewVTPMSealer(tee.VTPMSealerConfig{TPM2ToolsDir: cfg.TPM2ToolsDir, PCRs: cfg.VTPMSealPCRs})
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("acp-compute: tee.vtpm_seal_pcrs: %w", err)
		}
		return s, nil, provider, kind, nil
	}
	_, producer, err := buildTEEProducer(cfg)
	if err != nil {
		return nil, nil, "", "", err
	}
	s, closer, kind, err := tee.SealerFor(producer, tee.SealerOptions{Mode: cfg.SealerMode(), SEVGuestDevice: cfg.SEVDevice(), TPM2ToolsDir: cfg.TPM2ToolsDir, VTPMSealPCRs: cfg.VTPMSealPCRs})
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("acp-compute: %w", err)
	}
	return s, closer, provider, kind, nil
}

// readSecret reads the key file named by field: bare bytes (exactly
// wantLen of them when wantLen is set, any number otherwise) — exactly wantLen bare
// bytes, or a sealed key file opened by this host's TEE.
func readSecret(cfg TEEConfig, path string, wantLen int, field string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: read %s (%q): %w", field, path, err)
	}
	if !tee.IsSealedSecret(raw) {
		if wantLen > 0 && len(raw) != wantLen {
			return nil, fmt.Errorf("acp-compute: %s (%q) must be exactly %d bytes (got %d), or a key file sealed by `acp-compute seal-keys`", field, path, wantLen, len(raw))
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("acp-compute: %s (%q) is empty", field, path)
		}
		return raw, nil
	}
	sealer, closer, provider, kind, err := hostSealer(cfg)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: %s (%q) is sealed and this host cannot open it: %w", field, path, err)
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	plain, err := tee.OpenSecretWith(raw, sealer, kind, provider, field)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: %s (%q): %w", field, path, err)
	}
	if (wantLen > 0 && len(plain) != wantLen) || len(plain) == 0 {
		n := len(plain)
		for i := range plain {
			plain[i] = 0
		}
		return nil, fmt.Errorf("acp-compute: %s (%q): the sealed key is %d bytes, want %d", field, path, n, wantLen)
	}
	return plain, nil
}

// loadSigningKey reads a signing key file under the suite its
// configuration names (ADR 0031): the 32-byte seed of an ed25519 or
// ml-dsa-87 key, the PKCS#8 PEM of an ecdsa-p384-sha384 key — bare, or
// sealed in place by `acp-compute seal-keys`. The plaintext read from
// disk is wiped once the key holds it.
func loadSigningKey(cfg TEEConfig, kc SigningKeyConfig, field string) (*crypto.SigningKey, error) {
	suite, err := kc.signatureSuite()
	if err != nil {
		return nil, fmt.Errorf("acp-compute: %s.suite: %w", field, err)
	}
	raw, err := readSecret(cfg, kc.SeedPath, suite.KeyFileSize(), field+".seed_path")
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	key, err := crypto.LoadSigningKey(suite, raw)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: %s (%q): %w", field, kc.SeedPath, err)
	}
	return key, nil
}
