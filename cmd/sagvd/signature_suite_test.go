// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// writeSigningKeyFile makes a key of suite and writes its file form.
func writeSigningKeyFile(t *testing.T, path string, suite crypto.SignatureSuite) *crypto.SigningKey {
	t.Helper()
	key, err := crypto.GenerateSigningKey(suite, nil)
	require.NoError(t, err)
	file, err := key.KeyFileBytes()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, file, 0o600))
	return key
}

// The daemon reads its signing keys under the suite the configuration
// names (keys.<name>.suite), prints the suite in its identity, seals the
// key file whatever its form, and opens it again. On the FIPS module
// v1.0.0 a configuration that names ml-dsa-87 is refused with the
// module's reason.
func TestLoadMaterials_SigningKeysUnderEverySuite(t *testing.T) {
	for _, suite := range crypto.Suites() {
		suite := suite
		t.Run(string(suite), func(t *testing.T) {
			f := newMaterialFixture(t)
			cfg := f.cfg
			if suite.Available() != nil {
				// cnsa accepts ml-dsa-87, so the configuration is valid; the
				// build decides availability, at load, with the module's reason.
				cfg.Crypto.Profile = "cnsa"
				cfg.Crypto.SignatureSuite = string(suite)
				cfg.Keys.AuthoritySigning.Suite = string(suite)
				require.NoError(t, cfg.Validate(), "the suite id is valid; the build decides availability")
				_, err := LoadMaterials(cfg, shared_time.NewSystemClock())
				require.Error(t, err)
				require.Contains(t, err.Error(), "unavailable in FIPS 140-3 Go Cryptographic Module")
				return
			}
			// The general profile signs with ed25519 unless the config picks
			// another suite it accepts (part three): the keys and the pick agree.
			cfg.Crypto.SignatureSuite = string(suite)
			authKey := writeSigningKeyFile(t, filepath.Join(f.dir, "authority.key"), suite)
			cfg.Keys.AuthoritySigning = SigningKeyConfig{KeyID: "authority-1", SeedPath: filepath.Join(f.dir, "authority.key"), Suite: string(crypto.RecordAlg(suite))}
			auditKey := writeSigningKeyFile(t, filepath.Join(f.dir, "audit.key"), suite)
			cfg.Keys.AuditSigning = SigningKeyConfig{KeyID: "audit-1", SeedPath: filepath.Join(f.dir, "audit.key"), Suite: string(suite)}
			cfg.Audit.LogPath = filepath.Join(f.dir, "returnpath.db")
			require.NoError(t, cfg.Validate())

			mat, err := LoadMaterials(cfg, shared_time.NewSystemClock())
			require.NoError(t, err)
			require.Equal(t, suite, mat.AuthoritySigningSuite)
			require.Equal(t, authKey.PublicKeyBytes(), mat.AuthoritySigningPublicKey)
			sig, err := mat.Store.Sign(mat.AuthoritySigningKeyID, keys.PurposeSigningAuthority, []byte("verdict"))
			require.NoError(t, err)
			require.Len(t, sig, suite.SignatureSize())
			vk, err := mat.Store.Resolve(mat.AuthoritySigningKeyID, keys.PurposeSigningAuthority)
			require.NoError(t, err)
			require.NoError(t, vk.VerifyRecord(crypto.RecordAlg(suite), []byte("verdict"), sig))
			mat.Store.Zeroize()

			// identity names the suites beside the PEMs.
			raw, err := json.Marshal(cfg)
			require.NoError(t, err)
			cfgPath := filepath.Join(f.dir, "sagvd.json")
			require.NoError(t, os.WriteFile(cfgPath, raw, 0o600))
			var out strings.Builder
			require.NoError(t, runIdentityCmd([]string{"-config", cfgPath}, &out))
			var id authorityIdentity
			require.NoError(t, json.Unmarshal([]byte(out.String()), &id))
			require.Equal(t, string(suite), id.AuthoritySignatureSuite)
			require.Equal(t, string(suite), id.AuditSignatureSuite)
			pub, err := crypto.ParsePublicKeyFile([]byte(id.AuthorityPublicKeyPEM))
			require.NoError(t, err)
			require.Equal(t, authKey.Public(), pub)
			pub, err = crypto.ParsePublicKeyFile([]byte(id.AuditPublicKeyPEM))
			require.NoError(t, err)
			require.Equal(t, auditKey.Public(), pub)

			// seal-keys seals the key file whatever its form; the daemon opens it.
			var stdout, stderr bytes.Buffer
			require.NoError(t, runSealKeysCmd([]string{"-config", cfgPath}, &stdout, &stderr))
			sealed, err := os.ReadFile(cfg.Keys.AuthoritySigning.SeedPath)
			require.NoError(t, err)
			require.True(t, tee.IsSealedSecret(sealed))
			after, err := LoadMaterials(cfg, shared_time.NewSystemClock())
			require.NoError(t, err)
			require.Equal(t, authKey.PublicKeyBytes(), after.AuthoritySigningPublicKey)
			after.Store.Zeroize()
			audit, err := openReturnPathAudit(cfg, shared_time.NewSystemClock(), nil, nil)
			require.NoError(t, err)
			require.NoError(t, audit.Close())
		})
	}
}

// A key file is read as the suite says, never guessed: a seed under the
// ECDSA suite, a PEM under a seed suite, and an unknown suite are refused.
func TestLoadMaterials_RefusesAKeyFileOfAnotherSuite(t *testing.T) {
	f := newMaterialFixture(t)
	cfg := f.cfg
	cfg.Crypto.SignatureSuite = string(crypto.SuiteECDSAP384SHA384)
	cfg.Keys.AuthoritySigning.Suite = string(crypto.SuiteECDSAP384SHA384)
	require.NoError(t, cfg.Validate())
	_, err := LoadMaterials(cfg, shared_time.NewSystemClock())
	require.Error(t, err)
	require.Contains(t, err.Error(), "keys.authority_signing")

	writeSigningKeyFile(t, filepath.Join(f.dir, "ec.pem"), crypto.SuiteECDSAP384SHA384)
	cfg = f.cfg
	cfg.Keys.AuthoritySigning = SigningKeyConfig{KeyID: "authority-1", SeedPath: filepath.Join(f.dir, "ec.pem")}
	_, err = LoadMaterials(cfg, shared_time.NewSystemClock())
	require.Error(t, err, "a PEM read as an Ed25519 seed is the wrong length")

	cfg = f.cfg
	cfg.Keys.AuthoritySigning.Suite = "rsa-pss"
	require.ErrorContains(t, cfg.Validate(), "keys.authority_signing.suite")
}

// The worker registry names each worker's suite beside its raw key.
func TestLoadWorkerRegistry_SuitePerWorker(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var entries []WorkerEntry
	want := map[ids.KeyID]crypto.SuitePublicKey{}
	for _, suite := range crypto.Suites() {
		if suite.Available() != nil {
			continue
		}
		key, err := crypto.GenerateSigningKey(suite, nil)
		require.NoError(t, err)
		kid := ids.KeyID("worker-" + string(suite))
		entries = append(entries, WorkerEntry{KeyID: string(kid), SigningPublicKeyHex: hex.EncodeToString(key.PublicKeyBytes()), Suite: string(crypto.RecordAlg(suite))})
		want[kid] = key.Public()
	}
	raw, err := json.Marshal(WorkerRegistryFile{Workers: entries})
	require.NoError(t, err)
	path := filepath.Join(dir, "workers.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	resolver, loaded, err := LoadWorkerRegistry(path, kms.DefaultSignaturePolicy())
	require.NoError(t, err)
	require.Len(t, loaded, len(entries))
	for kid, pub := range want {
		vk, err := resolver.Resolve(kid, keys.PurposeSigningAuthority)
		require.NoError(t, err)
		require.Equal(t, pub.Suite, vk.Suite)
		require.Equal(t, pub.Bytes, vk.PublicKey)
	}

	// The key length must be the suite's.
	bad := WorkerRegistryFile{Workers: []WorkerEntry{{KeyID: "w", SigningPublicKeyHex: hex.EncodeToString(make([]byte, 32)), Suite: string(crypto.SuiteECDSAP384SHA384)}}}
	raw, err = json.Marshal(bad)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	_, _, err = LoadWorkerRegistry(path, kms.DefaultSignaturePolicy())
	require.ErrorContains(t, err, "97 bytes for ecdsa-p384-sha384")
}

// The operator's stop list verifies under the operator key of any suite,
// read from its PEM.
func TestNewOperatorStopSource_UnderEverySuite(t *testing.T) {
	t.Parallel()
	for _, suite := range crypto.Suites() {
		suite := suite
		if suite.Available() != nil {
			continue
		}
		t.Run(string(suite), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			key, err := crypto.GenerateSigningKey(suite, nil)
			require.NoError(t, err)
			pemBytes, err := key.Public().PEM()
			require.NoError(t, err)
			cfg := OperatorStopConfig{KeyID: "operator-test", PublicKeyPath: writeFile(t, dir, "operator.pem", pemBytes), ListPath: filepath.Join(dir, "stop.json")}
			writeStopList(t, cfg.ListPath, key, revocation.List{Serial: 3})
			src, serial, err := newOperatorStopSource(cfg, kms.DefaultSignaturePolicy())
			require.NoError(t, err)
			require.Equal(t, uint64(3), serial)
			list, err := src()
			require.NoError(t, err)
			require.Equal(t, crypto.RecordAlg(suite), list.Alg)
		})
	}
}
