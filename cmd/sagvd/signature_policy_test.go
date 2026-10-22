// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/failover"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// The profile decides the suite (ADR 0031, part three): the signing keys
// must be of the suite the profile signs with, the keys the daemon pins
// must be of suites the profile accepts, and the identity names both.
func TestSignaturePolicy_TheProfileDecidesTheSuite(t *testing.T) {
	ecdsaOK := crypto.SuiteECDSAP384SHA384.Available() == nil
	require.True(t, ecdsaOK)

	t.Run("cnsa refuses ed25519 signing keys at validation", func(t *testing.T) {
		f := newMaterialFixture(t)
		cfg := f.cfg
		cfg.Crypto.Profile = "cnsa"
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "keys.authority_signing is a ed25519 key, but the cnsa profile signs with ecdsa-p384-sha384")
	})

	t.Run("a pick outside the profile is refused", func(t *testing.T) {
		f := newMaterialFixture(t)
		cfg := f.cfg
		cfg.Crypto.Profile = "fips"
		cfg.Crypto.SignatureSuite = "ml-dsa-87"
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "which the fips profile does not accept")
	})

	t.Run("the X9 bank: fips with ecdsa-p384-sha384 keys", func(t *testing.T) {
		f := newMaterialFixture(t)
		cfg := f.cfg
		cfg.Crypto.Profile = "fips"
		cfg.Crypto.SignatureSuite = string(crypto.SuiteECDSAP384SHA384)
		authKey := writeSigningKeyFile(t, filepath.Join(f.dir, "authority.pem"), crypto.SuiteECDSAP384SHA384)
		cfg.Keys.AuthoritySigning = SigningKeyConfig{KeyID: "authority-1", SeedPath: filepath.Join(f.dir, "authority.pem"), Suite: string(crypto.SuiteECDSAP384SHA384)}
		// The worker registry holds an ed25519 worker: fips accepts it.
		require.NoError(t, cfg.Validate())
		mat, err := LoadMaterials(cfg, shared_time.NewSystemClock())
		require.NoError(t, err)
		require.Equal(t, authKey.Public().Bytes, mat.AuthoritySigningPublicKey)
		mat.Store.Zeroize()

		raw, err := json.Marshal(cfg)
		require.NoError(t, err)
		cfgPath := filepath.Join(f.dir, "sagvd.json")
		require.NoError(t, os.WriteFile(cfgPath, raw, 0o600))
		var out strings.Builder
		require.NoError(t, runIdentityCmd([]string{"-config", cfgPath}, &out))
		var id authorityIdentity
		require.NoError(t, json.Unmarshal([]byte(out.String()), &id))
		require.Equal(t, "fips", id.CryptoProfile)
		require.Equal(t, "ecdsa-p384-sha384", id.SignatureSuite)
		require.Equal(t, []string{"ed25519", "ecdsa-p384-sha384"}, id.SignatureSuites)
		require.Equal(t, "ecdsa-p384-sha384", id.AuthoritySignatureSuite)
	})

	t.Run("cnsa refuses a worker the profile does not accept", func(t *testing.T) {
		f := newMaterialFixture(t)
		cfg := f.cfg
		cfg.Crypto.Profile = "cnsa"
		writeSigningKeyFile(t, filepath.Join(f.dir, "authority.pem"), crypto.SuiteECDSAP384SHA384)
		cfg.Keys.AuthoritySigning = SigningKeyConfig{KeyID: "authority-1", SeedPath: filepath.Join(f.dir, "authority.pem"), Suite: string(crypto.SuiteECDSAP384SHA384)}
		require.NoError(t, cfg.Validate())
		// The fixture's registry holds an ed25519 worker.
		_, err := LoadMaterials(cfg, shared_time.NewSystemClock())
		require.Error(t, err)
		require.Contains(t, err.Error(), "worker registry entry 0")
		require.Contains(t, err.Error(), "ed25519 key, which the cnsa profile does not accept")

		// An ECDSA worker is accepted.
		wk, err := crypto.GenerateSigningKey(crypto.SuiteECDSAP384SHA384, nil)
		require.NoError(t, err)
		reg, err := json.Marshal(WorkerRegistryFile{Workers: []WorkerEntry{{KeyID: "worker-ec", SigningPublicKeyHex: hex.EncodeToString(wk.PublicKeyBytes()), Suite: string(crypto.SuiteECDSAP384SHA384)}}})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(cfg.Workers.RegistryPath, reg, 0o600))
		mat, err := LoadMaterials(cfg, shared_time.NewSystemClock())
		require.NoError(t, err)
		mat.Store.Zeroize()
	})

	t.Run("cnsa refuses an ed25519 operator key and sentinel key", func(t *testing.T) {
		dir := t.TempDir()
		pol, err := kms.NewSignaturePolicyFromNames("cnsa", "")
		require.NoError(t, err)
		edKey, err := crypto.GenerateSigningKey(crypto.SuiteEd25519, nil)
		require.NoError(t, err)
		ecKey, err := crypto.GenerateSigningKey(crypto.SuiteECDSAP384SHA384, nil)
		require.NoError(t, err)
		edPEM, err := edKey.Public().PEM()
		require.NoError(t, err)
		ecPEM, err := ecKey.Public().PEM()
		require.NoError(t, err)
		edCfg := OperatorStopConfig{KeyID: "operator-ed", PublicKeyPath: writeFile(t, dir, "ed.pem", edPEM), ListPath: filepath.Join(dir, "stop-ed.json")}
		writeStopList(t, edCfg.ListPath, edKey, revocation.List{Serial: 1})
		_, err = loadOperatorStop(edCfg, pol)
		require.Error(t, err)
		require.Contains(t, err.Error(), "operator key operator-ed is a ed25519 key, which the cnsa profile does not accept")
		ecCfg := OperatorStopConfig{KeyID: "operator-test", PublicKeyPath: writeFile(t, dir, "ec.pem", ecPEM), ListPath: filepath.Join(dir, "stop-ec.json")}
		writeStopList(t, ecCfg.ListPath, ecKey, revocation.List{Serial: 1})
		list, err := loadOperatorStop(ecCfg, pol)
		require.NoError(t, err)
		require.Equal(t, crypto.SuiteECDSAP384SHA384, list.Alg)

		// A policy signed by the ECDSA operator that pins an ed25519
		// sentinel is refused for the sentinel's suite.
		sentinelEd, err := crypto.GenerateSigningKey(crypto.SuiteEd25519, nil)
		require.NoError(t, err)
		now := time.Now().UTC().Truncate(time.Second)
		policy := func(spub crypto.SuitePublicKey) string {
			p, err := failover.Sign(failover.Policy{
				Serial: 7, IssuedAt: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
				SentinelPublicKey: spub.Bytes, SentinelAlg: crypto.RecordAlg(spub.Suite),
				Standby:  failover.Standby{Kind: "gcp-sev-snp", Endpoint: "https://standby.example:8443", Measurements: []string{strings.Repeat("ab", 48)}},
				Triggers: failover.Triggers{CompromiseReport: true}, SigningKeyID: "operator-test",
			}, ecKey)
			require.NoError(t, err)
			raw, err := json.Marshal(p)
			require.NoError(t, err)
			return writeFile(t, dir, "policy-"+string(spub.Suite)+".json", raw)
		}
		_, err = loadFailoverPolicy(ecCfg, policy(sentinelEd.Public()), pol)
		require.Error(t, err)
		require.Contains(t, err.Error(), "sentinel key "+sentinel.KeyID(sentinelEd.Public())+" is a ed25519 key, which the cnsa profile does not accept")
		sentinelEc, err := crypto.GenerateSigningKey(crypto.SuiteECDSAP384SHA384, nil)
		require.NoError(t, err)
		p, err := loadFailoverPolicy(ecCfg, policy(sentinelEc.Public()), pol)
		require.NoError(t, err)
		require.Equal(t, crypto.SuiteECDSAP384SHA384, p.Alg)
		_, err = loadFailoverPolicy(edCfg, policy(sentinelEc.Public()), pol)
		require.Error(t, err, "the operator key itself must be accepted")
	})
}
