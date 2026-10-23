// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee/ratstest"
)

// tee.peer.verifier: builtin by default; rats needs the Verifier's URL
// and key and none of the family's own inputs; what cannot admit a peer
// is refused; a family this side cannot pin from the Evidence is named.
func TestValidateTEE_PeerVerifier(t *testing.T) {
	with := func(provider string, v *PeerVerifierConfig, mutate func(p *PeerTEEConfig)) TEEConfig {
		c := TEEConfig{Provider: "simulated", SeedPath: "/seed", InsecureSimulation: true, WorkloadDescriptor: "acp-compute-worker-v1"}
		c.Peer = PeerTEEConfig{Provider: provider, MeasurementPath: "/m", Verifier: v}
		if provider == "simulated" && (v == nil || !v.delegated()) {
			c.Peer.PublicKeyPath = "/k"
		}
		if (provider == "gcp-sev-snp" || provider == "azure-cgpu") && (v == nil || !v.delegated()) {
			c.Peer.AMDCertChainPath = "/chain.pem"
		}
		if mutate != nil {
			mutate(&c.Peer)
		}
		return c
	}
	rats := func(mutate func(v *PeerVerifierConfig)) *PeerVerifierConfig {
		v := &PeerVerifierConfig{Mode: "rats", URL: "https://verifier.bank.example", EARPublicKeyPath: "/ear.jwk"}
		if mutate != nil {
			mutate(v)
		}
		return v
	}
	for name, tc := range map[string]struct {
		cfg  TEEConfig
		want string
	}{
		"builtin by default":           {with("simulated", nil, nil), ""},
		"builtin named":                {with("simulated", &PeerVerifierConfig{Mode: "builtin"}, nil), ""},
		"builtin with a url":           {with("simulated", &PeerVerifierConfig{URL: "https://v"}, nil), "apply to mode=rats only"},
		"unknown mode":                 {with("simulated", &PeerVerifierConfig{Mode: "veraison"}, nil), `mode "veraison": builtin or rats`},
		"rats, simulated peer":         {with("simulated", rats(nil), nil), ""},
		"rats needs no simulated key":  {with("simulated", rats(nil), func(p *PeerTEEConfig) { p.PublicKeyPath = "" }), ""},
		"rats, sev-snp peer, no chain": {with("gcp-sev-snp", rats(nil), nil), ""},
		"rats, tdx peer":               {with("gcp-tdx", rats(nil), nil), ""},
		"rats, azure-cgpu peer":        {with("azure-cgpu", rats(nil), func(p *PeerTEEConfig) { p.AMDCertChainPath = "/chain.pem" }), "not \"azure-cgpu\""},
		"rats without url":             {with("simulated", rats(func(v *PeerVerifierConfig) { v.URL = "" }), nil), "tee.peer.verifier.url required"},
		"rats with a bad url":          {with("simulated", rats(func(v *PeerVerifierConfig) { v.URL = "verifier.bank.example" }), nil), "is not an http(s) URL"},
		"rats without key":             {with("simulated", rats(func(v *PeerVerifierConfig) { v.EARPublicKeyPath = "" }), nil), "ear_public_key_path required"},
		"rats accepting contraindicated": {with("simulated", rats(func(v *PeerVerifierConfig) { v.Accept = []string{"affirming", "contraindicated"} }), nil),
			"only affirming and warning can admit"},
		"rats accepting warning":   {with("simulated", rats(func(v *PeerVerifierConfig) { v.Accept = []string{"affirming", "warning"} }), nil), ""},
		"rats negative timeout":    {with("simulated", rats(func(v *PeerVerifierConfig) { v.TimeoutSeconds = -1 }), nil), "must not be negative"},
		"rats client cert alone":   {with("simulated", rats(func(v *PeerVerifierConfig) { v.ClientCertPath = "/c.crt" }), nil), "client_cert_path and client_key_path go together"},
		"rats mutual tls":          {with("simulated", rats(func(v *PeerVerifierConfig) { v.ClientCertPath, v.ClientKeyPath = "/c.crt", "/c.key" }), nil), ""},
		"builtin sev-snp no chain": {with("gcp-sev-snp", nil, func(p *PeerTEEConfig) { p.AMDCertChainPath = "" }), "amd_cert_chain_path required"},
	} {
		t.Run(name, func(t *testing.T) {
			errs := validateTEE(tc.cfg)
			if tc.want == "" {
				require.Empty(t, errs, "%v", errors.Join(errs...))
				return
			}
			require.ErrorContains(t, errors.Join(errs...), tc.want)
		})
	}
	require.Equal(t, "builtin", (*PeerVerifierConfig)(nil).mode())
	require.False(t, (*PeerVerifierConfig)(nil).delegated())
}

// The delegated verifier is built from the Verifier's key and URL alone
// — no chain, no PCS — and holds the pin; its files must be there.
func TestBuildPeerVerifier_Delegated(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, b, 0o600))
		return p
	}
	m32, m48 := write("m32", bytes.Repeat([]byte{1}, 32)), write("m48", bytes.Repeat([]byte{2}, 48))
	double := &ratstest.Server{}
	key := write("ear.jwk", double.PublicJWK())
	ca := write("ca.pem", []byte("-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"))
	absent := filepath.Join(dir, "absent")
	rats := func(mutate func(v *PeerVerifierConfig)) *PeerVerifierConfig {
		v := &PeerVerifierConfig{Mode: "rats", URL: "https://verifier.bank.example", EARPublicKeyPath: key, PolicyID: "policy:bank", TimeoutSeconds: 3}
		if mutate != nil {
			mutate(v)
		}
		return v
	}
	provider, v, err := buildPeerVerifier(PeerTEEConfig{Provider: "gcp-sev-snp", MeasurementPath: m48, Verifier: rats(nil)})
	require.NoError(t, err)
	require.Equal(t, tee.ProviderGCPSEVSNP, provider)
	require.IsType(t, &tee.RATSVerifier{}, v)
	require.NotNil(t, tee.RecordVerifierOf(v))
	require.Equal(t, "rats https://verifier.bank.example", tee.DescribeVerifier(v))
	provider, v, err = buildPeerVerifier(PeerTEEConfig{MeasurementPath: m32, Verifier: rats(nil)})
	require.NoError(t, err)
	require.Equal(t, tee.ProviderSimulated, provider)
	require.IsType(t, &tee.RATSVerifier{}, v)
	_, _, err = buildPeerVerifier(PeerTEEConfig{Provider: "gcp-tdx", MeasurementPath: m48, Verifier: rats(func(v *PeerVerifierConfig) { v.CAPath = ca })})
	require.ErrorContains(t, err, "no certificate", "a CA file that is not one is refused at build time")
	for name, tc := range map[string]struct {
		cfg  PeerTEEConfig
		want string
	}{
		"key file missing":    {PeerTEEConfig{MeasurementPath: m32, Verifier: rats(func(v *PeerVerifierConfig) { v.EARPublicKeyPath = absent })}, "read tee.peer.verifier.ear_public_key_path"},
		"key not a key":       {PeerTEEConfig{MeasurementPath: m32, Verifier: rats(func(v *PeerVerifierConfig) { v.EARPublicKeyPath = m32 })}, "tee.peer.verifier.ear_public_key_path"},
		"ca file missing":     {PeerTEEConfig{MeasurementPath: m32, Verifier: rats(func(v *PeerVerifierConfig) { v.CAPath = absent })}, "read tee.peer.verifier.ca_path"},
		"pin of wrong length": {PeerTEEConfig{Provider: "gcp-sev-snp", MeasurementPath: m32, Verifier: rats(nil)}, "the pin for gcp-sev-snp is 48 bytes"},
		"plain http afar":     {PeerTEEConfig{MeasurementPath: m32, Verifier: rats(func(v *PeerVerifierConfig) { v.URL = "http://verifier.bank.example" })}, "plain http to a host that is not loopback"},
		"azure-cgpu":          {PeerTEEConfig{Provider: "azure-cgpu", MeasurementPath: m48, Verifier: rats(nil)}, "no reader for the measurement"},
		"client cert missing": {PeerTEEConfig{MeasurementPath: m32, Verifier: rats(func(v *PeerVerifierConfig) { v.ClientCertPath, v.ClientKeyPath = absent, absent })}, "read tee.peer.verifier.client_cert_path"},
		"client pair broken":  {PeerTEEConfig{MeasurementPath: m32, Verifier: rats(func(v *PeerVerifierConfig) { v.ClientCertPath, v.ClientKeyPath = ca, m32 })}, "do not make a pair"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := buildPeerVerifier(tc.cfg)
			require.ErrorContains(t, err, tc.want)
		})
	}
	// The builtin path is untouched.
	provider, v, err = buildPeerVerifier(PeerTEEConfig{MeasurementPath: m32, PublicKeyPath: write("peer.pub", bytes.Repeat([]byte{3}, 32))})
	require.NoError(t, err)
	require.Equal(t, tee.ProviderSimulated, provider)
	require.IsType(t, &tee.SimulatedVerifier{}, v)
	require.Equal(t, "builtin", tee.DescribeVerifier(v))
}
