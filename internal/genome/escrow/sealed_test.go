// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package escrow

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

func simulatedTEE(t *testing.T, descriptor string) *tee.Simulated {
	t.Helper()
	s, err := tee.NewSimulated([]byte(descriptor), bytes.Repeat([]byte{3}, 32))
	require.NoError(t, err)
	return s
}

// The escrow key sealed on one host opens there — after a restart, with
// a fresh sealer of the same identity — and nowhere else. Its public half
// is readable without unsealing. Under every suite.
func TestSealedKeyOpensOnlyWhereItWasSealed(t *testing.T) {
	for _, suite := range kms.CurrentSuites() {
		t.Run(string(suite), func(t *testing.T) {
			if !suite.Available() {
				t.Skip("unavailable under fips140=only")
			}
			priv := mustKey(t, suite)
			host := simulatedTEE(t, "release-host-v1")
			sealed, err := SealKey(priv, host, tee.ProviderSimulated, host.Measurement())
			require.NoError(t, err)
			require.Equal(t, SealedSchemaV2, sealed.Schema)
			require.Equal(t, "simulated", sealed.TEE)
			require.Equal(t, string(suite), sealed.Suite)
			require.Equal(t, hex.EncodeToString(host.Measurement()), sealed.MeasurementHex)
			require.Equal(t, KeyTag(priv.PublicKey()), sealed.EscrowKey)
			require.NotContains(t, string(sealed.Sealed), string(priv.Bytes()))

			raw, err := sealed.Marshal()
			require.NoError(t, err)
			require.True(t, IsSealed(raw))
			require.False(t, IsSealed(PrivatePEM(priv)))
			require.False(t, IsSealed(append([]byte("{"), bytes.Repeat([]byte{1}, 31)...)), "a raw key that begins with '{' is still a raw key")
			parsed, err := ParseSealed(raw)
			require.NoError(t, err)
			pub, err := parsed.PublicKey()
			require.NoError(t, err)
			require.True(t, pub.Equal(priv.PublicKey()))

			restarted := simulatedTEE(t, "release-host-v1")
			got, err := parsed.Open(restarted, tee.ProviderSimulated, restarted.Measurement())
			require.NoError(t, err)
			require.True(t, got.Equal(priv))

			other := simulatedTEE(t, "release-host-v2")
			_, err = parsed.Open(other, tee.ProviderSimulated, other.Measurement())
			require.ErrorContains(t, err, "sealed at measurement")
			_, err = parsed.Open(other, tee.ProviderGCPSEVSNP, host.Measurement())
			require.ErrorContains(t, err, "sealed to simulated")
			// The same measurement claimed, another sealer behind it: the AEAD says no.
			_, err = parsed.Open(other, tee.ProviderSimulated, host.Measurement())
			require.ErrorContains(t, err, "unseal on simulated")
			_, err = parsed.Open(nil, tee.ProviderSimulated, host.Measurement())
			require.ErrorContains(t, err, "no TEE sealer")
		})
	}
}

// A v1 sealed file — an X25519 key sealed before ADR 0029 under the v1
// AAD — still opens on its host.
func TestSealedKey_LegacyFileOpens(t *testing.T) {
	if !kms.SuiteHPKEX25519.Available() {
		t.Skip("X25519 is unavailable under fips140=only (ADR 0030)")
	}
	priv := mustKey(t, LegacySuite)
	host := simulatedTEE(t, "release-host-v1")
	pemBytes, err := PublicPEM(priv.PublicKey())
	require.NoError(t, err)
	tag := KeyTag(priv.PublicKey())
	blob, err := host.Seal(priv.Bytes(), sealedAAD(tee.ProviderSimulated, host.Measurement(), tag))
	require.NoError(t, err)
	legacy := SealedKey{Schema: SealedSchema, TEE: "simulated", MeasurementHex: hex.EncodeToString(host.Measurement()), EscrowKey: tag, PublicKeyPEM: string(pemBytes), Sealed: blob}
	raw, err := legacy.Marshal()
	require.NoError(t, err)
	require.NotContains(t, string(raw), `"suite"`)
	parsed, err := ParseSealed(raw)
	require.NoError(t, err)
	got, err := parsed.Open(host, tee.ProviderSimulated, host.Measurement())
	require.NoError(t, err)
	require.True(t, got.Equal(priv))

	labelled := parsed
	labelled.Suite = string(LegacySuite)
	_, err = labelled.PublicKey()
	require.ErrorContains(t, err, "v1 sealed file")
}

// Every clear field is bound into the seal: a file edited on disk fails
// to open instead of opening as something else.
func TestSealedKeyFieldsAreBound(t *testing.T) {
	priv := mustKey(t, kms.SuiteHPKEP384)
	host := simulatedTEE(t, "release-host-v1")
	sealed, err := SealKey(priv, host, tee.ProviderSimulated, host.Measurement())
	require.NoError(t, err)

	other := mustKey(t, kms.SuiteHPKEP384)
	otherPEM, err := PublicPEM(other.PublicKey())
	require.NoError(t, err)

	swapped := sealed
	swapped.PublicKeyPEM, swapped.EscrowKey = string(otherPEM), KeyTag(other.PublicKey())
	_, err = swapped.Open(host, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "unseal")

	mismatched := sealed
	mismatched.PublicKeyPEM = string(otherPEM)
	_, err = mismatched.PublicKey()
	require.ErrorContains(t, err, "its tag says")

	relabelled := sealed
	relabelled.Suite = string(kms.SuiteHPKEMLKEM768)
	_, err = relabelled.PublicKey()
	require.ErrorContains(t, err, "says suite")

	raw, err := sealed.Marshal()
	require.NoError(t, err)
	_, err = ParseSealed(bytes.Replace(raw, []byte(SealedSchemaV2), []byte("vault-genome/sealed-escrow-key/v0"), 1))
	require.ErrorContains(t, err, "schema")
	_, err = ParseSealed(append(raw[:len(raw)-2], []byte(`,"extra":1}`)...))
	require.ErrorContains(t, err, "unknown field")
	_, err = ParseSealed([]byte(`{"schema":"` + SealedSchemaV2 + `"}`))
	require.ErrorContains(t, err, "incomplete")
	fresh, err := sealed.Marshal()
	require.NoError(t, err)
	require.Contains(t, string(fresh), `"suite": "hpke-p384-v2",`)
	_, err = ParseSealed(bytes.Replace(fresh, []byte(`"suite": "hpke-p384-v2",`), []byte(``), 1))
	require.ErrorContains(t, err, "names its suite")
	_, err = SealKey(nil, host, tee.ProviderSimulated, host.Measurement())
	require.Error(t, err)
}

// The recovery envelope: the escrow key wrapped to the operator's recovery
// key, opened only with it, and only as the key it names — the escrow key
// under one suite, the recovery key under any.
func TestRecoveryEnvelope(t *testing.T) {
	for _, pair := range [][2]kms.Suite{
		{LegacySuite, LegacySuite},
		{kms.SuiteHPKEP384, kms.SuiteHPKEP384},
		{kms.SuiteHPKEMLKEM1024P384, kms.SuiteHPKEMLKEM768},
		{kms.SuiteHPKEX25519, kms.SuiteHPKEXWing},
	} {
		t.Run(string(pair[0])+"/"+string(pair[1]), func(t *testing.T) {
			if !pair[0].Available() || !pair[1].Available() {
				t.Skip("a suite of the pair is unavailable under fips140=only")
			}
			priv := mustKey(t, pair[0])
			recovery := mustKey(t, pair[1])
			env, err := WrapRecovery(priv, recovery.PublicKey())
			require.NoError(t, err)
			require.Equal(t, RecoverySchemaV2, env.Schema)
			require.Equal(t, string(pair[0]), env.Suite)
			require.Equal(t, string(pair[1]), env.RecoverySuite)
			require.Equal(t, KeyTag(priv.PublicKey()), env.EscrowKey)
			require.Equal(t, KeyTag(recovery.PublicKey()), env.RecoveryKey)

			raw, err := env.Marshal()
			require.NoError(t, err)
			parsed, err := ParseRecovery(raw)
			require.NoError(t, err)
			got, err := parsed.Open(recovery)
			require.NoError(t, err)
			require.True(t, got.Equal(priv))

			wrong := mustKey(t, pair[1])
			_, err = parsed.Open(wrong)
			require.ErrorContains(t, err, "wrapped to recovery key")

			// The tags are bound: an envelope relabelled for another recovery key
			// does not open with it, and a swapped public key is caught.
			relabelled := parsed
			relabelled.RecoveryKey = KeyTag(wrong.PublicKey())
			_, err = relabelled.Open(wrong)
			require.ErrorContains(t, err, "open recovery envelope")
			other := mustKey(t, pair[0])
			otherPEM, err := PublicPEM(other.PublicKey())
			require.NoError(t, err)
			swapped := parsed
			swapped.PublicKeyPEM = string(otherPEM)
			_, err = swapped.Open(recovery)
			require.ErrorContains(t, err, "its tag says")

			_, err = ParseRecovery([]byte(strings.Replace(string(raw), RecoverySchemaV2, "x", 1)))
			require.ErrorContains(t, err, "schema")
			_, err = ParseRecovery([]byte(`{"schema":"` + RecoverySchemaV2 + `"}`))
			require.ErrorContains(t, err, "incomplete")
			_, err = WrapRecovery(priv, PublicKey{})
			require.Error(t, err)
			_, err = parsed.Open(nil)
			require.Error(t, err)
		})
	}
}

// A v1 recovery envelope — X25519 to X25519, the ECIES of ADR 0009 — opens
// with the X25519 recovery key of an earlier release.
func TestRecovery_LegacyEnvelopeOpens(t *testing.T) {
	if !kms.SuiteHPKEX25519.Available() {
		t.Skip("X25519 is unavailable under fips140=only (ADR 0030)")
	}
	priv := mustKey(t, LegacySuite)
	recovery := mustKey(t, LegacySuite)
	pemBytes, err := PublicPEM(priv.PublicKey())
	require.NoError(t, err)
	escrowTag, recoveryTag := KeyTag(priv.PublicKey()), KeyTag(recovery.PublicKey())
	ct, err := kms.X25519KeyWrapper{}.Wrap(priv.Bytes(), recovery.PublicKey().Bytes(), recoveryAAD(escrowTag, recoveryTag))
	require.NoError(t, err)
	legacy := Recovery{Schema: RecoverySchema, EscrowKey: escrowTag, RecoveryKey: recoveryTag, PublicKeyPEM: string(pemBytes), Ciphertext: ct}
	raw, err := legacy.Marshal()
	require.NoError(t, err)
	parsed, err := ParseRecovery(raw)
	require.NoError(t, err)
	got, err := parsed.Open(recovery)
	require.NoError(t, err)
	require.True(t, got.Equal(priv))

	p384 := mustKey(t, kms.SuiteHPKEP384)
	relabelled := parsed
	relabelled.RecoveryKey = KeyTag(p384.PublicKey())
	_, err = relabelled.Open(p384)
	require.ErrorContains(t, err, "v1 recovery envelope")
}
