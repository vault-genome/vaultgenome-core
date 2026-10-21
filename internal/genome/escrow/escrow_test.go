// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package escrow

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

func sealed(t *testing.T) (string, []byte) {
	t.Helper()
	blob, dek, err := bundle.SealBytes(bundle.Header{ContentKind: bundle.ContentDir, ContentRef: "/a", ContentSnapshot: []byte(`{}`)}, []byte("lora"))
	require.NoError(t, err)
	r, err := bundle.Identify(writeTemp(t, blob))
	require.NoError(t, err)
	return r.Header.KeyID, dek
}

func writeTemp(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "g.genome")
	require.NoError(t, os.WriteFile(p, b, 0o644))
	return p
}

func mustKey(t *testing.T, suite kms.Suite) *PrivateKey {
	t.Helper()
	k, err := GenerateKey(suite)
	require.NoError(t, err)
	return k
}

// The authority, and only it, gets the genome key back — under every suite.
func TestSealOpen(t *testing.T) {
	for _, suite := range kms.AllSuites() {
		t.Run(string(suite), func(t *testing.T) {
			kid, dek := sealed(t)
			authority := mustKey(t, suite)
			env, err := Seal(dek, kid, authority.PublicKey())
			require.NoError(t, err)
			require.Equal(t, SchemaV2, env.Schema)
			require.Equal(t, string(suite), env.Suite)
			require.Equal(t, KeyTag(authority.PublicKey()), env.EscrowKey)
			require.NotContains(t, string(env.Ciphertext), string(dek))

			raw, err := env.Marshal()
			require.NoError(t, err)
			back, err := Parse(raw)
			require.NoError(t, err)
			got, err := Open(back, authority)
			require.NoError(t, err)
			require.Equal(t, dek, got)

			other := mustKey(t, suite)
			_, err = Open(back, other)
			require.ErrorContains(t, err, "this authority holds")
		})
	}
}

// An envelope of a release before ADR 0029 — the ECIES of ADR 0009 to an
// X25519 key — opens with the same X25519 key, and with nothing else.
func TestOpen_LegacyEnvelope(t *testing.T) {
	kid, dek := sealed(t)
	authority := mustKey(t, LegacySuite)
	ct, err := kms.X25519KeyWrapper{}.Wrap(dek, authority.PublicKey().Bytes(), aad(kid))
	require.NoError(t, err)
	legacy := Envelope{Schema: Schema, KeyID: kid, EscrowKey: KeyTag(authority.PublicKey()), Ciphertext: ct}
	raw, err := legacy.Marshal()
	require.NoError(t, err)
	require.NotContains(t, string(raw), `"suite"`, "a v1 envelope names no suite")
	back, err := Parse(raw)
	require.NoError(t, err)
	got, err := Open(back, authority)
	require.NoError(t, err)
	require.Equal(t, dek, got)

	labelled := back
	labelled.Suite = string(LegacySuite)
	_, err = Open(labelled, authority)
	require.ErrorContains(t, err, "names no suite")

	// The same 32 bytes as a raw key file of an earlier release read as the same key.
	again, err := ParsePrivate(authority.Bytes())
	require.NoError(t, err)
	require.True(t, again.Equal(authority))
	got, err = Open(back, again)
	require.NoError(t, err)
	require.Equal(t, dek, got)
}

// A v2 envelope opens only under its suite with a key of that suite; a
// v1 envelope only with an X25519 key.
func TestOpen_SuiteMustMatch(t *testing.T) {
	kid, dek := sealed(t)
	p384 := mustKey(t, kms.SuiteHPKEP384)
	env, err := Seal(dek, kid, p384.PublicKey())
	require.NoError(t, err)

	relabelled := env
	relabelled.Suite = string(kms.SuiteHPKEMLKEM768)
	_, err = Open(relabelled, p384)
	require.ErrorContains(t, err, "is under KEM suite")

	x := mustKey(t, LegacySuite)
	ct, err := kms.X25519KeyWrapper{}.Wrap(dek, x.PublicKey().Bytes(), aad(kid))
	require.NoError(t, err)
	legacy := Envelope{Schema: Schema, KeyID: kid, EscrowKey: KeyTag(p384.PublicKey()), Ciphertext: ct}
	_, err = Open(legacy, p384)
	require.ErrorContains(t, err, "v1 envelope")
	_, err = Open(Envelope{Schema: "vault-genome/key-escrow/v3", KeyID: kid, EscrowKey: KeyTag(p384.PublicKey())}, p384)
	require.ErrorContains(t, err, "schema")
	_, err = Open(env, nil)
	require.ErrorContains(t, err, "no escrow private key")
}

func TestRefusals(t *testing.T) {
	kid, dek := sealed(t)
	authority := mustKey(t, LegacySuite)

	_, err := Seal(dek[:16], kid, authority.PublicKey())
	require.Error(t, err, "a key that is not the id's")
	_, err = Seal(dek, "genome-dek-1", authority.PublicKey())
	require.Error(t, err)
	_, err = Seal(dek, kid, PublicKey{})
	require.ErrorContains(t, err, "no escrow public key")

	env, err := Seal(dek, kid, authority.PublicKey())
	require.NoError(t, err)
	for name, mutate := range map[string]func(e *Envelope){
		"schema":     func(e *Envelope) { e.Schema = "v0" },
		"not a kid":  func(e *Envelope) { e.KeyID = "genome-dek-1" },
		"other kid":  func(e *Envelope) { kid2, _ := sealed(t); e.KeyID = kid2 },
		"ciphertext": func(e *Envelope) { e.Ciphertext = append([]byte(nil), e.Ciphertext...); e.Ciphertext[40] ^= 1 },
		"escrow key": func(e *Envelope) { e.EscrowKey = "0000000000000000" },
		"suite":      func(e *Envelope) { e.Suite = string(kms.SuiteHPKEXWing) },
	} {
		t.Run(name, func(t *testing.T) {
			e := env
			mutate(&e)
			_, err := Open(e, authority)
			require.Error(t, err)
		})
	}
	_, err = Parse([]byte(`{"schema":"x","extra":1}`))
	require.Error(t, err)
}

// Key files: the PEM of every suite round-trips, the raw X25519 file of
// an earlier release still reads, a file open to others is refused.
func TestKeyFiles(t *testing.T) {
	dir := t.TempDir()
	for _, suite := range kms.AllSuites() {
		t.Run(string(suite), func(t *testing.T) {
			priv := mustKey(t, suite)
			p := filepath.Join(dir, string(suite)+".key")
			require.NoError(t, os.WriteFile(p, PrivatePEM(priv), 0o600))
			got, err := ReadPrivate(p)
			require.NoError(t, err)
			require.True(t, got.Equal(priv))
			require.Equal(t, suite, got.Suite())

			pemBytes, err := PublicPEM(priv.PublicKey())
			require.NoError(t, err)
			pub, err := ParsePublicPEM(pemBytes)
			require.NoError(t, err)
			require.True(t, pub.Equal(priv.PublicKey()))
			require.Equal(t, suite, pub.Suite())
			if suite == kms.SuiteHPKEX25519 || suite == kms.SuiteHPKEP384 {
				require.Contains(t, string(pemBytes), "BEGIN PUBLIC KEY", "PKIX for the curves every tool reads")
			} else {
				require.Contains(t, string(pemBytes), "BEGIN VAULT GENOME HPKE PUBLIC KEY")
				require.Contains(t, string(pemBytes), "Suite: "+string(suite))
			}
		})
	}

	// The raw 32-byte file of an earlier release.
	legacy := mustKey(t, LegacySuite)
	p := filepath.Join(dir, "legacy.key")
	require.NoError(t, os.WriteFile(p, legacy.Bytes(), 0o600))
	got, err := ReadPrivate(p)
	require.NoError(t, err)
	require.True(t, got.Equal(legacy))

	require.NoError(t, os.Chmod(p, 0o644))
	_, err = ReadPrivate(p)
	require.ErrorContains(t, err, "chmod 600")
	short := filepath.Join(dir, "short.key")
	require.NoError(t, os.WriteFile(short, []byte("short"), 0o600))
	_, err = ReadPrivate(short)
	require.ErrorContains(t, err, "not a private key")
	_, err = ReadPrivate(filepath.Join(dir, "absent"))
	require.Error(t, err)
	big := filepath.Join(dir, "big.key")
	require.NoError(t, os.WriteFile(big, make([]byte, maxKeyFileBytes+1), 0o600))
	_, err = ReadPrivate(big)
	require.ErrorContains(t, err, "larger than")

	// The PKIX PEM of an earlier release's X25519 public key is the same key.
	x, err := ecdh.X25519().NewPublicKey(legacy.PublicKey().Bytes())
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(x)
	require.NoError(t, err)
	pub, err := ParsePublicPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	require.NoError(t, err)
	require.True(t, pub.Equal(legacy.PublicKey()))

	_, err = ParsePublicPEM([]byte("nope"))
	require.Error(t, err)
	ec, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err = x509.MarshalPKIXPublicKey(ec.PublicKey())
	require.NoError(t, err)
	_, err = ParsePublicPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	require.ErrorContains(t, err, "want X25519 or P-384")
	_, err = ParsePublicPEM(pem.EncodeToMemory(&pem.Block{Type: pemHPKEPublic, Headers: map[string]string{pemSuiteHeader: "hpke-p256-v1"}, Bytes: []byte{1}}))
	require.ErrorContains(t, err, "unknown KEM suite")
	_, err = ParsePrivate(pem.EncodeToMemory(&pem.Block{Type: pemHPKEPrivate, Headers: map[string]string{pemSuiteHeader: string(kms.SuiteHPKEP384)}, Bytes: []byte{1, 2, 3}}))
	require.Error(t, err, "a P-384 private key of three bytes")
	_, err = NewPublicKey(kms.Suite("nope"), []byte{1})
	require.ErrorContains(t, err, "unknown KEM suite")
	_, err = NewPrivateKey(kms.Suite("nope"), []byte{1})
	require.ErrorContains(t, err, "unknown KEM suite")
}

// The tag of an X25519 key is the tag earlier releases gave it.
func TestKeyTag_IsStableForX25519(t *testing.T) {
	legacy := mustKey(t, LegacySuite)
	x, err := ecdh.X25519().NewPrivateKey(legacy.Bytes())
	require.NoError(t, err)
	require.Equal(t, legacy.PublicKey().Bytes(), x.PublicKey().Bytes())
	require.Len(t, KeyTag(legacy.PublicKey()), 16)
}
