// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package escrow

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// lowOrderPublicKeyPEM is a 32-byte X25519 point of low order in PKIX
// form: the curve accepts it as a key, the KEM refuses it as a recipient.
func lowOrderPublicKeyPEM(t *testing.T) []byte {
	t.Helper()
	pub, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// A genome key is never encapsulated to a public key the KEM cannot use:
// NewPublicKey refuses the low-order point, so no PublicKey of it exists.
func TestSeal_RefusesAnUnusableEscrowKey(t *testing.T) {
	if !kms.SuiteHPKEX25519.Available() {
		t.Skip("X25519 is unavailable under fips140=only (ADR 0030)")
	}
	_, err := ParsePublicPEM(lowOrderPublicKeyPEM(t))
	require.ErrorContains(t, err, "kms:")
	_, err = NewPublicKey(LegacySuite, make([]byte, 32))
	require.ErrorContains(t, err, "kms:")
}

// TestReadPrivate_RefusesWhatItCannotRead proves the failure modes of a
// key file beyond its mode: a directory where a file should be, and a
// file the process may not open.
func TestReadPrivate_RefusesWhatItCannotRead(t *testing.T) {
	if !kms.SuiteHPKEX25519.Available() {
		t.Skip("the legacy X25519 key cannot be made under fips140=only (ADR 0030)")
	}
	dir := t.TempDir()
	asDir := filepath.Join(dir, "escrow.key")
	require.NoError(t, os.Mkdir(asDir, 0o700))
	_, err := ReadPrivate(asDir)
	require.Error(t, err, "a directory is not a key file")

	if os.Geteuid() == 0 {
		t.Skip("root opens files regardless of their mode")
	}
	priv := mustKey(t, LegacySuite)
	unreadable := filepath.Join(dir, "unreadable.key")
	require.NoError(t, os.WriteFile(unreadable, PrivatePEM(priv), 0o000))
	_, err = ReadPrivate(unreadable)
	require.ErrorIs(t, err, os.ErrPermission)
}

// TestParsePublicPEM_Refusals pins each way a PEM can fail to be a
// usable escrow key: the wrong block type, a block that is not a
// public key at all, a well-formed X25519 point the KEM refuses, and
// the product's own block without a suite or with a key of the wrong size.
func TestParsePublicPEM_Refusals(t *testing.T) {
	if !kms.SuiteHPKEX25519.Available() {
		t.Skip("X25519 is unavailable under fips140=only (ADR 0030)")
	}
	cases := []struct {
		name string
		pem  []byte
		want string
	}{
		{"wrong block type", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}}), "not a PEM public key"},
		{"not a public key", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")}), "escrow: "},
		{"low-order point", lowOrderPublicKeyPEM(t), "kms:"},
		{"hpke block without a suite", pem.EncodeToMemory(&pem.Block{Type: pemHPKEPublic, Bytes: make([]byte, 1184)}), "unknown KEM suite"},
		{"hpke block of the wrong size", pem.EncodeToMemory(&pem.Block{Type: pemHPKEPublic, Headers: map[string]string{pemSuiteHeader: string(kms.SuiteHPKEMLKEM768)}, Bytes: make([]byte, 10)}), "1184 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, err := ParsePublicPEM(tc.pem)
			require.True(t, pub.IsZero())
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// TestRecovery_Refusals pins the recovery envelope's refusals beyond the
// happy path: an unusable recovery key at wrap time, and at open time
// the wrong schema, a public key that does not parse, a suite the
// envelope misnames, and contents that are not the private half of the
// key the envelope names.
func TestRecovery_Refusals(t *testing.T) {
	priv := mustKey(t, kms.SuiteHPKEP384)
	recovery := mustKey(t, kms.SuiteHPKEP384)

	env, err := WrapRecovery(priv, recovery.PublicKey())
	require.NoError(t, err)

	// wrapTo re-encapsulates raw under the tags env carries, the way a
	// forged or corrupted envelope would.
	wrapTo := func(raw []byte) Recovery {
		ct, err := recovery.Suite().Wrap(kms.PurposeEscrowRecovery, raw, recovery.PublicKey().Bytes(), recoveryAADV2(env.EscrowKey, env.RecoveryKey))
		require.NoError(t, err)
		forged := env
		forged.Ciphertext = ct
		return forged
	}
	other := mustKey(t, kms.SuiteHPKEP384)

	cases := []struct {
		name string
		env  func() Recovery
		want string
	}{
		{"wrong schema", func() Recovery { e := env; e.Schema = "v0"; return e }, "recovery schema"},
		{"public key does not parse", func() Recovery { e := env; e.PublicKeyPEM = "nope"; return e }, "not a PEM public key"},
		{"recovery suite misnamed", func() Recovery { e := env; e.RecoverySuite = string(kms.SuiteHPKEMLKEM768); return e }, "wrapped under KEM suite"},
		{"escrow suite misnamed", func() Recovery { e := env; e.Suite = string(kms.SuiteHPKEMLKEM768); return e }, "its public key is under"},
		{"contents are not a key", func() Recovery { return wrapTo([]byte("short")) }, "not a hpke-p384-v2 key"},
		{"contents are another key", func() Recovery { return wrapTo(other.Bytes()) }, "not the private half"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.env().Open(recovery)
			require.Nil(t, got)
			require.ErrorContains(t, err, tc.want)
		})
	}

	_, err = ParseRecovery([]byte("{not json"))
	require.ErrorContains(t, err, "recovery envelope")
	raw, err := env.Marshal()
	require.NoError(t, err)
	_, err = ParseRecovery(append(raw[:len(raw)-3], []byte(`,"extra":1}`)...))
	require.ErrorContains(t, err, "unknown field")
	_, err = ParseRecovery([]byte(`{"schema":"` + RecoverySchemaV2 + `","escrow_key":"a","recovery_key":"b","public_key_pem":"c","ciphertext":"AA=="}`))
	require.ErrorContains(t, err, "names its suites")
}

// failingSealer is a TEE whose sealing primitive is down.
type failingSealer struct{}

var errSealDown = errors.New("sealing device unavailable")

func (failingSealer) Seal([]byte, []byte) ([]byte, error)   { return nil, errSealDown }
func (failingSealer) Unseal([]byte, []byte) ([]byte, error) { return nil, errSealDown }

// TestSealedKey_Refusals pins the sealed escrow key's refusals beyond
// the happy path: a sealer that fails, a file of the wrong schema, a
// public key that does not parse, and unsealed contents that are not
// the private half of the key the file names.
func TestSealedKey_Refusals(t *testing.T) {
	host := simulatedTEE(t, "release-host-v1")
	priv := mustKey(t, kms.SuiteHPKEMLKEM768)

	_, err := SealKey(priv, failingSealer{}, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "escrow: seal to simulated")
	require.ErrorIs(t, err, errSealDown)

	s, err := SealKey(priv, host, tee.ProviderSimulated, host.Measurement())
	require.NoError(t, err)

	wrongSchema := s
	wrongSchema.Schema = "v0"
	_, err = wrongSchema.PublicKey()
	require.ErrorContains(t, err, "schema")
	_, err = wrongSchema.Open(host, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "schema")

	unparsable := s
	unparsable.PublicKeyPEM = "nope"
	_, err = unparsable.PublicKey()
	require.ErrorContains(t, err, "not a PEM public key")

	// sealTo seals raw under the file's own AAD, the way a forged or
	// corrupted file would.
	sealTo := func(raw []byte) SealedKey {
		blob, err := host.Seal(raw, sealedAADV2(tee.ProviderSimulated, host.Measurement(), s.EscrowKey, priv.Suite()))
		require.NoError(t, err)
		forged := s
		forged.Sealed = blob
		return forged
	}
	_, err = sealTo([]byte("short")).Open(host, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "not a hpke-mlkem768-v2 key")
	other := mustKey(t, kms.SuiteHPKEMLKEM768)
	_, err = sealTo(other.Bytes()).Open(host, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "not the private half")

	_, err = ParseSealed([]byte("{not json"))
	require.ErrorContains(t, err, "sealed key")
}

// TestShort proves long digests are abbreviated for messages and short
// ones are left alone.
func TestShort(t *testing.T) {
	require.Equal(t, "0123456789ab…", short("0123456789abcdef"))
	require.Equal(t, "0123456789ab", short("0123456789ab"))
	require.Equal(t, "", short(""))
}

// TestOpen_RefusesAKeyThatIsNotTheOneNamed proves that an envelope whose
// ciphertext opens cleanly is still refused when the key inside is not
// the genome key its KeyID names.
func TestOpen_RefusesAKeyThatIsNotTheOneNamed(t *testing.T) {
	kid, _ := sealed(t)
	_, otherDEK := sealed(t)
	authority := mustKey(t, kms.SuiteHPKEP384)
	ct, err := authority.Suite().Wrap(kms.PurposeEscrowDEK, otherDEK, authority.PublicKey().Bytes(), aadV2(kid))
	require.NoError(t, err)
	forged := Envelope{Schema: SchemaV2, KeyID: kid, EscrowKey: KeyTag(authority.PublicKey()), Suite: string(authority.Suite()), Ciphertext: ct}
	dek, err := Open(forged, authority)
	require.Nil(t, dek)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "escrow: open", "the envelope opened; the key inside is what was refused")
}
