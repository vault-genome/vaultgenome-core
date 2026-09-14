// SPDX-License-Identifier: AGPL-3.0-or-later

package crosscloud

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	stdtime "time"

	"github.com/stretchr/testify/require"

	krt "github.com/ai-continuity-platform/core/internal/contracts/key_release_token"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
	"github.com/ai-continuity-platform/core/internal/vault/kms"
)

// These tests prove the X25519 KEM path (ADR 0009) end to end through the
// receiver's real code: DEKs are encapsulated to the destination's attested
// X25519 PUBLIC key and can only be decapsulated with the TEE-held PRIVATE key —
// the honest replacement for the symmetric measurement-derived wrap (defect b),
// whose "measurement is secret" premise never held.

func x25519Keypair(t *testing.T) (pub, priv []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return k.PublicKey().Bytes(), k.Bytes()
}

// signedTokenKEM builds a source-signed token whose DEKs are KEM-encapsulated to
// recipientPub (the destination's attested public key).
func signedTokenKEM(t *testing.T, signer keys.Signer, sourceKID ids.KeyID, destMeasure, recipientPub []byte, deks map[ids.KeyID][]byte) krt.KeyReleaseToken {
	t.Helper()
	tokenID := ids.DecisionID("xcc-tok-kem-1")
	wrapper := kms.NewX25519KeyWrapper()
	wrapped := make([]krt.WrappedKey, 0, len(deks))
	for kid, pt := range deks {
		aad := canonicalWrapAAD(tokenID, destMeasure, kid)
		ct, err := wrapper.Wrap(pt, recipientPub, aad)
		require.NoError(t, err)
		wrapped = append(wrapped, krt.WrappedKey{KeyID: kid, Purpose: krt.PurposeSealing, Ciphertext: ct, AAD: aad})
	}
	tok := krt.KeyReleaseToken{
		SchemaVersion:          krt.SchemaVersionCurrent,
		TokenID:                tokenID,
		DecisionID:             ids.DecisionID("dec-kem-1"),
		RequestID:              ids.RequestID("xcc-req-kem-1"),
		DestinationMeasurement: destMeasure,
		Wrapped:                wrapped,
		PolicyVersion:          "policy-kem-v1",
		AuthorizedAt:           stdtime.Date(2026, 5, 9, 12, 5, 0, 0, stdtime.UTC),
		SigningKeyID:           sourceKID,
		Signature:              []byte{0x00},
		AuditEventID:           ids.AuditEventID("evt-kem-1"),
	}
	require.NoError(t, tok.SignWith(signer))
	return tok
}

// makeKEMReceiver builds a receiver configured for the X25519 KEM path with the
// given TEE-held private key.
func makeKEMReceiver(t *testing.T, priv []byte) (*Receiver, *keys.InMemoryStore, ids.KeyID, []byte, *keys.InMemoryStore) {
	t.Helper()
	clock := shared_time.NewFakeClock(stdtime.Date(2026, 5, 9, 12, 0, 0, 0, stdtime.UTC))
	sourceKeystore := keys.NewInMemoryStore(clock)
	sourceKID := ids.KeyID("source-auth-kem")
	_, err := sourceKeystore.GenerateSigning(sourceKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	destProducer, err := tee.NewSimulated([]byte("kem-recv-test"), mustRandomBytes(t, 32))
	require.NoError(t, err)
	destKeystore := keys.NewInMemoryStore(clock)

	receiver, err := NewReceiver(Config{
		SourceAuthorityKeys: sourceKeystore,
		LocalTEE:            destProducer,
		Unwrapper:           kms.NewX25519KeyUnwrapper(),
		RecipientPrivateKey: priv,
		Registrar:           destKeystore,
	})
	require.NoError(t, err)
	return receiver, sourceKeystore, sourceKID, []byte(destProducer.Measurement()), destKeystore
}

func TestKEM_CrossCloudRoundTrip(t *testing.T) {
	t.Parallel()
	pub, priv := x25519Keypair(t)
	receiver, signer, sourceKID, destMeasure, destKeystore := makeKEMReceiver(t, priv)

	dek := mustRandomBytes(t, 32)
	tok := signedTokenKEM(t, signer, sourceKID, destMeasure, pub,
		map[ids.KeyID][]byte{ids.KeyID("dek-kem"): dek})

	n, err := receiver.HandleKeyReleaseToken(tok)
	require.NoError(t, err)
	require.Equal(t, 1, n, "KEM-wrapped DEK must be decapsulated and registered")

	// Registered and usable in the destination keystore.
	_, _, err = destKeystore.Seal(ids.KeyID("dek-kem"), []byte("ping"), nil)
	require.NoError(t, err)
}

func TestKEM_WrongPrivateKeyIsRejected(t *testing.T) {
	t.Parallel()
	pub, _ := x25519Keypair(t)       // DEK encapsulated to THIS public key
	_, wrongPriv := x25519Keypair(t) // receiver holds a DIFFERENT private key
	receiver, signer, sourceKID, destMeasure, _ := makeKEMReceiver(t, wrongPriv)

	tok := signedTokenKEM(t, signer, sourceKID, destMeasure, pub,
		map[ids.KeyID][]byte{ids.KeyID("dek-kem"): mustRandomBytes(t, 32)})

	n, err := receiver.HandleKeyReleaseToken(tok)
	require.Error(t, err, "decapsulation with the wrong private key must fail")
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
	require.Equal(t, 0, n)
}
