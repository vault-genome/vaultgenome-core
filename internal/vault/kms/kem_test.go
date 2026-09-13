// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/stretchr/testify/require"
)

func newX25519(t *testing.T) (priv, pub []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return k.Bytes(), k.PublicKey().Bytes()
}

func TestX25519KEM_RoundTrip(t *testing.T) {
	t.Parallel()
	priv, pub := newX25519(t)
	w := NewX25519KeyWrapper()
	u := NewX25519KeyUnwrapper()
	dek := []byte("a-32-byte-data-encryption-key!!!")
	aad := []byte("token=abc|kid=1")

	wrapped, err := w.Wrap(dek, pub, aad)
	require.NoError(t, err)
	require.Greater(t, len(wrapped), 32+12, "must carry ephemeral pubkey + nonce + tag")
	require.NotContains(t, string(wrapped), string(dek))

	got, err := u.Unwrap(wrapped, priv, aad)
	require.NoError(t, err)
	require.Equal(t, dek, got)
}

func TestX25519KEM_WrongPrivateKeyFails(t *testing.T) {
	t.Parallel()
	_, pub := newX25519(t)
	otherPriv, _ := newX25519(t)
	wrapped, err := NewX25519KeyWrapper().Wrap([]byte("dek"), pub, []byte("aad"))
	require.NoError(t, err)
	_, err = NewX25519KeyUnwrapper().Unwrap(wrapped, otherPriv, []byte("aad"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestX25519KEM_TamperFails(t *testing.T) {
	t.Parallel()
	priv, pub := newX25519(t)
	wrapped, err := NewX25519KeyWrapper().Wrap([]byte("dek"), pub, []byte("aad"))
	require.NoError(t, err)
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0x01
	_, err = NewX25519KeyUnwrapper().Unwrap(tampered, priv, []byte("aad"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestX25519KEM_WrongAADFails(t *testing.T) {
	t.Parallel()
	priv, pub := newX25519(t)
	wrapped, err := NewX25519KeyWrapper().Wrap([]byte("dek"), pub, []byte("aad-1"))
	require.NoError(t, err)
	_, err = NewX25519KeyUnwrapper().Unwrap(wrapped, priv, []byte("aad-2"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestX25519KEM_FreshEphemeralPerWrap(t *testing.T) {
	t.Parallel()
	_, pub := newX25519(t)
	w := NewX25519KeyWrapper()
	c1, err := w.Wrap([]byte("dek"), pub, []byte("aad"))
	require.NoError(t, err)
	c2, err := w.Wrap([]byte("dek"), pub, []byte("aad"))
	require.NoError(t, err)
	require.NotEqual(t, c1, c2, "each Wrap uses a fresh ephemeral key + nonce")
}

func TestX25519KEM_RejectsBadKeys(t *testing.T) {
	t.Parallel()
	_, err := NewX25519KeyWrapper().Wrap([]byte("dek"), make([]byte, 31), []byte("aad"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
	_, pub := newX25519(t)
	wrapped, err := NewX25519KeyWrapper().Wrap([]byte("dek"), pub, []byte("aad"))
	require.NoError(t, err)
	_, err = NewX25519KeyUnwrapper().Unwrap(wrapped, make([]byte, 31), []byte("aad"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}
