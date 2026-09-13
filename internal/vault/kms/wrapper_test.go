// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"bytes"
	"testing"

	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/stretchr/testify/require"
)

func makeMeasurement(b byte) []byte {
	m := make([]byte, 32)
	for i := range m {
		m[i] = b
	}
	return m
}

func TestSimulatedKeyWrapper_RoundTrip(t *testing.T) {
	t.Parallel()
	w := NewSimulatedKeyWrapper()
	u := NewSimulatedKeyUnwrapper()
	measurement := makeMeasurement(0x42)
	plaintext := []byte("super-secret-DEK-32-bytes-of-key1")
	aad := []byte("token-id|measurement|key-id")

	ct, err := w.Wrap(plaintext, measurement, aad)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, ct, "ciphertext must differ from plaintext")

	plain, err := u.Unwrap(ct, measurement, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, plain)
}

func TestSimulatedKeyWrapper_DifferentNoncesEachWrap(t *testing.T) {
	t.Parallel()
	w := NewSimulatedKeyWrapper()
	measurement := makeMeasurement(0x42)
	plaintext := []byte("test")
	aad := []byte("aad")

	ct1, err := w.Wrap(plaintext, measurement, aad)
	require.NoError(t, err)
	ct2, err := w.Wrap(plaintext, measurement, aad)
	require.NoError(t, err)
	require.NotEqual(t, ct1, ct2, "fresh GCM nonce per Wrap call → identical inputs produce different ciphertexts")
}

func TestSimulatedKeyWrapper_WrongMeasurementFails(t *testing.T) {
	t.Parallel()
	w := NewSimulatedKeyWrapper()
	u := NewSimulatedKeyUnwrapper()
	measurementSrc := makeMeasurement(0x42)
	measurementDst := makeMeasurement(0x99)
	plaintext := []byte("dek")
	aad := []byte("aad")

	ct, err := w.Wrap(plaintext, measurementSrc, aad)
	require.NoError(t, err)

	_, err = u.Unwrap(ct, measurementDst, aad)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestSimulatedKeyWrapper_TamperedCiphertextFails(t *testing.T) {
	t.Parallel()
	w := NewSimulatedKeyWrapper()
	u := NewSimulatedKeyUnwrapper()
	measurement := makeMeasurement(0x42)
	plaintext := []byte("dek")
	aad := []byte("aad")

	ct, err := w.Wrap(plaintext, measurement, aad)
	require.NoError(t, err)

	// Flip a byte in the ciphertext (post-nonce).
	tampered := append([]byte{}, ct...)
	tampered[len(tampered)-1] ^= 0x01
	_, err = u.Unwrap(tampered, measurement, aad)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestSimulatedKeyWrapper_TamperedAADFails(t *testing.T) {
	t.Parallel()
	w := NewSimulatedKeyWrapper()
	u := NewSimulatedKeyUnwrapper()
	measurement := makeMeasurement(0x42)
	plaintext := []byte("dek")
	aadSrc := []byte("aad-1")
	aadDst := []byte("aad-2")

	ct, err := w.Wrap(plaintext, measurement, aadSrc)
	require.NoError(t, err)
	_, err = u.Unwrap(ct, measurement, aadDst)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestSimulatedKeyWrapper_WrongMeasurementSize(t *testing.T) {
	t.Parallel()
	w := NewSimulatedKeyWrapper()
	short := make([]byte, 31)
	_, err := w.Wrap([]byte("x"), short, []byte("aad"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestSimulatedKeyUnwrapper_WrongMeasurementSize(t *testing.T) {
	t.Parallel()
	u := NewSimulatedKeyUnwrapper()
	short := make([]byte, 31)
	_, err := u.Unwrap([]byte{1, 2, 3}, short, []byte("aad"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestSimulatedKeyUnwrapper_TruncatedCiphertext(t *testing.T) {
	t.Parallel()
	u := NewSimulatedKeyUnwrapper()
	measurement := makeMeasurement(0x42)
	short := []byte{1, 2, 3} // shorter than GCM nonce size (12)
	_, err := u.Unwrap(short, measurement, []byte("aad"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestSimulatedKeyWrapper_EmptyPlaintextRejected(t *testing.T) {
	t.Parallel()
	w := NewSimulatedKeyWrapper()
	measurement := makeMeasurement(0x42)
	_, err := w.Wrap(nil, measurement, []byte("aad"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestSimulatedKeyWrapper_DerivationStable(t *testing.T) {
	t.Parallel()
	measurement := makeMeasurement(0x42)
	k1, err := deriveWrapKey(measurement)
	require.NoError(t, err)
	k2, err := deriveWrapKey(measurement)
	require.NoError(t, err)
	require.True(t, bytes.Equal(k1[:], k2[:]), "wrap key derivation must be deterministic")
}

func TestSimulatedKeyWrapper_DerivationVariesPerMeasurement(t *testing.T) {
	t.Parallel()
	m1 := makeMeasurement(0x42)
	m2 := makeMeasurement(0x99)
	k1, err := deriveWrapKey(m1)
	require.NoError(t, err)
	k2, err := deriveWrapKey(m2)
	require.NoError(t, err)
	require.False(t, bytes.Equal(k1[:], k2[:]), "different measurements must yield different wrap keys")
}
