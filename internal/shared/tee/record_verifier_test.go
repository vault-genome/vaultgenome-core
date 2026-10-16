// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type bareVerifier struct{}

func (bareVerifier) Verify(Evidence, Nonce) (Measurement, error) { return nil, nil }

type recordVerifier struct{ bareVerifier }

func (recordVerifier) VerifyRecord(string, []byte, Nonce) (Measurement, *AttestationDetail, error) {
	return nil, nil, nil
}

// forwardingWrapper is what the metrics recorder is: it forwards
// VerifyRecord and says what it wraps.
type forwardingWrapper struct{ inner Verifier }

func (w forwardingWrapper) Verify(ev Evidence, n Nonce) (Measurement, error) {
	return w.inner.Verify(ev, n)
}
func (w forwardingWrapper) VerifyRecord(string, []byte, Nonce) (Measurement, *AttestationDetail, error) {
	return nil, nil, nil
}
func (w forwardingWrapper) Unwrap() Verifier { return w.inner }

// A wrapper counts as a record verifier only when what it wraps is one:
// the handshake takes the record path for the delegated Verifier alone.
func TestRecordVerifierOf_LooksThroughWrappers(t *testing.T) {
	t.Parallel()
	require.Nil(t, RecordVerifierOf(bareVerifier{}))
	require.NotNil(t, RecordVerifierOf(recordVerifier{}))
	require.Nil(t, RecordVerifierOf(forwardingWrapper{inner: bareVerifier{}}))
	require.NotNil(t, RecordVerifierOf(forwardingWrapper{inner: recordVerifier{}}))
	require.NotNil(t, RecordVerifierOf(forwardingWrapper{inner: forwardingWrapper{inner: recordVerifier{}}}))
	require.Nil(t, RecordVerifierOf(forwardingWrapper{inner: forwardingWrapper{inner: bareVerifier{}}}))
}
