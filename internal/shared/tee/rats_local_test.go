// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// The measurement the pin is held against is read from the message as
// it travels, by this side's own parsers: the SEV-SNP report's
// MEASUREMENT, the TDX quote's MRTD and RTMRs, the simulated statement's
// field — never from the Verifier's annotated evidence.
func TestLocalMeasurement_ReadsEachFamilysMessage(t *testing.T) {
	withRealSEVParse(t)
	nonce := Nonce("a thirty-two byte challenger nonce!")
	launch := bytes.Repeat([]byte{0xA5}, 48)
	report := sevReport(nonce, launch)
	_, value, err := WrapEvidence(ProviderGCPSEVSNP, Evidence(report), []byte("the certificate table"))
	require.NoError(t, err)
	m, err := localMeasurement(ProviderGCPSEVSNP, value)
	require.NoError(t, err)
	require.Equal(t, Measurement(launch), m)

	quote := tdxEvidence(t, "q1.quote.bin")
	q, err := parseTDXQuote(quote)
	require.NoError(t, err)
	_, value, err = WrapEvidence(ProviderGCPTDX, Evidence(quote), nil)
	require.NoError(t, err)
	m, err = localMeasurement(ProviderGCPTDX, value)
	require.NoError(t, err)
	require.Equal(t, tdxMeasurement(q.MRTD, q.RTMR), m)

	sim, err := NewSimulated([]byte("worker"), bytes.Repeat([]byte{0x11}, 32))
	require.NoError(t, err)
	statement, err := sim.Quote(nonce)
	require.NoError(t, err)
	m, err = localMeasurement(ProviderSimulated, statement)
	require.NoError(t, err)
	require.True(t, sim.Measurement().Equal(m))

	// A message of another provider's name, or one that does not parse, is refused; a family without a reader is named.
	_, value, _ = WrapEvidence(ProviderGCPTDX, Evidence(report), nil)
	_, err = localMeasurement(ProviderGCPSEVSNP, value)
	require.ErrorContains(t, err, `from provider "tdx_guest"`)
	_, value, _ = WrapEvidence(ProviderGCPSEVSNP, Evidence(report[:100]), nil)
	_, err = localMeasurement(ProviderGCPSEVSNP, value)
	require.ErrorContains(t, err, "does not parse")
	_, err = localMeasurement(ProviderSimulated, []byte("not a statement"))
	require.ErrorContains(t, err, "not a simulated statement")
	_, err = localMeasurement(ProviderAWSNitro, nil)
	require.Equal(t, codeNoLocalReader, shared_errors.CodeOf(err))
	// A nil value only asks whether the family has a reader.
	_, err = localMeasurement(ProviderGCPSEVSNP, nil)
	require.NoError(t, err)
}

// The session is opened with what the Evidence carries for the
// challenge: the configfs-tsm families' REPORT_DATA (SHA-256 of the
// challenge, then zeros — 64 bytes, as the Verifier's scheme compares
// it), the simulated family's challenge itself.
func TestSessionNonceFor_IsWhatTheReportCarries(t *testing.T) {
	t.Parallel()
	nonce := Nonce("a thirty-two byte challenger nonce!")
	for _, p := range []Provider{ProviderGCPSEVSNP, ProviderGCPTDX} {
		sn := sessionNonceFor(p, nonce)
		require.Len(t, sn, 64, p)
		prefix := computeReportDataPrefix(nonce)
		require.Equal(t, prefix[:], sn[:32])
		require.Equal(t, make([]byte, 32), sn[32:])
	}
	require.Equal(t, []byte(nonce), sessionNonceFor(ProviderSimulated, nonce))
	require.Equal(t, 48, measurementLen(ProviderGCPSEVSNP))
	require.Equal(t, 32, measurementLen(ProviderSimulated))
	require.Equal(t, 0, measurementLen(ProviderAWSNitro))
}
