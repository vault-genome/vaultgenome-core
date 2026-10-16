// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// tsmProducer stands for a configfs-tsm producer: a report, and the
// auxblob the kernel showed beside it.
type tsmProducer struct {
	report, aux []byte
	m           tee.Measurement
}

func (p tsmProducer) Quote(tee.Nonce) (tee.Evidence, error) { return tee.Evidence(p.report), nil }
func (p tsmProducer) QuoteWithAux(tee.Nonce) (tee.Evidence, []byte, error) {
	return tee.Evidence(p.report), p.aux, nil
}
func (p tsmProducer) Measurement() tee.Measurement { return p.m }

// plainProducer is a producer without an auxblob.
type plainProducer struct {
	report []byte
	err    error
}

func (p plainProducer) Quote(tee.Nonce) (tee.Evidence, error) {
	return tee.Evidence(p.report), p.err
}
func (p plainProducer) Measurement() tee.Measurement {
	return tee.Measurement(bytes.Repeat([]byte{1}, 48))
}

// recordingVerifier keeps what it was handed and answers with a fixed
// measurement: the test looks at the bytes, not the verdict.
type recordingVerifier struct {
	got *[]byte
	m   tee.Measurement
}

func (v recordingVerifier) Verify(ev tee.Evidence, _ tee.Nonce) (tee.Measurement, error) {
	*v.got = append([]byte(nil), ev...)
	return v.m, nil
}

// A configfs-tsm family's Evidence goes on the wire as the TSM report —
// outblob, the auxblob beside it, the kernel's provider name — under the
// TSM media type; a producer without an auxblob sends the report alone;
// the other families send their bytes as they are; the producer's
// failure is the handshake failure it always was.
func TestProduceRecord_TSMFamilyCarriesTheReportAndTheAuxblob(t *testing.T) {
	t.Parallel()
	nonce := tee.Nonce(bytes.Repeat([]byte{0x11}, 32))
	report := bytes.Repeat([]byte{0xAB}, 1184)
	aux := []byte("GUID table, the VCEK in DER")

	r, err := produceRecord(tee.ProviderGCPSEVSNP, tsmProducer{report: report, aux: aux}, nonce, "server")
	require.NoError(t, err)
	require.Equal(t, tee.MediaTypeTSMReportJSON, r.Type)
	require.True(t, r.IsEvidence())
	var tsm tee.TSMReport
	require.NoError(t, json.Unmarshal(r.Value, &tsm))
	require.Equal(t, "sev_guest", tsm.Provider)
	require.Equal(t, report, tsm.OutBlob)
	require.Equal(t, aux, tsm.AuxBlob)
	// The record inside a frame is the json-record of RFC 9999.
	b, err := json.Marshal(r)
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(b, []byte(`["application/vnd.veraison.tsm-report+json","`)), string(b[:60]))
	require.True(t, bytes.HasSuffix(b, []byte(`",4]`)))

	r2, err := produceRecord(tee.ProviderGCPTDX, plainProducer{report: report}, nonce, "client")
	require.NoError(t, err)
	require.Equal(t, tee.MediaTypeTSMReportJSON, r2.Type)
	require.NotContains(t, string(r2.Value), "auxblob")
	require.Contains(t, string(r2.Value), `"provider":"tdx_guest"`)

	r3, err := produceRecord(tee.ProviderSimulated, tsmProducer{report: []byte("signed statement"), aux: aux}, nonce, "client")
	require.NoError(t, err)
	require.Equal(t, tee.MediaTypeSimulatedEvidence, r3.Type)
	require.Equal(t, []byte("signed statement"), r3.Value, "no TSM report around a family that is not configfs-tsm's")

	_, err = produceRecord(tee.ProviderSimulated, plainProducer{err: errors.New("no device")}, nonce, "client")
	require.ErrorContains(t, err, "client TEE quote generation failed")
	require.Equal(t, CodeHandshakeFailure, shared_errors.CodeOf(err))

	_, err = produceRecord(tee.ProviderAuto, plainProducer{report: report}, nonce, "client")
	require.Error(t, err, "auto is not a family and has no media type")
}

// Both peers of a configfs-tsm family: the handshake carries each
// report inside a TSM report, and each side's verifier is handed the
// report itself — the outblob — not the wrapper around it, so the
// builtin verifiers read what they always read.
func TestHandshake_TSMFamily_TheVerifierReadsTheReportNotTheWrapper(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	serverReport := bytes.Repeat([]byte{0xA1}, 1184)
	clientReport := bytes.Repeat([]byte{0xB2}, 1184)
	serverM := tee.Measurement(bytes.Repeat([]byte{0x51}, 48))
	clientM := tee.Measurement(bytes.Repeat([]byte{0x52}, 48))
	var serverSaw, clientSaw []byte
	c, s, cs, ss := runLoopbackHandshake(t, peers, func(cfg *HandshakeConfig) {
		cfg.LocalProvider, cfg.PeerProvider = tee.ProviderGCPSEVSNP, tee.ProviderGCPSEVSNP
		if cfg.Role == RoleServer {
			cfg.Producer = tsmProducer{report: serverReport, aux: []byte("server host's table"), m: serverM}
			cfg.Verifier = recordingVerifier{got: &serverSaw, m: clientM}
		} else {
			cfg.Producer = tsmProducer{report: clientReport, aux: []byte("client host's table"), m: clientM}
			cfg.Verifier = recordingVerifier{got: &clientSaw, m: serverM}
		}
	})
	defer func() { _ = c.Close(); _ = s.Close() }()

	require.Equal(t, clientReport, serverSaw, "the server's verifier was handed the client's report, not the TSM report around it")
	require.Equal(t, serverReport, clientSaw, "the client's verifier was handed the server's report")
	require.True(t, clientM.Equal(ss.PeerMeasurement))
	require.True(t, serverM.Equal(cs.PeerMeasurement))
}

// A record of another family is refused by name before any verifier
// runs: a sev_guest TSM report reaching a peer configured for TDX.
func TestHandshake_TSMFamily_WrongProviderNameIsRefusedByName(t *testing.T) {
	t.Parallel()
	report := bytes.Repeat([]byte{0xA1}, 1184)
	m := tee.Measurement(bytes.Repeat([]byte{0x51}, 48))
	var serverSaw, clientSaw []byte
	lis := listenLoopback(t)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(testHandshakeTimeout))
		_, err = DoHandshake(HandshakeConfig{
			Role: RoleServer, Conn: conn, Clock: shared_time.NewSystemClock(),
			LocalProvider: tee.ProviderGCPSEVSNP, PeerProvider: tee.ProviderGCPTDX, // expects a tdx_guest peer
			Producer: tsmProducer{report: report, m: m},
			Verifier: recordingVerifier{got: &serverSaw, m: m},
		})
		serverErr <- err
	}()
	conn, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(testHandshakeTimeout))
	_, err = DoHandshake(HandshakeConfig{
		Role: RoleClient, Conn: conn, Clock: shared_time.NewSystemClock(), ProposedChallenge: []byte("test-proposed-challenge"),
		LocalProvider: tee.ProviderGCPSEVSNP, PeerProvider: tee.ProviderGCPSEVSNP,
		Producer: tsmProducer{report: report, m: m}, // sends a sev_guest report
		Verifier: recordingVerifier{got: &clientSaw, m: m},
	})
	require.Error(t, err, "the client is told the server refused")
	serr := <-serverErr
	require.Error(t, serr)
	require.Contains(t, serr.Error(), `from provider "sev_guest"`)
	require.Contains(t, serr.Error(), "gcp-tdx")
	require.Nil(t, serverSaw, "no verifier ran on the server")
	require.Equal(t, report, clientSaw, "the client had verified the server's report before it attested")
}
