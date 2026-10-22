// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// A peer that hangs up during the handshake is a disconnect on the
// record, not a refusal: the error is classified peer_disconnected,
// Operational, whichever side and step the hang-up lands on. Before
// this, the raw socket error reached the authority's audit as a trust
// refusal of category unknown.
func TestDoHandshake_APeerThatHangsUpIsPeerDisconnected(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	server := func(conn net.Conn) HandshakeConfig {
		return HandshakeConfig{Role: RoleServer, Conn: conn, Producer: peers.serverProducer, Verifier: peers.serverVerifier, LocalProvider: tee.ProviderSimulated, PeerProvider: tee.ProviderSimulated}
	}
	client := func(conn net.Conn) HandshakeConfig {
		return HandshakeConfig{Role: RoleClient, Conn: conn, Producer: peers.clientProducer, Verifier: peers.clientVerifier, LocalProvider: tee.ProviderSimulated, PeerProvider: tee.ProviderSimulated}
	}

	t.Run("the client hangs up before its hello: the server's first read", func(t *testing.T) {
		c, s := net.Pipe()
		defer func() { _ = s.Close() }()
		require.NoError(t, c.Close())
		_, err := DoHandshake(server(s))
		require.Error(t, err)
		require.Equal(t, CodePeerDisconnected, shared_errors.CodeOf(err))
		require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
		require.Contains(t, err.Error(), "hello_client")
	})

	t.Run("the client hangs up after its hello: the server's hello write", func(t *testing.T) {
		c, s := net.Pipe()
		defer func() { _ = s.Close() }()
		go func() {
			hc, err := NewHelloClient(make([]byte, NonceMinBytes), make([]byte, NonceMinBytes))
			if err == nil {
				_ = writeBody(c, hc)
			}
			_ = c.Close()
		}()
		_, err := DoHandshake(server(s))
		require.Error(t, err)
		require.Equal(t, CodePeerDisconnected, shared_errors.CodeOf(err))
		require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	})

	t.Run("the server hangs up after the client's hello: the client's read", func(t *testing.T) {
		c, s := net.Pipe()
		defer func() { _ = c.Close() }()
		go func() {
			var hc HelloClient
			_, _ = readBodyAs(s, FrameTypeHelloClient, &hc)
			_ = s.Close()
		}()
		_, err := DoHandshake(client(c))
		require.Error(t, err)
		require.Equal(t, CodePeerDisconnected, shared_errors.CodeOf(err))
		require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
		require.Contains(t, err.Error(), "hello_server")
	})
}

// A refusal the peer sends as an error frame keeps its own code and
// category through classifyIO: only unclassified I/O errors are turned
// into transport codes.
func TestClassifyIO_LeavesClassifiedErrorsAlone(t *testing.T) {
	t.Parallel()
	refusal := shared_errors.Authority(CodeHandshakeFailure, "contraindicated", nil)
	require.Same(t, refusal, classifyIO(refusal, "attest_client"))
	require.NoError(t, classifyIO(nil, "attest_client"))
}
