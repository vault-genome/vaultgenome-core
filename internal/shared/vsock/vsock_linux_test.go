// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux && (amd64 || arm64)

package vsock

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// struct sockaddr_vm, field by field (uapi/linux/vm_sockets.h).
func TestSockaddrVMLayout(t *testing.T) {
	var sa rawSockaddrVM
	require.Equal(t, uintptr(16), unsafe.Sizeof(sa))
	require.Equal(t, uintptr(0), unsafe.Offsetof(sa.family))
	require.Equal(t, uintptr(2), unsafe.Offsetof(sa.reserved1))
	require.Equal(t, uintptr(4), unsafe.Offsetof(sa.port))
	require.Equal(t, uintptr(8), unsafe.Offsetof(sa.cid))
	require.Equal(t, uintptr(12), unsafe.Offsetof(sa.flags))
}

func TestListenRefusesReservedPorts(t *testing.T) {
	_, err := Listen(0)
	require.ErrorContains(t, err, "want 1..4294967294")
	_, err = Listen(0xFFFFFFFF)
	require.ErrorContains(t, err, "want 1..4294967294")
}

// loopbackOrSkip skips where the kernel has no vsock loopback transport
// (vsock_loopback, Linux 5.6+, not loaded on every CI runner); the
// hardware kit is the proof in an enclave.
func loopbackOrSkip(t *testing.T, port uint32) net.Listener {
	t.Helper()
	ln, err := Listen(port)
	if err != nil {
		if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.ENODEV) || errors.Is(err, syscall.EADDRNOTAVAIL) {
			t.Skipf("no AF_VSOCK on this kernel: %v", err)
		}
		require.NoError(t, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := Dial(ctx, CIDLocal, port)
	if err != nil {
		_ = ln.Close()
		t.Skipf("no vsock loopback transport on this kernel: %v", err)
	}
	// The probe is accepted and closed here, so the test's own Accept gets
	// the test's own connection, not the probe waiting in the backlog.
	probe, err := acceptWithin(ln, 2*time.Second)
	require.NoError(t, err)
	_ = probe.Close()
	_ = c.Close()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// acceptWithin is Accept with a bound, so a test fails rather than hangs.
func acceptWithin(ln net.Listener, d time.Duration) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := ln.Accept(); ch <- res{c, err} }()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-time.After(d):
		return nil, errors.New("accept: nothing within the bound")
	}
}

// A round trip over the kernel's loopback: bytes both ways, the peer
// address, a read deadline, and Close unblocking Accept.
func TestLoopbackRoundTrip(t *testing.T) {
	ln := loopbackOrSkip(t, 47001)
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(io.LimitReader(c, 5))
		_, _ = c.Write([]byte("pong"))
		got <- b
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := Dial(ctx, CIDLocal, 47001)
	require.NoError(t, err)
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = c.Write([]byte("ping!"))
	require.NoError(t, err)
	select {
	case b := <-got:
		require.Equal(t, []byte("ping!"), b)
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not read the bytes")
	}
	reply := make([]byte, 4)
	_, err = io.ReadFull(c, reply)
	require.NoError(t, err)
	require.Equal(t, "pong", string(reply))
	require.NoError(t, c.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = c.Read(reply)
	require.Error(t, err)
	require.NoError(t, c.Close())

	done := make(chan error, 1)
	go func() { _, err := ln.Accept(); done <- err }()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, ln.Close())
	select {
	case err := <-done:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}

// TLS terminates over vsock the way acp-bootstrap serves in an enclave.
func TestLoopbackTLS(t *testing.T) {
	ln := loopbackOrSkip(t, 47002)
	defer ln.Close()
	cert, pool := selfSigned(t)
	srv := tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	go func() {
		c, err := srv.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, io.LimitReader(c, 4))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := Dial(ctx, CIDLocal, 47002)
	require.NoError(t, err)
	require.NoError(t, raw.SetDeadline(time.Now().Add(5*time.Second)))
	c := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "enclave"})
	defer c.Close()
	_, err = c.Write([]byte("echo"))
	require.NoError(t, err)
	b := make([]byte, 4)
	_, err = io.ReadFull(c, b)
	require.NoError(t, err)
	require.Equal(t, "echo", string(b))
}

// The error paths a deployment meets: a port already taken, a port
// nobody listens on, and the addresses a connection reports.
func TestLoopbackErrorsAndAddresses(t *testing.T) {
	ln := loopbackOrSkip(t, 47003)
	require.Equal(t, "vsock://any:47003", ln.Addr().String())

	_, err := Listen(47003)
	require.Error(t, err, "the port is taken")
	require.ErrorContains(t, err, "bind port 47003")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = Dial(ctx, CIDLocal, 47999)
	require.Error(t, err, "nobody listens on 47999")
	require.ErrorContains(t, err, "connect 1:47999")

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	c, err := Dial(ctx, CIDLocal, 47003)
	require.NoError(t, err)
	defer c.Close()
	require.Equal(t, Addr{CID: CIDLocal, Port: 47003}, c.RemoteAddr())
	require.NoError(t, c.SetWriteDeadline(time.Now().Add(time.Second)))
	select {
	case s := <-accepted:
		defer s.Close()
		require.Equal(t, Addr{CID: CIDAny, Port: 47003}, s.LocalAddr())
		require.Equal(t, "vsock", s.RemoteAddr().Network())
	case <-time.After(2 * time.Second):
		t.Fatal("the connection was not accepted")
	}
	// The kernel auto-binds the dialing side to VMADDR_CID_ANY and an
	// ephemeral port; getsockname(2) reports exactly that (Linux 7.0).
	la := c.LocalAddr().(Addr)
	require.Equal(t, uint32(CIDAny), la.CID)
	require.NotZero(t, la.Port)
	require.NotEqual(t, uint32(0xFFFFFFFF), la.Port, "a port, not VMADDR_PORT_ANY")
}

// A CID nobody has is refused at once — by connect(2), or by socket(2)
// where the kernel has no vsock at all; either way Dial says so and
// leaves no descriptor behind. Runs without the loopback transport.
func TestDialRefusesACIDNobodyHas(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := Dial(ctx, 9999, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "vsock: ")
}

// A dial whose deadline has already passed returns an error rather than
// waiting: the connect fails outright or the wait for it times out.
func TestDialHonoursAnExpiredDeadline(t *testing.T) {
	ln := loopbackOrSkip(t, 47004)
	_ = ln
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	c, err := Dial(ctx, CIDLocal, 47998)
	if err == nil {
		_ = c.Close()
		t.Fatal("a dial to a port nobody listens on, with its deadline passed, succeeded")
	}
}
