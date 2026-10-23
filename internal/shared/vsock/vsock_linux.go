// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux && (amd64 || arm64)

package vsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// afVSOCK is AF_VSOCK (Linux include/linux/socket.h).
const afVSOCK = 40

// rawSockaddrVM is struct sockaddr_vm: the family, a reserved 16-bit
// field, the port, the CID, svm_flags and the padding to sizeof(struct
// sockaddr), 16 bytes in all.
type rawSockaddrVM struct {
	family    uint16
	reserved1 uint16
	port      uint32
	cid       uint32
	flags     uint8
	zero      [3]uint8
}

// A different layout fails to build.
var _ [16]byte = [unsafe.Sizeof(rawSockaddrVM{})]byte{}

func newSocket() (int, error) {
	fd, err := syscall.Socket(afVSOCK, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("vsock: socket(AF_VSOCK): %w", err)
	}
	return fd, nil
}

// sockaddrCall is bind(2) or connect(2) on a sockaddr_vm: the syscall
// package's Sockaddr has no AF_VSOCK variant, so the call is made raw.
func sockaddrCall(trap uintptr, fd int, sa *rawSockaddrVM) syscall.Errno {
	_, _, e := syscall.Syscall(trap, uintptr(fd), uintptr(unsafe.Pointer(sa)), unsafe.Sizeof(*sa))
	return e
}

// Listen binds a stream listener to port on every CID this host has.
func Listen(port uint32) (net.Listener, error) {
	if port == 0 || port == 0xFFFFFFFF {
		return nil, fmt.Errorf("vsock: listen port %d: want 1..4294967294", port)
	}
	fd, err := newSocket()
	if err != nil {
		return nil, err
	}
	sa := rawSockaddrVM{family: afVSOCK, port: port, cid: CIDAny}
	if e := sockaddrCall(syscall.SYS_BIND, fd, &sa); e != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("vsock: bind port %d: %w", port, e)
	}
	if err := syscall.Listen(fd, syscall.SOMAXCONN); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("vsock: listen port %d: %w", port, err)
	}
	f := os.NewFile(uintptr(fd), fmt.Sprintf("vsock-listener:%d", port))
	rc, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("vsock: listener: %w", err)
	}
	return &listener{f: f, rc: rc, addr: Addr{CID: CIDAny, Port: port}}, nil
}

type listener struct {
	f    *os.File
	rc   syscall.RawConn
	addr Addr
	// closed is set by Close: the raw read Accept waits in reports a
	// closed descriptor as the poller's "use of closed file", which is
	// neither os.ErrClosed nor net.ErrClosed, so Accept answers from this.
	closed atomic.Bool
}

// Accept waits for a connection through the runtime's poller; Close makes
// it return net.ErrClosed. accept4(2) is made raw because the syscall
// package's Accept4 closes a descriptor whose peer address family it does
// not know — and it does not know AF_VSOCK.
func (l *listener) Accept() (net.Conn, error) {
	var (
		nfd  = -1
		peer rawSockaddrVM
		aerr syscall.Errno
	)
	err := l.rc.Read(func(fd uintptr) bool {
		salen := uint32(unsafe.Sizeof(peer))
		r, _, e := syscall.Syscall6(syscall.SYS_ACCEPT4, fd, uintptr(unsafe.Pointer(&peer)), uintptr(unsafe.Pointer(&salen)),
			syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0, 0)
		switch e {
		case 0:
			nfd = int(r)
			return true
		case syscall.EAGAIN:
			return false
		default:
			aerr = e
			return true
		}
	})
	if err != nil {
		if l.closed.Load() || errors.Is(err, os.ErrClosed) {
			return nil, net.ErrClosed
		}
		return nil, fmt.Errorf("vsock: accept: %w", err)
	}
	if aerr != 0 {
		return nil, fmt.Errorf("vsock: accept: %w", aerr)
	}
	return &conn{f: os.NewFile(uintptr(nfd), "vsock-conn"), local: l.addr, remote: Addr{CID: peer.cid, Port: peer.port}}, nil
}

func (l *listener) Close() error {
	l.closed.Store(true)
	return l.f.Close()
}
func (l *listener) Addr() net.Addr { return l.addr }

// Dial connects to port on cid. A deadline on ctx bounds the connect.
func Dial(ctx context.Context, cid, port uint32) (net.Conn, error) {
	fd, err := newSocket()
	if err != nil {
		return nil, err
	}
	sa := rawSockaddrVM{family: afVSOCK, port: port, cid: cid}
	e := sockaddrCall(syscall.SYS_CONNECT, fd, &sa)
	if e != 0 && e != syscall.EINPROGRESS {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("vsock: connect %d:%d: %w", cid, port, e)
	}
	f := os.NewFile(uintptr(fd), fmt.Sprintf("vsock-conn:%d:%d", cid, port))
	if e == syscall.EINPROGRESS {
		if err := awaitConnect(ctx, f); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("vsock: connect %d:%d: %w", cid, port, err)
		}
	}
	return &conn{f: f, local: localAddr(f), remote: Addr{CID: cid, Port: port}}, nil
}

// localAddr is getsockname(2) on a sockaddr_vm: what the kernel bound a
// dialed connection to — VMADDR_CID_ANY and an ephemeral port, as its
// auto-bind does; the zero Addr if it cannot be read.
func localAddr(f *os.File) Addr {
	rc, err := f.SyscallConn()
	if err != nil {
		return Addr{}
	}
	var (
		local rawSockaddrVM
		e     syscall.Errno
	)
	_ = rc.Control(func(fd uintptr) {
		salen := uint32(unsafe.Sizeof(local))
		_, _, e = syscall.Syscall(syscall.SYS_GETSOCKNAME, fd, uintptr(unsafe.Pointer(&local)), uintptr(unsafe.Pointer(&salen)))
	})
	if e != 0 {
		return Addr{}
	}
	return Addr{CID: local.cid, Port: local.port}
}

// awaitConnect waits for a non-blocking connect to finish, as the
// standard library's net package does: on every wake of the poller —
// the first call included, because preparing the wait clears a readiness
// the poller may already have seen — SO_ERROR says whether the connect
// failed, and getpeername(2) whether it has succeeded; anything else is
// still connecting, and the poller is asked to wait for writability.
func awaitConnect(ctx context.Context, f *os.File) error {
	if dl, ok := ctx.Deadline(); ok {
		if err := f.SetWriteDeadline(dl); err != nil {
			return err
		}
		defer func() { _ = f.SetWriteDeadline(time.Time{}) }()
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var soErr error
	if err := rc.Write(func(fd uintptr) bool {
		v, gerr := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_ERROR)
		switch e := syscall.Errno(v); {
		case gerr != nil:
			soErr = gerr
			return true
		case v != 0 && e != syscall.EINPROGRESS && e != syscall.EALREADY && e != syscall.EINTR:
			soErr = e
			return true
		case peerConnected(fd):
			return true
		default:
			return false
		}
	}); err != nil {
		return err
	}
	return soErr
}

// peerConnected is getpeername(2) on a sockaddr_vm: it succeeds once the
// socket is connected and fails with ENOTCONN before.
func peerConnected(fd uintptr) bool {
	var peer rawSockaddrVM
	salen := uint32(unsafe.Sizeof(peer))
	_, _, e := syscall.Syscall(syscall.SYS_GETPEERNAME, fd, uintptr(unsafe.Pointer(&peer)), uintptr(unsafe.Pointer(&salen)))
	return e == 0
}

// conn is a connected vsock stream on a pollable *os.File.
type conn struct {
	f             *os.File
	local, remote Addr
}

func (c *conn) Read(b []byte) (int, error)         { return c.f.Read(b) }
func (c *conn) Write(b []byte) (int, error)        { return c.f.Write(b) }
func (c *conn) Close() error                       { return c.f.Close() }
func (c *conn) LocalAddr() net.Addr                { return c.local }
func (c *conn) RemoteAddr() net.Addr               { return c.remote }
func (c *conn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }
