// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vsock is a stream socket over AF_VSOCK, the only channel a Nitro
// enclave has to its parent instance (ADR 0036): an enclave has no network
// interface at all, not even loopback, so a daemon inside one listens here
// and dials out here. It is written with the standard library's syscall
// package from the kernel's interface (Linux include/uapi/linux/vm_sockets.h:
// struct sockaddr_vm, VMADDR_CID_ANY, VMADDR_CID_LOCAL) and vsock(7); the
// listener and the connections are *os.File on non-blocking descriptors, so
// the runtime's poller drives them, deadlines included, and Close unblocks
// Accept. It exists on Linux on amd64 and arm64; elsewhere Listen and Dial
// refuse.
package vsock

import "fmt"

const (
	// CIDAny binds a listener to whatever CID this host has
	// (VMADDR_CID_ANY, -1U).
	CIDAny = 0xFFFFFFFF
	// CIDLocal is this host itself (VMADDR_CID_LOCAL): the kernel's
	// loopback transport, used by the tests.
	CIDLocal = 1
	// CIDHost is the hypervisor's host (VMADDR_CID_HOST).
	CIDHost = 2
	// CIDNitroParent is the parent instance as an enclave sees it: AWS
	// documents it as always 3.
	CIDNitroParent = 3
)

// Addr is a vsock endpoint: a context identifier and a port.
type Addr struct {
	CID  uint32
	Port uint32
}

// Network implements net.Addr.
func (a Addr) Network() string { return "vsock" }

// String implements net.Addr: "vsock://<cid>:<port>", "any" for CIDAny.
func (a Addr) String() string {
	if a.CID == CIDAny {
		return fmt.Sprintf("vsock://any:%d", a.Port)
	}
	return fmt.Sprintf("vsock://%d:%d", a.CID, a.Port)
}
