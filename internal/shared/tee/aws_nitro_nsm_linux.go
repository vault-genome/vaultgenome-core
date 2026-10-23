// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package tee

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// nsmIoctlRaw is NSM_IOCTL_RAW: _IOWR(NSM_MAGIC 0x0A, 0, struct nsm_raw)
// = (3 << 30) | (32 << 16) | (0x0A << 8) | 0 (Linux include/uapi/linux/nsm.h).
const nsmIoctlRaw = 0xC0200A00

// nsmRaw is struct nsm_raw: the request iovec and the response iovec,
// each a 64-bit address and a 64-bit length. The kernel writes the
// response's length back.
type nsmRaw struct {
	reqAddr, reqLen, respAddr, respLen uint64
}

// The ioctl's size field says 32 bytes; a different layout fails to build.
var _ [32]byte = [unsafe.Sizeof(nsmRaw{})]byte{}

func nsmRawCallOS(f *os.File, req []byte) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("aws-nitro: NSM device not open")
	}
	if len(req) == 0 || len(req) > nsmRequestMaxBytes {
		return nil, fmt.Errorf("aws-nitro: an NSM request of %d bytes (1..%d)", len(req), nsmRequestMaxBytes)
	}
	resp := make([]byte, nsmResponseMaxBytes)
	raw := nsmRaw{
		reqAddr:  uint64(uintptr(unsafe.Pointer(&req[0]))),
		reqLen:   uint64(len(req)),
		respAddr: uint64(uintptr(unsafe.Pointer(&resp[0]))),
		respLen:  uint64(len(resp)),
	}
	sc, err := f.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("aws-nitro: NSM device: %w", err)
	}
	var errno syscall.Errno
	if err := sc.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, nsmIoctlRaw, uintptr(unsafe.Pointer(&raw)))
	}); err != nil {
		return nil, fmt.Errorf("aws-nitro: NSM device: %w", err)
	}
	runtime.KeepAlive(req)
	runtime.KeepAlive(resp)
	if errno != 0 {
		return nil, fmt.Errorf("aws-nitro: NSM_IOCTL_RAW: %w", errno)
	}
	if raw.respLen == 0 || raw.respLen > uint64(len(resp)) {
		return nil, fmt.Errorf("aws-nitro: the NSM wrote %d bytes into a %d-byte buffer", raw.respLen, len(resp))
	}
	return resp[:raw.respLen], nil
}
