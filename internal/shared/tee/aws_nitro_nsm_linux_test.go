// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package tee

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// ioc is the kernel's _IOC(dir, type, nr, size): the direction at bit 30,
// the size at 16, the type (the magic) at 8, the number at 0 (Linux
// include/uapi/asm-generic/ioctl.h).
func ioc(dir, typ, nr, size uint32) uint32 {
	return dir<<30 | size<<16 | typ<<8 | nr
}

// NSM_IOCTL_RAW is _IOWR(0x0A, 0, struct nsm_raw) — read and write, the
// magic 0x0A, the number 0, the 32 bytes of struct nsm_raw (Linux
// include/uapi/linux/nsm.h).
func TestNSM_IoctlNumber(t *testing.T) {
	const iocWrite, iocRead = 1, 2 // _IOC_WRITE, _IOC_READ
	require.Equal(t, ioc(iocRead|iocWrite, 0x0A, 0, 32), uint32(nsmIoctlRaw))
	require.Equal(t, uint32(0xC0200A00), uint32(nsmIoctlRaw))
}

// The ioctl goes to the kernel: on a file that is not the NSM the kernel
// answers ENOTTY, and the producer says so.
func TestNSM_RawCallReachesTheKernel(t *testing.T) {
	_, err := nsmRawCallOS(nil, []byte{0xa0})
	require.ErrorContains(t, err, "not open")
	f, err := os.Create(filepath.Join(t.TempDir(), "not-nsm"))
	require.NoError(t, err)
	defer f.Close()
	_, err = nsmRawCallOS(f, []byte{0xa0})
	require.Error(t, err)
	require.True(t, errors.Is(err, syscall.ENOTTY), "%v", err)
	_, err = nsmRawCallOS(f, make([]byte, nsmRequestMaxBytes+1))
	require.ErrorContains(t, err, "4097 bytes")
}
