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

// NSM_IOCTL_RAW is _IOWR(0x0A, 0, struct nsm_raw): the direction bits
// (read|write = 3) at 30, the 32-byte size at 16, the magic at 8, the
// number at 0 (Linux include/uapi/asm-generic/ioctl.h, uapi/linux/nsm.h).
func TestNSM_IoctlNumber(t *testing.T) {
	const iocRead, iocWrite = 2, 1
	want := uint32((iocRead|iocWrite)<<30 | 32<<16 | 0x0A<<8 | 0)
	require.Equal(t, want, uint32(nsmIoctlRaw))
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
