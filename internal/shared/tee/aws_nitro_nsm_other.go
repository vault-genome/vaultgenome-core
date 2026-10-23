// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package tee

import (
	"fmt"
	"os"
	"runtime"
)

// nsmRawCallOS refuses: the NSM is a device inside a Nitro enclave, whose
// kernel is Linux.
func nsmRawCallOS(*os.File, []byte) ([]byte, error) {
	return nil, fmt.Errorf("aws-nitro: the NSM exists only inside a Nitro enclave (Linux), not on %s", runtime.GOOS)
}
