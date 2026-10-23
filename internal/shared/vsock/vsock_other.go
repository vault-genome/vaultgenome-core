// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !(linux && (amd64 || arm64))

package vsock

import (
	"context"
	"fmt"
	"net"
	"runtime"
)

// Listen refuses: AF_VSOCK is implemented here for Linux on amd64 and arm64.
func Listen(port uint32) (net.Listener, error) {
	return nil, fmt.Errorf("vsock: AF_VSOCK is not available on %s/%s", runtime.GOOS, runtime.GOARCH)
}

// Dial refuses, as Listen does.
func Dial(context.Context, uint32, uint32) (net.Conn, error) {
	return nil, fmt.Errorf("vsock: AF_VSOCK is not available on %s/%s", runtime.GOOS, runtime.GOARCH)
}
