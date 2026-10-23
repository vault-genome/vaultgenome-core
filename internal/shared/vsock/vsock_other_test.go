// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !(linux && (amd64 || arm64))

package vsock

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// Where AF_VSOCK is not implemented, both ends refuse with the platform named.
func TestRefusedOffLinux(t *testing.T) {
	_, err := Listen(5005)
	require.ErrorContains(t, err, "AF_VSOCK is not available on")
	_, err = Dial(context.Background(), CIDNitroParent, 8000)
	require.ErrorContains(t, err, "AF_VSOCK is not available on")
}
