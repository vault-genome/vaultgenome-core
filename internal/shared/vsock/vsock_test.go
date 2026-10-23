// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package vsock

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddr(t *testing.T) {
	a := Addr{CID: CIDNitroParent, Port: 8000}
	require.Equal(t, "vsock", a.Network())
	require.Equal(t, "vsock://3:8000", a.String())
	require.Equal(t, "vsock://any:5005", Addr{CID: CIDAny, Port: 5005}.String())
}
