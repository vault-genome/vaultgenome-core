// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestSEVSNPVTPMSealer(t *testing.T, g *fakeSEVGuest) *SEVSNPVTPMSealer {
	t.Helper()
	vt, err := NewVTPMSealer(VTPMSealerConfig{})
	require.NoError(t, err)
	s, err := NewSEVSNPVTPMSealer(NewGCPSEVSealer(sealerDevice(t), g.measurement[:], g.policy), vt)
	require.NoError(t, err)
	return s
}

// The file opens where both agree, and nowhere else: another boot on the same
// chip (the gap the chip's key leaves on a firmware-only measurement), and the
// same boot on another chip, are each refused.
func TestSEVSNPVTPMSealerOpensOnlyWhereChipAndBootAgree(t *testing.T) {
	g := testGuest()
	installFakeGuest(t, g)
	tpm := newFakeVTPM(t)
	s := newTestSEVSNPVTPMSealer(t, g)
	plain := []byte("an escrow key")
	aad := []byte("sagvd escrow")

	blob, err := s.Seal(plain, aad)
	require.NoError(t, err)
	got, err := s.Unseal(blob, aad)
	require.NoError(t, err)
	require.Equal(t, plain, got)

	// The chip alone opens its own blob after the kernel changed: what the
	// nesting is for.
	chipOnly := NewGCPSEVSealer(sealerDevice(t), g.measurement[:], g.policy)
	inner, err := chipOnly.Seal(plain, aad)
	require.NoError(t, err)
	tpm.boot = "boot-2-another-kernel"
	_, err = chipOnly.Unseal(inner, aad)
	require.NoError(t, err, "the chip's key does not see the kernel")
	_, err = s.Unseal(blob, aad)
	require.ErrorContains(t, err, "the vTPM refuses this boot")

	// The same boot, another chip.
	tpm.boot = "boot-1"
	g.chip = []byte("another chip")
	_, err = s.Unseal(blob, aad)
	require.ErrorContains(t, err, "the chip refuses")

	// Another file's AAD.
	g.chip = testGuest().chip
	_, err = s.Unseal(blob, []byte("acp-compute escrow"))
	require.Error(t, err)
}

func TestNewSEVSNPVTPMSealerNeedsBoth(t *testing.T) {
	_, err := NewSEVSNPVTPMSealer(nil, nil)
	require.Error(t, err)
}
