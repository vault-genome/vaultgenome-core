// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// nitroPinnedDoc is a document with every PCR a Nitro document defines.
func nitroPinnedDoc(label string) map[int][]byte {
	pcrs := map[int][]byte{}
	for _, i := range nitroDefinedPCRs {
		pcrs[i] = nitroPCR(label, i)
	}
	return pcrs
}

// TestAWSNitro_Verifier_PCRPins: the policy holds the document to PCRs
// beyond PCR0 — each pin must match, a missing PCR is refused, and the
// refusal names the PCR.
func TestAWSNitro_Verifier_PCRPins(t *testing.T) {
	t.Parallel()
	now := time.Now()
	chain := newNitroTestChain(t, now)
	nonce := bytes.Repeat([]byte{0x22}, NonceMinBytes)
	pcrs := nitroPinnedDoc("image")
	ev := chain.sign(t, nitroTestDoc{Timestamp: now, Nonce: nonce, PCRs: pcrs})
	build := func(pins map[int][]byte) *AWSNitroVerifier {
		v, err := NewAWSNitroVerifier(nil, pcrs[0], AWSNitroVerifierConfig{PinnedRoots: [][]byte{chain.rootDER}, Now: func() time.Time { return now }, PCRPins: pins})
		require.NoError(t, err)
		return v
	}

	got, err := build(map[int][]byte{1: pcrs[1], 2: pcrs[2], 3: pcrs[3], 4: pcrs[4], 8: pcrs[8]}).Verify(ev, nonce)
	require.NoError(t, err, "every pin matches")
	require.Equal(t, Measurement(pcrs[0]), got)

	for _, i := range []int{1, 2, 3, 4, 8} {
		_, err := build(map[int][]byte{i: nitroPCR("another", i)}).Verify(ev, nonce)
		requireIntegrityErr(t, err, fmt.Sprintf("PCR%d is not the pinned value", i))
	}

	// A document without the pinned PCR is refused, not waved through.
	short := chain.sign(t, nitroTestDoc{Timestamp: now, Nonce: nonce, PCRs: map[int][]byte{0: pcrs[0], 1: pcrs[1]}})
	_, err = build(map[int][]byte{8: pcrs[8]}).Verify(short, nonce)
	requireIntegrityErr(t, err, "PCR8 is not the pinned value")
}

// TestAWSNitro_Verifier_PinsOnTheParentDoNotAdmitADebugEnclave: in debug
// mode PCR0, PCR1 and PCR2 are zero while PCR3 and PCR4 keep the parent's
// values (measured on hardware, ADR 0036, though AWS's guide says a debug
// document's PCRs are all zero). Pins on the parent match such a document;
// the verifier still refuses it by its zero PCR0.
func TestAWSNitro_Verifier_PinsOnTheParentDoNotAdmitADebugEnclave(t *testing.T) {
	t.Parallel()
	now := time.Now()
	chain := newNitroTestChain(t, now)
	nonce := bytes.Repeat([]byte{0x33}, NonceMinBytes)
	prod := nitroPinnedDoc("image")
	zero := make([]byte, 48)
	debug := map[int][]byte{0: zero, 1: zero, 2: zero, 3: prod[3], 4: prod[4], 8: zero}
	ev := chain.sign(t, nitroTestDoc{Timestamp: now, Nonce: nonce, PCRs: debug})
	v, err := NewAWSNitroVerifier(nil, prod[0], AWSNitroVerifierConfig{PinnedRoots: [][]byte{chain.rootDER}, Now: func() time.Time { return now },
		PCRPins: map[int][]byte{3: prod[3], 4: prod[4]}})
	require.NoError(t, err)
	_, err = v.Verify(ev, nonce)
	requireIntegrityErr(t, err, "debug-mode enclave rejected")
}

// TestAWSNitro_Verifier_DetailNamesWhatItRead: the record that admits an
// enclave says which module signed, when, every PCR the document defines,
// the pins it was held to, and the digest of its user data.
func TestAWSNitro_Verifier_DetailNamesWhatItRead(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Millisecond)
	chain := newNitroTestChain(t, now)
	nonce := bytes.Repeat([]byte{0x44}, NonceMinBytes)
	pcrs := nitroPinnedDoc("image")
	pcrs[15] = nitroPCR("undefined", 5)
	userData := []byte("the image's build manifest")
	ev := chain.sign(t, nitroTestDoc{Timestamp: now, Nonce: nonce, PCRs: pcrs, UserData: userData})
	v, err := NewAWSNitroVerifier(nil, pcrs[0], AWSNitroVerifierConfig{PinnedRoots: [][]byte{chain.rootDER}, Now: func() time.Time { return now },
		PCRPins: map[int][]byte{8: pcrs[8], 2: pcrs[2]}})
	require.NoError(t, err)

	m, detail, err := VerifyDetailed(v, ev, nonce)
	require.NoError(t, err)
	require.Equal(t, Measurement(pcrs[0]), m)
	require.NotNil(t, detail)
	require.Equal(t, ProviderAWSNitro, detail.Provider)
	require.NotNil(t, detail.Nitro)
	require.Equal(t, "i-0e35190ae3157095d-enc019e0512a5715d4f", detail.Nitro.ModuleID)
	require.True(t, detail.Nitro.Timestamp.Equal(now))
	require.Equal(t, time.UTC, detail.Nitro.Timestamp.Location())
	require.Len(t, detail.Nitro.PCRs, 6, "the PCRs a document defines, not PCR15")
	for _, i := range nitroDefinedPCRs {
		require.Equal(t, hex.EncodeToString(pcrs[i]), detail.Nitro.PCRs[fmt.Sprint(i)])
	}
	require.Equal(t, []int{2, 8}, detail.Nitro.Pinned, "the pins in order")
	sum := sha256.Sum256(userData)
	require.Equal(t, hex.EncodeToString(sum[:]), detail.Nitro.UserDataSHA256)

	// A refusal carries no detail.
	_, detail, err = VerifyDetailed(v, ev, bytes.Repeat([]byte{0x45}, NonceMinBytes))
	require.Error(t, err)
	require.Nil(t, detail)
}

// TestAWSNitro_Verifier_PCRPinRefusals: a pin that cannot mean anything
// fails at construction.
func TestAWSNitro_Verifier_PCRPinRefusals(t *testing.T) {
	t.Parallel()
	good := nitroPCR("image", 1)
	for name, tc := range map[string]struct {
		pins map[int][]byte
		want string
	}{
		"the measurement itself": {map[int][]byte{0: good}, "PCR0 is the measurement itself"},
		"an undefined PCR":       {map[int][]byte{5: good}, "PCR5 is not one a Nitro attestation document defines"},
		"out of range":           {map[int][]byte{32: good}, "PCR32 is not one"},
		"a short value":          {map[int][]byte{1: good[:32]}, "the PCR1 pin is 32 bytes"},
		"zero":                   {map[int][]byte{8: make([]byte, 48)}, "the PCR8 pin is zero"},
	} {
		_, err := NewAWSNitroVerifier(nil, nitroPCR("image", 0), AWSNitroVerifierConfig{PCRPins: tc.pins})
		requireStructuralErr(t, err, tc.want)
		require.NotEmpty(t, name)
	}
	// With PCR2 as the measurement, PCR0 may be pinned.
	_, err := NewAWSNitroVerifier(nil, nitroPCR("image", 2), AWSNitroVerifierConfig{PCRIndex: 2, PCRPins: map[int][]byte{0: nitroPCR("image", 0)}})
	require.NoError(t, err)
}

// TestAWSNitroPolicyConfig_VerifierConfig: the registry's nitro section
// as the verifier's configuration; absent, the default policy.
func TestAWSNitroPolicyConfig_VerifierConfig(t *testing.T) {
	t.Parallel()
	var absent *AWSNitroPolicyConfig
	cfg, err := absent.VerifierConfig()
	require.NoError(t, err)
	require.Nil(t, cfg.PCRPins)
	require.Zero(t, cfg.MaxClockSkew)

	pcr8 := nitroPCR("signer", 8)
	cfg, err = (&AWSNitroPolicyConfig{PCRs: map[string]string{"8": " " + hex.EncodeToString(pcr8) + " "}, MaxClockSkewSeconds: 60}).VerifierConfig()
	require.NoError(t, err)
	require.Equal(t, map[int][]byte{8: pcr8}, cfg.PCRPins)
	require.Equal(t, time.Minute, cfg.MaxClockSkew)

	for name, c := range map[string]AWSNitroPolicyConfig{
		"negative skew": {MaxClockSkewSeconds: -1},
		"a padded key":  {PCRs: map[string]string{"08": hex.EncodeToString(pcr8)}},
		"not hex":       {PCRs: map[string]string{"8": "not hex"}},
	} {
		_, err := c.VerifierConfig()
		require.Error(t, err, name)
	}
}
