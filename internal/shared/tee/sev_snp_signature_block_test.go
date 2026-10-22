// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The signature block beyond the 48-byte r and s is reserved and zero; a
// report with anything else there is not what the firmware emitted and is
// refused at the parse (ADR 0034: found by the differential test, which
// saw the product verify 416 single-byte mutants of every genuine report
// while go-sev-guest refused them all).
func TestSEVSNPParse_RefusesANonZeroSignatureReserve(t *testing.T) {
	matches, err := filepath.Glob("../../../scripts/hardware-test/gcp-sev-snp/keybind-evidence/*/report-vaultgenome.bin")
	require.NoError(t, err)
	if len(matches) == 0 {
		t.Skip("no genuine report on record")
	}
	raw, err := os.ReadFile(matches[len(matches)-1])
	require.NoError(t, err)
	vcek, err := os.ReadFile(filepath.Join(filepath.Dir(matches[len(matches)-1]), "cert-VCEK.bin"))
	require.NoError(t, err)

	rep, err := parseSEVSNPReport(raw)
	require.NoError(t, err)
	require.NoError(t, verifySEVReportSignature(rep, vcek), "the genuine report verifies")

	for _, off := range []int{
		sevOffSignature + sevSigComponent,              // the byte above r's 48
		sevOffSignature + sevSigSlot - 1,               // the last byte of r's slot
		sevOffSignature + sevSigSlot + sevSigComponent, // the byte above s's 48
		sevOffSignature + 2*sevSigSlot,                 // the first reserved byte after s
		sevReportLen - 1,                               // the last byte of the report
	} {
		m := append([]byte(nil), raw...)
		m[off] ^= 0x01
		_, err := parseSEVSNPReport(m)
		require.Error(t, err, "offset %#x", off)
		require.Contains(t, err.Error(), "reserved byte", "offset %#x", off)
	}
	// A flip inside r or s still fails, at the signature.
	m := append([]byte(nil), raw...)
	m[sevOffSignature+1] ^= 0x01
	rep2, err := parseSEVSNPReport(m)
	require.NoError(t, err)
	require.Error(t, verifySEVReportSignature(rep2, vcek))
}
