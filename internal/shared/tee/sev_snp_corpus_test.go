// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"encoding/binary"
	"testing"

	"github.com/vault-genome/vaultgenome-core/pkg/teeconformance"
)

// The product's own SEV-SNP reading held to the published corpus through
// the public harness (ADR 0034, part four): every genuine report on
// record verifies with the fields the corpus expects, and the two
// mutants of each are refused. The same call any other Go verifier makes.
func TestSEVSNPCorpus_ProductReading(t *testing.T) {
	teeconformance.RunSEVSNPCorpus(t, "../../../test/corpus/sev-snp", func(report, vcek, chain []byte) (teeconformance.SEVSNPReading, error) {
		rep, err := parseSEVSNPReport(report)
		if err != nil {
			return teeconformance.SEVSNPReading{}, err
		}
		if err := verifyAMDChain(vcek, chain); err != nil {
			return teeconformance.SEVSNPReading{}, err
		}
		if err := verifySEVReportSignature(rep, vcek); err != nil {
			return teeconformance.SEVSNPReading{}, err
		}
		return teeconformance.SEVSNPReading{
			Verified:     true,
			Version:      binary.LittleEndian.Uint32(rep.Raw[sevOffVersion:]),
			Policy:       rep.Policy,
			PlatformInfo: binary.LittleEndian.Uint64(rep.Raw[sevOffPlatformInfo:]),
			ReportedTCB:  rep.ReportedTCB,
			Measurement:  rep.Measurement[:],
			ChipID:       rep.ChipID[:],
		}, nil
	})
}
