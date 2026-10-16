// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import "github.com/vault-genome/vaultgenome-core/internal/shared/tee"

// evRecord is a simulated-TEE Evidence record for the frame tests.
func evRecord(s string) CMWRecord {
	r, err := NewEvidenceRecord(tee.MediaTypeSimulatedEvidence, []byte(s))
	if err != nil {
		panic(err)
	}
	return r
}
