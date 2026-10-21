// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/fips140"
	"runtime/debug"
)

// FIPS140 describes the cryptographic module this process runs on (ADR
// 0030): whether FIPS 140-3 mode is on (the build selected the Go
// Cryptographic Module with GOFIPS140, or fips140=on), whether it is
// enforced (fips140=only — the assessment mode, in which a non-approved
// algorithm fails instead of running), the module's version as the
// Security Policy names it ("v1.0.0"; "latest" outside a frozen module)
// and the GOFIPS140 setting the binary was built with.
type FIPS140 struct {
	Enabled  bool   `json:"enabled"`
	Enforced bool   `json:"enforced"`
	Version  string `json:"version"`
	Build    string `json:"build,omitempty"`
}

// FIPSStatus reports the module's state for identity and version output.
func FIPSStatus() FIPS140 {
	st := FIPS140{Enabled: fips140.Enabled(), Enforced: fips140.Enforced(), Version: fips140.Version()}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "GOFIPS140" {
				st.Build = s.Value
			}
		}
	}
	return st
}

// FIPSOnly reports whether the process runs under fips140=only, where a
// non-approved algorithm (X25519 among them) returns an error or panics.
func FIPSOnly() bool { return fips140.Enforced() }
