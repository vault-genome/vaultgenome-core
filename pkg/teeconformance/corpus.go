// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: Apache-2.0

package teeconformance

// The SEV-SNP corpus (ADR 0034): every genuine attestation report Vault
// Genome has on record, each with the VCEK it verifies under and AMD's
// chain for its product, and what every verifier must read from it —
// published so that any SEV-SNP verifier, in Go or not, can be held to
// the same bytes. A Go verifier runs it from its own tests with
// RunSEVSNPCorpus; a verifier in any language runs it through
// tools/corpus-harness. The corpus directory is test/corpus/sev-snp in
// the module, or the same directory unpacked from a release.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// SEVSNPReading is what a verifier read from a report: whether it
// verified under the VCEK and chain it was given, and the fields the
// corpus holds every verifier to. A field left zero or nil is not
// compared — a verifier that does not expose it is not held to it.
type SEVSNPReading struct {
	Verified     bool
	Version      uint32
	Policy       uint64
	PlatformInfo uint64
	ReportedTCB  uint64
	Measurement  []byte
	ChipID       []byte
}

// SEVSNPCase is one report of the corpus with its certificates and the
// reading the corpus expects.
type SEVSNPCase struct {
	ID       string
	Product  string // Milan, Genoa, Turin — the KDS product line
	Report   []byte // the raw 1184-byte attestation report
	VCEK     []byte // DER
	Chain    []byte // AMD's ASK+ARK bundle for the product, PEM as KDS serves it
	Expected SEVSNPReading
}

// SEVSNPReader is a verifier's reading of one report under the given
// VCEK and chain. A report that does not verify is reported with
// Verified false or with an error; either counts as refused.
type SEVSNPReader func(report, vcek, chain []byte) (SEVSNPReading, error)

// LoadSEVSNPCorpus reads the corpus directory: manifest.tsv names the
// files, expected.tsv what every verifier must read.
func LoadSEVSNPCorpus(dir string) ([]SEVSNPCase, error) {
	manifest, err := readTSV(filepath.Join(dir, "manifest.tsv"))
	if err != nil {
		return nil, err
	}
	expectedRows, err := readTSV(filepath.Join(dir, "expected.tsv"))
	if err != nil {
		return nil, err
	}
	expected := map[string]map[string]string{}
	for _, r := range expectedRows {
		expected[r["id"]] = r
	}
	var cases []SEVSNPCase
	for _, r := range manifest {
		e, ok := expected[r["id"]]
		if !ok {
			return nil, fmt.Errorf("corpus: %s has no row in expected.tsv", r["id"])
		}
		c := SEVSNPCase{ID: r["id"], Product: r["product"]}
		for _, f := range []struct {
			dst  *[]byte
			path string
		}{{&c.Report, r["report"]}, {&c.VCEK, r["vcek"]}, {&c.Chain, r["chain"]}} {
			b, err := os.ReadFile(filepath.Join(dir, f.path))
			if err != nil {
				return nil, fmt.Errorf("corpus: %s: %w", r["id"], err)
			}
			*f.dst = b
		}
		if c.Expected, err = expectedReading(e); err != nil {
			return nil, fmt.Errorf("corpus: %s: %w", r["id"], err)
		}
		cases = append(cases, c)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("corpus: no reports in %s", dir)
	}
	return cases, nil
}

// RunSEVSNPCorpus holds a verifier to the corpus: every report must
// verify under its VCEK and chain with the fields the corpus expects,
// and two mutants of every report — a byte of the measurement and a
// byte of the signature flipped — must be refused.
func RunSEVSNPCorpus(t *testing.T, dir string, read SEVSNPReader) {
	t.Helper()
	cases, err := LoadSEVSNPCorpus(dir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, c := range cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			got, err := read(c.Report, c.VCEK, c.Chain)
			if err != nil {
				t.Fatalf("the genuine report: %v", err)
			}
			if !got.Verified {
				t.Fatalf("the genuine report did not verify")
			}
			for _, d := range compareReading(got, c.Expected) {
				t.Errorf("%s", d)
			}
			for name, off := range map[string]int{"measurement": 0x090, "signature": 0x2A0} {
				m := append([]byte(nil), c.Report...)
				m[off] ^= 0xFF
				got, err := read(m, c.VCEK, c.Chain)
				if err == nil && got.Verified {
					t.Errorf("a mutant (byte %#x, the %s) verified", off, name)
				}
			}
		})
	}
}

func compareReading(got, want SEVSNPReading) []string {
	var d []string
	if got.Version != 0 && got.Version != want.Version {
		d = append(d, fmt.Sprintf("version: read %d, the corpus says %d", got.Version, want.Version))
	}
	for _, f := range []struct {
		name      string
		got, want uint64
	}{{"policy", got.Policy, want.Policy}, {"platform_info", got.PlatformInfo, want.PlatformInfo}, {"reported_tcb", got.ReportedTCB, want.ReportedTCB}} {
		if f.got != 0 && f.got != f.want {
			d = append(d, fmt.Sprintf("%s: read %#x, the corpus says %#x", f.name, f.got, f.want))
		}
	}
	if got.Measurement != nil && !bytes.Equal(got.Measurement, want.Measurement) {
		d = append(d, fmt.Sprintf("measurement: read %x, the corpus says %x", got.Measurement, want.Measurement))
	}
	if got.ChipID != nil && !bytes.Equal(got.ChipID, want.ChipID) {
		d = append(d, fmt.Sprintf("chip_id: read %x…, the corpus says %x…", got.ChipID[:8], want.ChipID[:8]))
	}
	return d
}

func expectedReading(e map[string]string) (SEVSNPReading, error) {
	var r SEVSNPReading
	r.Verified = e["verdict"] == "verifies"
	v, err := strconv.ParseUint(e["version"], 10, 32)
	if err != nil {
		return r, fmt.Errorf("expected.tsv: version: %w", err)
	}
	r.Version = uint32(v)
	for _, f := range []struct {
		dst *uint64
		col string
	}{{&r.Policy, "policy"}, {&r.PlatformInfo, "platform_info"}, {&r.ReportedTCB, "reported_tcb"}} {
		n, err := strconv.ParseUint(strings.TrimPrefix(e[f.col], "0x"), 16, 64)
		if err != nil {
			return r, fmt.Errorf("expected.tsv: %s: %w", f.col, err)
		}
		*f.dst = n
	}
	if r.Measurement, err = hex.DecodeString(e["measurement"]); err != nil {
		return r, fmt.Errorf("expected.tsv: measurement: %w", err)
	}
	if r.ChipID, err = hex.DecodeString(e["chip_id"]); err != nil {
		return r, fmt.Errorf("expected.tsv: chip_id: %w", err)
	}
	return r, nil
}

func readTSV(path string) ([]map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("%s: no rows", path)
	}
	cols := strings.Split(lines[0], "\t")
	var rows []map[string]string
	for i, l := range lines[1:] {
		f := strings.Split(l, "\t")
		if len(f) != len(cols) {
			return nil, fmt.Errorf("%s: row %d has %d fields, the header %d", path, i+1, len(f), len(cols))
		}
		r := map[string]string{}
		for j, c := range cols {
			r[c] = f[j]
		}
		rows = append(rows, r)
	}
	return rows, nil
}
