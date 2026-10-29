//go:build differential

// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The differential test of ADR 0034: the product's reading of every
// genuine SEV-SNP report on record (test/corpus/sev-snp) is held against
// two implementations nobody here wrote — Google's go-sev-guest, through
// tools/oracle, and VirTEE's snpguest when VG_SNPGUEST names it — on the
// verdict, on the fields, and on the refusal map of every single-byte
// mutant of every report. One test calls both sides; a drift between
// them is a red test, not a note.
//
//	VG_ORACLE=/path/to/oracle VG_SNPGUEST=/path/to/snpguest go test -tags differential ./internal/shared/tee/ -run TestDifferential -v
//
// VG_ORACLE unset builds tools/oracle on the fly; VG_SNPGUEST unset
// skips the VirTEE leg (snpguest builds on Linux x86-64 only).
// VG_DIFFERENTIAL_RECORD=/path/to/file.json writes the record of the run.

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	differentialRoot   = "../../.."
	differentialCorpus = "test/corpus/sev-snp"
)

type corpusRow map[string]string

func readCorpus(t *testing.T) []corpusRow {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(differentialRoot, differentialCorpus, "manifest.tsv"))
	require.NoError(t, err, "the corpus manifest; build it with python3 -I test/corpus/sev-snp/build.py")
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	require.Greater(t, len(lines), 1)
	cols := strings.Split(lines[0], "\t")
	var rows []corpusRow
	for _, l := range lines[1:] {
		f := strings.Split(l, "\t")
		require.Len(t, f, len(cols), l)
		r := corpusRow{}
		for i, c := range cols {
			r[c] = f[i]
		}
		rows = append(rows, r)
	}
	return rows
}

type oracleOut struct {
	Tool        string         `json:"tool"`
	Parsed      bool           `json:"parsed"`
	ParseError  string         `json:"parse_error"`
	ProductLine string         `json:"product_line"`
	Verified    bool           `json:"verified"`
	VerifyError string         `json:"verify_error"`
	Report      map[string]any `json:"report"`
	Sweep       string         `json:"sweep"`
}

func oracleBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("VG_ORACLE"); p != "" {
		return p
	}
	bin := filepath.Join(t.TempDir(), "oracle")
	cmd := exec.Command("go", "build", "-C", filepath.Join(differentialRoot, "tools", "oracle"), "-o", bin, ".")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "building tools/oracle: %s", out)
	return bin
}

func runOracle(t *testing.T, bin, report, vcek, chain string, sweep bool) oracleOut {
	t.Helper()
	args := []string{"sevsnp", "-report", report, "-vcek", vcek, "-chain", chain}
	if sweep {
		args = append(args, "-sweep")
	}
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run() // exit 1 is a refusal, read from the JSON; exit 2 is a usage error
	var out oracleOut
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out), "oracle output: %s / %s", stdout.String(), stderr.String())
	return out
}

// protojson prints uint64 as a decimal string, uint32 as a number, bytes
// as base64, and leaves zero-valued fields out.
func pjU64(t *testing.T, v any) uint64 {
	t.Helper()
	switch x := v.(type) {
	case nil:
		return 0
	case string:
		n, err := strconv.ParseUint(x, 10, 64)
		require.NoError(t, err, x)
		return n
	case float64:
		return uint64(x)
	}
	t.Fatalf("unexpected protojson value %T", v)
	return 0
}

func pjBytes(t *testing.T, v any) []byte {
	t.Helper()
	if v == nil {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(v.(string))
	require.NoError(t, err)
	return b
}

// cpuidFMS is the CPUID function 1 EAX value for a family, model and
// stepping, the form go-sev-guest reports (extended family and model in
// the high bits, as the chip encodes them).
func cpuidFMS(fam, model, step uint8) uint32 {
	base, ext := uint32(fam), uint32(0)
	if fam >= 0xF {
		base, ext = 0xF, uint32(fam)-0xF
	}
	return ext<<20 | uint32(model>>4)<<16 | base<<8 | uint32(model&0xF)<<4 | uint32(step)
}

// ourSweep flips every byte of the report in turn and records, per
// offset, how the product refuses the mutant: P at the parse, S at the
// signature — or V if it verifies, which no offset may.
func ourSweep(raw, vcek []byte) string {
	var sb strings.Builder
	for i := range raw {
		m := append([]byte(nil), raw...)
		m[i] ^= 0xFF
		rep, err := parseSEVSNPReport(m)
		switch {
		case err != nil:
			sb.WriteByte('P')
		case verifySEVReportSignature(rep, vcek) != nil:
			sb.WriteByte('S')
		default:
			sb.WriteByte('V')
		}
	}
	return sb.String()
}

// offsetRanges prints the offsets whose sweep letter is c as hex ranges.
func offsetRanges(sweep string, c byte) string {
	var parts []string
	start := -1
	for i := 0; i <= len(sweep); i++ {
		in := i < len(sweep) && sweep[i] == c
		switch {
		case in && start < 0:
			start = i
		case !in && start >= 0:
			if i-1 == start {
				parts = append(parts, fmt.Sprintf("%#x", start))
			} else {
				parts = append(parts, fmt.Sprintf("%#x-%#x", start, i-1))
			}
			start = -1
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

func toPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// snpguestCertsDir lays the chain out the way snpguest reads it: ark.pem,
// ask.pem and vcek.pem in one directory — or ark.pem, asvk.pem and
// vlek.pem for a report a VLEK signed (ADR 0038).
func snpguestCertsDir(t *testing.T, vcek, chainPEM []byte, signer string) string {
	t.Helper()
	dir := t.TempDir()
	rest := chainPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		require.NoError(t, err)
		name := "ask.pem"
		if signer == AMDSignerVLEK {
			name = "asvk.pem"
		}
		if c.Subject.String() == c.Issuer.String() {
			name = "ark.pem"
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), toPEM(blk.Bytes), 0o644))
	}
	v := vcek
	if !bytes.HasPrefix(v, []byte("-----BEGIN")) {
		v = toPEM(v)
	}
	leaf := "vcek.pem"
	if signer == AMDSignerVLEK {
		leaf = "vlek.pem"
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, leaf), v, 0o644))
	return dir
}

type differentialResult struct {
	ID             string `json:"id"`
	Product        string `json:"product"`
	Version        uint32 `json:"version"`
	Chip           string `json:"chip_id_prefix"`
	ReportedTCB    string `json:"reported_tcb"`
	Product_       string `json:"product_verdict"`
	Google         string `json:"google_go_sev_guest"`
	VirTEE         string `json:"virtee_snpguest"`
	FieldsCompared int    `json:"fields_compared"`
	SweepOurs      string `json:"sweep_product"` // counts: P/S/V
	SweepGoogle    string `json:"sweep_go_sev_guest"`
	SameRefusalMap bool   `json:"same_refusal_offsets"` // every offset refused by both
}

func TestDifferential_SEVSNP(t *testing.T) {
	rows := readCorpus(t)
	bin := oracleBinary(t)
	snpguest := os.Getenv("VG_SNPGUEST")
	var results []differentialResult
	for _, r := range rows {
		r := r
		t.Run(r["id"], func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(differentialRoot, differentialCorpus, r["report"]))
			require.NoError(t, err)
			vcek, err := os.ReadFile(filepath.Join(differentialRoot, differentialCorpus, r["vcek"]))
			require.NoError(t, err)
			chain, err := os.ReadFile(filepath.Join(differentialRoot, differentialCorpus, r["chain"]))
			require.NoError(t, err)

			// The product's reading: parse, AMD's chain (the VCEK's, or a
			// VLEK's through the ASVK — ADR 0038), the signature, the detail.
			rep, err := parseSEVSNPReport(raw)
			require.NoError(t, err, "product: parse")
			signer := r["signer"]
			if signer == "" {
				signer = AMDSignerVCEK
			}
			require.Equal(t, signer, sevSigningKeyName(rep.SigningKey), "the manifest's signer is the report's FLAGS.SIGNING_KEY")
			if signer == AMDSignerVLEK {
				require.NoError(t, verifyAMDChainVLEK(vcek, chain), "product: AMD VLEK chain")
				require.Error(t, verifyAMDChain(vcek, chain), "product: a VLEK is refused under the VCEK chain check")
			} else {
				require.NoError(t, verifyAMDChain(vcek, chain), "product: AMD chain")
			}
			require.NoError(t, verifySEVReportSignature(rep, vcek), "product: signature")
			det := sevSNPReportDetail(rep)

			// Google's reading.
			out := runOracle(t, bin, filepath.Join(differentialRoot, differentialCorpus, r["report"]), filepath.Join(differentialRoot, differentialCorpus, r["vcek"]), filepath.Join(differentialRoot, differentialCorpus, r["chain"]), true)
			require.True(t, out.Parsed, "go-sev-guest: parse: %s", out.ParseError)
			require.True(t, out.Verified, "go-sev-guest: verify: %s", out.VerifyError)
			require.Equal(t, r["product"], out.ProductLine, "product line")
			R := out.Report
			fields := 0
			check := func(name string, ours, theirs any) {
				require.Equal(t, ours, theirs, "%s: product vs go-sev-guest", name)
				fields++
			}
			check("version", uint64(det.Version), pjU64(t, R["version"]))
			check("guest_svn", uint64(det.GuestSVN), pjU64(t, R["guest_svn"]))
			check("policy", rep.Policy, pjU64(t, R["policy"]))
			check("platform_info", binary.LittleEndian.Uint64(raw[0x040:]), pjU64(t, R["platform_info"]))
			check("vmpl", uint64(rep.VMPL), pjU64(t, R["vmpl"]))
			check("signature_algo", uint64(rep.SignatureAlgo), pjU64(t, R["signature_algo"]))
			check("current_tcb", binary.LittleEndian.Uint64(raw[0x038:]), pjU64(t, R["current_tcb"]))
			check("reported_tcb", rep.ReportedTCB, pjU64(t, R["reported_tcb"]))
			check("committed_tcb", binary.LittleEndian.Uint64(raw[0x1E0:]), pjU64(t, R["committed_tcb"]))
			check("launch_tcb", binary.LittleEndian.Uint64(raw[0x1F0:]), pjU64(t, R["launch_tcb"]))
			check("measurement", rep.Measurement[:], pjBytes(t, R["measurement"]))
			check("host_data", rep.HostData[:], pjBytes(t, R["host_data"]))
			check("report_data", rep.ReportData[:], pjBytes(t, R["report_data"]))
			check("chip_id", rep.ChipID[:], pjBytes(t, R["chip_id"]))
			check("current_mit_vector", det.MitigationVector.Current, fmt.Sprintf("%#x", pjU64(t, R["current_mit_vector"])))
			check("launch_mit_vector", det.MitigationVector.Launch, fmt.Sprintf("%#x", pjU64(t, R["launch_mit_vector"])))
			check("firmware_current", det.Firmware.Current, fmt.Sprintf("%d.%d.%d", pjU64(t, R["current_major"]), pjU64(t, R["current_minor"]), pjU64(t, R["current_build"])))
			check("firmware_committed", det.Firmware.Committed, fmt.Sprintf("%d.%d.%d", pjU64(t, R["committed_major"]), pjU64(t, R["committed_minor"]), pjU64(t, R["committed_build"])))
			if det.Version >= 3 {
				check("cpuid_fms", uint64(cpuidFMS(det.CPUID.Family, det.CPUID.Model, det.CPUID.Stepping)), pjU64(t, R["cpuid1eax_fms"]))
			}

			// Every single-byte mutant: refused by both, at whichever stage.
			ours := ourSweep(raw, vcek)
			require.Len(t, out.Sweep, len(raw), "go-sev-guest sweep length")
			if n := strings.Count(ours, "V"); n != 0 {
				t.Logf("product verified %d mutants at offsets %s", n, offsetRanges(ours, 'V'))
			}
			if n := strings.Count(out.Sweep, "V"); n != 0 {
				t.Logf("go-sev-guest verified %d mutants at offsets %s", n, offsetRanges(out.Sweep, 'V'))
			}
			t.Logf("refusal stages — product: parse %s, signature %s; go-sev-guest: parse %s, verify %s",
				offsetRanges(ours, 'P'), offsetRanges(ours, 'S'), offsetRanges(out.Sweep, 'P'), offsetRanges(out.Sweep, 'S'))
			require.Equal(t, 0, strings.Count(ours, "V"), "product verified a mutant")
			require.Equal(t, 0, strings.Count(out.Sweep, "V"), "go-sev-guest verified a mutant")
			count := func(s string) string {
				return fmt.Sprintf("P=%d S=%d V=%d", strings.Count(s, "P"), strings.Count(s, "S"), strings.Count(s, "V"))
			}

			// VirTEE's reading, when the tool is here.
			virtee := "not run (VG_SNPGUEST unset)"
			if snpguest != "" {
				dir := snpguestCertsDir(t, vcek, chain, signer)
				for _, args := range [][]string{{"verify", "certs", dir}, {"verify", "attestation", dir, filepath.Join(differentialRoot, differentialCorpus, r["report"])}} {
					o, err := exec.Command(snpguest, args...).CombinedOutput()
					require.NoError(t, err, "snpguest %v: %s", args, o)
				}
				o, err := exec.Command(snpguest, "display", "report", filepath.Join(differentialRoot, differentialCorpus, r["report"])).CombinedOutput()
				require.NoError(t, err, "snpguest display report: %s", o)
				shown := strings.ToLower(strings.Map(func(c rune) rune {
					if c == ' ' || c == '\n' || c == '\t' {
						return -1
					}
					return c
				}, string(o)))
				require.Contains(t, shown, hex.EncodeToString(rep.Measurement[:]), "snpguest shows the measurement the product read")
				require.Contains(t, shown, hex.EncodeToString(rep.ChipID[:]), "snpguest shows the chip id the product read")
				virtee = "verified; measurement and chip id as the product read them"
			}

			results = append(results, differentialResult{
				ID: r["id"], Product: r["product"], Version: det.Version, Chip: r["chip_id"][:16], ReportedTCB: r["reported_tcb"],
				Product_: "verified", Google: "verified", VirTEE: virtee, FieldsCompared: fields,
				SweepOurs: count(ours), SweepGoogle: count(out.Sweep), SameRefusalMap: true,
			})
			t.Logf("%s: %s v%d chip %s… tcb %s — product verified, go-sev-guest verified, %d fields equal; mutants: product %s, go-sev-guest %s; snpguest: %s",
				r["id"], r["product"], det.Version, r["chip_id"][:12], r["reported_tcb"], fields, count(ours), count(out.Sweep), virtee)
		})
	}
	if rec := os.Getenv("VG_DIFFERENTIAL_RECORD"); rec != "" {
		record := map[string]any{
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"corpus":       differentialCorpus,
			"reports":      len(results),
			"oracle":       "go-sev-guest v0.15.0 (tools/oracle)",
			"snpguest":     snpguest != "",
			"results":      results,
		}
		b, err := json.MarshalIndent(record, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(rec, append(b, '\n'), 0o644))
		t.Logf("record written: %s", rec)
	}
}
