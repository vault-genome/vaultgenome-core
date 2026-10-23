//go:build differential

// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package chain_test

// ADR 0034, part three: the auditor's own verifier of the audit log
// (tools/auditor/verify_audit.py — the standard library of Python, the
// bbolt file read as bytes, the curves written out) against the product's
// `acpctl audit verify`, on the same files: every genuine log on record,
// a log written under each signature suite with payloads that exercise
// the canonical encoding, and mutants of both. One test calls both; the
// verdicts, the counts and the tips must agree, and a byte out of place
// must be refused by both.
//
//	go test -tags differential ./internal/audit/chain/ -run TestDifferential_Auditor -v
//
// VG_AUDITOR_RECORD=/path/to/file.json writes the record of the run.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

const auditorRoot = "../../.."

type auditorVerdict struct {
	OK     bool
	Events int
	Tip    string
	Err    string
}

func buildACPCTL(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "acpctl")
	out, err := exec.Command("go", "build", "-o", bin, filepath.Join(auditorRoot, "cmd", "acpctl")).CombinedOutput()
	require.NoError(t, err, "building acpctl: %s", out)
	return bin
}

// productVerdict is `acpctl audit verify --json`: the first line is the
// JSON record; a refusal adds a line of prose after it.
func productVerdict(t *testing.T, bin, db, pem string, kid ids.KeyID) auditorVerdict {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, "audit", "verify", "--audit", db, "--audit-pubkey", pem, "--audit-kid", string(kid), "--json")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	line, _, _ := strings.Cut(stdout.String(), "\n")
	var r struct {
		OK         bool   `json:"ok"`
		EventCount int    `json:"event_count"`
		Tip        string `json:"tip"`
		Error      string `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(line), &r), "acpctl output: %s / %s", stdout.String(), stderr.String())
	return auditorVerdict{OK: r.OK, Events: r.EventCount, Tip: r.Tip, Err: r.Error}
}

// auditorVerdictOf is the Python tool's `--json` record.
func auditorVerdictOf(t *testing.T, db, pem string, kid ids.KeyID) auditorVerdict {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("python3", "-I", filepath.Join(auditorRoot, "tools", "auditor", "verify_audit.py"), "--audit", db, "--audit-pubkey", pem, "--audit-kid", string(kid), "--json")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	var r struct {
		OK     bool     `json:"ok"`
		Events int      `json:"events"`
		Tip    string   `json:"tip"`
		Errors []string `json:"errors"`
	}
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &r), "verify_audit.py output: %s / %s", stdout.String(), stderr.String())
	return auditorVerdict{OK: r.OK, Events: r.Events, Tip: r.Tip, Err: strings.Join(r.Errors, "; ")}
}

// writeLog writes a bbolt audit log of n events signed under suite, the
// way the daemons write theirs, with payloads that exercise the canonical
// encoding: HTML-escaped characters, quotes, a line separator, non-ASCII,
// nested objects and arrays, an empty string and a zero.
func writeLog(t *testing.T, dir string, suite crypto.SignatureSuite, n int) (db, pem string, kid ids.KeyID) {
	t.Helper()
	db = filepath.Join(dir, "audit-"+string(suite)+".db")
	ks := keys.NewInMemoryStore(shared_time.NewSystemClock())
	kid = ids.KeyID("audit-" + string(suite))
	vk, err := ks.GenerateSigningSuite(kid, keys.PurposeSigningAudit, suite)
	require.NoError(t, err)
	pubPEM, err := crypto.PublicKeyPEMSuite(suite, vk.PublicKey)
	require.NoError(t, err)
	pem = filepath.Join(dir, "audit-"+string(suite)+".pem")
	require.NoError(t, os.WriteFile(pem, pubPEM, 0o644))
	bs, err := store.Open(db)
	require.NoError(t, err)
	c := chain.NewInMemoryChain()
	t0 := time.Date(2026, 10, 22, 23, 0, 0, 123456789, time.UTC)
	for i := 0; i < n; i++ {
		payload := fmt.Sprintf(`{"suite":%q,"n":%d,"note":"<tag> & \"quotes\"   — кириллица, 日本語","nested":{"z":[1,2,{"a":null,"b":true}],"empty":"","zero":0},"when":"%s"}`,
			suite, i, t0.Add(time.Duration(i)*time.Millisecond*1500).Format(time.RFC3339Nano))
		evt := audit_event.AuditEvent{
			SchemaVersion: audit_event.SchemaVersionCurrent,
			EventID:       ids.AuditEventID(fmt.Sprintf("evt-%04d", i+1)),
			Kind:          audit_event.KindRequestReceived,
			OccurredAt:    t0.Add(time.Duration(i) * 1500 * time.Millisecond),
			SessionID:     ids.SessionID("sess-1"),
			RequestID:     ids.RequestID(fmt.Sprintf("req-%d", i)),
			Payload:       []byte(payload),
			SigningKeyID:  kid,
		}
		signed, err := c.Append(evt, ks)
		require.NoError(t, err)
		require.NoError(t, bs.Append(signed))
	}
	require.NoError(t, bs.Close())
	return db, pem, kid
}

// mutate copies src to dst and flips one byte at offset from the nth
// occurrence of needle — inside an event's stored JSON, so that the file
// stays a bbolt file and the event stays JSON.
func mutate(t *testing.T, src, dst string, needle []byte, nth, offset int) {
	t.Helper()
	b, err := os.ReadFile(src)
	require.NoError(t, err)
	at := -1
	for i := 0; i <= nth; i++ {
		at = bytes.Index(b[at+1:], needle) + at + 1
		require.GreaterOrEqual(t, at, 0, "needle %q #%d", needle, nth)
	}
	m := append([]byte(nil), b...)
	i := at + offset
	if m[i] == 'A' {
		m[i] = 'B'
	} else {
		m[i] = 'A'
	}
	require.NoError(t, os.WriteFile(dst, m, 0o644))
}

type auditorResult struct {
	Case      string `json:"case"`
	Suite     string `json:"suite"`
	Events    int    `json:"events"`
	Product   string `json:"product_acpctl"`
	Auditor   string `json:"auditor_python"`
	TipsEqual bool   `json:"tips_equal"`
	Note      string `json:"note,omitempty"`
}

func TestDifferential_Auditor(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	bin := buildACPCTL(t)
	dir := t.TempDir()
	type tc struct {
		name, db, pem string
		kid           ids.KeyID
		suite         crypto.SignatureSuite
		wantOK        bool
		unsupported   bool // the Python tool says so, by design (ML-DSA-87)
	}
	var cases []tc

	// Every genuine log on record, with the key the kit kept beside it.
	genuine, err := filepath.Glob(filepath.Join(auditorRoot, "scripts", "hardware-test", "*", "evidence", "*", "authority", "xcc-audit.db"))
	require.NoError(t, err)
	require.NotEmpty(t, genuine, "no genuine audit log on record")
	for _, db := range genuine {
		bs, err := store.OpenReadOnly(db)
		require.NoError(t, err)
		events, err := bs.Load()
		require.NoError(t, err)
		require.NoError(t, bs.Close())
		require.NotEmpty(t, events)
		rel, _ := filepath.Rel(auditorRoot, db)
		suite, err := crypto.RecordSuite(events[0].Alg)
		require.NoError(t, err)
		cases = append(cases, tc{name: "genuine:" + rel, db: db, pem: filepath.Join(filepath.Dir(db), "audit.pem"), kid: events[0].SigningKeyID, suite: suite, wantOK: true})
	}
	// A log under each suite, written the way the daemons write theirs.
	for _, suite := range crypto.Suites() {
		if _, err := keys.NewInMemoryStore(nil).GenerateSigningSuite("probe", keys.PurposeSigningAudit, suite); err != nil {
			t.Logf("suite %s not available on this build: %v", suite, err)
			continue
		}
		db, pem, kid := writeLog(t, dir, suite, 9)
		cases = append(cases, tc{name: "written:" + string(suite), db: db, pem: pem, kid: kid, suite: suite, wantOK: true, unsupported: suite == crypto.SuiteMLDSA87})
	}
	// Mutants: a byte of an event's kind, of a signature, of a prev_hash — in a written log and in a genuine one.
	for _, base := range []tc{cases[len(genuine)], cases[0]} {
		for _, m := range []struct {
			what   string
			needle []byte
			nth    int
			off    int
		}{{"kind", []byte(`"kind":"`), 1, 8}, {"signature", []byte(`"signature":"`), 0, 20}, {"prev_hash", []byte(`"prev_hash":"`), 2, 20}} {
			dst := filepath.Join(dir, fmt.Sprintf("mutant-%s-%s.db", m.what, filepath.Base(base.db)))
			mutate(t, base.db, dst, m.needle, m.nth, m.off)
			cases = append(cases, tc{name: "mutant:" + m.what + ":" + base.name, db: dst, pem: base.pem, kid: base.kid, suite: base.suite, wantOK: false, unsupported: base.unsupported})
		}
	}

	var results []auditorResult
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			p := productVerdict(t, bin, c.db, c.pem, c.kid)
			a := auditorVerdictOf(t, c.db, c.pem, c.kid)
			require.Equal(t, c.wantOK, p.OK, "acpctl: %s", p.Err)
			r := auditorResult{Case: c.name, Suite: string(c.suite), Events: p.Events, Product: verdictWord(p), Auditor: verdictWord(a)}
			if c.unsupported {
				require.False(t, a.OK)
				require.Contains(t, a.Err, "not implemented", "the Python tool says it cannot read this suite")
				r.Note = "ML-DSA-87: the auditor's tool does not implement the suite and says so"
			} else {
				require.Equal(t, p.OK, a.OK, "acpctl: %s / python: %s", p.Err, a.Err)
				if p.OK {
					require.Equal(t, p.Events, a.Events)
					require.Equal(t, p.Tip, a.Tip)
					r.TipsEqual = true
				}
			}
			results = append(results, r)
			t.Logf("%s: acpctl %s; python %s%s", c.name, verdictWord(p), verdictWord(a), map[bool]string{true: "; tips equal", false: ""}[r.TipsEqual])
		})
	}
	if rec := os.Getenv("VG_AUDITOR_RECORD"); rec != "" {
		b, err := json.MarshalIndent(map[string]any{"generated_at": time.Now().UTC().Format(time.RFC3339), "cases": len(results), "results": results}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(rec, append(b, '\n'), 0o644))
		t.Logf("record written: %s", rec)
	}
}

func verdictWord(v auditorVerdict) string {
	if v.OK {
		return fmt.Sprintf("ok (%d events, tip %s…)", v.Events, v.Tip[:12])
	}
	first, _, _ := strings.Cut(v.Err, ";")
	if i := strings.Index(first, "event #"); i >= 0 {
		first = first[i:]
	}
	if len(first) > 90 {
		first = first[:90]
	}
	return "refused: " + first
}
