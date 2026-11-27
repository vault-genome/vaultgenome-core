// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package doctrine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The records of the hardware kits' runs are evidence that others read,
// and name no account of the workstation a run was made from, nor of the
// person at it (scripts/check-records.sh, scripts/hardware-test/
// redact-record.py). Until 2026-11-27 they did: 111 files of the records
// on main named the workstation's user — the paths its runners printed
// under its home, the user a machine's guest agent made for the key gcloud
// put in the project's metadata, the owner of a file a listing named —,
// and nothing held the tree to it.

// Each form the check knows is caught wherever it stands in a file that is
// not source code, and the file is named; a test of code that sets a home
// of its own is not read.
func Test_Regression_RecordsScriptCatchesEachForm(t *testing.T) {
	t.Parallel()
	script := filepath.Join(locateModuleRoot(t), "scripts", "check-records.sh")
	tree := t.TempDir()
	planted := map[string]string{
		"kit/evidence/a/runner.log":              "== evidence: /Users/someone/dev/vg-kit/evidence/a\n",
		"kit/evidence/a/report.json":             `{"corpus": "/Users/someone/dev/vg-kit/test/corpus"}` + "\n",
		"kit/evidence/b/vm-serial-console.txt":   "Nov 27 13:28:01 vm google_guest_agent[947]: Creating user someone.\n",
		"kit/evidence/b/vm-2-serial-console.txt": "Nov 27 13:28:02 vm google_guest_agent[947]: Updating keys for user someone.\n",
		"kit/evidence/c/listing.txt":             "-rw-r--r--@ 1 someone  staff  2.7M Oct 29 20:12 genome.tar\n",
		"kit/evidence/d/steps.txt":               "the oracle: /private/tmp/claude-501/-Users-someone-Desktop-X/12345678-1234-1234-1234-123456789abc/scratchpad/bin/oracle\n",
		"docs/notes.md":                          "the plan (`~/.claude/projects/-Users-someone-Desktop-X/plan.md`)\n",
	}
	for rel, content := range planted {
		p := filepath.Join(tree, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	code := filepath.Join(tree, "cmd", "x", "x_test.go")
	if err := os.MkdirAll(filepath.Dir(code), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(code, []byte("package x\n\n// t.Setenv(\"HOME\", \"/Users/someone\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runScript(t, script, tree)
	if err == nil {
		t.Fatalf("check-records.sh returned green on a tree whose records name an account\noutput:\n%s", out)
	}
	if !strings.Contains(out, "check-records: FAIL") {
		t.Fatalf("check-records.sh failed but did not say FAIL\noutput:\n%s", out)
	}
	for rel := range planted {
		if !strings.Contains(out, "./"+rel) {
			t.Errorf("check-records.sh did not name %s\noutput:\n%s", rel, out)
		}
	}
	if strings.Contains(out, "x_test.go") {
		t.Errorf("check-records.sh read source code: a test of code may set a home of its own\noutput:\n%s", out)
	}
}

// A record that names nobody passes: the forms as the redaction writes
// them are not taken for names, nor is a path under /Users/Shared.
func Test_Regression_RecordsScriptPassesCleanTree(t *testing.T) {
	t.Parallel()
	script := filepath.Join(locateModuleRoot(t), "scripts", "check-records.sh")
	tree := t.TempDir()
	clean := strings.Join([]string{
		"== evidence: ~/dev/vg-kit/evidence/a",
		"Nov 27 13:28:01 vm google_guest_agent[947]: Creating user (an account of whoever runs the kit).",
		"Nov 27 13:28:02 vm google_guest_agent[947]: Updating keys for user (an account of whoever runs the kit).",
		"-rw-r--r--@ 1 (owner)  staff  2.7M Oct 29 20:12 genome.tar",
		"the oracle: <scratch>/bin/oracle",
		"a shared file: /Users/Shared/vg/notes.txt",
		"",
	}, "\n")
	p := filepath.Join(tree, "kit", "evidence", "a", "steps.txt")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(clean), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runScript(t, script, tree)
	if err != nil {
		t.Fatalf("check-records.sh returned non-zero on a clean tree\noutput:\n%s\nerr: %v", out, err)
	}
	if !strings.Contains(out, "check-records: PASS") {
		t.Fatalf("check-records.sh returned zero but did not say PASS\noutput:\n%s", out)
	}
}

// The tree itself: no record of a run, nor any other file but source code,
// names an account of a workstation or of the person at it.
func TestRecords_TheTreeNamesNoAccountOfAWorkstation(t *testing.T) {
	t.Parallel()
	root := locateModuleRoot(t)
	out, err := runScript(t, filepath.Join(root, "scripts", "check-records.sh"), root)
	if err != nil || !strings.Contains(out, "check-records: PASS") {
		t.Fatalf("a file of the tree names an account (redact it with scripts/hardware-test/redact-record.py):\n%s\nerr: %v", out, err)
	}
}
