// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
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

// A log in segments (ADR 0027) as acpctl reads it: the archives before
// the live file, verified as one chain, each archive against the record
// that closed it, and nothing written to any of them.

// segmentedLog is a log of three segments of four events each: two
// archives (the second opening with the first's closing record) and a
// live file opening with the second's closing record.
type segmentedLog struct {
	live, archiveDir string
	pubPath          string
	kid              ids.KeyID
	archives         []store.Archive
	total            int
}

func writeSegmentedLog(t *testing.T) segmentedLog {
	t.Helper()
	dir := t.TempDir()
	live := filepath.Join(dir, "audit.bbolt")
	archiveDir := filepath.Join(dir, "archive")
	ks := keys.NewInMemoryStore(shared_time.NewSystemClock())
	kid := ids.KeyID("test-audit-signing")
	vk, err := ks.RegisterSigningFromSeed(kid, keys.PurposeSigningAudit, bytes.Repeat([]byte{0x24}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	pubPath := filepath.Join(dir, "audit.pub")
	require.NoError(t, os.WriteFile(pubPath, vk.PublicKey, 0o600))

	s, err := store.Open(live)
	require.NoError(t, err)
	c, err := chain.OpenPersistentChain(s, ks)
	require.NoError(t, err)
	n := 0
	appendOne := func() {
		n++
		_, err := c.Append(audit_event.AuditEvent{
			SchemaVersion: audit_event.SchemaVersionCurrent,
			EventID:       ids.AuditEventID(fmt.Sprintf("evt-%04d", n)),
			Kind:          audit_event.KindRequestReceived,
			OccurredAt:    time.Date(2026, 10, 16, 12, 0, n, 0, time.UTC),
			SessionID:     ids.SessionID(fmt.Sprintf("sess-%d", n%2)),
			RequestID:     ids.RequestID(fmt.Sprintf("req-%d", n%3)),
			Payload:       fmt.Appendf(nil, `{"n":%d}`, n),
			SigningKeyID:  kid,
		}, ks)
		require.NoError(t, err)
	}
	rotate := func() {
		var closed store.ClosedSegment
		rotated, err := c.Rotate(func(base, n int, tip []byte) (chain.Persister, error) {
			next, cs, err := store.Rotate(s, archiveDir, base, n, tip)
			if err != nil {
				return nil, err
			}
			s, closed = next, cs
			return next, nil
		}, func() (audit_event.AuditEvent, keys.Signer, error) {
			raw, _ := json.Marshal(closed)
			return audit_event.AuditEvent{
				SchemaVersion: audit_event.SchemaVersionCurrent,
				EventID:       ids.AuditEventID("evt-closing-" + closed.Segment),
				Kind:          audit_event.KindAuditSegmentClosed,
				OccurredAt:    time.Date(2026, 10, 16, 13, 0, n, 0, time.UTC),
				Payload:       raw,
				SigningKeyID:  kid,
			}, ks, nil
		})
		require.NoError(t, err)
		require.True(t, rotated)
	}
	for i := 0; i < 4; i++ {
		appendOne()
	}
	rotate()
	for i := 0; i < 3; i++ {
		appendOne()
	}
	rotate()
	for i := 0; i < 3; i++ {
		appendOne()
	}
	total := c.Len()
	require.NoError(t, s.Close())
	archives, err := store.ListArchives(live, archiveDir)
	require.NoError(t, err)
	require.Len(t, archives, 2)
	return segmentedLog{live: live, archiveDir: archiveDir, pubPath: pubPath, kid: kid, archives: archives, total: total}
}

func (l segmentedLog) verifyArgs(extra ...string) []string {
	return append([]string{"verify", "--audit", l.live, "--audit-pubkey", l.pubPath, "--audit-kid", string(l.kid)}, extra...)
}

func hashOf(t *testing.T, path string) string {
	t.Helper()
	sum, _, err := store.HashFile(path)
	require.NoError(t, err)
	return hex.EncodeToString(sum)
}

// verifyJSON runs audit verify with extra flags and decodes the result.
func verifySegmentsJSON(t *testing.T, l segmentedLog, extra ...string) (int, auditVerifyResult, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	rc := auditCmd(l.verifyArgs(append(extra, "--json")...), &stdout, &stderr)
	var res auditVerifyResult
	if stdout.Len() > 0 {
		require.NoError(t, json.Unmarshal(stdout.Bytes(), &res), stdout.String())
	}
	return rc, res, stderr.String()
}

func TestAuditVerifyCmd_VerifiesTheSegmentsAsOneChain(t *testing.T) {
	t.Parallel()
	l := writeSegmentedLog(t)
	before := []string{hashOf(t, l.archives[0].Path), hashOf(t, l.archives[1].Path)}

	rc, res, stderr := verifySegmentsJSON(t, l)
	require.Equal(t, 0, rc, stderr)
	require.True(t, res.OK)
	require.Equal(t, 12, res.EventCount, "four, then the closing and three, then the closing and three")
	require.Equal(t, l.total, res.EventCount)
	require.Equal(t, l.archiveDir, res.ArchiveDir)
	require.Len(t, res.Segments, 3)
	require.Equal(t, []int{0, 4, 8}, []int{res.Segments[0].FirstIndex, res.Segments[1].FirstIndex, res.Segments[2].FirstIndex})
	require.Equal(t, []int{4, 4, 4}, []int{res.Segments[0].Events, res.Segments[1].Events, res.Segments[2].Events})
	require.Equal(t, before[0], res.Segments[0].SHA256)
	require.Equal(t, before[1], res.Segments[1].SHA256)
	require.True(t, res.Segments[2].Live)
	require.Empty(t, res.Segments[2].SHA256)
	require.Equal(t, res.Segments[2].Tip, res.Tip)
	require.Empty(t, res.StartsAfter)
	require.Equal(t, before, []string{hashOf(t, l.archives[0].Path), hashOf(t, l.archives[1].Path)},
		"verifying changes no byte of an archive")

	// The text form lists the files.
	var stdout, errOut bytes.Buffer
	rc = auditCmd(l.verifyArgs(), &stdout, &errOut)
	require.Equal(t, 0, rc, errOut.String())
	out := stdout.String()
	require.Contains(t, out, "audit chain ok — 12 events verified, tip "+res.Tip)
	require.Contains(t, out, "archive "+l.archives[0].Path+": events #0..#3  sha256 "+before[0])
	require.Contains(t, out, "archive "+l.archives[1].Path+": events #4..#7  sha256 "+before[1])
	require.Contains(t, out, "live    "+l.live+": events #8..#11")

	// A log of one file prints as before.
	path, pub, kid, _ := buildAuditFixture(t, 1)
	pubPath := filepath.Join(t.TempDir(), "pub")
	require.NoError(t, os.WriteFile(pubPath, pub, 0o600))
	stdout.Reset()
	rc = auditCmd([]string{"verify", "--audit", path, "--audit-pubkey", pubPath, "--audit-kid", string(kid)}, &stdout, &errOut)
	require.Equal(t, 0, rc, errOut.String())
	require.Equal(t, 1, strings.Count(stdout.String(), "\n"), stdout.String())
}

func TestAuditVerifyCmd_NeedsTheHistoryOrTheOperatorsWord(t *testing.T) {
	t.Parallel()
	l := writeSegmentedLog(t)
	rc, full, _ := verifySegmentsJSON(t, l)
	require.Equal(t, 0, rc)
	firstTip := full.Segments[0].Tip

	// The first archive shipped away: the chain does not reach genesis.
	require.NoError(t, os.Rename(l.archives[0].Path, l.archives[0].Path+".shipped"))
	rc, res, stderr := verifySegmentsJSON(t, l)
	require.Equal(t, 4, rc)
	require.False(t, res.OK)
	require.Contains(t, res.Error, "segments before it are not in "+l.archiveDir)
	require.Contains(t, res.Error, "--from-tip "+firstTip)
	require.Equal(t, firstTip, res.StartsAfter)
	require.Contains(t, stderr, "chain BROKEN")

	// The operator vouches for it with the tip they recorded: verified
	// from there, and the result says where it starts.
	rc, res, stderr = verifySegmentsJSON(t, l, "--from-tip", firstTip)
	require.Equal(t, 0, rc, stderr)
	require.True(t, res.OK)
	require.Equal(t, 12, res.EventCount)
	require.Len(t, res.Segments, 2)
	require.Equal(t, 4, res.Segments[0].FirstIndex)
	require.Equal(t, firstTip, res.StartsAfter)
	var stdout, errOut bytes.Buffer
	require.Equal(t, 0, auditCmd(l.verifyArgs("--from-tip", firstTip), &stdout, &errOut))
	require.Contains(t, stdout.String(), "starts after tip "+firstTip+": the segments before it are not here")

	// The wrong tip, or no tip at all, is refused.
	wrong := strings.Repeat("ab", 32)
	rc, res, _ = verifySegmentsJSON(t, l, "--from-tip", wrong)
	require.Equal(t, 4, rc)
	require.Contains(t, res.Error, "not after --from-tip "+wrong)
	var out bytes.Buffer
	require.Equal(t, 2, auditCmd(l.verifyArgs("--from-tip", "xyz"), &out, &errOut))
	require.Contains(t, errOut.String(), "--from-tip must be a 32-byte hash")

	// A segment missing in the middle is a gap, whatever is vouched for.
	require.NoError(t, os.Rename(l.archives[0].Path+".shipped", l.archives[0].Path))
	require.NoError(t, os.Rename(l.archives[1].Path, l.archives[1].Path+".shipped"))
	rc, res, _ = verifySegmentsJSON(t, l)
	require.Equal(t, 4, rc)
	require.Contains(t, res.Error, "starts at event #8")
	require.Contains(t, res.Error, "but "+l.archives[0].Name+" ended at event #3")
}

func TestAuditVerifyCmd_AnArchiveMustBeTheFileTheChainRecorded(t *testing.T) {
	t.Parallel()
	l := writeSegmentedLog(t)

	// A byte added to the first archive: it is not the file the second
	// segment's opening record describes.
	f, err := os.OpenFile(l.archives[0].Path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.Write([]byte{0})
	require.NoError(t, err)
	require.NoError(t, f.Close())
	rc, res, stderr := verifySegmentsJSON(t, l)
	require.Equal(t, 4, rc)
	require.False(t, res.OK)
	require.Contains(t, res.Error, l.archives[0].Name+" is not the file the chain recorded")
	require.Contains(t, stderr, "chain BROKEN")

	// An archive renamed to claim other indices: refused by its contents.
	l2 := writeSegmentedLog(t)
	lying := filepath.Join(l2.archiveDir, store.SegmentName(l2.live, 4, 9))
	require.NoError(t, os.Rename(l2.archives[1].Path, lying))
	rc, res, _ = verifySegmentsJSON(t, l2)
	require.Equal(t, 4, rc)
	require.Contains(t, res.Error, "not #4..#9 as its name says")
}

func TestAuditReaders_SpanTheSegments(t *testing.T) {
	t.Parallel()
	l := writeSegmentedLog(t)

	// query: every event of every segment, in order; --request narrows.
	var stdout, stderr bytes.Buffer
	rc := auditCmd([]string{"query", "--audit", l.live, "--limit", "0"}, &stdout, &stderr)
	require.Equal(t, 0, rc, stderr.String())
	require.Contains(t, stdout.String(), "matched: 12 of 12 events")
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	require.Contains(t, lines[0], "evt-0001")
	require.Contains(t, lines[4], "evt-closing-"+l.archives[0].Name)
	require.Contains(t, lines[8], "evt-closing-"+l.archives[1].Name)
	stdout.Reset()
	rc = auditCmd([]string{"query", "--audit", l.live, "--request", "req-1", "--json"}, &stdout, &stderr)
	require.Equal(t, 0, rc, stderr.String())
	require.Equal(t, 4, strings.Count(stdout.String(), "\n"), stdout.String())
	require.NotContains(t, stdout.String(), `"req-2"`)
	stdout.Reset()
	rc = auditCmd([]string{"query", "--audit", l.live, "--archive-dir", t.TempDir()}, &stdout, &stderr)
	require.Equal(t, 0, rc, stderr.String())
	require.Contains(t, stdout.String(), "matched: 4 of 4 events", "another archive directory: the live file alone")

	// status counts the whole log.
	stdout.Reset()
	rc = statusCmd([]string{"--audit", l.live, "--json"}, &stdout, &stderr)
	require.Equal(t, 0, rc, stderr.String())
	var summary statusSummary
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &summary))
	require.Equal(t, 12, summary.AuditEventCount)
	require.Equal(t, 2, summary.KindHistogram[string(audit_event.KindAuditSegmentClosed)])

	// lineage follows a session across the segments.
	stdout.Reset()
	rc = lineageCmd([]string{"--audit", l.live, "--session-id", "sess-1", "--json"}, &stdout, &stderr)
	require.Equal(t, 0, rc, stderr.String())
	require.Equal(t, 5, strings.Count(stdout.String(), `"evt-`), stdout.String())

	// Nothing was written to any file.
	for _, a := range l.archives {
		ro, err := store.OpenReadOnly(a.Path)
		require.NoError(t, err)
		require.NoError(t, ro.Close())
	}
}
