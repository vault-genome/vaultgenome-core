// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package store_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
)

// A log in segments (ADR 0027): the store moves a closed segment aside
// as a file, continues from it in a fresh one, reads an archive without
// changing a byte of it, and finishes a rotation a crash interrupted.

func TestSegmentName_And_ListArchives(t *testing.T) {
	t.Parallel()
	live := "/var/lib/vg/returnpath-audit.db"
	require.Equal(t, "returnpath-audit.0000000000-0000000004.db", store.SegmentName(live, 0, 4))
	require.Equal(t, "audit.0000000005-0000001234", store.SegmentName("/x/audit", 5, 1234))

	dir := t.TempDir()
	for _, name := range []string{
		"returnpath-audit.0000000005-0000000009.db",
		"returnpath-audit.0000000000-0000000004.db",
		"returnpath-audit.0000000010-0000000010.db",
		"returnpath-audit.db",                              // the live file's own name
		"other.0000000000-0000000004.db",                   // another log's archive
		"returnpath-audit.0000000020-0000000019.db",        // first after last
		"returnpath-audit.0000000020-0000000021.db.sha256", // not an archive
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600))
	}
	require.NoError(t, os.Mkdir(filepath.Join(dir, "returnpath-audit.0000000030-0000000031.db"), 0o700))

	got, err := store.ListArchives(live, dir)
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, []int{0, 5, 10}, []int{got[0].FirstIndex, got[1].FirstIndex, got[2].FirstIndex})
	require.Equal(t, 9, got[1].LastIndex)
	require.Equal(t, "returnpath-audit.0000000005-0000000009.db", got[1].Name)
	require.Equal(t, filepath.Join(dir, got[1].Name), got[1].Path)

	none, err := store.ListArchives(live, filepath.Join(dir, "absent"))
	require.NoError(t, err)
	require.Empty(t, none)
}

func TestCreate_RecordsWhereTheSegmentStarts(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	tip := bytes.Repeat([]byte{0xAB}, audit_event.HashSize)
	start := store.SegmentStart{
		Schema: store.SegmentStartSchema, FirstIndex: 7, PrevTipHex: hex.EncodeToString(tip),
		PrevSegment: "audit.0000000000-0000000006.db",
	}
	s, err := store.Create(path, start)
	require.NoError(t, err)
	first, prev, err := s.Start()
	require.NoError(t, err)
	require.Equal(t, 7, first)
	require.Equal(t, tip, prev)
	got, ok, err := s.SegmentStart()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, start, got)
	require.NoError(t, s.Append(sampleEvent(0)))
	require.NoError(t, s.Close())

	// Reopened the ordinary way, the file still says where it starts.
	s, err = store.Open(path)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	first, prev, err = s.Start()
	require.NoError(t, err)
	require.Equal(t, 7, first)
	require.Equal(t, tip, prev)
	n, err := s.Len()
	require.NoError(t, err)
	require.Equal(t, 1, n)

	// Never over an existing file.
	_, err = store.Create(path, start)
	require.Error(t, err)

	// A log's first segment has no start of its own: index 0, genesis.
	plain, err := store.Open(filepath.Join(t.TempDir(), "plain.db"))
	require.NoError(t, err)
	defer func() { _ = plain.Close() }()
	first, prev, err = plain.Start()
	require.NoError(t, err)
	require.Equal(t, 0, first)
	require.Equal(t, make([]byte, audit_event.HashSize), prev)
	_, ok, err = plain.SegmentStart()
	require.NoError(t, err)
	require.False(t, ok)

	// A start must be whole.
	for name, bad := range map[string]store.SegmentStart{
		"schema":  {Schema: "x", FirstIndex: 7, PrevTipHex: start.PrevTipHex, PrevSegment: start.PrevSegment},
		"index":   {Schema: store.SegmentStartSchema, FirstIndex: 0, PrevTipHex: start.PrevTipHex, PrevSegment: start.PrevSegment},
		"tip":     {Schema: store.SegmentStartSchema, FirstIndex: 7, PrevTipHex: "zz", PrevSegment: start.PrevSegment},
		"segment": {Schema: store.SegmentStartSchema, FirstIndex: 7, PrevTipHex: start.PrevTipHex, PrevSegment: "a/b.db"},
	} {
		_, err := store.Create(filepath.Join(t.TempDir(), name+".db"), bad)
		require.Error(t, err, name)
	}
}

func TestOpenReadOnly_LeavesTheFileAsItIs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		require.NoError(t, s.Append(sampleEvent(i)))
	}
	require.NoError(t, s.Close())
	before, size, err := store.HashFile(path)
	require.NoError(t, err)

	ro, err := store.OpenReadOnly(path)
	require.NoError(t, err)
	require.True(t, ro.ReadOnly())
	events, err := ro.Load()
	require.NoError(t, err)
	require.Len(t, events, 3)
	n, err := ro.Len()
	require.NoError(t, err)
	require.Equal(t, 3, n)
	evt, ok, err := ro.At(2)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, sampleEvent(2).EventID, evt.EventID)
	require.Error(t, ro.Append(sampleEvent(9)), "a read-only store takes no event")
	_, _, err = store.Rotate(ro, filepath.Join(dir, "archive"), 0, 3, sampleEvent(2).Hash)
	require.Error(t, err, "a read-only store is not rotated")
	require.NoError(t, ro.Close())

	after, size2, err := store.HashFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after, "reading an archive changes no byte of it")
	require.Equal(t, size, size2)

	// A missing file is refused, not created.
	absent := filepath.Join(dir, "absent.db")
	_, err = store.OpenReadOnly(absent)
	require.Error(t, err)
	_, statErr := os.Stat(absent)
	require.True(t, os.IsNotExist(statErr))
}

func TestRotate_MovesTheSegmentAndContinuesFromIt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	live := filepath.Join(dir, "returnpath-audit.db")
	archive := filepath.Join(dir, "archive")
	s, err := store.Open(live)
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		require.NoError(t, s.Append(sampleEvent(i)))
	}
	tip := sampleEvent(4).Hash

	next, closed, err := store.Rotate(s, archive, 0, 5, tip)
	require.NoError(t, err)
	defer func() { _ = next.Close() }()
	require.Equal(t, store.SegmentClosedSchema, closed.Schema)
	require.Equal(t, "returnpath-audit.0000000000-0000000004.db", closed.Segment)
	require.Equal(t, filepath.Join(archive, closed.Segment), closed.Path)
	require.Equal(t, 0, closed.FirstIndex)
	require.Equal(t, 4, closed.LastIndex)
	require.Equal(t, hex.EncodeToString(tip), closed.TipHex)
	sum, size, err := store.HashFile(closed.Path)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(sum), closed.SHA256Hex)
	require.Equal(t, size, closed.Bytes)
	require.Positive(t, size)

	// The fresh live file continues from the archive's tip, empty.
	first, prev, err := next.Start()
	require.NoError(t, err)
	require.Equal(t, 5, first)
	require.Equal(t, tip, prev)
	n, err := next.Len()
	require.NoError(t, err)
	require.Equal(t, 0, n)
	require.NoError(t, next.Append(sampleEvent(5)))

	// The archive reads back whole, read-only, as a log's first segment.
	ro, err := store.OpenReadOnly(closed.Path)
	require.NoError(t, err)
	n, err = ro.Len()
	require.NoError(t, err)
	require.Equal(t, 5, n)
	first, _, err = ro.Start()
	require.NoError(t, err)
	require.Equal(t, 0, first)
	require.NoError(t, ro.Close())

	// The next closing is named by the log's indices, not the file's.
	next2, closed2, err := store.Rotate(next, archive, 5, 6, sampleEvent(5).Hash)
	require.NoError(t, err)
	defer func() { _ = next2.Close() }()
	require.Equal(t, "returnpath-audit.0000000005-0000000005.db", closed2.Segment)
	archives, err := store.ListArchives(live, archive)
	require.NoError(t, err)
	require.Len(t, archives, 2)
	require.Equal(t, closed.Segment, archives[0].Name)
	require.Equal(t, closed2.Segment, archives[1].Name)

	// Nothing to close, a tip that is not a hash: refused, the store
	// still open.
	_, _, err = store.Rotate(next2, archive, 6, 6, tip)
	require.Error(t, err)
	_, _, err = store.Rotate(next2, archive, 6, 7, []byte{1})
	require.Error(t, err)
	require.NoError(t, next2.Append(sampleEvent(6)))
}

func TestRotate_AFailureBeforeTheMoveLeavesTheStoreOpen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	live := filepath.Join(dir, "audit.db")
	s, err := store.Open(live)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	require.NoError(t, s.Append(sampleEvent(0)))

	// The archive directory cannot be created: under a regular file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o600))
	_, _, err = store.Rotate(s, filepath.Join(dir, "file", "archive"), 0, 1, sampleEvent(0).Hash)
	require.Error(t, err)
	require.NoError(t, s.Append(sampleEvent(1)))

	// The archive exists already.
	archive := filepath.Join(dir, "archive")
	require.NoError(t, os.MkdirAll(archive, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(archive, store.SegmentName(live, 0, 1)), []byte("x"), 0o600))
	_, _, err = store.Rotate(s, archive, 0, 2, sampleEvent(1).Hash)
	require.Error(t, err)
	require.NoError(t, s.Append(sampleEvent(2)))
	n, err := s.Len()
	require.NoError(t, err)
	require.Equal(t, 3, n)
}

// rotatedLog writes three events to live, closes them into archive, and
// returns the fresh live store (empty, continuing the archive) and the
// closed segment.
func rotatedLog(t *testing.T, live, archive string) (*store.BBoltStore, store.ClosedSegment) {
	t.Helper()
	s, err := store.Open(live)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		require.NoError(t, s.Append(sampleEvent(i)))
	}
	next, closed, err := store.Rotate(s, archive, 0, 3, sampleEvent(2).Hash)
	require.NoError(t, err)
	return next, closed
}

func TestOpenLive_AFreshLogStartsAtGenesis(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	live := filepath.Join(dir, "audit.db")
	archive := filepath.Join(dir, "archive")
	s, unrecorded, err := store.OpenLive(live, archive)
	require.NoError(t, err)
	require.Nil(t, unrecorded)
	first, _, err := s.Start()
	require.NoError(t, err)
	require.Equal(t, 0, first)
	require.NoError(t, s.Append(sampleEvent(0)))
	require.NoError(t, s.Close())
	_, err = os.Stat(archive)
	require.True(t, os.IsNotExist(err), "a log with nothing closed has no archive directory")

	// An existing first segment opens as it is.
	s, unrecorded, err = store.OpenLive(live, archive)
	require.NoError(t, err)
	require.Nil(t, unrecorded)
	n, err := s.Len()
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.NoError(t, s.Close())

	_, _, err = store.OpenLive("", archive)
	require.Error(t, err)
}

func TestOpenLive_FinishesARotationACrashInterrupted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	live := filepath.Join(dir, "audit.db")
	archive := filepath.Join(dir, "archive")
	next, closed := rotatedLog(t, live, archive)
	require.NoError(t, next.Close())

	// Crashed between the move and the creation of the fresh file: the
	// live file is absent, the archive is there. The log continues from
	// the archive, and the closing is to be recorded.
	require.NoError(t, os.Remove(live))
	s, unrecorded, err := store.OpenLive(live, archive)
	require.NoError(t, err)
	require.NotNil(t, unrecorded)
	require.Equal(t, closed, *unrecorded)
	first, prev, err := s.Start()
	require.NoError(t, err)
	require.Equal(t, 3, first)
	require.Equal(t, sampleEvent(2).Hash, prev)
	n, err := s.Len()
	require.NoError(t, err)
	require.Equal(t, 0, n)
	require.NoError(t, s.Close())

	// Crashed between the creation and the record: the live file is
	// there, empty, and names the archive. Still to be recorded.
	s, unrecorded, err = store.OpenLive(live, archive)
	require.NoError(t, err)
	require.NotNil(t, unrecorded)
	require.Equal(t, closed, *unrecorded)
	require.NoError(t, s.Append(sampleEvent(3)))
	require.NoError(t, s.Close())

	// Recorded: nothing pending.
	s, unrecorded, err = store.OpenLive(live, archive)
	require.NoError(t, err)
	require.Nil(t, unrecorded)
	first, _, err = s.Start()
	require.NoError(t, err)
	require.Equal(t, 3, first)
	require.NoError(t, s.Close())
}

func TestOpenLive_AnEmptyFirstSegmentBesideArchivesContinuesThem(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	live := filepath.Join(dir, "audit.db")
	archive := filepath.Join(dir, "archive")
	next, closed := rotatedLog(t, live, archive)
	require.NoError(t, next.Close())
	require.NoError(t, os.Remove(live))

	// A start that did not know the archives left a fresh first segment.
	plain, err := store.Open(live)
	require.NoError(t, err)
	require.NoError(t, plain.Close())

	s, unrecorded, err := store.OpenLive(live, archive)
	require.NoError(t, err)
	require.NotNil(t, unrecorded)
	require.Equal(t, closed.SHA256Hex, unrecorded.SHA256Hex)
	first, _, err := s.Start()
	require.NoError(t, err)
	require.Equal(t, 3, first)
	require.NoError(t, s.Close())
}

func TestOpenLive_RefusesAChainOfItsOwnBesideArchives(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	live := filepath.Join(dir, "audit.db")
	archive := filepath.Join(dir, "archive")
	next, _ := rotatedLog(t, live, archive)
	require.NoError(t, next.Close())
	require.NoError(t, os.Remove(live))
	plain, err := store.Open(live)
	require.NoError(t, err)
	require.NoError(t, plain.Append(sampleEvent(0)))
	require.NoError(t, plain.Close())

	_, _, err = store.OpenLive(live, archive)
	require.Error(t, err)
	require.Contains(t, err.Error(), "starts a chain of its own")
}

func TestOpenLive_RefusesAnAbsentOrMisnamedArchive(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	live := filepath.Join(dir, "audit.db")
	archive := filepath.Join(dir, "archive")
	next, closed := rotatedLog(t, live, archive)
	require.NoError(t, next.Close())

	// The live file names an archive that is gone: the closing cannot be
	// recorded, and the daemon must not go on without it.
	require.NoError(t, os.Rename(closed.Path, closed.Path+".moved"))
	_, _, err := store.OpenLive(live, archive)
	require.Error(t, err)
	require.Contains(t, err.Error(), "put it back")
	require.NoError(t, os.Rename(closed.Path+".moved", closed.Path))

	// An archive whose name claims more events than it holds.
	require.NoError(t, os.Remove(live))
	lying := filepath.Join(archive, store.SegmentName(live, 0, 9))
	require.NoError(t, os.Rename(closed.Path, lying))
	_, _, err = store.OpenLive(live, archive)
	require.Error(t, err)
	require.Contains(t, err.Error(), "as its name says")
	require.NoError(t, os.Rename(lying, closed.Path))

	// Whole again: the log continues.
	s, unrecorded, err := store.OpenLive(live, archive)
	require.NoError(t, err)
	require.NotNil(t, unrecorded)
	require.NoError(t, s.Close())
}

func TestProbeArchiveDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	live := filepath.Join(dir, "audit.db")
	archive := filepath.Join(dir, "archive")
	require.NoError(t, store.ProbeArchiveDir(live, archive))
	entries, err := os.ReadDir(archive)
	require.NoError(t, err)
	require.Empty(t, entries, "the probe leaves nothing behind")
	entries, err = os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o600))
	require.Error(t, store.ProbeArchiveDir(live, filepath.Join(dir, "file", "archive")))
}
