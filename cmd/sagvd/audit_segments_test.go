// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// The audit log in segments (ADR 0027): a trigger closes the live file
// into the archive directory, the closing is the first event of the
// fresh file, the count and the links continue, and a start finishes
// what a crash interrupted.

// segmentedAuditConfig is a config whose log closes segments by count
// and by age (0 turns a trigger off).
func segmentedAuditConfig(t *testing.T, events, maxAgeSeconds int) Config {
	t.Helper()
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "audit.seed")
	require.NoError(t, os.WriteFile(seedPath, bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize), 0o600))
	cfg := DefaultConfig()
	cfg.Audit.LogPath = filepath.Join(dir, "returnpath.db")
	cfg.Audit.SegmentEvents = events
	cfg.Audit.SegmentMaxAgeSeconds = maxAgeSeconds
	cfg.Keys.AuditSigning = SigningKeyConfig{KeyID: "audit-test-1", SeedPath: seedPath}
	return cfg
}

func openSegmentedAudit(t *testing.T, cfg Config, clock shared_time.Clock) (*returnPathAudit, *metrics.Registry) {
	t.Helper()
	registry := metrics.NewRegistry()
	a, err := openReturnPathAudit(cfg, clock, registry, nil)
	require.NoError(t, err)
	require.NotNil(t, a)
	t.Cleanup(func() { _ = a.Close() })
	return a, registry
}

func refuse(t *testing.T, a *returnPathAudit, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		require.NoError(t, a.TrustRefused("tls", "10.0.0.9:4", tee.Provider("simulated"), errors.New("no certificate")))
	}
}

func archivesOf(t *testing.T, cfg Config) []store.Archive {
	t.Helper()
	archives, err := store.ListArchives(cfg.Audit.LogPath, cfg.Audit.ArchiveDirectory())
	require.NoError(t, err)
	return archives
}

// closingRecord reads the AUDIT_SEGMENT_CLOSED event at idx and checks
// it against the archive it names.
func closingRecord(t *testing.T, a *returnPathAudit, idx int) store.ClosedSegment {
	t.Helper()
	evt, ok := a.persistent.EventAt(idx)
	require.True(t, ok, "event #%d", idx)
	require.Equal(t, audit_event.KindAuditSegmentClosed, evt.Kind)
	var closed store.ClosedSegment
	require.NoError(t, json.Unmarshal(evt.Payload, &closed))
	require.Equal(t, store.SegmentClosedSchema, closed.Schema)
	require.Equal(t, closed.TipHex, hex.EncodeToString(evt.PrevHash), "the closing record links to the archive's tip")
	path := filepath.Join(a.cfg.ArchiveDirectory(), closed.Segment)
	sum, size, err := store.HashFile(path)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(sum), closed.SHA256Hex, "the archive hashes to what the record says")
	require.Equal(t, size, closed.Bytes)
	closed.Path = path
	return closed
}

func TestReturnPathAudit_ClosesASegmentByCount(t *testing.T) {
	cfg := segmentedAuditConfig(t, 5, 0)
	a, registry := openSegmentedAudit(t, cfg, shared_time.NewSystemClock())
	_, err := os.Stat(cfg.Audit.ArchiveDirectory())
	require.NoError(t, err, "the archive directory is proved at start")

	refuse(t, a, 4)
	require.Empty(t, archivesOf(t, cfg))
	require.Equal(t, 4, a.Len())

	// The fifth event fills the segment: it closes, and the fresh file
	// opens with the record of it.
	refuse(t, a, 1)
	archives := archivesOf(t, cfg)
	require.Len(t, archives, 1)
	require.Equal(t, "returnpath.0000000000-0000000004.db", archives[0].Name)
	require.Equal(t, 6, a.Len(), "five events and the closing record")
	require.Equal(t, 5, a.Base())
	closed := closingRecord(t, a, 5)
	require.Equal(t, 0, closed.FirstIndex)
	require.Equal(t, 4, closed.LastIndex)
	require.Equal(t, a.segmentsClosed.Value(), uint64(1))
	require.Equal(t, uint64(1), a.events.Value(metrics.Label{Name: "kind", Value: string(audit_event.KindAuditSegmentClosed)}))
	require.Equal(t, uint64(5), a.events.Value(metrics.Label{Name: "kind", Value: string(audit_event.KindTrustEvaluated)}))
	require.Equal(t, float64(1), a.segmentEvents.Value())
	var out bytes.Buffer
	require.NoError(t, registry.WriteMetricsTo(&out))
	require.Contains(t, out.String(), "sagvd_audit_segments_closed_total 1")

	// The live segment verifies; the archive verifies on its own from
	// genesis, read-only, and reads back whole.
	require.NoError(t, a.persistent.Verify(a.keys))
	ro, err := store.OpenReadOnly(closed.Path)
	require.NoError(t, err)
	ca, err := chain.OpenPersistentChain(ro, a.keys)
	require.NoError(t, err)
	require.Equal(t, 5, ca.Len())
	require.Equal(t, closed.TipHex, hex.EncodeToString(ca.Tip()))
	require.NoError(t, ro.Close())

	// The next segment fills with its record and four more; the archive
	// after it is named by the log's indices.
	refuse(t, a, 4)
	require.Len(t, archivesOf(t, cfg), 2)
	require.Equal(t, "returnpath.0000000005-0000000009.db", archivesOf(t, cfg)[1].Name)
	require.Equal(t, 11, a.Len())
	require.Equal(t, 10, a.Base())
	second := closingRecord(t, a, 10)
	require.Equal(t, 5, second.FirstIndex)
	require.Equal(t, 9, second.LastIndex)
	require.Equal(t, uint64(2), a.segmentsClosed.Value())
	tip := a.Tip()
	require.NoError(t, a.Close())

	// Reopened: the log's count and tip, nothing recorded twice, and the
	// live segment verified from the archive's tip.
	again, err := openReturnPathAudit(cfg, shared_time.NewSystemClock(), nil, nil)
	require.NoError(t, err)
	defer func() { _ = again.Close() }()
	require.Equal(t, 11, again.Len())
	require.Equal(t, 10, again.Base())
	require.Equal(t, tip, again.Tip())
	require.Len(t, archivesOf(t, cfg), 2)
	refuse(t, again, 1)
	require.Equal(t, 12, again.Len())
}

func TestReturnPathAudit_ClosesASegmentByAge(t *testing.T) {
	start := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	clock := shared_time.NewFakeClock(start)
	cfg := segmentedAuditConfig(t, 0, 3600)
	a, _ := openSegmentedAudit(t, cfg, clock)

	refuse(t, a, 2)
	clock.Step(59 * time.Minute)
	refuse(t, a, 1)
	require.Empty(t, archivesOf(t, cfg), "under an hour: open")

	// An hour after its first event, the segment closes at the next
	// event.
	clock.Step(time.Minute)
	refuse(t, a, 1)
	archives := archivesOf(t, cfg)
	require.Len(t, archives, 1)
	require.Equal(t, "returnpath.0000000000-0000000003.db", archives[0].Name)
	require.Equal(t, 5, a.Len())
	require.Equal(t, 4, a.Base())
	closing := closingRecord(t, a, 4)
	require.Equal(t, 3, closing.LastIndex)

	// The fresh segment measures from its closing record.
	clock.Step(30 * time.Minute)
	refuse(t, a, 1)
	require.Len(t, archivesOf(t, cfg), 1)
	clock.Step(31 * time.Minute)
	refuse(t, a, 1)
	require.Len(t, archivesOf(t, cfg), 2)
	require.Equal(t, "returnpath.0000000004-0000000006.db", archivesOf(t, cfg)[1].Name)
	require.Equal(t, 8, a.Len())
	require.Equal(t, 7, a.Base())
}

func TestReturnPathAudit_RecordsAClosingACrashLeftUnrecorded(t *testing.T) {
	cfg := segmentedAuditConfig(t, 3, 0)
	a, _ := openSegmentedAudit(t, cfg, shared_time.NewSystemClock())
	refuse(t, a, 3)
	require.Equal(t, 4, a.Len())
	closed := closingRecord(t, a, 3)
	tip := a.Tip()
	require.NoError(t, a.Close())

	// Crashed after the move, before the fresh file: the live file is
	// absent. The start continues from the archive and records the
	// closing — the same record the crashed process would have written.
	require.NoError(t, os.Remove(cfg.Audit.LogPath))
	again, err := openReturnPathAudit(cfg, shared_time.NewSystemClock(), nil, nil)
	require.NoError(t, err)
	require.Equal(t, 4, again.Len())
	require.Equal(t, 3, again.Base())
	recorded := closingRecord(t, again, 3)
	require.Equal(t, closed.Segment, recorded.Segment)
	require.Equal(t, closed.SHA256Hex, recorded.SHA256Hex)
	require.NotEqual(t, tip, again.Tip(), "a new record, signed at this start")
	require.NoError(t, again.persistent.Verify(again.keys))
	require.NoError(t, again.Close())

	// Crashed after the fresh file, before the record: the live file is
	// there, empty, naming the archive. Recorded at start.
	require.NoError(t, os.Remove(cfg.Audit.LogPath))
	empty, unrecorded, err := store.OpenLive(cfg.Audit.LogPath, cfg.Audit.ArchiveDirectory())
	require.NoError(t, err)
	require.NotNil(t, unrecorded)
	require.NoError(t, empty.Close())
	third, err := openReturnPathAudit(cfg, shared_time.NewSystemClock(), nil, nil)
	require.NoError(t, err)
	require.Equal(t, 4, third.Len())
	closingRecord(t, third, 3)
	require.NoError(t, third.Close())

	// Started once more: nothing to record, the count stands.
	fourth, err := openReturnPathAudit(cfg, shared_time.NewSystemClock(), nil, nil)
	require.NoError(t, err)
	require.Equal(t, 4, fourth.Len())
	require.NoError(t, fourth.Close())

	// The archive gone before its closing was recorded: the daemon does
	// not start — a segment closed off the record is a decision off the
	// record.
	require.NoError(t, os.Remove(cfg.Audit.LogPath))
	empty, _, err = store.OpenLive(cfg.Audit.LogPath, cfg.Audit.ArchiveDirectory())
	require.NoError(t, err)
	require.NoError(t, empty.Close())
	require.NoError(t, os.Rename(closed.Path, closed.Path+".shipped"))
	_, err = openReturnPathAudit(cfg, shared_time.NewSystemClock(), nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "put it back")
}

func TestReturnPathAudit_RefusesAnArchiveDirItCannotMoveInto(t *testing.T) {
	cfg := segmentedAuditConfig(t, 3, 0)
	dir := filepath.Dir(cfg.Audit.LogPath)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o600))
	cfg.Audit.ArchiveDir = filepath.Join(dir, "file", "archive")
	_, err := openReturnPathAudit(cfg, shared_time.NewSystemClock(), nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "audit.archive_dir")

	// Without a trigger the directory is not needed, and not made.
	cfg.Audit.SegmentEvents = 0
	cfg.Audit.ArchiveDir = ""
	a, err := openReturnPathAudit(cfg, shared_time.NewSystemClock(), nil, nil)
	require.NoError(t, err)
	require.NoError(t, a.Close())
	_, err = os.Stat(filepath.Join(dir, "archive"))
	require.True(t, os.IsNotExist(err))
}
