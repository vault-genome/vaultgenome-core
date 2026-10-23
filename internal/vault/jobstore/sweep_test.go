// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package jobstore

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

// Finished jobs expire (ADR 0027): a sweep deletes the records and views
// of jobs that finished before the cutoff, oldest first, in bounded
// batches, and never a job that is queued or running.

var t0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

// finish puts a record for id, moves it to status at at, and keeps a
// view for it.
func finish(t *testing.T, s *Store, id, status string, at time.Time) {
	t.Helper()
	if err := s.Put(Record{ID: id, SubmittedAt: at.Add(-time.Minute), Status: StatusQueued, Attempts: 1, UpdatedAt: at.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetStatus(id, status, "", at); err != nil {
		t.Fatal(err)
	}
	if err := s.PutView(id, []byte(`{"job_id":"`+id+`"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestSweep_DeletesOnlyFinishedJobsOlderThanTheCutoff(t *testing.T) {
	s, _ := open(t)
	finish(t, s, "old-ok", StatusSucceeded, t0)
	finish(t, s, "old-failed", StatusFailed, t0.Add(time.Second))
	finish(t, s, "recent", StatusSucceeded, t0.Add(2*time.Hour))
	if err := s.Put(Record{ID: "queued", SubmittedAt: t0.Add(-24 * time.Hour), Status: StatusQueued, Attempts: 1, UpdatedAt: t0.Add(-24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Record{ID: "running", SubmittedAt: t0.Add(-24 * time.Hour), Status: StatusRunning, Attempts: 1, UpdatedAt: t0.Add(-24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Finished(); n != 3 {
		t.Fatalf("finished on record: %d, want 3", n)
	}

	// Nothing finished before t0.
	if n, err := s.Sweep(t0, 100); err != nil || n != 0 {
		t.Fatalf("sweep before anything finished: n=%d err=%v", n, err)
	}
	// The two that finished before t0+1h go; the recent one and the
	// jobs in flight stay, old as they are.
	n, err := s.Sweep(t0.Add(time.Hour), 100)
	if err != nil || n != 2 {
		t.Fatalf("sweep: n=%d err=%v", n, err)
	}
	for _, id := range []string{"old-ok", "old-failed"} {
		if _, found, _ := s.Get(id); found {
			t.Fatalf("%s still on record", id)
		}
		if _, kept, _ := s.View(id); kept {
			t.Fatalf("%s's view still kept", id)
		}
	}
	for _, id := range []string{"recent", "queued", "running"} {
		if _, found, _ := s.Get(id); !found {
			t.Fatalf("%s swept", id)
		}
	}
	if _, kept, _ := s.View("recent"); !kept {
		t.Fatal("the recent view is gone")
	}
	pending, _ := s.Pending()
	if len(pending) != 2 {
		t.Fatalf("pending after the sweep: %d, want 2", len(pending))
	}
	if n, _ := s.Finished(); n != 1 {
		t.Fatalf("finished after the sweep: %d, want 1", n)
	}
	// Idempotent.
	if n, err := s.Sweep(t0.Add(time.Hour), 100); err != nil || n != 0 {
		t.Fatalf("second sweep: n=%d err=%v", n, err)
	}
}

func TestSweep_IsBoundedAndOldestFirst(t *testing.T) {
	s, _ := open(t)
	for i := 0; i < 5; i++ {
		finish(t, s, fmt.Sprintf("job-%d", i), StatusSucceeded, t0.Add(time.Duration(i)*time.Minute))
	}
	cutoff := t0.Add(time.Hour)
	for want, left := range map[int][]string{} {
		_ = want
		_ = left
	}
	n, err := s.Sweep(cutoff, 2)
	if err != nil || n != 2 {
		t.Fatalf("first batch: n=%d err=%v", n, err)
	}
	for _, id := range []string{"job-0", "job-1"} {
		if _, found, _ := s.Get(id); found {
			t.Fatalf("%s should have gone first", id)
		}
	}
	if _, found, _ := s.Get("job-2"); !found {
		t.Fatal("job-2 swept out of order")
	}
	if n, _ := s.Sweep(cutoff, 2); n != 2 {
		t.Fatalf("second batch: %d", n)
	}
	if n, _ := s.Sweep(cutoff, 2); n != 1 {
		t.Fatalf("third batch: %d", n)
	}
	if n, _ := s.Sweep(cutoff, 0); n != 0 {
		t.Fatalf("a batch of zero sweeps %d", n)
	}
}

func TestSweep_ATransitionMovesTheJobInTheIndex(t *testing.T) {
	s, _ := open(t)
	finish(t, s, "job", StatusSucceeded, t0)
	// Marked again, later: the earlier index entry must go, or the sweep
	// would delete a job by a time it no longer finished at.
	if err := s.SetStatus("job", StatusFailed, "judged again", t0.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Finished(); n != 1 {
		t.Fatalf("one job, %d index entries", n)
	}
	if n, _ := s.Sweep(t0.Add(time.Hour), 10); n != 0 {
		t.Fatalf("swept by the earlier time: %d", n)
	}
	if n, _ := s.Sweep(t0.Add(4*time.Hour), 10); n != 1 {
		t.Fatalf("not swept by the later time: %d", n)
	}
	// Put over a finished record keeps one entry too.
	finish(t, s, "again", StatusSucceeded, t0)
	if err := s.Put(Record{ID: "again", Status: StatusSucceeded, UpdatedAt: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Finished(); n != 1 {
		t.Fatalf("one job, %d index entries after Put", n)
	}
	if err := s.Put(Record{ID: "again", Status: StatusQueued, UpdatedAt: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Finished(); n != 0 {
		t.Fatalf("a job put back in flight is still indexed: %d", n)
	}
}

func TestOpen_IndexesAStoreWrittenBeforeTheIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	finish(t, s, "old", StatusSucceeded, t0)
	finish(t, s, "newer", StatusFailed, t0.Add(2*time.Hour))
	if err := s.Put(Record{ID: "queued", Status: StatusQueued, UpdatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A store from 0.5.0 has no index: drop it.
	db, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error { return tx.DeleteBucket([]byte(bucketFinished)) }); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if n, _ := s.Finished(); n != 2 {
		t.Fatalf("indexed on open: %d, want 2", n)
	}
	if n, _ := s.Sweep(t0.Add(time.Hour), 10); n != 1 {
		t.Fatalf("swept after the backfill: %d, want 1", n)
	}
	if _, found, _ := s.Get("old"); found {
		t.Fatal("old still on record")
	}
	if _, found, _ := s.Get("queued"); !found {
		t.Fatal("the queued job was swept")
	}
}
