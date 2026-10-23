// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
)

// Finished jobs expire from the store after queue.retain_finished_seconds
// (ADR 0027): a completion sweeps what finished before the window, at
// most once a minute; a job in flight is never swept; GET answers 404
// for an expired job.
func TestJobQueue_FinishedJobsExpireFromTheStore(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	advance := func(d time.Duration) {
		clock.mu.Lock()
		clock.now = clock.now.Add(d)
		clock.mu.Unlock()
	}
	store := openTestStore(t)
	q := NewJobQueue(clock, 20*time.Millisecond)
	q.AttachStore(store, 3, nil)
	swept := metrics.NewRegistry().NewCounter("sagvd_jobs_swept_total", "")
	q.SetRetention(time.Hour, swept)
	ta := newTestAuthority(t, nil)
	submit := func(req string) string {
		t.Helper()
		id, _ := NewJobID()
		if _, err := q.SubmitRecorded(id, ta.flow(t, req, testGenomeID), testInfo(testGenomeID), aMinute, JobRecord{Request: json.RawMessage(`{}`), RequestID: req}); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Next(context.Background()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	complete := func(id string) {
		q.CompleteGated(id, returnpath.CandidateOutput{OutputKind: "bytes", Bytes: []byte("ok")}, "worker-1", GateView{Level: "EXACT"}, nil, nil)
	}

	a := submit("req-a")
	complete(a)
	if _, kept := q.GetRaw(a); !kept {
		t.Fatal("a just-finished job is kept")
	}
	// A job in flight through the whole window.
	inFlight := submit("req-in-flight")

	// Two hours on, the next completion sweeps a; b stays, so does the
	// job in flight.
	advance(2 * time.Hour)
	b := submit("req-b")
	complete(b)
	if _, kept := q.GetRaw(a); kept {
		t.Fatal("a finished two hours ago, retention is one hour: still kept")
	}
	if _, kept := q.GetRaw(b); !kept {
		t.Fatal("b, just finished, swept")
	}
	if _, ok := q.Get(inFlight); !ok {
		t.Fatal("the job in flight was swept")
	}
	if n, _ := store.Len(); n != 2 {
		t.Fatalf("records after the sweep: %d, want 2", n)
	}
	if swept.Value() != 1 {
		t.Fatalf("swept counter: %d, want 1", swept.Value())
	}

	// Within a minute of the last sweep no sweep runs, however old the
	// jobs are: c finishes 30 s later with a one-second window, and b is
	// still there. A minute on, the next completion sweeps both.
	q.SetRetention(time.Second, swept)
	advance(30 * time.Second)
	c := submit("req-c")
	complete(c)
	if _, kept := q.GetRaw(b); !kept {
		t.Fatal("b swept within a minute of the last sweep")
	}
	advance(time.Minute)
	d := submit("req-d")
	complete(d)
	for _, id := range []string{b, c} {
		if _, kept := q.GetRaw(id); kept {
			t.Fatalf("%s still kept after the window", id)
		}
	}
	if _, kept := q.GetRaw(d); !kept {
		t.Fatal("d, just finished, swept")
	}
	if swept.Value() != 3 {
		t.Fatalf("swept counter: %d, want 3", swept.Value())
	}

	// Without a retention nothing expires.
	q.SetRetention(0, swept)
	advance(24 * time.Hour)
	e := submit("req-e")
	complete(e)
	if _, kept := q.GetRaw(d); !kept {
		t.Fatal("d swept with retention off")
	}
}
