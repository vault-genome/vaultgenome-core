// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	"github.com/vault-genome/vaultgenome-core/internal/vault/jobstore"
)

func openTestStore(t *testing.T) *jobstore.Store {
	t.Helper()
	s, err := jobstore.Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// The queue on disk (ADR 0026): a submission leaves its record, every
// transition updates it, a finished job leaves its view, and a fresh
// queue over the same store answers for the finished job.
func TestJobQueue_StoreRecordsSubmissionTransitionsAndTheView(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 10, 15, 18, 0, 0, 0, time.UTC)}
	store := openTestStore(t)
	q := NewJobQueue(clock, 20*time.Millisecond)
	q.AttachStore(store, 3, nil)
	ta := newTestAuthority(t, nil)

	id, err := NewJobID()
	if err != nil {
		t.Fatal(err)
	}
	first := clock.Now().Add(-time.Hour)
	if _, err := q.SubmitRecorded(id, ta.flow(t, "req-1", testGenomeID), testInfo(testGenomeID), aMinute, JobRecord{
		Request: json.RawMessage(`{"genome":{"bundle":"gen-0.genome"}}`), RequestID: "req-1", DeadlineSeconds: 60, SubmittedAt: first,
	}); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := store.Get(id)
	if err != nil || !ok {
		t.Fatalf("record after submit: ok=%v err=%v", ok, err)
	}
	if rec.Status != jobstore.StatusQueued || rec.Attempts != 1 || rec.RequestID != "req-1" || rec.DeadlineSeconds != 60 ||
		!rec.SubmittedAt.Equal(first) || string(rec.Request) != `{"genome":{"bundle":"gen-0.genome"}}` {
		t.Fatalf("record after submit: %+v", rec)
	}
	if view, _ := q.Get(id); !view.SubmittedAt.Equal(first) {
		t.Fatalf("the in-memory job keeps the first acceptance: %v", view.SubmittedAt)
	}

	job, err := q.Next(context.Background())
	if err != nil || job.ID != id {
		t.Fatalf("Next: %v %v", job.ID, err)
	}
	if rec, _, _ = store.Get(id); rec.Status != jobstore.StatusRunning {
		t.Fatalf("after Next: %+v", rec)
	}
	q.Requeue(id)
	if rec, _, _ = store.Get(id); rec.Status != jobstore.StatusQueued {
		t.Fatalf("after Requeue: %+v", rec)
	}
	if _, err := q.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.advance(5 * time.Second)
	q.CompleteGated(id, returnpath.CandidateOutput{OutputKind: "bytes", Bytes: []byte("ok")}, "worker-1", GateView{Level: "EXACT"}, nil, nil)
	if rec, _, _ = store.Get(id); rec.Status != jobstore.StatusSucceeded || rec.LastError != "" {
		t.Fatalf("after CompleteGated: %+v", rec)
	}
	kept, ok, err := store.View(id)
	if err != nil || !ok || !strings.Contains(string(kept), `"status":"succeeded"`) || !strings.Contains(string(kept), id) {
		t.Fatalf("kept view: ok=%v err=%v %s", ok, err, kept)
	}

	// A fresh queue over the same store knows nothing in memory, and
	// still answers for the finished job from the kept view.
	again := NewJobQueue(clock, 20*time.Millisecond)
	again.AttachStore(store, 3, nil)
	if _, ok := again.Get(id); ok {
		t.Fatal("a fresh queue has the job in memory")
	}
	raw, ok := again.GetRaw(id)
	if !ok || string(raw) != string(kept) {
		t.Fatalf("GetRaw from the store: ok=%v %s", ok, raw)
	}
	if _, ok := again.GetRaw("nobody"); ok {
		t.Fatal("GetRaw answered for a job that never was")
	}

	// A failure is kept the same way, with its reason on the record.
	id2, _ := NewJobID()
	if _, err := q.SubmitRecorded(id2, ta.flow(t, "req-2", testGenomeID), testInfo(testGenomeID), aMinute, JobRecord{Request: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	q.CompleteFailure(id2, errors.New("the worker never answered"))
	if rec, _, _ = store.Get(id2); rec.Status != jobstore.StatusFailed || rec.LastError != "the worker never answered" {
		t.Fatalf("after CompleteFailure: %+v", rec)
	}
	if kept, ok, _ := store.View(id2); !ok || !strings.Contains(string(kept), `"status":"failed"`) {
		t.Fatalf("kept view of the failure: %s", kept)
	}
}

// Resume admits again what the store holds as unfinished, oldest first,
// and fails on the record what it cannot admit: a job past the attempt
// limit, a job without its request, a job the admission refuses.
func TestJobQueue_ResumeAdmitsPendingInOrderAndFailsTheRest(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 10, 15, 18, 0, 0, 0, time.UTC)}
	store := openTestStore(t)
	t0 := clock.Now().Add(-time.Hour)
	req := json.RawMessage(`{"genome":{"bundle":"gen-0.genome","key_file":"gen-0.key"}}`)
	for _, rec := range []jobstore.Record{
		{ID: "b-running", Request: req, RequestID: "req-b", SubmittedAt: t0.Add(time.Second), Status: jobstore.StatusRunning, Attempts: 1},
		{ID: "a-queued", Request: req, RequestID: "req-a", SubmittedAt: t0, Status: jobstore.StatusQueued, Attempts: 1},
		{ID: "c-exhausted", Request: req, RequestID: "req-c", SubmittedAt: t0.Add(2 * time.Second), Status: jobstore.StatusQueued, Attempts: 3},
		{ID: "d-no-request", RequestID: "req-d", SubmittedAt: t0.Add(3 * time.Second), Status: jobstore.StatusQueued, Attempts: 1},
		{ID: "e-done", Request: req, RequestID: "req-e", SubmittedAt: t0.Add(4 * time.Second), Status: jobstore.StatusSucceeded, Attempts: 1},
	} {
		if err := store.Put(rec); err != nil {
			t.Fatal(err)
		}
	}
	q := NewJobQueue(clock, 20*time.Millisecond)
	q.AttachStore(store, 3, nil)
	ta := newTestAuthority(t, nil)

	var order []string
	resumed, failed, err := q.Resume(func(rec jobstore.Record) error {
		order = append(order, rec.ID)
		if rec.ID == "b-running" {
			return errors.New("the bundle is gone")
		}
		_, err := q.SubmitRecorded(rec.ID, ta.flow(t, rec.RequestID, testGenomeID), testInfo(testGenomeID), aMinute, JobRecord{
			Request: rec.Request, RequestID: rec.RequestID, DeadlineSeconds: rec.DeadlineSeconds, Attempt: rec.Attempts + 1, SubmittedAt: rec.SubmittedAt,
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if resumed != 1 || failed != 3 {
		t.Fatalf("resumed %d failed %d, want 1 and 3", resumed, failed)
	}
	if strings.Join(order, " ") != "a-queued b-running" {
		t.Fatalf("readmit order %v: oldest first, and only what can be admitted", order)
	}

	a, _, _ := store.Get("a-queued")
	if a.Status != jobstore.StatusQueued || a.Attempts != 2 || !a.SubmittedAt.Equal(t0) {
		t.Fatalf("a after resume: %+v", a)
	}
	if view, ok := q.Get("a-queued"); !ok || view.Status != JobStatusQueued || !view.SubmittedAt.Equal(t0) {
		t.Fatalf("a in memory after resume: ok=%v %+v", ok, view)
	}
	for id, want := range map[string]string{
		"b-running":    "not admitted again: the bundle is gone",
		"c-exhausted":  "admitted 3 times and never finished",
		"d-no-request": "request was not recorded",
	} {
		rec, _, _ := store.Get(id)
		if rec.Status != jobstore.StatusFailed || !strings.Contains(rec.LastError, want) {
			t.Fatalf("%s after resume: %+v (want %q)", id, rec, want)
		}
		raw, ok := q.GetRaw(id)
		if !ok || !strings.Contains(string(raw), `"status":"failed"`) || !strings.Contains(string(raw), want) {
			t.Fatalf("%s kept view: ok=%v %s", id, ok, raw)
		}
	}
	if e, _, _ := store.Get("e-done"); e.Status != jobstore.StatusSucceeded || e.Attempts != 1 {
		t.Fatalf("a finished job was touched: %+v", e)
	}
	if q.Depth() != 1 {
		t.Fatalf("Depth %d, want 1 (only a-queued)", q.Depth())
	}
}

func TestJobQueue_WithoutStore_NothingToResume(t *testing.T) {
	q := NewJobQueue(nil, 20*time.Millisecond)
	resumed, failed, err := q.Resume(func(jobstore.Record) error { t.Fatal("readmit called without a store"); return nil })
	if resumed != 0 || failed != 0 || err != nil {
		t.Fatalf("Resume without a store: %d %d %v", resumed, failed, err)
	}
	if _, ok := q.GetRaw("x"); ok {
		t.Fatal("GetRaw answered without a store")
	}
	// A store write that fails does not stop the job: the queue still
	// works after its store is closed.
	store := openTestStore(t)
	q.AttachStore(store, 1, nil)
	_ = store.Close()
	ta := newTestAuthority(t, nil)
	id, _ := NewJobID()
	if _, err := q.SubmitRecorded(id, ta.flow(t, "req-x", testGenomeID), testInfo(testGenomeID), aMinute, JobRecord{Request: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("a closed store stopped a submission: %v", err)
	}
	if view, ok := q.Get(id); !ok || view.Status != JobStatusQueued {
		t.Fatalf("the job is not queued in memory: ok=%v %+v", ok, view)
	}
}

// With a store, a finished job leaves memory as soon as its view is on
// disk (KNOWN_ISSUES #18): GET answers from the store, the queue holds
// only what is in flight. A view the store refuses keeps the job in
// memory, so GET still answers; without a store every job stays, as it
// always did.
func TestJobQueue_FinishedJobsLeaveMemoryOnceTheStoreHasTheView(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	store := openTestStore(t)
	q := NewJobQueue(clock, 20*time.Millisecond)
	q.AttachStore(store, 3, nil)
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

	ok := submit("req-ok")
	failed := submit("req-failed")
	if q.Held() != 2 {
		t.Fatalf("two jobs in flight, held %d", q.Held())
	}
	q.CompleteGated(ok, returnpath.CandidateOutput{OutputKind: "bytes", Bytes: []byte("ok")}, "worker-1", GateView{Level: "EXACT"}, nil, nil)
	q.CompleteFailure(failed, errors.New("the worker never answered"))
	if q.Held() != 0 {
		t.Fatalf("finished jobs still in memory: %d", q.Held())
	}
	if _, inMemory := q.Get(ok); inMemory {
		t.Fatal("the finished job is still in memory")
	}
	raw, kept := q.GetRaw(ok)
	if !kept || !strings.Contains(string(raw), `"status":"succeeded"`) || !strings.Contains(string(raw), `"level":"EXACT"`) {
		t.Fatalf("GET of the finished job from the store: kept=%v %s", kept, raw)
	}
	if raw, kept := q.GetRaw(failed); !kept || !strings.Contains(string(raw), `"status":"failed"`) || !strings.Contains(string(raw), "the worker never answered") {
		t.Fatalf("GET of the failed job from the store: kept=%v %s", kept, raw)
	}
	q.Requeue(ok)
	q.MarkDispatched(ok, clock.Now())
	if q.Held() != 0 || q.Depth() != 0 {
		t.Fatalf("a finished job cannot come back: held %d depth %d", q.Held(), q.Depth())
	}

	// The store refuses the view (closed underneath): the job stays.
	stuck := submit("req-stuck")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	q.CompleteGated(stuck, returnpath.CandidateOutput{OutputKind: "bytes", Bytes: []byte("ok")}, "worker-1", GateView{Level: "EXACT"}, nil, nil)
	if q.Held() != 1 {
		t.Fatalf("a job whose view the store refused must stay in memory, held %d", q.Held())
	}
	if view, inMemory := q.Get(stuck); !inMemory || view.Status != JobStatusSucceeded {
		t.Fatalf("GET of the job the store refused: %v %+v", inMemory, view)
	}

	// Without a store, every job stays.
	alone := NewJobQueue(clock, 20*time.Millisecond)
	id, _ := NewJobID()
	if _, err := alone.Submit(id, ta.flow(t, "req-alone", testGenomeID), testInfo(testGenomeID), aMinute); err != nil {
		t.Fatal(err)
	}
	if _, err := alone.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	alone.CompleteFailure(id, errors.New("refused"))
	if alone.Held() != 1 {
		t.Fatalf("without a store the finished job must stay, held %d", alone.Held())
	}
	if view, inMemory := alone.Get(id); !inMemory || view.Status != JobStatusFailed {
		t.Fatalf("GET without a store: %v %+v", inMemory, view)
	}
}
