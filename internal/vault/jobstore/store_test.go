// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package jobstore

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jobs.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestOpen_RequiresAPath(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("Open(\"\") succeeded")
	}
}

func TestPutGet_RoundTrip(t *testing.T) {
	s, _ := open(t)
	at := time.Date(2026, 10, 15, 18, 0, 0, 0, time.UTC)
	rec := Record{ID: "a", Request: json.RawMessage(`{"genome":{"bundle":"gen-0.genome"}}`), RequestID: "req-1",
		DeadlineSeconds: 60, SubmittedAt: at, Status: StatusQueued, Attempts: 1, UpdatedAt: at}
	if err := s.Put(rec); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Get("a")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.ID != "a" || string(got.Request) != `{"genome":{"bundle":"gen-0.genome"}}` || got.RequestID != "req-1" ||
		got.DeadlineSeconds != 60 || !got.SubmittedAt.Equal(at) || got.Status != StatusQueued || got.Attempts != 1 {
		t.Fatalf("round trip: %+v", got)
	}
	if _, ok, _ := s.Get("missing"); ok {
		t.Fatal("found a record that was never written")
	}
	if err := s.Put(Record{}); err == nil {
		t.Fatal("Put without an id succeeded")
	}
}

func TestSetStatus_KeepsTheRestAndRefusesUnknown(t *testing.T) {
	s, _ := open(t)
	at := time.Date(2026, 10, 15, 18, 0, 0, 0, time.UTC)
	if err := s.Put(Record{ID: "a", Request: json.RawMessage(`{}`), DeadlineSeconds: 30, SubmittedAt: at, Status: StatusQueued, Attempts: 1}); err != nil {
		t.Fatal(err)
	}
	later := at.Add(5 * time.Second)
	if err := s.SetStatus("a", StatusFailed, "the worker never answered", later); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Get("a")
	if got.Status != StatusFailed || got.LastError != "the worker never answered" || !got.UpdatedAt.Equal(later) ||
		got.DeadlineSeconds != 30 || got.Attempts != 1 || string(got.Request) != `{}` {
		t.Fatalf("after SetStatus: %+v", got)
	}
	if err := s.SetStatus("nope", StatusQueued, "", later); err == nil {
		t.Fatal("SetStatus on an unknown id succeeded")
	}
}

func TestPending_OrderedBySubmissionThenID_TerminalExcluded(t *testing.T) {
	s, _ := open(t)
	t0 := time.Date(2026, 10, 15, 18, 0, 0, 0, time.UTC)
	for _, r := range []Record{
		{ID: "c", SubmittedAt: t0.Add(2 * time.Second), Status: StatusRunning},
		{ID: "a", SubmittedAt: t0, Status: StatusQueued},
		{ID: "d", SubmittedAt: t0.Add(3 * time.Second), Status: StatusSucceeded},
		{ID: "b", SubmittedAt: t0, Status: StatusQueued},
		{ID: "e", SubmittedAt: t0.Add(4 * time.Second), Status: StatusFailed},
	} {
		if err := s.Put(r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Pending()
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(got))
	for i, r := range got {
		ids[i] = r.ID
	}
	if want := "a b c"; joined(ids) != want {
		t.Fatalf("pending order %v, want %s", ids, want)
	}
	if n, _ := s.Len(); n != 5 {
		t.Fatalf("Len %d, want 5", n)
	}
}

func joined(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += " "
		}
		out += id
	}
	return out
}

func TestViews_SurviveReopen(t *testing.T) {
	s, path := open(t)
	if err := s.PutView("a", []byte(`{"id":"a","status":"succeeded"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutView("", []byte(`{}`)); err == nil {
		t.Fatal("PutView without an id succeeded")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	view, ok, err := again.View("a")
	if err != nil || !ok || string(view) != `{"id":"a","status":"succeeded"}` {
		t.Fatalf("View after reopen: ok=%v err=%v %s", ok, err, view)
	}
	if _, ok, _ := again.View("b"); ok {
		t.Fatal("found a view that was never written")
	}
}

func TestOpen_RefusesASecondHolder(t *testing.T) {
	_, path := open(t)
	start := time.Now()
	if _, err := Open(path); err == nil {
		t.Fatal("a second Open on a held file succeeded")
	}
	if took := time.Since(start); took < openTimeout/2 {
		t.Fatalf("second Open gave up after %s: it did not wait for the lock", took)
	}
}
