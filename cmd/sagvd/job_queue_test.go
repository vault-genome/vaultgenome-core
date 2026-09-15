// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ai-continuity-platform/core/internal/compute/returnpath"
	"github.com/ai-continuity-platform/core/internal/compute/returnpath/transport"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
)

// testJobRequest builds a minimal valid transport.JobRequest for
// queue tests. The queue never unseals or verifies the request —
// it just carries it — so the SealedMaterial values are
// placeholders.
func testJobRequest(now time.Time, manifestID string) transport.JobRequest {
	return transport.JobRequest{
		Type:                   transport.FrameTypeJobRequest,
		SchemaVersion:          1,
		ManifestID:             manifestID,
		SessionID:              "sess-" + manifestID,
		ExpectedOutputKind:     "text/plain",
		ExpectedOutputMaxBytes: 1024,
		Deadline:               now.Add(60 * time.Second),
		IssuedAt:               now,
		SealedMaterial: []transport.SealedMaterialRef{{
			RecipientKeyID: "kid-test",
			Nonce:          []byte("nonce-12-bytes"),
			Ciphertext:     []byte("ciphertext-placeholder"),
		}},
	}
}

// testClock is a controllable clock so tests can assert that
// SubmittedAt / StartedAt / CompletedAt carry the expected values.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Since(t time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Sub(t)
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// assertClockSatisfiesInterface is a compile-time guard that the
// testClock satisfies shared_time.Clock. Without this, a future
// interface-method addition would fail silently at test runtime
// rather than at compile time.
var _ shared_time.Clock = (*testClock)(nil)

func TestJobQueue_SubmitAssignsIDAndQueuedStatus(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)}
	q := NewJobQueue(clock, 50*time.Millisecond)

	id, view, err := q.Submit(testJobRequest(clock.Now(), "m-1"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if id == "" {
		t.Fatal("Submit returned empty id")
	}
	if len(id) != 32 {
		t.Fatalf("id len = %d want 32", len(id))
	}
	if view.Status != JobStatusQueued {
		t.Fatalf("view.Status = %s want queued", view.Status)
	}
	if view.ID != id {
		t.Fatalf("view.ID = %s want %s", view.ID, id)
	}
	if !view.SubmittedAt.Equal(clock.Now()) {
		t.Fatalf("view.SubmittedAt = %v want %v", view.SubmittedAt, clock.Now())
	}
	if view.StartedAt != nil {
		t.Fatalf("view.StartedAt should be nil for queued job, got %v", view.StartedAt)
	}
	if q.Depth() != 1 {
		t.Fatalf("Depth = %d want 1", q.Depth())
	}
}

func TestJobQueue_SubmitRejectsInvalidRequest(t *testing.T) {
	q := NewJobQueue(nil, 50*time.Millisecond)

	// Missing ManifestID → invalid.
	bad := transport.JobRequest{
		Type:                   transport.FrameTypeJobRequest,
		SchemaVersion:          1,
		SessionID:              "s",
		ExpectedOutputKind:     "k",
		ExpectedOutputMaxBytes: 1,
		Deadline:               time.Now().Add(time.Second),
		IssuedAt:               time.Now(),
		SealedMaterial: []transport.SealedMaterialRef{{
			RecipientKeyID: "kid", Nonce: []byte("n"), Ciphertext: []byte("c"),
		}},
	}
	if _, _, err := q.Submit(bad); err == nil {
		t.Fatal("Submit with missing ManifestID: want error, got nil")
	}
	if q.Depth() != 0 {
		t.Fatalf("Depth = %d want 0 after rejected Submit", q.Depth())
	}
}

func TestJobQueue_Next_PopsFIFO(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)}
	q := NewJobQueue(clock, 10*time.Millisecond)

	ids := make([]string, 3)
	for i := range ids {
		id, _, err := q.Submit(testJobRequest(clock.Now(), fmt.Sprintf("m-%d", i)))
		if err != nil {
			t.Fatalf("Submit[%d]: %v", i, err)
		}
		ids[i] = id
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i, want := range ids {
		gotID, gotReq, err := q.Next(ctx)
		if err != nil {
			t.Fatalf("Next[%d]: %v", i, err)
		}
		if gotID != want {
			t.Fatalf("Next[%d] id = %s want %s (not FIFO)", i, gotID, want)
		}
		if gotReq.ManifestID != fmt.Sprintf("m-%d", i) {
			t.Fatalf("Next[%d] manifest_id = %s", i, gotReq.ManifestID)
		}
		view, ok := q.Get(gotID)
		if !ok {
			t.Fatalf("Get after Next: job missing")
		}
		if view.Status != JobStatusRunning {
			t.Fatalf("Status after Next = %s want running", view.Status)
		}
		if view.StartedAt == nil {
			t.Fatal("StartedAt not set after Next")
		}
	}
	if q.Depth() != 0 {
		t.Fatalf("Depth after drain = %d want 0", q.Depth())
	}
}

func TestJobQueue_Next_BlocksUntilSubmit(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)}
	q := NewJobQueue(clock, 20*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	type nextResult struct {
		id  string
		err error
	}
	done := make(chan nextResult, 1)
	go func() {
		id, _, err := q.Next(ctx)
		done <- nextResult{id, err}
	}()

	// Give Next a chance to spin through at least one empty poll.
	time.Sleep(50 * time.Millisecond)
	submitted, _, err := q.Submit(testJobRequest(clock.Now(), "m-wait"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("Next err: %v", res.err)
		}
		if res.id != submitted {
			t.Fatalf("Next returned %s want %s", res.id, submitted)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Next did not unblock within 1s after Submit")
	}
}

func TestJobQueue_Next_ContextCancelReturnsErrQueueClosed(t *testing.T) {
	q := NewJobQueue(nil, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := q.Next(ctx)
	if !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Next err = %v want ErrQueueClosed", err)
	}
}

func TestJobQueue_CompleteSuccess_RecordsCandidate(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)}
	q := NewJobQueue(clock, 10*time.Millisecond)

	id, _, err := q.Submit(testJobRequest(clock.Now(), "m-ok"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := q.Next(ctx); err != nil {
		t.Fatalf("Next: %v", err)
	}

	clock.advance(100 * time.Millisecond)
	out := returnpath.CandidateOutput{
		ManifestID: "m-ok",
		SessionID:  "sess-m-ok",
		OutputKind: "text/plain",
		Bytes:      []byte("hello"),
		ProducedAt: clock.Now(),
	}
	q.CompleteSuccess(id, out, "worker-kid-1")

	view, ok := q.Get(id)
	if !ok {
		t.Fatal("Get after CompleteSuccess: missing")
	}
	if view.Status != JobStatusSucceeded {
		t.Fatalf("Status = %s want succeeded", view.Status)
	}
	if view.Result == nil {
		t.Fatal("Result nil on succeeded job")
	}
	if view.Result.ByteCount != len(out.Bytes) {
		t.Fatalf("ByteCount = %d want %d", view.Result.ByteCount, len(out.Bytes))
	}
	if view.Result.WorkerSigningKeyID != "worker-kid-1" {
		t.Fatalf("WorkerSigningKeyID = %s", view.Result.WorkerSigningKeyID)
	}
	if view.CompletedAt == nil {
		t.Fatal("CompletedAt nil on succeeded job")
	}
}

func TestJobQueue_CompleteFailure_RecordsClassifiedError(t *testing.T) {
	q := NewJobQueue(nil, 10*time.Millisecond)

	id, _, err := q.Submit(testJobRequest(time.Now().UTC(), "m-fail"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	failErr := shared_errors.Authority("worker_rejected_job",
		"queue_test: simulated reject", nil)
	q.CompleteFailure(id, failErr)

	view, ok := q.Get(id)
	if !ok {
		t.Fatal("Get missing")
	}
	if view.Status != JobStatusFailed {
		t.Fatalf("Status = %s want failed", view.Status)
	}
	if view.Error == nil {
		t.Fatal("Error nil on failed job")
	}
	if view.Error.Category != "authority" {
		t.Fatalf("Error.Category = %s want authority", view.Error.Category)
	}
	if view.Error.Code != "worker_rejected_job" {
		t.Fatalf("Error.Code = %s", view.Error.Code)
	}
}

func TestJobQueue_Complete_UnknownID_IsNoop(t *testing.T) {
	q := NewJobQueue(nil, 10*time.Millisecond)
	// Should not panic.
	q.CompleteSuccess("no-such-id", returnpath.CandidateOutput{}, "k")
	q.CompleteFailure("no-such-id", errors.New("dummy"))
}

func TestJobQueue_Get_UnknownID(t *testing.T) {
	q := NewJobQueue(nil, 10*time.Millisecond)
	_, ok := q.Get("no-such-id")
	if ok {
		t.Fatal("Get on missing id returned ok=true")
	}
}

func TestJobQueue_DefaultPollInterval(t *testing.T) {
	q := NewJobQueue(nil, 0)
	if q.pollInterval != 250*time.Millisecond {
		t.Fatalf("pollInterval = %v want 250ms (default)", q.pollInterval)
	}
}

func TestJobQueue_Concurrent_SubmitAndNext(t *testing.T) {
	// Submit N jobs from one goroutine while M Next goroutines drain.
	// All IDs must be returned exactly once, with no deadlock.
	const N = 100
	const M = 4

	q := NewJobQueue(nil, 5*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	submitted := make([]string, 0, N)
	var submittedMu sync.Mutex
	go func() {
		for i := 0; i < N; i++ {
			id, _, err := q.Submit(testJobRequest(time.Now().UTC(), fmt.Sprintf("m-%d", i)))
			if err != nil {
				t.Errorf("Submit[%d]: %v", i, err)
				return
			}
			submittedMu.Lock()
			submitted = append(submitted, id)
			submittedMu.Unlock()
		}
	}()

	gotCh := make(chan string, N)
	var wg sync.WaitGroup
	for g := 0; g < M; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				id, _, err := q.Next(ctx)
				if err != nil {
					return
				}
				gotCh <- id
			}
		}()
	}

	got := make(map[string]bool, N)
	for i := 0; i < N; i++ {
		select {
		case id := <-gotCh:
			if got[id] {
				t.Errorf("id %s delivered twice", id)
			}
			got[id] = true
		case <-time.After(3 * time.Second):
			t.Fatalf("only drained %d/%d jobs within 3s", i, N)
		}
	}
	cancel()
	wg.Wait()

	if len(got) != N {
		t.Fatalf("got %d unique ids want %d", len(got), N)
	}
}

func TestJobQueue_GateJobs_CarryTheirGenomeAndVerdict(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)}
	q := NewJobQueue(clock, 10*time.Millisecond)
	genome := GenomeView{Bundle: "gen-0.genome", KeyID: "genome-0123456789ab-g0-0123456789ab", Fixtures: 3}
	spec := &gateSpec{GenomeID: genome.KeyID}

	id, view, err := q.SubmitGenome(testJobRequest(clock.Now(), "m-gate"), &genome, spec)
	if err != nil {
		t.Fatalf("SubmitGenome: %v", err)
	}
	if view.Genome == nil || view.Genome.KeyID != genome.KeyID || view.Gate != nil {
		t.Fatalf("queued view: %+v", view)
	}
	if got := q.GateFor(id); got != spec {
		t.Fatalf("GateFor returned %p want %p", got, spec)
	}
	if q.GateFor("no-such-id") != nil {
		t.Fatal("GateFor on an unknown id must be nil")
	}
	plain, _, err := q.Submit(testJobRequest(clock.Now(), "m-plain"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if q.GateFor(plain) != nil {
		t.Fatal("a job without a gate has no spec")
	}

	// Judged and passed: result and verdict on the view.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := q.Next(ctx); err != nil {
		t.Fatalf("Next: %v", err)
	}
	out := returnpath.CandidateOutput{ManifestID: "m-gate", SessionID: "sess-m-gate", OutputKind: "text/plain", Bytes: []byte("{}"), ProducedAt: clock.Now()}
	q.CompleteGated(id, out, "worker-kid-1", GateView{Level: "EXACT", Door: "pinned replay", Fixtures: 3}, nil)
	view, _ = q.Get(id)
	if view.Status != JobStatusSucceeded || view.Result == nil || view.Result.WorkerSigningKeyID != "worker-kid-1" {
		t.Fatalf("passed gate job: %+v", view)
	}
	if view.Gate == nil || view.Gate.Level != "EXACT" || view.Gate.Door != "pinned replay" || view.Genome == nil {
		t.Fatalf("passed gate job view lacks the verdict: %+v", view)
	}

	// Judged and refused: failed, with the verdict still on record and
	// the worker that answered named.
	id2, _, err := q.SubmitGenome(testJobRequest(clock.Now(), "m-gate-2"), &genome, spec)
	if err != nil {
		t.Fatalf("SubmitGenome: %v", err)
	}
	if _, _, err := q.Next(ctx); err != nil {
		t.Fatalf("Next: %v", err)
	}
	q.CompleteGated(id2, out, "worker-kid-1", GateView{Level: "FAIL", Fixtures: 3},
		shared_errors.Operational(CodeGateFailed, "missed", nil))
	view, _ = q.Get(id2)
	if view.Status != JobStatusFailed || view.Error == nil || view.Error.Code != CodeGateFailed || view.Result != nil {
		t.Fatalf("refused gate job: %+v", view)
	}
	if view.Gate == nil || view.Gate.Level != "FAIL" {
		t.Fatalf("refused gate job view lacks the verdict: %+v", view)
	}
	q.CompleteGated("no-such-id", out, "k", GateView{}, nil) // no panic
}
