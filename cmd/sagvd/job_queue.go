// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ai-continuity-platform/core/internal/compute/returnpath"
	"github.com/ai-continuity-platform/core/internal/compute/returnpath/transport"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/validation/reconstruction"
)

// ---- public status / types -----------------------------------------------

// JobStatus is the lifecycle phase of a submitted job.
type JobStatus string

const (
	// JobStatusQueued — accepted by POST /v1/jobs, waiting for a
	// worker to connect.
	JobStatusQueued JobStatus = "queued"

	// JobStatusRunning — currently being served by the dispatcher
	// (JobRequest has been written to a worker; we are waiting for
	// the CandidateOutputFrame).
	JobStatusRunning JobStatus = "running"

	// JobStatusSucceeded — worker returned a valid CandidateOutput;
	// GET /v1/jobs/{id} now surfaces the bytes.
	JobStatusSucceeded JobStatus = "succeeded"

	// JobStatusFailed — the Return Path session produced a
	// classified error. GET /v1/jobs/{id} surfaces
	// {category, code, message}.
	JobStatusFailed JobStatus = "failed"
)

// JobError captures a classified error produced during serving. The
// shape matches what shared_errors yields so operators can correlate
// a 500 on the REST API with a metric label and an audit-chain entry.
type JobError struct {
	Category string `json:"category"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// newJobError classifies err through shared_errors and returns the
// wire-ready JobError.
func newJobError(err error) JobError {
	if err == nil {
		return JobError{}
	}
	return JobError{
		Category: shared_errors.CategoryOf(err).String(),
		Code:     shared_errors.CodeOf(err),
		Message:  err.Error(),
	}
}

// Job is one unit of delegated compute tracked by sagvd. The struct
// is opaque to callers outside this package — the HTTP layer handles
// JSON marshalling via JobView below.
//
// Lifecycle: Queued (submitted) → Running (picked up by dispatcher) →
// Succeeded or Failed (dispatcher wrote outcome). Terminal states are
// immutable; no re-queue on failure in Phase 1.
type Job struct {
	// ID is a 16-byte hex-encoded random identifier assigned by the
	// queue at submission.
	ID string

	// Status is the current lifecycle phase.
	Status JobStatus

	// Req is the fully-formed transport.JobRequest the dispatcher
	// will write to the worker. Already validated at submission so
	// that a bad request fails fast on POST /v1/jobs and never
	// reaches the queue.
	Req transport.JobRequest

	// SubmittedAt records when POST /v1/jobs accepted the job.
	SubmittedAt time.Time

	// StartedAt records when the dispatcher picked this job up.
	// Zero until transition to Running.
	StartedAt time.Time

	// CompletedAt records when the dispatcher wrote the terminal
	// outcome. Zero until transition to Succeeded or Failed.
	CompletedAt time.Time

	// Candidate holds the worker's successful output. Zero-valued
	// unless Status == Succeeded.
	Candidate returnpath.CandidateOutput

	// WorkerSigningKeyID records the kid under which the
	// CandidateOutputFrame was signed on success. Empty otherwise.
	WorkerSigningKeyID string

	// Err is the classified error for Failed jobs; zero JobError
	// otherwise.
	Err JobError

	// Genome describes the sealed genome a gate job carries; nil for a
	// job without one.
	Genome *GenomeView

	// Gate is what judges a gate job's answer: the sealed references and
	// the operator's tolerance. Kept in memory for the job's lifetime and
	// never shown. nil for a job without a gate.
	Gate *gateSpec

	// GateResult is the verdict once the answer was judged; nil until
	// then.
	GateResult *GateView
}

// JobView is the JSON-serialisable projection GET /v1/jobs/{id}
// returns. Excludes internal wiring (no transport.JobRequest leak).
type JobView struct {
	ID                 string         `json:"job_id"`
	Status             JobStatus      `json:"status"`
	SubmittedAt        time.Time      `json:"submitted_at"`
	StartedAt          *time.Time     `json:"started_at,omitempty"`
	CompletedAt        *time.Time     `json:"completed_at,omitempty"`
	ManifestID         string         `json:"manifest_id"`
	SessionID          string         `json:"session_id"`
	ExpectedOutputKind string         `json:"expected_output_kind"`
	Deadline           time.Time      `json:"deadline"`
	Result             *CandidateView `json:"result,omitempty"`
	Error              *JobError      `json:"error,omitempty"`
	Genome             *GenomeView    `json:"genome,omitempty"`
	Gate               *GateView      `json:"gate,omitempty"`
}

// CandidateView is the subset of a successful CandidateOutput the
// REST API surfaces. Bytes are hex-encoded so the payload is
// transport-safe JSON.
type CandidateView struct {
	OutputKind         string    `json:"output_kind"`
	BytesHex           string    `json:"bytes_hex"`
	ByteCount          int       `json:"byte_count"`
	ProducedAt         time.Time `json:"produced_at"`
	WorkerSigningKeyID string    `json:"worker_signing_key_id"`
}

// toView renders a Job into its JSON-safe projection. Defensive copies
// of the bytes slice so callers cannot mutate queue state.
func (j *Job) toView() JobView {
	view := JobView{
		ID:                 j.ID,
		Status:             j.Status,
		SubmittedAt:        j.SubmittedAt,
		ManifestID:         j.Req.ManifestID,
		SessionID:          j.Req.SessionID,
		ExpectedOutputKind: j.Req.ExpectedOutputKind,
		Deadline:           j.Req.Deadline,
	}
	if !j.StartedAt.IsZero() {
		t := j.StartedAt
		view.StartedAt = &t
	}
	if !j.CompletedAt.IsZero() {
		t := j.CompletedAt
		view.CompletedAt = &t
	}
	if j.Status == JobStatusSucceeded {
		view.Result = &CandidateView{
			OutputKind:         string(j.Candidate.OutputKind),
			BytesHex:           hex.EncodeToString(j.Candidate.Bytes),
			ByteCount:          len(j.Candidate.Bytes),
			ProducedAt:         j.Candidate.ProducedAt,
			WorkerSigningKeyID: j.WorkerSigningKeyID,
		}
	}
	if j.Status == JobStatusFailed {
		err := j.Err
		view.Error = &err
	}
	if j.Genome != nil {
		g := *j.Genome
		view.Genome = &g
	}
	if j.GateResult != nil {
		g := *j.GateResult
		g.Attempts = append([]reconstruction.Attempt(nil), j.GateResult.Attempts...)
		view.Gate = &g
	}
	return view
}

// ---- queue ---------------------------------------------------------------

// JobQueue is a mutex-guarded in-memory FIFO of pending Jobs plus a
// map of every job ever seen (for GET /v1/jobs/{id} lookups).
//
// Scope / lifetime: process-local. A restart loses queued jobs; this
// is acceptable for Phase 1 because all demo jobs are idempotent and
// operators resubmit. A bbolt-backed durable queue lands when the
// broader persistence layer does (Phase 2 — see bbolt dependency in
// go.mod §dependency justification).
//
// Concurrency: safe for concurrent use. Submit / Next / Complete are
// the only public methods; Next blocks until either a job is
// available or the context is cancelled.
type JobQueue struct {
	mu sync.Mutex
	// jobs is every job the queue has ever seen, indexed by ID.
	// Jobs stay in the map after completion so GET /v1/jobs/{id}
	// still works. A TTL sweep lands in Phase 2.
	jobs map[string]*Job
	// pending is the FIFO order of queued job IDs. When a job
	// transitions out of Queued, it is removed from pending but
	// stays in jobs.
	pending []string

	clock shared_time.Clock
	// pollInterval bounds how often Next() re-checks under its
	// lock. Operators can tune this via Runtime.QueuePollMs.
	pollInterval time.Duration
}

// NewJobQueue constructs a fresh queue. clock may be nil (SystemClock
// is substituted). pollInterval must be > 0 — callers typically pass
// cfg.Runtime.QueuePoll().
func NewJobQueue(clock shared_time.Clock, pollInterval time.Duration) *JobQueue {
	if clock == nil {
		clock = shared_time.NewSystemClock()
	}
	if pollInterval <= 0 {
		pollInterval = 250 * time.Millisecond
	}
	return &JobQueue{
		jobs:         make(map[string]*Job),
		clock:        clock,
		pollInterval: pollInterval,
	}
}

// Submit validates req, assigns a fresh ID, and enqueues the job.
// Returns the job ID and the created Job (view). Req is expected to
// already carry the correctly-sealed SealedMaterial — this layer does
// not seal on the caller's behalf; the HTTP layer does.
func (q *JobQueue) Submit(req transport.JobRequest) (string, JobView, error) {
	return q.SubmitGenome(req, nil, nil)
}

// SubmitGenome enqueues a gate job: req carries the sealed model side of
// genome, and gate is what will judge the worker's answer.
func (q *JobQueue) SubmitGenome(req transport.JobRequest, genome *GenomeView, gate *gateSpec) (string, JobView, error) {
	id, err := NewJobID()
	if err != nil {
		return "", JobView{}, err
	}
	view, err := q.SubmitGenomeWithID(id, req, genome, gate)
	return id, view, err
}

// NewJobID mints a job id ahead of submission, so the audit record of
// a job can name it before the job exists.
func NewJobID() (string, error) {
	id, err := newJobID()
	if err != nil {
		return "", fmt.Errorf("sagvd: allocate job id: %w", err)
	}
	return id, nil
}

// SubmitGenomeWithID is SubmitGenome under a pre-minted id (NewJobID).
// An id already in the queue is refused.
func (q *JobQueue) SubmitGenomeWithID(id string, req transport.JobRequest, genome *GenomeView, gate *gateSpec) (JobView, error) {
	if err := req.Validate(); err != nil {
		return JobView{}, err
	}
	if id == "" {
		return JobView{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "sagvd: job id required", nil)
	}
	now := q.clock.Now().UTC()
	j := &Job{
		ID:          id,
		Status:      JobStatusQueued,
		Req:         req,
		SubmittedAt: now,
		Genome:      genome,
		Gate:        gate,
	}
	q.mu.Lock()
	if _, dup := q.jobs[id]; dup {
		q.mu.Unlock()
		return JobView{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "sagvd: job id already queued", nil)
	}
	q.jobs[id] = j
	q.pending = append(q.pending, id)
	view := j.toView() // render under the lock; Next may flip j.Status concurrently
	q.mu.Unlock()
	return view, nil
}

// Get returns the view for a job by ID. The bool is false if no such
// job exists.
func (q *JobQueue) Get(id string) (JobView, bool) {
	q.mu.Lock()
	j, ok := q.jobs[id]
	if !ok {
		q.mu.Unlock()
		return JobView{}, false
	}
	view := j.toView()
	q.mu.Unlock()
	return view, true
}

// Depth reports the count of pending (not-yet-dispatched) jobs. Used
// by the queue_depth gauge.
func (q *JobQueue) Depth() int {
	q.mu.Lock()
	n := len(q.pending)
	q.mu.Unlock()
	return n
}

// ErrQueueClosed is returned from Next when the context is cancelled.
var ErrQueueClosed = errors.New("sagvd: job queue: context done")

// Next blocks until a queued job is available, marks it Running, and
// returns a defensive copy of its transport.JobRequest plus its ID.
// On ctx.Done returns ErrQueueClosed.
//
// Polling model: Next acquires the mutex, checks the head of the
// pending slice, and either returns immediately or releases the lock
// and sleeps for pollInterval before retrying. This trades a small
// amount of latency for a much simpler implementation than a
// condition variable — acceptable in Phase 1 where the dispatcher is
// single-threaded and the poll interval is a quarter second.
func (q *JobQueue) Next(ctx context.Context) (string, transport.JobRequest, error) {
	for {
		if err := ctx.Err(); err != nil {
			return "", transport.JobRequest{}, ErrQueueClosed
		}
		q.mu.Lock()
		if len(q.pending) > 0 {
			id := q.pending[0]
			q.pending = q.pending[1:]
			j, ok := q.jobs[id]
			if !ok {
				// Should never happen: we keep them in sync, but a
				// belt-and-suspenders check keeps the invariant
				// visible to future maintainers.
				q.mu.Unlock()
				continue
			}
			j.Status = JobStatusRunning
			j.StartedAt = q.clock.Now().UTC()
			req := j.Req
			q.mu.Unlock()
			return id, req, nil
		}
		q.mu.Unlock()

		// Lockless wait for the next poll tick or ctx cancellation.
		select {
		case <-ctx.Done():
			return "", transport.JobRequest{}, ErrQueueClosed
		case <-time.After(q.pollInterval):
		}
	}
}

// GateFor returns what judges the job's answer, or nil for a job without
// a gate. The spec does not change after submission.
func (q *JobQueue) GateFor(id string) *gateSpec {
	q.mu.Lock()
	defer q.mu.Unlock()
	if j, ok := q.jobs[id]; ok {
		return j.Gate
	}
	return nil
}

// CompleteSuccess records a successful outcome.
func (q *JobQueue) CompleteSuccess(id string, out returnpath.CandidateOutput, workerKID string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[id]
	if !ok {
		return
	}
	j.Status = JobStatusSucceeded
	j.CompletedAt = q.clock.Now().UTC()
	j.Candidate = out
	j.WorkerSigningKeyID = workerKID
}

// CompleteGated records a gate job's outcome: the verdict, and with a
// nil err the worker's output as the result; with err the job failed on
// that classified error, the verdict still on record.
func (q *JobQueue) CompleteGated(id string, out returnpath.CandidateOutput, workerKID string, gate GateView, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[id]
	if !ok {
		return
	}
	j.CompletedAt = q.clock.Now().UTC()
	j.GateResult = &gate
	j.WorkerSigningKeyID = workerKID
	if err != nil {
		j.Status = JobStatusFailed
		j.Err = newJobError(err)
		return
	}
	j.Status = JobStatusSucceeded
	j.Candidate = out
}

// CompleteFailure records a classified failure. err is mapped through
// newJobError.
func (q *JobQueue) CompleteFailure(id string, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[id]
	if !ok {
		return
	}
	j.Status = JobStatusFailed
	j.CompletedAt = q.clock.Now().UTC()
	j.Err = newJobError(err)
}

// newJobID returns a 32-char hex ID (16 random bytes). Collisions are
// cryptographically improbable within a single process lifetime.
func newJobID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
