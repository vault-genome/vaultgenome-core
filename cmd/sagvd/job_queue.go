// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/validation/reconstruction"
	"github.com/vault-genome/vaultgenome-core/internal/vault/jobstore"
	"github.com/vault-genome/vaultgenome-core/internal/vault/orchestration"
)

// ---- public status / types -----------------------------------------------

// JobStatus is the lifecycle phase of a submitted job.
type JobStatus string

const (
	// JobStatusQueued — accepted by POST /v1/jobs (intake), waiting for
	// a worker to connect.
	JobStatusQueued JobStatus = "queued"

	// JobStatusRunning — the flow is being driven for this job: trust,
	// session, disclosure, the JobRequest on the wire, the candidate
	// awaited and judged.
	JobStatusRunning JobStatus = "running"

	// JobStatusSucceeded — the flow reached a release decision with
	// release=true; GET /v1/jobs/{id} surfaces the bytes.
	JobStatusSucceeded JobStatus = "succeeded"

	// JobStatusFailed — the flow refused release or ended before a
	// decision. GET /v1/jobs/{id} surfaces {category, code, message}.
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

// Job is one gate job tracked by sagvd: a request admitted into the
// nine-stage flow, the genome it names, and its outcome.
//
// Lifecycle: Queued (intake) → Running (dispatched to a worker) →
// Succeeded or Failed. Terminal states are immutable; no re-queue on
// failure. A job whose worker's Evidence proved too old at dispatch goes
// back to the head of the queue (Requeue) without having started.
type Job struct {
	// ID is a 16-byte hex-encoded random identifier minted before intake,
	// so the audit record of a job names it.
	ID string

	// Status is the current lifecycle phase.
	Status JobStatus

	// Flow is the job's passage through the nine stages (ADR 0015). It
	// is admitted at submission (stage 1) and driven by the dispatcher.
	Flow *orchestration.Flow

	// Info is what the authority keeps about the genome the job named:
	// its view, the references that judge the answer, the answer's exact
	// budget. Never plaintext.
	Info genomeInfo

	// DeadlineFor is how long the worker has from dispatch.
	DeadlineFor time.Duration

	// Deadline is when the worker's answer is due; set at dispatch.
	Deadline time.Time

	// SubmittedAt records when POST /v1/jobs accepted the job.
	SubmittedAt time.Time

	// StartedAt records when the dispatcher picked this job up.
	// Zero until transition to Running.
	StartedAt time.Time

	// CompletedAt records when the dispatcher wrote the terminal
	// outcome. Zero until transition to Succeeded or Failed.
	CompletedAt time.Time

	// Candidate holds the worker's output once release was authorised.
	// Zero-valued otherwise: a refused answer is never surfaced.
	Candidate returnpath.CandidateOutput

	// WorkerSigningKeyID records the kid under which the
	// CandidateOutputFrame was signed, once one arrived.
	WorkerSigningKeyID string

	// Err is the classified error for Failed jobs; zero JobError
	// otherwise.
	Err JobError

	// GateResult is the ladder's verdict once the answer was judged; nil
	// until then.
	GateResult *GateView

	// Top1 is the top-1 agreement once the answer was judged.
	Top1 *equivalence.Top1Report
}

// JobView is the JSON-serialisable projection GET /v1/jobs/{id}
// returns: the job's status, the genome it named, the gate's verdict,
// and the flow — every stage taken and every signed artifact, for an
// operator to verify against the keys `sagvd identity` prints.
type JobView struct {
	ID                 string                  `json:"job_id"`
	RequestID          string                  `json:"request_id"`
	Status             JobStatus               `json:"status"`
	State              string                  `json:"state"`
	SubmittedAt        time.Time               `json:"submitted_at"`
	StartedAt          *time.Time              `json:"started_at,omitempty"`
	CompletedAt        *time.Time              `json:"completed_at,omitempty"`
	ManifestID         string                  `json:"manifest_id,omitempty"`
	SessionID          string                  `json:"session_id,omitempty"`
	ExpectedOutputKind string                  `json:"expected_output_kind"`
	Deadline           *time.Time              `json:"deadline,omitempty"`
	Result             *CandidateView          `json:"result,omitempty"`
	Error              *JobError               `json:"error,omitempty"`
	Genome             *GenomeView             `json:"genome,omitempty"`
	Gate               *GateView               `json:"gate,omitempty"`
	Top1               *equivalence.Top1Report `json:"top1,omitempty"`
	Flow               *orchestration.View     `json:"flow,omitempty"`
}

// CandidateView is the subset of a released CandidateOutput the REST
// API surfaces. Bytes are hex-encoded so the payload is transport-safe
// JSON.
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
		ExpectedOutputKind: string(rjm.OutputKindBytesFixedLength),
	}
	if j.Flow != nil {
		snap := j.Flow.Snapshot()
		view.RequestID = snap.Request.RequestID.String()
		view.State = snap.State.String()
		view.ManifestID = j.Flow.ManifestID().String()
		view.SessionID = j.Flow.SessionID().String()
		view.Flow = &snap
	}
	if !j.StartedAt.IsZero() {
		t := j.StartedAt
		view.StartedAt = &t
	}
	if !j.CompletedAt.IsZero() {
		t := j.CompletedAt
		view.CompletedAt = &t
	}
	if !j.Deadline.IsZero() {
		t := j.Deadline
		view.Deadline = &t
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
	g := j.Info.View
	view.Genome = &g
	if j.GateResult != nil {
		g := *j.GateResult
		g.Attempts = append([]reconstruction.Attempt(nil), j.GateResult.Attempts...)
		view.Gate = &g
	}
	if j.Top1 != nil {
		t := *j.Top1
		t.Results = append([]equivalence.Top1Result(nil), j.Top1.Results...)
		view.Top1 = &t
	}
	return view
}

// ---- queue ---------------------------------------------------------------

// JobQueue is a mutex-guarded in-memory FIFO of pending Jobs plus a
// map of the jobs it holds (for GET /v1/jobs/{id} lookups).
//
// Scope / lifetime: process-local, unless a store is attached
// (AttachStore, ADR 0026): then every submission and transition is
// written to disk, a finished job's view outlives the process — and
// leaves memory, the store answering for it — and Resume admits again
// what a previous process left queued or running. Without a store a
// restart loses queued jobs, every finished job stays in memory, and
// the daemon says so.
//
// Concurrency: safe for concurrent use. Next blocks until either a job
// is available or the context is cancelled.
type JobQueue struct {
	mu sync.Mutex
	// jobs is every job in flight — queued or running — indexed by ID,
	// and, without a store, every job ever seen, so GET /v1/jobs/{id}
	// still answers. With a store a finished job leaves the map as soon
	// as its view is on disk, where GetRaw reads it: an authority that
	// runs for a month holds its jobs in flight, not its history
	// (KNOWN_ISSUES #18).
	jobs map[string]*Job
	// pending is the FIFO order of queued job IDs. When a job
	// transitions out of Queued, it is removed from pending but
	// stays in jobs.
	pending []string

	clock shared_time.Clock
	// pollInterval bounds how often Next() re-checks under its
	// lock. Operators can tune this via Runtime.QueuePollMs.
	pollInterval time.Duration

	// store, when set, keeps every job and its transitions on disk
	// (ADR 0026); a write that fails is logged, and the job goes on —
	// durability is what is lost, not the decision (the audit log is
	// the decision's record). maxResume bounds the admissions of one job
	// across restarts.
	store     *jobstore.Store
	maxResume int
	log       *slog.Logger
}

// AttachStore puts the queue on disk: every submission and transition is
// written to store, and Resume admits again what a previous process
// left queued or running. Called once, before the queue is used.
func (q *JobQueue) AttachStore(store *jobstore.Store, maxResume int, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	if maxResume <= 0 {
		maxResume = DefaultMaxResumeAttempts
	}
	q.mu.Lock()
	q.store, q.maxResume, q.log = store, maxResume, log
	q.mu.Unlock()
}

// JobRecord is what a submission leaves on the store beside the job: the
// request as accepted, so that a resume can admit it again.
type JobRecord struct {
	// Request is the submission body as accepted, re-encoded.
	Request json.RawMessage
	// RequestID is the RecoveryRequest's id this admission used.
	RequestID string
	// DeadlineSeconds is how long the worker has from dispatch.
	DeadlineSeconds int
	// Attempt is this admission's number: 1 at submission, one more
	// per resume; 0 means 1.
	Attempt int
	// SubmittedAt is when the job was first accepted; zero means now.
	SubmittedAt time.Time
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

// NewJobID mints a job id ahead of submission, so the audit record of
// a job can name it before the job exists.
func NewJobID() (string, error) {
	id, err := newJobID()
	if err != nil {
		return "", fmt.Errorf("sagvd: allocate job id: %w", err)
	}
	return id, nil
}

// Submit enqueues an admitted job under its pre-minted id (NewJobID):
// the flow intake produced, the genome it named, and how long the worker
// will have. An id already in the queue is refused. Nothing is left on
// the store to resume the job from; SubmitRecorded is the submission the
// daemon makes.
func (q *JobQueue) Submit(id string, flow *orchestration.Flow, info genomeInfo, deadline time.Duration) (JobView, error) {
	return q.SubmitRecorded(id, flow, info, deadline, JobRecord{})
}

// SubmitRecorded is Submit with what the store keeps to admit the job
// again after a restart (ADR 0026).
func (q *JobQueue) SubmitRecorded(id string, flow *orchestration.Flow, info genomeInfo, deadline time.Duration, rec JobRecord) (JobView, error) {
	if id == "" {
		return JobView{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "sagvd: job id required", nil)
	}
	if flow == nil {
		return JobView{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "sagvd: a job needs its flow", nil)
	}
	if deadline <= 0 {
		return JobView{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "sagvd: a job needs a positive deadline", nil)
	}
	if info.Gate == nil || info.Budget == 0 {
		return JobView{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "sagvd: a job needs its genome's references and budget", nil)
	}
	now := q.clock.Now().UTC()
	submitted := now
	if !rec.SubmittedAt.IsZero() {
		submitted = rec.SubmittedAt.UTC()
	}
	j := &Job{
		ID:          id,
		Status:      JobStatusQueued,
		Flow:        flow,
		Info:        info,
		DeadlineFor: deadline,
		SubmittedAt: submitted,
	}
	q.mu.Lock()
	if _, dup := q.jobs[id]; dup {
		q.mu.Unlock()
		return JobView{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "sagvd: job id already queued", nil)
	}
	q.jobs[id] = j
	q.pending = append(q.pending, id)
	view := j.toView() // render under the lock; Next may flip j.Status concurrently
	store := q.store
	q.mu.Unlock()
	if store != nil {
		attempt := rec.Attempt
		if attempt <= 0 {
			attempt = 1
		}
		if err := store.Put(jobstore.Record{
			ID: id, Request: rec.Request, RequestID: rec.RequestID, DeadlineSeconds: rec.DeadlineSeconds,
			SubmittedAt: submitted, Status: jobstore.StatusQueued, Attempts: attempt, UpdatedAt: now,
		}); err != nil {
			q.log.Error("sagvd job store refused a record; the job goes on in memory only", "job_id", id, "err", err)
		}
	}
	return view, nil
}

// transition writes a status change to the store, if any; a failure is
// logged, not fatal.
func (q *JobQueue) transition(id, status, lastErr string) {
	if q.store == nil {
		return
	}
	if err := q.store.SetStatus(id, status, lastErr, q.clock.Now().UTC()); err != nil {
		q.log.Error("sagvd job store refused a transition", "job_id", id, "status", status, "err", err)
	}
}

// keepView writes a finished job's view to the store, if any, so that
// every GET from now on — after a restart too — answers from disk; it
// reports whether the view is there.
func (q *JobQueue) keepView(id string, view []byte) bool {
	if q.store == nil || view == nil {
		return false
	}
	if err := q.store.PutView(id, view); err != nil {
		q.log.Error("sagvd job store refused a view; the job stays in memory", "job_id", id, "err", err)
		return false
	}
	return true
}

// forget drops a finished job from memory once the store answers for it.
func (q *JobQueue) forget(id string) {
	q.mu.Lock()
	if j, ok := q.jobs[id]; ok && (j.Status == JobStatusSucceeded || j.Status == JobStatusFailed) {
		delete(q.jobs, id)
	}
	q.mu.Unlock()
}

// Held is how many jobs the queue holds in memory: those in flight and,
// without a store, every job ever seen.
func (q *JobQueue) Held() int {
	q.mu.Lock()
	n := len(q.jobs)
	q.mu.Unlock()
	return n
}

// GetRaw returns the job's view as JSON: from memory for a job in
// flight, or from the store for a finished one.
func (q *JobQueue) GetRaw(id string) ([]byte, bool) {
	if view, ok := q.Get(id); ok {
		raw, err := json.Marshal(view)
		if err != nil {
			return nil, false
		}
		return raw, true
	}
	if q.store == nil {
		return nil, false
	}
	raw, ok, err := q.store.View(id)
	if err != nil {
		q.log.Error("sagvd job store could not read a view", "job_id", logSafe(id), "err", err)
		return nil, false
	}
	return raw, ok
}

// Resume admits again every job the store holds as queued or running —
// what a previous process accepted and did not finish — oldest first,
// through readmit, which runs the submission path for the record under
// its own id, as one more attempt. A job past maxResume admissions, one
// without its request, or one readmit refuses is failed on the record
// with the reason. It returns how many were resumed and how many failed.
func (q *JobQueue) Resume(readmit func(rec jobstore.Record) error) (resumed, failed int, err error) {
	if q.store == nil {
		return 0, 0, nil
	}
	pending, err := q.store.Pending()
	if err != nil {
		return 0, 0, err
	}
	for _, rec := range pending {
		var reason string
		switch {
		case len(rec.Request) == 0:
			reason = "the job's request was not recorded, so it cannot be admitted again"
		case rec.Attempts >= q.maxResume:
			reason = fmt.Sprintf("the job was admitted %d times and never finished (queue.max_resume_attempts %d)", rec.Attempts, q.maxResume)
		default:
			if rerr := readmit(rec); rerr != nil {
				reason = "not admitted again: " + rerr.Error()
			} else {
				resumed++
				continue
			}
		}
		failed++
		q.failOnRecord(rec, reason)
	}
	return resumed, failed, nil
}

// failOnRecord marks a record the resume could not admit as failed, with
// a view that says why, so GET /v1/jobs/{id} answers for it.
func (q *JobQueue) failOnRecord(rec jobstore.Record, reason string) {
	now := q.clock.Now().UTC()
	jerr := newJobError(shared_errors.Operational(shared_errors.CodeResourceExhausted, "sagvd: "+reason, nil))
	view := JobView{
		ID: rec.ID, Status: JobStatusFailed, SubmittedAt: rec.SubmittedAt, CompletedAt: &now, Error: &jerr,
		ExpectedOutputKind: string(rjm.OutputKindBytesFixedLength),
	}
	raw, _ := json.Marshal(view)
	q.transition(rec.ID, jobstore.StatusFailed, reason)
	q.keepView(rec.ID, raw)
	q.log.Warn("sagvd job from before the restart not resumed", "job_id", rec.ID, "attempts", rec.Attempts, "reason", reason)
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
// returns a copy of it (the flow is shared; the queue's own record is
// only written through the queue). On ctx.Done returns ErrQueueClosed.
//
// Polling model: Next acquires the mutex, checks the head of the
// pending slice, and either returns immediately or releases the lock
// and sleeps for pollInterval before retrying.
func (q *JobQueue) Next(ctx context.Context) (Job, error) {
	for {
		if err := ctx.Err(); err != nil {
			return Job{}, ErrQueueClosed
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
			cp := *j
			q.mu.Unlock()
			q.transition(id, jobstore.StatusRunning, "")
			return cp, nil
		}
		q.mu.Unlock()

		// Lockless wait for the next poll tick or ctx cancellation.
		select {
		case <-ctx.Done():
			return Job{}, ErrQueueClosed
		case <-time.After(q.pollInterval):
		}
	}
}

// Requeue puts a running job back at the head of the queue, untouched:
// the worker it was about to go to must attest again first.
func (q *JobQueue) Requeue(id string) {
	q.mu.Lock()
	j, ok := q.jobs[id]
	if !ok || j.Status != JobStatusRunning {
		q.mu.Unlock()
		return
	}
	j.Status = JobStatusQueued
	j.StartedAt = time.Time{}
	q.pending = append([]string{id}, q.pending...)
	q.mu.Unlock()
	q.transition(id, jobstore.StatusQueued, "")
}

// MarkDispatched records when the worker's answer is due, once the
// JobRequest is about to leave the vault.
func (q *JobQueue) MarkDispatched(id string, deadline time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if j, ok := q.jobs[id]; ok {
		j.Deadline = deadline.UTC()
	}
}

// CompleteGated records a judged job's outcome: the ladder's verdict and
// the top-1 agreement, and with a nil err the worker's output as the
// released result; with err the job failed on that classified error,
// the verdicts still on record and the output withheld.
func (q *JobQueue) CompleteGated(id string, out returnpath.CandidateOutput, workerKID string, gate GateView, top1 *equivalence.Top1Report, err error) {
	q.mu.Lock()
	j, ok := q.jobs[id]
	if !ok {
		q.mu.Unlock()
		return
	}
	j.CompletedAt = q.clock.Now().UTC()
	j.GateResult = &gate
	j.Top1 = top1
	j.WorkerSigningKeyID = workerKID
	status, lastErr := jobstore.StatusSucceeded, ""
	if err != nil {
		j.Status = JobStatusFailed
		j.Err = newJobError(err)
		status, lastErr = jobstore.StatusFailed, err.Error()
	} else {
		j.Status = JobStatusSucceeded
		j.Candidate = out
	}
	raw := q.viewJSON(j)
	q.mu.Unlock()
	q.transition(id, status, lastErr)
	if q.keepView(id, raw) {
		q.forget(id)
	}
}

// viewJSON renders j's view under the caller's lock; nil when there is no
// store to keep it for.
func (q *JobQueue) viewJSON(j *Job) []byte {
	if q.store == nil {
		return nil
	}
	raw, err := json.Marshal(j.toView())
	if err != nil {
		q.log.Error("sagvd job view did not encode", "job_id", j.ID, "err", err)
		return nil
	}
	return raw
}

// CompleteFailure records a classified failure. err is mapped through
// newJobError.
func (q *JobQueue) CompleteFailure(id string, err error) {
	q.mu.Lock()
	j, ok := q.jobs[id]
	if !ok {
		q.mu.Unlock()
		return
	}
	j.Status = JobStatusFailed
	j.CompletedAt = q.clock.Now().UTC()
	j.Err = newJobError(err)
	raw := q.viewJSON(j)
	q.mu.Unlock()
	q.transition(id, jobstore.StatusFailed, err.Error())
	if q.keepView(id, raw) {
		q.forget(id)
	}
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
