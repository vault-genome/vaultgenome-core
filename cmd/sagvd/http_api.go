// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ai-continuity-platform/core/internal/observability/metrics"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
)

// HTTPAPIServer is the operator-facing REST API in front of the
// JobQueue. It owns one net/http.Server and one *metrics.Registry-
// bound set of counters; the daemon hands it only the queue, the
// sealer, and the runtime bounds.
//
// Routes:
//
//	POST /v1/jobs         → 202 + {job_id, manifest_id, session_id, genome}
//	GET  /v1/jobs/{id}    → 200 + JobView
//
// A job is a gate job (ADR 0013): its body names a sealed genome in
// genome.bundle_dir, sagvd builds the JobRequest from it (genome_job.go)
// and, once the worker has answered, records the gate's verdict on the
// job. The authority names the job's manifest and session itself.
//
// All other paths / methods are 404 / 405. Responses are JSON-only
// (Content-Type: application/json) so SDKs do not have to handle two
// response shapes. Errors carry a classified payload
// {"error":{"category","code","message"}} so the Python SDK can map
// them back onto the same taxonomy the Return Path wire uses.
//
// Authentication: if HTTPAPIConfig.BearerToken is non-empty, every
// request must carry "Authorization: Bearer <token>" with a
// constant-time-matching token. Empty token = no auth — only safe
// for loopback demos.
type HTTPAPIServer struct {
	cfg     HTTPAPIConfig
	runtime RuntimeConfig
	queue   *JobQueue
	sealer  keys.Sealer
	sealKID ids.KeyID
	genomes *genomeJobs // nil: gate jobs are not configured
	clock   shared_time.Clock
	log     *slog.Logger

	listener net.Listener
	server   *http.Server
	metrics  *httpMetrics
}

// httpMetrics is the set of counters the REST API drives. Registered
// once at construction; exposed via the /metrics endpoint on the
// health HTTP server (same Registry is shared).
type httpMetrics struct {
	requests      *metrics.Counter // labels: route, status
	jobsSubmitted *metrics.Counter // unlabeled
}

// NewHTTPAPIServer wires a ready-to-Start server. The caller is
// expected to have already called cfg.Validate(); a non-host:port
// listen address here is a programmer error.
//
// sealer + sealKID cannot be zero: POST /v1/jobs needs them to
// produce SealedMaterialRef. We fail fast at construction so a
// misconfigured daemon cannot silently accept submissions. genomes may
// be nil (genome.bundle_dir not configured): then POST /v1/jobs refuses
// every submission with gate_jobs_disabled.
func NewHTTPAPIServer(
	cfg HTTPAPIConfig,
	runtime RuntimeConfig,
	queue *JobQueue,
	sealer keys.Sealer,
	sealKID ids.KeyID,
	genomes *genomeJobs,
	clock shared_time.Clock,
	registry *metrics.Registry,
	logger *slog.Logger,
) (*HTTPAPIServer, error) {
	if queue == nil {
		return nil, errors.New("sagvd: HTTPAPIServer requires non-nil JobQueue")
	}
	if sealer == nil {
		return nil, errors.New("sagvd: HTTPAPIServer requires non-nil Sealer")
	}
	if sealKID == "" {
		return nil, errors.New("sagvd: HTTPAPIServer requires session-sealing KeyID")
	}
	if clock == nil {
		clock = shared_time.NewSystemClock()
	}
	if registry == nil {
		return nil, errors.New("sagvd: HTTPAPIServer requires non-nil metrics.Registry")
	}
	if logger == nil {
		logger = slog.Default()
	}

	s := &HTTPAPIServer{
		cfg:     cfg,
		runtime: runtime,
		queue:   queue,
		sealer:  sealer,
		sealKID: sealKID,
		genomes: genomes,
		clock:   clock,
		log:     logger,
		metrics: &httpMetrics{
			requests: registry.NewCounter(
				"sagvd_http_requests_total",
				"Total HTTP requests to the operator REST API, labelled by route and status.",
			),
			jobsSubmitted: registry.NewCounter(
				"sagvd_jobs_submitted_total",
				"Total jobs accepted via POST /v1/jobs.",
			),
		},
	}
	return s, nil
}

// Start binds the listener (if a ListenAddress is configured) and
// launches the serving goroutine. Empty ListenAddress is a no-op:
// the REST API is disabled and in-process callers must drive the
// JobQueue directly (tests, loopback demos).
func (s *HTTPAPIServer) Start() error {
	if s.cfg.ListenAddress == "" {
		return nil
	}
	ln, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("sagvd: HTTP API listen %q: %w", s.cfg.ListenAddress, err)
	}
	s.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/jobs", s.withInstrumentation("/v1/jobs", s.withAuth(s.handleJobsCollection)))
	mux.HandleFunc("/v1/jobs/", s.withInstrumentation("/v1/jobs/{id}", s.withAuth(s.handleJobByID)))

	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: s.runtime.HTTPReadHeaderTimeout(),
		WriteTimeout:      s.runtime.HTTPWriteTimeout(),
		// IdleTimeout is generous; operator REST clients may keep
		// connections alive between polls of GET /v1/jobs/{id}.
		IdleTimeout: 60 * time.Second,
	}
	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("sagvd: HTTP API server exited with error", "err", err)
		}
	}()
	return nil
}

// Addr returns the bound host:port (useful in tests where the
// configured ListenAddress ends in :0). Returns the configured
// ListenAddress verbatim when the server is not bound.
func (s *HTTPAPIServer) Addr() string {
	if s.listener == nil {
		return s.cfg.ListenAddress
	}
	return s.listener.Addr().String()
}

// Close shuts the HTTP server down with Server.Shutdown, honouring
// ctx's deadline. Safe to call on a never-Started server.
func (s *HTTPAPIServer) Close(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

// ---- handlers ------------------------------------------------------------

// handleJobsCollection accepts POST /v1/jobs. GET on the collection
// is not currently supported — listing queued jobs is a Phase-2
// feature (pagination, filtering, ownership). In Phase 1 the operator
// knows the job IDs they submitted.
func (s *HTTPAPIServer) handleJobsCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	s.submitJob(w, r)
}

// handleJobByID accepts GET /v1/jobs/{id}. Anything else on the
// path is 404/405.
func (s *HTTPAPIServer) handleJobByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/jobs/")
	// strings.TrimPrefix leaves a trailing slash or a nested path
	// visible; both are invalid here.
	if id == "" || strings.ContainsRune(id, '/') {
		writeError(w, http.StatusNotFound, "structural", "not_found", "unknown resource")
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	view, ok := s.queue.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "structural", "job_not_found",
			"no job with id "+id)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// submitRequest is the body shape POST /v1/jobs accepts: which sealed
// genome to bring back, and how long the worker has.
type submitRequest struct {
	// Genome names a bundle in genome.bundle_dir and, unless its escrow
	// envelope is beside it, its key file.
	Genome genomeRef `json:"genome"`

	// DeadlineSecondsFromNow is how long the worker has to restore the
	// model and answer; 0 takes runtime.default_job_deadline_seconds,
	// which is also the ceiling.
	DeadlineSecondsFromNow int `json:"deadline_seconds_from_now,omitempty"`
}

// maxSubmitBodyBytes bounds a POST /v1/jobs body: it names files, it
// does not carry them.
const maxSubmitBodyBytes = 64 << 10

// submitResponse is what POST /v1/jobs returns on success.
type submitResponse struct {
	JobID      string     `json:"job_id"`
	ManifestID string     `json:"manifest_id"`
	SessionID  string     `json:"session_id"`
	Genome     GenomeView `json:"genome"`
}

// submitJob parses the body, builds the gate job from the named genome
// — opens the bundle, keeps the references, seals the model side under
// the session key — and enqueues it. Returns 202 Accepted on success.
func (s *HTTPAPIServer) submitJob(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSubmitBodyBytes)

	var req submitRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "structural", "decode_body",
			"decode request body: "+err.Error())
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "structural", "trailing_data",
			"request body contains trailing data after JSON object")
		return
	}
	if err := req.validate(); err != nil {
		writeError(w, http.StatusBadRequest, shared_errors.CategoryOf(err).String(),
			shared_errors.CodeOf(err), err.Error())
		return
	}
	if s.genomes == nil {
		writeError(w, http.StatusServiceUnavailable, "structural", CodeGateJobsDisabled,
			"gate jobs are not configured: set genome.bundle_dir")
		return
	}

	// Deadline defaulting + ceiling check. A submitter asking for
	// longer than the configured ceiling is Structurally rejected
	// so that operator-configured SLO bounds are ground truth.
	deadlineSecs := req.DeadlineSecondsFromNow
	if deadlineSecs == 0 {
		deadlineSecs = s.runtime.DefaultJobDeadlineSeconds
	}
	if deadlineSecs > s.runtime.DefaultJobDeadlineSeconds {
		writeError(w, http.StatusBadRequest, "structural", "deadline_exceeds_ceiling",
			fmt.Sprintf("deadline_seconds_from_now %d exceeds ceiling %d",
				deadlineSecs, s.runtime.DefaultJobDeadlineSeconds))
		return
	}
	if deadlineSecs <= 0 {
		writeError(w, http.StatusBadRequest, "structural", "deadline_invalid",
			"deadline_seconds_from_now must be > 0")
		return
	}

	job, err := s.genomes.build(req.Genome, time.Duration(deadlineSecs)*time.Second)
	if err != nil {
		writeError(w, statusForBuildError(err), shared_errors.CategoryOf(err).String(),
			shared_errors.CodeOf(err), err.Error())
		return
	}
	jobID, _, err := s.queue.SubmitGenome(job.Req, &job.Genome, job.Gate)
	if err != nil {
		writeError(w, http.StatusBadRequest, shared_errors.CategoryOf(err).String(),
			shared_errors.CodeOf(err), err.Error())
		return
	}
	s.metrics.jobsSubmitted.Inc()
	s.log.Info("sagvd gate job accepted",
		"job_id", jobID,
		"manifest_id", job.Req.ManifestID,
		"session_id", job.Req.SessionID,
		"genome_id", job.Genome.KeyID,
		"bundle", job.Genome.Bundle,
		"key_source", job.Genome.KeySource,
		"fixtures", job.Genome.Fixtures,
		"shipped_bytes", job.Genome.Bytes,
		"output_budget_bytes", job.Req.ExpectedOutputMaxBytes,
	)
	writeJSON(w, http.StatusAccepted, submitResponse{
		JobID: jobID, ManifestID: job.Req.ManifestID, SessionID: job.Req.SessionID, Genome: job.Genome,
	})
}

// statusForBuildError maps a gate-job build error to an HTTP status: what
// the caller named is 4xx, what the vault cannot do is 5xx.
func statusForBuildError(err error) int {
	switch shared_errors.CodeOf(err) {
	case CodeGenomeNotFound, CodeGenomeInvalid, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeFieldValueInvalid:
		return http.StatusBadRequest
	case CodeGenomeKeyInvalid:
		return http.StatusForbidden
	case CodeGenomeTooLarge:
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusInternalServerError
	}
}

// validate runs structural checks on the parsed body before any file
// is touched.
func (r submitRequest) validate() error {
	var errs []error
	if strings.TrimSpace(r.Genome.Bundle) == "" {
		errs = append(errs, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome.bundle required", nil))
	}
	if r.DeadlineSecondsFromNow < 0 {
		errs = append(errs, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"deadline_seconds_from_now must be >= 0", nil))
	}
	return errors.Join(errs...)
}

// ---- middleware ----------------------------------------------------------

// withAuth enforces the optional Bearer token on every write
// endpoint. If the configured token is empty, auth is a no-op.
func (s *HTTPAPIServer) withAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.BearerToken == "" {
			h(w, r)
			return
		}
		got := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(got, prefix) {
			writeError(w, http.StatusUnauthorized, "authority", "auth_missing",
				"missing Bearer credentials")
			return
		}
		token := got[len(prefix):]
		// Constant-time comparison: prevents timing side-channels
		// from revealing the token to a probing client.
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.BearerToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "authority", "auth_invalid",
				"invalid Bearer credentials")
			return
		}
		h(w, r)
	}
}

// withInstrumentation records one http_requests_total{route,status}
// sample per handled request. Status is captured via a thin
// ResponseWriter wrapper; we do not use httptest.ResponseRecorder in
// production because it buffers the whole body — we only need the
// final status code.
func (s *HTTPAPIServer) withInstrumentation(route string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		h(rec, r)
		status := rec.Status()
		s.metrics.requests.Inc(
			metrics.Label{Name: "route", Value: route},
			metrics.Label{Name: "status", Value: strconv.Itoa(status)},
		)
	}
}

// statusRecorder wraps http.ResponseWriter to capture the status
// code WriteHeader was called with. If WriteHeader is never called
// the net/http default (200) is reported via the Write fallback.
type statusRecorder struct {
	http.ResponseWriter
	status int32
}

// WriteHeader records the first code passed; subsequent calls are
// ignored (net/http itself warns on double-WriteHeader — we match
// that behaviour by only remembering the first code).
func (s *statusRecorder) WriteHeader(code int) {
	atomic.CompareAndSwapInt32(&s.status, 0, int32(code))
	s.ResponseWriter.WriteHeader(code)
}

// Write implicitly flushes headers with 200 when WriteHeader has
// not yet been called. We mirror that so Status() reports 200 in
// that case — not 0.
func (s *statusRecorder) Write(b []byte) (int, error) {
	atomic.CompareAndSwapInt32(&s.status, 0, http.StatusOK)
	return s.ResponseWriter.Write(b)
}

// Status returns the recorded status code, defaulting to 200 if
// neither WriteHeader nor Write was ever called.
func (s *statusRecorder) Status() int {
	v := int(atomic.LoadInt32(&s.status))
	if v == 0 {
		return http.StatusOK
	}
	return v
}

// ---- helpers -------------------------------------------------------------

// writeJSON marshals v and writes it with status + Content-Type.
// Marshalling errors are rare (only map-key or circular cases) and
// are surfaced as a 500 so operators see the cause.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w,
			`{"error":{"category":"operational","code":"marshal_failed","message":"response marshal failed"}}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeError writes a classified error response. The payload shape
// is stable for SDK consumption: {"error":{category,code,message}}.
func writeError(w http.ResponseWriter, status int, category, code, message string) {
	type envelope struct {
		Error struct {
			Category string `json:"category"`
			Code     string `json:"code"`
			Message  string `json:"message"`
		} `json:"error"`
	}
	var env envelope
	env.Error.Category = category
	env.Error.Code = code
	env.Error.Message = message
	writeJSON(w, status, env)
}

// writeMethodNotAllowed sends 405 with a classified error envelope
// and sets the Allow header to allowed, per RFC 9110 §15.5.5.
func writeMethodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, http.StatusMethodNotAllowed, "structural", "method_not_allowed",
		"method not allowed; allowed="+allowed)
}
