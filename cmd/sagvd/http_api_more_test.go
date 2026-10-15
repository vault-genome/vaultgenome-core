// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/jobstore"
	"github.com/vault-genome/vaultgenome-core/internal/vault/orchestration"
)

// The REST server is not wired without its queue or its registry; a
// missing clock and logger get defaults; an address that is taken is a
// Start failure that names it.
func TestHTTPAPI_WiringRefusalsAndDefaults(t *testing.T) {
	queue := NewJobQueue(shared_time.NewSystemClock(), 0)
	registry := metrics.NewRegistry()
	_, err := NewHTTPAPIServer(HTTPAPIConfig{}, RuntimeConfig{}, nil, nil, nil, nil, registry, nil)
	require.ErrorContains(t, err, "non-nil JobQueue")
	_, err = NewHTTPAPIServer(HTTPAPIConfig{}, RuntimeConfig{}, queue, nil, nil, nil, nil, nil)
	require.ErrorContains(t, err, "non-nil metrics.Registry")

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()
	s, err := NewHTTPAPIServer(HTTPAPIConfig{ListenAddress: taken.Addr().String()}, RuntimeConfig{}, queue, nil, nil, nil, registry, nil)
	require.NoError(t, err)
	require.NotNil(t, s.clock)
	require.NotNil(t, s.log)
	require.ErrorContains(t, s.Start(), "sagvd: HTTP API listen")
	require.Equal(t, taken.Addr().String(), s.Addr(), "the configured address, never bound")
}

// GET /v1/jobs/{id} is one id deep: a nested path is an unknown resource.
func TestHTTPAPI_GetJobByID_NestedPathIs404(t *testing.T) {
	fx := newTestFixture(t, "")
	resp, err := fx.client.Get(fx.base + "/v1/jobs/abc/result")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	env := decodeErrorEnvelope(t, resp.Body)
	require.Equal(t, "not_found", env.Error.Code)
	require.Equal(t, "structural", env.Error.Category)
}

// A body with anything after its JSON object is refused as trailing data.
func TestHTTPAPI_PostJobs_TrailingDataIs400(t *testing.T) {
	fx := newTestFixture(t, "")
	body := append(fx.goodSubmit().marshal(t), []byte(` {"again":true}`)...)
	resp, data := fx.post(t, body)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	env := decodeErrorEnvelope(t, bytes.NewReader(data))
	require.Equal(t, "trailing_data", env.Error.Code)
}

// A submission without a deadline takes runtime.default_job_deadline_seconds;
// a ceiling of zero leaves no deadline a job could have.
func TestHTTPAPI_PostJobs_DeadlineDefaults(t *testing.T) {
	fx := newTestFixture(t, "")
	body := fx.goodSubmit()
	body.DeadlineSecondsFromNow = 0
	resp, data := fx.post(t, body.marshal(t))
	require.Equal(t, http.StatusAccepted, resp.StatusCode, string(data))
	var accepted submitResponse
	require.NoError(t, json.Unmarshal(data, &accepted))
	view, ok := fx.queue.Get(accepted.JobID)
	require.True(t, ok)
	require.Equal(t, "queued", string(view.Status))

	noCeiling, err := NewHTTPAPIServer(HTTPAPIConfig{ListenAddress: "127.0.0.1:0"}, RuntimeConfig{HTTPReadHeaderTimeoutSeconds: 5, HTTPWriteTimeoutSeconds: 10, MaxPayloadBytes: 1 << 20},
		fx.queue, fx.server.genomes, fx.ta.authority, nil, metrics.NewRegistry(), nil)
	require.NoError(t, err)
	require.NoError(t, noCeiling.Start())
	t.Cleanup(func() { _ = noCeiling.Close(t.Context()) })
	resp, err = fx.client.Post("http://"+noCeiling.Addr()+"/v1/jobs", "application/json", bytes.NewReader(body.marshal(t)))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Equal(t, "deadline_invalid", decodeErrorEnvelope(t, resp.Body).Error.Code)
}

// A request the audit log cannot record is not admitted: 503, and the
// queue is untouched.
func TestHTTPAPI_PostJobs_AuditUnavailableIs503(t *testing.T) {
	fx := newTestFixture(t, "")
	require.NoError(t, fx.audit.Close())
	resp, data := fx.post(t, fx.goodSubmit().marshal(t))
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	env := decodeErrorEnvelope(t, bytes.NewReader(data))
	require.Equal(t, orchestration.CodeAuditUnavailable, env.Error.Code)
	require.Equal(t, 0, fx.queue.Depth())
}

func TestStatusForBuildError(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"not found":    {shared_errors.Structural(CodeGenomeNotFound, "x", nil), http.StatusBadRequest},
		"invalid":      {shared_errors.Structural(CodeGenomeInvalid, "x", nil), http.StatusBadRequest},
		"field":        {shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "x", nil), http.StatusBadRequest},
		"key":          {shared_errors.Authority(CodeGenomeKeyInvalid, "x", nil), http.StatusForbidden},
		"too large":    {shared_errors.Operational(CodeGenomeTooLarge, "x", nil), http.StatusRequestEntityTooLarge},
		"bundle dir":   {shared_errors.Operational(CodeBundleDirUnavailable, "x", nil), http.StatusInternalServerError},
		"unclassified": {bytes.ErrTooLarge, http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, statusForBuildError(tc.err))
		})
	}
}

func TestPrintableField(t *testing.T) {
	require.True(t, printableField(""))
	require.True(t, printableField("operator:rest (eu-west)"))
	require.True(t, printableField(strings.Repeat("x", maxRequestField)))
	require.False(t, printableField(strings.Repeat("x", maxRequestField+1)), "too long")
	require.False(t, printableField("line\nbreak"), "a control character")
}

// The status recorder reports 200 for a handler that wrote nothing, the
// first code written otherwise; writeJSON answers 500 when the value
// cannot be marshalled rather than sending half a body.
func TestStatusRecorderAndWriteJSON(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	require.Equal(t, http.StatusOK, rec.Status(), "nothing written yet")
	rec.WriteHeader(http.StatusAccepted)
	rec.WriteHeader(http.StatusTeapot)
	require.Equal(t, http.StatusAccepted, rec.Status(), "the first code sticks")

	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]any{"ch": make(chan int)})
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	env := decodeErrorEnvelope(t, w.Body)
	require.Equal(t, "marshal_failed", env.Error.Code)
	require.Equal(t, "operational", env.Error.Category)

	w = httptest.NewRecorder()
	writeJSON(w, http.StatusAccepted, submitResponse{JobID: "j1", State: "queued"})
	require.Equal(t, http.StatusAccepted, w.Code)
	require.JSONEq(t, `{"job_id":"j1","request_id":"","state":"queued","genome":{"bundle":"","key_id":"","key_source":"","bundle_sha256":"","payload_sha256":"","generation":0,"base":"","base_digest":"","files":0,"bytes":0,"fixtures":0,"critical":0}}`, w.Body.String())

	// Close on a server that never started is a no-op.
	s, err := NewHTTPAPIServer(HTTPAPIConfig{}, RuntimeConfig{}, NewJobQueue(shared_time.NewSystemClock(), time.Second), nil, nil, nil, metrics.NewRegistry(), nil)
	require.NoError(t, err)
	require.NoError(t, s.Close(t.Context()))
}

// A restart (ADR 0026): the store's unfinished jobs are admitted again
// under their own ids and request ids as one more attempt, and a job a
// previous process finished answers from its kept view.
func TestHTTPAPI_ResumesStoredJobsAndAnswersForKeptViews(t *testing.T) {
	fx := newTestFixtureWith(t, "", true)
	store := openTestStore(t)
	fx.queue.AttachStore(store, 3, nil)

	before := time.Date(2026, 10, 15, 17, 0, 0, 0, time.UTC)
	request, _ := json.Marshal(submitBody{Genome: map[string]string{"bundle": fx.genome.Bundle, "key_file": fx.genome.KeyFile}, RequestID: "req-before"})
	for _, rec := range []jobstore.Record{
		{ID: "job-in-flight", Request: request, RequestID: "req-before", DeadlineSeconds: 30, SubmittedAt: before, Status: jobstore.StatusRunning, Attempts: 1},
		{ID: "job-gone", Request: json.RawMessage(`{"genome":{"bundle":"vanished.genome","key_file":"vanished.key"}}`), RequestID: "req-gone", DeadlineSeconds: 30, SubmittedAt: before.Add(time.Second), Status: jobstore.StatusQueued, Attempts: 1},
	} {
		if err := store.Put(rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.PutView("job-done", []byte(`{"job_id":"job-done","status":"succeeded","kept":true}`)); err != nil {
		t.Fatal(err)
	}

	resumed, failed, err := fx.server.ResumeJobs()
	if err != nil || resumed != 1 || failed != 1 {
		t.Fatalf("ResumeJobs: resumed %d failed %d err %v, want 1, 1, nil", resumed, failed, err)
	}
	view, ok := fx.queue.Get("job-in-flight")
	if !ok || view.Status != JobStatusQueued || view.RequestID != "req-before" || !view.SubmittedAt.Equal(before) {
		t.Fatalf("the resumed job: ok=%v %+v", ok, view)
	}
	rec, _, _ := store.Get("job-in-flight")
	if rec.Status != jobstore.StatusQueued || rec.Attempts != 2 || rec.RequestID != "req-before" {
		t.Fatalf("the resumed job's record: %+v", rec)
	}
	if gone, _, _ := store.Get("job-gone"); gone.Status != jobstore.StatusFailed || !strings.Contains(gone.LastError, "not admitted again") {
		t.Fatalf("the job whose bundle vanished: %+v", gone)
	}

	// GET answers for all three: from memory, from the kept view, and
	// from the view the failed resume left.
	for id, want := range map[string]string{
		"job-in-flight": `"status":"queued"`,
		"job-done":      `"kept":true`,
		"job-gone":      `"status":"failed"`,
	} {
		status, body := getJob(t, fx, id)
		if status != http.StatusOK || !strings.Contains(string(body), want) {
			t.Fatalf("GET /v1/jobs/%s: %d %s (want %s)", id, status, body, want)
		}
	}
	if status, _ := getJob(t, fx, "never"); status != http.StatusNotFound {
		t.Fatalf("GET of a job that never was: %d", status)
	}

	// The record of the re-admission says why it is one.
	var resumedRecords int
	for _, e := range fx.audit.Chain().Events() {
		if e.Kind == "REQUEST_RECEIVED" && strings.Contains(string(e.Payload), `"resumed":{"attempt":2,`) {
			resumedRecords++
		}
	}
	if resumedRecords != 1 {
		t.Fatalf("REQUEST_RECEIVED with the resumed detail: %d, want 1", resumedRecords)
	}
}

func getJob(t *testing.T, fx *testHTTPFixture, id string) (int, []byte) {
	t.Helper()
	resp, err := fx.client.Get(fx.base + "/v1/jobs/" + id)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}
