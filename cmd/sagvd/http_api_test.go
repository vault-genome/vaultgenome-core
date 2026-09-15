// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ai-continuity-platform/core/internal/observability/metrics"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
)

// --- test fixtures --------------------------------------------------------

// testHTTPFixture bundles every piece a handler-level test needs:
// a live HTTPAPIServer, the queue behind it, and a client that
// talks to its bound listener. Cleanup closes the server.
type testHTTPFixture struct {
	server *HTTPAPIServer
	queue  *JobQueue
	client *http.Client
	base   string
	dir    string     // genome.bundle_dir
	genome testGenome // a sealed genome in dir
	audit  *returnPathAudit
}

// newTestFixture starts an HTTPAPIServer listening on 127.0.0.1:0
// (OS-assigned port) with the given bearer token, over a bundle dir
// holding one sealed genome. Empty token means auth is disabled.
func newTestFixture(t *testing.T, bearer string) *testHTTPFixture {
	return newTestFixtureWith(t, bearer, true)
}

func newTestFixtureWith(t *testing.T, bearer string, gateJobs bool) *testHTTPFixture {
	t.Helper()

	clock := shared_time.NewSystemClock()
	store := keys.NewInMemoryStore(clock)
	sealKID := testRegisterSealing(t, store)

	queue := NewJobQueue(clock, 50*time.Millisecond)
	registry := metrics.NewRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := HTTPAPIConfig{
		ListenAddress: "127.0.0.1:0",
		BearerToken:   bearer,
	}
	runtime := RuntimeConfig{
		HTTPReadHeaderTimeoutSeconds: 5,
		HTTPWriteTimeoutSeconds:      10,
		DefaultJobDeadlineSeconds:    60,
		MaxPayloadBytes:              1 << 20,
	}
	dir := t.TempDir()
	sealed := sealTestGenome(t, dir, genomeOptions{})
	var genomes *genomeJobs
	var audit *returnPathAudit
	if gateJobs {
		full := DefaultConfig()
		full.Genome.BundleDir = dir
		full.Runtime = runtime
		genomes = newGenomeJobs(full, store, sealKID, clock)
		audit, _ = newTestAudit(t)
	}
	srv, err := NewHTTPAPIServer(cfg, runtime, queue, store, sealKID, genomes, audit, clock, registry, logger)
	if err != nil {
		t.Fatalf("NewHTTPAPIServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Close(shutCtx)
	})

	return &testHTTPFixture{
		server: srv,
		queue:  queue,
		client: &http.Client{Timeout: 5 * time.Second},
		base:   "http://" + srv.Addr(),
		dir:    dir,
		genome: sealed,
		audit:  audit,
	}
}

// testRegisterSealing registers a fresh 32-byte AES-256 sealing
// material under a deterministic kid so sealing round-trips have
// something to work against.
func testRegisterSealing(t *testing.T, store *keys.InMemoryStore) ids.KeyID {
	t.Helper()
	kid := ids.KeyID("test-sealing-kid-1")
	material := make([]byte, 32)
	// Deterministic-but-non-zero pattern; keystore copies it
	// defensively so wiping our caller-side buffer is a no-op.
	for i := range material {
		material[i] = byte(i ^ 0xA5)
	}
	if err := store.RegisterSealing(kid, material); err != nil {
		t.Fatalf("RegisterSealing: %v", err)
	}
	return kid
}

// --- tests: happy path ----------------------------------------------------

// submitBody is what clients POST to /v1/jobs in these tests.
type submitBody struct {
	Genome                 map[string]string `json:"genome"`
	DeadlineSecondsFromNow int               `json:"deadline_seconds_from_now,omitempty"`
}

func (b submitBody) marshal(t *testing.T) []byte {
	t.Helper()
	bs, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal submit body: %v", err)
	}
	return bs
}

// goodSubmit returns a body that names the fixture's sealed genome.
// Individual tests clone and mutate.
func (fx *testHTTPFixture) goodSubmit() submitBody {
	return submitBody{
		Genome:                 map[string]string{"bundle": fx.genome.Bundle, "key_file": fx.genome.KeyFile},
		DeadlineSecondsFromNow: 30,
	}
}

func (fx *testHTTPFixture) post(t *testing.T, body []byte) (*http.Response, []byte) {
	t.Helper()
	resp, err := fx.client.Post(fx.base+"/v1/jobs", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

func TestHTTPAPI_PostJobs_HappyPath(t *testing.T) {
	fx := newTestFixture(t, "")

	resp, body := fx.post(t, fx.goodSubmit().marshal(t))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d want 202 (body=%s)", resp.StatusCode, body)
	}
	var out submitResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.JobID == "" || !strings.HasPrefix(out.ManifestID, "rjm-") || !strings.HasPrefix(out.SessionID, "ses-") {
		t.Fatalf("response lacks identities: %+v", out)
	}
	if out.Genome.KeyID != fx.genome.KeyID || out.Genome.Fixtures != 3 || out.Genome.KeySource != "key_file" {
		t.Fatalf("genome view: %+v", out.Genome)
	}
	view, ok := fx.queue.Get(out.JobID)
	if !ok {
		t.Fatal("queue missing submitted job")
	}
	if view.Genome == nil || view.Genome.KeyID != fx.genome.KeyID || view.Gate != nil {
		t.Fatalf("queued view: %+v", view)
	}
	if spec := fx.queue.GateFor(out.JobID); spec == nil || len(spec.Fixtures) != 3 {
		t.Fatalf("the queued job has no gate to judge it: %+v", spec)
	}
	if view.ManifestID != out.ManifestID || view.ExpectedOutputKind != "bytes/fixed-length" {
		t.Fatalf("queued view identities: %+v", view)
	}
}

func TestHTTPAPI_GetJobByID_HappyPath(t *testing.T) {
	fx := newTestFixture(t, "")

	_, body := fx.post(t, fx.goodSubmit().marshal(t))
	var submitted submitResponse
	if err := json.Unmarshal(body, &submitted); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}

	resp, err := fx.client.Get(fx.base + "/v1/jobs/" + submitted.JobID)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d want 200 (body=%s)", resp.StatusCode, body)
	}
	var view JobView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	if view.ID != submitted.JobID {
		t.Fatalf("view.ID = %s want %s", view.ID, submitted.JobID)
	}
	if view.Status != JobStatusQueued {
		t.Fatalf("view.Status = %s", view.Status)
	}
	if view.Genome == nil || view.Genome.Bundle != fx.genome.Bundle {
		t.Fatalf("view.Genome = %+v", view.Genome)
	}
}

func TestHTTPAPI_GetJobByID_NotFound(t *testing.T) {
	fx := newTestFixture(t, "")
	resp, err := fx.client.Get(fx.base + "/v1/jobs/" + strings.Repeat("0", 32))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d want 404", resp.StatusCode)
	}
	env := decodeErrorEnvelope(t, resp.Body)
	if env.Error.Code != "job_not_found" {
		t.Fatalf("code = %s", env.Error.Code)
	}
}

// --- tests: validation ----------------------------------------------------

func TestHTTPAPI_PostJobs_RejectsWhatItCannotBuild(t *testing.T) {
	fx := newTestFixture(t, "")
	otherDir := t.TempDir()
	foreign := sealTestGenome(t, otherDir, genomeOptions{name: "foreign"})
	if err := os.Rename(filepath.Join(otherDir, foreign.KeyFile), filepath.Join(fx.dir, "foreign.key")); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		mut      func(*submitBody)
		status   int
		category string
		code     string
	}{
		{"no genome", func(b *submitBody) { b.Genome = nil }, 400, "structural", "required_field_missing"},
		{"no bundle", func(b *submitBody) { delete(b.Genome, "bundle") }, 400, "structural", "required_field_missing"},
		{"bundle is a path", func(b *submitBody) { b.Genome["bundle"] = "../" + fx.genome.Bundle }, 400, "structural", "field_value_invalid"},
		{"bundle absent", func(b *submitBody) { b.Genome["bundle"] = "absent.genome" }, 400, "structural", CodeGenomeNotFound},
		{"key absent", func(b *submitBody) { b.Genome["key_file"] = "absent.key" }, 400, "structural", CodeGenomeNotFound},
		{"wrong key", func(b *submitBody) { b.Genome["key_file"] = "foreign.key" }, 403, "authority", CodeGenomeKeyInvalid},
		{"no key and no escrow", func(b *submitBody) { delete(b.Genome, "key_file") }, 400, "structural", CodeGenomeNotFound},
		{"negative deadline", func(b *submitBody) { b.DeadlineSecondsFromNow = -1 }, 400, "structural", "field_value_invalid"},
		{"deadline above ceiling", func(b *submitBody) { b.DeadlineSecondsFromNow = 3600 }, 400, "structural", "deadline_exceeds_ceiling"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fx.goodSubmit()
			tc.mut(&body)
			resp, data := fx.post(t, body.marshal(t))
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d want %d (body=%s)", resp.StatusCode, tc.status, data)
			}
			env := decodeErrorEnvelope(t, bytes.NewReader(data))
			if env.Error.Category != tc.category || env.Error.Code != tc.code {
				t.Fatalf("error = %s/%s want %s/%s (%s)", env.Error.Category, env.Error.Code, tc.category, tc.code, env.Error.Message)
			}
		})
	}
	if got := fx.queue.Depth(); got != 0 {
		t.Fatalf("refused submissions enqueued work: depth %d", got)
	}
}

func TestHTTPAPI_PostJobs_RejectsUnknownFieldsAndOversizedBodies(t *testing.T) {
	fx := newTestFixture(t, "")
	resp, data := fx.post(t, []byte(`{"genome":{"bundle":"x.genome"},"payload_base64":"aGk="}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d want 400 (%s)", resp.StatusCode, data)
	}
	if env := decodeErrorEnvelope(t, bytes.NewReader(data)); env.Error.Code != "decode_body" {
		t.Fatalf("code = %s (want decode_body)", env.Error.Code)
	}
	resp, data = fx.post(t, []byte(`{"genome":{"bundle":"x.genome"}} {}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d want 400 (%s)", resp.StatusCode, data)
	}
	if env := decodeErrorEnvelope(t, bytes.NewReader(data)); env.Error.Code != "trailing_data" {
		t.Fatalf("code = %s (want trailing_data)", env.Error.Code)
	}
	huge := []byte(`{"genome":{"bundle":"` + strings.Repeat("a", maxSubmitBodyBytes) + `"}}`)
	resp, _ = fx.post(t, huge)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized body: status = %d want 400", resp.StatusCode)
	}
}

// A job is on the audit record before it is queued, under its own id;
// a log that cannot take it refuses the job.
func TestHTTPAPI_PostJobs_IsOnTheRecordFirst(t *testing.T) {
	fx := newTestFixture(t, "")
	_, body := fx.post(t, fx.goodSubmit().marshal(t))
	var out submitResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	events := fx.audit.chain.Events()
	if len(events) != 1 || events[0].Kind != "MANIFEST_ISSUED" || string(events[0].ManifestID) != out.ManifestID {
		t.Fatalf("audit log after one job: %+v", events)
	}
	var p jobAcceptedPayload
	if err := json.Unmarshal(events[0].Payload, &p); err != nil || p.JobID != out.JobID || p.GenomeID != fx.genome.KeyID {
		t.Fatalf("MANIFEST_ISSUED payload: %+v (%v)", p, err)
	}

	if err := fx.audit.Close(); err != nil {
		t.Fatal(err)
	}
	resp, data := fx.post(t, fx.goodSubmit().marshal(t))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d want 503 (%s)", resp.StatusCode, data)
	}
	if env := decodeErrorEnvelope(t, bytes.NewReader(data)); env.Error.Code != CodeAuditUnavailable {
		t.Fatalf("code = %s", env.Error.Code)
	}
	if got := fx.queue.Depth(); got != 1 {
		t.Fatalf("a job the log did not take was queued: depth %d", got)
	}
}

func TestHTTPAPI_RequiresTheAuditLogWithGateJobs(t *testing.T) {
	clock := shared_time.NewSystemClock()
	store := keys.NewInMemoryStore(clock)
	sealKID := testRegisterSealing(t, store)
	full := DefaultConfig()
	full.Genome.BundleDir = t.TempDir()
	genomes := newGenomeJobs(full, store, sealKID, clock)
	_, err := NewHTTPAPIServer(HTTPAPIConfig{}, full.Runtime, NewJobQueue(clock, time.Second), store, sealKID, genomes, nil, clock, metrics.NewRegistry(), nil)
	if err == nil {
		t.Fatal("gate jobs without an audit log were accepted")
	}
}

func TestHTTPAPI_PostJobs_GateJobsDisabledIs503(t *testing.T) {
	fx := newTestFixtureWith(t, "", false)
	resp, data := fx.post(t, fx.goodSubmit().marshal(t))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d want 503 (%s)", resp.StatusCode, data)
	}
	if env := decodeErrorEnvelope(t, bytes.NewReader(data)); env.Error.Code != CodeGateJobsDisabled {
		t.Fatalf("code = %s", env.Error.Code)
	}
}

// --- tests: method/path routing ------------------------------------------

func TestHTTPAPI_GetJobsCollection_405(t *testing.T) {
	fx := newTestFixture(t, "")
	resp, err := fx.client.Get(fx.base + "/v1/jobs")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != http.MethodPost {
		t.Fatalf("Allow = %q want POST", got)
	}
}

func TestHTTPAPI_PostJobByID_405(t *testing.T) {
	fx := newTestFixture(t, "")
	resp, err := fx.client.Post(fx.base+"/v1/jobs/someid",
		"application/json", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d want 405", resp.StatusCode)
	}
}

// --- tests: bearer auth --------------------------------------------------

func TestHTTPAPI_Auth_MissingCredsIs401(t *testing.T) {
	fx := newTestFixture(t, "top-secret-token")
	resp, err := fx.client.Post(fx.base+"/v1/jobs", "application/json",
		bytes.NewReader(fx.goodSubmit().marshal(t)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401", resp.StatusCode)
	}
	env := decodeErrorEnvelope(t, resp.Body)
	if env.Error.Code != "auth_missing" {
		t.Fatalf("code = %s", env.Error.Code)
	}
}

func TestHTTPAPI_Auth_WrongTokenIs401(t *testing.T) {
	fx := newTestFixture(t, "top-secret-token")
	req, _ := http.NewRequest("POST", fx.base+"/v1/jobs",
		bytes.NewReader(fx.goodSubmit().marshal(t)))
	req.Header.Set("Authorization", "Bearer wrong-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := fx.client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401", resp.StatusCode)
	}
	env := decodeErrorEnvelope(t, resp.Body)
	if env.Error.Code != "auth_invalid" {
		t.Fatalf("code = %s", env.Error.Code)
	}
}

func TestHTTPAPI_Auth_RightTokenAccepted(t *testing.T) {
	fx := newTestFixture(t, "top-secret-token")
	req, _ := http.NewRequest("POST", fx.base+"/v1/jobs",
		bytes.NewReader(fx.goodSubmit().marshal(t)))
	req.Header.Set("Authorization", "Bearer top-secret-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := fx.client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d want 202 (body=%s)", resp.StatusCode, body)
	}
}

func TestHTTPAPI_Auth_GetRequiresToo(t *testing.T) {
	fx := newTestFixture(t, "top-secret-token")
	resp, err := fx.client.Get(fx.base + "/v1/jobs/anything")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401 for unauthenticated GET", resp.StatusCode)
	}
}

// --- tests: server lifecycle ----------------------------------------------

func TestHTTPAPI_EmptyListenIsNoOp(t *testing.T) {
	cfg := HTTPAPIConfig{ListenAddress: ""}
	runtime := DefaultConfig().Runtime
	clock := shared_time.NewSystemClock()
	store := keys.NewInMemoryStore(clock)
	_ = testRegisterSealing(t, store)

	srv, err := NewHTTPAPIServer(cfg, runtime, NewJobQueue(clock, runtime.QueuePoll()),
		store, "test-sealing-kid-1", nil, nil, clock, metrics.NewRegistry(), nil)
	if err != nil {
		t.Fatalf("NewHTTPAPIServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start empty-listen: %v", err)
	}
	if addr := srv.Addr(); addr != "" {
		t.Fatalf("Addr on empty-listen server = %q want empty", addr)
	}
	if err := srv.Close(context.Background()); err != nil {
		t.Fatalf("Close empty-listen: %v", err)
	}
}

// --- shared helpers -------------------------------------------------------

type errorEnvelope struct {
	Error struct {
		Category string `json:"category"`
		Code     string `json:"code"`
		Message  string `json:"message"`
	} `json:"error"`
}

func decodeErrorEnvelope(t *testing.T, r io.Reader) errorEnvelope {
	t.Helper()
	var env errorEnvelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if env.Error.Category == "" || env.Error.Code == "" {
		t.Fatalf("error envelope missing category/code: %+v", env)
	}
	return env
}
