// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
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
}

// newTestFixture starts an HTTPAPIServer listening on 127.0.0.1:0
// (OS-assigned port) with the given bearer token. Empty token
// means auth is disabled.
func newTestFixture(t *testing.T, bearer string) *testHTTPFixture {
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
		MaxPayloadBytes:              64 * 1024,
	}
	srv, err := NewHTTPAPIServer(cfg, runtime, queue, store, sealKID, clock, registry, logger)
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
	ManifestID             string `json:"manifest_id"`
	SessionID              string `json:"session_id"`
	ExpectedOutputKind     string `json:"expected_output_kind"`
	ExpectedOutputMaxBytes uint64 `json:"expected_output_max_bytes"`
	DeadlineSecondsFromNow int    `json:"deadline_seconds_from_now,omitempty"`
	PayloadBase64          string `json:"payload_base64"`
}

func (b submitBody) marshal(t *testing.T) []byte {
	t.Helper()
	bs, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal submit body: %v", err)
	}
	return bs
}

// goodSubmit returns a body that passes validate() for happy-path
// tests. Individual tests clone and mutate.
func goodSubmit() submitBody {
	return submitBody{
		ManifestID:             "m-http-1",
		SessionID:              "s-http-1",
		ExpectedOutputKind:     "text/plain",
		ExpectedOutputMaxBytes: 1024,
		DeadlineSecondsFromNow: 30,
		PayloadBase64:          base64.StdEncoding.EncodeToString([]byte("hello vault")),
	}
}

func TestHTTPAPI_PostJobs_HappyPath(t *testing.T) {
	fx := newTestFixture(t, "")

	resp, err := fx.client.Post(fx.base+"/v1/jobs", "application/json",
		bytes.NewReader(goodSubmit().marshal(t)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d want 202 (body=%s)", resp.StatusCode, body)
	}
	var out submitResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.JobID == "" {
		t.Fatal("job_id empty")
	}
	if _, ok := fx.queue.Get(out.JobID); !ok {
		t.Fatal("queue missing submitted job")
	}
}

func TestHTTPAPI_GetJobByID_HappyPath(t *testing.T) {
	fx := newTestFixture(t, "")

	postResp, err := fx.client.Post(fx.base+"/v1/jobs", "application/json",
		bytes.NewReader(goodSubmit().marshal(t)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	var submitted submitResponse
	if err := json.NewDecoder(postResp.Body).Decode(&submitted); err != nil {
		t.Fatalf("decode: %v", err)
	}
	postResp.Body.Close()

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

func TestHTTPAPI_PostJobs_RejectsMissingFields(t *testing.T) {
	fx := newTestFixture(t, "")
	cases := []struct {
		name string
		mut  func(*submitBody)
	}{
		{"no manifest_id", func(b *submitBody) { b.ManifestID = "" }},
		{"no session_id", func(b *submitBody) { b.SessionID = "" }},
		{"no output kind", func(b *submitBody) { b.ExpectedOutputKind = "" }},
		{"zero max bytes", func(b *submitBody) { b.ExpectedOutputMaxBytes = 0 }},
		{"no payload", func(b *submitBody) { b.PayloadBase64 = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := goodSubmit()
			tc.mut(&body)
			resp, err := fx.client.Post(fx.base+"/v1/jobs", "application/json",
				bytes.NewReader(body.marshal(t)))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d want 400", resp.StatusCode)
			}
			env := decodeErrorEnvelope(t, resp.Body)
			if env.Error.Category != "structural" {
				t.Fatalf("category = %s want structural", env.Error.Category)
			}
		})
	}
}

func TestHTTPAPI_PostJobs_RejectsBadBase64(t *testing.T) {
	fx := newTestFixture(t, "")
	body := goodSubmit()
	body.PayloadBase64 = "not-valid-base64!!!"

	resp, err := fx.client.Post(fx.base+"/v1/jobs", "application/json",
		bytes.NewReader(body.marshal(t)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d want 400", resp.StatusCode)
	}
	env := decodeErrorEnvelope(t, resp.Body)
	if env.Error.Code != "payload_base64_invalid" {
		t.Fatalf("code = %s", env.Error.Code)
	}
}

func TestHTTPAPI_PostJobs_RejectsOversizedPayload(t *testing.T) {
	fx := newTestFixture(t, "")
	body := goodSubmit()
	// Fixture MaxPayloadBytes=64 KiB. We want the decoded bytes to
	// exceed that, but the raw JSON body to remain below the
	// server's JSON ceiling (MaxPayloadBytes*4/3 + 16 KiB ≈ 101 KiB)
	// so the request reaches the post-decode length check instead of
	// tripping http.MaxBytesReader. 70 KiB plaintext → ~93 KiB of
	// base64 → ~94 KiB of JSON body — comfortably under the ceiling,
	// comfortably over the plaintext cap.
	big := make([]byte, 70*1024)
	body.PayloadBase64 = base64.StdEncoding.EncodeToString(big)

	resp, err := fx.client.Post(fx.base+"/v1/jobs", "application/json",
		bytes.NewReader(body.marshal(t)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d want 413", resp.StatusCode)
	}
}

func TestHTTPAPI_PostJobs_RejectsDeadlineAboveCeiling(t *testing.T) {
	fx := newTestFixture(t, "")
	body := goodSubmit()
	// Fixture DefaultJobDeadlineSeconds=60.
	body.DeadlineSecondsFromNow = 3600

	resp, err := fx.client.Post(fx.base+"/v1/jobs", "application/json",
		bytes.NewReader(body.marshal(t)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d want 400", resp.StatusCode)
	}
	env := decodeErrorEnvelope(t, resp.Body)
	if env.Error.Code != "deadline_exceeds_ceiling" {
		t.Fatalf("code = %s", env.Error.Code)
	}
}

func TestHTTPAPI_PostJobs_RejectsUnknownFields(t *testing.T) {
	fx := newTestFixture(t, "")
	raw := []byte(`{"manifest_id":"m","session_id":"s","expected_output_kind":"k",
		"expected_output_max_bytes":1,"payload_base64":"aGk=",
		"typo_field":"x"}`)

	resp, err := fx.client.Post(fx.base+"/v1/jobs", "application/json",
		bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d want 400", resp.StatusCode)
	}
	env := decodeErrorEnvelope(t, resp.Body)
	if env.Error.Code != "decode_body" {
		t.Fatalf("code = %s (want decode_body)", env.Error.Code)
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
		bytes.NewReader(goodSubmit().marshal(t)))
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
		bytes.NewReader(goodSubmit().marshal(t)))
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
		bytes.NewReader(goodSubmit().marshal(t)))
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
		store, "test-sealing-kid-1", clock, metrics.NewRegistry(), nil)
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
