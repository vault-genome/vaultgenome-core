//go:build integration

// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	workerSigningKID = "acp-compute-worker-demo"
	vaultDescriptor  = "sagvd-phase1-demo-v1"
	workerDescriptor = "acp-compute-phase1-demo-v1"
	jobOutputKind    = "lora-adapter-demo"

	startupTimeout = 30 * time.Second
	jobTimeout     = 60 * time.Second
)

// bins holds the binaries TestMain builds once per run.
var bins struct {
	sagvd, worker, bootstrap, acpctl, keygen string
}

func TestMain(m *testing.M) {
	code, err := buildAndRun(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func buildAndRun(m *testing.M) (int, error) {
	root, err := moduleRoot()
	if err != nil {
		return 0, err
	}
	dir, err := os.MkdirTemp("", "acp-integration-bin-")
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	bins.sagvd = filepath.Join(dir, "sagvd")
	bins.worker = filepath.Join(dir, "acp-compute")
	bins.bootstrap = filepath.Join(dir, "acp-bootstrap")
	bins.acpctl = filepath.Join(dir, "acpctl")
	bins.keygen = filepath.Join(dir, "keygen")
	for _, b := range []struct{ out, dir, pkg string }{
		{bins.sagvd, root, "./cmd/sagvd"},
		{bins.worker, root, "./cmd/acp-compute"},
		{bins.bootstrap, root, "./cmd/acp-bootstrap"},
		{bins.acpctl, root, "./cmd/acpctl"},
		{bins.keygen, filepath.Join(root, "deploy", "compose", "keygen"), "."},
	} {
		cmd := exec.Command("go", "build", "-o", b.out, b.pkg)
		cmd.Dir = b.dir
		if out, err := cmd.CombinedOutput(); err != nil {
			return 0, fmt.Errorf("go build %s: %w\n%s", b.pkg, err, out)
		}
	}
	return m.Run(), nil
}

// moduleRoot walks up from the working directory to the core module root.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && bytes.HasPrefix(data, []byte("module github.com/ai-continuity-platform/core\n")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("core module root not found above working directory")
		}
		dir = parent
	}
}

// ---- tests ------------------------------------------------------------------

// A job submitted over the authenticated REST API is sealed, dispatched
// over mutual TLS to a worker that proves its pinned TEE identity, and
// comes back as a worker-signed result.
func TestLiveDaemons_JobRoundTripOverMTLS(t *testing.T) {
	secrets := keygen(t)
	v := startVault(t, secrets)
	w, health := v.startWorker(t, "acp-compute", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	waitReady(t, w, health+"/healthz")

	job := v.waitJob(t, v.submitJob(t), "succeeded", jobTimeout)
	if job.Result == nil || job.Result.ByteCount == 0 {
		t.Fatalf("succeeded job carries no result: %+v", job)
	}
	if job.Result.WorkerSigningKeyID != workerSigningKID {
		t.Fatalf("result signed by %q, want %q", job.Result.WorkerSigningKeyID, workerSigningKID)
	}
	if job.Result.OutputKind != jobOutputKind {
		t.Fatalf("output kind %q, want %q", job.Result.OutputKind, jobOutputKind)
	}
	if raw, err := hex.DecodeString(job.Result.BytesHex); err != nil || len(raw) != job.Result.ByteCount {
		t.Fatalf("result bytes_hex inconsistent with byte_count=%d (decode err %v)", job.Result.ByteCount, err)
	}
	if got := v.counter(t, `sagvd_jobs_completed_total{outcome="success"}`); got < 1 {
		t.Fatalf("sagvd_jobs_completed_total{outcome=\"success\"} = %d, want >= 1", got)
	}
	if got := v.counter(t, `sagvd_sessions_opened_total`); got < 1 {
		t.Fatalf("sagvd_sessions_opened_total = %d, want >= 1", got)
	}
}

// The REST API refuses callers without the bearer token or with a wrong
// one, on both the write and the read endpoint.
func TestLiveDaemons_RESTRejectsMissingOrWrongToken(t *testing.T) {
	v := startVault(t, keygen(t))
	body := jobBody(t)
	for _, tc := range []struct {
		name, token, wantCode string
	}{
		{"missing token", "", "auth_missing"},
		{"wrong token", strings.Repeat("0", 64), "auth_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, resp := v.do(t, http.MethodPost, "/v1/jobs", tc.token, body)
			if status != http.StatusUnauthorized || !bytes.Contains(resp, []byte(tc.wantCode)) {
				t.Fatalf("POST /v1/jobs: status %d body %s, want 401 %s", status, resp, tc.wantCode)
			}
			if status, resp = v.do(t, http.MethodGet, "/v1/jobs/any-id", tc.token, nil); status != http.StatusUnauthorized {
				t.Fatalf("GET /v1/jobs/{id}: status %d body %s, want 401", status, resp)
			}
		})
	}
	if got := v.counter(t, `sagvd_jobs_submitted_total`); got != 0 {
		t.Fatalf("unauthenticated requests enqueued work: sagvd_jobs_submitted_total = %d", got)
	}
}

// The Return Path completes a TLS session only for a client certificate
// issued by the deployment CA; the server counts every refusal.
func TestLiveDaemons_ReturnPathRequiresTrustedClientCert(t *testing.T) {
	secrets := keygen(t)
	v := startVault(t, secrets)
	roots := certPool(t, filepath.Join(secrets, "shared", "tls", "ca.crt"))
	foreign := keygen(t) // an independent CA the vault does not trust
	foreignPair, err := tls.LoadX509KeyPair(
		filepath.Join(foreign, "acp-compute", "tls", "client.crt"),
		filepath.Join(foreign, "acp-compute", "tls", "client.key"))
	if err != nil {
		t.Fatal(err)
	}

	before := v.counter(t, `sagvd_handshake_failures_total{phase="tls"}`)
	for _, tc := range []struct {
		name  string
		certs []tls.Certificate
	}{
		{"no client certificate", nil},
		{"client certificate from a foreign CA", []tls.Certificate{foreignPair}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tlsProbe(v.vaultAddr, &tls.Config{
				RootCAs: roots, ServerName: "localhost", Certificates: tc.certs, MinVersion: tls.VersionTLS13,
			})
			var ne net.Error
			if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
				t.Fatalf("Return Path accepted the TLS session (err=%v)", err)
			}
		})
	}
	waitFor(t, 5*time.Second, "server-side TLS refusals counted", func() bool {
		return v.counter(t, `sagvd_handshake_failures_total{phase="tls"}`) >= before+2
	})
}

// A worker holding a valid mTLS client certificate and the session
// sealing key — but not the pinned TEE key — is refused at the Return
// Path handshake and never handed work. The job is held, not lost: the
// pinned worker receives it afterwards.
func TestLiveDaemons_UnpinnedWorkerIsRefusedWork(t *testing.T) {
	secrets := keygen(t)
	rogueTEE := keygen(t)
	v := startVault(t, secrets)

	rogue, rogueHealth := v.startWorker(t, "rogue-worker", workerIdentity{tlsFrom: secrets, teeFrom: rogueTEE})
	waitReady(t, rogue, rogueHealth+"/healthz")

	before := v.counter(t, `sagvd_handshake_failures_total{phase="handshake"}`)
	id := v.submitJob(t)
	waitFor(t, 20*time.Second, "rogue worker refused at the Return Path handshake", func() bool {
		return v.counter(t, `sagvd_handshake_failures_total{phase="handshake"}`) > before
	})
	if job := v.job(t, id); job.Status != "queued" {
		t.Fatalf("job reached %q while only an unpinned worker was connected, want queued", job.Status)
	}
	if got := v.counter(t, `sagvd_sessions_opened_total`); got != 0 {
		t.Fatalf("a Return Path session opened for the unpinned worker (sessions_opened_total = %d)", got)
	}

	w, health := v.startWorker(t, "acp-compute", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	waitReady(t, w, health+"/healthz")
	job := v.waitJob(t, id, "succeeded", jobTimeout)
	if job.Result == nil || job.Result.WorkerSigningKeyID != workerSigningKID {
		t.Fatalf("held job not delivered by the pinned worker: %+v", job)
	}
}

// Both daemons honour SIGTERM promptly while a Return Path session is
// open and idle — the state in which the worker sits blocked reading the
// next JobRequest. net.Conn reads do not observe context cancellation, so
// without the context-bound connection close the worker ignored SIGTERM
// in this state until the job deadline.
func TestLiveDaemons_ShutdownIsPromptWhileSessionIdle(t *testing.T) {
	secrets := keygen(t)
	v := startVault(t, secrets)
	w, health := v.startWorker(t, "acp-compute", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	waitReady(t, w, health+"/healthz")
	waitFor(t, 20*time.Second, "worker idle in an open Return Path session", func() bool {
		return v.counter(t, `sagvd_sessions_opened_total`) >= 1
	})
	for _, p := range []*proc{w, v.proc} {
		if took, killed := p.stop(); killed || took > 5*time.Second {
			t.Fatalf("%s took %s to honour SIGTERM (killed=%v), want < 5s",
				p.name, took.Round(time.Millisecond), killed)
		}
	}
}

// sagvd refuses to start when a listener reachable from the network
// would be unauthenticated. The check runs before any socket is bound.
func TestSagvd_RefusesUnauthenticatedNetworkExposure(t *testing.T) {
	secrets := keygen(t)
	for _, tc := range []struct {
		name   string
		mutate func(cfg map[string]any)
		want   string
	}{
		{
			name: "plaintext Return Path on all interfaces",
			mutate: func(cfg map[string]any) {
				vault := cfg["vault"].(map[string]any)
				vault["listen_address"] = fmt.Sprintf("0.0.0.0:%d", freePort(t))
				vault["tls"] = map[string]any{"enabled": false}
			},
			want: "vault.tls.enabled required",
		},
		{
			name: "REST API without a token on all interfaces",
			mutate: func(cfg map[string]any) {
				api := cfg["http_api"].(map[string]any)
				api["listen_address"] = fmt.Sprintf("0.0.0.0:%d", freePort(t))
				delete(api, "bearer_token_file")
			},
			want: "bearer_token or bearer_token_file required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := vaultConfig(secrets, loopback(t), loopback(t), loopback(t))
			tc.mutate(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, bins.sagvd, "-config", writeJSON(t, "sagvd.json", cfg)).CombinedOutput()
			if err == nil || ctx.Err() != nil {
				t.Fatalf("sagvd did not refuse the config (err=%v, ctx=%v)\n%s", err, ctx.Err(), out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("refusal does not name the problem %q:\n%s", tc.want, out)
			}
		})
	}
}

// ---- deployment helpers -----------------------------------------------------

// keygen provisions a fresh secrets tree (seeds, sealing key, mTLS PKI,
// API token) with the real deploy/compose/keygen binary.
func keygen(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "secrets")
	if b, err := exec.Command(bins.keygen, "-out", out, "-quiet").CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, b)
	}
	return out
}

// vault is one running sagvd plus the addresses to reach it.
type vault struct {
	secrets   string
	token     string
	vaultAddr string
	apiURL    string
	healthURL string
	proc      *proc
}

func vaultConfig(secrets, vaultAddr, apiAddr, healthAddr string) map[string]any {
	sec := func(p ...string) string { return filepath.Join(append([]string{secrets}, p...)...) }
	return map[string]any{
		"vault": map[string]any{
			"listen_address": vaultAddr,
			"tls": map[string]any{
				"enabled":     true,
				"server_cert": sec("sagvd", "tls", "server.crt"),
				"server_key":  sec("sagvd", "tls", "server.key"),
				"client_cas":  sec("shared", "tls", "ca.crt"),
			},
		},
		"http_api": map[string]any{
			"listen_address":    apiAddr,
			"bearer_token_file": sec("sagvd", "api_token"),
		},
		"tee": map[string]any{
			"workload_descriptor": vaultDescriptor,
			"seed_path":           sec("sagvd", "tee_seed"),
			"peer": map[string]any{
				"public_key_path":  sec("sagvd", "peer_worker_pubkey"),
				"measurement_path": sec("sagvd", "peer_worker_measurement"),
			},
		},
		"keys": map[string]any{
			"authority_signing": map[string]any{"kid": "sagvd-authority-demo", "seed_path": sec("sagvd", "authority_signing_seed")},
			"audit_signing":     map[string]any{"kid": "sagvd-audit-demo", "seed_path": sec("sagvd", "audit_signing_seed")},
			"session_sealing":   map[string]any{"kid": "session-sealing-demo", "material_path": sec("shared", "sealing.key")},
		},
		"workers": map[string]any{"registry_path": sec("shared", "workers.json")},
		"runtime": map[string]any{
			"job_timeout_seconds":              60,
			"handshake_timeout_seconds":        10,
			"queue_poll_ms":                    50,
			"http_read_header_timeout_seconds": 5,
			"http_write_timeout_seconds":       30,
			"default_job_deadline_seconds":     60,
			"max_payload_bytes":                4 << 20,
		},
		"health": map[string]any{"listen_address": healthAddr},
		"log":    map[string]any{"level": "debug", "format": "json"},
	}
}

// startVault runs sagvd with mTLS on the Return Path and a bearer token
// on the REST API, on loopback, and waits for /readyz.
func startVault(t *testing.T, secrets string) *vault {
	t.Helper()
	tok, err := os.ReadFile(filepath.Join(secrets, "sagvd", "api_token"))
	if err != nil {
		t.Fatal(err)
	}
	vaultAddr, apiAddr, healthAddr := loopback(t), loopback(t), loopback(t)
	v := &vault{
		secrets:   secrets,
		token:     strings.TrimSpace(string(tok)),
		vaultAddr: vaultAddr,
		apiURL:    "http://" + apiAddr,
		healthURL: "http://" + healthAddr,
	}
	cfg := writeJSON(t, "sagvd.json", vaultConfig(secrets, vaultAddr, apiAddr, healthAddr))
	v.proc = startProc(t, "sagvd", bins.sagvd, "-config", cfg)
	waitReady(t, v.proc, v.healthURL+"/readyz")
	return v
}

// workerIdentity chooses where a worker's credentials come from, so a
// test can combine a legitimate mTLS certificate with a foreign TEE key.
type workerIdentity struct {
	tlsFrom string // secrets tree providing the mTLS client certificate
	teeFrom string // secrets tree providing the TEE seed and signing seed
}

// startWorker runs acp-compute against v. The worker always trusts v's
// CA, pins v's TEE key and measurement, and holds v's session sealing
// key; id picks its own client certificate and TEE identity. It returns
// the process and the worker's health base URL.
func (v *vault) startWorker(t *testing.T, name string, id workerIdentity) (*proc, string) {
	t.Helper()
	healthAddr := loopback(t)
	cfg := map[string]any{
		"vault": map[string]any{
			"address": v.vaultAddr,
			"tls": map[string]any{
				"enabled":     true,
				"client_cert": filepath.Join(id.tlsFrom, "acp-compute", "tls", "client.crt"),
				"client_key":  filepath.Join(id.tlsFrom, "acp-compute", "tls", "client.key"),
				"ca_bundle":   filepath.Join(v.secrets, "shared", "tls", "ca.crt"),
				"server_name": "localhost",
			},
		},
		"tee": map[string]any{
			"workload_descriptor": workerDescriptor,
			"seed_path":           filepath.Join(id.teeFrom, "acp-compute", "tee_seed"),
			"peer": map[string]any{
				"public_key_path":  filepath.Join(v.secrets, "acp-compute", "peer_vault_pubkey"),
				"measurement_path": filepath.Join(v.secrets, "acp-compute", "peer_vault_measurement"),
			},
		},
		"keys": map[string]any{
			"worker_signing":  map[string]any{"kid": workerSigningKID, "seed_path": filepath.Join(id.teeFrom, "acp-compute", "worker_signing_seed")},
			"session_sealing": map[string]any{"kid": "session-sealing-demo", "material_path": filepath.Join(v.secrets, "shared", "sealing.key")},
		},
		"runtime": map[string]any{
			"job_timeout_seconds":       60,
			"handshake_timeout_seconds": 10,
			"dial_backoff_initial_ms":   100,
			"dial_backoff_max_ms":       1000,
			"idle_between_jobs_ms":      50,
		},
		"health": map[string]any{"listen_address": healthAddr},
		"log":    map[string]any{"level": "debug", "format": "json"},
	}
	p := startProc(t, name, bins.worker, "-config", writeJSON(t, name+".json", cfg))
	return p, "http://" + healthAddr
}

// ---- REST helpers -----------------------------------------------------------

type jobView struct {
	ID     string `json:"job_id"`
	Status string `json:"status"`
	Result *struct {
		OutputKind         string `json:"output_kind"`
		BytesHex           string `json:"bytes_hex"`
		ByteCount          int    `json:"byte_count"`
		WorkerSigningKeyID string `json:"worker_signing_key_id"`
	} `json:"result"`
	Error *struct {
		Category string `json:"category"`
		Code     string `json:"code"`
		Message  string `json:"message"`
	} `json:"error"`
}

func jobBody(t *testing.T) []byte {
	t.Helper()
	payload := make([]byte, 1024)
	nonce := make([]byte, 8)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{
		"manifest_id":               "it-manifest-" + hex.EncodeToString(nonce),
		"session_id":                "it-session-" + hex.EncodeToString(nonce),
		"expected_output_kind":      jobOutputKind,
		"expected_output_max_bytes": 4096,
		"deadline_seconds_from_now": 60,
		"payload_base64":            base64.StdEncoding.EncodeToString(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// do sends one REST request; an empty token sends no Authorization header.
func (v *vault) do(t *testing.T, method, path, token string, body []byte) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, v.apiURL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func (v *vault) submitJob(t *testing.T) string {
	t.Helper()
	status, body := v.do(t, http.MethodPost, "/v1/jobs", v.token, jobBody(t))
	if status != http.StatusAccepted {
		t.Fatalf("POST /v1/jobs: status %d body %s, want 202", status, body)
	}
	var r struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.JobID == "" {
		t.Fatalf("POST /v1/jobs: no job_id in %s (%v)", body, err)
	}
	return r.JobID
}

func (v *vault) job(t *testing.T, id string) jobView {
	t.Helper()
	status, body := v.do(t, http.MethodGet, "/v1/jobs/"+id, v.token, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /v1/jobs/%s: status %d body %s", id, status, body)
	}
	var j jobView
	if err := json.Unmarshal(body, &j); err != nil {
		t.Fatalf("decode job view: %v (%s)", err, body)
	}
	return j
}

// waitJob polls until the job reaches want, failing fast if it lands in
// a different terminal state.
func (v *vault) waitJob(t *testing.T, id, want string, timeout time.Duration) jobView {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		j := v.job(t, id)
		switch {
		case j.Status == want:
			return j
		case j.Status == "succeeded" || j.Status == "failed":
			t.Fatalf("job %s reached %q, want %q: %+v", id, j.Status, want, j)
		case time.Now().After(deadline):
			t.Fatalf("job %s still %q after %s, want %q", id, j.Status, timeout, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// counter reads one series from sagvd's Prometheus exposition; an absent
// series reads as zero.
func (v *vault) counter(t *testing.T, series string) uint64 {
	t.Helper()
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(v.healthURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), series+" "); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(rest), 10, 64)
			if err != nil {
				t.Fatalf("parse %s: %v", series, err)
			}
			return n
		}
	}
	return 0
}

// ---- TLS helpers ------------------------------------------------------------

func certPool(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("no certificates in %s", path)
	}
	return pool
}

// tlsProbe completes a client handshake and one read. Under TLS 1.3 the
// server's client-authentication verdict arrives after the client
// finishes its side of the handshake, so a refusal surfaces on the first
// read as a TLS alert. A read timeout means the server accepted the
// session and is waiting for the Return Path handshake.
func tlsProbe(addr string, cfg *tls.Config) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	return err
}

// ---- process helpers --------------------------------------------------------

// proc is one running daemon with its combined output captured.
type proc struct {
	name   string
	cmd    *exec.Cmd
	log    *syncBuffer
	exited chan struct{}
	err    error // set before exited is closed
}

func startProc(t *testing.T, name, bin string, args ...string) *proc {
	t.Helper()
	p := &proc{name: name, log: &syncBuffer{}, exited: make(chan struct{})}
	p.cmd = exec.Command(bin, args...)
	p.cmd.Stdout = p.log
	p.cmd.Stderr = p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.exited)
	}()
	t.Cleanup(func() {
		// Every daemon must honour SIGTERM: orchestrators (compose,
		// Kubernetes) send it and escalate to SIGKILL on a timeout.
		if took, killed := p.stop(); killed {
			t.Errorf("%s ignored SIGTERM for %s and had to be killed", p.name, took.Round(time.Millisecond))
		}
		if t.Failed() {
			t.Logf("---- %s output ----\n%s", p.name, p.log.String())
		}
	})
	return p
}

// stop sends SIGTERM (the daemons' graceful-shutdown path) and escalates
// to SIGKILL after 10 s. It reports how long the process took to exit and
// whether it had to be killed.
func (p *proc) stop() (time.Duration, bool) {
	select {
	case <-p.exited:
		return 0, false
	default:
	}
	start := time.Now()
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.exited:
		return time.Since(start), false
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.exited
		return time.Since(start), true
	}
}

// waitReady polls url until it answers 200, failing fast if p exits.
func waitReady(t *testing.T, p *proc, url string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(startupTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-p.exited:
			t.Fatalf("%s exited before %s answered: %v\n%s", p.name, url, p.err, p.log.String())
		default:
		}
		if resp, err := client.Get(url); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s: %s not ready within %s\n%s", p.name, url, startupTimeout, p.log.String())
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for: %s", timeout, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// loopback reserves a free 127.0.0.1 port and returns host:port.
func loopback(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("127.0.0.1:%d", freePort(t))
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func writeJSON(t *testing.T, name string, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// syncBuffer is a goroutine-safe io.Writer collecting process output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
