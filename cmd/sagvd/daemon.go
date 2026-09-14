// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/ai-continuity-platform/core/internal/compute/returnpath/server"
	"github.com/ai-continuity-platform/core/internal/compute/returnpath/transport"
	"github.com/ai-continuity-platform/core/internal/observability/health"
	"github.com/ai-continuity-platform/core/internal/observability/metrics"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
)

// Daemon is the sagvd runtime: a long-lived process that binds a
// Return Path listener, accepts acp-compute connections, pops one
// job off the JobQueue per accepted session, and drives the
// 4-frame handshake + one JobRequest + one CandidateOutput cycle to
// completion.
//
// Lifecycle mirrors cmd/acp-compute's Daemon:
//
//	d, err := NewDaemon(cfg, materials, queue, clock, logger, registry)
//	...
//	go d.Run(ctx)   // blocks until ctx is cancelled
//	<-ctx.Done()
//	d.Shutdown()    // flips health flags, closes listener
//	d.Zeroize()     // wipes the in-memory keystore (terminal)
//
// Concurrency model: Phase 1 is single-worker at the dispatcher.
// The accept goroutine hands each accepted net.Conn into the
// dispatcher, which runs one session to completion before accepting
// the next. Multiple workers may *connect* concurrently — only one
// gets the current job; the others wait. Phase 2 introduces a
// bounded pool when multi-tenant parallelism lands.
type Daemon struct {
	cfg       Config
	mat       *materials
	queue     *JobQueue
	clock     shared_time.Clock
	log       *slog.Logger
	tlsConfig *tls.Config

	health  *health.State
	metrics *daemonMetrics

	// listener is the TCP (or TLS-wrapped TCP) listener the
	// dispatcher accepts on. nil until Run has bound it.
	listener net.Listener
}

// daemonMetrics bundles the sagvd_* counters / gauges owned by the
// dispatcher side. The HTTP API owns jobs_submitted_total separately
// (via httpMetrics) because it is bumped on the POST path, never by
// the dispatcher. Both bundles share the same metrics.Registry and
// are exposed together on /metrics.
type daemonMetrics struct {
	jobsCompleted    *metrics.Counter // labels: outcome={success|reject|fail}
	sessionsOpened   *metrics.Counter // unlabeled
	handshakeFailure *metrics.Counter // labels: phase
	queueDepth       *metrics.Gauge   // set on every dispatcher tick
	lastSuccessUnix  *metrics.Gauge
	startUnix        *metrics.Gauge
}

// NewDaemon wires every piece the daemon needs. cfg is expected to
// have already been validated; mat was produced by LoadMaterials;
// queue is shared with the HTTP API so submissions flow in and
// results flow out atomically.
func NewDaemon(
	cfg Config,
	mat *materials,
	queue *JobQueue,
	clock shared_time.Clock,
	logger *slog.Logger,
	registry *metrics.Registry,
) (*Daemon, error) {
	if cfg.Vault.ListenAddress == "" {
		return nil, errors.New("sagvd: Daemon requires vault.listen_address")
	}
	if mat == nil {
		return nil, errors.New("sagvd: Daemon requires non-nil materials")
	}
	if queue == nil {
		return nil, errors.New("sagvd: Daemon requires non-nil JobQueue")
	}
	if clock == nil {
		return nil, errors.New("sagvd: Daemon requires non-nil clock")
	}
	if registry == nil {
		return nil, errors.New("sagvd: Daemon requires non-nil metrics.Registry")
	}
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}

	var tlsConfig *tls.Config
	if cfg.Vault.TLS.Enabled {
		tc, err := loadServerTLS(cfg.Vault.TLS)
		if err != nil {
			return nil, err
		}
		tlsConfig = tc
	}

	return &Daemon{
		cfg:       cfg,
		mat:       mat,
		queue:     queue,
		clock:     clock,
		log:       logger,
		tlsConfig: tlsConfig,
		health:    health.NewState(),
		metrics:   registerDaemonMetrics(registry, clock),
	}, nil
}

// Health returns the underlying health.State so the caller can pass
// it to health.NewServer.
func (d *Daemon) Health() *health.State { return d.health }

// Metrics exposes the daemon's metric bundle so the HTTP API can
// bump jobs_submitted_total without importing metric names twice.
// The returned pointer is aliased; callers must not construct new
// metrics through it.
func (d *Daemon) Metrics() *daemonMetrics { return d.metrics }

// Addr returns the bound listener address (useful in tests where
// cfg.Vault.ListenAddress ends in :0). Returns the configured
// address verbatim before Run binds it.
func (d *Daemon) Addr() string {
	if d.listener == nil {
		return d.cfg.Vault.ListenAddress
	}
	return d.listener.Addr().String()
}

// Run binds the Return Path listener and enters the accept /
// dispatch loop. Blocks until ctx is cancelled; on cancellation the
// listener is closed (unblocking Accept) and Run returns nil.
//
// On a bind failure Run returns the error without flipping health
// flags — the caller can report it and exit.
func (d *Daemon) Run(ctx context.Context) error {
	ln, err := d.listen()
	if err != nil {
		return err
	}
	d.listener = ln
	d.log.Info("sagvd return-path listener bound", "address", ln.Addr().String(),
		"tls_enabled", d.cfg.Vault.TLS.Enabled)
	d.health.MarkReady()

	// Close the listener when ctx fires so a blocked Accept returns.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Non-terminal accept errors (temporary: true) are
			// briefly backed off so a burst of bad peers can't
			// spin the CPU.
			d.log.Warn("sagvd accept error", "err", err)
			if !sleepContext(ctx, 250*time.Millisecond) {
				return nil
			}
			continue
		}
		d.serveOne(ctx, conn)
	}
}

// Shutdown flips health flags so orchestrator probes start failing
// before the listener is torn down. Closing the listener itself is
// handled by Run's ctx.Done hook.
func (d *Daemon) Shutdown() {
	d.health.MarkDown()
}

// Zeroize wipes the in-memory keystore. Call only after Run has
// returned; afterwards the daemon is unusable.
func (d *Daemon) Zeroize() {
	if d.mat != nil && d.mat.Store != nil {
		d.mat.Store.Zeroize()
	}
}

// ---- session dispatch ----------------------------------------------------

// serveOne runs exactly one Return Path session end-to-end:
//  1. TLS-wrap the raw conn (if TLS is enabled)
//  2. server.Accept the 4-frame handshake
//  3. queue.Next — block until a job is available or ctx is done
//  4. sess.ServeOneJob — deliver JobRequest, await CandidateOutput
//  5. queue.CompleteSuccess / CompleteFailure
//  6. sess.WriteShutdown + sess.Close
//
// Any error is logged with its classification; the connection is
// always closed before return so fd-leak is impossible.
func (d *Daemon) serveOne(parent context.Context, raw net.Conn) {
	// Close the connection when the daemon shuts down. net.Conn I/O does
	// not observe context cancellation, and Run serves connections
	// inline, so a session blocked on its worker would otherwise hold
	// shutdown until the job deadline.
	stopOnShutdown := context.AfterFunc(parent, func() { _ = raw.Close() })
	defer stopOnShutdown()

	// Wrap TLS first if configured; a failed TLS handshake is
	// Operational (peer never authenticated).
	var conn net.Conn = raw
	if d.tlsConfig != nil {
		tlsConn := tls.Server(raw, d.tlsConfig)
		handshakeCtx, cancel := context.WithTimeout(parent,
			d.cfg.Runtime.HandshakeTimeout())
		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			cancel()
			_ = raw.Close()
			d.metrics.handshakeFailure.Inc(
				metrics.Label{Name: "phase", Value: "tls"},
			)
			d.log.Warn("sagvd TLS handshake failed",
				"remote_addr", raw.RemoteAddr().String(),
				"err", err)
			return
		}
		cancel()
		conn = tlsConn
	}

	// 4-frame Return Path handshake. On failure the net.Conn is
	// left open by server.Accept (matches the transport contract);
	// we close it explicitly on every error path below.
	sess, err := server.Accept(server.SessionConfig{
		Conn:              conn,
		Producer:          d.mat.Producer,
		Verifier:          d.mat.Verifier,
		Clock:             d.clock,
		WorkerKeyResolver: d.mat.WorkerResolver,
		HandshakeTimeout:  d.cfg.Runtime.HandshakeTimeout(),
		OnSessionOpened: func(state *transport.SessionState) {
			d.metrics.sessionsOpened.Inc()
			d.log.Info("sagvd session opened",
				"remote_addr", conn.RemoteAddr().String(),
				"peer_measurement", hex.EncodeToString(state.PeerMeasurement[:]),
				"ready_at", state.ReadyAt.Format(time.RFC3339Nano),
			)
		},
		OnIntegrityFailure: func(ihErr error) {
			d.log.Error("sagvd integrity failure on wire",
				"code", shared_errors.CodeOf(ihErr),
				"err", ihErr)
		},
		OnWorkerSignatureFailure: func(frame transport.CandidateOutputFrame, sigErr error) {
			d.log.Error("sagvd worker signature verification failed",
				"manifest_id", frame.ManifestID,
				"session_id", frame.SessionID,
				"worker_kid", frame.WorkerSigningKeyID,
				"err", sigErr)
		},
		OnSessionClosed: func(reason string) {
			d.log.Debug("sagvd session closed", "reason", reason)
		},
	})
	if err != nil {
		_ = conn.Close()
		d.metrics.handshakeFailure.Inc(
			metrics.Label{Name: "phase", Value: "handshake"},
		)
		d.log.Warn("sagvd return-path handshake failed",
			"remote_addr", conn.RemoteAddr().String(),
			"code", shared_errors.CodeOf(err),
			"err", err)
		return
	}
	defer func() { _ = sess.Close() }()

	// Bound the whole job cycle (Next + ServeOneJob) by JobTimeout.
	sessCtx, cancel := context.WithTimeout(parent, d.cfg.Runtime.JobTimeout())
	defer cancel()

	// Wait for the next queued job. If the context is cancelled
	// while we wait, close the session cleanly.
	jobID, req, err := d.queue.Next(sessCtx)
	if err != nil {
		_ = sess.WriteShutdown(transport.CodeShutdownNormal, "sagvd: no work pending")
		return
	}
	d.metrics.queueDepth.Set(float64(d.queue.Depth()))

	d.log.Info("sagvd dispatching job",
		"job_id", jobID,
		"manifest_id", req.ManifestID,
		"session_id", req.SessionID,
	)

	verified, err := sess.ServeOneJobVerified(sessCtx, req)
	if err != nil {
		d.queue.CompleteFailure(jobID, err)
		d.metrics.jobsCompleted.Inc(
			metrics.Label{Name: "outcome", Value: outcomeFromError(err)},
		)
		_ = sess.WriteShutdown(shared_errors.CodeOf(err), "sagvd: job failed")
		d.log.Warn("sagvd job failed",
			"job_id", jobID,
			"category", shared_errors.CategoryOf(err).String(),
			"code", shared_errors.CodeOf(err),
			"err", err,
		)
		return
	}

	// The worker signing key ID is the one the session verified the
	// CandidateOutputFrame signature under, so it is recorded as the
	// authenticated provenance of the result.
	out := verified.Output
	d.queue.CompleteSuccess(jobID, out, string(verified.WorkerSigningKeyID))
	d.metrics.jobsCompleted.Inc(metrics.Label{Name: "outcome", Value: "success"})
	d.metrics.lastSuccessUnix.Set(float64(d.clock.Now().Unix()))
	_ = sess.WriteShutdown(transport.CodeShutdownNormal, "sagvd: job complete")
	d.log.Info("sagvd job completed",
		"job_id", jobID,
		"manifest_id", req.ManifestID,
		"output_kind", string(out.OutputKind),
		"output_bytes", len(out.Bytes),
		"worker_signing_kid", string(verified.WorkerSigningKeyID),
	)
}

// ---- listener setup -----------------------------------------------------

// listen binds a TCP listener on the configured address. When TLS
// is disabled, returns the plain net.Listener; when enabled, the
// TLS wrap happens per-connection in serveOne so a stalled TLS
// handshake cannot block the accept loop.
func (d *Daemon) listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", d.cfg.Vault.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("sagvd: listen %q: %w", d.cfg.Vault.ListenAddress, err)
	}
	return ln, nil
}

// loadServerTLS assembles a *tls.Config for an mTLS server. Loads
// the server certificate + key and the client-CA bundle; sets
// ClientAuth to RequireAndVerifyClientCert so an unauthenticated
// worker cannot even begin a Return Path handshake.
func loadServerTLS(cfg TLSConfig) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(cfg.ServerCert, cfg.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("sagvd: load server keypair: %w", err)
	}
	caBytes, err := os.ReadFile(cfg.ClientCAs)
	if err != nil {
		return nil, fmt.Errorf("sagvd: read client CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("sagvd: client CA bundle contains no valid PEM certificates")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ---- metrics registration -----------------------------------------------

// registerDaemonMetrics registers the sagvd_* family on registry
// and returns the bundle. The start_unix gauge is set immediately
// so operators can compute uptime from a single /metrics scrape.
func registerDaemonMetrics(r *metrics.Registry, clock shared_time.Clock) *daemonMetrics {
	m := &daemonMetrics{
		jobsCompleted: r.NewCounter(
			"sagvd_jobs_completed_total",
			"Total jobs that reached a terminal state, labelled by outcome.",
		),
		sessionsOpened: r.NewCounter(
			"sagvd_sessions_opened_total",
			"Total Return Path sessions that completed the 4-frame handshake.",
		),
		handshakeFailure: r.NewCounter(
			"sagvd_handshake_failures_total",
			"Total Return Path handshake failures, labelled by phase (tls|handshake).",
		),
		queueDepth: r.NewGauge(
			"sagvd_queue_depth",
			"Pending jobs waiting for a worker to pick them up.",
		),
		lastSuccessUnix: r.NewGauge(
			"sagvd_last_success_unix",
			"Unix-seconds of the vault's last successful job (0 if none).",
		),
		startUnix: r.NewGauge(
			"sagvd_start_unix",
			"Unix-seconds of the vault process start time.",
		),
	}
	m.startUnix.Set(float64(clock.Now().Unix()))
	return m
}

// ---- helpers -------------------------------------------------------------

// outcomeFromError maps a classified error to the
// jobs_completed_total{outcome} label. The taxonomy matches
// cmd/acp-compute/jobOutcomeFromError so a Grafana dashboard can
// cross-reference the two sides.
func outcomeFromError(err error) string {
	switch shared_errors.CategoryOf(err) {
	case shared_errors.CategoryOperational, shared_errors.CategoryStructural:
		return "reject"
	case shared_errors.CategoryAuthority, shared_errors.CategoryIntegrity, shared_errors.CategoryIncident:
		return "fail"
	default:
		return "fail"
	}
}

// sleepContext blocks for d unless ctx is cancelled first. Returns
// true if the sleep ran to completion, false if ctx was cancelled.
func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
