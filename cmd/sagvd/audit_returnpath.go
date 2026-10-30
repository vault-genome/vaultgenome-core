// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// The Return Path audit log (ADR 0014, 0015). Every decision the daemon
// takes goes to a durable, signed, hash-linked log BEFORE it becomes
// visible — the same log format, signing key and verifier (`acpctl audit
// verify`) as the cross-cloud releases, in its own file (audit.log_path).
//
// The nine-stage flow writes its own events through the orchestration
// Authority (REQUEST_RECEIVED through RELEASE_DECIDED and the incident
// arcs). This file holds the log itself and the two decisions the daemon
// takes before a flow exists — a peer refused at the TLS or Return Path
// handshake, a peer whose Evidence is too old to be handed a job — as
// TRUST_EVALUATED denials with no request behind them.
//
// A log that cannot be written stops the decision: a job is not queued,
// a candidate is not judged, a verdict is not surfaced (audit first-class,
// doctrine invariant #08).

// AuditConfig is where the daemon keeps its Return Path log, and when
// it closes a segment of it (ADR 0027).
type AuditConfig struct {
	// LogPath is the append-only bbolt file every Return Path decision
	// is written to, signed under keys.audit_signing and verified end to
	// end when it is opened. Required when gate jobs are enabled
	// (genome.bundle_dir). It must not be the cross-cloud subcommands'
	// crosscloud.audit_log_path: the daemon holds its file open, and one
	// process holds a log at a time. With segments (below) it is the
	// live segment: the newest events, verified at every start.
	LogPath string `json:"log_path,omitempty"`

	// SegmentEvents closes the live file once it holds this many events:
	// the file is moved into ArchiveDir under the indices of its first
	// and last events, and a fresh file continues the chain, its first
	// event the record of the closing (AUDIT_SEGMENT_CLOSED). 0, the
	// default, never closes a segment by count; 1 is refused.
	SegmentEvents int `json:"segment_events,omitempty"`
	// SegmentMaxAgeSeconds closes the live file once its first event is
	// this old, checked at every append: a quiet daemon closes its
	// segment at its next event. 0 never closes a segment by age.
	SegmentMaxAgeSeconds int `json:"segment_max_age_seconds,omitempty"`
	// ArchiveDir is where closed segments go: "archive" beside LogPath
	// unless set. It must be on LogPath's filesystem — a segment is
	// renamed into it, not copied — and the daemon proves that at start.
	// Nothing in the daemon deletes an archive: the operator moves them
	// where their policy keeps them, and `acpctl audit verify` reads them
	// beside the live file.
	ArchiveDir string `json:"archive_dir,omitempty"`
}

// Rotates reports whether either trigger closes segments.
func (a AuditConfig) Rotates() bool {
	return a.SegmentEvents > 0 || a.SegmentMaxAgeSeconds > 0
}

// SegmentMaxAge is SegmentMaxAgeSeconds as a duration.
func (a AuditConfig) SegmentMaxAge() time.Duration {
	return time.Duration(a.SegmentMaxAgeSeconds) * time.Second
}

// ArchiveDirectory is ArchiveDir, or "archive" beside LogPath.
func (a AuditConfig) ArchiveDirectory() string {
	if a.ArchiveDir != "" {
		return a.ArchiveDir
	}
	if a.LogPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(a.LogPath), "archive")
}

// CodeAuditUnavailable (Operational): the audit log could not record a
// decision, so the decision was not taken.
const CodeAuditUnavailable = "audit_unavailable"

// auditPayloadSchema names the payload shapes below.
const auditPayloadSchema = "vault-genome/returnpath-audit/v1"

// returnPathAudit is the daemon's audit log and refusal surface.
type returnPathAudit struct {
	emitter    *chainAuditEmitter
	chain      chain.Chain // counts every append into sagvd_audit_events_total, then closes the segment when it is due
	persistent *chain.PersistentChain
	keyID      ids.KeyID
	keys       *keys.InMemoryStore
	cfg        AuditConfig
	clock      shared_time.Clock
	logger     *slog.Logger

	// mu guards log: the live segment's store, which a rotation replaces.
	mu  sync.Mutex
	log *store.BBoltStore

	// firstAt is when the live segment's first event occurred, zero
	// while the segment is empty: what the age trigger measures from.
	// Read and written under the chain's lock only, in Rotate's
	// functions, and before the daemon serves.
	firstAt time.Time

	events         *metrics.Counter
	segmentsClosed *metrics.Counter
	segmentEvents  *metrics.Gauge
}

// openReturnPathAudit opens (or creates) the daemon's audit log under
// keys.audit_signing, verifying whatever its live segment holds, and
// finishes a rotation a crash interrupted: a closing not yet on the
// record is recorded before anything else (ADR 0027).
func openReturnPathAudit(cfg Config, clock shared_time.Clock, registry *metrics.Registry, logger *slog.Logger) (*returnPathAudit, error) {
	if cfg.Audit.LogPath == "" {
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Keys.AuditSigning.KeyID == "" || cfg.Keys.AuditSigning.SeedPath == "" {
		return nil, errors.New("sagvd: audit.log_path needs keys.audit_signing.kid and seed_path")
	}
	auditKey, err := loadSigningKey(cfg.TEE, cfg.Keys.AuditSigning, "keys.audit_signing")
	if err != nil {
		return nil, err
	}
	kid := ids.KeyID(cfg.Keys.AuditSigning.KeyID)
	ks := keys.NewInMemoryStore(clock)
	if _, err := ks.RegisterSigningKey(kid, keys.PurposeSigningAudit, auditKey); err != nil {
		return nil, fmt.Errorf("sagvd: register audit signing key: %w", err)
	}
	archiveDir := cfg.Audit.ArchiveDirectory()
	if cfg.Audit.Rotates() {
		if err := store.ProbeArchiveDir(cfg.Audit.LogPath, archiveDir); err != nil {
			return nil, fmt.Errorf("sagvd: audit.archive_dir: %w", err)
		}
	}
	logStore, unrecorded, err := store.OpenLive(cfg.Audit.LogPath, archiveDir)
	if err != nil {
		return nil, fmt.Errorf("sagvd: open audit.log_path: %w", err)
	}
	c, err := chain.OpenPersistentChain(logStore, ks)
	if err != nil {
		_ = logStore.Close()
		return nil, fmt.Errorf("sagvd: audit.log_path %q: %w", cfg.Audit.LogPath, err)
	}
	a := &returnPathAudit{
		persistent: c, keyID: kid, keys: ks, log: logStore, cfg: cfg.Audit, clock: clock, logger: logger,
	}
	counted := &countingChain{Chain: c, audit: a}
	if registry != nil {
		counted.events = registry.NewCounter("sagvd_audit_events_total",
			"Return Path audit events appended to audit.log_path, labelled by kind.")
		a.segmentsClosed = registry.NewCounter("sagvd_audit_segments_closed_total",
			"Segments of audit.log_path closed and moved into audit.archive_dir (ADR 0027).")
		a.segmentEvents = registry.NewGauge("sagvd_audit_segment_events",
			"Events in the live segment of audit.log_path: what the next start verifies.")
	}
	a.events, a.chain = counted.events, counted
	emitter, err := newChainAuditEmitter(counted, ks, kid, clock, "rp-evt-")
	if err != nil {
		_ = logStore.Close()
		return nil, fmt.Errorf("sagvd: build Return Path audit emitter: %w", err)
	}
	emitter.counter = uint64(c.Len())
	a.emitter = emitter
	if first, ok := c.EventAt(c.Base()); ok {
		a.firstAt = first.OccurredAt
	}
	if unrecorded != nil {
		if err := a.emit(audit_event.KindAuditSegmentClosed, *unrecorded); err != nil {
			_ = logStore.Close()
			return nil, fmt.Errorf("sagvd: record the closing of audit segment %s: %w", unrecorded.Segment, err)
		}
		logger.Info("sagvd audit segment closing recorded at start",
			"segment", unrecorded.Path, "first_index", unrecorded.FirstIndex, "last_index", unrecorded.LastIndex,
			"tip", unrecorded.TipHex, "sha256", unrecorded.SHA256Hex, "bytes", unrecorded.Bytes)
	}
	a.setSegmentGauge(c.Len() - c.Base())
	return a, nil
}

func (a *returnPathAudit) setSegmentGauge(live int) {
	if a.segmentEvents != nil {
		a.segmentEvents.Set(float64(live))
	}
}

// segmentDue reports whether the live segment, holding live events, is
// to be closed now: by count, or by the age of its first event. A
// segment holding only its opening record is never closed by age.
// Called under the chain's lock.
func (a *returnPathAudit) segmentDue(live int) bool {
	if live <= 0 {
		return false
	}
	if a.firstAt.IsZero() {
		a.firstAt = a.clock.Now().UTC()
	}
	if a.cfg.SegmentEvents > 0 && live >= a.cfg.SegmentEvents {
		return true
	}
	if maxAge := a.cfg.SegmentMaxAge(); maxAge > 0 && live >= 2 && a.clock.Now().Sub(a.firstAt) >= maxAge {
		return true
	}
	return false
}

// rotateIfDue closes the live segment when a trigger says so: the file
// is moved into the archive directory, a fresh one continues the chain,
// and the closing is its first event — under the chain's lock, so no
// other writer comes between (ADR 0027). Called after every append.
func (a *returnPathAudit) rotateIfDue() {
	if a == nil || a.persistent == nil || !a.cfg.Rotates() {
		return
	}
	var closed store.ClosedSegment
	rotated, err := a.persistent.Rotate(func(base, n int, tip []byte) (chain.Persister, error) {
		live := n - base
		a.setSegmentGauge(live)
		if !a.segmentDue(live) {
			return nil, nil
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		next, cs, err := store.Rotate(a.log, a.cfg.ArchiveDirectory(), base, n, tip)
		if err != nil {
			return nil, err
		}
		a.log, closed = next, cs
		return next, nil
	}, func() (audit_event.AuditEvent, keys.Signer, error) {
		raw, err := json.Marshal(closed)
		if err != nil {
			return audit_event.AuditEvent{}, nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "sagvd: encode the closed segment", err)
		}
		evt := a.emitter.build(audit_event.KindAuditSegmentClosed, raw, "", "", "")
		a.firstAt = evt.OccurredAt
		return evt, a.keys, nil
	})
	if err != nil {
		a.logger.Error("sagvd audit segment rotation failed; the log refuses every append until the daemon is started again",
			"segment", closed.Path, "err", err)
		return
	}
	if !rotated {
		return
	}
	if a.events != nil {
		a.events.Inc(metrics.Label{Name: "kind", Value: string(audit_event.KindAuditSegmentClosed)})
	}
	if a.segmentsClosed != nil {
		a.segmentsClosed.Inc()
	}
	a.setSegmentGauge(1)
	a.logger.Info("sagvd audit segment closed",
		"segment", closed.Path, "first_index", closed.FirstIndex, "last_index", closed.LastIndex,
		"tip", closed.TipHex, "sha256", closed.SHA256Hex, "bytes", closed.Bytes)
}

// Close releases the log. Safe on a nil receiver.
func (a *returnPathAudit) Close() error {
	if a == nil {
		return nil
	}
	a.keys.Zeroize()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.log == nil {
		return nil
	}
	return a.log.Close()
}

// Base is the index of the live segment's first event: the live segment
// holds Len()-Base() events.
func (a *returnPathAudit) Base() int {
	if a == nil || a.persistent == nil {
		return 0
	}
	return a.persistent.Base()
}

// Len is the number of events on record; Tip the hash of the last one.
func (a *returnPathAudit) Len() int {
	if a == nil {
		return 0
	}
	return a.chain.Len()
}

func (a *returnPathAudit) Tip() string {
	if a == nil {
		return ""
	}
	return hex.EncodeToString(a.chain.Tip())
}

// EventAt reads one event of the live segment by its index in the whole
// log: the console serves the journal from here, so nothing pauses.
func (a *returnPathAudit) EventAt(i int) (audit_event.AuditEvent, bool) {
	if a == nil || a.persistent == nil {
		return audit_event.AuditEvent{}, false
	}
	return a.persistent.EventAt(i)
}

// Chain, Signer and KeyID are what the orchestration Authority writes
// its events with. nil-safe: without a log there is no chain.
func (a *returnPathAudit) Chain() chain.Chain {
	if a == nil {
		return nil
	}
	return a.chain
}

func (a *returnPathAudit) Signer() keys.Signer {
	if a == nil {
		return nil
	}
	return a.keys
}

func (a *returnPathAudit) KeyID() ids.KeyID {
	if a == nil {
		return ""
	}
	return a.keyID
}

// emit appends one event with no request behind it; a failure is the
// audit_unavailable error the caller reports.
func (a *returnPathAudit) emit(kind audit_event.Kind, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "sagvd: encode audit payload", err)
	}
	if _, err := a.emitter.Emit(kind, raw, "", "", ""); err != nil {
		return shared_errors.Operational(CodeAuditUnavailable,
			fmt.Sprintf("sagvd: the audit log did not record %s", kind), err)
	}
	return nil
}

// trustPayload is a TRUST_EVALUATED denial taken before any request: a
// peer refused, or a peer told to attest again.
type trustPayload struct {
	Schema             string     `json:"schema"`
	Outcome            string     `json:"outcome"` // deny
	Phase              string     `json:"phase"`   // tls | handshake | session
	RemoteAddr         string     `json:"remote_addr,omitempty"`
	PeerProvider       string     `json:"peer_provider"`
	PeerMeasurementHex string     `json:"peer_measurement_hex,omitempty"`
	EvidenceAt         *time.Time `json:"evidence_at,omitempty"`
	EvidenceAgeSeconds float64    `json:"evidence_age_seconds,omitempty"`
	MaxAgeSeconds      float64    `json:"evidence_max_age_seconds,omitempty"`
	Category           string     `json:"category,omitempty"`
	Code               string     `json:"code,omitempty"`
	Reason             string     `json:"reason,omitempty"`
}

// TrustRefused records a peer whose TLS or Return Path handshake was
// refused: no session opened, no job was handed out.
func (a *returnPathAudit) TrustRefused(phase, remote string, peer tee.Provider, err error) error {
	if a == nil {
		return nil
	}
	return a.emit(audit_event.KindTrustEvaluated, trustPayload{
		Schema: auditPayloadSchema, Outcome: "deny", Phase: phase, RemoteAddr: remote, PeerProvider: string(peer),
		Category: shared_errors.CategoryOf(err).String(), Code: shared_errors.CodeOf(err), Reason: err.Error(),
	})
}

// CodeEvidenceStale (Authority): the worker's Return Path Evidence is
// older than runtime.evidence_max_age; it must attest again before it is
// handed a job.
const CodeEvidenceStale = "evidence_stale"

// TrustStale records a session whose Evidence was too old to hand a job
// to: the session is closed, the job stays queued.
func (a *returnPathAudit) TrustStale(remote string, peer tee.Provider, measurement tee.Measurement, evidenceAt time.Time, age, maxAge time.Duration) error {
	if a == nil {
		return nil
	}
	at := evidenceAt.UTC()
	return a.emit(audit_event.KindTrustEvaluated, trustPayload{
		Schema: auditPayloadSchema, Outcome: "deny", Phase: "session", RemoteAddr: remote, PeerProvider: string(peer),
		PeerMeasurementHex: hex.EncodeToString(measurement), EvidenceAt: &at,
		EvidenceAgeSeconds: age.Seconds(), MaxAgeSeconds: maxAge.Seconds(),
		Category: shared_errors.CategoryAuthority.String(), Code: CodeEvidenceStale,
		Reason: fmt.Sprintf("the worker's Evidence is %s old, runtime.evidence_max_age is %s; attest again", age.Round(time.Second), maxAge),
	})
}

// countingChain counts every event appended to the log, by kind, into
// sagvd_audit_events_total, and then closes the segment if it is due.
// Every writer — the daemon's refusals, the Authority's flow events, the
// disclosure sequencer, the validation and incident services — goes
// through it.
type countingChain struct {
	chain.Chain
	events *metrics.Counter
	audit  *returnPathAudit
}

func (c *countingChain) Append(evt audit_event.AuditEvent, signer keys.Signer) (audit_event.AuditEvent, error) {
	sealed, err := c.Chain.Append(evt, signer)
	if err != nil {
		return sealed, err
	}
	if c.events != nil {
		c.events.Inc(metrics.Label{Name: "kind", Value: string(sealed.Kind)})
	}
	c.audit.rotateIfDue()
	return sealed, nil
}
