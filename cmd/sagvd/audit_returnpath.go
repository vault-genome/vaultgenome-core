// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ai-continuity-platform/core/internal/audit/chain"
	"github.com/ai-continuity-platform/core/internal/audit/store"
	"github.com/ai-continuity-platform/core/internal/compute/returnpath"
	"github.com/ai-continuity-platform/core/internal/compute/returnpath/transport"
	"github.com/ai-continuity-platform/core/internal/contracts/audit_event"
	"github.com/ai-continuity-platform/core/internal/contracts/validation_result"
	"github.com/ai-continuity-platform/core/internal/observability/metrics"
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/validation/equivalence"
	"github.com/ai-continuity-platform/core/internal/validation/reconstruction"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
)

// The Return Path audit log (ADR 0014). Every decision the daemon takes
// about a job goes to a durable, signed, hash-linked log BEFORE it becomes
// visible — the same log format, signing key and verifier (`acpctl audit
// verify`) as the cross-cloud releases, in its own file (audit.log_path):
//
//	MANIFEST_ISSUED                a gate job was built and queued
//	TRUST_EVALUATED                a worker's TEE Evidence was verified (a
//	                               session opened) or refused
//	CANDIDATE_RECEIVED             a signed candidate output passed the
//	                               Return Path's checks
//	VALIDATION_STARTED             the gate began judging it
//	VALIDATION_DIMENSION_EVALUATED the behavioural dimension: the ladder
//	VALIDATION_FINDING             one per finding, before a failed verdict
//	VALIDATION_COMPLETED           the verdict, signed
//	SESSION_INVALIDATED            a job ended without a judged candidate
//	INCIDENT_DETECTED              an integrity or incident failure
//
// A log that cannot be written stops the decision: a job is not queued,
// a candidate is not judged, a verdict is not surfaced (audit first-class,
// doctrine invariant #08).

// AuditConfig is where the daemon keeps its Return Path log.
type AuditConfig struct {
	// LogPath is the append-only bbolt file every Return Path decision
	// is written to, signed under keys.audit_signing and verified end to
	// end when it is opened. Required when gate jobs are enabled
	// (genome.bundle_dir). It must not be the cross-cloud subcommands'
	// crosscloud.audit_log_path: the daemon holds its file open, and one
	// process holds a log at a time.
	LogPath string `json:"log_path,omitempty"`
}

// CodeAuditUnavailable (Operational): the audit log could not record a
// decision, so the decision was not taken.
const CodeAuditUnavailable = "audit_unavailable"

// auditPayloadSchema names the payload shapes below.
const auditPayloadSchema = "vault-genome/returnpath-audit/v1"

// returnPathAudit is the daemon's audit surface.
type returnPathAudit struct {
	emitter *chainAuditEmitter
	chain   chain.Chain
	keyID   ids.KeyID
	keys    *keys.InMemoryStore
	log     *store.BBoltStore
	events  *metrics.Counter // labels: kind
}

// openReturnPathAudit opens (or creates) the daemon's audit log under
// keys.audit_signing, verifying whatever it already holds.
func openReturnPathAudit(cfg Config, clock shared_time.Clock, registry *metrics.Registry) (*returnPathAudit, error) {
	if cfg.Audit.LogPath == "" {
		return nil, nil
	}
	if cfg.Keys.AuditSigning.KeyID == "" || cfg.Keys.AuditSigning.SeedPath == "" {
		return nil, errors.New("sagvd: audit.log_path needs keys.audit_signing.kid and seed_path")
	}
	seed, err := readExactly(cfg.Keys.AuditSigning.SeedPath, crypto.Ed25519SeedSize, "keys.audit_signing.seed_path")
	if err != nil {
		return nil, err
	}
	kid := ids.KeyID(cfg.Keys.AuditSigning.KeyID)
	ks := keys.NewInMemoryStore(clock)
	if _, err := ks.RegisterSigningFromSeed(kid, keys.PurposeSigningAudit, seed); err != nil {
		return nil, fmt.Errorf("sagvd: register audit signing key: %w", err)
	}
	logStore, err := store.Open(cfg.Audit.LogPath)
	if err != nil {
		return nil, fmt.Errorf("sagvd: open audit.log_path: %w", err)
	}
	c, err := chain.OpenPersistentChain(logStore, ks)
	if err != nil {
		_ = logStore.Close()
		return nil, fmt.Errorf("sagvd: audit.log_path %q: %w", cfg.Audit.LogPath, err)
	}
	emitter, err := newChainAuditEmitter(c, ks, kid, clock, "rp-evt-")
	if err != nil {
		_ = logStore.Close()
		return nil, fmt.Errorf("sagvd: build Return Path audit emitter: %w", err)
	}
	emitter.counter = uint64(c.Len())
	a := &returnPathAudit{emitter: emitter, chain: c, keyID: kid, keys: ks, log: logStore}
	if registry != nil {
		a.events = registry.NewCounter("sagvd_audit_events_total",
			"Return Path audit events appended to audit.log_path, labelled by kind.")
	}
	return a, nil
}

// Close releases the log. Safe on a nil receiver.
func (a *returnPathAudit) Close() error {
	if a == nil || a.log == nil {
		return nil
	}
	a.keys.Zeroize()
	return a.log.Close()
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

// emit appends one event; a failure is the audit_unavailable error the
// caller must stop on.
func (a *returnPathAudit) emit(kind audit_event.Kind, payload any, sessionID, manifestID string) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "sagvd: encode audit payload", err)
	}
	if _, err := a.emitter.Emit(kind, raw, ids.SessionID(sessionID), ids.ManifestID(manifestID), ""); err != nil {
		return shared_errors.Operational(CodeAuditUnavailable,
			fmt.Sprintf("sagvd: the audit log did not record %s; the decision is not taken", kind), err)
	}
	if a.events != nil {
		a.events.Inc(metrics.Label{Name: "kind", Value: string(kind)})
	}
	return nil
}

// ---- payloads ------------------------------------------------------------

type jobAcceptedPayload struct {
	Schema        string    `json:"schema"`
	JobID         string    `json:"job_id"`
	GenomeID      string    `json:"genome_id"`
	Bundle        string    `json:"bundle"`
	BundleSHA256  string    `json:"bundle_sha256"`
	PayloadSHA256 string    `json:"payload_sha256"`
	Generation    uint64    `json:"generation"`
	KeySource     string    `json:"key_source"`
	Base          string    `json:"base"`
	BaseDigest    string    `json:"base_digest"`
	Fixtures      int       `json:"fixtures"`
	Critical      int       `json:"critical"`
	ShippedFiles  int       `json:"shipped_files"`
	ShippedBytes  int64     `json:"shipped_bytes"`
	OutputBudget  uint64    `json:"output_budget_bytes"`
	Deadline      time.Time `json:"deadline"`
}

type trustPayload struct {
	Schema             string `json:"schema"`
	Outcome            string `json:"outcome"` // allow | deny
	Phase              string `json:"phase"`   // tls | handshake | session
	RemoteAddr         string `json:"remote_addr,omitempty"`
	PeerProvider       string `json:"peer_provider"`
	PeerMeasurementHex string `json:"peer_measurement_hex,omitempty"`
	JobID              string `json:"job_id,omitempty"`
	Category           string `json:"category,omitempty"`
	Code               string `json:"code,omitempty"`
	Reason             string `json:"reason,omitempty"`
}

type candidatePayload struct {
	Schema             string    `json:"schema"`
	JobID              string    `json:"job_id"`
	WorkerSigningKeyID string    `json:"worker_signing_key_id"`
	OutputKind         string    `json:"output_kind"`
	Bytes              int       `json:"bytes"`
	SHA256             string    `json:"sha256"`
	ProducedAt         time.Time `json:"produced_at"`
}

type validationStartedPayload struct {
	Schema   string   `json:"schema"`
	JobID    string   `json:"job_id"`
	GenomeID string   `json:"genome_id"`
	Fixtures int      `json:"fixtures"`
	Atol     float64  `json:"atol"`
	Rtol     float64  `json:"rtol"`
	Outliers int      `json:"max_non_critical_outliers"`
	Doors    []string `json:"doors"`
}

type validationDimensionPayload struct {
	Schema    string                   `json:"schema"`
	JobID     string                   `json:"job_id"`
	Dimension string                   `json:"dimension"`
	Verdict   string                   `json:"verdict"`
	Score     float64                  `json:"score"`
	Threshold float64                  `json:"threshold"`
	Level     string                   `json:"level"`
	Door      string                   `json:"door,omitempty"`
	Rung      int                      `json:"rung"`
	Attempts  []reconstruction.Attempt `json:"attempts"`
}

type validationFindingPayload struct {
	Schema   string `json:"schema"`
	JobID    string `json:"job_id"`
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type validationCompletedPayload struct {
	Schema            string  `json:"schema"`
	JobID             string  `json:"job_id"`
	Overall           string  `json:"overall"` // pass | fail
	Level             string  `json:"level"`
	Door              string  `json:"door,omitempty"`
	FixturesHash      string  `json:"fixtures_hash,omitempty"`
	NExact            int     `json:"n_exact"`
	NEquivalent       int     `json:"n_equivalent"`
	NMismatch         int     `json:"n_mismatch"`
	NCriticalMismatch int     `json:"n_critical_mismatch"`
	MaxAbsErr         float64 `json:"max_abs_err"`
	MaxRelErr         float64 `json:"max_rel_err"`
	VerdictSHA256     string  `json:"verdict_sha256,omitempty"` // of the signed verdict's canonical bytes
	SignerKeyID       string  `json:"signer_key_id,omitempty"`
	Category          string  `json:"category,omitempty"`
	Code              string  `json:"code,omitempty"`
	Reason            string  `json:"reason,omitempty"`
}

type sessionEndedPayload struct {
	Schema   string `json:"schema"`
	JobID    string `json:"job_id"`
	Stage    string `json:"stage"` // dispatch | serve | judge
	Category string `json:"category"`
	Code     string `json:"code"`
	Reason   string `json:"reason"`
	WorkerID string `json:"worker_signing_key_id,omitempty"`
}

// ---- decisions -----------------------------------------------------------

// JobAccepted records a gate job before it is queued.
func (a *returnPathAudit) JobAccepted(jobID string, job builtJob) error {
	if a == nil {
		return nil
	}
	return a.emit(audit_event.KindManifestIssued, jobAcceptedPayload{
		Schema: auditPayloadSchema, JobID: jobID, GenomeID: job.Genome.KeyID, Bundle: job.Genome.Bundle,
		BundleSHA256: job.Genome.BundleSHA256, PayloadSHA256: job.Genome.PayloadSHA256, Generation: job.Genome.Generation,
		KeySource: job.Genome.KeySource, Base: job.Genome.Base, BaseDigest: job.Genome.BaseDigest,
		Fixtures: job.Genome.Fixtures, Critical: job.Genome.Critical, ShippedFiles: job.Genome.Files,
		ShippedBytes: job.Genome.Bytes, OutputBudget: job.Req.ExpectedOutputMaxBytes, Deadline: job.Req.Deadline,
	}, job.Req.SessionID, job.Req.ManifestID)
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
	}, "", "")
}

// TrustAdmitted records that a job is being handed to a worker whose
// Evidence verified under the pinned identity.
func (a *returnPathAudit) TrustAdmitted(jobID string, req transport.JobRequest, remote string, peer tee.Provider, measurement tee.Measurement) error {
	if a == nil {
		return nil
	}
	return a.emit(audit_event.KindTrustEvaluated, trustPayload{
		Schema: auditPayloadSchema, Outcome: "allow", Phase: "session", RemoteAddr: remote,
		PeerProvider: string(peer), PeerMeasurementHex: hex.EncodeToString(measurement), JobID: jobID,
	}, req.SessionID, req.ManifestID)
}

// CandidateReceived records a candidate that passed the Return Path's
// binding, budget and signature checks, before it is judged.
func (a *returnPathAudit) CandidateReceived(jobID string, req transport.JobRequest, out returnpath.CandidateOutput, workerKID string) error {
	if a == nil {
		return nil
	}
	sum := sha256.Sum256(out.Bytes)
	return a.emit(audit_event.KindCandidateReceived, candidatePayload{
		Schema: auditPayloadSchema, JobID: jobID, WorkerSigningKeyID: workerKID, OutputKind: string(out.OutputKind),
		Bytes: len(out.Bytes), SHA256: hex.EncodeToString(sum[:]), ProducedAt: out.ProducedAt,
	}, req.SessionID, req.ManifestID)
}

// Judged records a gate's run — started, the behavioural dimension, every
// finding, completed — before the verdict is surfaced. gateErr is the
// classified error a refused or unjudgeable answer failed with.
func (a *returnPathAudit) Judged(jobID string, req transport.JobRequest, spec *gateSpec, gate GateView, gateErr error) error {
	if a == nil {
		return nil
	}
	if err := a.emit(audit_event.KindValidationStarted, validationStartedPayload{
		Schema: auditPayloadSchema, JobID: jobID, GenomeID: spec.GenomeID, Fixtures: len(spec.Fixtures),
		Atol: spec.Tol.Atol, Rtol: spec.Tol.Rtol, Outliers: spec.Pol.MaxNonCriticalOutliers,
		Doors: []string{doorPinnedReplay, doorNativeFloat},
	}, req.SessionID, req.ManifestID); err != nil {
		return err
	}
	dim := gateDimension(gate)
	if err := a.emit(audit_event.KindValidationDimension, validationDimensionPayload{
		Schema: auditPayloadSchema, JobID: jobID, Dimension: string(validation_result.DimensionBehavioral),
		Verdict: string(dim.Verdict), Score: dim.Score, Threshold: dim.Threshold,
		Level: gate.Level, Door: gate.Door, Rung: gate.Rung, Attempts: gate.Attempts,
	}, req.SessionID, req.ManifestID); err != nil {
		return err
	}
	for _, f := range dim.Details {
		if err := a.emit(audit_event.KindValidationFinding, validationFindingPayload{
			Schema: auditPayloadSchema, JobID: jobID, Code: f.Code, Severity: string(f.Severity), Message: f.Message,
		}, req.SessionID, req.ManifestID); err != nil {
			return err
		}
	}
	done := validationCompletedPayload{Schema: auditPayloadSchema, JobID: jobID, Overall: "fail", Level: gate.Level, Door: gate.Door}
	if gate.SignedVerdict != nil {
		v := gate.SignedVerdict.Verdict
		done.FixturesHash, done.NExact, done.NEquivalent = v.FixturesHash, v.NExact, v.NEquivalent
		done.NMismatch, done.NCriticalMismatch, done.MaxAbsErr, done.MaxRelErr = v.NMismatch, v.NCriticalMismatch, v.MaxAbsErr, v.MaxRelErr
		if canonical, err := v.CanonicalBytes(); err == nil {
			sum := sha256.Sum256(canonical)
			done.VerdictSHA256 = hex.EncodeToString(sum[:])
		}
		done.SignerKeyID = gate.SignerKeyID
	}
	if gateErr == nil {
		done.Overall = "pass"
	} else {
		done.Category, done.Code, done.Reason = shared_errors.CategoryOf(gateErr).String(), shared_errors.CodeOf(gateErr), gateErr.Error()
	}
	return a.emit(audit_event.KindValidationCompleted, done, req.SessionID, req.ManifestID)
}

// JobEnded records a job that ended without a judged candidate: the
// session was invalidated (operational, structural, authority failures)
// or an incident was detected (integrity, incident).
func (a *returnPathAudit) JobEnded(jobID string, req transport.JobRequest, stage string, workerKID string, err error) error {
	if a == nil {
		return nil
	}
	kind := audit_event.KindSessionInvalidated
	switch shared_errors.CategoryOf(err) {
	case shared_errors.CategoryIntegrity, shared_errors.CategoryIncident:
		kind = audit_event.KindIncidentDetected
	}
	return a.emit(kind, sessionEndedPayload{
		Schema: auditPayloadSchema, JobID: jobID, Stage: stage,
		Category: shared_errors.CategoryOf(err).String(), Code: shared_errors.CodeOf(err), Reason: err.Error(), WorkerID: workerKID,
	}, req.SessionID, req.ManifestID)
}

// gateDimension maps a gate's outcome onto the frozen ValidationResult
// behavioural dimension, the same way the receive-side gate does.
func gateDimension(gate GateView) validation_result.DimensionVerdict {
	res := reconstruction.LadderResult{Attempts: gate.Attempts, Rung: gate.Rung, Name: gate.Door, Kind: reconstruction.StrategyKind(gate.Kind)}
	if gate.SignedVerdict != nil {
		res.Opened = true
		res.Verdict = gate.SignedVerdict.Verdict
	}
	if len(res.Attempts) == 0 && !res.Opened {
		// Nothing could be judged: the output was not an answer.
		res.Attempts = []reconstruction.Attempt{{Name: "gate", Level: equivalence.Level("ERROR"), Err: "the candidate output could not be judged"}}
	}
	return reconstruction.LadderToDimensionVerdict(res, 1.0)
}
