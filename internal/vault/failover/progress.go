// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Under a policy that names the standby's sentinel the authority's work
// does not end with the failover (ADR 0041): it records the chain the
// standby continues, and watches the standby as it watched the primary. An
// authority that restarts in the middle reads how far it got from its own
// audit log, and goes on from there.

// Progress is how far the audit log shows the failover of one policy went.
type Progress struct {
	// DecisionID is the failover's; empty while the policy has carried
	// none out.
	DecisionID ids.DecisionID
	// Released is what the failover released, once the standby's restore
	// of it was confirmed; nil before.
	Released *Released
	// Continued is the chain the standby continued, once it is on record.
	Continued *ContinuationReport
}

// Spent reports whether the policy carried out its failover.
func (pr Progress) Spent() bool { return !pr.DecisionID.IsZero() }

// ReadProgress reads, from a verified audit log, how far p's failover
// went: decided, restored and confirmed, continued. It refuses a log that
// holds a failover under another policy of p's serial, or a policy of a
// higher serial than p — as CheckNotSpent does — and one whose records of
// the failover do not agree with each other.
func ReadProgress(p Policy, events []audit_event.AuditEvent) (Progress, error) {
	var (
		pr      Progress
		decided decidedPayload
		highest uint64
	)
	for _, e := range events {
		if e.Kind != audit_event.KindFailoverDecided {
			continue
		}
		var d decidedPayload
		if json.Unmarshal(e.Payload, &d) != nil {
			return Progress{}, fmt.Errorf("failover: audit event %s does not decode", e.EventID)
		}
		highest = max(highest, d.PolicySerial)
		if d.PolicySerial != p.Serial || d.Decision != DecisionFailover {
			continue
		}
		switch {
		case !bytes.Equal(d.PolicySHA256, p.Digest()):
			return Progress{}, fmt.Errorf("failover: policy serial %d already carried out a failover (audit event %s) as another policy than this one; moving again needs a new policy", p.Serial, e.EventID)
		case d.DecisionID.IsZero() || d.Generation == nil:
			return Progress{}, fmt.Errorf("failover: audit event %s records a failover without its decision ID or its generation", e.EventID)
		case pr.Spent():
			return Progress{}, fmt.Errorf("failover: the audit log holds two failovers under policy serial %d (%s and audit event %s)", p.Serial, pr.DecisionID, e.EventID)
		}
		pr.DecisionID, decided = d.DecisionID, d
	}
	if !pr.Spent() {
		if p.Serial < highest {
			return Progress{}, fmt.Errorf("failover: policy serial %d is older than serial %d already applied in the audit log (rollback refused)", p.Serial, highest)
		}
		return pr, nil
	}
	for _, e := range events {
		if e.Kind != audit_event.KindCrossCloudRestoreCompleted {
			continue
		}
		var c struct {
			DecisionID   ids.DecisionID `json:"decision_id"`
			BundleSHA256 string         `json:"bundle_sha256"`
			Generation   uint64         `json:"generation"`
			RestoredAt   time.Time      `json:"restored_at"`
		}
		if json.Unmarshal(e.Payload, &c) != nil {
			return Progress{}, fmt.Errorf("failover: audit event %s does not decode", e.EventID)
		}
		if c.DecisionID != pr.DecisionID {
			continue
		}
		if c.Generation != *decided.Generation || c.BundleSHA256 != decided.BundleSHA256 {
			return Progress{}, fmt.Errorf("failover: audit event %s confirms the restore of generation %d (%s); decision %s was to restore generation %d (%s)",
				e.EventID, c.Generation, c.BundleSHA256, pr.DecisionID, *decided.Generation, decided.BundleSHA256)
		}
		pr.Released = &Released{DecisionID: pr.DecisionID, Generation: c.Generation, BundleSHA256: c.BundleSHA256, RestoredAt: c.RestoredAt}
	}
	was, auditID, err := continuedOnRecord(events, pr.DecisionID)
	if err != nil {
		return Progress{}, err
	}
	if was != nil {
		if pr.Released == nil || was.ParentBundleSHA256 != pr.Released.BundleSHA256 {
			return Progress{}, fmt.Errorf("failover: audit event %s records a chain continued from a restore that is not on record", auditID)
		}
		r := was.report(auditID, pr.Released.RestoredAt)
		pr.Continued = &r
	}
	return pr, nil
}

// Resume builds the executor of a policy that already carried out its
// failover and names the standby's sentinel. What is left for it is the
// standby's chain and the watch on the standby: Failover refuses, as the
// policy is spent. It returns how far the log shows the failover went. A
// policy that has not failed over is New's to arm; one whose restore was
// never confirmed, or that names no standby sentinel, has nothing left to
// do, and moving again takes a new policy.
func Resume(cfg Config) (*Executor, Progress, error) {
	e, err := wire(cfg)
	if err != nil {
		return nil, Progress{}, err
	}
	p := cfg.Policy
	if !p.ContinuesChain() {
		if err := CheckNotSpent(p, cfg.Events()); err != nil {
			return nil, Progress{}, err
		}
		return nil, Progress{}, fmt.Errorf("failover: policy serial %d has not carried out a failover: there is nothing to go on with", p.Serial)
	}
	pr, err := ReadProgress(p, cfg.Events())
	switch {
	case err != nil:
		return nil, Progress{}, err
	case !pr.Spent():
		return nil, Progress{}, fmt.Errorf("failover: policy serial %d has not carried out a failover: there is nothing to go on with", p.Serial)
	case pr.Released == nil:
		return nil, Progress{}, fmt.Errorf("failover: policy serial %d already carried out a failover (decision %s), and the standby's restore was never confirmed; moving again needs a new policy", p.Serial, pr.DecisionID)
	case cfg.StandbyOutbox == "" || cfg.StandbySentinel == nil:
		return nil, Progress{}, errors.New("failover: the standby's outbox and a verifier for its TEE are required to go on after the failover")
	}
	return e, pr, nil
}

// standbyView is the policy as the authority watches the standby under it
// once the failover is done: the standby's sentinel where the primary's
// was — its key, its TEE pinned — and the same triggers.
func (p Policy) standbyView() (Policy, error) {
	s := p.Standby.Sentinel
	if s == nil {
		return Policy{}, errors.New("failover: the policy names no standby sentinel")
	}
	v := p
	v.SentinelPublicKey, v.SentinelAlg = s.PublicKey, s.Alg
	v.Primary = &Primary{Kind: p.Standby.Kind, Measurements: s.Measurements, AttestorPublicKey: s.AttestorPublicKey}
	return v, nil
}

// NewStandbyWatcher watches the standby's own outbox after a failover the
// way NewWatcher watched the primary's: only what verifies under the
// standby sentinel's key and carries the standby TEE's report, under
// verifier, counts; the policy's triggers are the same. The standby is the
// primary by then, and one serial performs one failover: a trigger it
// returns is for DeclineStandbyTrigger.
func NewStandbyWatcher(p Policy, outbox string, now func() time.Time, verifier tee.Verifier) (*Watcher, error) {
	view, err := p.standbyView()
	if err != nil {
		return nil, err
	}
	w := NewWatcher(view, outbox, now, verifier)
	w.subject = "standby"
	return w, nil
}

// StandbyTriggerReport is a sign of failure on the standby after the
// failover, and the decision recorded for it.
type StandbyTriggerReport struct {
	Trigger  *TriggerReport  `json:"trigger"`
	Decision *DecisionReport `json:"decision"`
	Ignored  []string        `json:"ignored,omitempty"`
}

// DeclineStandbyTrigger records a trigger from the standby, where this
// policy's failover went, as a failover declined (FAILOVER_DECIDED): one
// serial performs one failover, and the policy names nowhere further to
// go. Once: a trigger already declined — the same evidence, under the same
// policy and sentinel — is returned as it was recorded, and nothing is
// appended.
func (e *Executor) DeclineStandbyTrigger(t Trigger) (StandbyTriggerReport, error) {
	p := e.cfg.Policy
	_, sid, ok := p.StandbySentinel()
	if !ok {
		return StandbyTriggerReport{}, errors.New("failover: the policy names no standby sentinel")
	}
	evidence := sha256.Sum256(t.Evidence)
	rep := StandbyTriggerReport{Trigger: newReport(p, sid, t, evidence[:], t.Ignored).Trigger, Ignored: t.Ignored}
	pr, err := ReadProgress(p, e.cfg.Events())
	switch {
	case err != nil:
		return rep, err
	case pr.Released == nil:
		return rep, errors.New("failover: the standby is watched only after a failover whose restore there was confirmed")
	}
	for _, ev := range e.cfg.Events() {
		if ev.Kind != audit_event.KindFailoverDecided {
			continue
		}
		var d decidedPayload
		if json.Unmarshal(ev.Payload, &d) != nil {
			return rep, fmt.Errorf("failover: audit event %s does not decode", ev.EventID)
		}
		if d.Decision == DecisionDeclined && d.PolicySerial == p.Serial && d.Sentinel == sid && bytes.Equal(d.EvidenceSHA256, evidence[:]) {
			rep.Decision = &DecisionReport{Decision: d.Decision, Reason: d.Reason, AuditID: ev.EventID, DecidedAt: d.DecidedAt}
			return rep, nil
		}
	}
	decidedAt := e.cfg.Clock.Now().UTC()
	payload := decidedPayload{
		Decision: DecisionDeclined,
		Reason: fmt.Sprintf("%s on the standby, where failover policy serial %d already moved the genome: one serial performs one failover, and this policy names nowhere further to go",
			t.Kind, p.Serial),
		PolicySerial:    p.Serial,
		PolicySHA256:    p.Digest(),
		Sentinel:        sid,
		Trigger:         t.Kind,
		TriggerAt:       t.At,
		EvidenceSHA256:  evidence[:],
		StandbyKind:     tee.Provider(p.Standby.Kind),
		StandbyEndpoint: p.Standby.Endpoint,
		DecidedAt:       decidedAt,
	}
	if len(t.PrimaryMeasurement) > 0 {
		payload.PrimaryMeasurementHex = hex.EncodeToString(t.PrimaryMeasurement)
	}
	if l := t.reportedLast(); l != nil {
		g := l.Generation
		payload.ReportedLast = &g
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return rep, err
	}
	auditID, err := e.cfg.Audit.Emit(audit_event.KindFailoverDecided, raw, "", "", "")
	if err != nil {
		return rep, err
	}
	rep.Decision = &DecisionReport{Decision: payload.Decision, Reason: payload.Reason, AuditID: auditID, DecidedAt: decidedAt}
	e.log.Warn("a trigger on the standby is declined", slog.String("trigger", string(t.Kind)), slog.String("standby_sentinel", sid), slog.String("reason", payload.Reason))
	return rep, nil
}
