// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// After a failover the standby goes on by itself (ADR 0041): it trains
// from the generation it restored, and its own sentinel seals what it
// produces as the chain's next generation. Under a policy that names that
// sentinel, the release authority reads the standby's outbox and records
// the generation that continues the chain (CHAIN_CONTINUED). It releases
// nothing for it: the record says what the authority saw and checked.

// ContinuesChain reports whether the policy names the standby's own
// sentinel, and so has a chain for the authority to record after a
// failover.
func (p Policy) ContinuesChain() bool { return p.Standby.Sentinel != nil }

// StandbySentinelAllows reports whether measurement is one the policy pins
// the standby sentinel's records at.
func (p Policy) StandbySentinelAllows(measurement tee.Measurement) bool {
	s := p.Standby.Sentinel
	return s != nil && slices.Contains(s.Measurements, hex.EncodeToString(measurement))
}

// Released is the generation a failover released to the standby: what the
// first generation the standby seals must follow.
type Released struct {
	// DecisionID is the failover's, as FAILOVER_DECIDED recorded it.
	DecisionID   ids.DecisionID
	Generation   uint64
	BundleSHA256 string
}

// Continuation is the generation the standby's own sentinel sealed after
// the one released, as found in its outbox and checked.
type Continuation struct {
	Record sentinel.SealRecord
	// RecordSHA256 is the SHA-256 of the seal record as it was read.
	RecordSHA256 []byte
	// Measurement is what the record's TEE report attests.
	Measurement tee.Measurement
}

// FindContinuation reads, from the standby's outbox, the one record that
// can continue the chain — the seal record of the generation after the
// one released — and accepts it only when all of this holds:
//
//   - it verifies under the standby sentinel's key the policy names, and
//     says the generation its file name says;
//   - it names the released bundle as its parent;
//   - it carries a report of the standby's TEE, verified under verifier,
//     at a measurement the policy pins for the standby's sentinel;
//   - the outbox holds the bundle and the escrow envelope it describes,
//     and the key is escrowed to this authority (escrowTag).
//
// It returns the continuation; or, for a record that is there and fails a
// check, the file and the reason; or neither while the outbox holds no
// record of that generation. Nothing else in the outbox is looked at: an
// earlier chain under the same key, or a later generation that arrived
// first, is not what the authority waits for.
func FindContinuation(outbox string, p Policy, released Released, escrowTag string, verifier tee.Verifier) (*Continuation, *sentinel.Rejected, error) {
	pub, _, ok := p.StandbySentinel()
	if !ok {
		return nil, nil, errors.New("failover: the policy names no standby sentinel")
	}
	generation := released.Generation + 1
	setAside := func(reason string) (*Continuation, *sentinel.Rejected, error) {
		return nil, &sentinel.Rejected{File: sentinel.RecordName(generation), Reason: reason}, nil
	}
	rec, raw, err := sentinel.ReadRecord(outbox, generation, pub)
	switch {
	case errors.Is(err, sentinel.ErrAbsent):
		return nil, nil, nil
	case err != nil:
		return setAside(err.Error())
	case rec.ParentBundleSHA256 != released.BundleSHA256:
		return setAside(fmt.Sprintf("names bundle %s as its parent; generation %d was released as bundle %s", rec.ParentBundleSHA256, released.Generation, released.BundleSHA256))
	}
	m, err := rec.Attested(verifier)
	if err == nil && !p.StandbySentinelAllows(m) {
		err = fmt.Errorf("attested by %s measurement %x, which the policy does not pin for the standby's sentinel", p.Standby.Kind, m)
	}
	if err != nil {
		return setAside(err.Error())
	}
	_, env, err := sentinel.CheckGenome(outbox, rec)
	if err == nil && env.EscrowKey != escrowTag {
		err = fmt.Errorf("its key is escrowed to %s, not to this authority's %s", env.EscrowKey, escrowTag)
	}
	if err != nil {
		return setAside(err.Error())
	}
	sum := sha256.Sum256(raw)
	return &Continuation{Record: rec, RecordSHA256: sum[:], Measurement: m}, nil, nil
}

// continuedPayload is the JSON payload of a KindChainContinued audit event.
type continuedPayload struct {
	PolicySerial uint64 `json:"policy_serial"`
	PolicySHA256 []byte `json:"policy_sha256"`
	// DecisionID is the failover the chain continues from.
	DecisionID ids.DecisionID `json:"decision_id"`
	// Sentinel is the standby sentinel's key ID; MeasurementHex is what
	// its record's TEE report attests.
	Sentinel       string       `json:"sentinel"`
	StandbyKind    tee.Provider `json:"standby_kind"`
	MeasurementHex string       `json:"measurement_hex"`
	Generation     uint64       `json:"generation"`
	BundleSHA256   string       `json:"bundle_sha256"`
	KeyID          ids.KeyID    `json:"key_id"`
	SealedAt       time.Time    `json:"sealed_at"`
	// The generation it follows: the one the failover released.
	ParentGeneration   uint64    `json:"parent_generation"`
	ParentBundleSHA256 string    `json:"parent_bundle_sha256"`
	RecordSHA256       []byte    `json:"record_sha256"`
	RecordedAt         time.Time `json:"recorded_at"`
}

// ContinuationReport is the chain the standby continued, as recorded.
type ContinuationReport struct {
	Sentinel           string    `json:"sentinel"`
	MeasurementHex     string    `json:"measurement_hex"`
	Generation         uint64    `json:"generation"`
	BundleSHA256       string    `json:"bundle_sha256"`
	KeyID              string    `json:"key_id"`
	SealedAt           time.Time `json:"sealed_at"`
	ParentGeneration   uint64    `json:"parent_generation"`
	ParentBundleSHA256 string    `json:"parent_bundle_sha256"`
	// SealedAfterRestoreSeconds: from the restore the standby signed for to
	// the generation it sealed, both by the standby's clock.
	SealedAfterRestoreSeconds *float64         `json:"sealed_after_restore_seconds,omitempty"`
	RecordedAt                time.Time        `json:"recorded_at"`
	AuditID                   ids.AuditEventID `json:"audit_id"`
	// SetAside lists what the standby's outbox held as that generation and
	// did not count, and why.
	SetAside []sentinel.Rejected `json:"set_aside,omitempty"`
}

func (p continuedPayload) report(auditID ids.AuditEventID) ContinuationReport {
	return ContinuationReport{
		Sentinel: p.Sentinel, MeasurementHex: p.MeasurementHex, Generation: p.Generation, BundleSHA256: p.BundleSHA256,
		KeyID: string(p.KeyID), SealedAt: p.SealedAt, ParentGeneration: p.ParentGeneration, ParentBundleSHA256: p.ParentBundleSHA256,
		RecordedAt: p.RecordedAt, AuditID: auditID,
	}
}

// continuedOnRecord returns the continuation the audit log holds for a
// failover's decision ID, if any.
func continuedOnRecord(events []audit_event.AuditEvent, decisionID ids.DecisionID) (*continuedPayload, ids.AuditEventID, error) {
	for _, e := range events {
		if e.Kind != audit_event.KindChainContinued {
			continue
		}
		var p continuedPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return nil, "", fmt.Errorf("failover: audit event %s does not decode", e.EventID)
		}
		if p.DecisionID == decisionID {
			return &p, e.EventID, nil
		}
	}
	return nil, "", nil
}

// RecordContinuation puts c on the audit log as the chain the standby
// continues from released (CHAIN_CONTINUED) — once. A continuation already
// on record for that failover is returned as it was recorded and nothing
// is appended; one on record as another bundle is an error, not a second
// record.
func (e *Executor) RecordContinuation(c Continuation, released Released) (ContinuationReport, error) {
	p := e.cfg.Policy
	_, sid, ok := p.StandbySentinel()
	switch {
	case !ok:
		return ContinuationReport{}, errors.New("failover: the policy names no standby sentinel")
	case released.DecisionID.IsZero():
		return ContinuationReport{}, errors.New("failover: a continuation is recorded under the decision ID of its failover")
	case c.Record.Generation != released.Generation+1 || c.Record.ParentBundleSHA256 != released.BundleSHA256:
		return ContinuationReport{}, fmt.Errorf("failover: generation %d does not follow the released generation %d", c.Record.Generation, released.Generation)
	}
	was, auditID, err := continuedOnRecord(e.cfg.Events(), released.DecisionID)
	if err != nil {
		return ContinuationReport{}, err
	}
	if was != nil {
		if was.BundleSHA256 != c.Record.BundleSHA256 {
			return ContinuationReport{}, fmt.Errorf("failover: audit event %s already records generation %d as bundle %s; the standby's outbox now holds %s", auditID, was.Generation, was.BundleSHA256, c.Record.BundleSHA256)
		}
		return was.report(auditID), nil
	}
	payload := continuedPayload{
		PolicySerial:       p.Serial,
		PolicySHA256:       p.Digest(),
		DecisionID:         released.DecisionID,
		Sentinel:           sid,
		StandbyKind:        tee.Provider(p.Standby.Kind),
		MeasurementHex:     hex.EncodeToString(c.Measurement),
		Generation:         c.Record.Generation,
		BundleSHA256:       c.Record.BundleSHA256,
		KeyID:              ids.KeyID(c.Record.KeyID),
		SealedAt:           c.Record.SealedAt,
		ParentGeneration:   released.Generation,
		ParentBundleSHA256: released.BundleSHA256,
		RecordSHA256:       c.RecordSHA256,
		RecordedAt:         e.cfg.Clock.Now().UTC(),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ContinuationReport{}, err
	}
	auditID, err = e.cfg.Audit.Emit(audit_event.KindChainContinued, raw, "", "", "")
	if err != nil {
		return ContinuationReport{}, err
	}
	e.log.Info("the standby continues the chain", slog.String("decision_id", string(released.DecisionID)), slog.String("standby_sentinel", sid),
		slog.Uint64("generation", c.Record.Generation), slog.String("bundle_sha256", c.Record.BundleSHA256))
	return payload.report(auditID), nil
}

// Continue waits for the standby to seal the generation after the one
// rep's failover restored there, and records it. It returns rep with
// Continued filled in — or, when ctx ends first, rep as it was and ctx's
// error. A record of that generation that fails a check is noted once, in
// the log and in the report, and waited past: a file still being copied
// checks out when it is whole.
func (e *Executor) Continue(ctx context.Context, rep Report) (Report, error) {
	p := e.cfg.Policy
	switch {
	case !p.ContinuesChain():
		return rep, errors.New("failover: the policy names no standby sentinel: there is no chain to wait for")
	case e.cfg.StandbyOutbox == "" || e.cfg.StandbySentinel == nil:
		return rep, errors.New("failover: the standby's outbox and a verifier for its TEE are required to record the chain it continues")
	case rep.Status != StatusRestored || rep.Decision == nil || rep.Genome == nil:
		return rep, errors.New("failover: there is no confirmed restore for the standby to go on from")
	}
	released := Released{DecisionID: rep.Decision.DecisionID, Generation: rep.Genome.Generation, BundleSHA256: rep.Genome.BundleSHA256}
	tag := escrow.KeyTag(e.cfg.Escrow.PublicKey())
	var setAside []sentinel.Rejected
	seen := map[string]bool{}
	for {
		c, rejected, err := FindContinuation(e.cfg.StandbyOutbox, p, released, tag, e.cfg.StandbySentinel)
		if err != nil {
			return rep, err
		}
		if c != nil {
			cr, err := e.RecordContinuation(*c, released)
			if err != nil {
				return rep, err
			}
			if rep.Restore != nil {
				s := c.Record.SealedAt.Sub(rep.Restore.RestoredAt).Seconds()
				cr.SealedAfterRestoreSeconds = &s
			}
			cr.SetAside = setAside
			rep.Continued = &cr
			return rep, nil
		}
		if rejected != nil && !seen[rejected.Reason] {
			seen[rejected.Reason] = true
			setAside = append(setAside, *rejected)
			e.log.Warn("a record in the standby's outbox does not continue the chain", slog.String("file", rejected.File), slog.String("reason", rejected.Reason))
		}
		select {
		case <-ctx.Done():
			return rep, ctx.Err()
		case <-time.After(e.cfg.Poll):
		}
	}
}
