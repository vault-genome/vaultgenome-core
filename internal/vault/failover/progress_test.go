// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// An authority that restarts after the failover reads how far it got from
// its own audit log and goes on from there: it records the chain the
// standby continues, watches the standby as it watched the primary, and
// declines what the policy gives it nowhere to go on.
func TestTheAuthorityGoesOnFromItsLog(t *testing.T) {
	d := newDrill(t, 1.5, -2)
	side := newStandbySide(t)
	pol := d.turning(side)
	config := func() Config {
		return Config{
			Policy: pol, Outbox: d.outbox, Escrow: d.escrow, Coordinator: d.coord, Audit: d.audit, Events: d.audit.Events,
			IDs: &seqIDs{}, Clock: shared_time.NewSystemClock(), Poll: 20 * time.Millisecond, ConfirmWait: 20 * time.Second,
			StandbyOutbox: side.outbox, StandbySentinel: side.verifier,
		}
	}

	// Before the failover there is nothing to go on with, and the standby
	// is not there to watch.
	if pr, err := ReadProgress(pol, d.audit.Events()); err != nil || pr.Spent() {
		t.Fatalf("progress before the failover: %+v %v", pr, err)
	}
	if _, _, err := Resume(config()); err == nil || !strings.Contains(err.Error(), "has not carried out a failover") {
		t.Fatalf("resumed before the failover: %v", err)
	}
	idle, err := NewStandbyWatcher(pol, side.outbox, time.Now, side.verifier)
	must(t, err)
	if tr := idle.Observe(); tr != nil || idle.State != "waiting for the standby's first heartbeat" {
		t.Fatalf("an empty standby outbox: %+v, %q", tr, idle.State)
	}
	if _, err := NewStandbyWatcher(d.policy(), side.outbox, time.Now, side.verifier); err == nil {
		t.Fatal("a v1 policy has a standby to watch")
	}
	if _, err := d.turnExecutor(pol, side, side.outbox, nil).DeclineStandbyTrigger(Trigger{Kind: TriggerHeartbeatTimeout, At: time.Now()}); err == nil || !strings.Contains(err.Error(), "only after a failover") {
		t.Fatalf("a trigger on the standby before the failover: %v", err)
	}
	if n := len(d.audit.Events()); n != 0 {
		t.Fatalf("%d audit events before the failover", n)
	}

	rep, released, restored := d.failedOver(d.turnExecutor(pol, side, side.outbox, nil))

	// The authority restarts. What it reads from its log is what it did.
	resumed, pr, err := Resume(config())
	must(t, err)
	if !pr.Spent() || pr.DecisionID != rep.Decision.DecisionID || pr.Continued != nil || pr.Released == nil ||
		pr.Released.DecisionID != released.DecisionID || pr.Released.Generation != 1 || pr.Released.BundleSHA256 != released.BundleSHA256 || !pr.Released.RestoredAt.Equal(released.RestoredAt) {
		t.Fatalf("progress %+v, released %+v", pr, pr.Released)
	}
	// It does not fail over again: the policy is spent, and Failover holds
	// that where the decision is taken.
	before := len(d.audit.Events())
	if _, err := resumed.Failover(context.Background(), Trigger{Kind: TriggerHeartbeatTimeout, At: time.Now()}); err == nil || !strings.Contains(err.Error(), "already carried out") {
		t.Fatalf("a resumed executor failed over: %v", err)
	}
	if n := len(d.audit.Events()); n != before {
		t.Fatalf("%d audit events after a failover that was refused, %d before", n, before)
	}

	// The standby goes on, and the resumed authority records the chain.
	canary := d.goesOn(side, restored, filepath.Join(d.outbox, rep.Genome.Bundle))
	writeModel(t, restored, "weights v3, trained on the standby", 1.5, -2)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	continued, err := resumed.Continue(ctx, *pr.Released)
	must(t, err)
	if continued.Generation != 2 || continued.ParentBundleSHA256 != released.BundleSHA256 || continued.SealedAfterRestoreSeconds == nil || *continued.SealedAfterRestoreSeconds <= 0 {
		t.Fatalf("continued %+v", continued)
	}
	// A second restart finds the chain on record.
	_, pr, err = Resume(config())
	must(t, err)
	if pr.Continued == nil || pr.Continued.AuditID != continued.AuditID || pr.Continued.BundleSHA256 != continued.BundleSHA256 ||
		pr.Continued.SealedAfterRestoreSeconds == nil || *pr.Continued.SealedAfterRestoreSeconds != *continued.SealedAfterRestoreSeconds {
		t.Fatalf("progress after the chain: %+v", pr.Continued)
	}

	// The standby is watched as the primary was — under its own sentinel's
	// key: what the primary's outbox holds is nothing to this watch.
	foreign, err := NewStandbyWatcher(pol, d.outbox, time.Now, side.verifier)
	must(t, err)
	if tr := foreign.Observe(); tr != nil || len(foreign.Ignored) == 0 || !strings.Contains(foreign.Ignored[0], "the pinned sentinel is "+sentinel.KeyID(side.key.Public())) {
		t.Fatalf("the primary's records under the standby's watch: %+v, ignored %v", tr, foreign.Ignored)
	}
	w, err := NewStandbyWatcher(pol, side.outbox, time.Now, side.verifier)
	must(t, err)
	must(t, os.WriteFile(canary, []byte("read by an intruder"), 0o600))
	tr, err := w.Watch(ctx, 20*time.Millisecond, nil)
	must(t, err)
	if tr.Kind != TriggerCompromise || !bytes.Equal(tr.PrimaryMeasurement, side.chip.Measurement()) {
		t.Fatalf("trigger %+v", tr)
	}

	// One serial, one failover: the trigger there is declined, on the
	// record, once.
	lost, err := resumed.DeclineStandbyTrigger(*tr)
	must(t, err)
	if lost.Decision == nil || lost.Decision.Decision != DecisionDeclined || !strings.Contains(lost.Decision.Reason, "names nowhere further to go") ||
		lost.Trigger == nil || lost.Trigger.Kind != TriggerCompromise || len(lost.Trigger.Tripped) != 1 || lost.Trigger.Tripped[0].Target != canary {
		t.Fatalf("declined %+v, trigger %+v", lost.Decision, lost.Trigger)
	}
	events := d.audit.Events()
	if kinds := d.audit.kinds(); len(kinds) != 7 || kinds[5] != audit_event.KindChainContinued || kinds[6] != audit_event.KindFailoverDecided {
		t.Fatalf("audit %v", kinds)
	}
	var p decidedPayload
	must(t, json.Unmarshal(events[6].Payload, &p))
	if p.Decision != DecisionDeclined || p.DecisionID != "" || p.Generation != nil || p.PolicySerial != 7 || !bytes.Equal(p.PolicySHA256, pol.Digest()) ||
		p.Sentinel != sentinel.KeyID(side.key.Public()) || p.Trigger != TriggerCompromise || p.PrimaryMeasurementHex != hex.EncodeToString(side.chip.Measurement()) ||
		p.StandbyEndpoint != d.srv.URL || events[6].EventID != lost.Decision.AuditID {
		t.Fatalf("payload %+v", p)
	}
	again, err := resumed.DeclineStandbyTrigger(*tr)
	must(t, err)
	if again.Decision.AuditID != lost.Decision.AuditID || len(d.audit.Events()) != 7 {
		t.Fatalf("declined twice: %s then %s, %d events", lost.Decision.AuditID, again.Decision.AuditID, len(d.audit.Events()))
	}
	// The log reads as it did: one failover, restored, continued.
	if _, pr, err := Resume(config()); err != nil || pr.Continued == nil || pr.Released == nil {
		t.Fatalf("progress after the decline: %+v %v", pr, err)
	}
	if _, err := d.executor(pol); err == nil || !strings.Contains(err.Error(), "already carried out") {
		t.Fatalf("armed again after the decline: %v", err)
	}
}

func eventOf(t *testing.T, n int, kind audit_event.Kind, payload any) audit_event.AuditEvent {
	t.Helper()
	raw, err := json.Marshal(payload)
	must(t, err)
	return audit_event.AuditEvent{EventID: ids.AuditEventID(fmt.Sprintf("evt-%d", n)), Kind: kind, Payload: raw}
}

// ReadProgress says how far a failover went, and refuses a log whose
// records of it do not agree — with the policy, or with each other.
func TestReadProgressReadsWhatTheLogAgreesOn(t *testing.T) {
	_, op := operatorKey(t)
	pPub, _ := operatorKey(t)
	sPub, _ := operatorKey(t)
	aPub, _ := operatorKey(t)
	pol, err := Sign(v2Policy(pPub, sPub, aPub), op)
	must(t, err)
	gen, bundleB, bundleC := uint64(4), strings.Repeat("b", 64), strings.Repeat("c", 64)
	decision := decidedPayload{Decision: DecisionFailover, PolicySerial: 7, PolicySHA256: pol.Digest(), DecisionID: "dec-9", Generation: &gen, BundleSHA256: bundleB}
	type restoredPayload struct {
		DecisionID   string    `json:"decision_id"`
		Generation   uint64    `json:"generation"`
		BundleSHA256 string    `json:"bundle_sha256"`
		RestoredAt   time.Time `json:"restored_at"`
	}
	restored := restoredPayload{"dec-9", 4, bundleB, t0}
	chain := continuedPayload{DecisionID: "dec-9", Generation: 5, BundleSHA256: bundleC, ParentGeneration: 4, ParentBundleSHA256: bundleB, SealedAt: t0.Add(time.Minute)}
	ev := func(n int, kind audit_event.Kind, payload any) audit_event.AuditEvent {
		return eventOf(t, n, kind, payload)
	}
	undecodable := func(kind audit_event.Kind) audit_event.AuditEvent {
		return audit_event.AuditEvent{EventID: "evt-x", Kind: kind, Payload: []byte("{")}
	}
	log := []audit_event.AuditEvent{
		ev(1, audit_event.KindFailoverDecided, decidedPayload{Decision: DecisionDeclined, PolicySerial: 7, PolicySHA256: pol.Digest()}),
		ev(2, audit_event.KindFailoverDecided, decidedPayload{Decision: DecisionFailover, PolicySerial: 6, DecisionID: "dec-1", Generation: &gen}),
		ev(3, audit_event.KindCrossCloudRestoreCompleted, restoredPayload{"dec-1", 4, bundleB, t0}),
		ev(4, audit_event.KindFailoverDecided, decision),
		ev(5, audit_event.KindKeyReleaseAuthorized, map[string]string{"decision_id": "dec-9"}),
		ev(6, audit_event.KindCrossCloudRestoreCompleted, restored),
		ev(7, audit_event.KindChainContinued, chain),
	}

	// As far as the log goes, and no further.
	for upTo, want := range map[int]Progress{
		0: {},
		3: {},
		4: {DecisionID: "dec-9"},
		5: {DecisionID: "dec-9"},
		6: {DecisionID: "dec-9", Released: &Released{DecisionID: "dec-9", Generation: 4, BundleSHA256: bundleB, RestoredAt: t0}},
		7: {DecisionID: "dec-9", Released: &Released{DecisionID: "dec-9", Generation: 4, BundleSHA256: bundleB, RestoredAt: t0}, Continued: &ContinuationReport{Generation: 5}},
	} {
		got, err := ReadProgress(pol, log[:upTo])
		must(t, err)
		if got.DecisionID != want.DecisionID || got.Spent() != (want.DecisionID != "") || (got.Released == nil) != (want.Released == nil) || (got.Continued == nil) != (want.Continued == nil) {
			t.Fatalf("up to event %d: %+v", upTo, got)
		}
		if want.Released != nil && (got.Released.DecisionID != "dec-9" || got.Released.Generation != 4 || got.Released.BundleSHA256 != bundleB || !got.Released.RestoredAt.Equal(t0)) {
			t.Fatalf("up to event %d: released %+v", upTo, got.Released)
		}
		if want.Continued != nil && (got.Continued.Generation != 5 || got.Continued.BundleSHA256 != bundleC || got.Continued.AuditID != "evt-7" ||
			got.Continued.SealedAfterRestoreSeconds == nil || *got.Continued.SealedAfterRestoreSeconds != 60) {
			t.Fatalf("up to event %d: continued %+v", upTo, got.Continued)
		}
	}

	another := decision
	another.PolicySHA256 = bytes.Repeat([]byte{1}, 32)
	nameless := decision
	nameless.DecisionID = ""
	for name, tc := range map[string]struct {
		events []audit_event.AuditEvent
		want   string
	}{
		"a failover under another policy of the serial": {[]audit_event.AuditEvent{ev(1, audit_event.KindFailoverDecided, another)}, "as another policy than this one"},
		"a failover without its decision ID":            {[]audit_event.AuditEvent{ev(1, audit_event.KindFailoverDecided, nameless)}, "without its decision ID"},
		"two failovers under the serial":                {[]audit_event.AuditEvent{log[3], ev(9, audit_event.KindFailoverDecided, decision)}, "two failovers under policy serial 7"},
		"a policy of a higher serial already applied":   {[]audit_event.AuditEvent{ev(1, audit_event.KindFailoverDecided, decidedPayload{Decision: DecisionDeclined, PolicySerial: 9})}, "rollback refused"},
		"the restore of another generation":             {[]audit_event.AuditEvent{log[3], ev(2, audit_event.KindCrossCloudRestoreCompleted, restoredPayload{"dec-9", 3, bundleB, t0})}, "confirms the restore of generation 3"},
		"the restore of another bundle":                 {[]audit_event.AuditEvent{log[3], ev(2, audit_event.KindCrossCloudRestoreCompleted, restoredPayload{"dec-9", 4, bundleC, t0})}, "confirms the restore of generation 4"},
		"a chain continued from no restore":             {[]audit_event.AuditEvent{log[3], log[6]}, "a restore that is not on record"},
		"a decision that does not decode":               {[]audit_event.AuditEvent{undecodable(audit_event.KindFailoverDecided)}, "does not decode"},
		"a restore that does not decode":                {[]audit_event.AuditEvent{log[3], undecodable(audit_event.KindCrossCloudRestoreCompleted)}, "does not decode"},
		"a chain that does not decode":                  {[]audit_event.AuditEvent{log[3], log[5], undecodable(audit_event.KindChainContinued)}, "does not decode"},
	} {
		if _, err := ReadProgress(pol, tc.events); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

// Resume is for a policy that failed over, was confirmed, and names the
// standby's sentinel. Everything else has nothing to go on with.
func TestResumeNeedsAConfirmedFailoverToGoOnFrom(t *testing.T) {
	_, op := operatorKey(t)
	pPub, _ := operatorKey(t)
	sPub, _ := operatorKey(t)
	aPub, _ := operatorKey(t)
	v2, err := Sign(v2Policy(pPub, sPub, aPub), op)
	must(t, err)
	v1, err := Sign(testPolicy(pPub), op)
	must(t, err)
	key, err := escrow.GenerateKey(kms.PolicyForThisProcess().Writes())
	must(t, err)
	gen, bundleB := uint64(4), strings.Repeat("b", 64)
	decided := func(p Policy) audit_event.AuditEvent {
		return eventOf(t, 1, audit_event.KindFailoverDecided, decidedPayload{Decision: DecisionFailover, PolicySerial: p.Serial, PolicySHA256: p.Digest(), DecisionID: "dec-9", Generation: &gen, BundleSHA256: bundleB})
	}
	restored := eventOf(t, 2, audit_event.KindCrossCloudRestoreCompleted, map[string]any{"decision_id": "dec-9", "generation": 4, "bundle_sha256": bundleB, "restored_at": t0})
	config := func(p Policy, events ...audit_event.AuditEvent) Config {
		log := &memAudit{events: events}
		verifier := newStandbySide(t).verifier
		return Config{
			Policy: p, Outbox: t.TempDir(), Escrow: key, Coordinator: &kms.Coordinator{}, Audit: log, Events: log.Events, IDs: &seqIDs{},
			Clock: shared_time.NewSystemClock(), Poll: time.Millisecond, ConfirmWait: time.Second, StandbyOutbox: t.TempDir(), StandbySentinel: verifier,
		}
	}

	if e, pr, err := Resume(config(v2, decided(v2), restored)); err != nil || e == nil || pr.Released == nil {
		t.Fatalf("a confirmed failover under a v2 policy: %+v %v", pr, err)
	}
	unwired := config(v2, decided(v2), restored)
	unwired.StandbyOutbox = ""
	noVerifier := config(v2, decided(v2), restored)
	noVerifier.StandbySentinel = nil
	noClock := config(v2, decided(v2), restored)
	noClock.Clock = nil
	for name, tc := range map[string]struct {
		cfg  Config
		want string
	}{
		"a v2 policy that has not failed over":   {config(v2), "has not carried out a failover"},
		"a v1 policy that has not failed over":   {config(v1), "has not carried out a failover"},
		"a v1 policy that has: its work is done": {config(v1, decided(v1), restored), "already carried out a failover"},
		"a failover never confirmed":             {config(v2, decided(v2)), "the standby's restore was never confirmed"},
		"no outbox of the standby":               {unwired, "the standby's outbox and a verifier for its TEE are required"},
		"no verifier for the standby's TEE":      {noVerifier, "the standby's outbox and a verifier for its TEE are required"},
		"incomplete wiring":                      {noClock, "required"},
		"a log that does not agree":              {config(v2, decided(v2), eventOf(t, 2, audit_event.KindCrossCloudRestoreCompleted, map[string]any{"decision_id": "dec-9", "generation": 5})), "confirms the restore of generation 5"},
	} {
		if e, _, err := Resume(tc.cfg); e != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: executor %v, %v, want %q", name, e, err, tc.want)
		}
	}
}
