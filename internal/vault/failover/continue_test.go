// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// The standby goes on by itself (ADR 0041): what it has of its own once it
// does — its sentinel's key, the TEE that vouches for its records, and its
// outbox.
type standbySide struct {
	key      *crypto.SigningKey
	chip     *tee.Simulated
	verifier tee.Verifier
	outbox   string
}

func newStandbySide(t *testing.T) *standbySide {
	t.Helper()
	key, err := crypto.GenerateSigningKey(crypto.SuiteEd25519, nil)
	must(t, err)
	chip, err := tee.NewSimulated([]byte("standby-sentinel-v1"), bytes.Repeat([]byte{0x31}, 32))
	must(t, err)
	outbox := filepath.Join(t.TempDir(), "standby-outbox")
	must(t, os.MkdirAll(outbox, 0o755))
	return &standbySide{key: key, chip: chip, verifier: tee.NewSimulatedVerifier(chip.PublicKey(), chip.Measurement()), outbox: outbox}
}

// wait waits for the standby's sentinel to seal generation g and returns
// its record.
func (s *standbySide) wait(t *testing.T, g uint64) sentinel.SealRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rec, _, err := sentinel.ReadRecord(s.outbox, g, s.key.Public())
		if err == nil {
			return rec
		}
		if !errors.Is(err, sentinel.ErrAbsent) {
			t.Fatalf("the standby's generation %d: %v", g, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the standby did not seal generation %d", g)
	return sentinel.SealRecord{}
}

// ticked waits until the standby's sentinel has written n heartbeats: by
// then a state it was going to seal is sealed.
func (s *standbySide) ticked(t *testing.T, n uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if h, _, err := sentinel.ReadHeartbeat(s.outbox, s.key.Public()); err == nil && h.Seq >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the standby's sentinel did not reach heartbeat %d", n)
}

// turning returns d's policy naming the standby's own sentinel.
func (d *drill) turning(s *standbySide) Policy {
	d.t.Helper()
	p := d.policy()
	p.Schema = SchemaV2
	p.Standby.Sentinel = &StandbySentinel{PublicKey: s.key.Public().Bytes, Measurements: []string{hex.EncodeToString(s.chip.Measurement())}, AttestorPublicKey: s.chip.PublicKey()}
	signed, err := Sign(p, d.operator)
	must(d.t, err)
	return signed
}

// turnExecutor is d's executor under p, reading the standby's outbox at
// standbyOutbox.
func (d *drill) turnExecutor(p Policy, s *standbySide, standbyOutbox string, log *slog.Logger) *Executor {
	d.t.Helper()
	ex, err := New(Config{
		Policy: p, Outbox: d.outbox, Escrow: d.escrow, Coordinator: d.coord, Audit: d.audit, Events: d.audit.Events,
		IDs: &seqIDs{}, Clock: shared_time.NewSystemClock(), Poll: 20 * time.Millisecond, ConfirmWait: 20 * time.Second,
		StandbyOutbox: standbyOutbox, StandbySentinel: s.verifier, Log: log,
	})
	must(d.t, err)
	return ex
}

// failedOver runs the drill of TestFailoverOnCompromise: the primary seals
// two generations and is intruded on, and generation 1 is restored on the
// standby. It returns the report, what was released and the restored tree.
func (d *drill) failedOver(ex *Executor) (Report, Released, string) {
	d.t.Helper()
	reports := make(chan Report, 1)
	go func() {
		rep, err := ex.Run(context.Background())
		if err != nil {
			d.t.Errorf("executor: %v", err)
		}
		reports <- rep
	}()
	results := d.runSentinel(context.Background())
	d.waitChain(1)
	writeModel(d.t, d.state, "weights v2", 1.5, -2)
	chain := d.waitChain(2)
	must(d.t, os.WriteFile(d.canary, []byte("read by an intruder"), 0o600))
	<-results
	rep := <-reports
	if rep.Status != StatusRestored || rep.Genome == nil || rep.Genome.Generation != 1 || rep.Decision == nil {
		d.t.Fatalf("failover %+v", rep)
	}
	return rep, Released{DecisionID: rep.Decision.DecisionID, Generation: 1, BundleSHA256: rep.Genome.BundleSHA256}, filepath.Join(d.restores, chain[1].KeyID)
}

// goesOn starts the standby's own sentinel on the restored tree, the
// bundle it was restored from as its parent, the standby's TEE vouching
// for every record.
func (d *drill) goesOn(s *standbySide, restored, parentBundle string) {
	d.t.Helper()
	parent, err := bundle.Identify(parentBundle)
	must(d.t, err)
	canary := filepath.Join(d.t.TempDir(), "canary")
	must(d.t, os.WriteFile(canary, []byte("no process reads this"), 0o600))
	sn, err := sentinel.New(sentinel.Config{
		Source: dirSource{restored}, Outbox: s.outbox, Escrow: d.escrow.PublicKey(), Key: s.key, Parent: &parent,
		Attestor: s.chip, AttestorKind: tee.ProviderSimulated,
		Wires: []sentinel.Wire{&sentinel.PathWire{Path: canary}}, Interval: 20 * time.Millisecond, Settle: 40 * time.Millisecond,
	})
	must(d.t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	d.t.Cleanup(func() { cancel(); <-done })
	go func() {
		defer close(done)
		if _, err := sn.Run(ctx); err != nil {
			d.t.Errorf("the standby's sentinel: %v", err)
		}
	}()
}

// copyFile copies a file the way an outbox is replicated: under another
// name, then renamed, so a reader sees the file whole or not at all.
func copyFile(t *testing.T, from, to string) {
	t.Helper()
	raw, err := os.ReadFile(from)
	must(t, err)
	tmp := filepath.Join(filepath.Dir(to), "."+filepath.Base(to)+".arriving")
	must(t, os.WriteFile(tmp, raw, 0o644))
	must(t, os.Rename(tmp, to))
}

// replica copies an outbox as it stands: its records, bundles and
// envelopes, and not the files its sentinel is in the middle of writing.
func replica(t *testing.T, outbox string) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(outbox)
	must(t, err)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		copyFile(t, filepath.Join(outbox, e.Name()), filepath.Join(dir, e.Name()))
	}
	return dir
}

// The closed turn on the record: the primary is lost, the standby restores
// the last generation, goes on from it and seals the next under its own
// sentinel — and the authority, under the policy that named that sentinel
// before the failure, records the chain it continues.
func TestTheStandbyContinuesTheChain(t *testing.T) {
	d := newDrill(t, 1.5, -2)
	side := newStandbySide(t)
	pol := d.turning(side)
	ex := d.turnExecutor(pol, side, side.outbox, nil)
	rep, released, restored := d.failedOver(ex)
	if rep.Continued != nil {
		t.Fatalf("a failover alone continued a chain: %+v", rep.Continued)
	}

	// The standby's sentinel starts on the state as it was restored. That
	// state is its parent's: nothing is sealed from it, and nothing continues.
	d.goesOn(side, restored, filepath.Join(d.outbox, rep.Genome.Bundle))
	side.ticked(t, 6)
	c, rejected, err := FindContinuation(side.outbox, pol, released, escrowTag(d), side.verifier)
	must(t, err)
	if c != nil || rejected != nil {
		t.Fatalf("the restored state continued the chain: %+v %+v", c, rejected)
	}

	// Training goes on there, and the next state is sealed.
	writeModel(t, restored, "weights v3, trained on the standby", 1.5, -2)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rep, err = ex.Continue(ctx, rep)
	must(t, err)
	got := rep.Continued
	if got == nil || got.Generation != 2 || got.ParentGeneration != 1 || got.ParentBundleSHA256 != rep.Genome.BundleSHA256 || got.BundleSHA256 == rep.Genome.BundleSHA256 {
		t.Fatalf("continued %+v", got)
	}
	if got.Sentinel != sentinel.KeyID(side.key.Public()) || got.Sentinel == rep.Sentinel || got.MeasurementHex != hex.EncodeToString(side.chip.Measurement()) {
		t.Fatalf("recorded under %s at %s", got.Sentinel, got.MeasurementHex)
	}
	if got.SealedAfterRestoreSeconds == nil || *got.SealedAfterRestoreSeconds <= 0 || len(got.SetAside) != 0 {
		t.Fatalf("continued %+v", got)
	}

	// On the record: the failover's five events, then the chain it continues
	// — under the failover's decision ID, the policy, and the record itself.
	events := d.audit.Events()
	if kinds := d.audit.kinds(); len(kinds) != 6 || kinds[4] != audit_event.KindCrossCloudRestoreCompleted || kinds[5] != audit_event.KindChainContinued {
		t.Fatalf("audit %v", kinds)
	}
	var p continuedPayload
	must(t, json.Unmarshal(events[5].Payload, &p))
	raw, err := os.ReadFile(filepath.Join(side.outbox, sentinel.RecordName(2)))
	must(t, err)
	sum := sha256.Sum256(raw)
	if events[5].EventID != got.AuditID || p.DecisionID != rep.Decision.DecisionID || p.PolicySerial != 7 || !bytes.Equal(p.PolicySHA256, pol.Digest()) ||
		!bytes.Equal(p.RecordSHA256, sum[:]) || p.StandbyKind != tee.ProviderSimulated || p.Generation != 2 || string(p.KeyID) != got.KeyID ||
		p.ParentGeneration != 1 || p.ParentBundleSHA256 != rep.Genome.BundleSHA256 || p.RecordedAt.IsZero() {
		t.Fatalf("payload %+v", p)
	}

	// Asked again, the authority records nothing twice.
	again, err := ex.Continue(ctx, rep)
	must(t, err)
	if again.Continued == nil || again.Continued.AuditID != got.AuditID || len(d.audit.Events()) != 6 {
		t.Fatalf("asked again: %+v, %d events", again.Continued, len(d.audit.Events()))
	}

	// One serial, one failover, as before: the standby is not moved from
	// under this policy.
	if _, err := d.executor(pol); err == nil || !strings.Contains(err.Error(), "already carried out") {
		t.Fatalf("a second executor under the same policy: %v", err)
	}
}

// What does not continue the chain is set aside with its reason, or
// waited for — and nothing is recorded.
func TestWhatDoesNotContinueTheChain(t *testing.T) {
	d := newDrill(t, 1.5, -2)
	side := newStandbySide(t)
	pol := d.turning(side)
	ex := d.turnExecutor(pol, side, side.outbox, nil)
	rep, released, restored := d.failedOver(ex)
	d.goesOn(side, restored, filepath.Join(d.outbox, rep.Genome.Bundle))
	writeModel(t, restored, "weights v3", 1.5, -2)
	second := side.wait(t, 2)
	writeModel(t, restored, "weights v4", 1.5, -2)
	third := side.wait(t, 3)

	// As the standby sealed it, generation 2 continues the chain.
	sealed, rejected, err := FindContinuation(side.outbox, pol, released, escrowTag(d), side.verifier)
	must(t, err)
	if sealed == nil || rejected != nil || sealed.Record.Generation != 2 || sealed.Record.BundleSHA256 != second.BundleSHA256 {
		t.Fatalf("as sealed: %+v %+v", sealed, rejected)
	}

	// rewrite replaces generation 2's record with one made from it: signed
	// by key, and vouched for by chip when there is one.
	rewrite := func(dir string, mutate func(*sentinel.SealRecord), key *crypto.SigningKey, chip *tee.Simulated) {
		rec := second
		rec.Signature, rec.Attestation = nil, nil
		mutate(&rec)
		var err error
		if chip != nil {
			rec, err = sentinel.AttestRecord(rec, chip, tee.ProviderSimulated)
			must(t, err)
		}
		rec, err = sentinel.SignRecord(rec, key)
		must(t, err)
		raw, err := json.Marshal(rec)
		must(t, err)
		must(t, os.WriteFile(filepath.Join(dir, sentinel.RecordName(2)), raw, 0o644))
	}
	asItIs := func(*sentinel.SealRecord) {}
	another, err := tee.NewSimulated([]byte("another-machine"), bytes.Repeat([]byte{0x32}, 32))
	must(t, err)
	anotherVerifier := tee.NewSimulatedVerifier(another.PublicKey(), another.Measurement())

	for name, tc := range map[string]struct {
		scene    func(dir string) // what the authority's replica of the standby's outbox holds
		released *Released        // nil: what was released
		tag      string           // "": this authority's escrow key
		verifier tee.Verifier     // nil: the standby's
		want     string           // the reason; "": nothing there, waited for
	}{
		"signed by the primary's sentinel": {scene: func(dir string) {
			rewrite(dir, func(r *sentinel.SealRecord) { r.Sentinel = sentinel.KeyID(d.sentinelKey.Public()) }, d.sentinelKey, side.chip)
		}, want: "the pinned sentinel is " + sentinel.KeyID(side.key.Public())},
		"without the chip's report":   {scene: func(dir string) { rewrite(dir, asItIs, side.key, nil) }, want: "carries no attestation"},
		"with another chip's report":  {scene: func(dir string) { rewrite(dir, asItIs, side.key, another) }, want: "attestation does not verify"},
		"at a measurement not pinned": {scene: func(dir string) { rewrite(dir, asItIs, side.key, another) }, verifier: anotherVerifier, want: "which the policy does not pin for the standby's sentinel"},
		"a later generation under its name": {scene: func(dir string) {
			copyFile(t, filepath.Join(dir, sentinel.RecordName(3)), filepath.Join(dir, sentinel.RecordName(2)))
		}, want: "the file is generation 2, the record says 3"},
		"another parent": {released: &Released{DecisionID: released.DecisionID, Generation: 1, BundleSHA256: strings.Repeat("0", 64)}, want: "as its parent"},
		"its bundle not there yet": {scene: func(dir string) {
			must(t, os.Remove(filepath.Join(dir, second.Bundle)))
		}, want: "no such file"},
		"its bundle another": {scene: func(dir string) {
			copyFile(t, filepath.Join(dir, third.Bundle), filepath.Join(dir, second.Bundle))
		}, want: "the record says"},
		"its envelope not there yet": {scene: func(dir string) {
			must(t, os.Remove(filepath.Join(dir, second.Escrow)))
		}, want: "no such file"},
		"its key escrowed elsewhere": {tag: "another-authority", want: "its key is escrowed to"},
		"only the generation after it": {scene: func(dir string) {
			must(t, os.Remove(filepath.Join(dir, sentinel.RecordName(2))))
		}},
		"nothing at all": {scene: func(dir string) { must(t, os.RemoveAll(dir)) }},
	} {
		t.Run(name, func(t *testing.T) {
			dir := replica(t, side.outbox)
			if tc.scene != nil {
				tc.scene(dir)
			}
			rel, tag, verifier := released, escrowTag(d), side.verifier
			if tc.released != nil {
				rel = *tc.released
			}
			if tc.tag != "" {
				tag = tc.tag
			}
			if tc.verifier != nil {
				verifier = tc.verifier
			}
			c, rejected, err := FindContinuation(dir, pol, rel, tag, verifier)
			must(t, err)
			switch {
			case c != nil:
				t.Fatalf("accepted: %+v", c.Record)
			case tc.want == "" && rejected != nil:
				t.Fatalf("set aside, where there was nothing to: %+v", rejected)
			case tc.want != "" && (rejected == nil || rejected.File != sentinel.RecordName(2) || !strings.Contains(rejected.Reason, tc.want)):
				t.Fatalf("set aside %+v, want %q", rejected, tc.want)
			}
		})
	}

	// A policy that names no standby sentinel has no chain to look for.
	if _, _, err := FindContinuation(side.outbox, d.policy(), released, escrowTag(d), side.verifier); err == nil || !strings.Contains(err.Error(), "names no standby sentinel") {
		t.Fatalf("under a v1 policy: %v", err)
	}
	if n := len(d.audit.Events()); n != 5 {
		t.Fatalf("%d audit events: looking recorded something", n)
	}

	// Recorded once, under its failover — and never as another bundle, or
	// for a generation that does not follow the one released.
	first, err := ex.RecordContinuation(*sealed, released)
	must(t, err)
	same, err := ex.RecordContinuation(*sealed, released)
	must(t, err)
	if same.AuditID != first.AuditID || len(d.audit.Events()) != 6 {
		t.Fatalf("recorded twice: %s then %s, %d events", first.AuditID, same.AuditID, len(d.audit.Events()))
	}
	changed := *sealed
	changed.Record.BundleSHA256 = strings.Repeat("1", 64)
	if _, err := ex.RecordContinuation(changed, released); err == nil || !strings.Contains(err.Error(), "already records generation 2") {
		t.Fatalf("recorded as another bundle: %v", err)
	}
	if _, err := ex.RecordContinuation(Continuation{Record: third}, released); err == nil || !strings.Contains(err.Error(), "does not follow the released generation 1") {
		t.Fatalf("generation 3 recorded after generation 1: %v", err)
	}
	if _, err := ex.RecordContinuation(*sealed, Released{Generation: 1, BundleSHA256: released.BundleSHA256}); err == nil || !strings.Contains(err.Error(), "decision ID") {
		t.Fatalf("recorded under no failover: %v", err)
	}
	if n := len(d.audit.Events()); n != 6 {
		t.Fatalf("%d audit events after the refusals", n)
	}
}

// lines collects what an executor logs.
type lines struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lines) count(what string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Count(l.buf.String(), what)
}

// A generation whose files are still on their way to the authority is
// waited for: what was missing is noted once, and the generation is
// recorded when it is whole.
func TestTheContinuationIsWaitedFor(t *testing.T) {
	d := newDrill(t, 1.5, -2)
	side := newStandbySide(t)
	pol := d.turning(side)
	arriving := t.TempDir() // the authority's replica of the standby's outbox
	logged := &lines{}
	ex := d.turnExecutor(pol, side, arriving, slog.New(slog.NewTextHandler(logged, nil)))
	rep, _, restored := d.failedOver(ex)
	d.goesOn(side, restored, filepath.Join(d.outbox, rep.Genome.Bundle))
	writeModel(t, restored, "weights v3", 1.5, -2)
	second := side.wait(t, 2)

	type result struct {
		rep Report
		err error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		rep, err := ex.Continue(ctx, rep)
		done <- result{rep, err}
	}()

	// The record arrives first; the bundle and the envelope are still on
	// their way.
	const noted = "a record in the standby's outbox does not continue the chain"
	copyFile(t, filepath.Join(side.outbox, sentinel.RecordName(2)), filepath.Join(arriving, sentinel.RecordName(2)))
	for deadline := time.Now().Add(10 * time.Second); logged.count(noted) == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the missing bundle was not noted")
		}
	}
	time.Sleep(100 * time.Millisecond) // the outbox is read again and again meanwhile
	select {
	case r := <-done:
		t.Fatalf("recorded before the generation was whole: %+v %v", r.rep.Continued, r.err)
	default:
	}
	copyFile(t, filepath.Join(side.outbox, second.Bundle), filepath.Join(arriving, second.Bundle))
	copyFile(t, filepath.Join(side.outbox, second.Escrow), filepath.Join(arriving, second.Escrow))

	r := <-done
	must(t, r.err)
	got := r.rep.Continued
	if got == nil || got.Generation != 2 || got.BundleSHA256 != second.BundleSHA256 {
		t.Fatalf("continued %+v", got)
	}
	// Noted for each thing that was missing, once: the bundle, then — if
	// the outbox was read between the two copies — the envelope.
	if n := len(got.SetAside); n < 1 || n > 2 || !strings.Contains(got.SetAside[0].Reason, "no such file") || logged.count(noted) != n {
		t.Fatalf("set aside %+v, noted %d times", got.SetAside, logged.count(noted))
	}
}

// Continue is refused where there is nothing to go on from, and ends with
// its context where the standby never seals.
func TestContinueNeedsAFailoverToGoOnFrom(t *testing.T) {
	d := newDrill(t, 1.5, -2)
	side := newStandbySide(t)
	pol := d.turning(side)
	restoredReport := Report{Status: StatusRestored, Decision: &DecisionReport{DecisionID: "dec-1"}, Genome: &GenomeReport{Generation: 1, BundleSHA256: strings.Repeat("a", 64)}}

	v1, err := d.executor(d.policy())
	must(t, err)
	if _, err := v1.Continue(context.Background(), restoredReport); err == nil || !strings.Contains(err.Error(), "names no standby sentinel") {
		t.Fatalf("under a v1 policy: %v", err)
	}
	unwired, err := d.executor(pol)
	must(t, err)
	if _, err := unwired.Continue(context.Background(), restoredReport); err == nil || !strings.Contains(err.Error(), "the standby's outbox and a verifier for its TEE are required") {
		t.Fatalf("without the standby's outbox: %v", err)
	}
	ex := d.turnExecutor(pol, side, side.outbox, nil)
	for name, rep := range map[string]Report{
		"declined":    {Status: StatusDeclined, Decision: &DecisionReport{}},
		"failed":      {Status: StatusFailed, Decision: &DecisionReport{DecisionID: "dec-1"}, Genome: &GenomeReport{Generation: 1}},
		"no decision": {Status: StatusRestored, Genome: &GenomeReport{Generation: 1}},
	} {
		if _, err := ex.Continue(context.Background(), rep); err == nil || !strings.Contains(err.Error(), "no confirmed restore") {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A standby that never seals: the wait ends with its context, and the
	// report is as it was.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	rep, err := ex.Continue(ctx, restoredReport)
	if !errors.Is(err, context.DeadlineExceeded) || rep.Continued != nil {
		t.Fatalf("waiting on an empty outbox: %+v %v", rep.Continued, err)
	}
	if n := len(d.audit.Events()); n != 0 {
		t.Fatalf("%d audit events for nothing", n)
	}
}
