// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/failover"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// Exit codes of sagvd failover.
const (
	failoverExitRestored = 0 // restored and confirmed, or stopped by a signal
	failoverExitFailed   = 1
	failoverExitDeclined = 3 // a trigger the policy gave it nothing to do about: before a failover, or on the standby after it
)

// runFailoverCmd carries out the operator's failover policy (ADR 0012). It
// watches the primary's outbox; when a trigger the policy names fires, it
// chooses the last trustworthy genome, records the decision, releases the
// genome's escrowed key to the standby the policy names — through the
// ordinary attested release, under the operator stop — and confirms the
// standby's restore and gate from its TEE-signed receipt.
//
// Under a policy that names the standby's own sentinel it then goes on
// (ADR 0041): it records the generation with which the standby continues
// the chain (CHAIN_CONTINUED), and watches the standby as it watched the
// primary. A trigger there is declined on the record — one serial performs
// one failover — and ends the run. Started again after the failover, it
// reads from the audit log how far it got and goes on from there.
//
// Flags:
//
//	-config <path>          sagvd JSON config (required)
//	-policy <path>          the operator's signed failover policy (required)
//	-outbox <dir>           the primary's outbox, replicated here (required)
//	-standby-outbox <dir>   the standby's own outbox, replicated here: required
//	                        when the policy names the standby's sentinel
//	-poll <duration>        how often the outboxes are read (default 2s)
//	-confirm-wait <dur>     how long the standby may take to restore and gate (default 15m)
//	-report <path>          also write the report here
//
// The audit log is opened to check the policy before watching, then closed
// while the executor waits, so other releases can run; it is opened again,
// and verified again, each time there is something to record.
//
// Exit codes: 0 restored (or stopped by a signal), 3 declined — a trigger
// before the failover, or on the standby after it — and 1 failed.
// Cancelling ctx stops the watch.
func runFailoverCmd(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("sagvd failover", flag.ContinueOnError)
	var (
		configPath, policyPath, outbox, standbyOutbox, reportPath string
		poll, confirmWait                                         time.Duration
	)
	fs.StringVar(&configPath, "config", "", "path to sagvd JSON config (required)")
	fs.StringVar(&policyPath, "policy", "", "the operator's signed failover policy (required)")
	fs.StringVar(&outbox, "outbox", "", "the primary's outbox, replicated here (required)")
	fs.StringVar(&standbyOutbox, "standby-outbox", "", "the standby's own outbox, replicated here (required when the policy names the standby's sentinel)")
	fs.DurationVar(&poll, "poll", 2*time.Second, "how often the outboxes are read")
	fs.DurationVar(&confirmWait, "confirm-wait", 15*time.Minute, "how long the standby may take to restore and gate")
	fs.StringVar(&reportPath, "report", "", "also write the report to this file")
	if err := fs.Parse(args); err != nil {
		return failoverExitFailed, err
	}
	switch {
	case configPath == "" || policyPath == "" || outbox == "":
		return failoverExitFailed, errors.New("failover: -config, -policy and -outbox required")
	case poll <= 0 || confirmWait <= 0:
		return failoverExitFailed, errors.New("failover: -poll and -confirm-wait must be positive")
	}

	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return failoverExitFailed, err
	}
	if err := cfg.Validate(); err != nil {
		return failoverExitFailed, fmt.Errorf("failover: config validation: %w", err)
	}
	if !cfg.CrossCloud.Enabled {
		return failoverExitFailed, errors.New("failover: crosscloud.enabled=false in config — refusing to run")
	}
	if cfg.CrossCloud.KeyEscrowPath == "" {
		return failoverExitFailed, errors.New("failover: crosscloud.key_escrow_path required: genome keys reach the release authority only through escrow")
	}
	sigPol, err := cfg.Crypto.SignaturePolicy()
	if err != nil {
		return failoverExitFailed, fmt.Errorf("failover: crypto: %w", err)
	}
	pol, err := loadFailoverPolicy(cfg.CrossCloud.OperatorStop, policyPath, sigPol)
	if err != nil {
		return failoverExitFailed, err
	}
	switch {
	case pol.ContinuesChain() && standbyOutbox == "":
		return failoverExitFailed, errors.New("failover: the policy names the standby's sentinel: -standby-outbox required (the standby's own outbox, replicated here)")
	case !pol.ContinuesChain() && standbyOutbox != "":
		return failoverExitFailed, errors.New("failover: -standby-outbox given, and the policy names no standby sentinel")
	}
	if err := checkDestinationEndpoint(pol.Standby.Endpoint); err != nil {
		return failoverExitFailed, err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	clock := shared_time.NewSystemClock()
	// The authority's keys, the escrow key unsealed among them: held for
	// the whole watch, so a key that will not open is known before a
	// trigger, not at it.
	mat, err := LoadMaterials(cfg, clock)
	if err != nil {
		return failoverExitFailed, err
	}
	defer func() { mat.Store.Zeroize(); _ = mat.Close() }()
	if mat.Escrow == nil {
		return failoverExitFailed, errors.New("failover: crosscloud.key_escrow_path required: genome keys reach the release authority only through escrow")
	}
	logger.Info("failover escrow key", slog.String("escrow_key", escrow.KeyTag(mat.Escrow.PublicKey())), slog.String("storage", mat.EscrowSource))

	// Before watching: the policy stands and names a standby this authority
	// can verify — and how far the audit log shows its failover went.
	progress, err := preflightFailover(cfg, clock, pol)
	if err != nil {
		return failoverExitFailed, err
	}
	// The verifier for the primary's TEE, when the policy pins it: its
	// records count only with the chip's report (ADR 0017). And the one for
	// the standby's, when the policy names the standby's sentinel.
	primary, err := primaryVerifier(cfg, pol)
	if err != nil {
		return failoverExitFailed, err
	}
	standbySentinel, err := standbySentinelVerifier(cfg, pol)
	if err != nil {
		return failoverExitFailed, err
	}
	run := &failoverRun{cfg: cfg, pol: pol, clock: clock, mat: mat, logger: logger, outbox: outbox, standbyOutbox: standbyOutbox,
		poll: poll, confirmWait: confirmWait, reportPath: reportPath, primary: primary, standbySentinel: standbySentinel}
	_, sid := pol.Sentinel()

	// Started again after the failover: nothing is watched for a second
	// one. What is left is the standby's chain and the watch on the standby.
	if progress.Spent() {
		rep := failover.Report{
			Status: failover.StatusRestored, PolicySerial: pol.Serial, PolicySHA256: hex.EncodeToString(pol.Digest()), Sentinel: sid,
			Decision: &failover.DecisionReport{Decision: failover.DecisionFailover, DecisionID: progress.DecisionID},
			Genome:   &failover.GenomeReport{Generation: progress.Released.Generation, BundleSHA256: progress.Released.BundleSHA256},
		}
		// The run that carried the failover out may have left its report
		// where this one writes: its trigger, release, restore and timing
		// are in no other place, and are kept.
		if earlier, ok := earlierReport(reportPath, rep); ok {
			rep = earlier
		}
		// What the standby did since is read from the log, not from a file.
		rep.Continued, rep.StandbyTrigger = progress.Continued, nil
		out := failoverOutput{Resumed: true, Report: rep}
		logger.Info("failover taken up from the audit log", slog.Uint64("policy_serial", pol.Serial), slog.String("decision_id", string(progress.DecisionID)),
			slog.Uint64("generation", progress.Released.Generation), slog.Bool("chain_continued", progress.Continued != nil))
		if err := printFailover(out, reportPath); err != nil {
			return failoverExitFailed, err
		}
		return run.goOn(ctx, out, *progress.Released)
	}

	primaryPin := "none: the sentinel's key alone is trusted"
	if pol.PinsPrimary() {
		primaryPin = pol.Primary.Kind + " " + strings.Join(pol.Primary.Measurements, ",")
	}
	standbyOwn := "none: the run ends with the restore"
	if _, id, ok := pol.StandbySentinel(); ok {
		standbyOwn = id
	}
	logger.Info("failover armed", slog.Uint64("policy_serial", pol.Serial), slog.String("sentinel", sid), slog.String("primary_tee", primaryPin),
		slog.Int64("stopped_grace_seconds", pol.Triggers.StoppedGraceSeconds),
		slog.String("standby", pol.Standby.Kind+" "+pol.Standby.Endpoint), slog.String("standby_sentinel", standbyOwn), slog.String("outbox", outbox))

	trig, err := failover.NewWatcher(pol, outbox, clock.Now, primary).Watch(ctx, poll, logger)
	if err != nil {
		if ctx.Err() != nil {
			return failoverExitRestored, printFailover(failoverOutput{Report: failover.Report{Status: "stopped", PolicySerial: pol.Serial, Sentinel: sid}}, reportPath)
		}
		return failoverExitFailed, err
	}

	// A trigger fired: open the audit log again, verified end to end, and
	// act on it.
	var (
		rep    failover.Report
		runErr error
	)
	out, err := run.onTheLog(false, func(ex *failover.Executor) error {
		rep, runErr = ex.Failover(ctx, *trig)
		return nil
	})
	if err != nil {
		return failoverExitFailed, err
	}
	out.Report = rep
	if err := printFailover(out, reportPath); err != nil {
		return failoverExitFailed, err
	}
	switch {
	case runErr != nil:
		return failoverExitFailed, runErr
	case rep.Status == failover.StatusDeclined:
		return failoverExitDeclined, nil
	case !pol.ContinuesChain():
		return failoverExitRestored, nil
	}
	released, err := failover.ReleasedBy(rep)
	if err != nil {
		return failoverExitFailed, err
	}
	return run.goOn(ctx, out, released)
}

// earlierReport reads the report an earlier run of this failover left at
// path, and returns it when it is this failover's: restored, under the
// same policy and decision, of the same genome.
func earlierReport(path string, want failover.Report) (failover.Report, bool) {
	if path == "" {
		return failover.Report{}, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return failover.Report{}, false
	}
	var was failoverOutput
	if json.Unmarshal(raw, &was) != nil {
		return failover.Report{}, false
	}
	r := was.Report
	if r.Status != failover.StatusRestored || r.PolicySerial != want.PolicySerial || r.PolicySHA256 != want.PolicySHA256 ||
		r.Decision == nil || r.Decision.DecisionID != want.Decision.DecisionID ||
		r.Genome == nil || r.Genome.Generation != want.Genome.Generation || r.Genome.BundleSHA256 != want.Genome.BundleSHA256 {
		return failover.Report{}, false
	}
	return r, true
}

// failoverRun is one run of sagvd failover: the policy it carries out,
// and what it opens the audit log with each time there is something to
// record.
type failoverRun struct {
	cfg                   Config
	pol                   failover.Policy
	clock                 shared_time.Clock
	mat                   *materials
	logger                *slog.Logger
	outbox, standbyOutbox string
	poll, confirmWait     time.Duration
	reportPath            string
	primary               tee.Verifier
	standbySentinel       tee.Verifier
}

// onTheLog opens the audit log, verified end to end, builds the executor
// — a new one, or the one of a failover already carried out — runs act
// with it, and closes the log again. It returns the log's state after.
func (r *failoverRun) onTheLog(resumed bool, act func(*failover.Executor) error) (failoverOutput, error) {
	xcc, err := LoadCrossCloudMaterials(r.cfg, r.clock)
	if err != nil {
		return failoverOutput{}, err
	}
	defer func() { _ = xcc.Close() }()
	suites, err := r.cfg.Crypto.Policy()
	if err != nil {
		return failoverOutput{}, fmt.Errorf("crypto: %w", err)
	}
	coord, err := kms.NewCoordinator(kms.Config{
		AuditChain:   xcc.AuditEmitter,
		Signer:       r.mat.Store,
		Verifiers:    xcc.VerifierRegistry,
		Policy:       revocation.NewGate(failover.NewGate(xcc.AllowList, r.pol), xcc.StopList),
		Transport:    xcc.Transport,
		IDGenerator:  xcc.IDGenerator,
		NonceSource:  xcc.NonceSource,
		Clock:        r.clock,
		SigningKeyID: r.mat.AuthoritySigningKeyID,
		Suites:       suites,
		Receipts:     xcc.Transport,
	})
	if err != nil {
		return failoverOutput{}, err
	}
	fc := failover.Config{
		Policy: r.pol, Outbox: r.outbox, Escrow: r.mat.Escrow, Primary: r.primary, Coordinator: coord,
		Audit: xcc.AuditEmitter, Events: xcc.AuditChain.Events, IDs: xcc.IDGenerator, Clock: r.clock,
		Poll: r.poll, ConfirmWait: r.confirmWait, Log: r.logger,
		StandbyOutbox: r.standbyOutbox, StandbySentinel: r.standbySentinel,
	}
	var ex *failover.Executor
	if resumed {
		ex, _, err = failover.Resume(fc)
	} else {
		ex, err = failover.New(fc)
	}
	if err != nil {
		return failoverOutput{}, err
	}
	if err := act(ex); err != nil {
		return failoverOutput{}, err
	}
	return failoverOutput{AuditChainLength: xcc.AuditChain.Len(), AuditTip: hex.EncodeToString(xcc.AuditChain.Tip()), StopSerial: xcc.StopSerial}, nil
}

// goOn is what is left after a confirmed restore under a policy that
// names the standby's sentinel (ADR 0041). The audit log stays closed
// while it waits. It reads the standby's outbox for the generation that
// continues the chain and records it, once; and it watches the standby's
// sentinel as the primary's was watched. A trigger there is declined on
// the record and ends the run with failoverExitDeclined; a signal ends it
// with failoverExitRestored. The report is printed again each time it
// gains something.
func (r *failoverRun) goOn(ctx context.Context, out failoverOutput, released failover.Released) (int, error) {
	watcher, err := failover.NewStandbyWatcher(r.pol, r.standbyOutbox, r.clock.Now, r.standbySentinel)
	if err != nil {
		return failoverExitFailed, err
	}
	_, standbyID, _ := r.pol.StandbySentinel()
	r.logger.Info("failover goes on: the standby's chain and the standby are watched", slog.String("standby_sentinel", standbyID),
		slog.String("standby_outbox", r.standbyOutbox), slog.Uint64("after_generation", released.Generation))
	tag := escrow.KeyTag(r.mat.Escrow.PublicKey())
	var setAside []sentinel.Rejected
	seen := map[string]bool{}
	state := ""
	for {
		if out.Continued == nil {
			c, rejected, err := failover.FindContinuation(r.standbyOutbox, r.pol, released, tag, r.standbySentinel)
			if err != nil {
				return failoverExitFailed, err
			}
			if rejected != nil && !seen[rejected.Reason] {
				seen[rejected.Reason] = true
				setAside = append(setAside, *rejected)
				r.logger.Warn("a record in the standby's outbox does not continue the chain", slog.String("file", rejected.File), slog.String("reason", rejected.Reason))
			}
			if c != nil {
				var continued failover.ContinuationReport
				logState, err := r.onTheLog(true, func(ex *failover.Executor) (err error) {
					continued, err = ex.RecordContinuation(*c, released)
					return err
				})
				if err != nil {
					return failoverExitFailed, err
				}
				continued.SetAside = setAside
				out.Continued = &continued
				out.AuditChainLength, out.AuditTip, out.StopSerial = logState.AuditChainLength, logState.AuditTip, logState.StopSerial
				if err := printFailover(out, r.reportPath); err != nil {
					return failoverExitFailed, err
				}
			}
		}
		if t := watcher.Observe(); t != nil {
			r.logger.Warn("a trigger on the standby", slog.String("trigger", string(t.Kind)), slog.Time("at", t.At))
			var declined failover.StandbyTriggerReport
			logState, err := r.onTheLog(true, func(ex *failover.Executor) (err error) {
				declined, err = ex.DeclineStandbyTrigger(*t)
				return err
			})
			if err != nil {
				return failoverExitFailed, err
			}
			out.StandbyTrigger = &declined
			out.AuditChainLength, out.AuditTip, out.StopSerial = logState.AuditChainLength, logState.AuditTip, logState.StopSerial
			if err := printFailover(out, r.reportPath); err != nil {
				return failoverExitFailed, err
			}
			return failoverExitDeclined, nil
		}
		if watcher.State != state {
			state = watcher.State
			r.logger.Info("failover watch", slog.String("state", state), slog.String("watching", "the standby"))
		}
		select {
		case <-ctx.Done():
			return failoverExitRestored, nil
		case <-time.After(r.poll):
		}
	}
}

// loadFailoverPolicy verifies the policy under the operator key the stop
// list is pinned to: one operator, one key, for both.
func loadFailoverPolicy(op OperatorStopConfig, path string, sigPol kms.SignaturePolicy) (failover.Policy, error) {
	pub, err := loadSigningPublicKey(op.PublicKeyPath)
	if err != nil {
		return failover.Policy{}, fmt.Errorf("failover: crosscloud.operator_stop.public_key_path: %w", err)
	}
	if err := sigPol.CheckAcceptedKey("operator key "+op.KeyID, pub.Suite); err != nil {
		return failover.Policy{}, fmt.Errorf("failover: crosscloud.operator_stop.public_key_path: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return failover.Policy{}, fmt.Errorf("failover: -policy: %w", err)
	}
	p, err := failover.Parse(raw, pub, op.KeyID)
	if err != nil {
		return failover.Policy{}, err
	}
	// The sentinel's key the policy pins must be one this authority
	// accepts: every record of the outbox is checked under it.
	spub, sid := p.Sentinel()
	if err := sigPol.CheckAcceptedKey("the policy's sentinel key "+sid, spub.Suite); err != nil {
		return failover.Policy{}, fmt.Errorf("failover: -policy: %w", err)
	}
	// And the standby sentinel's, when the policy names it: the chain it
	// continues is checked under that one.
	if standbyPub, standbyID, ok := p.StandbySentinel(); ok {
		if err := sigPol.CheckAcceptedKey("the policy's standby sentinel key "+standbyID, standbyPub.Suite); err != nil {
			return failover.Policy{}, fmt.Errorf("failover: -policy: %w", err)
		}
	}
	return p, nil
}

// primaryVerifier builds the verifier for the primary's TEE the policy
// pins. Nil when the policy pins no primary.
func primaryVerifier(cfg Config, pol failover.Policy) (tee.Verifier, error) {
	if !pol.PinsPrimary() {
		return nil, nil
	}
	return pinnedVerifier(cfg, "primary", pol.Primary.Kind, pol.Primary.Measurements, pol.Primary.AttestorPublicKey)
}

// standbySentinelVerifier builds the verifier for the reports on the
// records of the standby's own sentinel: the standby's TEE, at the
// measurements the policy pins for that sentinel (ADR 0041). Nil when the
// policy names no standby sentinel.
func standbySentinelVerifier(cfg Config, pol failover.Policy) (tee.Verifier, error) {
	if !pol.ContinuesChain() {
		return nil, nil
	}
	s := pol.Standby.Sentinel
	return pinnedVerifier(cfg, "standby sentinel", pol.Standby.Kind, s.Measurements, s.AttestorPublicKey)
}

// pinnedVerifier builds the verifier for a TEE the policy pins a
// sentinel's records to (who: the primary, or the standby's sentinel),
// from the anchors this authority's verifier registry holds for that kind
// (the AMD chain, KDS mirror and VCEK cache of a SEV-SNP entry) and the
// measurements — and, for a simulated TEE, the attestation key — the
// policy pins.
func pinnedVerifier(cfg Config, who, kindName string, measurementsHex []string, attestor []byte) (tee.Verifier, error) {
	kind, err := tee.ParseProvider(kindName)
	if err != nil {
		return nil, fmt.Errorf("failover: %s kind: %w", who, err)
	}
	specs, err := loadVerifierSpecs(cfg.CrossCloud.VerifierRegistryPath, cfg.CrossCloud.InsecureSimulatedDestinations)
	if err != nil {
		return nil, err
	}
	var anchor *tee.VerifierSpec
	for i := range specs {
		if specs[i].Provider == kind {
			anchor = &specs[i].Spec
		}
	}
	if anchor == nil {
		return nil, fmt.Errorf("failover: the policy pins a %s %s, and this authority's verifier registry has no %s entry to take its anchors from", kind, who, kind)
	}
	measurements := make([]tee.Measurement, 0, len(measurementsHex))
	for _, m := range measurementsHex {
		b, err := hex.DecodeString(m)
		if err != nil {
			return nil, fmt.Errorf("failover: %s measurement: %w", who, err)
		}
		measurements = append(measurements, tee.Measurement(b))
	}
	switch kind {
	case tee.ProviderGCPSEVSNP:
		spec := *anchor
		spec.ExpectedMeasurement = measurements[0]
		spec.GCPSEV.AcceptableMeasurements = measurements
		return tee.BuildVerifier(spec)
	case tee.ProviderSimulated:
		// One verifier per measurement; a record verifies under any.
		verifiers := make([]tee.Verifier, 0, len(measurements))
		for _, m := range measurements {
			spec := *anchor
			spec.AttestorPubKey = crypto.PublicKey(attestor)
			spec.ExpectedMeasurement = m
			v, err := tee.BuildVerifier(spec)
			if err != nil {
				return nil, err
			}
			verifiers = append(verifiers, v)
		}
		return anyVerifier(verifiers), nil
	default:
		return nil, fmt.Errorf("failover: the policy pins a %s %s; no verifier this build can run for it (supported: gcp-sev-snp, simulated)", kind, who)
	}
}

// anyVerifier accepts evidence any of its verifiers accepts.
type anyVerifier []tee.Verifier

func (a anyVerifier) Verify(ev tee.Evidence, nonce tee.Nonce) (tee.Measurement, error) {
	m, _, err := a.VerifyDetailed(ev, nonce)
	return m, err
}

// VerifyDetailed keeps the accepting verifier's detail.
func (a anyVerifier) VerifyDetailed(ev tee.Evidence, nonce tee.Nonce) (tee.Measurement, *tee.AttestationDetail, error) {
	var last error
	for _, v := range a {
		m, d, err := tee.VerifyDetailed(v, ev, nonce)
		if err == nil {
			return m, d, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("no verifier")
	}
	return nil, nil, last
}

// preflightFailover checks, on the audit log as it stands, that this
// authority can verify the policy's standby and that the policy may run:
// it stands and is not spent — or, when it names the standby's sentinel,
// it already carried out its failover, the standby's restore was
// confirmed, and what is left is to go on. It returns how far the log
// shows the failover went.
func preflightFailover(cfg Config, clock shared_time.Clock, pol failover.Policy) (failover.Progress, error) {
	xcc, err := LoadCrossCloudMaterials(cfg, clock)
	if err != nil {
		return failover.Progress{}, err
	}
	defer func() { _ = xcc.Close() }()
	if !xcc.VerifierRegistry.Has(tee.Provider(pol.Standby.Kind)) {
		return failover.Progress{}, fmt.Errorf("failover: the policy's standby is %s, and this authority has no verifier for it", pol.Standby.Kind)
	}
	if !pol.ContinuesChain() {
		if err := pol.ActiveAt(clock.Now()); err != nil {
			return failover.Progress{}, err
		}
		return failover.Progress{}, failover.CheckNotSpent(pol, xcc.AuditChain.Events())
	}
	progress, err := failover.ReadProgress(pol, xcc.AuditChain.Events())
	switch {
	case err != nil:
		return failover.Progress{}, err
	case !progress.Spent():
		return progress, pol.ActiveAt(clock.Now())
	case progress.Released == nil:
		return failover.Progress{}, fmt.Errorf("failover: policy serial %d already carried out a failover (decision %s), and the standby's restore was never confirmed; moving again needs a new policy", pol.Serial, progress.DecisionID)
	}
	return progress, nil
}

// failoverOutput is the report sagvd failover prints, with the audit log's
// state after it.
type failoverOutput struct {
	failover.Report
	// Resumed: this run took the failover up from the audit log, after
	// it. The trigger, the release and the timing are those of the run
	// that carried it out: kept, when -report names the file that run
	// wrote, and absent otherwise.
	Resumed          bool   `json:"resumed,omitempty"`
	AuditChainLength int    `json:"audit_chain_length,omitempty"`
	AuditTip         string `json:"audit_tip,omitempty"`
	StopSerial       uint64 `json:"operator_stop_serial,omitempty"`
}

func printFailover(out failoverOutput, reportPath string) error {
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if _, err := os.Stdout.Write(raw); err != nil {
		return err
	}
	if reportPath != "" {
		return os.WriteFile(reportPath, raw, 0o644)
	}
	return nil
}
