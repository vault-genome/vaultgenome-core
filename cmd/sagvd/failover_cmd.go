// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ai-continuity-platform/core/internal/genome/escrow"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/failover"
	"github.com/ai-continuity-platform/core/internal/vault/kms"
	"github.com/ai-continuity-platform/core/internal/vault/revocation"
)

// Exit codes of sagvd failover.
const (
	failoverExitRestored = 0 // restored and confirmed, or stopped before any trigger
	failoverExitFailed   = 1
	failoverExitDeclined = 3
)

// runFailoverCmd carries out the operator's failover policy (ADR 0012). It
// watches the primary's outbox; when a trigger the policy names fires, it
// chooses the last trustworthy genome, records the decision, releases the
// genome's escrowed key to the standby the policy names — through the
// ordinary attested release, under the operator stop — and confirms the
// standby's restore and gate from its TEE-signed receipt.
//
// Flags:
//
//	-config <path>        sagvd JSON config (required)
//	-policy <path>        the operator's signed failover policy (required)
//	-outbox <dir>         the primary's outbox, replicated here (required)
//	-poll <duration>      how often the outbox is read (default 2s)
//	-confirm-wait <dur>   how long the standby may take to restore and gate (default 15m)
//	-report <path>        also write the report here
//
// The audit log is opened to check the policy before watching, then closed
// while the executor waits, so other releases can run; it is opened again,
// and verified again, when a trigger fires.
//
// Exit codes: 0 restored (or stopped by a signal before any trigger),
// 3 declined, 1 failed. Cancelling ctx stops the watch.
func runFailoverCmd(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("sagvd failover", flag.ContinueOnError)
	var (
		configPath, policyPath, outbox, reportPath string
		poll, confirmWait                          time.Duration
	)
	fs.StringVar(&configPath, "config", "", "path to sagvd JSON config (required)")
	fs.StringVar(&policyPath, "policy", "", "the operator's signed failover policy (required)")
	fs.StringVar(&outbox, "outbox", "", "the primary's outbox, replicated here (required)")
	fs.DurationVar(&poll, "poll", 2*time.Second, "how often the outbox is read")
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
	pol, err := loadFailoverPolicy(cfg.CrossCloud.OperatorStop, policyPath)
	if err != nil {
		return failoverExitFailed, err
	}
	if err := checkDestinationEndpoint(pol.Standby.Endpoint); err != nil {
		return failoverExitFailed, err
	}
	escrowKey, err := escrow.ReadPrivate(cfg.CrossCloud.KeyEscrowPath)
	if err != nil {
		return failoverExitFailed, fmt.Errorf("failover: crosscloud.key_escrow_path: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	clock := shared_time.NewSystemClock()

	// Before watching: the policy stands, is not spent, and names a
	// standby this authority can verify.
	if err := preflightFailover(cfg, clock, pol); err != nil {
		return failoverExitFailed, err
	}
	_, sid := pol.Sentinel()
	logger.Info("failover armed", slog.Uint64("policy_serial", pol.Serial), slog.String("sentinel", sid),
		slog.String("standby", pol.Standby.Kind+" "+pol.Standby.Endpoint), slog.String("outbox", outbox))

	trig, err := failover.NewWatcher(pol, outbox, clock.Now).Watch(ctx, poll, logger)
	if err != nil {
		if ctx.Err() != nil {
			return failoverExitRestored, printFailover(failoverOutput{Report: failover.Report{Status: "stopped", PolicySerial: pol.Serial, Sentinel: sid}}, reportPath)
		}
		return failoverExitFailed, err
	}

	// A trigger fired: open the audit log again, verified end to end, and
	// act on it.
	mat, err := LoadMaterials(cfg, clock)
	if err != nil {
		return failoverExitFailed, err
	}
	xcc, err := LoadCrossCloudMaterials(cfg, clock)
	if err != nil {
		return failoverExitFailed, err
	}
	defer func() { _ = xcc.Close() }()
	coord, err := kms.NewCoordinator(kms.Config{
		AuditChain:   xcc.AuditEmitter,
		Signer:       mat.Store,
		Verifiers:    xcc.VerifierRegistry,
		Policy:       revocation.NewGate(failover.NewGate(xcc.AllowList, pol), xcc.StopList),
		Transport:    xcc.Transport,
		IDGenerator:  xcc.IDGenerator,
		NonceSource:  xcc.NonceSource,
		Clock:        clock,
		SigningKeyID: mat.AuthoritySigningKeyID,
		Receipts:     xcc.Transport,
	})
	if err != nil {
		return failoverExitFailed, err
	}
	ex, err := failover.New(failover.Config{
		Policy: pol, Outbox: outbox, Escrow: escrowKey, Coordinator: coord,
		Audit: xcc.AuditEmitter, Events: xcc.AuditChain.Events, IDs: xcc.IDGenerator, Clock: clock,
		Poll: poll, ConfirmWait: confirmWait, Log: logger,
	})
	if err != nil {
		return failoverExitFailed, err
	}
	rep, runErr := ex.Failover(ctx, *trig)
	out := failoverOutput{Report: rep, AuditChainLength: xcc.AuditChain.Len(), AuditTip: hex.EncodeToString(xcc.AuditChain.Tip()), StopSerial: xcc.StopSerial}
	if err := printFailover(out, reportPath); err != nil {
		return failoverExitFailed, err
	}
	switch {
	case runErr != nil:
		return failoverExitFailed, runErr
	case rep.Status == failover.StatusDeclined:
		return failoverExitDeclined, nil
	}
	return failoverExitRestored, nil
}

// loadFailoverPolicy verifies the policy under the operator key the stop
// list is pinned to: one operator, one key, for both.
func loadFailoverPolicy(op OperatorStopConfig, path string) (failover.Policy, error) {
	pub, err := loadAttestorPubKey(op.PublicKeyPath)
	if err != nil {
		return failover.Policy{}, fmt.Errorf("failover: crosscloud.operator_stop.public_key_path: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return failover.Policy{}, fmt.Errorf("failover: -policy: %w", err)
	}
	return failover.Parse(raw, ed25519.PublicKey(pub), op.KeyID)
}

func preflightFailover(cfg Config, clock shared_time.Clock, pol failover.Policy) error {
	xcc, err := LoadCrossCloudMaterials(cfg, clock)
	if err != nil {
		return err
	}
	defer func() { _ = xcc.Close() }()
	if !xcc.VerifierRegistry.Has(tee.Provider(pol.Standby.Kind)) {
		return fmt.Errorf("failover: the policy's standby is %s, and this authority has no verifier for it", pol.Standby.Kind)
	}
	if err := pol.ActiveAt(clock.Now()); err != nil {
		return err
	}
	return failover.CheckNotSpent(pol, xcc.AuditChain.Events())
}

// failoverOutput is the report sagvd failover prints, with the audit log's
// state after it.
type failoverOutput struct {
	failover.Report
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
