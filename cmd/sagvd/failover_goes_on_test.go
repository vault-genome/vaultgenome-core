// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contentdir"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/failover"
)

// stateDir is a sentinel's source: a directory, read the way `acpctl
// sentinel watch --content-dir` reads one.
type stateDir struct{ dir string }

func (d stateDir) Kind() string                 { return bundle.ContentDir }
func (d stateDir) Ref() string                  { return d.dir }
func (d stateDir) Fingerprint() (string, error) { return contentdir.Fingerprint(d.dir) }
func (d stateDir) Capture() bundle.Capture {
	return func(w io.Writer) (json.RawMessage, int64, error) {
		snap, n, err := contentdir.Capture(d.dir, w)
		if err != nil {
			return nil, 0, err
		}
		raw, err := json.Marshal(snap)
		return raw, n, err
	}
}

// sealing runs a sentinel until it has sealed generation g and leaves it
// running, heartbeat and all. It returns that generation's record and the
// sentinel's canary: touching it is an intrusion.
func sealing(t *testing.T, cfg sentinel.Config, g uint64) (sentinel.SealRecord, string) {
	t.Helper()
	canary := filepath.Join(t.TempDir(), "canary")
	require.NoError(t, os.WriteFile(canary, []byte("no process reads this"), 0o600))
	require.NoError(t, os.MkdirAll(cfg.Outbox, 0o755))
	cfg.Wires, cfg.Interval, cfg.Settle = []sentinel.Wire{&sentinel.PathWire{Path: canary}}, 10*time.Millisecond, 20*time.Millisecond
	sn, err := sentinel.New(cfg)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	go func() {
		defer close(done)
		_, _ = sn.Run(ctx)
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		rec, _, err := sentinel.ReadRecord(cfg.Outbox, g, cfg.Key.Public())
		if err == nil {
			return rec, canary
		}
		require.ErrorIs(t, err, sentinel.ErrAbsent)
		require.True(t, time.Now().Before(deadline), "generation %d was not sealed", g)
	}
}

func modelState(t *testing.T, weights string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "adapter.safetensors"), []byte(weights), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "genome.json"), []byte(`{"step":1}`), 0o644))
	return dir
}

// Under a policy that names the standby's sentinel, sagvd failover started
// after the failover takes it up from the audit log (ADR 0041): it records
// the chain the standby continues, once; it watches the standby; and a
// trigger there is declined on the record, once, with exit code 3.
func TestFailoverCmd_GoesOnAfterTheFailover(t *testing.T) {
	f := newFailoverFixture(t)
	esc, err := escrow.ReadPrivate(f.cfg.CrossCloud.KeyEscrowPath)
	require.NoError(t, err)
	primaryKey, err := crypto.GenerateSigningKey(crypto.SuiteEd25519, nil)
	require.NoError(t, err)
	standbyKey, err := crypto.GenerateSigningKey(crypto.SuiteEd25519, nil)
	require.NoError(t, err)
	chip, err := tee.NewSimulated([]byte("standby-sentinel"), bytes.Repeat([]byte{0x61}, 32))
	require.NoError(t, err)
	pol := f.signedPolicy(t, string(tee.ProviderSimulated), f.operator, func(p *failover.Policy) {
		p.SentinelPublicKey = primaryKey.Public().Bytes
		p.Standby.Sentinel = &failover.StandbySentinel{PublicKey: standbyKey.Public().Bytes,
			Measurements: []string{hex.EncodeToString(chip.Measurement())}, AttestorPublicKey: chip.PublicKey()}
	})
	require.Equal(t, failover.SchemaV2, pol.Schema)
	policy := f.policyFile(t, pol)
	standbyOutbox := filepath.Join(f.dir, "standby-outbox")
	report := filepath.Join(f.dir, "report.json")
	args := []string{"-config", f.cfgPath, "-policy", policy, "-outbox", f.outbox, "-standby-outbox", standbyOutbox, "-poll", "20ms", "-report", report}

	// The flag and the policy go together.
	code, err := runFailoverCmd(context.Background(), []string{"-config", f.cfgPath, "-policy", policy, "-outbox", f.outbox})
	require.Equal(t, failoverExitFailed, code)
	require.ErrorContains(t, err, "the policy names the standby's sentinel: -standby-outbox required")
	code, err = runFailoverCmd(context.Background(), []string{"-config", f.cfgPath, "-policy", f.policy(t, string(tee.ProviderSimulated), f.operator),
		"-outbox", f.outbox, "-standby-outbox", standbyOutbox})
	require.Equal(t, failoverExitFailed, code)
	require.ErrorContains(t, err, "-standby-outbox given, and the policy names no standby sentinel")

	// The primary sealed generation 0, and the authority failed over to
	// it: the decision is on its log.
	released, _ := sealing(t, sentinel.Config{Source: stateDir{modelState(t, "weights v1")}, Outbox: f.outbox, Escrow: esc.PublicKey(), Key: primaryKey}, 0)
	emit := func(kind audit_event.Kind, payload map[string]any) {
		t.Helper()
		raw, err := json.Marshal(payload)
		require.NoError(t, err)
		xcc, err := LoadCrossCloudMaterials(f.cfg, shared_time.NewSystemClock())
		require.NoError(t, err)
		_, err = xcc.AuditEmitter.Emit(kind, raw, "", "", "")
		require.NoError(t, err)
		require.NoError(t, xcc.Close())
	}
	emit(audit_event.KindFailoverDecided, map[string]any{"decision": failover.DecisionFailover, "policy_serial": pol.Serial, "policy_sha256": pol.Digest(),
		"decision_id": "dec-live", "generation": 0, "bundle_sha256": released.BundleSHA256, "standby_kind": pol.Standby.Kind, "standby_endpoint": pol.Standby.Endpoint})

	// Decided and never confirmed: there is nothing to go on with.
	code, err = runFailoverCmd(context.Background(), args)
	require.Equal(t, failoverExitFailed, code)
	require.ErrorContains(t, err, "already carried out a failover (decision dec-live), and the standby's restore was never confirmed")
	require.NoFileExists(t, report)

	emit(audit_event.KindCrossCloudRestoreCompleted, map[string]any{"decision_id": "dec-live", "generation": 0, "bundle_sha256": released.BundleSHA256,
		"restored_at": time.Now().UTC()})

	// The standby goes on: its own sentinel, on what it trained from the
	// restored state, the restored bundle its parent.
	parent, err := bundle.Identify(filepath.Join(f.outbox, released.Bundle))
	require.NoError(t, err)
	next, canary := sealing(t, sentinel.Config{Source: stateDir{modelState(t, "weights v2, trained on the standby")}, Outbox: standbyOutbox,
		Escrow: esc.PublicKey(), Key: standbyKey, Parent: &parent, Attestor: chip, AttestorKind: tee.ProviderSimulated}, 1)

	// The run that carried the failover out left its report where this one
	// writes: what it says of the trigger and the timing is kept.
	first, err := json.Marshal(failoverOutput{AuditChainLength: 2, Report: failover.Report{
		Status: failover.StatusRestored, PolicySerial: pol.Serial, PolicySHA256: hex.EncodeToString(pol.Digest()),
		Trigger:  &failover.TriggerReport{Kind: failover.TriggerHeartbeatTimeout},
		Decision: &failover.DecisionReport{Decision: failover.DecisionFailover, DecisionID: "dec-live"},
		Genome:   &failover.GenomeReport{Generation: 0, BundleSHA256: released.BundleSHA256, KeyID: released.KeyID},
		Timing:   &failover.Timing{RPOSeconds: 2.5},
	}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(report, first, 0o644))

	// run starts the command and, when stopWhen is given, stops it by its
	// context once the report holds that; it returns the exit code and
	// the last report written.
	run := func(stopWhen string) (int, failoverOutput) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var (
			code int
			err  error
		)
		captureStdout(t, func() {
			done := make(chan struct{})
			go func() {
				defer close(done)
				code, err = runFailoverCmd(ctx, args)
			}()
			for stopWhen != "" {
				raw, _ := os.ReadFile(report)
				if strings.Contains(string(raw), stopWhen) || ctx.Err() != nil {
					cancel()
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			<-done
		})
		require.NoError(t, err)
		raw, err := os.ReadFile(report)
		require.NoError(t, err)
		var out failoverOutput
		require.NoError(t, json.Unmarshal(raw, &out), string(raw))
		return code, out
	}

	// Started again, the authority takes the failover up from its log and
	// records the chain the standby continues.
	code, out := run(`"continued"`)
	require.Equal(t, failoverExitRestored, code)
	require.True(t, out.Resumed)
	require.Equal(t, failover.StatusRestored, out.Status)
	require.EqualValues(t, "dec-live", out.Decision.DecisionID)
	require.NotNil(t, out.Timing, "the earlier run's report is kept")
	require.Equal(t, 2.5, out.Timing.RPOSeconds)
	require.EqualValues(t, failover.TriggerHeartbeatTimeout, out.Trigger.Kind)
	require.Equal(t, released.KeyID, out.Genome.KeyID)
	require.NotNil(t, out.Continued)
	require.Equal(t, uint64(1), out.Continued.Generation)
	require.Equal(t, next.BundleSHA256, out.Continued.BundleSHA256)
	require.Equal(t, released.BundleSHA256, out.Continued.ParentBundleSHA256)
	require.Equal(t, sentinel.KeyID(standbyKey.Public()), out.Continued.Sentinel)
	require.Equal(t, hex.EncodeToString(chip.Measurement()), out.Continued.MeasurementHex)
	require.NotNil(t, out.Continued.SealedAfterRestoreSeconds)
	require.Nil(t, out.StandbyTrigger)
	require.Equal(t, 3, out.AuditChainLength)

	// The standby is intruded on. Started once more, the authority finds
	// the chain on record, sees the standby's report and declines: this
	// policy names nowhere further to go.
	require.NoError(t, os.WriteFile(canary, []byte("read by an intruder"), 0o600))
	require.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join(standbyOutbox, sentinel.CompromiseFile))
		return err == nil
	}, 10*time.Second, 10*time.Millisecond, "the standby's sentinel did not report")
	code, out = run("")
	require.Equal(t, failoverExitDeclined, code)
	require.True(t, out.Resumed)
	require.NotNil(t, out.Continued, "the chain is read from the log")
	require.Equal(t, next.BundleSHA256, out.Continued.BundleSHA256)
	require.NotNil(t, out.StandbyTrigger)
	require.EqualValues(t, failover.TriggerCompromise, out.StandbyTrigger.Trigger.Kind)
	require.Equal(t, hex.EncodeToString(chip.Measurement()), out.StandbyTrigger.Trigger.PrimaryMeasurementHex)
	require.Equal(t, failover.DecisionDeclined, out.StandbyTrigger.Decision.Decision)
	require.Contains(t, out.StandbyTrigger.Decision.Reason, "names nowhere further to go")
	require.Equal(t, 4, out.AuditChainLength)
	declined := out.StandbyTrigger.Decision.AuditID

	// And once more: the same trigger is on record already, and is not
	// recorded twice.
	code, out = run("")
	require.Equal(t, failoverExitDeclined, code)
	require.Equal(t, declined, out.StandbyTrigger.Decision.AuditID)
	require.Equal(t, 4, out.AuditChainLength)

	xcc, err := LoadCrossCloudMaterials(f.cfg, shared_time.NewSystemClock())
	require.NoError(t, err)
	defer func() { _ = xcc.Close() }()
	var kinds []string
	for _, e := range xcc.AuditChain.Events() {
		kinds = append(kinds, string(e.Kind))
	}
	require.Equal(t, []string{"FAILOVER_DECIDED", "CROSS_CLOUD_RESTORE_COMPLETED", "CHAIN_CONTINUED", "FAILOVER_DECIDED"}, kinds)
}

// A report found where this run writes is kept only when it is this
// failover's.
func TestEarlierReportIsKeptOnlyWhenItIsThisFailovers(t *testing.T) {
	dir := t.TempDir()
	want := failover.Report{Status: failover.StatusRestored, PolicySerial: 4, PolicySHA256: strings.Repeat("ab", 32),
		Decision: &failover.DecisionReport{DecisionID: "dec-1"}, Genome: &failover.GenomeReport{Generation: 3, BundleSHA256: strings.Repeat("cd", 32)}}
	write := func(name string, mutate func(*failover.Report)) string {
		r := want
		decision, genome := *want.Decision, *want.Genome
		r.Decision, r.Genome = &decision, &genome
		r.Timing = &failover.Timing{RTOSeconds: 9}
		mutate(&r)
		raw, err := json.Marshal(failoverOutput{Report: r})
		require.NoError(t, err)
		return writeFile(t, dir, name, raw)
	}
	got, ok := earlierReport(write("same.json", func(*failover.Report) {}), want)
	require.True(t, ok)
	require.Equal(t, 9.0, got.Timing.RTOSeconds)

	for name, path := range map[string]string{
		"no path":             "",
		"no file":             filepath.Join(dir, "absent.json"),
		"not a report":        writeFile(t, dir, "junk.json", []byte("{")),
		"another policy":      write("policy.json", func(r *failover.Report) { r.PolicySHA256 = strings.Repeat("ef", 32) }),
		"another serial":      write("serial.json", func(r *failover.Report) { r.PolicySerial = 5 }),
		"another decision":    write("decision.json", func(r *failover.Report) { r.Decision.DecisionID = "dec-2" }),
		"no decision":         write("nodecision.json", func(r *failover.Report) { r.Decision = nil }),
		"another generation":  write("generation.json", func(r *failover.Report) { r.Genome.Generation = 4 }),
		"another bundle":      write("bundle.json", func(r *failover.Report) { r.Genome.BundleSHA256 = strings.Repeat("00", 32) }),
		"no genome":           write("nogenome.json", func(r *failover.Report) { r.Genome = nil }),
		"a failover declined": write("declined.json", func(r *failover.Report) { r.Status = failover.StatusDeclined }),
		"a run stopped":       write("stopped.json", func(r *failover.Report) { r.Status = "stopped" }),
	} {
		_, ok := earlierReport(path, want)
		require.False(t, ok, name)
	}
}

// The standby sentinel's records are verified by a kind this build can
// verify, from the anchors the registry holds for the standby's kind — and
// by nothing under a policy that names no standby sentinel.
func TestStandbySentinelVerifier(t *testing.T) {
	f := newFailoverFixture(t)
	chip, err := tee.NewSimulated([]byte("standby-sentinel"), bytes.Repeat([]byte{0x61}, 32))
	require.NoError(t, err)
	key, err := crypto.GenerateSigningKey(crypto.SuiteEd25519, nil)
	require.NoError(t, err)
	named := func(p *failover.Policy) {
		p.Standby.Sentinel = &failover.StandbySentinel{PublicKey: key.Public().Bytes, Measurements: []string{hex.EncodeToString(chip.Measurement())}, AttestorPublicKey: chip.PublicKey()}
	}
	v, err := standbySentinelVerifier(f.cfg, f.signedPolicy(t, string(tee.ProviderSimulated), f.operator))
	require.NoError(t, err)
	require.Nil(t, v)

	pol := f.signedPolicy(t, string(tee.ProviderSimulated), f.operator, named)
	v, err = standbySentinelVerifier(f.cfg, pol)
	require.NoError(t, err)
	now := time.Now().UTC()
	h, err := sentinel.AttestHeartbeat(sentinel.Heartbeat{Sentinel: sentinel.KeyID(key.Public()), Seq: 1, At: now, StartedAt: now, Status: sentinel.StatusWatching}, chip, tee.ProviderSimulated)
	require.NoError(t, err)
	h, err = sentinel.SignHeartbeat(h, key)
	require.NoError(t, err)
	m, err := h.Attested(v)
	require.NoError(t, err)
	require.True(t, pol.StandbySentinelAllows(m))
	stranger, err := tee.NewSimulated([]byte("standby-sentinel"), bytes.Repeat([]byte{0x62}, 32))
	require.NoError(t, err)
	h2, err := sentinel.AttestHeartbeat(sentinel.Heartbeat{Sentinel: sentinel.KeyID(key.Public()), Seq: 2, At: now, StartedAt: now, Status: sentinel.StatusWatching}, stranger, tee.ProviderSimulated)
	require.NoError(t, err)
	h2, err = sentinel.SignHeartbeat(h2, key)
	require.NoError(t, err)
	_, err = h2.Attested(v)
	require.Error(t, err)

	// A standby of a kind whose sentinel this build cannot verify is
	// refused before anything is watched.
	meas := makeMeasurementHex(0x55)
	f.cfg.CrossCloud.VerifierRegistryPath = writeFile(t, f.dir, "registry-two.json", []byte(`{"verifiers":[{"provider":"simulated","attestor_pubkey_path":"`+
		writeFile(t, f.dir, "attestor2.pub", generateEd25519PubRaw(t))+`","expected_measurement_hex":"`+meas+`"},{"provider":"gcp-tdx","expected_measurement_hex":"`+strings.Repeat("ab", 48)+`"}]}`))
	f.write(t, "twokinds.json")
	tdx := f.signedPolicy(t, string(tee.ProviderGCPTDX), f.operator, func(p *failover.Policy) {
		p.Standby.Measurements = []string{strings.Repeat("ab", 48)}
		p.Standby.Sentinel = &failover.StandbySentinel{PublicKey: key.Public().Bytes, Measurements: []string{strings.Repeat("ab", 48)}}
	})
	code, err := runFailoverCmd(context.Background(), []string{"-config", f.cfgPath, "-policy", f.policyFile(t, tdx), "-outbox", f.outbox, "-standby-outbox", t.TempDir()})
	require.Equal(t, failoverExitFailed, code)
	require.ErrorContains(t, err, "the policy pins a gcp-tdx standby sentinel; no verifier this build can run for it")
}
