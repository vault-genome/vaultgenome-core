//go:build integration

// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Continuity Drill, live and local (ADR 0012): the primary's sentinel
// (`acpctl sentinel watch`) keeps a model genome sealed as it trains; the
// release authority (`sagvd failover`) watches its outbox under the
// operator's signed failover policy; the standby (`acp-bootstrap`) holds a
// replica of the outbox and waits. When the primary is attacked, or dies,
// the authority releases the last trustworthy genome's escrowed key to the
// standby — and nowhere else — and confirms the standby restored it and
// proved the model works.

// failoverReport is what `sagvd failover` prints.
type failoverReport struct {
	Status  string `json:"status"`
	Error   string `json:"error"`
	Trigger struct {
		Kind    string `json:"kind"`
		Tripped []struct {
			Wire   string `json:"wire"`
			Target string `json:"target"`
		} `json:"tripped"`
	} `json:"trigger"`
	Decision struct {
		Decision   string `json:"decision"`
		DecisionID string `json:"decision_id"`
	} `json:"decision"`
	Genome *struct {
		Generation uint64 `json:"generation"`
		KeyID      string `json:"key_id"`
	} `json:"genome"`
	Release *struct {
		PolicyVersion string `json:"policy_version"`
	} `json:"release"`
	Restore *struct {
		Gate *struct {
			Level string `json:"level"`
		} `json:"gate"`
		RequiredGate string `json:"required_gate"`
	} `json:"restore"`
	Timing *struct {
		RPOSeconds      float64 `json:"rpo_seconds"`
		DetectSeconds   float64 `json:"detect_seconds"`
		FailoverSeconds float64 `json:"failover_seconds"`
		RTOSeconds      float64 `json:"rto_seconds"`
	} `json:"timing"`
	AuditChainLength int `json:"audit_chain_length"`
}

type failoverRig struct {
	x         *xcc
	state     string
	outbox    string
	restored  string
	canary    string
	srcCfg    string
	escrowPEM string
	seed      string
	policy    string
}

// newFailoverRig provisions the three machines: the primary's state, key and
// canary; the standby, gating with a door that answers as the right model;
// the authority with an escrow key; and the operator's policy.
func newFailoverRig(t *testing.T, timeout string) *failoverRig {
	t.Helper()
	x := newXCC(t)
	r := &failoverRig{x: x, outbox: filepath.Join(t.TempDir(), "outbox"), restored: t.TempDir()}
	if err := os.MkdirAll(r.outbox, 0o755); err != nil {
		t.Fatal(err)
	}
	var rightResp []byte
	r.state, rightResp = modelGenomeDir(t, "AADAPwAAAMA=", "AACAPgAAQEA=") // [1.5, -2], [0.25, 3]
	right := filepath.Join(x.dir, "right.json")
	if err := os.WriteFile(right, rightResp, 0o644); err != nil {
		t.Fatal(err)
	}
	door := filepath.Join(x.dir, "door.sh")
	if err := os.WriteFile(door, []byte("#!/bin/sh\ncat >/dev/null\ncat "+right+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.canary = filepath.Join(t.TempDir(), "canary")
	writeSecret(t, r.canary, []byte("no process reads this"))

	// The standby replicates the primary's outbox; here it reads it in place.
	destCfg := x.destinationConfig(t, "standby", map[string]any{
		"genome": map[string]any{"bundle_dir": r.outbox, "restore_dir": r.restored, "rescan_seconds": 1,
			"gate": map[string]any{"command": []string{door, "{genome}"}, "atol": 1e-3, "rtol": 1e-3, "required": true}},
	})
	id := identityOf(t, bins.bootstrap, destCfg)
	x.startDestination(t, destCfg)

	escrowKey := filepath.Join(x.dir, "escrow.key")
	acpctl(t, "escrow", "keygen", "--out", escrowKey, "--pub", filepath.Join(x.dir, "escrow-local.pem"))
	cfg := x.sourceConfig(t, id, id["measurement_hex"])
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c["crosscloud"].(map[string]any)["key_escrow_path"] = escrowKey
	r.srcCfg = writeJSON(t, "sagvd-failover.json", c)
	r.escrowPEM = filepath.Join(t.TempDir(), "escrow.pem")
	writeSecret(t, r.escrowPEM, []byte(identityOf(t, bins.sagvd, r.srcCfg)["key_escrow_public_key_pem"]))

	// The primary's sentinel key, and the operator's policy pinning it.
	r.seed = filepath.Join(t.TempDir(), "sentinel.seed")
	pub := filepath.Join(t.TempDir(), "sentinel.pem")
	acpctl(t, "sentinel", "keygen", "--out", r.seed, "--pub", pub)
	r.policy = filepath.Join(x.dir, "failover.json")
	acpctl(t, "failover", "issue", "--key", x.operatorSeed, "--kid", "operator-1", "--serial", "1",
		"--sentinel-pub", pub, "--standby-kind", "simulated", "--standby-endpoint", x.endpoint,
		"--standby-measurement", id["measurement_hex"], "--heartbeat-timeout", timeout,
		"--require-gate", "EQUIVALENT", "--reason", "drill", "--out", r.policy)
	if out := acpctl(t, "failover", "verify", "--in", r.policy, "--pubkey", x.operatorPEM, "--kid", "operator-1"); !strings.Contains(out, "stands") {
		t.Fatalf("failover verify: %s", out)
	}
	return r
}

func (r *failoverRig) sentinel(t *testing.T) *proc {
	t.Helper()
	return startProc(t, "sentinel", bins.acpctl, "sentinel", "watch", "--content-dir", r.state, "--outbox", r.outbox,
		"--escrow-to", r.escrowPEM, "--key", r.seed, "--tripwire", r.canary, "--interval", "200ms", "--settle", "300ms")
}

func (r *failoverRig) executor(t *testing.T, report string) *proc {
	t.Helper()
	return startProc(t, "sagvd failover", bins.sagvd, "failover", "-config", r.srcCfg, "-policy", r.policy,
		"-outbox", r.outbox, "-poll", "200ms", "-confirm-wait", "60s", "-report", report)
}

// records counts the seal records in the outbox.
func (r *failoverRig) records(t *testing.T) int {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(r.outbox, "gen-*.seal.json"))
	if err != nil {
		t.Fatal(err)
	}
	return len(m)
}

func exitCode(p *proc) int {
	<-p.exited
	var ee *exec.ExitError
	if errors.As(p.err, &ee) {
		return ee.ExitCode()
	}
	if p.err != nil {
		return -1
	}
	return 0
}

func readReport(t *testing.T, p *proc, path string) failoverReport {
	t.Helper()
	select {
	case <-p.exited:
	case <-time.After(jobTimeout):
		t.Fatalf("sagvd failover did not finish\n%s", p.log.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no report: %v\n%s", err, p.log.String())
	}
	var rep failoverReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("report: %v\n%s", err, raw)
	}
	return rep
}

// The intrusion drill: the canary is touched and the model tampered with;
// the sentinel stops sealing and reports; the authority fails over to the
// last genome sealed before the intrusion.
func TestLiveFailover_CompromiseToStandby(t *testing.T) {
	r := newFailoverRig(t, "30s")
	primary := r.sentinel(t)
	waitFor(t, 20*time.Second, "generation 0", func() bool { return r.records(t) >= 1 })
	report := filepath.Join(t.TempDir(), "report.json")
	authority := r.executor(t, report)

	// Training goes on: a new adapter, sealed as generation 1.
	if err := os.WriteFile(filepath.Join(r.state, "adapter", "adapter_model.safetensors"), []byte("lora weights, epoch 2"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 20*time.Second, "generation 1", func() bool { return r.records(t) >= 2 })

	// The intrusion.
	writeSecret(t, r.canary, []byte("read by an intruder"))
	if code := exitCode(primary); code != 3 {
		t.Fatalf("sentinel exited %d, want 3 (compromised)\n%s", code, primary.log.String())
	}
	if err := os.WriteFile(filepath.Join(r.state, "adapter", "adapter_model.safetensors"), []byte("planted"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep := readReport(t, authority, report)
	if code := exitCode(authority); code != 0 || rep.Status != "restored" {
		t.Fatalf("sagvd failover exited %d: %+v\n%s", code, rep, authority.log.String())
	}
	if rep.Trigger.Kind != "compromise-report" || len(rep.Trigger.Tripped) != 1 || rep.Trigger.Tripped[0].Target != r.canary {
		t.Fatalf("trigger %+v", rep.Trigger)
	}
	if rep.Genome == nil || rep.Genome.Generation != 1 {
		t.Fatalf("genome %+v, want generation 1", rep.Genome)
	}
	if rep.Restore == nil || rep.Restore.Gate == nil || rep.Restore.Gate.Level != "EXACT" || rep.Restore.RequiredGate != "EQUIVALENT" {
		t.Fatalf("restore %+v", rep.Restore)
	}
	if !strings.HasSuffix(rep.Release.PolicyVersion, ";failover=1;revocation=1") {
		t.Fatalf("policy version %q", rep.Release.PolicyVersion)
	}
	restored, err := os.ReadFile(filepath.Join(r.restored, rep.Genome.KeyID, "adapter", "adapter_model.safetensors"))
	if err != nil || string(restored) != "lora weights, epoch 2" {
		t.Fatalf("the standby restored %q (%v)", restored, err)
	}
	// On record: the decision, the release (3 events), the confirmation.
	if ok, events, _ := r.x.auditVerify(t); !ok || events != 5 || rep.AuditChainLength != 5 {
		t.Fatalf("audit log: ok=%v events=%d report=%d, want 5", ok, events, rep.AuditChainLength)
	}
	t.Logf("failover: detect %.2fs, failover %.2fs, RTO %.2fs, RPO %.2fs", rep.Timing.DetectSeconds, rep.Timing.FailoverSeconds, rep.Timing.RTOSeconds, rep.Timing.RPOSeconds)

	// The policy is spent: moving again takes a new one.
	var again failoverReport
	out, err := runJSON(t, &again, bins.sagvd, "failover", "-config", r.srcCfg, "-policy", r.policy, "-outbox", r.outbox)
	if err == nil || !strings.Contains(out, "already carried out") {
		t.Fatalf("a spent policy ran again: %v\n%s", err, out)
	}
}

// The crash drill: the primary is killed outright and writes nothing more;
// its heartbeat stops rising, and the authority fails over once the
// policy's timeout has passed.
func TestLiveFailover_KilledPrimary(t *testing.T) {
	r := newFailoverRig(t, "3s")
	primary := r.sentinel(t)
	waitFor(t, 20*time.Second, "generation 0", func() bool { return r.records(t) >= 1 })
	report := filepath.Join(t.TempDir(), "report.json")
	authority := r.executor(t, report)
	time.Sleep(time.Second) // the authority sees the heartbeat rise

	if err := primary.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-primary.exited

	rep := readReport(t, authority, report)
	if code := exitCode(authority); code != 0 || rep.Status != "restored" || rep.Trigger.Kind != "heartbeat-timeout" || rep.Genome.Generation != 0 {
		t.Fatalf("sagvd failover exited %d: %+v\n%s", code, rep, authority.log.String())
	}
	if rep.Timing.DetectSeconds < 3 {
		t.Fatalf("failed over %.2fs after the last heartbeat, inside the 3s timeout", rep.Timing.DetectSeconds)
	}
	t.Logf("failover: detect %.2fs, failover %.2fs, RTO %.2fs, RPO %.2fs", rep.Timing.DetectSeconds, rep.Timing.FailoverSeconds, rep.Timing.RTOSeconds, rep.Timing.RPOSeconds)
}
