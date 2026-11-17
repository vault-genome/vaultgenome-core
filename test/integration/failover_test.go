//go:build integration

// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	Resumed bool   `json:"resumed"`
	Trigger struct {
		Kind    string `json:"kind"`
		Tripped []struct {
			Wire   string `json:"wire"`
			Target string `json:"target"`
		} `json:"tripped"`
		PrimaryMeasurementHex string `json:"primary_measurement_hex"`
	} `json:"trigger"`
	Decision struct {
		Decision   string `json:"decision"`
		Reason     string `json:"reason"`
		DecisionID string `json:"decision_id"`
	} `json:"decision"`
	Ignored  []string `json:"ignored"`
	SetAside []struct {
		File   string `json:"file"`
		Reason string `json:"reason"`
	} `json:"set_aside"`
	Genome *struct {
		Generation   uint64 `json:"generation"`
		KeyID        string `json:"key_id"`
		BundleSHA256 string `json:"bundle_sha256"`
	} `json:"genome"`
	// Under a policy that names the standby's sentinel (ADR 0041): the
	// chain the standby went on with, and a trigger there, declined.
	Continued *struct {
		Sentinel                  string   `json:"sentinel"`
		Generation                uint64   `json:"generation"`
		BundleSHA256              string   `json:"bundle_sha256"`
		KeyID                     string   `json:"key_id"`
		ParentGeneration          uint64   `json:"parent_generation"`
		ParentBundleSHA256        string   `json:"parent_bundle_sha256"`
		SealedAfterRestoreSeconds *float64 `json:"sealed_after_restore_seconds"`
	} `json:"continued"`
	StandbyTrigger *struct {
		Trigger struct {
			Kind string `json:"kind"`
		} `json:"trigger"`
		Decision struct {
			Decision string `json:"decision"`
			Reason   string `json:"reason"`
		} `json:"decision"`
	} `json:"standby_trigger"`
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
	// teeSeed and teeDescriptor name the primary's simulated TEE when the
	// rig attests (ADR 0017); empty otherwise.
	teeSeed, teeDescriptor string
	// What the standby goes on with (ADR 0041), when the rig has it do so:
	// its own outbox, and where its sentinel's process ID is written.
	standbyOutbox, standbySentinelPID string
}

// rigOptions shape a rig: the primary attested by a (simulated) TEE and
// pinned in the policy, a grace on `stopped`, and a standby that goes on
// by itself after a restore, its sentinel named in the policy.
type rigOptions struct {
	attested     bool
	stoppedGrace string
	goesOn       bool
}

// newFailoverRig provisions the three machines: the primary's state, key and
// canary; the standby, gating with a door that answers as the right model;
// the authority with an escrow key sealed to its (simulated) TEE; and the
// operator's policy.
func newFailoverRig(t *testing.T, timeout string, opts ...rigOptions) *failoverRig {
	t.Helper()
	var o rigOptions
	if len(opts) > 0 {
		o = opts[0]
	}
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
	r.escrowPEM = filepath.Join(t.TempDir(), "escrow.pem")
	genomeCfg := map[string]any{"bundle_dir": r.outbox, "restore_dir": r.restored, "rescan_seconds": 1,
		"gate": map[string]any{"command": []string{door, "{genome}"}, "atol": 1e-3, "rtol": 1e-3, "required": true}}
	var standbySentinel []string
	if o.goesOn {
		standbySentinel = r.standbyGoesOn(t, genomeCfg)
	}
	destCfg := x.destinationConfig(t, "standby", map[string]any{"genome": genomeCfg})
	id := identityOf(t, bins.bootstrap, destCfg)
	x.startDestination(t, destCfg)

	// The authority's escrow key: made in its own process and written
	// sealed to its TEE (ADR 0016); the public half goes to the primary.
	cfg := x.sourceConfig(t, id, id["measurement_hex"])
	escrowSealed := filepath.Join(x.dir, "escrow.sealed")
	var provisioned struct {
		EscrowKey string `json:"escrow_key"`
		TEE       string `json:"tee"`
	}
	if out, err := runJSON(t, &provisioned, bins.sagvd, "escrow-provision", "-config", cfg, "-out", escrowSealed, "-pub", filepath.Join(x.dir, "escrow-local.pem")); err != nil || provisioned.TEE != "simulated" {
		t.Fatalf("escrow-provision: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c["crosscloud"].(map[string]any)["key_escrow_path"] = escrowSealed
	r.srcCfg = writeJSON(t, "sagvd-failover.json", c)
	authority := identityOf(t, bins.sagvd, r.srcCfg)
	if authority["key_escrow_tag"] != provisioned.EscrowKey || authority["key_escrow_storage"] != "sealed:simulated" {
		t.Fatalf("identity %+v, want escrow key %s sealed", authority, provisioned.EscrowKey)
	}
	writeSecret(t, r.escrowPEM, []byte(authority["key_escrow_public_key_pem"]))

	// The primary's sentinel key, and the operator's policy pinning it.
	r.seed = filepath.Join(t.TempDir(), "sentinel.seed")
	pub := filepath.Join(t.TempDir(), "sentinel.pem")
	acpctl(t, "sentinel", "keygen", "--out", r.seed, "--pub", pub)
	r.policy = filepath.Join(x.dir, "failover.json")
	issue := []string{"failover", "issue", "--key", x.operatorSeed, "--kid", "operator-1", "--serial", "1",
		"--sentinel-pub", pub, "--standby-kind", "simulated", "--standby-endpoint", x.endpoint,
		"--standby-measurement", id["measurement_hex"], "--heartbeat-timeout", timeout,
		"--require-gate", "EQUIVALENT", "--reason", "drill", "--out", r.policy}
	if o.stoppedGrace != "" {
		issue = append(issue, "--stopped-grace", o.stoppedGrace)
	}
	issue = append(issue, standbySentinel...)
	if o.attested {
		// The primary's TEE, simulated: its identity is what the operator
		// pins, and the sentinel attests every record with it.
		r.teeSeed = filepath.Join(t.TempDir(), "primary-tee.seed")
		writeSecret(t, r.teeSeed, []byte(strings.Repeat("p", 32)))
		r.teeDescriptor = "primary-drill-v1"
		var primary struct {
			TEE            string `json:"tee"`
			MeasurementHex string `json:"measurement_hex"`
			AttestorPEM    string `json:"attestor_public_key_pem"`
		}
		if out, err := runJSON(t, &primary, bins.acpctl, "sentinel", "identity", "--tee", "simulated", "--tee-seed", r.teeSeed, "--workload-descriptor", r.teeDescriptor); err != nil {
			t.Fatalf("sentinel identity: %v\n%s", err, out)
		}
		attestorPub := filepath.Join(x.dir, "primary-attestor.pem")
		writeSecret(t, attestorPub, []byte(primary.AttestorPEM))
		issue = append(issue, "--primary-kind", primary.TEE, "--primary-measurement", primary.MeasurementHex, "--primary-attestor-pub", attestorPub)
	}
	acpctl(t, issue...)
	if out := acpctl(t, "failover", "verify", "--in", r.policy, "--pubkey", x.operatorPEM, "--kid", "operator-1"); !strings.Contains(out, "stands") {
		t.Fatalf("failover verify: %s", out)
	}
	return r
}

func (r *failoverRig) sentinel(t *testing.T) *proc {
	t.Helper()
	args := []string{"sentinel", "watch", "--content-dir", r.state, "--outbox", r.outbox,
		"--escrow-to", r.escrowPEM, "--key", r.seed, "--tripwire", r.canary, "--interval", "200ms", "--settle", "300ms"}
	if r.teeSeed != "" {
		args = append(args, "--tee", "simulated", "--tee-seed", r.teeSeed, "--workload-descriptor", r.teeDescriptor)
	}
	return startProc(t, "sentinel", bins.acpctl, args...)
}

func (r *failoverRig) executor(t *testing.T, report string) *proc {
	t.Helper()
	args := []string{"failover", "-config", r.srcCfg, "-policy", r.policy,
		"-outbox", r.outbox, "-poll", "200ms", "-confirm-wait", "60s", "-report", report}
	if r.standbyOutbox != "" {
		args = append(args, "-standby-outbox", r.standbyOutbox)
	}
	return startProc(t, "sagvd failover", bins.sagvd, args...)
}

// standbyGoesOn provisions what the standby goes on with after a restore
// (ADR 0041): its own sentinel's key and (simulated) TEE, an outbox of
// its own, and the one command acp-bootstrap runs once its gate has
// passed. The command starts that sentinel on the restored tree, the
// bundle it was restored from as its parent; then training goes on — a
// new adapter, a moment later. It returns the flags that name the
// sentinel in the operator's policy.
func (r *failoverRig) standbyGoesOn(t *testing.T, genomeCfg map[string]any) []string {
	t.Helper()
	dir := t.TempDir()
	seed, pub := filepath.Join(dir, "standby-sentinel.seed"), filepath.Join(dir, "standby-sentinel.pem")
	acpctl(t, "sentinel", "keygen", "--out", seed, "--pub", pub)
	teeSeed := filepath.Join(dir, "standby-tee.seed")
	writeSecret(t, teeSeed, []byte(strings.Repeat("s", 32)))
	const descriptor = "standby-drill-v1"
	var identity struct {
		MeasurementHex string `json:"measurement_hex"`
		AttestorPEM    string `json:"attestor_public_key_pem"`
	}
	if out, err := runJSON(t, &identity, bins.acpctl, "sentinel", "identity", "--tee", "simulated", "--tee-seed", teeSeed, "--workload-descriptor", descriptor); err != nil {
		t.Fatalf("sentinel identity: %v\n%s", err, out)
	}
	attestorPub := filepath.Join(dir, "standby-attestor.pem")
	writeSecret(t, attestorPub, []byte(identity.AttestorPEM))
	r.standbyOutbox, r.standbySentinelPID = filepath.Join(dir, "outbox"), filepath.Join(dir, "sentinel.pid")
	if err := os.MkdirAll(r.standbyOutbox, 0o755); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(dir, "canary")
	writeSecret(t, canary, []byte("no process reads this"))
	q := func(path string) string { return "'" + path + "'" }
	script := filepath.Join(dir, "go-on.sh")
	body := "#!/bin/sh\n" +
		"# What the standby runs after a restore its gate passed: $1 the restored tree, $2 the bundle it came from.\n" +
		"# A later restore on a machine that already goes on starts nothing again.\n" +
		"[ -e " + q(filepath.Join(dir, "going-on")) + " ] && exit 0\n" +
		": > " + q(filepath.Join(dir, "going-on")) + "\n" +
		q(bins.acpctl) + " sentinel watch --content-dir \"$1\" --outbox " + q(r.standbyOutbox) + " --escrow-to " + q(r.escrowPEM) + " --key " + q(seed) +
		" --parent \"$2\" --tee simulated --tee-seed " + q(teeSeed) + " --workload-descriptor " + descriptor +
		" --tripwire " + q(canary) + " --interval 200ms --settle 300ms >" + q(filepath.Join(dir, "sentinel.log")) + " 2>&1 &\n" +
		"echo $! > " + q(r.standbySentinelPID) + "\n" +
		"( sleep 1; printf 'lora weights, epoch 3, trained on the standby' > \"$1/adapter/adapter_model.safetensors\" ) >/dev/null 2>&1 &\n" +
		"exit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	genomeCfg["after_restore"] = map[string]any{"command": []string{script, "{genome}", "{bundle}"}, "timeout_seconds": 30}
	t.Cleanup(func() {
		r.killStandbySentinel()
		if t.Failed() {
			if raw, err := os.ReadFile(filepath.Join(dir, "sentinel.log")); err == nil {
				t.Logf("---- the standby's sentinel ----\n%s", raw)
			}
		}
	})
	return []string{"--standby-sentinel-pub", pub, "--standby-sentinel-measurement", identity.MeasurementHex, "--standby-sentinel-attestor-pub", attestorPub}
}

// killStandbySentinel kills the sentinel the standby started, without a
// word: the standby is gone.
func (r *failoverRig) killStandbySentinel() {
	raw, err := os.ReadFile(r.standbySentinelPID)
	if err != nil {
		return
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil {
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Kill()
		}
	}
}

// peekReport reads the report a running `sagvd failover` last wrote, if
// it has written one.
func peekReport(path string) (failoverReport, bool) {
	var rep failoverReport
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &rep) != nil {
		return failoverReport{}, false
	}
	return rep, true
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

// The primary attested (ADR 0017): its records carry its TEE's report, the
// policy pins its measurement, and the drill runs as before — the decision
// naming the primary. Then the seed is stolen and used off the chip: a
// rogue sentinel's records are ignored, the silence is a trigger, and
// nothing in the rogue outbox is trusted, so the second policy declines.
func TestLiveFailover_AttestedPrimary(t *testing.T) {
	r := newFailoverRig(t, "3s", rigOptions{attested: true})
	primary := r.sentinel(t)
	waitFor(t, 20*time.Second, "generation 0", func() bool { return r.records(t) >= 1 })
	report := filepath.Join(t.TempDir(), "report.json")
	authority := r.executor(t, report)
	if err := os.WriteFile(filepath.Join(r.state, "adapter", "adapter_model.safetensors"), []byte("lora weights, epoch 2"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 20*time.Second, "generation 1", func() bool { return r.records(t) >= 2 })
	writeSecret(t, r.canary, []byte("read by an intruder"))
	if code := exitCode(primary); code != 3 {
		t.Fatalf("sentinel exited %d, want 3 (compromised)\n%s", code, primary.log.String())
	}
	rep := readReport(t, authority, report)
	if code := exitCode(authority); code != 0 || rep.Status != "restored" || rep.Trigger.Kind != "compromise-report" || rep.Genome == nil || rep.Genome.Generation != 1 {
		t.Fatalf("sagvd failover exited %d: %+v\n%s", code, rep, authority.log.String())
	}
	if rep.Trigger.PrimaryMeasurementHex == "" {
		t.Fatalf("the trigger names no primary measurement: %+v", rep.Trigger)
	}
	if ok, events, _ := r.x.auditVerify(t); !ok || events != 5 {
		t.Fatalf("audit log: ok=%v events=%d", ok, events)
	}

	// The seed stolen, the chip not. The thief copies the outbox to a
	// machine of their own (another simulated TEE), drops the compromise
	// report, and runs a sentinel there with the stolen seed: it seals a
	// generation 2 of its own and heartbeats, every record attested by the
	// wrong chip. A second policy pins the primary as before. The rogue's
	// records are ignored, the silence after the primary's last genuine
	// word is the trigger, nothing past that word is trusted, and the
	// quarantine declines the rest: no key moves.
	rogueOutbox := filepath.Join(t.TempDir(), "rogue-outbox")
	copyDir(t, r.outbox, rogueOutbox)
	if err := os.Remove(filepath.Join(rogueOutbox, "compromise.json")); err != nil {
		t.Fatal(err)
	}
	var p1 struct {
		Primary struct {
			Measurements []string `json:"measurements"`
		} `json:"primary"`
		Standby struct {
			Measurements []string `json:"measurements"`
		} `json:"standby"`
	}
	raw, err := os.ReadFile(r.policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &p1); err != nil {
		t.Fatal(err)
	}
	policy2 := filepath.Join(r.x.dir, "failover-2.json")
	acpctl(t, "failover", "issue", "--key", r.x.operatorSeed, "--kid", "operator-1", "--serial", "2",
		"--sentinel-pub", sentinelPubOf(t, r.seed), "--standby-kind", "simulated", "--standby-endpoint", r.x.endpoint,
		"--standby-measurement", p1.Standby.Measurements[0], "--no-compromise-trigger", "--heartbeat-timeout", "2s", "--quarantine", "24h",
		"--primary-kind", "simulated", "--primary-measurement", p1.Primary.Measurements[0], "--primary-attestor-pub", filepath.Join(r.x.dir, "primary-attestor.pem"),
		"--require-gate", "EQUIVALENT", "--reason", "a stolen seed off the pinned chip", "--out", policy2)
	report2 := filepath.Join(t.TempDir(), "rogue-report.json")
	second := startProc(t, "sagvd failover (rogue)", bins.sagvd, "failover", "-config", r.srcCfg, "-policy", policy2,
		"-outbox", rogueOutbox, "-poll", "200ms", "-confirm-wait", "10s", "-report", report2)
	waitFor(t, 20*time.Second, "the second executor watching the genuine heartbeat", func() bool {
		return strings.Contains(second.log.String(), `"state":"watching"`)
	})
	if err := os.WriteFile(filepath.Join(r.state, "adapter", "adapter_model.safetensors"), []byte("weights of the thief"), 0o644); err != nil {
		t.Fatal(err)
	}
	rogueTEE := filepath.Join(t.TempDir(), "rogue-tee.seed")
	writeSecret(t, rogueTEE, []byte(strings.Repeat("r", 32)))
	rogue := startProc(t, "rogue sentinel", bins.acpctl, "sentinel", "watch", "--content-dir", r.state, "--outbox", rogueOutbox,
		"--escrow-to", r.escrowPEM, "--key", r.seed, "--interval", "200ms", "--settle", "0s",
		"--tee", "simulated", "--tee-seed", rogueTEE, "--workload-descriptor", "the-thief's-machine")
	waitFor(t, 20*time.Second, "the rogue's generation 2", func() bool { _, err := os.Stat(filepath.Join(rogueOutbox, "gen-000002.seal.json")); return err == nil })
	rep2 := readReport(t, second, report2)
	_ = rogue.cmd.Process.Kill()
	<-rogue.exited
	if code := exitCode(second); code != 3 || rep2.Status != "declined" || rep2.Trigger.Kind != "heartbeat-timeout" {
		t.Fatalf("rogue: sagvd failover exited %d: %+v\n%s", code, rep2, second.log.String())
	}
	if rep2.Trigger.PrimaryMeasurementHex != rep.Trigger.PrimaryMeasurementHex {
		t.Fatalf("the trigger was attested by %q, want the primary's %q", rep2.Trigger.PrimaryMeasurementHex, rep.Trigger.PrimaryMeasurementHex)
	}
	// Refused either way: the wrong measurement under the verifier, or a
	// measurement the policy does not pin.
	refused := false
	for _, note := range rep2.Ignored {
		if strings.Contains(note, "does not pin as the primary") || strings.Contains(note, "attestation does not verify") {
			refused = true
		}
	}
	if !refused {
		t.Fatalf("the rogue's attested records were not refused: %v", rep2.Ignored)
	}
	pastTheWord := false
	for _, r := range rep2.SetAside {
		if r.File == "gen-000002.seal.json" && strings.Contains(r.Reason, "after generation 1") {
			pastTheWord = true
		}
	}
	if !pastTheWord || !strings.Contains(rep2.Decision.Reason, "no genome in the verified chain") {
		t.Fatalf("set aside %+v; declined for %q", rep2.SetAside, rep2.Decision.Reason)
	}
	if ok, events, _ := r.x.auditVerify(t); !ok || events != 6 {
		t.Fatalf("audit log after the decline: ok=%v events=%d, want 6 (one more FAILOVER_DECIDED)", ok, events)
	}
}

// A sentinel stopped by its operator stands the authority down for the
// policy's grace, no longer: not back in time, the primary fails over.
func TestLiveFailover_StoppedOverdue(t *testing.T) {
	r := newFailoverRig(t, "30s", rigOptions{stoppedGrace: "2s"})
	primary := r.sentinel(t)
	waitFor(t, 20*time.Second, "generation 0", func() bool { return r.records(t) >= 1 })
	report := filepath.Join(t.TempDir(), "report.json")
	authority := r.executor(t, report)
	time.Sleep(time.Second)
	if err := primary.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if code := exitCode(primary); code != 0 {
		t.Fatalf("sentinel exited %d on SIGINT, want 0 (stopped)\n%s", code, primary.log.String())
	}
	rep := readReport(t, authority, report)
	if code := exitCode(authority); code != 0 || rep.Status != "restored" || rep.Trigger.Kind != "stopped-overdue" || rep.Genome.Generation != 0 {
		t.Fatalf("sagvd failover exited %d: %+v\n%s", code, rep, authority.log.String())
	}
	if !strings.Contains(authority.log.String(), "standing down for") {
		t.Fatalf("the authority did not stand down first\n%s", authority.log.String())
	}
}

// The closed turn, live (ADR 0041). The primary is intruded on, and the
// authority fails over to the last trustworthy genome. The standby's gate
// passes and the standby goes on by itself: acp-bootstrap runs its one
// command, which starts the standby's own sentinel on the restored tree,
// and training goes on there. The authority does not exit. It records the
// generation the standby seals as the chain's next, under the policy that
// named that sentinel before the failure. Restarted, it takes the failover
// up from its audit log. And when the standby is lost in its turn, that
// is on the record as declined: the policy names nowhere further to go.
func TestLiveFailover_TheStandbyGoesOn(t *testing.T) {
	r := newFailoverRig(t, "3s", rigOptions{goesOn: true})
	primary := r.sentinel(t)
	waitFor(t, 20*time.Second, "generation 0", func() bool { return r.records(t) >= 1 })
	report := filepath.Join(t.TempDir(), "report.json")
	authority := r.executor(t, report)
	if err := os.WriteFile(filepath.Join(r.state, "adapter", "adapter_model.safetensors"), []byte("lora weights, epoch 2"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 20*time.Second, "generation 1", func() bool { return r.records(t) >= 2 })
	writeSecret(t, r.canary, []byte("read by an intruder"))
	if code := exitCode(primary); code != 3 {
		t.Fatalf("sentinel exited %d, want 3 (compromised)\n%s", code, primary.log.String())
	}

	// The failover — and then, with nobody doing anything, the chain.
	var rep failoverReport
	waitFor(t, jobTimeout, "the chain the standby continues, on the authority's report", func() bool {
		select {
		case <-authority.exited:
			t.Fatalf("sagvd failover exited before the standby went on\n%s", authority.log.String())
		default:
		}
		var ok bool
		rep, ok = peekReport(report)
		return ok && rep.Continued != nil
	})
	if rep.Status != "restored" || rep.Resumed || rep.Trigger.Kind != "compromise-report" || rep.Genome == nil || rep.Genome.Generation != 1 ||
		rep.Restore == nil || rep.Restore.Gate == nil || rep.Restore.Gate.Level != "EXACT" || rep.StandbyTrigger != nil {
		t.Fatalf("report %+v\n%s", rep, authority.log.String())
	}
	c := rep.Continued
	if c.Generation != 2 || c.ParentGeneration != 1 || c.ParentBundleSHA256 != rep.Genome.BundleSHA256 || c.BundleSHA256 == rep.Genome.BundleSHA256 ||
		!strings.HasPrefix(c.Sentinel, "sentinel-") || c.SealedAfterRestoreSeconds == nil || *c.SealedAfterRestoreSeconds <= 0 {
		t.Fatalf("continued %+v", c)
	}
	// What the standby sealed is what was trained there, on the tree it restored.
	trained, err := os.ReadFile(filepath.Join(r.restored, rep.Genome.KeyID, "adapter", "adapter_model.safetensors"))
	if err != nil || string(trained) != "lora weights, epoch 3, trained on the standby" {
		t.Fatalf("the standby's state is %q (%v)", trained, err)
	}
	if !strings.Contains(r.x.dest.log.String(), "after-restore command done") {
		t.Fatalf("the destination did not say its command was done\n%s", r.x.dest.log.String())
	}
	// On record: the failover's five events, then the chain it continues.
	if ok, events, _ := r.x.auditVerify(t); !ok || events != 6 || rep.AuditChainLength != 6 {
		t.Fatalf("audit log: ok=%v events=%d report=%d, want 6", ok, events, rep.AuditChainLength)
	}
	// The two outboxes are one chain: generations 0 and 1 sealed on the
	// primary, 2 on the standby, each naming the one before.
	together := t.TempDir()
	for _, outbox := range []string{r.outbox, r.standbyOutbox} {
		bundles, err := filepath.Glob(filepath.Join(outbox, "gen-*.genome"))
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range bundles {
			raw, err := os.ReadFile(b)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(together, filepath.Base(b)), raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if out := acpctl(t, "genome", "chain", "--dir", together); !strings.Contains(out, "3 generation(s)") || !strings.Contains(out, "chain valid") {
		t.Fatalf("the chain across the two machines:\n%s", out)
	}
	t.Logf("closed turn: failover %.2fs; the standby sealed generation %d %.2fs after its restore", rep.Timing.FailoverSeconds, c.Generation, *c.SealedAfterRestoreSeconds)

	// While the authority watches the standby, an operator opens the
	// generation the standby sealed: an ordinary attested release of its
	// escrowed key, to the same destination. The run that watches holds
	// nothing the release needs; the standby restores the generation
	// beside the model it goes on with, and its command — run after every
	// restore whose gate passed — starts nothing a second time.
	bundle2 := filepath.Join(r.standbyOutbox, "gen-000002.genome")
	replicate(t, bundle2, r.outbox)
	if rel, out, err := runRelease(t, r.srcCfg, r.x.endpoint, "reopen-generation-2", "-key-escrow", bundle2+".escrow"); err != nil || rel.Status != "ok" {
		t.Fatalf("release of the generation the standby sealed: %v\n%s", err, out)
	}
	if conf, out, err := r.x.confirm(t, r.srcCfg, "-decision-id", "reopen-generation-2", "-destination-endpoint", r.x.endpoint,
		"-bundle", bundle2, "-require-gate", "EQUIVALENT", "-wait", "30s"); err != nil || conf.Status != "ok" {
		t.Fatalf("confirm of the generation the standby sealed: %v\n%s", err, out)
	}
	reopened, err := os.ReadFile(filepath.Join(r.restored, c.KeyID, "adapter", "adapter_model.safetensors"))
	if err != nil || string(reopened) != string(trained) {
		t.Fatalf("generation 2 opened again is %q (%v), want what was trained on the standby", reopened, err)
	}
	waitFor(t, 20*time.Second, "the standby's command after the second restore", func() bool {
		return len(r.x.destLog("after-restore command done")) == 2
	})
	if raw, err := os.ReadFile(r.standbySentinelPID); err != nil || len(strings.Fields(string(raw))) != 1 {
		t.Fatalf("the standby's sentinel was started again: %q (%v)", raw, err)
	}
	select {
	case <-authority.exited:
		t.Fatalf("sagvd failover exited when a generation was opened beside it\n%s", authority.log.String())
	default:
	}
	// The release and its confirmation are on the same log, after the chain.
	ok, onLog, _ := r.x.auditVerify(t)
	if !ok || onLog <= 6 {
		t.Fatalf("audit log after the release: ok=%v events=%d, want more than 6", ok, onLog)
	}

	// The authority is still there, watching the standby. It is restarted:
	// stopped, it leaves with 0 ...
	select {
	case <-authority.exited:
		t.Fatalf("sagvd failover exited after the chain\n%s", authority.log.String())
	default:
	}
	if _, killed := authority.stop(); killed {
		t.Fatal("sagvd failover ignored SIGTERM")
	}
	if code := exitCode(authority); code != 0 {
		t.Fatalf("sagvd failover exited %d on SIGTERM, want 0\n%s", code, authority.log.String())
	}
	// ... and started again, it takes the failover up from its log:
	// nothing is decided or recorded a second time, and the report it
	// writes over keeps what the first run said of the failover.
	second := r.executor(t, report)
	waitFor(t, 30*time.Second, "the restarted authority watching the standby", func() bool {
		rep2, ok := peekReport(report)
		return ok && rep2.Resumed && rep2.Continued != nil && strings.Contains(second.log.String(), `"state":"watching"`)
	})
	if rep2, _ := peekReport(report); rep2.Status != "restored" || rep2.Continued.BundleSHA256 != c.BundleSHA256 || rep2.Decision.DecisionID != rep.Decision.DecisionID ||
		rep2.Trigger.Kind != "compromise-report" || rep2.Timing == nil || rep2.Timing.FailoverSeconds != rep.Timing.FailoverSeconds || rep2.Restore == nil {
		t.Fatalf("taken up as %+v", rep2)
	}
	if ok, events, _ := r.x.auditVerify(t); !ok || events != onLog {
		t.Fatalf("audit log after the restart: ok=%v events=%d, want %d", ok, events, onLog)
	}

	// The standby is lost: its sentinel dies without a word and its
	// heartbeat stops. One serial, one failover — declined, on the record.
	r.killStandbySentinel()
	rep3 := readReport(t, second, report)
	if code := exitCode(second); code != 3 || rep3.StandbyTrigger == nil || rep3.StandbyTrigger.Trigger.Kind != "heartbeat-timeout" ||
		rep3.StandbyTrigger.Decision.Decision != "declined" || !strings.Contains(rep3.StandbyTrigger.Decision.Reason, "names nowhere further to go") {
		t.Fatalf("sagvd failover exited %d: %+v\n%s", code, rep3.StandbyTrigger, second.log.String())
	}
	if ok, events, _ := r.x.auditVerify(t); !ok || events != onLog+1 {
		t.Fatalf("audit log after the standby was lost: ok=%v events=%d, want %d", ok, events, onLog+1)
	}
	// Started once more — writing its report elsewhere — it finds that
	// trigger on record and adds nothing; of the failover it says what the
	// log says, and no more.
	report3 := filepath.Join(t.TempDir(), "report-3.json")
	third := r.executor(t, report3)
	rep4 := readReport(t, third, report3)
	if code := exitCode(third); code != 3 || rep4.StandbyTrigger == nil || rep4.StandbyTrigger.Decision.Decision != "declined" ||
		!rep4.Resumed || rep4.Timing != nil || rep4.Genome == nil || rep4.Genome.Generation != 1 {
		t.Fatalf("sagvd failover exited %d: %+v\n%s", code, rep4, third.log.String())
	}
	if ok, events, _ := r.x.auditVerify(t); !ok || events != onLog+1 {
		t.Fatalf("audit log after one more run: ok=%v events=%d, want %d", ok, events, onLog+1)
	}
}

// sentinelPubOf writes the PEM public half of a sentinel seed.
func sentinelPubOf(t *testing.T, seed string) string {
	t.Helper()
	var id struct {
		PEM string `json:"sentinel_public_key_pem"`
	}
	teeSeed := filepath.Join(t.TempDir(), "tee.seed")
	writeSecret(t, teeSeed, []byte(strings.Repeat("x", 32)))
	if out, err := runJSON(t, &id, bins.acpctl, "sentinel", "identity", "--tee", "simulated", "--tee-seed", teeSeed, "--key", seed); err != nil {
		t.Fatalf("sentinel identity: %v\n%s", err, out)
	}
	p := filepath.Join(t.TempDir(), "sentinel.pem")
	writeSecret(t, p, []byte(id.PEM))
	return p
}

// copyDir copies the regular files of src into dst.
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
