// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ai-continuity-platform/core/internal/genome/sentinel"
	"github.com/ai-continuity-platform/core/internal/vault/failover"
)

// failoverCmd dispatches `acpctl failover <issue|verify>` (ADR 0012). The
// operator signs the failover policy with the operator key that signs
// stop lists; it never lives on the release host.
func failoverCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: acpctl failover <issue|verify> [flags]")
		return 2
	}
	switch args[0] {
	case "issue":
		return failoverIssueCmd(args[1:], stdout, stderr)
	case "verify":
		return failoverVerifyCmd(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, "failover subcommands:")
		fmt.Fprintln(stdout, "  issue   sign a failover policy: the primary's sentinel, the standby, the triggers")
		fmt.Fprintln(stdout, "  verify  check a policy against the operator public key and print it")
		return 0
	default:
		fmt.Fprintf(stderr, "acpctl failover: unknown subcommand %q\n", args[0])
		return 2
	}
}

func failoverIssueCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("failover issue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var measurements repeatedFlag
	var (
		seedPath    = fs.String("key", "", "Operator seed file (acpctl stop keygen) (required)")
		kid         = fs.String("kid", "", "Operator key ID the release host trusts (required)")
		serial      = fs.Uint64("serial", 0, "Policy serial; higher than any failover policy issued before (required)")
		sentinelPub = fs.String("sentinel-pub", "", "The primary's sentinel public key: PEM or 32 raw bytes (required)")
		kind        = fs.String("standby-kind", "", "The standby's TEE kind, e.g. gcp-sev-snp (required)")
		endpoint    = fs.String("standby-endpoint", "", "The standby's acp-bootstrap URL, https (required)")
		timeout     = fs.Duration("heartbeat-timeout", 0, "Fail over when no heartbeat rises for this long (0: not a trigger)")
		noReport    = fs.Bool("no-compromise-trigger", false, "Do not fail over on a compromise report")
		quarantine  = fs.Duration("quarantine", 0, "Distrust genomes sealed this long before the trigger")
		maxRPO      = fs.Duration("max-rpo", 0, "Decline when the newest trustworthy genome is older than this at the trigger (0: no bound)")
		gate        = fs.String("require-gate", "EQUIVALENT", "Gate verdict the standby's receipt must carry: EQUIVALENT, EXACT or none")
		validFor    = fs.Duration("valid-for", 30*24*time.Hour, "How long the policy stands")
		reason      = fs.String("reason", "", "Why; recorded with the policy")
		out         = fs.String("out", "", "Where to write the signed policy (required)")
	)
	fs.Var(&measurements, "standby-measurement", "A measurement (hex) the standby must attest (repeatable; at least one)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *seedPath == "" || *kid == "" || *serial == 0 || *sentinelPub == "" || *kind == "" || *endpoint == "" || len(measurements) == 0 || *out == "" {
		fmt.Fprintln(stderr, "acpctl failover issue: --key, --kid, --serial, --sentinel-pub, --standby-kind, --standby-endpoint, --standby-measurement and --out are required")
		return 2
	}
	if *gate == "none" {
		*gate = ""
	}
	seed, err := os.ReadFile(*seedPath)
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintf(stderr, "acpctl failover issue: --key must be a %d-byte seed file (%v)\n", ed25519.SeedSize, err)
		return 1
	}
	spub, err := readEd25519PublicKey(*sentinelPub)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl failover issue: --sentinel-pub: %v\n", err)
		return 1
	}
	now := time.Now().UTC().Truncate(time.Second)
	for i, m := range measurements {
		measurements[i] = strings.ToLower(m)
	}
	p, err := failover.Sign(failover.Policy{
		Serial:            *serial,
		IssuedAt:          now,
		NotAfter:          now.Add(*validFor),
		SentinelPublicKey: spub,
		Standby:           failover.Standby{Kind: *kind, Endpoint: *endpoint, Measurements: measurements},
		Triggers:          failover.Triggers{CompromiseReport: !*noReport, HeartbeatTimeoutSeconds: int64(timeout.Seconds())},
		QuarantineSeconds: int64(quarantine.Seconds()),
		MaxRPOSeconds:     int64(maxRPO.Seconds()),
		RequireGate:       *gate,
		Reason:            *reason,
		SigningKeyID:      *kid,
	}, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		fmt.Fprintf(stderr, "acpctl failover issue: %v\n", err)
		return 1
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err == nil {
		err = os.WriteFile(*out, append(raw, '\n'), 0o644)
	}
	if err != nil {
		fmt.Fprintf(stderr, "acpctl failover issue: write: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "failover policy serial %d written to %s: sentinel %s -> %s %s, until %s\n",
		p.Serial, *out, sentinel.KeyID(spub), p.Standby.Kind, p.Standby.Endpoint, p.NotAfter.Format(time.RFC3339))
	return 0
}

func failoverVerifyCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("failover verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "Signed failover policy (required)")
	pubPath := fs.String("pubkey", "", "Operator public key: PEM or 32 raw bytes (required)")
	kid := fs.String("kid", "", "Operator key ID (required)")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" || *pubPath == "" || *kid == "" {
		fmt.Fprintln(stderr, "acpctl failover verify: --in, --pubkey and --kid are required")
		return 2
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl failover verify: %v\n", err)
		return 1
	}
	pub, err := readEd25519PublicKey(*pubPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl failover verify: %v\n", err)
		return 1
	}
	p, err := failover.Parse(raw, ed25519.PublicKey(pub), *kid)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl failover verify: %v\n", err)
		return 4
	}
	_, sid := p.Sentinel()
	standing := "stands"
	if err := p.ActiveAt(time.Now()); err != nil {
		standing = err.Error()
	}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{"policy": p, "sentinel": sid, "standing": standing})
		return 0
	}
	fmt.Fprintf(stdout, "valid failover policy, serial %d, issued %s, until %s: %s\n", p.Serial, p.IssuedAt.Format(time.RFC3339), p.NotAfter.Format(time.RFC3339), standing)
	fmt.Fprintf(stdout, "  primary sentinel: %s\n", sid)
	fmt.Fprintf(stdout, "  standby:          %s %s, measurements %s\n", p.Standby.Kind, p.Standby.Endpoint, strings.Join(p.Standby.Measurements, ", "))
	var triggers []string
	if p.Triggers.CompromiseReport {
		triggers = append(triggers, "compromise report")
	}
	if p.Triggers.HeartbeatTimeoutSeconds > 0 {
		triggers = append(triggers, fmt.Sprintf("no heartbeat for %ds", p.Triggers.HeartbeatTimeoutSeconds))
	}
	fmt.Fprintf(stdout, "  triggers:         %s\n", strings.Join(triggers, ", "))
	gate := p.RequireGate
	if gate == "" {
		gate = "none"
	}
	fmt.Fprintf(stdout, "  required gate:    %s; quarantine %ds; max RPO %ds (0: no bound)\n", gate, p.QuarantineSeconds, p.MaxRPOSeconds)
	if p.Reason != "" {
		fmt.Fprintf(stdout, "  reason:           %s\n", p.Reason)
	}
	return 0
}
