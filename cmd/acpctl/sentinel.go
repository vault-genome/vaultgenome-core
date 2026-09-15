// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ai-continuity-platform/core/internal/genome/bundle"
	"github.com/ai-continuity-platform/core/internal/genome/escrow"
	"github.com/ai-continuity-platform/core/internal/genome/sentinel"
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
)

// sentinelCmd dispatches `acpctl sentinel <keygen|watch>` (ADR 0012): the
// process beside a running model that keeps its state sealed and says
// when the machine can no longer be trusted.
func sentinelCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printSentinelUsage(stderr)
		return 2
	}
	switch args[0] {
	case "keygen":
		return sentinelKeygenCmd(args[1:], stdout, stderr)
	case "watch":
		return sentinelWatchCmd(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printSentinelUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "acpctl sentinel: unknown subcommand %q\n", args[0])
		printSentinelUsage(stderr)
		return 2
	}
}

func printSentinelUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: acpctl sentinel <keygen|watch> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  keygen  create the sentinel's signing key (seed file + PEM public key)")
	fmt.Fprintln(w, "  watch   seal the state as it changes, watch tripwires, report compromise")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The operator pins the sentinel's public key in the failover policy")
	fmt.Fprintln(w, "(acpctl failover issue --sentinel-pub); the release authority accepts")
	fmt.Fprintln(w, "nothing from the outbox that this key did not sign.")
}

func sentinelKeygenCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sentinel keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	seedPath := fs.String("out", "", "Where to write the 32-byte seed (created 0600, never overwritten)")
	pubPath := fs.String("pub", "", "Where to write the PEM public key the operator pins in the failover policy")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *seedPath == "" || *pubPath == "" {
		fmt.Fprintln(stderr, "acpctl sentinel keygen: --out and --pub are required")
		return 2
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err == nil {
		err = writeKeyFile(*seedPath, priv.Seed(), false)
	}
	var pemBytes []byte
	if err == nil {
		pemBytes, err = crypto.PublicKeyPEM(crypto.PublicKey(pub))
	}
	if err == nil {
		err = os.WriteFile(*pubPath, pemBytes, 0o644)
	}
	if err != nil {
		fmt.Fprintf(stderr, "acpctl sentinel keygen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "sentinel key %s: seed %s (stays on the primary), public key %s (pin it in the failover policy)\n", sentinel.KeyID(pub), *seedPath, *pubPath)
	return 0
}

// readSeed reads an Ed25519 seed file, refusing one other users can read.
func readSeed(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is open to other users (mode %04o); chmod 600 it", path, perm)
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s holds %d bytes, not a %d-byte seed", path, len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// sentinelSource adapts a payload source to the sentinel.
type sentinelSource struct{ payloadSource }

func (s sentinelSource) Kind() string                 { return string(s.kind) }
func (s sentinelSource) Ref() string                  { return s.ref }
func (s sentinelSource) Fingerprint() (string, error) { return s.fingerprint() }
func (s sentinelSource) Capture() bundle.Capture      { return s.capture }

func sentinelWatchCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sentinel watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var tripwires, probes repeatedFlag
	var (
		contentDir   = fs.String("content-dir", "", "Directory whose state is kept sealed (mutually exclusive with --model)")
		modelRef     = fs.String("model", "", "Ollama model kept sealed (mutually exclusive with --content-dir)")
		ollamaHome   = fs.String("ollama-home", defaultOllamaHome(), "Path to OLLAMA root")
		outbox       = fs.String("outbox", "", "Directory the sentinel writes genomes, escrow envelopes and records to (required)")
		escrowTo     = fs.String("escrow-to", "", "The release authority's escrow public key (PEM): every genome key is sealed to it (required)")
		keyPath      = fs.String("key", "", "The sentinel's seed file, mode 0600 (acpctl sentinel keygen) (required)")
		parentPath   = fs.String("parent", "", "For an empty outbox: the genome this state was restored from; the chain continues it")
		interval     = fs.Duration("interval", 5*time.Second, "Time between ticks: tripwires, seal, heartbeat")
		settle       = fs.Duration("settle", 3*time.Second, "How long the state must stay unchanged before it is sealed")
		probeTimeout = fs.Duration("probe-timeout", 10*time.Second, "How long a probe may run")
	)
	fs.Var(&tripwires, "tripwire", "A file or directory that must not change (repeatable)")
	fs.Var(&probes, "probe", "A command that must keep exiting 0, split on spaces (repeatable)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl sentinel watch {--content-dir DIR | --model REF} --outbox DIR --escrow-to AUTHORITY.pem --key SEED")
		fmt.Fprintln(stderr, "                             [--tripwire PATH]... [--probe CMD]... [--interval 5s] [--settle 3s] [--parent BUNDLE]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Every tick: check the tripwires; if the state settled into something new, seal it as")
		fmt.Fprintln(stderr, "the next generation (its key sealed only to the release authority); write a signed")
		fmt.Fprintln(stderr, "heartbeat. When a tripwire fires: seal nothing more, write a signed compromise report")
		fmt.Fprintln(stderr, "naming the last genome sealed before it, and exit 3. SIGINT/SIGTERM: a heartbeat that")
		fmt.Fprintln(stderr, "says the sentinel was stopped (no failover), exit 0.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch {
	case (*contentDir == "") == (*modelRef == ""):
		fmt.Fprintln(stderr, "acpctl sentinel watch: pass exactly one of --content-dir or --model")
		return 2
	case *outbox == "" || *escrowTo == "" || *keyPath == "":
		fmt.Fprintln(stderr, "acpctl sentinel watch: --outbox, --escrow-to and --key are required")
		return 2
	}

	key, err := readSeed(*keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl sentinel watch: --key: %v\n", err)
		return 2
	}
	raw, err := os.ReadFile(*escrowTo)
	var escrowPub *ecdh.PublicKey
	if err == nil {
		escrowPub, err = escrow.ParsePublicPEM(raw)
	}
	if err != nil {
		fmt.Fprintf(stderr, "acpctl sentinel watch: --escrow-to: %v\n", err)
		return 2
	}
	src := dirSource(*contentDir)
	if *modelRef != "" {
		src = ollamaSource(*modelRef, *ollamaHome)
	}
	var wires []sentinel.Wire
	for _, p := range tripwires {
		wires = append(wires, &sentinel.PathWire{Path: p})
	}
	for _, p := range probes {
		argv := strings.Fields(p)
		if len(argv) == 0 {
			fmt.Fprintln(stderr, "acpctl sentinel watch: empty --probe")
			return 2
		}
		wires = append(wires, &sentinel.ProbeWire{Argv: argv, Timeout: *probeTimeout})
	}
	cfg := sentinel.Config{
		Source:   sentinelSource{src},
		Outbox:   *outbox,
		Escrow:   escrowPub,
		Key:      key,
		Wires:    wires,
		Interval: *interval,
		Settle:   *settle,
		Log:      slog.New(slog.NewJSONHandler(stderr, nil)),
	}
	if *parentPath != "" {
		id, err := bundle.Identify(*parentPath)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl sentinel watch: --parent: %v\n", err)
			return 2
		}
		cfg.Parent = &id
	}
	s, err := sentinel.New(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl sentinel watch: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	res, err := s.Run(ctx)
	out := map[string]any{"sentinel": s.ID(), "outcome": res.Outcome, "generations_sealed": res.Generations, "last": res.Last}
	if res.Compromise != nil {
		out["compromise"] = res.Compromise
	}
	if err != nil {
		out["error"] = err.Error()
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	switch {
	case err != nil:
		return 1
	case res.Outcome == sentinel.OutcomeCompromised:
		return 3
	}
	return 0
}
