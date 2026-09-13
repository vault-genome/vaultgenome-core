// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ai-continuity-platform/core/internal/compute/worker"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
)

// Build-time variables. -ldflags "-X main.version=... -X main.commit=..."
// at release time; the defaults here are what a local `go run` sees.
var (
	version = "0.0.0-dev"
	commit  = "none"
)

func main() {
	// Sub-command dispatch (version / help) — these short-circuit before
	// any daemon wiring so the binary remains cheap to probe in CI.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("acp-compute %s (commit %s)\n", version, commit)
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}

	if err := runDaemon(os.Args[1:]); err != nil {
		// Error path: JSON-log the failure so operators see the
		// category/code in their log aggregator, then exit non-zero.
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).
			Error("acp-compute: terminated with error", "err", err.Error())
		os.Exit(1)
	}
}

// runDaemon is the full daemon entry point extracted out of main() so
// it is testable (no os.Exit, no global state).
func runDaemon(args []string) error {
	fs := flag.NewFlagSet("acp-compute", flag.ContinueOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to JSON config file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("acp-compute: -config is required (see acp-compute help)")
	}

	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("acp-compute: config validation: %w", err)
	}

	logger := buildLogger(cfg.Log)
	clock := shared_time.NewSystemClock()

	logger.Info("acp-compute starting",
		"version", version,
		"commit", commit,
		"config_path", configPath,
		"vault_address", cfg.Vault.Address,
		"workload_descriptor", cfg.TEE.WorkloadDescriptor,
	)

	mat, err := LoadMaterials(cfg, clock)
	if err != nil {
		return err
	}

	// Log the worker's signing pubkey once; the operator copies this
	// into sagvd's PublicKeyResolver config so the vault can verify
	// every CandidateOutputFrame this worker produces.
	logger.Info("worker signing identity",
		"kid", string(mat.SigningKeyID),
		"pubkey_hex", hex.EncodeToString(mat.SigningPublicKey),
	)

	// R-11 swap point. Iteration 7 (task #78) flipped this from the
	// deterministic MVP placeholder to the real generative backend.
	// Because the Reconstructor interface was frozen in iteration 5,
	// this is the only production line that had to change: the daemon
	// loop, Return Path client, and validation surface all consume the
	// interface and are unaffected.
	recon, err := worker.NewGenerativeReconstructor(clock)
	if err != nil {
		return err
	}

	registry := NewRegistry()
	daemon, err := NewDaemon(cfg, mat, clock, logger, recon, registry)
	if err != nil {
		return err
	}

	// Wire the HTTP surface (optional: empty ListenAddress disables).
	hs := NewHealthServer(cfg.Health.ListenAddress, daemon.Health(), registry, logger)
	if err := hs.Start(); err != nil {
		return fmt.Errorf("acp-compute: health server: %w", err)
	}

	// Signal-driven shutdown: SIGINT / SIGTERM cancel the ctx handed
	// to daemon.Run; on return we run graceful cleanup.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runErr := daemon.Run(ctx)

	// Graceful shutdown: flip health flags first so any in-flight
	// probe sees 503 before we tear down state; then close the HTTP
	// server; finally zeroize keys.
	daemon.Shutdown()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	if err := hs.Close(shutCtx); err != nil {
		logger.Warn("health server shutdown error", "err", err)
	}
	daemon.Zeroize()

	logger.Info("acp-compute stopped")
	return runErr
}

// buildLogger constructs a *slog.Logger per the LogConfig. Invalid
// combinations are filtered out in Validate(); buildLogger treats any
// survivor as one of the four accepted values.
func buildLogger(cfg LogConfig) *slog.Logger {
	var lvl slog.Level
	switch cfg.Level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if cfg.Format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

func printUsage() {
	fmt.Println("acp-compute — external compute worker (delegated, non-authority)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  acp-compute -config PATH")
	fmt.Println("  acp-compute version")
	fmt.Println("  acp-compute help")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Long-lived worker daemon. Dials sagvd over the Return Path,")
	fmt.Println("  serves one reconstruction job per session, then reconnects.")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -config PATH   JSON config file; see cmd/acp-compute/doc.go for schema.")
}
