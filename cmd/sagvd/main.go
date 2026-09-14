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

	"github.com/ai-continuity-platform/core/internal/observability/health"
	"github.com/ai-continuity-platform/core/internal/observability/metrics"
	"github.com/ai-continuity-platform/core/internal/observability/teemetrics"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
)

// These variables are populated at link time by the Makefile /
// release pipeline. See Makefile target "build" and
// .github/workflows/release.yml.
var (
	version = "0.0.0-dev"
	commit  = "none"
)

func main() {
	// Sub-command dispatch (version / help) — these short-circuit
	// before any daemon wiring so the binary remains cheap to probe
	// in CI.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("sagvd %s (commit %s)\n", version, commit)
			return
		case "help", "--help", "-h":
			printUsage()
			return
		case "identity":
			if err := runIdentityCmd(os.Args[2:], os.Stdout); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).
					Error("sagvd identity: terminated with error", "err", err.Error())
				os.Exit(1)
			}
			return
		case "crosscloud-restore":
			// Phase 4 Cross-Cloud KMS-Mediated Restore CLI entry
			// point. Loads cross-cloud materials from the same
			// config file the daemon uses, instantiates a
			// kms.Coordinator, and runs CoordinateRestore once.
			// Output is JSON: CoordinationResult on success;
			// classified-error envelope on failure.
			if err := runCrossCloudRestoreCmd(os.Args[2:]); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).
					Error("sagvd crosscloud-restore: terminated with error", "err", err.Error())
				os.Exit(1)
			}
			return
		case "crosscloud-confirm":
			// Confirms a released genome's restore from the
			// destination's TEE-signed receipt and records it
			// (ADR 0011).
			if err := runCrossCloudConfirmCmd(os.Args[2:]); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).
					Error("sagvd crosscloud-confirm: terminated with error", "err", err.Error())
				os.Exit(1)
			}
			return
		}
	}

	if err := runDaemon(os.Args[1:]); err != nil {
		// Error path: JSON-log the failure so operators see the
		// category/code in their log aggregator, then exit
		// non-zero.
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).
			Error("sagvd: terminated with error", "err", err.Error())
		os.Exit(1)
	}
}

// runDaemon is the full daemon entry point extracted out of main()
// so it is testable (no os.Exit, no global state).
func runDaemon(args []string) error {
	fs := flag.NewFlagSet("sagvd", flag.ContinueOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to JSON config file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("sagvd: -config is required (see sagvd help)")
	}

	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("sagvd: config validation: %w", err)
	}
	if err := cfg.ResolveSecrets(); err != nil {
		return err
	}

	logger := buildLogger(cfg.Log)
	clock := shared_time.NewSystemClock()

	logger.Info("sagvd starting",
		"version", version,
		"commit", commit,
		"config_path", configPath,
		"vault_listen_address", cfg.Vault.ListenAddress,
		"http_api_listen_address", cfg.HTTPAPI.ListenAddress,
		"health_listen_address", cfg.Health.ListenAddress,
		"workload_descriptor", cfg.TEE.WorkloadDescriptor,
	)

	mat, err := LoadMaterials(cfg, clock)
	if err != nil {
		return err
	}

	// Log the vault's authority-signing pubkey + every accepted
	// worker kid/pubkey once. Operators cross-check against the
	// worker-side `worker signing identity` line emitted by
	// acp-compute at startup.
	logger.Info("sagvd authority signing identity",
		"kid", string(mat.AuthoritySigningKeyID),
		"pubkey_hex", hex.EncodeToString(mat.AuthoritySigningPublicKey),
	)
	logger.Info("sagvd session sealing identity",
		"kid", string(mat.SessionSealingKeyID),
	)
	for _, w := range mat.WorkerEntries {
		logger.Info("sagvd accepted worker signing identity",
			"kid", w.KeyID,
			"pubkey_hex", w.SigningPublicKeyHex,
			"note", w.Note,
		)
	}

	registry := metrics.NewRegistry()
	teeRec := teemetrics.New(registry)
	// Phase 1: vault uses the simulated TEE backend by default. When
	// the keystore loader switches on tee.Provider in Phase 2, this
	// label tracks the configured backend automatically.
	mat.InstrumentTEE(teeRec, "simulated")
	teeRec.RecordCapability("simulated", true)

	queue := NewJobQueue(clock, cfg.Runtime.QueuePoll())

	daemon, err := NewDaemon(cfg, mat, queue, clock, logger, registry)
	if err != nil {
		return err
	}

	httpAPI, err := NewHTTPAPIServer(
		cfg.HTTPAPI, cfg.Runtime, queue,
		mat.Store, mat.SessionSealingKeyID,
		clock, registry, logger,
	)
	if err != nil {
		return err
	}
	if err := httpAPI.Start(); err != nil {
		return err
	}

	// Health / metrics HTTP surface. Empty ListenAddress disables
	// the server (tests and loopback-only demos).
	hs := health.NewServer(cfg.Health.ListenAddress, daemon.Health(), registry, logger)
	if err := hs.Start(); err != nil {
		return fmt.Errorf("sagvd: health server: %w", err)
	}

	// Signal-driven shutdown: SIGINT / SIGTERM cancel the ctx
	// handed to daemon.Run; on return we run graceful cleanup.
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runErr := daemon.Run(ctx)

	// Graceful shutdown: flip health flags first so any in-flight
	// probe sees 503 before we tear down state; then close the
	// two HTTP servers; finally zeroize keys.
	daemon.Shutdown()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	if err := httpAPI.Close(shutCtx); err != nil {
		logger.Warn("sagvd HTTP API server shutdown error", "err", err)
	}
	if err := hs.Close(shutCtx); err != nil {
		logger.Warn("sagvd health server shutdown error", "err", err)
	}
	daemon.Zeroize()

	logger.Info("sagvd stopped")
	return runErr
}

// buildLogger constructs a *slog.Logger per the LogConfig. Invalid
// combinations are filtered out in Validate(); buildLogger treats
// any survivor as one of the four accepted values.
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
	fmt.Println("sagvd — Secure AI Genome Vault Daemon (authority / vault)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  sagvd -config PATH")
	fmt.Println("  sagvd identity -config PATH")
	fmt.Println("  sagvd crosscloud-restore -config PATH -decision-id ID -destination-kind KIND \\")
	fmt.Println("        -destination-endpoint URL -key-file KID:PATH [-key-file ...] [-session-id ID] [-manifest-id ID]")
	fmt.Println("  sagvd crosscloud-confirm -config PATH -decision-id ID -destination-endpoint URL \\")
	fmt.Println("        {-bundle PATH | -key-id KID} [-wait DURATION]")
	fmt.Println("  sagvd version")
	fmt.Println("  sagvd help")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Authority daemon. Binds the Return Path listener for")
	fmt.Println("  acp-compute workers and the operator REST API for job")
	fmt.Println("  submission (POST /v1/jobs) and lookup (GET /v1/jobs/{id}).")
	fmt.Println()
	fmt.Println("  identity prints the authority signing key and TEE identity other")
	fmt.Println("  hosts pin, as JSON. crosscloud-restore releases DEKs to an attested,")
	fmt.Println("  allow-listed acp-bootstrap destination (docs/operator/06_cross_cloud_restore.md);")
	fmt.Println("  crosscloud-confirm records its restore once the destination's TEE-signed")
	fmt.Println("  receipt checks out against that release (ADR 0011).")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -config PATH   JSON config file; see cmd/sagvd/doc.go for schema.")
}
