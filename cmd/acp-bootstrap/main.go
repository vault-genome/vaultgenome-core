// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ai-continuity-platform/core/internal/bootstrap/crosscloud"
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
	"github.com/ai-continuity-platform/core/internal/vault/kms"
)

// version / commit are populated at link time by the Makefile.
var (
	version = "0.0.0-dev"
	commit  = "none"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("acp-bootstrap %s (commit %s)\n", version, commit)
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}
	if err := run(os.Args[1:]); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).
			Error("acp-bootstrap: terminated with error", "err", err.Error())
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`acp-bootstrap %s — destination daemon for Phase 4 cross-cloud restore

USAGE
    acp-bootstrap -config /path/to/config.json
    acp-bootstrap version
    acp-bootstrap help

CONFIG FORMAT
    JSON file with sections: http, tee, source_authority, health, log.
    See cmd/acp-bootstrap/config.go for the full schema.

ENDPOINTS
    POST /v1/crosscloud/handshake — accept signed handshake from source
    POST /v1/crosscloud/token     — accept signed key-release token

REFERENCES
    ADR 0006 — Cross-Cloud KMS-Mediated Restore
    docs/operator/06_cross_cloud_restore.md
`, version)
}

func run(args []string) error {
	fs := flag.NewFlagSet("acp-bootstrap", flag.ContinueOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to JSON config file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("acp-bootstrap: -config is required (see acp-bootstrap help)")
	}

	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("acp-bootstrap: config validation: %w", err)
	}

	logger := buildLogger(cfg.Log)
	clock := shared_time.NewSystemClock()

	logger.Info("acp-bootstrap starting",
		"version", version,
		"commit", commit,
		"http_listen", cfg.HTTP.ListenAddress,
		"tee_provider", cfg.TEE.Provider,
		"source_authority_kid", cfg.SourceAuthority.KeyID,
	)

	// 1. Build local TEE producer.
	producer, err := buildTEEProducer(cfg.TEE)
	if err != nil {
		return err
	}
	logger.Info("local TEE producer ready",
		"provider", cfg.TEE.Provider,
		"measurement_hex", fmt.Sprintf("%x", producer.Measurement()),
	)

	// 2. Build verify-only resolver for the source-authority pubkey.
	sourceResolver, err := loadSourceAuthorityResolver(cfg.SourceAuthority, clock)
	if err != nil {
		return err
	}

	// 3. Build destination keystore (where unwrapped DEKs land).
	destKeystore := keys.NewInMemoryStore(clock)

	// 4. Build Receiver.
	receiver, err := crosscloud.NewReceiver(crosscloud.Config{
		SourceAuthorityKeys: sourceResolver,
		LocalTEE:            producer,
		Unwrapper:           kms.NewSimulatedKeyUnwrapper(),
		Registrar:           destKeystore,
	})
	if err != nil {
		return err
	}

	// 5. Build HTTP handler + mux.
	handler, err := crosscloud.NewHTTPHandler(crosscloud.HTTPHandlerConfig{
		Receiver:    receiver,
		BearerToken: cfg.HTTP.BearerToken,
		Logger:      logger,
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	for path, h := range handler.Routes() {
		mux.HandleFunc(path, h)
	}

	// 6. Start HTTP listener.
	httpServer, ln, err := buildHTTPServer(cfg.HTTP, mux, logger)
	if err != nil {
		return err
	}

	// 7. Start health listener if configured.
	var healthServer *http.Server
	if cfg.Health.ListenAddress != "" {
		healthServer = &http.Server{
			Addr:              cfg.Health.ListenAddress,
			ReadHeaderTimeout: 3 * time.Second,
			Handler:           buildHealthMux(),
		}
		go func() {
			if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Warn("health server stopped", "err", err.Error())
			}
		}()
		logger.Info("health server listening", "addr", cfg.Health.ListenAddress)
	}

	// 8. Run HTTP server until signalled.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("crosscloud HTTP listener serving", "addr", ln.Addr().String())
		if cfg.HTTP.TLS.Enabled {
			errCh <- httpServer.ServeTLS(ln, cfg.HTTP.TLS.ServerCert, cfg.HTTP.TLS.ServerKey)
		} else {
			errCh <- httpServer.Serve(ln)
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("http server shutdown error", "err", err.Error())
	}
	if healthServer != nil {
		_ = healthServer.Shutdown(shutdownCtx)
	}
	logger.Info("acp-bootstrap stopped")
	return nil
}

// buildTEEProducer constructs the local TEE producer per cfg.Provider.
// MVP/demo only supports the simulated backend; real backends are
// added in subsequent phases.
func buildTEEProducer(cfg TEEConfig) (tee.Producer, error) {
	switch cfg.Provider {
	case "simulated":
		seed, err := readExactly(cfg.SeedPath, crypto.Ed25519SeedSize, "tee.seed_path")
		if err != nil {
			return nil, err
		}
		return tee.NewSimulated([]byte(cfg.WorkloadDescriptor), seed)
	default:
		return nil, fmt.Errorf("acp-bootstrap: tee.provider %q not yet supported in this build", cfg.Provider)
	}
}

// pubkeyResolver is a verify-only keys.Resolver wrapping a single
// (kid, purpose, pubkey) triple. The destination needs to verify
// signatures on incoming handshakes / tokens but never signs with
// the source authority key, so a pubkey-only resolver is the right
// shape.
type pubkeyResolver struct {
	kid     ids.KeyID
	purpose keys.Purpose
	pub     crypto.PublicKey
	created int64
}

func (r *pubkeyResolver) Resolve(kid ids.KeyID, want keys.Purpose) (keys.VerifyingKey, error) {
	if kid != r.kid {
		return keys.VerifyingKey{}, fmt.Errorf("acp-bootstrap: kid %q not registered (have %q)", kid, r.kid)
	}
	if want != r.purpose {
		return keys.VerifyingKey{}, fmt.Errorf("acp-bootstrap: kid %q registered for purpose %d, requested %d", kid, r.purpose, want)
	}
	return keys.VerifyingKey{
		KeyID:     r.kid,
		Purpose:   r.purpose,
		PublicKey: r.pub,
		CreatedAt: r.created,
	}, nil
}

// loadSourceAuthorityResolver loads the source-authority public key
// from disk (raw or PEM) and wraps it in a verify-only resolver
// keyed by cfg.KeyID under keys.PurposeSigningAuthority.
func loadSourceAuthorityResolver(cfg SourceAuthorityConfig, clock shared_time.Clock) (keys.Resolver, error) {
	pub, err := loadAttestorPubKey(cfg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("acp-bootstrap: load source authority pubkey: %w", err)
	}
	return &pubkeyResolver{
		kid:     ids.KeyID(cfg.KeyID),
		purpose: keys.PurposeSigningAuthority,
		pub:     pub,
		created: clock.Now().UTC().Unix(),
	}, nil
}

// loadAttestorPubKey reads either a raw 32-byte Ed25519 public key
// file or a PEM-encoded SubjectPublicKeyInfo and returns the
// crypto.PublicKey.
func loadAttestorPubKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.Contains(string(data), "-----BEGIN") {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("attestor pubkey: invalid PEM")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("attestor pubkey: parse PKIX: %w", err)
		}
		ed, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("attestor pubkey: PEM key is %T, want ed25519.PublicKey", key)
		}
		return crypto.PublicKey(ed), nil
	}
	if len(data) != crypto.Ed25519PublicKeySize {
		return nil, fmt.Errorf("attestor pubkey: file %d bytes, want %d (raw Ed25519) or PEM-encoded", len(data), crypto.Ed25519PublicKeySize)
	}
	return crypto.PublicKey(data), nil
}

// buildHTTPServer assembles the http.Server and binds the listener.
// TLS is configured by ServeTLS in run() — we only wire the
// http.Server here.
func buildHTTPServer(cfg HTTPConfig, handler http.Handler, logger *slog.Logger) (*http.Server, net.Listener, error) {
	ln, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("acp-bootstrap: bind %s: %w", cfg.ListenAddress, err)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout(),
		WriteTimeout:      cfg.WriteTimeout(),
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	if cfg.TLS.Enabled {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.TLS.ClientCAs != "" {
			caRaw, err := os.ReadFile(cfg.TLS.ClientCAs)
			if err != nil {
				return nil, nil, fmt.Errorf("acp-bootstrap: read tls.client_cas: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caRaw) {
				return nil, nil, errors.New("acp-bootstrap: tls.client_cas contained no PEM certs")
			}
			srv.TLSConfig.ClientCAs = pool
			srv.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	return srv, ln, nil
}

func buildHealthMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	return mux
}

func buildLogger(cfg LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if strings.ToLower(cfg.Format) == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

// readExactly reads a file and verifies it is exactly want bytes.
// Used for raw-bytes key files (Ed25519 seeds, AES keys,
// measurements).
func readExactly(path string, want int, label string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("acp-bootstrap: %s required", label)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("acp-bootstrap: read %s %q: %w", label, path, err)
	}
	if len(data) != want {
		return nil, fmt.Errorf("acp-bootstrap: %s %q: %d bytes, want %d", label, path, len(data), want)
	}
	return data, nil
}
