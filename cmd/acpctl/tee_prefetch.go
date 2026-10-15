// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// acpctl tee prefetch / cache-status: a host that will have no route to
// the hardware vendors (an air-gapped site) fills its verifiers' caches
// while it still has one, and knows until when they are good.
//
// A daemon's verifier of its peer asks a vendor for what it cannot know
// by itself — AMD KDS for the VCEK of the peer's chip at the peer's TCB,
// Intel PCS for the TCB info of the peer's platform and the QE identity
// — and keeps the answers in the cache directories its configuration
// names (tee.peer.vcek_cache_dir, tee.peer.pcs_cache_dir), checking each
// on use exactly like a fresh one. prefetch fills those caches with what
// this host's own evidence needs: it takes this host's report through
// configfs-tsm and verifies it as the configured peer verifier would,
// pinned to this host's own measurement, with the vendors reachable. The
// two daemons of one host (the Return Path kits' shape) then have what
// they need for each other; a peer on another chip fills its own host's
// caches the same way, and the operator copies the files — a cache is
// files named by chip and TCB, portable and never trusted on its own.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// teeConfigFile is the part of a daemon's configuration prefetch and
// cache-status read: the host's own TEE and the peer verifier's caches.
// sagvd, acp-compute and acp-bootstrap name these fields alike.
type teeConfigFile struct {
	TEE struct {
		Provider     string `json:"provider"`
		TSMReportDir string `json:"tsm_report_dir"`
		Peer         struct {
			Provider              string   `json:"provider"`
			AMDCertChainPath      string   `json:"amd_cert_chain_path"`
			AMDKDSURL             string   `json:"amd_kds_url"`
			VCEKCacheDir          string   `json:"vcek_cache_dir"`
			MinReportedTCB        uint64   `json:"min_reported_tcb"`
			PCSURL                string   `json:"pcs_url"`
			PCSCacheDir           string   `json:"pcs_cache_dir"`
			AcceptableTCBStatuses []string `json:"acceptable_tcb_statuses"`
			NRASCacheDir          string   `json:"nras_cache_dir"`
			RIMCacheDir           string   `json:"rim_cache_dir"`
		} `json:"peer"`
	} `json:"tee"`
}

func loadTEEConfigFile(path string) (teeConfigFile, error) {
	var cfg teeConfigFile
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c teeConfigFile) cacheDirs() tee.CacheDirs {
	p := c.TEE.Peer
	return tee.CacheDirs{VCEK: p.VCEKCacheDir, PCS: p.PCSCacheDir, NRAS: p.NRASCacheDir, RIM: p.RIMCacheDir}
}

// prefetchReport is what `tee prefetch --json` prints.
type prefetchReport struct {
	Provider       string           `json:"provider"`
	MeasurementHex string           `json:"measurement_hex"`
	Entries        []tee.CacheEntry `json:"entries"`
	EarliestExpiry string           `json:"earliest_expiry,omitempty"`
}

func teePrefetchCmd(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("tee prefetch", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "the daemon's configuration (sagvd, acp-compute or acp-bootstrap): its tee and tee.peer sections (required)")
	asJSON := flags.Bool("json", false, "print the result as JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "acpctl tee prefetch: --config is required")
		flags.Usage()
		return 2
	}
	cfg, err := loadTEEConfigFile(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl tee prefetch: %v\n", err)
		return 1
	}
	own, peer, err := prefetchFamilies(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl tee prefetch: %v\n", err)
		return 1
	}
	if own == tee.ProviderSimulated || peer == tee.ProviderSimulated {
		fmt.Fprintln(stdout, "nothing to prefetch: a simulated TEE asks no vendor")
		return 0
	}
	if own != peer {
		fmt.Fprintf(stderr, "acpctl tee prefetch: this host is %s and the peer is %s: prefetch fills a cache with what this host's own evidence needs; run it on a host of the peer's family and copy its cache directory here\n", own, peer)
		return 1
	}
	spec, err := prefetchSpec(cfg, own)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl tee prefetch: %v\n", err)
		return 1
	}
	producer, err := prefetchProducer(cfg, own)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl tee prefetch: %v\n", err)
		return 1
	}
	spec.ExpectedMeasurement = producer.Measurement()
	nonce := make(tee.Nonce, 32)
	if _, err := rand.Read(nonce); err != nil {
		fmt.Fprintf(stderr, "acpctl tee prefetch: nonce: %v\n", err)
		return 1
	}
	evidence, err := producer.Quote(nonce)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl tee prefetch: this host's report: %v\n", err)
		return 1
	}
	verifier, err := tee.BuildVerifier(spec)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl tee prefetch: build the %s verifier: %v\n", own, err)
		return 1
	}
	measurement, err := verifier.Verify(evidence, nonce)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl tee prefetch: this host's evidence did not verify with the vendors reachable: %v\n", err)
		return 1
	}
	now := time.Now()
	entries := tee.CacheStatus(cfg.cacheDirs(), now)
	if *asJSON {
		rep := prefetchReport{Provider: string(own), MeasurementHex: hex.EncodeToString(measurement), Entries: entries}
		if t, ok := tee.EarliestExpiry(entries); ok {
			rep.EarliestExpiry = t.UTC().Format(time.RFC3339)
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return 0
	}
	fmt.Fprintf(stdout, "prefetched for a %s peer on this host: its evidence verified under measurement %s…\n", own, hex.EncodeToString(measurement)[:16])
	printCacheEntries(stdout, entries, now)
	return 0
}

// prefetchFamilies resolves this host's family and the peer's. auto is
// the kernel's answer (ADR 0025); the provider names are the families
// the build runs for them.
func prefetchFamilies(cfg teeConfigFile) (own, peer tee.Provider, err error) {
	if cfg.TEE.Provider == "" {
		return "", "", errors.New("tee.provider is not set in the configuration")
	}
	own, err = tee.ParseProvider(cfg.TEE.Provider)
	if err != nil {
		return "", "", fmt.Errorf("tee.provider: %w", err)
	}
	if own == tee.ProviderAuto {
		family, _, err := tee.ResolveAuto(cfg.TEE.TSMReportDir)
		if err != nil {
			return "", "", fmt.Errorf("tee.provider=auto: %w", err)
		}
		own = family
	}
	if cfg.TEE.Peer.Provider == "" {
		return "", "", errors.New("tee.peer.provider is not set in the configuration: there is no verifier to prefetch for")
	}
	peer, err = tee.ParseProvider(cfg.TEE.Peer.Provider)
	if err != nil {
		return "", "", fmt.Errorf("tee.peer.provider: %w", err)
	}
	return own, peer, nil
}

// prefetchSpec is the peer verifier as the daemon would build it from the
// configuration, without the measurement pin (prefetch pins this host's
// own). It refuses what cannot be prefetched before any hardware is
// touched: a family this command does not cover, a missing AMD chain, a
// configuration with no cache to fill.
func prefetchSpec(cfg teeConfigFile, family tee.Provider) (tee.VerifierSpec, error) {
	p := cfg.TEE.Peer
	spec := tee.VerifierSpec{Provider: family}
	switch family {
	case tee.ProviderGCPSEVSNP:
		if p.VCEKCacheDir == "" {
			return spec, errors.New("tee.peer.vcek_cache_dir is not set: the verifier keeps no VCEK on disk, so there is nothing to fill")
		}
		if p.AMDCertChainPath == "" {
			return spec, errors.New("tee.peer.amd_cert_chain_path is not set")
		}
		chain, err := os.ReadFile(p.AMDCertChainPath)
		if err != nil {
			return spec, fmt.Errorf("read tee.peer.amd_cert_chain_path (%q): %w — `acpctl tee fetch-amd-chain --product <milan|genoa|turin> --out %s` writes it while a route to AMD KDS exists", p.AMDCertChainPath, err, p.AMDCertChainPath)
		}
		spec.GCPSEV = tee.GCPSEVVerifierConfig{AMDRootPEM: chain, AMDKDSURL: p.AMDKDSURL, VCEKCacheDir: p.VCEKCacheDir, MinReportedTCB: p.MinReportedTCB}
	case tee.ProviderGCPTDX:
		if p.PCSCacheDir == "" {
			return spec, errors.New("tee.peer.pcs_cache_dir is not set: the verifier keeps no PCS document on disk, so there is nothing to fill")
		}
		spec.GCPTDX = tee.GCPTDXVerifierConfig{PCSURL: p.PCSURL, PCSCacheDir: p.PCSCacheDir, AcceptableTCBStatuses: p.AcceptableTCBStatuses}
	default:
		return spec, fmt.Errorf("prefetch covers gcp-sev-snp and gcp-tdx; for %s run the daemon once with the vendors reachable — any attestation fills its caches — then `acpctl tee cache-status`", family)
	}
	return spec, nil
}

// prefetchProducer is this host's own TEE, the source of the evidence
// prefetch verifies.
func prefetchProducer(cfg teeConfigFile, family tee.Provider) (tee.Producer, error) {
	switch family {
	case tee.ProviderGCPSEVSNP:
		return tee.NewGCPSEVProducer(tee.GCPSEVProducerConfig{TSMReportDir: cfg.TEE.TSMReportDir})
	case tee.ProviderGCPTDX:
		return tee.NewGCPTDXProducer(tee.GCPTDXProducerConfig{TSMReportDir: cfg.TEE.TSMReportDir})
	default:
		return nil, fmt.Errorf("no producer for %s", family)
	}
}

func teeCacheStatusCmd(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("tee cache-status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "the daemon's configuration: the cache directories its tee.peer section names (required)")
	asJSON := flags.Bool("json", false, "print the entries as JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "acpctl tee cache-status: --config is required")
		flags.Usage()
		return 2
	}
	cfg, err := loadTEEConfigFile(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl tee cache-status: %v\n", err)
		return 1
	}
	dirs := cfg.cacheDirs()
	if dirs == (tee.CacheDirs{}) {
		fmt.Fprintln(stderr, "acpctl tee cache-status: the configuration names no cache directory (tee.peer.vcek_cache_dir, pcs_cache_dir, nras_cache_dir, rim_cache_dir): the verifier asks the vendors on every use")
		return 1
	}
	now := time.Now()
	entries := tee.CacheStatus(dirs, now)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(entries)
	} else {
		printCacheEntries(stdout, entries, now)
	}
	if len(entries) == 0 {
		fmt.Fprintln(stderr, "acpctl tee cache-status: the caches are empty: `acpctl tee prefetch --config` fills them while the vendors are reachable")
		return 1
	}
	for _, e := range entries {
		if !e.Current {
			return 1
		}
	}
	return 0
}

// printCacheEntries prints one line per cached document, the dirs they
// are in, and the earliest expiry.
func printCacheEntries(w io.Writer, entries []tee.CacheEntry, now time.Time) {
	if len(entries) == 0 {
		fmt.Fprintln(w, "the caches are empty")
		return
	}
	current := 0
	for _, e := range entries {
		state := "EXPIRED or unusable"
		if e.Current {
			state = "current"
			current++
		}
		var validity string
		switch {
		case !e.NotAfter.IsZero():
			validity = fmt.Sprintf("valid %s → %s", e.NotBefore.UTC().Format("2006-01-02"), e.NotAfter.UTC().Format("2006-01-02T15:04Z"))
			if e.Current {
				validity += fmt.Sprintf(" (%s left)", shortDuration(e.NotAfter.Sub(now)))
			}
		case e.Current:
			validity = "no expiry"
		}
		line := fmt.Sprintf("%-9s %-18s %s", e.Kind, state, e.Path())
		if e.Subject != "" {
			line += "  " + e.Subject
		}
		if validity != "" {
			line += "  " + validity
		}
		if e.Note != "" {
			line += "  — " + e.Note
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintf(w, "%d of %d current", current, len(entries))
	if t, ok := tee.EarliestExpiry(entries); ok {
		fmt.Fprintf(w, "; the earliest expiry is %s — run prefetch again before then, with the vendors reachable", t.UTC().Format(time.RFC3339))
	}
	fmt.Fprintln(w)
}

func shortDuration(d time.Duration) string {
	if d < 0 {
		return "0"
	}
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return strings.TrimSuffix(d.Round(time.Minute).String(), "0s")
	}
}
