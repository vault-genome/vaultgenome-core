// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// provisionCmd is `acpctl provision`: one command stands up the key
// material, the two daemons' configurations, their identities and pins,
// and seals every key file to the host — the first-deployment procedure
// (docs/operator/09_first_deployment.md, section 3) done by the release's
// own binaries from one place, instead of by hand or by each kit's shell.
//
// It runs the release's acp-keygen, sagvd and acp-compute (found in
// --bin-dir, beside acpctl, or on PATH): keygen writes the secrets tree;
// the configurations are written for the family named; each daemon's
// `identity` reads its measurement from the hardware and the other side
// pins it; each daemon's `seal-keys` seals its key files. The operator's
// copy of the REST token is kept beside the tree, never printed. What the
// command wrote and learned is in provision.json.
func provisionCmd(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("provision", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var o provisionOptions
	flags.StringVar(&o.out, "out", "", "the deployment directory to write (required; created 0700)")
	flags.StringVar(&o.binDir, "bin-dir", "", "where the release's acp-keygen, sagvd and acp-compute are (default: beside acpctl, then PATH)")
	flags.StringVar(&o.provider, "provider", "", "the TEE family both daemons attest with on this host: gcp-sev-snp, gcp-tdx, azure-sev-snp, simulated, or auto (configfs-tsm says which) (required)")
	flags.StringVar(&o.peerProvider, "peer-provider", "", "the family each daemon expects of the other (default: the provider, resolved when auto)")
	flags.StringVar(&o.sealer, "sealer", "auto", "tee.sealer for both daemons: auto, tee or tpm2 (ADR 0025 step 1b)")
	flags.BoolVar(&o.insecureSimulation, "insecure-simulation", false, "allow the simulated TEE (development only; both daemons refuse it otherwise)")
	flags.StringVar(&o.vaultListen, "vault-listen", "127.0.0.1:9443", "sagvd's Return Path listen address")
	flags.StringVar(&o.vaultAddress, "vault-address", "", "the address acp-compute dials (default: --vault-listen)")
	flags.StringVar(&o.vaultServerName, "vault-server-name", "localhost", "the TLS name acp-compute verifies sagvd's certificate against")
	flags.StringVar(&o.apiListen, "api-listen", "127.0.0.1:9080", "sagvd's REST API listen address")
	flags.StringVar(&o.vaultHealth, "vault-health", "127.0.0.1:9081", "sagvd's health and metrics listen address")
	flags.StringVar(&o.workerHealth, "worker-health", "127.0.0.1:9082", "acp-compute's health and metrics listen address")
	flags.StringVar(&o.amdCertChain, "amd-cert-chain", "", "the AMD ASK+ARK chain (PEM) of the chip's product, for a SEV-SNP peer")
	flags.StringVar(&o.fetchAMDChain, "fetch-amd-chain", "", "fetch the AMD chain for this product (milan, genoa, turin) from AMD KDS into the deployment directory, verified against the pinned roots (ADR 0024)")
	flags.StringVar(&o.kdsURL, "kds-url", "", "AMD KDS base URL for --fetch-amd-chain (default https://kdsintf.amd.com)")
	flags.StringVar(&o.pcsCacheDir, "pcs-cache-dir", "", "Intel PCS cache directory for a gcp-tdx peer (default <out>/pcs-cache)")
	flags.StringVar(&o.doorPython, "door-python", "", "the Python of the worker's runtime; with --base-model this makes the door command")
	flags.StringVar(&o.workerPackage, "worker-package", "", "the directory holding vg_genome (PYTHONPATH of the door)")
	flags.StringVar(&o.baseModel, "base-model", "", "the base model directory the door restores the genome onto")
	flags.StringVar(&o.device, "device", "cpu", "the door's device: cpu or cuda")
	flags.Var(&o.doorCommand, "door-command", "one argument of the door command, repeated (replaces --door-python and --base-model)")
	flags.IntVar(&o.doorTimeout, "door-timeout", 300, "the door's timeout in seconds")
	flags.StringVar(&o.genomeDir, "genome-dir", "", "sagvd's genome.bundle_dir (default <out>/genomes)")
	flags.StringVar(&o.auditLog, "audit-log", "", "sagvd's audit log (default <out>/audit/returnpath-audit.db)")
	flags.StringVar(&o.queuePath, "queue-path", "", "sagvd's job queue on disk (default <out>/queue/sagvd-jobs.db)")
	flags.StringVar(&o.vaultDescriptor, "vault-descriptor", "sagvd-v1", "sagvd's tee.workload_descriptor")
	flags.StringVar(&o.workerDescriptor, "worker-descriptor", "acp-compute-v1", "acp-compute's tee.workload_descriptor")
	flags.IntVar(&o.maxSessions, "max-sessions", 1, "sagvd's runtime.max_sessions")
	flags.StringVar(&o.logLevel, "log-level", "info", "both daemons' log level")
	flags.BoolVar(&o.force, "force", false, "overwrite an existing deployment directory's files")
	flags.BoolVar(&o.skipSeal, "skip-seal", false, "write everything but leave the key files unsealed (seal them with sagvd seal-keys and acp-compute seal-keys)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if o.out == "" || o.provider == "" {
		fmt.Fprintln(stderr, "acpctl provision: --out and --provider are required")
		flags.Usage()
		return 2
	}
	result, err := provision(o, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "acpctl provision:", err)
		return 1
	}
	printJSON(stdout, result)
	return 0
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, " ") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

type provisionOptions struct {
	out, binDir                                      string
	provider, peerProvider, sealer                   string
	insecureSimulation                               bool
	vaultListen, vaultAddress, vaultServerName       string
	apiListen, vaultHealth, workerHealth             string
	amdCertChain, fetchAMDChain, kdsURL, pcsCacheDir string
	doorPython, workerPackage, baseModel, device     string
	doorCommand                                      stringList
	doorTimeout                                      int
	genomeDir, auditLog, queuePath                   string
	vaultDescriptor, workerDescriptor                string
	maxSessions                                      int
	logLevel                                         string
	force, skipSeal                                  bool
}

// provisionResult is provision.json: what was written and learned. It
// carries no secret — the token's path, not the token.
type provisionResult struct {
	Schema        string              `json:"schema"`
	Out           string              `json:"out"`
	Provider      string              `json:"provider"`
	PeerProvider  string              `json:"peer_provider"`
	Sealer        string              `json:"sealer"`
	Binaries      map[string]string   `json:"binaries"`
	Secrets       string              `json:"secrets"`
	Configs       map[string]string   `json:"configs"`
	ConfigsSHA256 map[string]string   `json:"configs_sha256"`
	Pins          map[string]string   `json:"pins"`
	AMDCertChain  string              `json:"amd_cert_chain,omitempty"`
	Vault         provisionedSide     `json:"vault"`
	Worker        provisionedSide     `json:"worker"`
	APITokenFile  string              `json:"api_token_file"`
	Sealed        map[string][]string `json:"sealed,omitempty"`
	Next          []string            `json:"next"`
}

type provisionedSide struct {
	MeasurementHex        string   `json:"measurement_hex"`
	Sealer                string   `json:"sealer,omitempty"`
	VTPMPCRDigestHex      string   `json:"vtpm_pcr_digest_hex,omitempty"`
	AuditKID              string   `json:"audit_kid,omitempty"`
	AuditPublicKeyPEM     string   `json:"audit_public_key_pem,omitempty"`
	AuthorityKID          string   `json:"authority_kid,omitempty"`
	AuthorityPublicKeyPEM string   `json:"authority_public_key_pem,omitempty"`
	IdentityFile          string   `json:"identity_file"`
	Warnings              []string `json:"warnings,omitempty"`
}

// daemonIdentity is what `sagvd identity` and `acp-compute identity`
// print, the parts provision reads.
type daemonIdentity struct {
	TEEProvider           string `json:"tee_provider"`
	TEEMeasurementHex     string `json:"tee_measurement_hex"`
	Sealer                string `json:"sealer"`
	AuditKID              string `json:"audit_kid"`
	AuditPublicKeyPEM     string `json:"audit_public_key_pem"`
	AuthorityKID          string `json:"authority_kid"`
	AuthorityPublicKeyPEM string `json:"authority_public_key_pem"`
	VTPM                  *struct {
		PCRDigestHex string `json:"pcr_digest_hex"`
	} `json:"vtpm"`
}

// daemonSealed is what `seal-keys` prints, the parts provision reads.
type daemonSealed struct {
	Sealer string `json:"sealer"`
	Sealed []struct {
		Name string `json:"name"`
	} `json:"sealed"`
	AlreadySealed []struct {
		Name string `json:"name"`
	} `json:"already_sealed"`
}

// runDaemon runs a daemon's subcommand with a timeout and returns its
// stdout; stderr goes into the error. A var so tests substitute it.
var runDaemon = func(bin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // the release's own binaries, found by provisionBinaries
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", filepath.Base(bin), strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// provisionBinaries finds the release's binaries: in binDir, beside this
// executable, or on PATH. acp-keygen may be installed as keygen.
func provisionBinaries(binDir string) (map[string]string, error) {
	names := map[string][]string{"keygen": {"acp-keygen", "keygen"}, "sagvd": {"sagvd"}, "acp-compute": {"acp-compute"}}
	dirs := []string{}
	if binDir != "" {
		dirs = append(dirs, binDir)
	}
	if self, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(self))
	}
	found := map[string]string{}
	for key, candidates := range names {
		for _, dir := range dirs {
			for _, name := range candidates {
				p := filepath.Join(dir, name)
				if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
					found[key] = p
					break
				}
			}
			if found[key] != "" {
				break
			}
		}
		if found[key] == "" {
			for _, name := range candidates {
				if p, err := exec.LookPath(name); err == nil {
					found[key] = p
					break
				}
			}
		}
		if found[key] == "" {
			return nil, fmt.Errorf("the release's %s was not found in --bin-dir, beside acpctl or on PATH (looked for %s)", key, strings.Join(candidates, ", "))
		}
	}
	return found, nil
}

// provisionFamily resolves the family named: a hardware name as it is,
// auto through configfs-tsm on this host, and refuses what this command
// cannot set up.
func provisionFamily(name string) (local, resolved tee.Provider, err error) {
	p, err := tee.ParseProvider(name)
	if err != nil {
		return "", "", fmt.Errorf("--provider %q: %w", name, err)
	}
	switch p {
	case tee.ProviderAuto:
		family, tsm, err := tee.ResolveAuto("")
		if err != nil {
			return "", "", fmt.Errorf("--provider auto: %w", err)
		}
		_ = tsm
		return tee.ProviderAuto, family, nil
	case tee.ProviderGCPSEVSNP, tee.ProviderGCPTDX, tee.ProviderAzureSEVSNP, tee.ProviderSimulated:
		return p, p, nil
	case tee.ProviderAzureCGPU:
		return "", "", errors.New("--provider azure-cgpu: the confidential GPU VM needs its GPU attestation command and policy; set it up by the runbook (docs/operator/runbooks/real-tee-azure-cgpu.md)")
	default:
		return "", "", fmt.Errorf("--provider %q: no deployment this command can set up (supported: gcp-sev-snp, gcp-tdx, azure-sev-snp, simulated, auto)", name)
	}
}

// measurementLen is the pin's length for a family: 32 bytes for the
// simulated TEE (SHA-256 of the descriptor), 48 for the hardware ones.
func measurementLen(p tee.Provider) int {
	if p == tee.ProviderSimulated {
		return 32
	}
	return 48
}

func provision(o provisionOptions, stdout io.Writer) (*provisionResult, error) {
	if o.vaultAddress == "" {
		o.vaultAddress = o.vaultListen
	}
	local, family, err := provisionFamily(o.provider)
	if err != nil {
		return nil, err
	}
	peer := family
	if o.peerProvider != "" {
		if peer, err = tee.ParseProvider(o.peerProvider); err != nil {
			return nil, fmt.Errorf("--peer-provider %q: %w", o.peerProvider, err)
		}
		if peer == tee.ProviderAuto {
			return nil, errors.New("--peer-provider cannot be auto: name the family the other side attests as")
		}
	}
	if (family == tee.ProviderSimulated || peer == tee.ProviderSimulated) && !o.insecureSimulation {
		return nil, errors.New("the simulated TEE is for development: pass --insecure-simulation to set it up")
	}
	if family != tee.ProviderSimulated && peer == tee.ProviderSimulated || family == tee.ProviderSimulated && peer != tee.ProviderSimulated {
		return nil, errors.New("a hardware daemon and a simulated peer do not pin each other: both sides are simulated or neither")
	}
	switch o.sealer {
	case "auto", "tee", "tpm2":
	default:
		return nil, fmt.Errorf("--sealer %q: one of auto, tee, tpm2", o.sealer)
	}
	var door []string
	switch {
	case len(o.doorCommand) > 0:
		door = o.doorCommand
	case o.doorPython != "" && o.baseModel != "":
		door = []string{o.doorPython, "-m", "vg_genome", "door", "--stdin-genome", "--base", o.baseModel, "--device", o.device}
	default:
		return nil, errors.New("the worker's door: pass --door-python with --base-model (the worker runtime and the base model), or --door-command for each argument")
	}
	bins, err := provisionBinaries(o.binDir)
	if err != nil {
		return nil, err
	}
	out, err := filepath.Abs(o.out)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(out); err == nil && st.IsDir() && !o.force {
		entries, _ := os.ReadDir(out)
		if len(entries) > 0 {
			return nil, fmt.Errorf("%s exists and is not empty; pass --force to write into it", out)
		}
	}
	for _, d := range []string{out, filepath.Join(out, "pins"), filepath.Join(out, "operator")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	secrets := filepath.Join(out, "secrets")
	genomeDir := orDefault(o.genomeDir, filepath.Join(out, "genomes"))
	auditLog := orDefault(o.auditLog, filepath.Join(out, "audit", "returnpath-audit.db"))
	queuePath := orDefault(o.queuePath, filepath.Join(out, "queue", "sagvd-jobs.db"))
	for _, d := range []string{genomeDir, filepath.Dir(auditLog), filepath.Dir(queuePath)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(stdout, "provision: %s (family %s, peer %s, sealer %s)\n", out, family, peer, o.sealer)

	// 1. The key material.
	keygenArgs := []string{"-out", secrets, "-private", "-quiet"}
	if o.force {
		keygenArgs = append(keygenArgs, "-force")
	}
	if _, err := runDaemon(bins["keygen"], keygenArgs...); err != nil {
		return nil, fmt.Errorf("key material: %w", err)
	}
	fmt.Fprintf(stdout, "  key material: %s (acp-keygen, private modes)\n", secrets)
	tokenSrc := filepath.Join(secrets, "sagvd", "api_token")
	tokenCopy := filepath.Join(out, "operator", "api_token")
	if err := copyFile(tokenSrc, tokenCopy, 0o600); err != nil {
		return nil, fmt.Errorf("the operator's copy of the REST token: %w", err)
	}
	// The session sealing key is shared by value, not by file: each daemon
	// seals its own copy to the host it runs on (seal-keys seals a file to
	// the sealer of the daemon that ran it), so the worker gets a copy of
	// its own — what a worker on another host would carry anyway.
	workerSealingKey := filepath.Join(secrets, "acp-compute", "sealing.key")
	if err := copyFile(filepath.Join(secrets, "shared", "sealing.key"), workerSealingKey, 0o600); err != nil {
		return nil, fmt.Errorf("the worker's copy of the session sealing key: %w", err)
	}

	// 2. What the peer's verifier needs.
	res := &provisionResult{Schema: "vault-genome/acpctl-provision/v1", Out: out, Provider: string(local), PeerProvider: string(peer), Sealer: o.sealer,
		Binaries: bins, Secrets: secrets, Configs: map[string]string{}, ConfigsSHA256: map[string]string{}, Pins: map[string]string{}, APITokenFile: tokenCopy, Sealed: map[string][]string{}}
	peerCfg := map[string]any{"provider": string(peer)}
	switch peer {
	case tee.ProviderGCPSEVSNP, tee.ProviderAzureSEVSNP:
		chain := o.amdCertChain
		if o.fetchAMDChain != "" {
			chain = filepath.Join(out, "amd-"+strings.ToLower(o.fetchAMDChain)+"-cert_chain.pem")
			pem, info, err := tee.FetchAMDCertChain(o.kdsURL, o.fetchAMDChain)
			if err != nil {
				return nil, fmt.Errorf("--fetch-amd-chain %s: %w", o.fetchAMDChain, err)
			}
			if err := os.WriteFile(chain, pem, 0o600); err != nil {
				return nil, err
			}
			fmt.Fprintf(stdout, "  AMD chain: %s (%s; ARK %s, a root this build pins)\n", chain, info.Product, info.ARKFingerprintSHA256)
		}
		if chain == "" {
			return nil, fmt.Errorf("a %s peer needs the AMD chain of the chip's product: --amd-cert-chain PATH or --fetch-amd-chain milan|genoa|turin", peer)
		}
		if _, err := os.Stat(chain); err != nil {
			return nil, fmt.Errorf("--amd-cert-chain: %w", err)
		}
		if chain, err = filepath.Abs(chain); err != nil {
			return nil, err
		}
		res.AMDCertChain = chain
		vcek := filepath.Join(out, "vcek-cache")
		if err := os.MkdirAll(vcek, 0o700); err != nil {
			return nil, err
		}
		peerCfg["amd_cert_chain_path"] = chain
		peerCfg["vcek_cache_dir"] = vcek
	case tee.ProviderGCPTDX:
		pcs := orDefault(o.pcsCacheDir, filepath.Join(out, "pcs-cache"))
		if err := os.MkdirAll(pcs, 0o700); err != nil {
			return nil, err
		}
		peerCfg["pcs_cache_dir"] = pcs
	}

	// 3. The pins: placeholders of the family's length until identity fills them.
	vaultPin := filepath.Join(out, "pins", "vault.measurement")
	workerPin := filepath.Join(out, "pins", "worker.measurement")
	for _, p := range []string{vaultPin, workerPin} {
		if err := os.WriteFile(p, make([]byte, measurementLen(peer)), 0o600); err != nil {
			return nil, err
		}
	}
	res.Pins["vault"], res.Pins["worker"] = vaultPin, workerPin

	// 4. The configurations.
	sec := func(p ...string) string { return filepath.Join(append([]string{secrets}, p...)...) }
	teeOf := func(descriptor, seed string, peerPin, peerPub string) map[string]any {
		t := map[string]any{"provider": string(local), "sealer": o.sealer, "workload_descriptor": descriptor}
		pc := map[string]any{}
		for k, v := range peerCfg {
			pc[k] = v
		}
		pc["measurement_path"] = peerPin
		if family == tee.ProviderSimulated {
			t["seed_path"] = seed
			t["insecure_simulation"] = true
			pc["public_key_path"] = peerPub
		}
		t["peer"] = pc
		return t
	}
	sagvdCfg := map[string]any{
		"vault": map[string]any{"listen_address": o.vaultListen,
			"tls": map[string]any{"enabled": true, "server_cert": sec("sagvd", "tls", "server.crt"), "server_key": sec("sagvd", "tls", "server.key"), "client_cas": sec("shared", "tls", "ca.crt")}},
		"http_api": map[string]any{"listen_address": o.apiListen, "bearer_token_file": sec("sagvd", "api_token")},
		"tee":      teeOf(o.vaultDescriptor, sec("sagvd", "tee_seed"), workerPin, sec("sagvd", "peer_worker_pubkey")),
		"keys": map[string]any{
			"authority_signing": map[string]any{"kid": "sagvd-authority-demo", "seed_path": sec("sagvd", "authority_signing_seed")},
			"audit_signing":     map[string]any{"kid": "sagvd-audit-demo", "seed_path": sec("sagvd", "audit_signing_seed")},
			"session_sealing":   map[string]any{"kid": "session-sealing-demo", "material_path": sec("shared", "sealing.key")}},
		"workers": map[string]any{"registry_path": sec("shared", "workers.json")},
		"genome":  map[string]any{"bundle_dir": genomeDir, "gate": map[string]any{"atol": 1e-2, "rtol": 1e-3, "max_non_critical_outliers": 0}},
		"audit":   map[string]any{"log_path": auditLog, "segment_events": 100000, "segment_max_age_seconds": 86400},
		"queue":   map[string]any{"path": queuePath, "retain_finished_seconds": 30 * 86400},
		"runtime": map[string]any{"job_timeout_seconds": 600, "handshake_timeout_seconds": 30, "queue_poll_ms": 50, "max_sessions": o.maxSessions,
			"http_read_header_timeout_seconds": 5, "http_write_timeout_seconds": 30, "default_job_deadline_seconds": 600, "max_payload_bytes": 4 << 20},
		"health": map[string]any{"listen_address": o.vaultHealth},
		"log":    map[string]any{"level": o.logLevel, "format": "json"},
	}
	doorCfg := map[string]any{"command": door, "timeout_seconds": o.doorTimeout}
	env := []string{"TOKENIZERS_PARALLELISM=false"}
	if o.workerPackage != "" {
		env = append([]string{"PYTHONPATH=" + o.workerPackage}, env...)
	}
	doorCfg["env"] = env
	workerCfg := map[string]any{
		"vault": map[string]any{"address": o.vaultAddress,
			"tls": map[string]any{"enabled": true, "client_cert": sec("acp-compute", "tls", "client.crt"), "client_key": sec("acp-compute", "tls", "client.key"), "ca_bundle": sec("shared", "tls", "ca.crt"), "server_name": o.vaultServerName}},
		"tee": teeOf(o.workerDescriptor, sec("acp-compute", "tee_seed"), vaultPin, sec("acp-compute", "peer_vault_pubkey")),
		"keys": map[string]any{
			"worker_signing":  map[string]any{"kid": "acp-compute-worker-demo", "seed_path": sec("acp-compute", "worker_signing_seed")},
			"session_sealing": map[string]any{"kid": "session-sealing-demo", "material_path": workerSealingKey}},
		"genome":  map[string]any{"door": doorCfg},
		"runtime": map[string]any{"job_timeout_seconds": 600, "handshake_timeout_seconds": 30, "dial_backoff_initial_ms": 500, "dial_backoff_max_ms": 5000, "idle_between_jobs_ms": 200},
		"health":  map[string]any{"listen_address": o.workerHealth},
		"log":     map[string]any{"level": o.logLevel, "format": "json"},
	}
	sagvdPath, workerPath := filepath.Join(out, "sagvd.json"), filepath.Join(out, "acp-compute.json")
	for _, c := range []struct {
		path string
		cfg  map[string]any
	}{{sagvdPath, sagvdCfg}, {workerPath, workerCfg}} {
		raw, err := json.MarshalIndent(c.cfg, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(c.path, append(raw, '\n'), 0o600); err != nil {
			return nil, err
		}
	}
	res.Configs["sagvd"], res.Configs["acp-compute"] = sagvdPath, workerPath
	for key, path := range res.Configs {
		if res.ConfigsSHA256[key], err = provisionDigest(path); err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(stdout, "  configurations: %s, %s\n", sagvdPath, workerPath)

	// 5. The identities, and the pins from them: each side pins the other.
	identify := func(key, bin, cfg, pinPath, name string, side *provisionedSide) error {
		raw, err := runDaemon(bin, "identity", "-config", cfg)
		if err != nil {
			return fmt.Errorf("%s identity: %w", name, err)
		}
		var id daemonIdentity
		if err := json.Unmarshal(raw, &id); err != nil {
			return fmt.Errorf("%s identity: not JSON: %w", name, err)
		}
		m, err := hex.DecodeString(id.TEEMeasurementHex)
		if err != nil || len(m) != measurementLen(peer) {
			return fmt.Errorf("%s identity: tee_measurement_hex %q is not a %d-byte measurement", name, id.TEEMeasurementHex, measurementLen(peer))
		}
		if err := os.WriteFile(pinPath, m, 0o600); err != nil {
			return err
		}
		idFile := filepath.Join(out, key+"-identity.json")
		if err := os.WriteFile(idFile, raw, 0o600); err != nil {
			return err
		}
		side.MeasurementHex, side.Sealer, side.IdentityFile = id.TEEMeasurementHex, id.Sealer, idFile
		side.AuditKID, side.AuditPublicKeyPEM = id.AuditKID, id.AuditPublicKeyPEM
		side.AuthorityKID, side.AuthorityPublicKeyPEM = id.AuthorityKID, id.AuthorityPublicKeyPEM
		if id.VTPM != nil {
			side.VTPMPCRDigestHex = id.VTPM.PCRDigestHex
		}
		if id.TEEProvider != "" && tee.Provider(id.TEEProvider) != family && tee.Provider(id.TEEProvider) != local {
			side.Warnings = append(side.Warnings, fmt.Sprintf("%s attests as %s, not the %s this deployment names", name, id.TEEProvider, family))
		}
		fmt.Fprintf(stdout, "  %s identity: %s (%s)\n", name, id.TEEMeasurementHex, id.TEEProvider)
		return nil
	}
	// sagvd's measurement is the worker's pin, and the worker's is sagvd's.
	if err := identify("sagvd", bins["sagvd"], sagvdPath, vaultPin, "sagvd", &res.Vault); err != nil {
		return nil, err
	}
	if err := identify("acp-compute", bins["acp-compute"], workerPath, workerPin, "acp-compute", &res.Worker); err != nil {
		return nil, err
	}
	if res.Vault.AuditPublicKeyPEM != "" {
		auditPub := filepath.Join(out, "operator", "audit_public_key.pem")
		if err := os.WriteFile(auditPub, []byte(res.Vault.AuditPublicKeyPEM), 0o600); err != nil {
			return nil, err
		}
		fmt.Fprintf(stdout, "  audit public key: %s (keep it off the host: it verifies the log)\n", auditPub)
	}

	// 6. The key files sealed to this host.
	if o.skipSeal {
		res.Next = append(res.Next, bins["sagvd"]+" seal-keys -config "+sagvdPath, bins["acp-compute"]+" seal-keys -config "+workerPath)
	} else {
		for _, s := range []struct{ key, bin, cfg string }{{"sagvd", bins["sagvd"], sagvdPath}, {"acp-compute", bins["acp-compute"], workerPath}} {
			raw, err := runDaemon(s.bin, "seal-keys", "-config", s.cfg)
			if err != nil {
				return nil, fmt.Errorf("%s seal-keys: %w", s.key, err)
			}
			var sealed daemonSealed
			if err := json.Unmarshal(raw, &sealed); err != nil {
				return nil, fmt.Errorf("%s seal-keys: not JSON: %w", s.key, err)
			}
			names := []string{}
			for _, e := range sealed.Sealed {
				names = append(names, e.Name)
			}
			for _, e := range sealed.AlreadySealed {
				names = append(names, e.Name+" (already)")
			}
			res.Sealed[s.key] = names
			fmt.Fprintf(stdout, "  %s key files sealed (%s): %s\n", s.key, sealed.Sealer, strings.Join(names, ", "))
		}
	}
	res.Next = append(res.Next, bins["sagvd"]+" -config "+sagvdPath, bins["acp-compute"]+" -config "+workerPath,
		"acpctl genome seal --content-dir <genome> --output "+filepath.Join(genomeDir, "gen-0.genome")+" --key-out "+filepath.Join(genomeDir, "gen-0.key"))
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(out, "provision.json"), append(raw, '\n'), 0o600); err != nil {
		return nil, err
	}
	fmt.Fprintf(stdout, "  REST token (the operator's copy): %s (not printed)\n", tokenCopy)
	fmt.Fprintf(stdout, "provision.json: %s\n", filepath.Join(out, "provision.json"))
	return res, nil
}

func orDefault(v, d string) string {
	if v != "" {
		return v
	}
	return d
}

// copyFile copies src to dst with mode, refusing to follow a symlink.
func copyFile(src, dst string, mode fs.FileMode) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", src)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, mode)
}

// provisionDigest is the SHA-256 of a config as written, for the summary
// an operator compares against the host's copy.
func provisionDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
