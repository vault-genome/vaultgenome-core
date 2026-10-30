// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
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
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/console"
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
//
// Across two hosts (ADR 0028) the same work is three commands:
// `provision authority` on the authority's host, which writes the
// worker's bundle; `provision join --bundle` on the worker's host; and
// `provision pin-worker --identity` on the authority's host, with the
// identity the worker wrote.
func provisionCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "authority":
			return provisionAuthorityCmd(args[1:], stdout, stderr)
		case "join":
			return provisionJoinCmd(args[1:], stdout, stderr)
		case "pin-worker":
			return provisionPinWorkerCmd(args[1:], stdout, stderr)
		case "help", "-h", "--help":
			provisionUsage(stderr)
			return 0
		}
	}
	flags := flag.NewFlagSet("provision", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var o provisionOptions
	o.commonFlags(flags)
	o.authorityFlags(flags)
	o.workerFlags(flags)
	flags.StringVar(&o.peerProvider, "peer-provider", "", "the family each daemon expects of the other (default: the provider, resolved when auto)")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl provision --out DIR --provider FAMILY [flags]            (both daemons on this host)")
		fmt.Fprintln(stderr, "       acpctl provision authority|join|pin-worker [flags]             (two hosts, ADR 0028; see acpctl provision help)")
		flags.PrintDefaults()
	}
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

func provisionUsage(w io.Writer) {
	fmt.Fprintln(w, "acpctl provision stands up a deployment with the release's own binaries.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "One host (both daemons):")
	fmt.Fprintln(w, "  acpctl provision --out DIR --provider FAMILY [--fetch-amd-chain PRODUCT] --door-python PY --base-model DIR ...")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Two hosts (ADR 0028), in this order:")
	fmt.Fprintln(w, "  1. on the authority's host:")
	fmt.Fprintln(w, "     acpctl provision authority --out DIR --provider FAMILY --worker-provider FAMILY \\")
	fmt.Fprintln(w, "         --vault-listen 0.0.0.0:9443 --vault-address HOST:9443 [--fetch-amd-chain WORKER-PRODUCT] [--fetch-own-amd-chain OWN-PRODUCT]")
	fmt.Fprintln(w, "     -> DIR/worker-bundle.tar: carry it to the worker's host, once, and delete it after step 2")
	fmt.Fprintln(w, "  2. on the worker's host:")
	fmt.Fprintln(w, "     acpctl provision join --bundle worker-bundle.tar --out DIR [--provider auto] --door-python PY --base-model DIR ...")
	fmt.Fprintln(w, "     -> DIR/acp-compute-identity.json: carry it back to the authority's host")
	fmt.Fprintln(w, "  3. on the authority's host:")
	fmt.Fprintln(w, "     acpctl provision pin-worker --out DIR --identity acp-compute-identity.json")
	fmt.Fprintln(w, "     -> the deployment is complete; start sagvd (again, if it was started before this step), then acp-compute")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Each form prints its flags with -h.")
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
	consoleListen                                    string
	amdCertChain, fetchAMDChain, kdsURL, pcsCacheDir string
	ownAMDCertChain, fetchOwnAMDChain                string
	doorPython, workerPackage, baseModel, device     string
	doorCommand                                      stringList
	doorTimeout                                      int
	genomeDir, auditLog, queuePath                   string
	vaultDescriptor, workerDescriptor                string
	maxSessions                                      int
	logLevel                                         string
	force, skipSeal                                  bool
	// two hosts
	workerProvider, bundle, identity string
}

// commonFlags are the flags every form takes.
func (o *provisionOptions) commonFlags(flags *flag.FlagSet) {
	flags.StringVar(&o.out, "out", "", "the deployment directory to write (required; created 0700)")
	flags.StringVar(&o.binDir, "bin-dir", "", "where the release's acp-keygen, sagvd and acp-compute are (default: beside acpctl, then PATH)")
	flags.StringVar(&o.provider, "provider", "", "the TEE family the daemon(s) on this host attest with: gcp-sev-snp, aws-sev-snp, gcp-tdx, azure-sev-snp, simulated, or auto (configfs-tsm says which — on EC2 the machine's vendor — or the vTPM's HCL report under Azure's paravisor)")
	flags.StringVar(&o.sealer, "sealer", "auto", "tee.sealer for the daemon(s) on this host: auto, tee or tpm2 (ADR 0025 step 1b)")
	flags.BoolVar(&o.insecureSimulation, "insecure-simulation", false, "allow the simulated TEE (development only; the daemons refuse it otherwise)")
	flags.StringVar(&o.logLevel, "log-level", "info", "the daemons' log level")
	flags.BoolVar(&o.force, "force", false, "overwrite an existing deployment directory's files")
	flags.BoolVar(&o.skipSeal, "skip-seal", false, "write everything but leave the key files unsealed (seal them with the daemon's seal-keys)")
}

// authorityFlags are the flags of the authority's side.
func (o *provisionOptions) authorityFlags(flags *flag.FlagSet) {
	flags.StringVar(&o.vaultListen, "vault-listen", "127.0.0.1:9443", "sagvd's Return Path listen address")
	flags.StringVar(&o.vaultAddress, "vault-address", "", "the address acp-compute dials (default: --vault-listen; required when the listen address binds every interface)")
	flags.StringVar(&o.vaultServerName, "vault-server-name", "localhost", "the TLS name acp-compute verifies sagvd's certificate against")
	flags.StringVar(&o.apiListen, "api-listen", "127.0.0.1:9080", "sagvd's REST API listen address")
	flags.StringVar(&o.consoleListen, "console-listen", "", "Where sagvd listens for the people's consoles (ADR 0039), as host:port; empty: no console. Passes are made with `acpctl console invite`")
	flags.StringVar(&o.vaultHealth, "vault-health", "127.0.0.1:9081", "sagvd's health and metrics listen address")
	flags.StringVar(&o.amdCertChain, "amd-cert-chain", "", "the AMD ASK+ARK chain (PEM) of the worker's chip's product, for sagvd's verifier of a SEV-SNP worker")
	flags.StringVar(&o.fetchAMDChain, "fetch-amd-chain", "", "fetch the AMD chain for the worker's product (milan, genoa, turin) from AMD KDS into the deployment directory, verified against the pinned roots (ADR 0024); the VLEK chain for an aws-sev-snp worker (ADR 0038)")
	flags.StringVar(&o.kdsURL, "kds-url", "", "AMD KDS base URL for the chain fetches (default https://kdsintf.amd.com)")
	flags.StringVar(&o.pcsCacheDir, "pcs-cache-dir", "", "Intel PCS cache directory for a gcp-tdx peer (default <out>/pcs-cache)")
	flags.StringVar(&o.genomeDir, "genome-dir", "", "sagvd's genome.bundle_dir (default <out>/genomes)")
	flags.StringVar(&o.auditLog, "audit-log", "", "sagvd's audit log (default <out>/audit/returnpath-audit.db)")
	flags.StringVar(&o.queuePath, "queue-path", "", "sagvd's job queue on disk (default <out>/queue/sagvd-jobs.db)")
	flags.StringVar(&o.vaultDescriptor, "vault-descriptor", "sagvd-v1", "sagvd's tee.workload_descriptor")
	flags.StringVar(&o.workerDescriptor, "worker-descriptor", "acp-compute-v1", "acp-compute's tee.workload_descriptor")
	flags.IntVar(&o.maxSessions, "max-sessions", 1, "sagvd's runtime.max_sessions")
}

// workerFlags are the flags of the worker's side: its door and its health
// listener.
func (o *provisionOptions) workerFlags(flags *flag.FlagSet) {
	flags.StringVar(&o.workerHealth, "worker-health", "127.0.0.1:9082", "acp-compute's health and metrics listen address")
	flags.StringVar(&o.doorPython, "door-python", "", "the Python of the worker's runtime; with --base-model this makes the door command")
	flags.StringVar(&o.workerPackage, "worker-package", "", "the directory holding vg_genome (PYTHONPATH of the door)")
	flags.StringVar(&o.baseModel, "base-model", "", "the base model directory the door restores the genome onto")
	flags.StringVar(&o.device, "device", "cpu", "the door's device: cpu or cuda")
	flags.Var(&o.doorCommand, "door-command", "one argument of the door command, repeated (replaces --door-python and --base-model)")
	flags.IntVar(&o.doorTimeout, "door-timeout", 300, "the door's timeout in seconds")
}

// provisionResult is provision.json: what was written and learned. It
// carries no secret — the token's path, not the token.
type provisionResult struct {
	Schema string `json:"schema"`
	// Role is both (one host), authority or worker (ADR 0028); Phase is
	// complete, awaiting-worker (the authority before pin-worker) or
	// joined (the worker).
	Role          string              `json:"role"`
	Phase         string              `json:"phase"`
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
	APITokenFile  string              `json:"api_token_file,omitempty"`
	Sealed        map[string][]string `json:"sealed,omitempty"`
	// WorkerBundle is the bundle the authority wrote for the worker's
	// host; WorkerBundleSHA256 its hash; VaultAddress what the worker
	// dials (two hosts).
	WorkerBundle       string   `json:"worker_bundle,omitempty"`
	WorkerBundleSHA256 string   `json:"worker_bundle_sha256,omitempty"`
	VaultAddress       string   `json:"vault_address,omitempty"`
	Next               []string `json:"next"`
}

type provisionedSide struct {
	Provider              string   `json:"provider,omitempty"`
	MeasurementHex        string   `json:"measurement_hex"`
	Sealer                string   `json:"sealer,omitempty"`
	VTPMPCRDigestHex      string   `json:"vtpm_pcr_digest_hex,omitempty"`
	VTPMPCRs              string   `json:"vtpm_pcrs,omitempty"`
	VLEKCSPID             string   `json:"vlek_csp_id,omitempty"`
	AuditKID              string   `json:"audit_kid,omitempty"`
	AuditPublicKeyPEM     string   `json:"audit_public_key_pem,omitempty"`
	AuthorityKID          string   `json:"authority_kid,omitempty"`
	AuthorityPublicKeyPEM string   `json:"authority_public_key_pem,omitempty"`
	IdentityFile          string   `json:"identity_file,omitempty"`
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
	AWSSEVSNP             *struct {
		CSPID string `json:"csp_id"`
	} `json:"aws_sev_snp"`
	VTPM *struct {
		PCRs         []string `json:"pcrs"`
		PCRDigestHex string   `json:"pcr_digest_hex"`
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

// provisionBinaries finds the release's binaries named in need (keygen,
// sagvd, acp-compute): in binDir, beside this executable, or on PATH.
// acp-keygen may be installed as keygen.
func provisionBinaries(binDir string, need ...string) (map[string]string, error) {
	names := map[string][]string{"keygen": {"acp-keygen", "keygen"}, "sagvd": {"sagvd"}, "acp-compute": {"acp-compute"}}
	if len(need) == 0 {
		need = []string{"keygen", "sagvd", "acp-compute"}
	}
	dirs := []string{}
	if binDir != "" {
		dirs = append(dirs, binDir)
	}
	if self, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(self))
	}
	found := map[string]string{}
	for _, key := range need {
		candidates := names[key]
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
	case tee.ProviderGCPSEVSNP, tee.ProviderAWSSEVSNP, tee.ProviderGCPTDX, tee.ProviderAzureSEVSNP, tee.ProviderSimulated:
		return p, p, nil
	case tee.ProviderAzureCGPU:
		return "", "", errors.New("--provider azure-cgpu: the confidential GPU VM needs its GPU attestation command and policy; set it up by the runbook (docs/operator/runbooks/real-tee-azure-cgpu.md)")
	case tee.ProviderGCPSEVSNPVTPM:
		return "", "", errors.New("--provider gcp-sev-snp-vtpm: each host's boot (pcr_digests) is pinned from its own identity after its first boot has settled; set it up by the runbook (docs/operator/runbooks/real-tee-gcp-sev-snp-vtpm.md)")
	default:
		return "", "", fmt.Errorf("--provider %q: no deployment this command can set up (supported: gcp-sev-snp, aws-sev-snp, gcp-tdx, azure-sev-snp, simulated, auto)", name)
	}
}

// peerFamily parses the family the other side attests as, under the
// flag named, and checks it against this host's.
func peerFamily(flagName, name string, family tee.Provider, insecureSimulation bool) (tee.Provider, error) {
	peer := family
	if name != "" {
		p, err := tee.ParseProvider(name)
		if err != nil {
			return "", fmt.Errorf("%s %q: %w", flagName, name, err)
		}
		if p == tee.ProviderAuto {
			return "", fmt.Errorf("%s cannot be auto: name the family the other side attests as", flagName)
		}
		peer = p
	}
	if (family == tee.ProviderSimulated || peer == tee.ProviderSimulated) && !insecureSimulation {
		return "", errors.New("the simulated TEE is for development: pass --insecure-simulation to set it up")
	}
	if family != tee.ProviderSimulated && peer == tee.ProviderSimulated || family == tee.ProviderSimulated && peer != tee.ProviderSimulated {
		return "", errors.New("a hardware daemon and a simulated peer do not pin each other: both sides are simulated or neither")
	}
	return peer, nil
}

// measurementLen is the pin's length for a family: 32 bytes for the
// simulated TEE (SHA-256 of the descriptor), 48 for the hardware ones.
func measurementLen(p tee.Provider) int {
	if p == tee.ProviderSimulated {
		return 32
	}
	return 48
}

// checkSealer validates --sealer.
func checkSealer(s string) error {
	switch s {
	case "auto", "tee", "tpm2", "both":
		return nil
	default:
		return fmt.Errorf("--sealer %q: one of auto, tee, tpm2, both", s)
	}
}

// doorOf resolves the worker's door command from the flags.
func doorOf(o provisionOptions) ([]string, error) {
	switch {
	case len(o.doorCommand) > 0:
		return o.doorCommand, nil
	case o.doorPython != "" && o.baseModel != "":
		return []string{o.doorPython, "-m", "vg_genome", "door", "--stdin-genome", "--base", o.baseModel, "--device", o.device}, nil
	default:
		return nil, errors.New("the worker's door: pass --door-python with --base-model (the worker runtime and the base model), or --door-command for each argument")
	}
}

// prepareOut resolves the deployment directory, refusing a non-empty one
// without --force, and creates it with the subdirectories named.
func prepareOut(o provisionOptions, subdirs ...string) (string, error) {
	out, err := filepath.Abs(o.out)
	if err != nil {
		return "", err
	}
	if st, err := os.Stat(out); err == nil && st.IsDir() && !o.force {
		entries, _ := os.ReadDir(out)
		if len(entries) > 0 {
			return "", fmt.Errorf("%s exists and is not empty; pass --force to write into it", out)
		}
	}
	for _, d := range append([]string{out}, subdirs...) {
		if !filepath.IsAbs(d) {
			d = filepath.Join(out, d)
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", err
		}
	}
	return out, nil
}

// amdSignerFor is the key a family's reports are signed by: a VLEK on EC2
// (the ASVK+ARK chain), the chip's VCEK elsewhere (ADR 0038).
func amdSignerFor(family tee.Provider) string {
	if family == tee.ProviderAWSSEVSNP {
		return tee.AMDSignerVLEK
	}
	return tee.AMDSignerVCEK
}

// amdChain resolves a SEV-SNP peer's chain: the PEM given, or fetched for
// the product named into out — the chain of signer (vcek or vlek); the
// result is an absolute path.
func amdChain(out, given, fetch, kdsURL, signer, what string, stdout io.Writer) (string, error) {
	chain := given
	if fetch != "" {
		name := "amd-" + strings.ToLower(fetch) + "-cert_chain.pem"
		if signer == tee.AMDSignerVLEK {
			name = "amd-" + strings.ToLower(fetch) + "-vlek-cert_chain.pem"
		}
		chain = filepath.Join(out, name)
		pem, info, err := tee.FetchAMDCertChainSigned(kdsURL, fetch, signer)
		if err != nil {
			return "", fmt.Errorf("fetch the AMD %s chain for %s: %w", signer, fetch, err)
		}
		if err := os.WriteFile(chain, pem, 0o600); err != nil {
			return "", err
		}
		fmt.Fprintf(stdout, "  AMD %s chain (%s): %s (%s; ARK %s, a root this build pins)\n", strings.ToUpper(signer), what, chain, info.Product, info.ARKFingerprintSHA256)
	}
	if chain == "" {
		return "", nil
	}
	if _, err := os.Stat(chain); err != nil {
		return "", fmt.Errorf("the AMD chain (%s): %w", what, err)
	}
	return filepath.Abs(chain)
}

// peerConfig is the tee.peer configuration a daemon needs to verify a
// peer of family: the AMD chain and VCEK cache for a SEV-SNP peer, the
// Intel PCS cache for a TDX one.
func peerConfig(out string, family tee.Provider, chain, pcsCacheDir string) (map[string]any, error) {
	cfg := map[string]any{"provider": string(family)}
	switch family {
	case tee.ProviderGCPSEVSNP, tee.ProviderAzureSEVSNP:
		if chain == "" {
			return nil, fmt.Errorf("a %s peer needs the AMD chain of its chip's product: --amd-cert-chain PATH or --fetch-amd-chain milan|genoa|turin", family)
		}
		vcek := filepath.Join(out, "vcek-cache")
		if err := os.MkdirAll(vcek, 0o700); err != nil {
			return nil, err
		}
		cfg["amd_cert_chain_path"] = chain
		cfg["vcek_cache_dir"] = vcek
	case tee.ProviderAWSSEVSNP:
		// No VCEK to cache: the VLEK travels with the report; the chain is
		// the ASVK+ARK bundle. csp_ids is pinned from the peer's identity
		// (its VLEK's CSP_ID) once that is known.
		if chain == "" {
			return nil, fmt.Errorf("a %s peer needs the AMD VLEK chain of its chip's product: --amd-cert-chain PATH or --fetch-amd-chain milan (ADR 0038)", family)
		}
		cfg["amd_cert_chain_path"] = chain
	case tee.ProviderGCPTDX:
		pcs := orDefault(pcsCacheDir, filepath.Join(out, "pcs-cache"))
		if err := os.MkdirAll(pcs, 0o700); err != nil {
			return nil, err
		}
		cfg["pcs_cache_dir"] = pcs
	}
	if bootPinned(family) {
		cfg["pcr_digests"] = []string{placeholderBoot}
	}
	return cfg, nil
}

// bootPinned reports whether a peer of family is pinned to its boot as
// well as its measurement: the families whose launch measurement is the
// cloud's — Azure's paravisor and firmware, Google's UEFI — and whose OS
// only the vTPM measures (ADR 0037).
func bootPinned(family tee.Provider) bool {
	return family == tee.ProviderAzureSEVSNP || family == tee.ProviderAzureCGPU || family == tee.ProviderGCPSEVSNPVTPM
}

// bootPCRsFor is the PCR selection a host of family quotes and seals
// under, written as tee.vtpm_quote_pcrs and tee.vtpm_seal_pcrs: for the
// Azure families the boot without PCR 10, IMA's runtime log, which the
// images Azure ships extend as files are first read — a digest over it
// names one moment of one boot, and a pin or a seal taken then does not
// hold across a restart (ADR 0037, amendment of 2026-10-28). Empty where
// the daemon's default serves.
func bootPCRsFor(family tee.Provider) string {
	if family == tee.ProviderAzureSEVSNP || family == tee.ProviderAzureCGPU {
		return tee.TPMBootPCRsWithoutIMA
	}
	return ""
}

// placeholderBoot is a boot pin until the peer's identity names its own:
// a digest no boot measures, so a daemon started before the pin refuses
// every peer, as it does on the measurement's placeholder.
var placeholderBoot = strings.Repeat("0", 2*sha256.Size)

// pinBoot puts the peer's boot — the vTPM digest its identity printed — in
// place of the placeholder in the configuration at path, and records the
// configuration's new digest under key.
func pinBoot(res *provisionResult, key, path, digestHex, peerName string, stdout io.Writer) error {
	if d, err := hex.DecodeString(digestHex); err != nil || len(d) != sha256.Size {
		return fmt.Errorf("%s identity: vtpm.pcr_digest_hex %q is not a 32-byte digest: %s pins the peer's boot as well as its measurement (ADR 0037)", peerName, digestHex, key)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var cfg map[string]any
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	teeCfg, _ := cfg["tee"].(map[string]any)
	peerCfg, _ := teeCfg["peer"].(map[string]any)
	if peerCfg == nil {
		return fmt.Errorf("%s: no tee.peer to pin the boot in", path)
	}
	peerCfg["pcr_digests"] = []string{digestHex}
	pinned, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(pinned, '\n'), 0o600); err != nil {
		return err
	}
	if res.ConfigsSHA256[key], err = provisionDigest(path); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "  %s pins %s boot: %s\n", key, peerName, digestHex)
	return nil
}

// printBootPCRs says which PCRs the configurations quote and seal under,
// where the selection is provision's and not the daemon's default.
func printBootPCRs(stdout io.Writer, family tee.Provider) {
	if sel := bootPCRsFor(family); sel != "" {
		fmt.Fprintf(stdout, "  boot PCRs, quoted and sealed: %s (IMA's PCR 10 left out: it moves within a boot)\n", sel)
	}
}

// teeSection is a daemon's tee configuration: this host's family and
// sealer, the descriptor, and the peer it verifies and pins.
func teeSection(local, family tee.Provider, sealer, descriptor string, peerCfg map[string]any, peerPin, seed, peerPub string) map[string]any {
	t := map[string]any{"provider": string(local), "sealer": sealer, "workload_descriptor": descriptor}
	if sel := bootPCRsFor(family); sel != "" {
		t["vtpm_quote_pcrs"], t["vtpm_seal_pcrs"] = sel, sel
	}
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

// sagvdConfig is sagvd.json for the deployment.
func sagvdConfig(o provisionOptions, out, secrets string, teeCfg map[string]any, genomeDir, auditLog, queuePath string) map[string]any {
	sec := func(p ...string) string { return filepath.Join(append([]string{secrets}, p...)...) }
	cfg := map[string]any{
		"vault": map[string]any{"listen_address": o.vaultListen,
			"tls": map[string]any{"enabled": true, "server_cert": sec("sagvd", "tls", "server.crt"), "server_key": sec("sagvd", "tls", "server.key"), "client_cas": sec("shared", "tls", "ca.crt")}},
		"http_api": map[string]any{"listen_address": o.apiListen, "bearer_token_file": sec("sagvd", "api_token")},
		"tee":      teeCfg,
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
	if o.consoleListen != "" {
		// The operator key is the first owner's, written when they join
		// (ADR 0039): it is made on their computer, never here.
		dir := filepath.Join(out, "console")
		cfg["console"] = map[string]any{"listen_address": o.consoleListen, "dir": dir}
		cfg["operator_stop"] = map[string]any{"kid": console.StopKeyID, "public_key_path": filepath.Join(dir, "operator_stop.pem"), "list_path": filepath.Join(dir, "stop_list.json")}
	}
	return cfg
}

// workerConfig is acp-compute.json for the deployment: the authority it
// dials, its own keys, the door.
func workerConfig(o provisionOptions, secrets string, teeCfg map[string]any, vaultAddress, serverName string, door []string, sealingKey string) map[string]any {
	sec := func(p ...string) string { return filepath.Join(append([]string{secrets}, p...)...) }
	doorCfg := map[string]any{"command": door, "timeout_seconds": o.doorTimeout}
	env := []string{"TOKENIZERS_PARALLELISM=false"}
	if o.workerPackage != "" {
		env = append([]string{"PYTHONPATH=" + o.workerPackage}, env...)
	}
	doorCfg["env"] = env
	return map[string]any{
		"vault": map[string]any{"address": vaultAddress,
			"tls": map[string]any{"enabled": true, "client_cert": sec("acp-compute", "tls", "client.crt"), "client_key": sec("acp-compute", "tls", "client.key"), "ca_bundle": sec("shared", "tls", "ca.crt"), "server_name": serverName}},
		"tee": teeCfg,
		"keys": map[string]any{
			"worker_signing":  map[string]any{"kid": "acp-compute-worker-demo", "seed_path": sec("acp-compute", "worker_signing_seed")},
			"session_sealing": map[string]any{"kid": "session-sealing-demo", "material_path": sealingKey}},
		"genome":  map[string]any{"door": doorCfg},
		"runtime": map[string]any{"job_timeout_seconds": 600, "handshake_timeout_seconds": 30, "dial_backoff_initial_ms": 500, "dial_backoff_max_ms": 5000, "idle_between_jobs_ms": 200},
		"health":  map[string]any{"listen_address": o.workerHealth},
		"log":     map[string]any{"level": o.logLevel, "format": "json"},
	}
}

// writeConfigs writes each configuration 0600 and records its digest.
func writeConfigs(res *provisionResult, configs map[string]struct {
	path string
	cfg  map[string]any
}) error {
	keys := make([]string, 0, len(configs))
	for k := range configs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		c := configs[key]
		raw, err := json.MarshalIndent(c.cfg, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(c.path, append(raw, '\n'), 0o600); err != nil {
			return err
		}
		res.Configs[key] = c.path
		if res.ConfigsSHA256[key], err = provisionDigest(c.path); err != nil {
			return err
		}
	}
	return nil
}

// identify runs a daemon's identity, pins its measurement at pinPath,
// keeps the identity file and fills side.
func identify(out, key, bin, cfg, pinPath, name string, family, local tee.Provider, side *provisionedSide, stdout io.Writer) error {
	raw, err := runDaemon(bin, "identity", "-config", cfg)
	if err != nil {
		return fmt.Errorf("%s identity: %w", name, err)
	}
	var id daemonIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		return fmt.Errorf("%s identity: not JSON: %w", name, err)
	}
	m, err := hex.DecodeString(id.TEEMeasurementHex)
	if err != nil || len(m) != measurementLen(family) {
		return fmt.Errorf("%s identity: tee_measurement_hex %q is not a %d-byte measurement", name, id.TEEMeasurementHex, measurementLen(family))
	}
	if pinPath != "" {
		if err := os.WriteFile(pinPath, m, 0o600); err != nil {
			return err
		}
	}
	idFile := filepath.Join(out, key+"-identity.json")
	if err := os.WriteFile(idFile, raw, 0o600); err != nil {
		return err
	}
	side.Provider = id.TEEProvider
	side.MeasurementHex, side.Sealer, side.IdentityFile = id.TEEMeasurementHex, id.Sealer, idFile
	side.AuditKID, side.AuditPublicKeyPEM = id.AuditKID, id.AuditPublicKeyPEM
	side.AuthorityKID, side.AuthorityPublicKeyPEM = id.AuthorityKID, id.AuthorityPublicKeyPEM
	if id.AWSSEVSNP != nil {
		side.VLEKCSPID = id.AWSSEVSNP.CSPID
	}
	if id.VTPM != nil {
		side.VTPMPCRDigestHex = id.VTPM.PCRDigestHex
		side.VTPMPCRs = strings.Join(id.VTPM.PCRs, "+")
		// The pin is a digest over the PCRs the daemon quoted: those must
		// be the ones its configuration names, or the pin names another
		// selection than the operator chose — a daemon that predates
		// tee.vtpm_quote_pcrs for its family quotes its default.
		if want := bootPCRsFor(family); want != "" && len(id.VTPM.PCRs) > 0 && side.VTPMPCRs != want {
			return fmt.Errorf("%s identity: its vTPM quoted %s, not the %s its configuration names (tee.vtpm_quote_pcrs): a %s that predates the selection? the release's binaries go together", name, side.VTPMPCRs, want, key)
		}
	}
	if id.TEEProvider != "" && tee.Provider(id.TEEProvider) != family && tee.Provider(id.TEEProvider) != local {
		side.Warnings = append(side.Warnings, fmt.Sprintf("%s attests as %s, not the %s this deployment names", name, id.TEEProvider, family))
	}
	fmt.Fprintf(stdout, "  %s identity: %s (%s)\n", name, id.TEEMeasurementHex, id.TEEProvider)
	return nil
}

// sealKeys runs a daemon's seal-keys and records what it sealed.
func sealKeys(res *provisionResult, key, bin, cfg string, stdout io.Writer) error {
	raw, err := runDaemon(bin, "seal-keys", "-config", cfg)
	if err != nil {
		return fmt.Errorf("%s seal-keys: %w", key, err)
	}
	var sealed daemonSealed
	if err := json.Unmarshal(raw, &sealed); err != nil {
		return fmt.Errorf("%s seal-keys: not JSON: %w", key, err)
	}
	names := []string{}
	for _, e := range sealed.Sealed {
		names = append(names, e.Name)
	}
	for _, e := range sealed.AlreadySealed {
		names = append(names, e.Name+" (already)")
	}
	res.Sealed[key] = names
	fmt.Fprintf(stdout, "  %s key files sealed (%s): %s\n", key, sealed.Sealer, strings.Join(names, ", "))
	return nil
}

// writeAuditPublicKey keeps the audit public key for the operator.
func writeAuditPublicKey(out string, res *provisionResult, stdout io.Writer) error {
	if res.Vault.AuditPublicKeyPEM == "" {
		return nil
	}
	auditPub := filepath.Join(out, "operator", "audit_public_key.pem")
	if err := os.WriteFile(auditPub, []byte(res.Vault.AuditPublicKeyPEM), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "  audit public key: %s (keep it off the host: it verifies the log)\n", auditPub)
	return nil
}

// writeResult writes provision.json.
func writeResult(out string, res *provisionResult, stdout io.Writer) error {
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "provision.json"), append(raw, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "provision.json: %s\n", filepath.Join(out, "provision.json"))
	return nil
}

// keygen runs acp-keygen into secrets, keeps the operator's copy of the
// REST token and gives the worker its own copy of the session sealing
// key: each daemon seals its own copy to the host it runs on (seal-keys
// seals a file to the sealer of the daemon that ran it) — what a worker
// on another host carries anyway.
func keygen(bins map[string]string, out, secrets string, force bool, stdout io.Writer) (tokenCopy, workerSealingKey string, err error) {
	keygenArgs := []string{"-out", secrets, "-private", "-quiet"}
	if force {
		keygenArgs = append(keygenArgs, "-force")
	}
	if _, err := runDaemon(bins["keygen"], keygenArgs...); err != nil {
		return "", "", fmt.Errorf("key material: %w", err)
	}
	fmt.Fprintf(stdout, "  key material: %s (acp-keygen, private modes)\n", secrets)
	tokenCopy = filepath.Join(out, "operator", "api_token")
	if err := copyFile(filepath.Join(secrets, "sagvd", "api_token"), tokenCopy, 0o600); err != nil {
		return "", "", fmt.Errorf("the operator's copy of the REST token: %w", err)
	}
	workerSealingKey = filepath.Join(secrets, "acp-compute", "sealing.key")
	if err := copyFile(filepath.Join(secrets, "shared", "sealing.key"), workerSealingKey, 0o600); err != nil {
		return "", "", fmt.Errorf("the worker's copy of the session sealing key: %w", err)
	}
	return tokenCopy, workerSealingKey, nil
}

// provision is the one-host form: both daemons on this host.
func provision(o provisionOptions, stdout io.Writer) (*provisionResult, error) {
	if o.vaultAddress == "" {
		o.vaultAddress = o.vaultListen
	}
	local, family, err := provisionFamily(o.provider)
	if err != nil {
		return nil, err
	}
	peer, err := peerFamily("--peer-provider", o.peerProvider, family, o.insecureSimulation)
	if err != nil {
		return nil, err
	}
	if err := checkSealer(o.sealer); err != nil {
		return nil, err
	}
	door, err := doorOf(o)
	if err != nil {
		return nil, err
	}
	bins, err := provisionBinaries(o.binDir)
	if err != nil {
		return nil, err
	}
	genomeDir, auditLog, queuePath := o.genomeDir, o.auditLog, o.queuePath
	out, err := prepareOut(o, "pins", "operator")
	if err != nil {
		return nil, err
	}
	genomeDir = orDefault(genomeDir, filepath.Join(out, "genomes"))
	auditLog = orDefault(auditLog, filepath.Join(out, "audit", "returnpath-audit.db"))
	queuePath = orDefault(queuePath, filepath.Join(out, "queue", "sagvd-jobs.db"))
	for _, d := range []string{genomeDir, filepath.Dir(auditLog), filepath.Dir(queuePath)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	secrets := filepath.Join(out, "secrets")
	fmt.Fprintf(stdout, "provision: %s (family %s, peer %s, sealer %s)\n", out, family, peer, o.sealer)

	// 1. The key material.
	tokenCopy, workerSealingKey, err := keygen(bins, out, secrets, o.force, stdout)
	if err != nil {
		return nil, err
	}

	// 2. What the peer's verifier needs: one chip, one chain, both ways.
	res := &provisionResult{Schema: "vault-genome/acpctl-provision/v1", Role: "both", Phase: "complete", Out: out, Provider: string(local), PeerProvider: string(peer), Sealer: o.sealer,
		Binaries: bins, Secrets: secrets, Configs: map[string]string{}, ConfigsSHA256: map[string]string{}, Pins: map[string]string{}, APITokenFile: tokenCopy, Sealed: map[string][]string{}}
	chain, err := amdChain(out, o.amdCertChain, o.fetchAMDChain, o.kdsURL, amdSignerFor(peer), "the chip's product", stdout)
	if err != nil {
		return nil, err
	}
	res.AMDCertChain = chain
	peerCfg, err := peerConfig(out, peer, chain, o.pcsCacheDir)
	if err != nil {
		return nil, err
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
	sagvdPath, workerPath := filepath.Join(out, "sagvd.json"), filepath.Join(out, "acp-compute.json")
	if err := writeConfigs(res, map[string]struct {
		path string
		cfg  map[string]any
	}{
		"sagvd": {sagvdPath, sagvdConfig(o, out, secrets,
			teeSection(local, family, o.sealer, o.vaultDescriptor, peerCfg, workerPin, sec("sagvd", "tee_seed"), sec("sagvd", "peer_worker_pubkey")), genomeDir, auditLog, queuePath)},
		"acp-compute": {workerPath, workerConfig(o, secrets,
			teeSection(local, family, o.sealer, o.workerDescriptor, peerCfg, vaultPin, sec("acp-compute", "tee_seed"), sec("acp-compute", "peer_vault_pubkey")),
			o.vaultAddress, o.vaultServerName, door, workerSealingKey)},
	}); err != nil {
		return nil, err
	}
	fmt.Fprintf(stdout, "  configurations: %s, %s\n", sagvdPath, workerPath)
	printBootPCRs(stdout, family)

	// 5. The identities, and the pins from them: each side pins the other,
	// its measurement and, where the vTPM measures the OS, its boot.
	if err := identify(out, "sagvd", bins["sagvd"], sagvdPath, vaultPin, "sagvd", family, local, &res.Vault, stdout); err != nil {
		return nil, err
	}
	if err := identify(out, "acp-compute", bins["acp-compute"], workerPath, workerPin, "acp-compute", family, local, &res.Worker, stdout); err != nil {
		return nil, err
	}
	if bootPinned(peer) {
		if err := pinBoot(res, "sagvd", sagvdPath, res.Worker.VTPMPCRDigestHex, "acp-compute's", stdout); err != nil {
			return nil, err
		}
		if err := pinBoot(res, "acp-compute", workerPath, res.Vault.VTPMPCRDigestHex, "sagvd's", stdout); err != nil {
			return nil, err
		}
	}
	if err := writeAuditPublicKey(out, res, stdout); err != nil {
		return nil, err
	}

	// 6. The key files sealed to this host.
	if o.skipSeal {
		res.Next = append(res.Next, bins["sagvd"]+" seal-keys -config "+sagvdPath, bins["acp-compute"]+" seal-keys -config "+workerPath)
	} else {
		for _, s := range []struct{ key, bin, cfg string }{{"sagvd", bins["sagvd"], sagvdPath}, {"acp-compute", bins["acp-compute"], workerPath}} {
			if err := sealKeys(res, s.key, s.bin, s.cfg, stdout); err != nil {
				return nil, err
			}
		}
	}
	res.Next = append(res.Next, bins["sagvd"]+" -config "+sagvdPath, bins["acp-compute"]+" -config "+workerPath,
		"acpctl genome seal --content-dir <genome> --output "+filepath.Join(genomeDir, "gen-0.genome")+" --key-out "+filepath.Join(genomeDir, "gen-0.key"))
	if err := writeResult(out, res, stdout); err != nil {
		return nil, err
	}
	fmt.Fprintf(stdout, "  REST token (the operator's copy): %s (not printed)\n", tokenCopy)
	return res, nil
}

// ---------------------------------------------------------------------
// Two hosts (ADR 0028)
// ---------------------------------------------------------------------

// workerBundleSchema names the bundle's manifest.
const workerBundleSchema = "vault-genome/acpctl-worker-bundle/v1"

// workerBundle is the manifest of worker-bundle.tar: who the authority is
// and where, what the worker is, and every file with its SHA-256. The
// files are the worker's secrets, the CA certificate, the authority's
// measurement as the worker's pin, and the authority's AMD chain when
// the worker verifies a SEV-SNP authority.
type workerBundle struct {
	Schema    string            `json:"schema"`
	Authority bundleAuthority   `json:"authority"`
	Worker    bundleWorker      `json:"worker"`
	Files     map[string]string `json:"files"`
}

type bundleAuthority struct {
	Provider        string `json:"provider"`
	MeasurementHex  string `json:"measurement_hex"`
	VaultAddress    string `json:"vault_address"`
	VaultServerName string `json:"vault_server_name"`
	// AMDCertChain is the bundle path of the authority's product's chain,
	// for the worker's verifier of a SEV-SNP authority.
	AMDCertChain string `json:"amd_cert_chain,omitempty"`
	// PCRDigestHex is the authority's boot as its vTPM measured it, for the
	// worker's pin of an authority whose OS only the vTPM measures.
	PCRDigestHex string `json:"pcr_digest_hex,omitempty"`
	// CSPID is the authority's VLEK's CSP_ID, for the worker's pin of an
	// aws-sev-snp authority (tee.peer.csp_ids; ADR 0038).
	CSPID string `json:"csp_id,omitempty"`
}

type bundleWorker struct {
	Provider   string `json:"provider"`
	Descriptor string `json:"descriptor"`
	Simulated  bool   `json:"simulated"`
}

// bundleName is the file the authority writes.
const bundleName = "worker-bundle.tar"

// writeWorkerBundle writes the bundle at path: the manifest first, then
// every file under root named in files, each hashed into the manifest.
func writeWorkerBundle(bundlePath, root string, files []string, m workerBundle) (string, error) {
	m.Files = map[string]string{}
	type entry struct {
		name string
		data []byte
	}
	var entries []entry
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return "", fmt.Errorf("the worker's bundle: %w", err)
		}
		sum := sha256.Sum256(data)
		m.Files[name] = hex.EncodeToString(sum[:])
		entries = append(entries, entry{name, data})
	}
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Unix(0, 0), Format: tar.FormatPAX}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := write("bundle.json", append(manifest, '\n')); err != nil {
		return "", err
	}
	for _, e := range entries {
		if err := write(e.name, e.data); err != nil {
			return "", err
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := os.WriteFile(bundlePath, buf.Bytes(), 0o600); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// readWorkerBundle reads a bundle: its manifest, and every file checked
// against the manifest's hash. A file the manifest does not list, a hash
// that does not match, or a name that leaves the deployment directory is
// refused.
func readWorkerBundle(bundlePath string) (workerBundle, map[string][]byte, error) {
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return workerBundle{}, nil, fmt.Errorf("--bundle: %w", err)
	}
	tr := tar.NewReader(bytes.NewReader(raw))
	var m workerBundle
	files := map[string][]byte{}
	haveManifest := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return workerBundle{}, nil, fmt.Errorf("--bundle: not a bundle: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return workerBundle{}, nil, fmt.Errorf("--bundle: %q is not a regular file", h.Name)
		}
		name := h.Name
		if name != path.Clean(name) || path.IsAbs(name) || name == "." || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
			return workerBundle{}, nil, fmt.Errorf("--bundle: %q is not a path inside the deployment", h.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			return workerBundle{}, nil, fmt.Errorf("--bundle: read %q: %w", name, err)
		}
		if name == "bundle.json" {
			if err := json.Unmarshal(data, &m); err != nil {
				return workerBundle{}, nil, fmt.Errorf("--bundle: its manifest does not decode: %w", err)
			}
			haveManifest = true
			continue
		}
		files[name] = data
	}
	if !haveManifest {
		return workerBundle{}, nil, errors.New("--bundle: no bundle.json manifest")
	}
	if m.Schema != workerBundleSchema {
		return workerBundle{}, nil, fmt.Errorf("--bundle: schema %q, want %s", m.Schema, workerBundleSchema)
	}
	for name, data := range files {
		want, listed := m.Files[name]
		if !listed {
			return workerBundle{}, nil, fmt.Errorf("--bundle: %q is in the bundle but not in its manifest", name)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != want {
			return workerBundle{}, nil, fmt.Errorf("--bundle: %q does not hash to what the manifest says", name)
		}
	}
	for name := range m.Files {
		if _, ok := files[name]; !ok {
			return workerBundle{}, nil, fmt.Errorf("--bundle: %q is in the manifest but not in the bundle", name)
		}
	}
	if m.Authority.VaultAddress == "" || m.Authority.MeasurementHex == "" || m.Worker.Provider == "" {
		return workerBundle{}, nil, errors.New("--bundle: the manifest does not name the authority's address and measurement and the worker's family")
	}
	return m, files, nil
}

// pathInside joins a bundle entry's name under root and refuses a result
// that is not strictly inside root: the manifest's names are checked when
// the bundle is read, and the path is checked again where it is written.
func pathInside(root, name string) (string, error) {
	root = filepath.Clean(root)
	if name == "" || path.IsAbs(name) || filepath.IsAbs(name) || name != path.Clean(name) {
		return "", fmt.Errorf("--bundle: %q is not a path inside the deployment", name)
	}
	dst := filepath.Clean(filepath.Join(root, filepath.FromSlash(name)))
	if !strings.HasPrefix(dst, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("--bundle: %q is not a path inside the deployment", name)
	}
	return dst, nil
}

// unspecifiedHost reports whether a listen address binds every interface.
func unspecifiedHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

// provisionAuthorityCmd is `acpctl provision authority`.
func provisionAuthorityCmd(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("provision authority", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var o provisionOptions
	o.commonFlags(flags)
	o.authorityFlags(flags)
	flags.StringVar(&o.workerProvider, "worker-provider", "", "the TEE family the worker attests with on its host (default: this host's family)")
	flags.StringVar(&o.ownAMDCertChain, "own-amd-chain", "", "the AMD chain (PEM) of this host's chip's product, carried in the bundle for the worker's verifier of a SEV-SNP authority")
	flags.StringVar(&o.fetchOwnAMDChain, "fetch-own-amd-chain", "", "fetch the AMD chain for this host's product (milan, genoa, turin) from AMD KDS for the bundle")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl provision authority --out DIR --provider FAMILY [--worker-provider FAMILY] --vault-listen ADDR --vault-address HOST:PORT [flags]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Step 1 of 3 on the authority's host (ADR 0028): the key material, sagvd's configuration for the")
		fmt.Fprintln(stderr, "worker's family, sagvd's identity and sealed key files, and DIR/worker-bundle.tar for the worker's host.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if o.out == "" || o.provider == "" {
		fmt.Fprintln(stderr, "acpctl provision authority: --out and --provider are required")
		flags.Usage()
		return 2
	}
	result, err := provisionAuthority(o, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "acpctl provision authority:", err)
		return 1
	}
	printJSON(stdout, result)
	return 0
}

// provisionAuthority is step 1 of 3: everything the one-host form does
// except what needs the worker's chip, and the bundle for the worker.
func provisionAuthority(o provisionOptions, stdout io.Writer) (*provisionResult, error) {
	if o.vaultAddress == "" {
		if unspecifiedHost(o.vaultListen) {
			return nil, fmt.Errorf("--vault-listen %s binds every interface: pass --vault-address HOST:PORT, the address the worker dials", o.vaultListen)
		}
		o.vaultAddress = o.vaultListen
	}
	if _, _, err := net.SplitHostPort(o.vaultAddress); err != nil {
		return nil, fmt.Errorf("--vault-address %q: %w", o.vaultAddress, err)
	}
	local, family, err := provisionFamily(o.provider)
	if err != nil {
		return nil, err
	}
	worker, err := peerFamily("--worker-provider", o.workerProvider, family, o.insecureSimulation)
	if err != nil {
		return nil, err
	}
	if err := checkSealer(o.sealer); err != nil {
		return nil, err
	}
	bins, err := provisionBinaries(o.binDir, "keygen", "sagvd")
	if err != nil {
		return nil, err
	}
	out, err := prepareOut(o, "pins", "operator")
	if err != nil {
		return nil, err
	}
	genomeDir := orDefault(o.genomeDir, filepath.Join(out, "genomes"))
	auditLog := orDefault(o.auditLog, filepath.Join(out, "audit", "returnpath-audit.db"))
	queuePath := orDefault(o.queuePath, filepath.Join(out, "queue", "sagvd-jobs.db"))
	for _, d := range []string{genomeDir, filepath.Dir(auditLog), filepath.Dir(queuePath)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	secrets := filepath.Join(out, "secrets")
	fmt.Fprintf(stdout, "provision authority: %s (family %s, worker %s, sealer %s, the worker dials %s)\n", out, family, worker, o.sealer, o.vaultAddress)

	// 1. The key material: both sides', the worker's to leave in the bundle.
	tokenCopy, workerSealingKey, err := keygen(bins, out, secrets, o.force, stdout)
	if err != nil {
		return nil, err
	}
	res := &provisionResult{Schema: "vault-genome/acpctl-provision/v1", Role: "authority", Phase: "awaiting-worker", Out: out, Provider: string(local), PeerProvider: string(worker), Sealer: o.sealer,
		Binaries: bins, Secrets: secrets, Configs: map[string]string{}, ConfigsSHA256: map[string]string{}, Pins: map[string]string{}, APITokenFile: tokenCopy, Sealed: map[string][]string{},
		VaultAddress: o.vaultAddress}

	// 2. What sagvd's verifier needs of the worker's family, and what the
	// worker's verifier needs of this host's: two chains when both are
	// SEV-SNP chips.
	chain, err := amdChain(out, o.amdCertChain, o.fetchAMDChain, o.kdsURL, amdSignerFor(worker), "the worker's product, for sagvd", stdout)
	if err != nil {
		return nil, err
	}
	res.AMDCertChain = chain
	peerCfg, err := peerConfig(out, worker, chain, o.pcsCacheDir)
	if err != nil {
		return nil, err
	}
	var ownChain string
	if family == tee.ProviderGCPSEVSNP || family == tee.ProviderAzureSEVSNP || family == tee.ProviderAWSSEVSNP {
		ownChain, err = amdChain(out, o.ownAMDCertChain, o.fetchOwnAMDChain, o.kdsURL, amdSignerFor(family), "this host's product, for the worker", stdout)
		if err != nil {
			return nil, err
		}
		if ownChain == "" {
			return nil, fmt.Errorf("the worker verifies this host's %s report: pass --own-amd-chain PATH or --fetch-own-amd-chain milan|genoa|turin, the chain of this chip's product", family)
		}
	}

	// 3. The pins: sagvd's placeholder until its identity fills it; the
	// worker's placeholder until pin-worker.
	vaultPin := filepath.Join(out, "pins", "vault.measurement")
	workerPin := filepath.Join(out, "pins", "worker.measurement")
	for _, p := range []string{vaultPin, workerPin} {
		if err := os.WriteFile(p, make([]byte, measurementLen(worker)), 0o600); err != nil {
			return nil, err
		}
	}
	res.Pins["vault"], res.Pins["worker"] = vaultPin, workerPin

	// 4. sagvd's configuration.
	sec := func(p ...string) string { return filepath.Join(append([]string{secrets}, p...)...) }
	sagvdPath := filepath.Join(out, "sagvd.json")
	if err := writeConfigs(res, map[string]struct {
		path string
		cfg  map[string]any
	}{
		"sagvd": {sagvdPath, sagvdConfig(o, out, secrets,
			teeSection(local, family, o.sealer, o.vaultDescriptor, peerCfg, workerPin, sec("sagvd", "tee_seed"), sec("sagvd", "peer_worker_pubkey")), genomeDir, auditLog, queuePath)},
	}); err != nil {
		return nil, err
	}
	fmt.Fprintf(stdout, "  configuration: %s\n", sagvdPath)
	printBootPCRs(stdout, family)

	// 5. sagvd's identity: the worker's pin, into the bundle.
	if err := identify(out, "sagvd", bins["sagvd"], sagvdPath, vaultPin, "sagvd", family, local, &res.Vault, stdout); err != nil {
		return nil, err
	}
	if err := writeAuditPublicKey(out, res, stdout); err != nil {
		return nil, err
	}

	// 6. The worker's bundle: its secrets, the CA, the authority's
	// measurement and chain, under a manifest of hashes. Then the
	// worker's secrets leave this host.
	files := []string{
		"secrets/acp-compute/worker_signing_seed", "secrets/acp-compute/sealing.key",
		"secrets/acp-compute/tls/client.crt", "secrets/acp-compute/tls/client.key",
		"secrets/shared/tls/ca.crt", "pins/vault.measurement",
	}
	if family == tee.ProviderSimulated {
		files = append(files, "secrets/acp-compute/tee_seed", "secrets/acp-compute/peer_vault_pubkey")
	}
	_ = workerSealingKey
	manifest := workerBundle{Schema: workerBundleSchema,
		Authority: bundleAuthority{Provider: string(family), MeasurementHex: res.Vault.MeasurementHex, VaultAddress: o.vaultAddress, VaultServerName: o.vaultServerName, CSPID: res.Vault.VLEKCSPID},
		Worker:    bundleWorker{Provider: string(worker), Descriptor: o.workerDescriptor, Simulated: worker == tee.ProviderSimulated}}
	if bootPinned(family) {
		if d, err := hex.DecodeString(res.Vault.VTPMPCRDigestHex); err != nil || len(d) != sha256.Size {
			return nil, fmt.Errorf("sagvd identity: vtpm.pcr_digest_hex %q is not a 32-byte digest: the worker pins a %s authority's boot as well as its measurement (ADR 0037)", res.Vault.VTPMPCRDigestHex, family)
		}
		manifest.Authority.PCRDigestHex = res.Vault.VTPMPCRDigestHex
	}
	if ownChain != "" {
		rel, err := filepath.Rel(out, ownChain)
		if err != nil || strings.HasPrefix(rel, "..") {
			// A chain given from outside the deployment: copy it in.
			rel = filepath.Join("chains", "authority-amd-cert_chain.pem")
			if err := copyFile(ownChain, filepath.Join(out, rel), 0o600); err != nil {
				return nil, err
			}
		}
		manifest.Authority.AMDCertChain = filepath.ToSlash(rel)
		files = append(files, filepath.ToSlash(rel))
	}
	bundlePath := filepath.Join(out, bundleName)
	sum, err := writeWorkerBundle(bundlePath, out, files, manifest)
	if err != nil {
		return nil, err
	}
	if err := os.RemoveAll(filepath.Join(secrets, "acp-compute")); err != nil {
		return nil, fmt.Errorf("remove the worker's secrets from this host: %w", err)
	}
	res.WorkerBundle, res.WorkerBundleSHA256 = bundlePath, sum
	res.Worker = provisionedSide{Provider: string(worker)}
	fmt.Fprintf(stdout, "  worker bundle: %s (sha256 %s; %d files; the worker's secrets are no longer on this host)\n", bundlePath, sum, len(files))

	// 7. sagvd's key files sealed to this host.
	if o.skipSeal {
		res.Next = append(res.Next, bins["sagvd"]+" seal-keys -config "+sagvdPath)
	} else if err := sealKeys(res, "sagvd", bins["sagvd"], sagvdPath, stdout); err != nil {
		return nil, err
	}
	res.Next = append(res.Next,
		"carry "+bundlePath+" to the worker's host over a channel you trust (it holds the worker's private keys); delete it there after the next step",
		"on the worker's host: acpctl provision join --bundle "+bundleName+" --out <dir> --door-python <python> --base-model <dir> --worker-package <dir>",
		"carry the worker's <dir>/acp-compute-identity.json back here",
		"acpctl provision pin-worker --out "+out+" --identity acp-compute-identity.json",
		bins["sagvd"]+" -config "+sagvdPath+" (after pin-worker; pins are read at start)",
		"acpctl genome seal --content-dir <genome> --output "+filepath.Join(genomeDir, "gen-0.genome")+" --key-out "+filepath.Join(genomeDir, "gen-0.key"))
	if err := writeResult(out, res, stdout); err != nil {
		return nil, err
	}
	fmt.Fprintf(stdout, "  REST token (the operator's copy): %s (not printed)\n", tokenCopy)
	return res, nil
}

// provisionJoinCmd is `acpctl provision join`.
func provisionJoinCmd(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("provision join", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var o provisionOptions
	o.commonFlags(flags)
	o.workerFlags(flags)
	flags.StringVar(&o.bundle, "bundle", "", "the worker-bundle.tar the authority's host wrote (required)")
	flags.StringVar(&o.workerDescriptor, "worker-descriptor", "", "acp-compute's tee.workload_descriptor (default: what the bundle names)")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl provision join --bundle worker-bundle.tar --out DIR [--provider auto] --door-python PY --base-model DIR [flags]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Step 2 of 3 on the worker's host (ADR 0028): the bundle unpacked into DIR, acp-compute's configuration")
		fmt.Fprintln(stderr, "for the authority it names, acp-compute's identity (DIR/acp-compute-identity.json, for pin-worker) and")
		fmt.Fprintln(stderr, "its key files sealed to this host.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if o.out == "" || o.bundle == "" {
		fmt.Fprintln(stderr, "acpctl provision join: --out and --bundle are required")
		flags.Usage()
		return 2
	}
	if o.provider == "" {
		o.provider = "auto"
	}
	result, err := provisionJoin(o, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "acpctl provision join:", err)
		return 1
	}
	printJSON(stdout, result)
	return 0
}

// provisionJoin is step 2 of 3: the worker's host joins the deployment
// the bundle describes.
func provisionJoin(o provisionOptions, stdout io.Writer) (*provisionResult, error) {
	m, files, err := readWorkerBundle(o.bundle)
	if err != nil {
		return nil, err
	}
	workerFamily := tee.Provider(m.Worker.Provider)
	authorityFamily := tee.Provider(m.Authority.Provider)
	local, family, err := provisionFamily(o.provider)
	if err != nil {
		return nil, err
	}
	if family != workerFamily {
		return nil, fmt.Errorf("this host attests as %s, but the authority provisioned the worker as %s (its --worker-provider): the authority would refuse it; provision the authority again for this family, or run this on a %s host", family, workerFamily, workerFamily)
	}
	if family == tee.ProviderSimulated && !o.insecureSimulation {
		return nil, errors.New("the simulated TEE is for development: pass --insecure-simulation to set it up")
	}
	if err := checkSealer(o.sealer); err != nil {
		return nil, err
	}
	door, err := doorOf(o)
	if err != nil {
		return nil, err
	}
	bins, err := provisionBinaries(o.binDir, "acp-compute")
	if err != nil {
		return nil, err
	}
	out, err := prepareOut(o, "pins")
	if err != nil {
		return nil, err
	}
	secrets := filepath.Join(out, "secrets")
	fmt.Fprintf(stdout, "provision join: %s (family %s, the authority %s at %s, sealer %s)\n", out, family, authorityFamily, m.Authority.VaultAddress, o.sealer)

	// 1. The bundle's files, into the deployment.
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		dst, err := pathInside(out, name)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(dst, files[name], 0o600); err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(stdout, "  from the bundle: %d files (%s)\n", len(names), strings.Join(names, ", "))
	res := &provisionResult{Schema: "vault-genome/acpctl-provision/v1", Role: "worker", Phase: "joined", Out: out, Provider: string(local), PeerProvider: string(authorityFamily), Sealer: o.sealer,
		Binaries: bins, Secrets: secrets, Configs: map[string]string{}, ConfigsSHA256: map[string]string{}, Pins: map[string]string{}, Sealed: map[string][]string{},
		VaultAddress: m.Authority.VaultAddress,
		Vault:        provisionedSide{Provider: m.Authority.Provider, MeasurementHex: m.Authority.MeasurementHex}}
	vaultPin := filepath.Join(out, "pins", "vault.measurement")
	res.Pins["vault"] = vaultPin
	if pin, err := os.ReadFile(vaultPin); err != nil || hex.EncodeToString(pin) != m.Authority.MeasurementHex || len(pin) != measurementLen(authorityFamily) {
		return nil, errors.New("--bundle: pins/vault.measurement is not the authority's measurement the manifest names")
	}

	// 2. What acp-compute's verifier needs of the authority's family.
	chain := ""
	if m.Authority.AMDCertChain != "" {
		chain = filepath.Join(out, filepath.FromSlash(m.Authority.AMDCertChain))
		res.AMDCertChain = chain
	}
	peerCfg, err := peerConfig(out, authorityFamily, chain, o.pcsCacheDir)
	if err != nil {
		return nil, fmt.Errorf("the authority is %s and the bundle carries no chain for it: %w", authorityFamily, err)
	}
	if bootPinned(authorityFamily) {
		if d, err := hex.DecodeString(m.Authority.PCRDigestHex); err != nil || len(d) != sha256.Size {
			return nil, fmt.Errorf("--bundle: the manifest names no boot for the %s authority (authority.pcr_digest_hex): the worker pins its boot as well as its measurement (ADR 0037); provision the authority again with this release", authorityFamily)
		}
		peerCfg["pcr_digests"] = []string{m.Authority.PCRDigestHex}
		res.Vault.VTPMPCRDigestHex = m.Authority.PCRDigestHex
	}
	if authorityFamily == tee.ProviderAWSSEVSNP && m.Authority.CSPID != "" {
		// The provider whose VLEK signs the authority's reports, pinned
		// from the authority's own identity (ADR 0038).
		peerCfg["csp_ids"] = []string{m.Authority.CSPID}
		res.Vault.VLEKCSPID = m.Authority.CSPID
	}

	// 3. acp-compute's configuration.
	sec := func(p ...string) string { return filepath.Join(append([]string{secrets}, p...)...) }
	descriptor := orDefault(o.workerDescriptor, m.Worker.Descriptor)
	workerPath := filepath.Join(out, "acp-compute.json")
	if err := writeConfigs(res, map[string]struct {
		path string
		cfg  map[string]any
	}{
		"acp-compute": {workerPath, workerConfig(o, secrets,
			teeSection(local, family, o.sealer, descriptor, peerCfg, vaultPin, sec("acp-compute", "tee_seed"), sec("acp-compute", "peer_vault_pubkey")),
			m.Authority.VaultAddress, m.Authority.VaultServerName, door, sec("acp-compute", "sealing.key"))},
	}); err != nil {
		return nil, err
	}
	fmt.Fprintf(stdout, "  configuration: %s\n", workerPath)
	printBootPCRs(stdout, family)

	// 4. The worker's identity, for the authority to pin.
	if err := identify(out, "acp-compute", bins["acp-compute"], workerPath, "", "acp-compute", family, local, &res.Worker, stdout); err != nil {
		return nil, err
	}

	// 5. The key files sealed to this host.
	if o.skipSeal {
		res.Next = append(res.Next, bins["acp-compute"]+" seal-keys -config "+workerPath)
	} else if err := sealKeys(res, "acp-compute", bins["acp-compute"], workerPath, stdout); err != nil {
		return nil, err
	}
	res.Next = append(res.Next,
		"delete "+o.bundle+": its files are in "+out+" now, sealed to this host",
		"carry "+res.Worker.IdentityFile+" to the authority's host and run: acpctl provision pin-worker --out <authority dir> --identity acp-compute-identity.json",
		bins["acp-compute"]+" -config "+workerPath+" (once the authority has pinned this worker and is running)")
	if err := writeResult(out, res, stdout); err != nil {
		return nil, err
	}
	fmt.Fprintf(stdout, "  identity for the authority: %s\n", res.Worker.IdentityFile)
	return res, nil
}

// provisionPinWorkerCmd is `acpctl provision pin-worker`.
func provisionPinWorkerCmd(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("provision pin-worker", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var o provisionOptions
	flags.StringVar(&o.out, "out", "", "the authority's deployment directory, as provision authority wrote it (required)")
	flags.StringVar(&o.identity, "identity", "", "the worker's acp-compute-identity.json, as provision join wrote it (required)")
	flags.BoolVar(&o.force, "force", false, "pin an identity of another family than the authority was provisioned for, or pin again")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl provision pin-worker --out DIR --identity acp-compute-identity.json")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Step 3 of 3 on the authority's host (ADR 0028): the worker's measurement pinned; the deployment is complete.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if o.out == "" || o.identity == "" {
		fmt.Fprintln(stderr, "acpctl provision pin-worker: --out and --identity are required")
		flags.Usage()
		return 2
	}
	result, err := provisionPinWorker(o, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "acpctl provision pin-worker:", err)
		return 1
	}
	printJSON(stdout, result)
	return 0
}

// provisionPinWorker is step 3 of 3: the worker's measurement, from the
// identity its host wrote, pinned on the authority.
func provisionPinWorker(o provisionOptions, stdout io.Writer) (*provisionResult, error) {
	out, err := filepath.Abs(o.out)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(out, "provision.json"))
	if err != nil {
		return nil, fmt.Errorf("--out: not a deployment provision authority wrote: %w", err)
	}
	var res provisionResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("--out: provision.json does not decode: %w", err)
	}
	if res.Role != "authority" {
		return nil, fmt.Errorf("--out: provision.json has role %q; pin-worker completes a deployment provision authority began", res.Role)
	}
	if res.Phase == "complete" && !o.force {
		return nil, errors.New("--out: the worker is pinned already (phase complete); pass --force to pin another")
	}
	idRaw, err := os.ReadFile(o.identity)
	if err != nil {
		return nil, fmt.Errorf("--identity: %w", err)
	}
	var id daemonIdentity
	if err := json.Unmarshal(idRaw, &id); err != nil {
		return nil, fmt.Errorf("--identity: not JSON: %w", err)
	}
	worker := tee.Provider(res.PeerProvider)
	m, err := hex.DecodeString(id.TEEMeasurementHex)
	if err != nil || len(m) != measurementLen(worker) {
		return nil, fmt.Errorf("--identity: tee_measurement_hex %q is not a %d-byte measurement of a %s worker", id.TEEMeasurementHex, measurementLen(worker), worker)
	}
	var warnings []string
	if id.TEEProvider != "" && tee.Provider(id.TEEProvider) != worker {
		msg := fmt.Sprintf("the identity attests as %s, but the authority was provisioned for a %s worker (--worker-provider): sagvd would refuse it at every handshake", id.TEEProvider, worker)
		if !o.force {
			return nil, errors.New(msg + "; provision the authority again for that family, or pass --force to pin it anyway")
		}
		warnings = append(warnings, msg)
	}
	if bootPinned(worker) {
		if id.VTPM == nil {
			return nil, fmt.Errorf("--identity: no vtpm.pcr_digest_hex: a %s worker is pinned to its boot as well as its measurement (ADR 0037)", worker)
		}
		if d, err := hex.DecodeString(id.VTPM.PCRDigestHex); err != nil || len(d) != sha256.Size {
			return nil, fmt.Errorf("--identity: vtpm.pcr_digest_hex %q is not a 32-byte digest", id.VTPM.PCRDigestHex)
		}
		// The digest is over the PCRs the worker quoted: the selection its
		// configuration names, or the pin is over PCRs the operator did not
		// choose (a worker that predates the field quotes its default).
		if want, got := bootPCRsFor(worker), strings.Join(id.VTPM.PCRs, "+"); want != "" && got != "" && got != want {
			return nil, fmt.Errorf("--identity: the worker's vTPM quoted %s, not the %s its configuration names (tee.vtpm_quote_pcrs): an acp-compute that predates the selection? the release's binaries go together", got, want)
		}
	}
	pinPath := res.Pins["worker"]
	if pinPath == "" {
		pinPath = filepath.Join(out, "pins", "worker.measurement")
	}
	if err := os.WriteFile(pinPath, m, 0o600); err != nil {
		return nil, err
	}
	if bootPinned(worker) {
		cfgPath := res.Configs["sagvd"]
		if cfgPath == "" {
			cfgPath = filepath.Join(out, "sagvd.json")
		}
		if res.ConfigsSHA256 == nil {
			res.ConfigsSHA256 = map[string]string{}
		}
		if err := pinBoot(&res, "sagvd", cfgPath, id.VTPM.PCRDigestHex, "the worker's", stdout); err != nil {
			return nil, err
		}
	}
	idFile := filepath.Join(out, "acp-compute-identity.json")
	if err := os.WriteFile(idFile, idRaw, 0o600); err != nil {
		return nil, err
	}
	res.Worker = provisionedSide{Provider: id.TEEProvider, MeasurementHex: id.TEEMeasurementHex, Sealer: id.Sealer, IdentityFile: idFile, Warnings: warnings}
	if id.VTPM != nil {
		res.Worker.VTPMPCRDigestHex = id.VTPM.PCRDigestHex
		res.Worker.VTPMPCRs = strings.Join(id.VTPM.PCRs, "+")
	}
	res.Pins["worker"] = pinPath
	res.Phase = "complete"
	res.Next = []string{
		res.Binaries["sagvd"] + " -config " + res.Configs["sagvd"] + " (start it again if it is running: pins are read at start)",
		"on the worker's host: acp-compute -config <dir>/acp-compute.json",
	}
	fmt.Fprintf(stdout, "provision pin-worker: %s pins the worker %s (%s)\n", out, id.TEEMeasurementHex, id.TEEProvider)
	if err := writeResult(out, &res, stdout); err != nil {
		return nil, err
	}
	return &res, nil
}

// ---------------------------------------------------------------------

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
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
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
