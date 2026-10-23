// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command acp-keygen provisions the key material a sagvd + acp-compute
// deployment starts from: the simulated-TEE seeds, the signing seeds, the
// pre-shared session sealing key, a private mTLS PKI for the Return Path,
// the operator REST API bearer token and the worker registry. It ships as
// a release binary next to the daemons, signed and attested like them, so
// a first deployment needs nothing from the source tree (docs/operator/
// 09_first_deployment.md).
//
// # What it writes (under -out)
//
//	shared/
//	  sealing.key               32 B AES-256 session sealing key (pre-shared)
//	  workers.json              worker signing registry consumed by sagvd
//	  tls/ca.crt                private CA certificate, trusted by both sides
//	sagvd/
//	  tee_seed                  32 B Ed25519 seed (vault simulated TEE)
//	  authority_signing_seed    authority signing key file (see -signature-suite)
//	  audit_signing_seed        audit signing key file (see -signature-suite)
//	  peer_worker_pubkey        32 B Ed25519 public key (pinned worker TEE)
//	  peer_worker_measurement   32 B SHA-256 (pinned worker workload)
//	  api_token                 REST API bearer token (64 hex chars, 128+ bits)
//	  tls/server.crt|.key       Return Path server certificate (ECDSA P-256)
//	acp-compute/
//	  tee_seed                  32 B Ed25519 seed (worker simulated TEE)
//	  worker_signing_seed       worker signing key file (see -signature-suite)
//	  peer_vault_pubkey         32 B Ed25519 public key (pinned vault TEE)
//	  peer_vault_measurement    32 B SHA-256 (pinned vault workload)
//	  tls/client.crt|.key       Return Path client certificate (ECDSA P-256)
//
// The CA private key signs the two leaf certificates in memory and is
// never written to disk: rotating the PKI means re-running acp-keygen
// with -force. The server certificate names the Compose service ("sagvd",
// which acp-compute verifies as tls.server_name) and the loopback
// addresses, so the same tree serves a containerised run and a
// single-host run (the hardware kits, the integration tests).
//
// The two workload-descriptor strings MUST match tee.workload_descriptor
// in sagvd's and acp-compute's configs when the simulated TEE is used:
// peer measurements are SHA-256 of those strings (the derivation
// tee.MeasurementOf uses), so a mismatch fails every handshake
// Authority-classified. On a hardware TEE the daemons' `identity`
// commands print the measurements the chips report, and those replace
// the two peer_*_measurement files before the first start, as the kits do.
//
// # The signature suite
//
// The three signing keys — the authority's, the audit log's, the
// worker's — are made under one signature suite (ADR 0031), ed25519 by
// default: -signature-suite ecdsa-p384-sha384 or ml-dsa-87 makes them
// under that suite instead, and the daemons' configs then name it
// (keys.<name>.suite) so the file is read as the suite says. A key file
// is the suite's file form: the 32-byte seed of an ed25519 or ml-dsa-87
// key, the PKCS#8 PEM of an ecdsa-p384-sha384 key; the file names stay
// the same. The worker registry names the suite beside the worker's raw
// public key. The two TEE seeds are the simulated TEE's Ed25519
// evidence keys and are not on the suite.
//
// # Usage
//
//	acp-keygen -out /etc/acp/secrets [-signature-suite SUITE] [-private] [-force] [-quiet]
//
// acp-keygen refuses to overwrite an existing tree unless -force is
// passed: regenerating secrets under a running pair desynchronises it
// (sealed material stops opening, TEE evidence stops pinning, TLS stops
// verifying).
//
// # File modes
//
// By default files are written 0644 and directories 0755: the Compose
// deployment runs the daemons in distroless containers as uid 65532 and
// reads this tree through a read-only bind mount that preserves host
// ownership, so a 0600 file owned by the operator would be unreadable to
// the container user. With -private, files are 0600 and directories 0700
// — for a host where the daemons run as the user that provisioned them,
// as on the hardware kits' guests, where the daemons then seal every key
// file in place to the TEE (`sagvd seal-keys`, `acp-compute seal-keys`,
// ADR 0023) and the plaintext is gone before the first handshake.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/buildinfo"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
)

var (
	version = "0.0.0-dev"
	commit  = "none"
)

// Canonical workload descriptors and key IDs. See the package comment
// for the files these must stay in lock-step with.
const (
	vaultWorkloadDescriptor  = "sagvd-phase1-demo-v1"
	workerWorkloadDescriptor = "acp-compute-phase1-demo-v1"

	// session_sealing.kid MUST be identical across both daemons (sagvd
	// writes it into JobRequest.SealedMaterialRef.RecipientKeyID;
	// acp-compute's Opener resolves the same kid from its keystore).
	kidAuthoritySigning = "sagvd-authority-demo"
	kidSessionSealing   = "session-sealing-demo"
	kidWorkerSigning    = "acp-compute-worker-demo"

	// TLS identities: vaultTLSName is what acp-compute dials and
	// verifies (tls.server_name); workerTLSName is the client identity.
	vaultTLSName  = "sagvd"
	workerTLSName = "acp-compute"

	leafValidity = 365 * 24 * time.Hour
	caValidity   = leafValidity + 24*time.Hour
	clockSkew    = 5 * time.Minute
)

type layout struct {
	root string

	sharedDir, sagvdDir, workerDir          string
	sharedTLSDir, sagvdTLSDir, workerTLSDir string

	sealingKey  string // shared/sealing.key
	workersJSON string // shared/workers.json
	caCert      string // shared/tls/ca.crt

	sagvdTEESeed              string
	sagvdAuthoritySigningSeed string
	sagvdAuditSigningSeed     string
	sagvdPeerWorkerPubkey     string
	sagvdPeerWorkerMeasure    string
	sagvdAPIToken             string
	sagvdTLSCert              string
	sagvdTLSKey               string

	workerTEESeed         string
	workerSigningSeed     string
	workerPeerVaultPubkey string
	workerPeerVaultMeas   string
	workerTLSCert         string
	workerTLSKey          string
}

func newLayout(root string) layout {
	l := layout{
		root:      root,
		sharedDir: filepath.Join(root, "shared"),
		sagvdDir:  filepath.Join(root, "sagvd"),
		workerDir: filepath.Join(root, "acp-compute"),
	}
	l.sharedTLSDir = filepath.Join(l.sharedDir, "tls")
	l.sagvdTLSDir = filepath.Join(l.sagvdDir, "tls")
	l.workerTLSDir = filepath.Join(l.workerDir, "tls")

	l.sealingKey = filepath.Join(l.sharedDir, "sealing.key")
	l.workersJSON = filepath.Join(l.sharedDir, "workers.json")
	l.caCert = filepath.Join(l.sharedTLSDir, "ca.crt")

	l.sagvdTEESeed = filepath.Join(l.sagvdDir, "tee_seed")
	l.sagvdAuthoritySigningSeed = filepath.Join(l.sagvdDir, "authority_signing_seed")
	l.sagvdAuditSigningSeed = filepath.Join(l.sagvdDir, "audit_signing_seed")
	l.sagvdPeerWorkerPubkey = filepath.Join(l.sagvdDir, "peer_worker_pubkey")
	l.sagvdPeerWorkerMeasure = filepath.Join(l.sagvdDir, "peer_worker_measurement")
	l.sagvdAPIToken = filepath.Join(l.sagvdDir, "api_token")
	l.sagvdTLSCert = filepath.Join(l.sagvdTLSDir, "server.crt")
	l.sagvdTLSKey = filepath.Join(l.sagvdTLSDir, "server.key")

	l.workerTEESeed = filepath.Join(l.workerDir, "tee_seed")
	l.workerSigningSeed = filepath.Join(l.workerDir, "worker_signing_seed")
	l.workerPeerVaultPubkey = filepath.Join(l.workerDir, "peer_vault_pubkey")
	l.workerPeerVaultMeas = filepath.Join(l.workerDir, "peer_vault_measurement")
	l.workerTLSCert = filepath.Join(l.workerTLSDir, "client.crt")
	l.workerTLSKey = filepath.Join(l.workerTLSDir, "client.key")
	return l
}

func (l layout) dirs() []string {
	return []string{
		l.sharedDir, l.sagvdDir, l.workerDir,
		l.sharedTLSDir, l.sagvdTLSDir, l.workerTLSDir,
	}
}

func (l layout) files() []string {
	return []string{
		l.sealingKey, l.workersJSON, l.caCert,
		l.sagvdTEESeed, l.sagvdAuthoritySigningSeed, l.sagvdAuditSigningSeed,
		l.sagvdPeerWorkerPubkey, l.sagvdPeerWorkerMeasure,
		l.sagvdAPIToken, l.sagvdTLSCert, l.sagvdTLSKey,
		l.workerTEESeed, l.workerSigningSeed,
		l.workerPeerVaultPubkey, l.workerPeerVaultMeas,
		l.workerTLSCert, l.workerTLSKey,
	}
}

// workersRegistry mirrors cmd/sagvd/workers.go:WorkerRegistryFile — a
// divergence here silently breaks sagvd startup.
type workersRegistry struct {
	Workers []workerEntry `json:"workers"`
}

type workerEntry struct {
	KeyID               string `json:"kid"`
	SigningPublicKeyHex string `json:"signing_pubkey_hex"`
	// Suite is the signature suite of the worker's key (ADR 0031):
	// absent for ed25519, the suite id otherwise.
	Suite string `json:"suite,omitempty"`
	Note  string `json:"note,omitempty"`
}

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

// realMain parses the flags and runs; it is main without the process.
func realMain(args []string, stdout, stderr io.Writer) int {
	version, commit = buildinfo.Resolve(version, commit)
	fs := flag.NewFlagSet("acp-keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		outDir      = fs.String("out", "", "output directory for the secrets tree (required)")
		force       = fs.Bool("force", false, "overwrite any existing files under -out")
		quiet       = fs.Bool("quiet", false, "suppress non-error stdout")
		private     = fs.Bool("private", false, "write files 0600 and directories 0700 instead of 0644/0755")
		suiteName   = fs.String("signature-suite", string(crypto.SuiteEd25519), "signature suite of the three signing keys (ADR 0031): ed25519, ecdsa-p384-sha384 or ml-dsa-87; the daemons' configs name it as keys.<name>.suite")
		showVersion = fs.Bool("version", false, "print the build version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "acp-keygen %s (commit %s)\n", version, commit)
		return 0
	}
	if *outDir == "" {
		fmt.Fprintln(stderr, "acp-keygen: -out is required (the directory to write the secrets tree to)")
		fs.Usage()
		return 2
	}
	suite, err := crypto.SuiteOrDefault(*suiteName)
	if err == nil {
		err = suite.Available()
	}
	if err != nil {
		fmt.Fprintln(stderr, "acp-keygen: -signature-suite:", err)
		return 2
	}
	if err := run(*outDir, *force, *quiet, *private, suite, stdout); err != nil {
		fmt.Fprintln(stderr, "acp-keygen:", err)
		return 1
	}
	return 0
}

func run(outDir string, force, quiet, private bool, suite crypto.SignatureSuite, stdout io.Writer) error {
	lo := newLayout(outDir)
	if err := preflight(lo, force); err != nil {
		return err
	}
	dirMode, fileMode := fs.FileMode(0o755), fs.FileMode(0o644)
	if private {
		dirMode, fileMode = 0o700, 0o600
	}
	for _, d := range lo.dirs() {
		if err := os.MkdirAll(d, dirMode); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
		// MkdirAll leaves a pre-existing directory's mode alone; force
		// it so a -force re-run cannot produce a mixed-permission tree.
		if err := os.Chmod(d, dirMode); err != nil {
			return fmt.Errorf("chmod %s: %w", d, err)
		}
	}

	// The TEE seeds: the simulated TEE's Ed25519 evidence keys.
	seeds := make(map[string][]byte, 2)
	for _, name := range []string{"sagvdTEE", "workerTEE"} {
		b, err := randomBytes(ed25519.SeedSize)
		if err != nil {
			return err
		}
		seeds[name] = b
	}
	// The signing keys, under the suite (ADR 0031), in the suite's file form.
	signing := make(map[string]*crypto.SigningKey, 3)
	keyFiles := make(map[string][]byte, 3)
	for _, name := range []string{"sagvdAuthority", "sagvdAudit", "workerSigning"} {
		k, err := crypto.GenerateSigningKey(suite, nil)
		if err != nil {
			return fmt.Errorf("generate %s signing key (%s): %w", name, suite, err)
		}
		file, err := k.KeyFileBytes()
		if err != nil {
			return err
		}
		signing[name], keyFiles[name] = k, file
	}
	sealingKey, err := randomBytes(32)
	if err != nil {
		return err
	}
	tokenBytes, err := randomBytes(32)
	if err != nil {
		return err
	}
	apiToken := hex.EncodeToString(tokenBytes)

	// Each side pins the OTHER side's TEE public key: the Return Path
	// verifier rejects evidence signed by anything but the expected seed.
	sagvdTEEPub := ed25519.NewKeyFromSeed(seeds["sagvdTEE"]).Public().(ed25519.PublicKey)
	workerTEEPub := ed25519.NewKeyFromSeed(seeds["workerTEE"]).Public().(ed25519.PublicKey)
	workerSigningPub := signing["workerSigning"].PublicKeyBytes()

	sagvdMeasurement := sha256.Sum256([]byte(vaultWorkloadDescriptor))
	workerMeasurement := sha256.Sum256([]byte(workerWorkloadDescriptor))

	pki, err := newPKI(time.Now())
	if err != nil {
		return err
	}

	reg := workersRegistry{Workers: []workerEntry{{
		KeyID:               kidWorkerSigning,
		SigningPublicKeyHex: hex.EncodeToString(workerSigningPub),
		Suite:               string(crypto.RecordAlg(suite)),
		Note:                "Provisioned by acp-keygen; regenerate with acp-keygen -force.",
	}}}
	regBytes, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal workers.json: %w", err)
	}

	writes := []struct {
		path string
		data []byte
	}{
		{lo.sealingKey, sealingKey},
		{lo.workersJSON, append(regBytes, '\n')},
		{lo.caCert, pki.caPEM},

		{lo.sagvdTEESeed, seeds["sagvdTEE"]},
		{lo.sagvdAuthoritySigningSeed, keyFiles["sagvdAuthority"]},
		{lo.sagvdAuditSigningSeed, keyFiles["sagvdAudit"]},
		{lo.sagvdPeerWorkerPubkey, workerTEEPub},
		{lo.sagvdPeerWorkerMeasure, workerMeasurement[:]},
		{lo.sagvdAPIToken, []byte(apiToken + "\n")},
		{lo.sagvdTLSCert, pki.serverCertPEM},
		{lo.sagvdTLSKey, pki.serverKeyPEM},

		{lo.workerTEESeed, seeds["workerTEE"]},
		{lo.workerSigningSeed, keyFiles["workerSigning"]},
		{lo.workerPeerVaultPubkey, sagvdTEEPub},
		{lo.workerPeerVaultMeas, sagvdMeasurement[:]},
		{lo.workerTLSCert, pki.clientCertPEM},
		{lo.workerTLSKey, pki.clientKeyPEM},
	}
	for _, w := range writes {
		if err := writeBytes(w.path, w.data, fileMode); err != nil {
			return err
		}
	}

	if !quiet {
		// Identity lines operators can eyeball against the daemons'
		// startup logs. The bearer token itself is never printed.
		fmt.Fprintf(stdout, "acp-keygen: wrote secrets under %q (files %04o, directories %04o)\n", outDir, fileMode, dirMode)
		fmt.Fprintf(stdout, "  signature suite:             %s (keys.<name>.suite in the daemons' configs)\n", suite)
		fmt.Fprintf(stdout, "  authority signing kid:       %s\n", kidAuthoritySigning)
		fmt.Fprintf(stdout, "  session sealing kid:         %s\n", kidSessionSealing)
		fmt.Fprintf(stdout, "  worker signing kid:          %s\n", kidWorkerSigning)
		fmt.Fprintf(stdout, "  sagvd TEE pubkey:            %s\n", hex.EncodeToString(sagvdTEEPub))
		fmt.Fprintf(stdout, "  worker TEE pubkey:           %s\n", hex.EncodeToString(workerTEEPub))
		fmt.Fprintf(stdout, "  worker signing pubkey:       %s\n", hex.EncodeToString(workerSigningPub))
		fmt.Fprintf(stdout, "  sagvd expected measurement:  %s\n", hex.EncodeToString(sagvdMeasurement[:]))
		fmt.Fprintf(stdout, "  worker expected measurement: %s\n", hex.EncodeToString(workerMeasurement[:]))
		fmt.Fprintf(stdout, "  mTLS: CA + server (%s, localhost, 127.0.0.1, ::1) + client (%s), valid %s\n",
			vaultTLSName, workerTLSName, leafValidity)
		fmt.Fprintf(stdout, "  REST API bearer token:       %s (not printed)\n", lo.sagvdAPIToken)
	}
	return nil
}

// pkiMaterial is the PEM-encoded output of newPKI.
type pkiMaterial struct {
	caPEM                       []byte
	serverCertPEM, serverKeyPEM []byte
	clientCertPEM, clientKeyPEM []byte
}

// newPKI creates a private CA and issues the Return Path server and
// client certificates. The CA key exists only in memory.
func newPKI(now time.Time) (pkiMaterial, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return pkiMaterial{}, fmt.Errorf("generate CA key: %w", err)
	}
	caSerial, err := randomSerial()
	if err != nil {
		return pkiMaterial{}, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "acp-local-deployment-ca", Organization: []string{"AI Continuity Platform"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return pkiMaterial{}, fmt.Errorf("create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return pkiMaterial{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	serverCert, serverKey, err := issueLeaf(caCert, caKey, now, &x509.Certificate{
		Subject:     pkix.Name{CommonName: vaultTLSName},
		DNSNames:    []string{vaultTLSName, "localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return pkiMaterial{}, fmt.Errorf("issue server certificate: %w", err)
	}
	clientCert, clientKey, err := issueLeaf(caCert, caKey, now, &x509.Certificate{
		Subject:     pkix.Name{CommonName: workerTLSName},
		DNSNames:    []string{workerTLSName},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return pkiMaterial{}, fmt.Errorf("issue client certificate: %w", err)
	}
	return pkiMaterial{
		caPEM:         pemBlock("CERTIFICATE", caDER),
		serverCertPEM: serverCert,
		serverKeyPEM:  serverKey,
		clientCertPEM: clientCert,
		clientKeyPEM:  clientKey,
	}, nil
}

// issueLeaf signs tmpl with the CA and returns PEM certificate + PKCS#8
// private key.
func issueLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, now time.Time, tmpl *x509.Certificate) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = now.Add(-clockSkew)
	tmpl.NotAfter = now.Add(leafValidity)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER), nil
}

// preflight enforces the -force requirement without touching the tree.
func preflight(lo layout, force bool) error {
	if _, err := os.Stat(lo.root); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", lo.root, err)
	}
	var found int
	for _, p := range lo.files() {
		if _, err := os.Stat(p); err == nil {
			found++
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", p, err)
		}
	}
	if found > 0 && !force {
		return fmt.Errorf(
			"refusing to overwrite existing secrets (%d files under %q); "+
				"re-run with -force to regenerate (this WILL desynchronise any running daemons)",
			found, lo.root)
	}
	return nil
}

// randomBytes returns n bytes from crypto/rand; failure is fatal rather
// than a fallback to weaker randomness.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}
	return b, nil
}

func randomSerial() (*big.Int, error) {
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("certificate serial: %w", err)
	}
	return s, nil
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// writeBytes writes data with the given mode, truncating any existing
// file, and re-applies the mode so a -force re-run cannot leave a stale
// one.
func writeBytes(path string, data []byte, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return f.Close()
}
