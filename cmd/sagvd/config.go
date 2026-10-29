// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/exposure"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Config is the full on-disk configuration for the sagvd authority
// daemon. Every field is frozen for the Phase-1 investor demo;
// additions are a minor-version change and must update
// `cmd/sagvd/doc.go`.
type Config struct {
	// Vault controls the Return Path TCP listener (where acp-compute
	// workers dial in).
	Vault VaultConfig `json:"vault"`

	// HTTPAPI controls the operator REST API listener (POST /v1/jobs,
	// GET /v1/jobs/{id}).
	HTTPAPI HTTPAPIConfig `json:"http_api"`

	// TEE configures the simulated TEE the vault presents during the
	// Return Path handshake. In Phase 3 this section is replaced by a
	// hardware-backed backend with identical surface.
	TEE TEEConfig `json:"tee"`

	// Keys points at the on-disk material the vault uses to sign
	// authority artifacts and to seal SealedMaterial for JobRequest.
	Keys KeysConfig `json:"keys"`

	// Workers points at the static JSON registry of known worker
	// signing public keys. See workers.go.
	Workers WorkersConfig `json:"workers"`

	// Runtime tunables for the accept / dispatch loop and HTTP timeouts.
	Runtime RuntimeConfig `json:"runtime"`

	// Health controls the local HTTP server that exposes /healthz,
	// /readyz and /metrics. Empty ListenAddress disables the server
	// (useful in tests).
	Health HealthConfig `json:"health"`

	// Log controls structured-logging format and verbosity.
	Log LogConfig `json:"log"`

	// CrossCloud configures cross-cloud key release, run by the
	// `sagvd crosscloud-restore` subcommand (the daemon itself serves
	// no cross-cloud requests). When CrossCloud.Enabled is false (the
	// default) every other field in this section is ignored.
	//
	// See ADR 0006, ADR 0009 and docs/operator/06_cross_cloud_restore.md.
	CrossCloud CrossCloudConfig `json:"crosscloud,omitempty"`

	// Genome configures the gate jobs the REST API accepts: a job names
	// a sealed genome in Genome.BundleDir; sagvd opens it with its key,
	// keeps the genome's reference fixtures, ships the model side to the
	// worker, and holds what the worker computes to the references with
	// the equivalence gate. Without a BundleDir the REST API accepts no
	// jobs (ADR 0013).
	Genome GenomeConfig `json:"genome,omitempty"`

	// Audit is the daemon's Return Path audit log: every decision about
	// a job — accepted, worker admitted or refused, candidate received,
	// judged — on a durable, signed, hash-linked record before it takes
	// effect (ADR 0014). Required when gate jobs are enabled.
	Audit AuditConfig `json:"audit,omitempty"`

	// Queue is where the daemon keeps its accepted jobs on disk, so that
	// a restart resumes what was queued or in flight (ADR 0026). Without
	// a path the queue is in memory and a restart loses it; the daemon
	// says so at start when gate jobs are enabled.
	Queue QueueConfig `json:"queue,omitempty"`

	// Crypto is the cryptographic profile (ADR 0029): the KEM suite the
	// authority encapsulates keys under across clouds and the suites it
	// accepts a destination's answer under. Omitted, the general profile.
	Crypto CryptoConfig `json:"crypto,omitempty"`

	// OperatorStop is the operator's signed stop list (ADR 0010) as Trust
	// Admission consults it for gate jobs (ADR 0015): a stop-all list
	// denies every job, a list revoking the worker's measurement denies
	// that worker, and every denial is a signed, recorded decision. The
	// list is re-read at every admission, so the operator stops the
	// daemon's releases by writing a new list. Optional; when set, all
	// three fields are required.
	OperatorStop OperatorStopConfig `json:"operator_stop,omitempty"`
}

// CryptoConfig is the deployment's cryptographic profile (ADR 0029): the
// KEM suite this daemon encapsulates under and the suites it accepts.
type CryptoConfig struct {
	// Profile is "general" (the default: X25519 written, every suite of
	// the build accepted), "fips" (P-384 written; P-384, ML-KEM-768 and
	// the MLKEM1024-P384 hybrid accepted — the primitives the Go
	// Cryptographic Module lists as approved) or "cnsa" (the
	// MLKEM1024-P384 hybrid only).
	Profile string `json:"profile,omitempty"`

	// KEMSuites narrows the profile's list to these suites, in this
	// order of preference (the first is written). Every name must be
	// one the profile accepts; a profile is never widened here.
	KEMSuites []string `json:"kem_suites,omitempty"`

	// SignatureSuite picks the signature suite this daemon signs with
	// from the profile's list (ADR 0031): general and fips sign with
	// ed25519 and cnsa with ecdsa-p384-sha384 unless this names another
	// suite the profile accepts — fips with ecdsa-p384-sha384 is the
	// deployment a bank held to X9 runs. Every signing key the config
	// names (keys.<name>.suite) must be of this suite; a profile is never
	// widened here.
	SignatureSuite string `json:"signature_suite,omitempty"`
}

// Policy returns the configuration as the policy the kms package applies.
func (c CryptoConfig) Policy() (kms.SuitePolicy, error) {
	return kms.NewSuitePolicyFromNames(c.Profile, c.KEMSuites)
}

// SignaturePolicy returns the profile's signature policy: the suite the
// daemon signs with and the suites it accepts (ADR 0031).
func (c CryptoConfig) SignaturePolicy() (kms.SignaturePolicy, error) {
	return kms.NewSignaturePolicyFromNames(c.Profile, c.SignatureSuite)
}

// PolicyProfileGate is the one policy profile the daemon serves: restore
// the named genome in an attested worker and hold it to its sealed
// references under genome.gate. A RecoveryRequest naming another profile
// is denied at Trust Admission.
const PolicyProfileGate = "gate"

// PolicyVersion is the policy every session is pinned to and validation
// checks alignment with (op.policy_alignment): the gate's tolerance, in
// full, so a tolerance changed under a live session is a recorded
// operational failure rather than a silent drift.
func (c Config) PolicyVersion() string {
	g := c.Genome.Gate
	v := fmt.Sprintf("gate-policy/v1;atol=%g;rtol=%g;outliers=%d", g.Atol, g.Rtol, g.MaxNonCriticalOutliers)
	if g.Bfloat16 != nil {
		v += fmt.Sprintf(";bf16-atol=%g;bf16-rtol=%g", g.Bfloat16.Atol, g.Bfloat16.Rtol)
	}
	return v
}

// GateTolerance is a tolerance of the float door: |got - expected| <= atol + rtol*|expected|.
type GateTolerance struct {
	Atol float64 `json:"atol"`
	Rtol float64 `json:"rtol"`
}

// ToleranceFor is the tolerance a genome is held to, by the dtype its
// recipe names: the bfloat16 table when the operator set one and the
// genome computed in bfloat16, the float32 tolerance otherwise.
func (g GateConfig) ToleranceFor(dtype string) equivalence.Tolerance {
	if g.Bfloat16 != nil && dtype == "bfloat16" {
		return equivalence.Tolerance{Atol: g.Bfloat16.Atol, Rtol: g.Bfloat16.Rtol}
	}
	return equivalence.Tolerance{Atol: g.Atol, Rtol: g.Rtol}
}

// OperatorStopEnabled reports whether trust consults a stop list.
func (c Config) OperatorStopEnabled() bool {
	return c.OperatorStop.KeyID != "" || c.OperatorStop.PublicKeyPath != "" || c.OperatorStop.ListPath != ""
}

// GenomeConfig is where the sealed genomes a job may name live, how
// their keys are found, and the tolerance the gate holds a restored model
// to.
type GenomeConfig struct {
	// BundleDir holds the .genome bundles a job may name, with their key
	// files (acpctl genome seal --key-out) or escrow envelopes (--escrow-to,
	// as <bundle>.escrow) beside them. A job names files in it; paths are
	// refused.
	BundleDir string `json:"bundle_dir,omitempty"`

	// KeyEscrowPath is the authority's escrow private key that opens the
	// escrow envelopes in BundleDir: the file `sagvd escrow-provision`
	// writes, sealed to this host's TEE (ADR 0016). Under
	// tee.insecure_simulation a raw 32-byte key (acpctl escrow keygen,
	// mode 0600) is accepted too. Empty falls back to
	// crosscloud.key_escrow_path; without either, jobs must name a key
	// file.
	KeyEscrowPath string `json:"key_escrow_path,omitempty"`

	// Gate is the tolerance every gate job is held to. The byte-exact door
	// is always tried first; this is the tolerance of the native-float
	// door behind it. Declared here, by the operator, in advance — not by
	// the job.
	Gate GateConfig `json:"gate"`
}

// GateConfig is the native-float door's tolerance and outlier policy.
type GateConfig struct {
	Atol                   float64 `json:"atol"`
	Rtol                   float64 `json:"rtol"`
	MaxNonCriticalOutliers int     `json:"max_non_critical_outliers"`
	// Bfloat16, when set, is the tolerance for a genome whose recipe says
	// its base computed in bfloat16: across devices such logits differ by
	// one or two bfloat16 quanta (KNOWN_ISSUES #13), and the float32
	// tolerance above refuses them. The operator sets it knowingly; it is
	// part of the policy every session is pinned to. Absent: bfloat16
	// genomes are held to the float32 tolerance.
	Bfloat16 *GateTolerance `json:"bfloat16,omitempty"`
}

// Enabled reports whether gate jobs can be built.
func (g GenomeConfig) Enabled() bool { return g.BundleDir != "" }

// EscrowKeyPath is the escrow private key that opens envelopes in
// BundleDir: genome.key_escrow_path, or crosscloud.key_escrow_path.
func (c Config) EscrowKeyPath() string {
	if c.Genome.KeyEscrowPath != "" {
		return c.Genome.KeyEscrowPath
	}
	return c.CrossCloud.KeyEscrowPath
}

// VaultConfig aggregates how sagvd accepts Return Path connections.
type VaultConfig struct {
	// ListenAddress is the host:port the vault binds for Return Path
	// inbound sessions. Workers dial this address.
	ListenAddress string `json:"listen_address"`

	// TLS configures mutual TLS for the Return Path listener. When
	// Enabled=false the listener is plain TCP. Validate() refuses a
	// plain-TCP listener on any non-loopback address: workers across a
	// network must authenticate with mTLS.
	TLS TLSConfig `json:"tls"`
}

// HTTPAPIConfig controls the operator REST API.
type HTTPAPIConfig struct {
	// ListenAddress is the host:port the REST API binds. An empty
	// value disables the REST API (tests and loopback-only demos
	// can dispatch jobs in-process through the JobQueue).
	ListenAddress string `json:"listen_address"`

	// BearerToken, if non-empty, is compared (constant-time) against
	// the client-supplied "Authorization: Bearer <token>" header on
	// every endpoint. An unauthenticated REST API is only accepted on a
	// loopback bind; Validate() refuses a non-loopback bind without a
	// token, and requires at least MinNonLoopbackTokenLen characters.
	BearerToken string `json:"bearer_token,omitempty"`

	// BearerTokenFile is the path to a file holding the bearer token
	// (surrounding whitespace is trimmed). Prefer it over BearerToken
	// so the secret lives with the other key material rather than in
	// the config file. Mutually exclusive with BearerToken; resolved at
	// startup by ResolveSecrets().
	BearerTokenFile string `json:"bearer_token_file,omitempty"`
}

// MinNonLoopbackTokenLen is the minimum bearer-token length accepted
// for a REST API reachable beyond the local host.
const MinNonLoopbackTokenLen = exposure.MinBearerTokenLen

// TLSConfig holds server-side mTLS material. All file paths are
// resolved relative to the process working directory.
type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
	ClientCAs  string `json:"client_cas"`
}

// TEEConfig names the TEE this vault attests with on the Return Path
// and pins the worker's TEE it will accept.
type TEEConfig struct {
	// Provider is the local TEE backend: "auto" (the family this host
	// attests with, resolved when the file is loaded, ADR 0025: what the
	// kernel's configfs-tsm serves — sev_guest or tdx_guest — or, under
	// Azure's paravisor, the vTPM's HCL report: azure-sev-snp), "gcp-sev-snp" (AMD SEV-SNP
	// reports through configfs-tsm, on any SEV-SNP guest with Linux 6.7
	// or later — the chip signs), "gcp-tdx", "azure-cgpu", "azure-sev-snp", or "simulated"
	// (a key read from SeedPath signs; no hardware isolation; development
	// and tests only). The family names "sev-snp" and "tdx" are accepted
	// for the first two. Default "simulated". The cross-cloud release path
	// (sagvd crosscloud-*) does not depend on it.
	Provider string `json:"provider,omitempty"`

	// WorkloadDescriptor names this workload. The simulated provider
	// hashes it into its measurement; a hardware provider records it
	// and attests with the launch measurement the chip reports.
	WorkloadDescriptor string `json:"workload_descriptor"`

	// SeedPath is a 32-byte file holding the Ed25519 seed the simulated
	// provider signs Evidence with. Sensitive — chmod 0600. Simulated
	// only.
	SeedPath string `json:"seed_path,omitempty"`

	// TSMReportDir overrides the configfs-tsm report directory (default
	// /sys/kernel/config/tsm/report). gcp-sev-snp only.
	TSMReportDir string `json:"tsm_report_dir,omitempty"`

	// SEVGuestDevice is the sev-guest character device the sealer asks
	// for this guest's derived key (default /dev/sev-guest): what seals
	// the escrow key to this host (ADR 0016). gcp-sev-snp only.
	SEVGuestDevice string `json:"sev_guest_device,omitempty"`

	// GPUAttestCommand, TPM2ToolsDir and AKHandle configure the
	// azure-cgpu producer (TPM2ToolsDir and AKHandle the azure-sev-snp one too): the command that obtains NVIDIA's signed
	// attestation tokens for a nonce (the nonce is appended; required),
	// where tpm2-tools live (default PATH), and the vTPM handle of the
	// HCL attestation key (default: found by its public key). azure-cgpu
	// only.
	GPUAttestCommand []string `json:"gpu_attest_command,omitempty"`
	TPM2ToolsDir     string   `json:"tpm2_tools_dir,omitempty"`
	AKHandle         string   `json:"ak_handle,omitempty"`

	// VTPMSealPCRs is the PCR selection the escrow key is sealed to on a
	// host whose TEE gives no sealing key of its own — gcp-tdx and
	// azure-cgpu seal to the guest's vTPM (ADR 0022). "sha256:<n>,<n>,...";
	// empty means every PCR the azure-cgpu quote covers (sha256:0-14).
	VTPMSealPCRs string `json:"vtpm_seal_pcrs,omitempty"`

	// VTPMQuotePCRs is the PCR selection the vTPM quotes where the quote
	// carries the boot (ADR 0037): gcp-sev-snp-vtpm (empty means sha256:0-9,
	// the firmware's and GRUB's — the kernel, its command line and initrd
	// among them), azure-sev-snp and azure-cgpu (empty means sha256:0-14;
	// `acpctl provision` writes sha256:0-9,11-14, the boot without IMA's
	// PCR 10, so the pinned boot holds across a restart).
	VTPMQuotePCRs string `json:"vtpm_quote_pcrs,omitempty"`

	// AKIntermediatesPath is a PEM file of the certificates between the
	// vTPM's attestation-key certificate and Google's EK/AK root; empty
	// means the one the certificate's issuer URL serves. gcp-sev-snp-vtpm only.
	AKIntermediatesPath string `json:"ak_intermediates_path,omitempty"`

	// Peer holds the trust-anchor material for the worker's TEE side.
	// The vault accepts exactly one worker TEE identity: a Return Path
	// session opens only for a worker whose Evidence verifies under it.
	Peer PeerTEEConfig `json:"peer"`

	// InsecureSimulation must be true to run the simulated provider:
	// its Evidence is signed by a key read from SeedPath, with no
	// hardware isolation. The flag puts that in the config itself.
	// Simulated only.
	InsecureSimulation bool `json:"insecure_simulation,omitempty"`

	// Sealer is how the daemon seals its key files to this host (ADR 0025,
	// step 1b): "auto" (the TEE's own key where it has one — SEV-SNP's
	// derived key — else the host's TPM 2.0, else the simulated key),
	// "tee" (the TEE's own key only; refused on TDX and Azure, which have
	// none), "tpm2" (the host's TPM 2.0 through tpm2-tools, whatever
	// the TEE), or "both" (SEV-SNP's derived key nested inside the TPM's
	// sealed object, ADR 0037: this chip and the boot the PCR policy names).
	// Every sealed file names the sealer it was made with.
	Sealer string `json:"sealer,omitempty"`

	// AutoResolvedFrom is set by ResolveAuto when Provider was "auto": the
	// configfs-tsm provider name the family was taken from (ADR 0025).
	// Not read from the file.
	AutoResolvedFrom string `json:"-"`
}

// SealerMode is tee.sealer with the default applied.
func (t TEEConfig) SealerMode() tee.SealerMode {
	m, err := tee.ParseSealerMode(t.Sealer)
	if err != nil {
		return tee.SealerModeAuto
	}
	return m
}

// ResolveAuto replaces tee.provider "auto" with the family this host
// attests with (ADR 0025) — what the kernel's configfs-tsm serves, or,
// under Azure's paravisor, what the vTPM's HCL report names — keeping
// where the answer came from in AutoResolvedFrom; any other provider is
// left as it is. It runs when
// the file is loaded, before validation, so that the family's own rules
// apply to the rest of the section.
func (t *TEEConfig) ResolveAuto() error {
	p, err := tee.ParseProvider(t.Provider)
	if err != nil || p != tee.ProviderAuto {
		return nil
	}
	family, name, err := tee.ResolveAuto(t.TSMReportDir)
	if err != nil {
		return fmt.Errorf("tee.provider=auto: %w", err)
	}
	t.Provider, t.AutoResolvedFrom = string(family), name
	return nil
}

// PeerTEEConfig pins the worker-side TEE the vault will accept.
type PeerTEEConfig struct {
	// Provider is the worker's TEE backend: "simulated" (default) or
	// "gcp-sev-snp". The verifier for it runs here; verification never
	// needs hardware.
	Provider string `json:"provider,omitempty"`

	// PublicKeyPath is the worker's 32-byte raw Ed25519 attestation key.
	// Simulated peers only; a SEV-SNP report is signed by the chip's
	// VCEK, which chains to AMD.
	PublicKeyPath string `json:"public_key_path,omitempty"`

	// MeasurementPath is the worker's launch measurement, raw: 32 bytes
	// for a simulated peer, 48 for SEV-SNP (never truncated, ADR 0007).
	MeasurementPath string `json:"measurement_path"`

	// AMDCertChainPath is the AMD ASK+ARK certificate chain (PEM) the
	// worker's VCEK must chain to — the chip's product line, as AMD KDS
	// serves it (`acpctl tee fetch-amd-chain`); its root must be one of
	// the AMD roots the binary pins (ADR 0024). Required for gcp-sev-snp
	// and azure-cgpu and azure-sev-snp peers. For an aws-sev-snp peer it
	// is the ASVK+ARK chain a VLEK chains to (`acpctl tee fetch-amd-chain
	// --signer vlek`; ADR 0038).
	AMDCertChainPath string `json:"amd_cert_chain_path,omitempty"`

	// AMDKDSURL overrides the AMD KDS base URL (a mirror). gcp-sev-snp
	// peers only.
	AMDKDSURL string `json:"amd_kds_url,omitempty"`

	// VCEKCacheDir keeps fetched VCEK certificates on disk so each chip
	// is asked of AMD KDS once; a cached certificate is still checked
	// against the pinned chain on every use. gcp-sev-snp peers only.
	VCEKCacheDir string `json:"vcek_cache_dir,omitempty"`

	// MinReportedTCB is the lowest REPORTED_TCB accepted from the
	// worker. gcp-sev-snp peers only.
	MinReportedTCB uint64 `json:"min_reported_tcb,omitempty"`
	// SEVSNP holds a SEV-SNP peer's report to the attack record (ADR 0033):
	// the TCB floors, the platform's word, the guest's policy, the mitigation
	// vector, the chip. Absent: the floors AMD's bulletins printed when they
	// were read, for the chip's variant.
	SEVSNP *tee.SEVSNPPolicyConfig `json:"sev_snp,omitempty"`

	// CSPIDs, for an aws-sev-snp peer, are the cloud providers whose VLEK
	// may sign the peer's report, as the VLEK's CSP_ID extension spells
	// them ("CN=cc-us-east-2.amazonaws.com", one per AWS region). Empty
	// accepts any VLEK that chains to AMD's root; the record says whose it
	// was. An EC2 report names no chip, so sev_snp.chip_ids does not apply
	// to this peer (ADR 0038).
	CSPIDs []string `json:"csp_ids,omitempty"`

	// PCSURL overrides the Intel PCS base URL (a mirror, a PCCS); PCSCacheDir
	// keeps the TCB info and QE identity documents between runs, each
	// checked like a fresh one on every use; AcceptableTCBStatuses lists
	// the Intel TCB statuses accepted (default UpToDate only; OutOfDate and
	// Revoked never). gcp-tdx peers only.
	PCSURL                string   `json:"pcs_url,omitempty"`
	PCSCacheDir           string   `json:"pcs_cache_dir,omitempty"`
	AcceptableTCBStatuses []string `json:"acceptable_tcb_statuses,omitempty"`

	// NRASJWKSURL overrides NVIDIA's attestation key-set URL; NRASCacheDir
	// keeps the key set between runs; GPUPolicy is what the GPU's claims
	// must say. azure-cgpu peers only, which also take the AMD fields
	// above (amd_cert_chain_path is the Genoa chain for NCC H100 v5).
	NRASJWKSURL  string           `json:"nras_jwks_url,omitempty"`
	NRASCacheDir string           `json:"nras_cache_dir,omitempty"`
	GPUPolicy    *GPUPolicyConfig `json:"gpu_policy,omitempty"`
	// PCRDigests (hex, 32 bytes each) pin what the peer's vTPM measured of
	// its boot: the quote's PCR digest must be one of them (`identity`
	// prints it as vtpm.pcr_digest_hex). Required for an azure-cgpu,
	// azure-sev-snp and gcp-sev-snp-vtpm peer: the launch measurement of
	// each is the cloud's — Azure's paravisor and firmware, Google's UEFI —
	// and only the vTPM measures the kernel (ADR 0037).
	PCRDigests []string `json:"pcr_digests,omitempty"`

	// PCRSelection is the selection a gcp-sev-snp-vtpm peer's quote must
	// cover; empty means sha256:0-9. GCEProjectIDs, when set, are the
	// Compute Engine projects such a peer may be an instance of, as its
	// vTPM's attestation-key certificate names them. GCEEKAKRootsPath adds
	// roots (PEM) to Google's EK/AK root, which the binary pins.
	PCRSelection     string   `json:"pcr_selection,omitempty"`
	GCEProjectIDs    []string `json:"gce_project_ids,omitempty"`
	GCEEKAKRootsPath string   `json:"gce_ek_ak_roots_path,omitempty"`

	// Verifier chooses who appraises the worker's Evidence (ADR 0025,
	// step 2b): this daemon's builtin verifier for the family (the
	// default), or a RATS Verifier asked over Veraison's
	// challenge-response API. The pin (measurement_path) is held here
	// either way.
	Verifier *PeerVerifierConfig `json:"verifier,omitempty"`
}

// PeerVerifierConfig is tee.peer.verifier: builtin, or a delegated RATS
// Verifier whose attestation result (EAR) this daemon verifies under the
// key on file and judges by the policy here. In the delegated mode the
// family's own inputs (the AMD chain, Intel's PCS) are the Verifier's
// business and need not be configured here; the peer's family and its
// measurement still are.
type PeerVerifierConfig struct {
	// Mode is "builtin" (default) or "rats".
	Mode string `json:"mode,omitempty"`
	// URL is the Verifier's base URL (https; plain http reaches loopback
	// only). rats only.
	URL string `json:"url,omitempty"`
	// EARPublicKeyPath holds the key the Verifier signs EARs with: a PEM
	// "PUBLIC KEY" block or a JSON Web Key, as its well-known document
	// publishes it (`ear-verification-key`). ES256, so EC P-256. rats only.
	EARPublicKeyPath string `json:"ear_public_key_path,omitempty"`
	// CAPath, when set, is the CA bundle (PEM) the Verifier's TLS
	// certificate must chain to; otherwise the system roots. rats only.
	CAPath string `json:"ca_path,omitempty"`
	// ClientCertPath and ClientKeyPath, when set, are this daemon's TLS
	// client certificate and key for a Verifier that takes only known
	// callers (mutual TLS). Both or neither. rats only.
	ClientCertPath string `json:"client_cert_path,omitempty"`
	ClientKeyPath  string `json:"client_key_path,omitempty"`
	// PolicyID, when set, is the ear.appraisal-policy-id the appraisal
	// must name. rats only.
	PolicyID string `json:"policy_id,omitempty"`
	// Submod, when set, is the appraisal (attester component) judged
	// by; otherwise the EAR must carry exactly one. rats only.
	Submod string `json:"submod,omitempty"`
	// Accept are the ear.status values that admit the peer: affirming
	// (the default), and warning if the operator says so. rats only.
	Accept []string `json:"accept,omitempty"`
	// TimeoutSeconds bounds each request to the Verifier; 10 by default.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// delegatedPeerFamilies are the families whose measurement this side
// reads from the Evidence itself, so a delegated verdict can be pinned.
var delegatedPeerFamilies = []tee.Provider{tee.ProviderSimulated, tee.ProviderGCPSEVSNP, tee.ProviderGCPTDX}

func (c *PeerVerifierConfig) mode() string {
	if c == nil || c.Mode == "" {
		return "builtin"
	}
	return c.Mode
}

// delegated reports whether appraisal goes to a RATS Verifier.
func (c *PeerVerifierConfig) delegated() bool { return c.mode() == "rats" }

func (c *PeerVerifierConfig) timeout() time.Duration {
	if c == nil || c.TimeoutSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// validate checks tee.peer.verifier for a peer of family peer.
func (c *PeerVerifierConfig) validate(peer tee.Provider) []error {
	if c == nil {
		return nil
	}
	var errs []error
	switch c.mode() {
	case "builtin":
		if c.URL != "" || c.EARPublicKeyPath != "" || c.CAPath != "" || c.ClientCertPath != "" || c.ClientKeyPath != "" || c.PolicyID != "" || c.Submod != "" || len(c.Accept) > 0 || c.TimeoutSeconds != 0 {
			errs = append(errs, errors.New("tee.peer.verifier: url, ear_public_key_path, ca_path, client_cert_path, client_key_path, policy_id, submod, accept and timeout_seconds apply to mode=rats only"))
		}
	case "rats":
		if c.URL == "" {
			errs = append(errs, errors.New("tee.peer.verifier.url required when tee.peer.verifier.mode=rats"))
		} else if u, err := url.Parse(c.URL); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			errs = append(errs, fmt.Errorf("tee.peer.verifier.url %q is not an http(s) URL", c.URL))
		}
		if c.EARPublicKeyPath == "" {
			errs = append(errs, errors.New("tee.peer.verifier.ear_public_key_path required when tee.peer.verifier.mode=rats (the key the Verifier signs its results with)"))
		}
		for _, a := range c.Accept {
			if a != tee.EARStatusAffirming && a != tee.EARStatusWarning {
				errs = append(errs, fmt.Errorf("tee.peer.verifier.accept %q: only affirming and warning can admit a peer", a))
			}
		}
		if c.TimeoutSeconds < 0 {
			errs = append(errs, errors.New("tee.peer.verifier.timeout_seconds must not be negative"))
		}
		if (c.ClientCertPath == "") != (c.ClientKeyPath == "") {
			errs = append(errs, errors.New("tee.peer.verifier.client_cert_path and client_key_path go together"))
		}
		if peer != "" && !slices.Contains(delegatedPeerFamilies, peer) {
			errs = append(errs, fmt.Errorf("tee.peer.verifier.mode=rats holds the pin by reading the Evidence itself, which this build does for %v, not %q", delegatedPeerFamilies, peer))
		}
	default:
		errs = append(errs, fmt.Errorf("tee.peer.verifier.mode %q: builtin or rats", c.Mode))
	}
	return errs
}

// pcrDigests decodes PCRDigests; a malformed entry is a config error.
func pcrDigests(hexes []string) ([][]byte, error) {
	out := make([][]byte, 0, len(hexes))
	for _, h := range hexes {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("pcr_digests: %q is not a 32-byte hex digest", h)
		}
		out = append(out, b)
	}
	return out, nil
}

// GPUPolicyConfig is the operator's word on NVIDIA's per-GPU claims.
type GPUPolicyConfig struct {
	AllowSecureBootOff bool     `json:"allow_secure_boot_off,omitempty"`
	AllowDebug         bool     `json:"allow_debug,omitempty"`
	AllowUnsignedRIM   bool     `json:"allow_unsigned_rim,omitempty"`
	HWModels           []string `json:"hw_models,omitempty"`
	DriverVersions     []string `json:"driver_versions,omitempty"`
	VBIOSVersions      []string `json:"vbios_versions,omitempty"`
	// Evaluation says whose evaluation of the GPU's report the verdict
	// rests on: "nras" (default) takes NVIDIA's signed tokens; "both"
	// requires them and the verifier's own evaluation of the attestation
	// report the evidence carries — the chain to NVIDIA's device root,
	// the report's signature and nonce, the firmware id, and the runtime
	// measurements against NVIDIA's reference manifests (ADR 0021).
	// "own" is refused by this build (the manifests' XML signatures are
	// not verified). With "both", RIMServiceURL and RIMCacheDir say where
	// the manifests come from and are kept; the NVIDIA roots are pinned in
	// the binary unless NVIDIADeviceRootPath / NVIDIARIMRootPath name
	// other PEM files.
	Evaluation           string `json:"evaluation,omitempty"`
	RIMServiceURL        string `json:"rim_service_url,omitempty"`
	RIMCacheDir          string `json:"rim_cache_dir,omitempty"`
	NVIDIADeviceRootPath string `json:"nvidia_device_root_path,omitempty"`
	NVIDIARIMRootPath    string `json:"nvidia_rim_root_path,omitempty"`
	// Revocation says whether the verifier's own evaluation asks NVIDIA's
	// OCSP responder about the GPU's certificate chain: "ocsp" (the
	// default under both and own; answers cached a day under
	// rim_cache_dir) or "off" (unchecked, on the record). OCSPURL
	// overrides the responder (default http://ocsp.ndis.nvidia.com).
	Revocation string `json:"revocation,omitempty"`
	OCSPURL    string `json:"ocsp_url,omitempty"`
}

func (g *GPUPolicyConfig) policy() tee.GPUClaimsPolicy {
	if g == nil {
		return tee.GPUClaimsPolicy{}
	}
	return tee.GPUClaimsPolicy{AllowSecureBootOff: g.AllowSecureBootOff, AllowDebug: g.AllowDebug, AllowUnsignedRIM: g.AllowUnsignedRIM,
		AcceptableHWModels: g.HWModels, AcceptableDriverVersions: g.DriverVersions, AcceptableVBIOSVersions: g.VBIOSVersions}
}

// validate checks the evaluation named, if any.
func (g *GPUPolicyConfig) validate() error {
	if g == nil {
		return nil
	}
	switch g.Evaluation {
	case "", tee.GPUEvaluationNRAS, tee.GPUEvaluationBoth, tee.GPUEvaluationOwn:
	default:
		return fmt.Errorf("gpu_policy.evaluation %q (one of nras, both, own)", g.Evaluation)
	}
	switch g.Revocation {
	case "", tee.GPURevocationOCSP, tee.GPURevocationOff:
	default:
		return fmt.Errorf("gpu_policy.revocation %q (one of ocsp, off)", g.Revocation)
	}
	if (g.Revocation != "" || g.OCSPURL != "") && (g.Evaluation == "" || g.Evaluation == tee.GPUEvaluationNRAS) {
		return errors.New("gpu_policy.revocation and ocsp_url apply to the verifier's own evaluation (evaluation both or own)")
	}
	return nil
}

// apply sets the evaluation fields of a verifier config from the policy,
// reading the root PEM files it names.
func (g *GPUPolicyConfig) apply(cfg *tee.AzureCGPUVerifierConfig) error {
	if g == nil {
		return nil
	}
	cfg.GPUEvaluation, cfg.RIMServiceURL, cfg.RIMCacheDir = g.Evaluation, g.RIMServiceURL, g.RIMCacheDir
	cfg.GPURevocation, cfg.OCSPURL = g.Revocation, g.OCSPURL
	var err error
	if g.NVIDIADeviceRootPath != "" {
		if cfg.NVIDIADeviceRootPEM, err = os.ReadFile(g.NVIDIADeviceRootPath); err != nil {
			return fmt.Errorf("gpu_policy.nvidia_device_root_path: %w", err)
		}
	}
	if g.NVIDIARIMRootPath != "" {
		if cfg.NVIDIARIMRootPEM, err = os.ReadFile(g.NVIDIARIMRootPath); err != nil {
			return fmt.Errorf("gpu_policy.nvidia_rim_root_path: %w", err)
		}
	}
	return nil
}

// supportedProviders are the TEE backends this build can attest with
// on the Return Path, and verify a peer's Evidence for.
var supportedProviders = []tee.Provider{tee.ProviderGCPSEVSNP, tee.ProviderGCPSEVSNPVTPM, tee.ProviderGCPTDX, tee.ProviderAzureCGPU, tee.ProviderAzureSEVSNP, tee.ProviderAWSSEVSNP, tee.ProviderSimulated, tee.ProviderAuto}

// DefaultSEVGuestDevice is where the Linux sev-guest driver appears.
const DefaultSEVGuestDevice = "/dev/sev-guest"

// SEVDevice is the sev-guest device the sealer opens.
func (t TEEConfig) SEVDevice() string {
	if t.SEVGuestDevice != "" {
		return t.SEVGuestDevice
	}
	return DefaultSEVGuestDevice
}

// ProviderKind parses TEEConfig.Provider, defaulting to simulated.
func (t TEEConfig) ProviderKind() (tee.Provider, error) {
	if strings.TrimSpace(t.Provider) == "" {
		return tee.ProviderSimulated, nil
	}
	return tee.ParseProvider(t.Provider)
}

// ProviderKind parses PeerTEEConfig.Provider, defaulting to simulated.
func (p PeerTEEConfig) ProviderKind() (tee.Provider, error) {
	if strings.TrimSpace(p.Provider) == "" {
		return tee.ProviderSimulated, nil
	}
	return tee.ParseProvider(p.Provider)
}

// validateTEE checks the local provider and the peer pin as a pair of
// choices: a simulated producer needs its seed and the operator's
// acknowledgement; a hardware producer signs with the chip and refuses
// both; a simulated peer is pinned by key and measurement; a SEV-SNP
// peer by measurement and the AMD chain.
func validateTEE(t TEEConfig) []error {
	var errs []error
	if _, err := tee.ParseSealerMode(t.Sealer); err != nil {
		errs = append(errs, err)
	}
	switch provider, err := t.ProviderKind(); {
	case err != nil:
		errs = append(errs, fmt.Errorf("tee.provider invalid: %w", err))
	case !slices.Contains(supportedProviders, provider):
		errs = append(errs, fmt.Errorf("tee.provider %q is not available in this build (supported: %v)", provider, supportedProviders))
	case provider == tee.ProviderSimulated:
		if t.SeedPath == "" {
			errs = append(errs, errors.New("tee.seed_path required when tee.provider=simulated"))
		}
		if !t.InsecureSimulation {
			errs = append(errs, errors.New("tee.provider=simulated has no hardware isolation: set tee.insecure_simulation=true to run it, for development and tests only"))
		}
		if t.TSMReportDir != "" {
			errs = append(errs, errors.New("tee.tsm_report_dir applies to gcp-sev-snp and gcp-tdx only"))
		}
		if t.SEVGuestDevice != "" {
			errs = append(errs, errors.New("tee.sev_guest_device applies to gcp-sev-snp only"))
		}
		if t.VTPMSealPCRs != "" {
			errs = append(errs, errors.New("tee.vtpm_seal_pcrs applies to gcp-tdx and azure-cgpu only"))
		}
	case provider == tee.ProviderAuto:
		// The family is the kernel's to say at start (configfs-tsm); the
		// rules of a hardware provider apply, and the per-family settings
		// are checked for form here and for fit by the family resolved.
		if t.SeedPath != "" || t.InsecureSimulation {
			errs = append(errs, errors.New("tee.seed_path and tee.insecure_simulation apply to the simulated provider only; tee.provider=auto runs the family configfs-tsm, or the vTPM's HCL report under Azure's paravisor, serves"))
		}
		for _, sel := range []struct{ name, v string }{{"tee.vtpm_seal_pcrs", t.VTPMSealPCRs}, {"tee.vtpm_quote_pcrs", t.VTPMQuotePCRs}} {
			if sel.v != "" {
				if err := tee.ValidatePCRSelection(sel.v); err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", sel.name, err))
				}
			}
		}
	case provider == tee.ProviderGCPSEVSNP || provider == tee.ProviderGCPTDX || provider == tee.ProviderAWSSEVSNP:
		if t.SeedPath != "" {
			errs = append(errs, errors.New("tee.seed_path applies to the simulated provider only; a hardware TEE signs with its own key"))
		}
		if t.InsecureSimulation {
			errs = append(errs, errors.New("tee.insecure_simulation applies to the simulated provider only"))
		}
		if provider == tee.ProviderGCPTDX && t.SEVGuestDevice != "" {
			errs = append(errs, errors.New("tee.sev_guest_device applies to gcp-sev-snp and aws-sev-snp only"))
		}
		if provider == tee.ProviderGCPSEVSNP && t.VTPMSealPCRs != "" {
			if m := t.SealerMode(); m != tee.SealerModeBoth && m != tee.SealerModeTPM2 {
				errs = append(errs, errors.New("tee.vtpm_seal_pcrs: gcp-sev-snp seals with the chip's derived key unless tee.sealer is both or tpm2"))
			} else if err := tee.ValidatePCRSelection(t.VTPMSealPCRs); err != nil {
				errs = append(errs, fmt.Errorf("tee.vtpm_seal_pcrs: %w", err))
			}
		}
		if provider == tee.ProviderAWSSEVSNP {
			if m := t.SealerMode(); m == tee.SealerModeBoth || m == tee.SealerModeTPM2 {
				errs = append(errs, errors.New("tee.sealer: an EC2 SEV-SNP instance has no vTPM in this build; aws-sev-snp seals with the firmware's derived key (tee.sealer auto or tee; ADR 0038)"))
			}
			if t.VTPMSealPCRs != "" || t.VTPMQuotePCRs != "" {
				errs = append(errs, errors.New("tee.vtpm_seal_pcrs and tee.vtpm_quote_pcrs do not apply to aws-sev-snp (no vTPM)"))
			}
		}
		if provider == tee.ProviderGCPTDX && t.VTPMSealPCRs != "" {
			if err := tee.ValidatePCRSelection(t.VTPMSealPCRs); err != nil {
				errs = append(errs, fmt.Errorf("tee.vtpm_seal_pcrs: %w", err))
			}
		}
	case provider == tee.ProviderGCPSEVSNPVTPM:
		if t.SeedPath != "" || t.InsecureSimulation {
			errs = append(errs, errors.New("tee.seed_path and tee.insecure_simulation apply to the simulated provider only"))
		}
		for _, sel := range []struct{ name, v string }{{"tee.vtpm_seal_pcrs", t.VTPMSealPCRs}, {"tee.vtpm_quote_pcrs", t.VTPMQuotePCRs}} {
			if sel.v != "" {
				if err := tee.ValidatePCRSelection(sel.v); err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", sel.name, err))
				}
			}
		}
		if len(t.GPUAttestCommand) > 0 || t.AKHandle != "" {
			errs = append(errs, errors.New("tee.gpu_attest_command and ak_handle apply to azure-cgpu and azure-sev-snp only (gcp-sev-snp-vtpm makes its attestation key from Google's template)"))
		}
	case provider == tee.ProviderAzureSEVSNP:
		if t.SeedPath != "" || t.InsecureSimulation {
			errs = append(errs, errors.New("tee.seed_path and tee.insecure_simulation apply to the simulated provider only"))
		}
		if t.TSMReportDir != "" || t.SEVGuestDevice != "" {
			errs = append(errs, errors.New("tee.tsm_report_dir and tee.sev_guest_device do not apply to azure-sev-snp (the report comes from the vTPM)"))
		}
		for _, sel := range []struct{ name, v string }{{"tee.vtpm_seal_pcrs", t.VTPMSealPCRs}, {"tee.vtpm_quote_pcrs", t.VTPMQuotePCRs}} {
			if sel.v != "" {
				if err := tee.ValidatePCRSelection(sel.v); err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", sel.name, err))
				}
			}
		}
		if len(t.GPUAttestCommand) > 0 {
			errs = append(errs, errors.New("tee.gpu_attest_command applies to azure-cgpu only (azure-sev-snp has no GPU)"))
		}
	case provider == tee.ProviderAzureCGPU:
		if t.SeedPath != "" || t.InsecureSimulation {
			errs = append(errs, errors.New("tee.seed_path and tee.insecure_simulation apply to the simulated provider only"))
		}
		if t.TSMReportDir != "" || t.SEVGuestDevice != "" {
			errs = append(errs, errors.New("tee.tsm_report_dir and tee.sev_guest_device do not apply to azure-cgpu (the report comes from the vTPM)"))
		}
		for _, sel := range []struct{ name, v string }{{"tee.vtpm_seal_pcrs", t.VTPMSealPCRs}, {"tee.vtpm_quote_pcrs", t.VTPMQuotePCRs}} {
			if sel.v != "" {
				if err := tee.ValidatePCRSelection(sel.v); err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", sel.name, err))
				}
			}
		}
		if len(t.GPUAttestCommand) == 0 {
			errs = append(errs, errors.New("tee.gpu_attest_command required when tee.provider=azure-cgpu (the command that obtains NVIDIA's attestation tokens for a nonce)"))
		}
	}
	if lp, _ := t.ProviderKind(); lp != tee.ProviderAzureCGPU && lp != tee.ProviderAzureSEVSNP && (len(t.GPUAttestCommand) > 0 || t.AKHandle != "" ||
		(t.TPM2ToolsDir != "" && lp != tee.ProviderGCPSEVSNPVTPM)) {
		errs = append(errs, errors.New("tee.gpu_attest_command and ak_handle apply to azure-cgpu and azure-sev-snp only, and tpm2_tools_dir to those and gcp-sev-snp-vtpm"))
	}
	if lp, _ := t.ProviderKind(); lp != tee.ProviderGCPSEVSNPVTPM && t.AKIntermediatesPath != "" {
		errs = append(errs, errors.New("tee.ak_intermediates_path applies to gcp-sev-snp-vtpm only"))
	}
	if lp, _ := t.ProviderKind(); t.VTPMQuotePCRs != "" && !tee.QuotesTheBoot(lp) && lp != tee.ProviderAuto {
		errs = append(errs, errors.New("tee.vtpm_quote_pcrs applies to gcp-sev-snp-vtpm, azure-sev-snp and azure-cgpu only, the families whose vTPM quotes the boot"))
	}
	if t.Peer.MeasurementPath == "" {
		errs = append(errs, errors.New("tee.peer.measurement_path required"))
	}
	switch peer, err := t.Peer.ProviderKind(); {
	case peer == tee.ProviderAuto:
		errs = append(errs, errors.New("tee.peer.provider cannot be auto: name the family the peer must attest as (gcp-sev-snp, gcp-tdx, azure-cgpu, azure-sev-snp, aws-sev-snp or simulated); only the daemon's own tee.provider may be auto"))
	case err != nil:
		errs = append(errs, fmt.Errorf("tee.peer.provider invalid: %w", err))
	case !slices.Contains(supportedProviders, peer):
		errs = append(errs, fmt.Errorf("tee.peer.provider %q: no verifier this build can run end to end (supported: %v)", peer, supportedProviders))
	case peer == tee.ProviderSimulated:
		if t.Peer.PublicKeyPath == "" && !t.Peer.Verifier.delegated() {
			errs = append(errs, errors.New("tee.peer.public_key_path required when tee.peer.provider=simulated"))
		}
		if t.Peer.AMDCertChainPath != "" || t.Peer.AMDKDSURL != "" || t.Peer.VCEKCacheDir != "" || t.Peer.MinReportedTCB != 0 || t.Peer.SEVSNP != nil {
			errs = append(errs, errors.New("tee.peer.amd_cert_chain_path, amd_kds_url, vcek_cache_dir, min_reported_tcb and sev_snp apply to a gcp-sev-snp, azure-cgpu, azure-sev-snp or aws-sev-snp peer only"))
		}
		if t.Peer.PCSURL != "" || t.Peer.PCSCacheDir != "" || len(t.Peer.AcceptableTCBStatuses) > 0 {
			errs = append(errs, errors.New("tee.peer.pcs_url, pcs_cache_dir and acceptable_tcb_statuses apply to a gcp-tdx peer only"))
		}
	case peer == tee.ProviderGCPSEVSNP:
		if t.Peer.PublicKeyPath != "" {
			errs = append(errs, errors.New("tee.peer.public_key_path applies to a simulated peer only; a SEV-SNP report is signed by the chip's VCEK"))
		}
		if t.Peer.AMDCertChainPath == "" && !t.Peer.Verifier.delegated() {
			errs = append(errs, errors.New("tee.peer.amd_cert_chain_path required when tee.peer.provider=gcp-sev-snp (the AMD ASK+ARK chain the VCEK must chain to)"))
		}
		if t.Peer.PCSURL != "" || t.Peer.PCSCacheDir != "" || len(t.Peer.AcceptableTCBStatuses) > 0 {
			errs = append(errs, errors.New("tee.peer.pcs_url, pcs_cache_dir and acceptable_tcb_statuses apply to a gcp-tdx peer only"))
		}
	case peer == tee.ProviderAWSSEVSNP:
		if t.Peer.PublicKeyPath != "" {
			errs = append(errs, errors.New("tee.peer.public_key_path applies to a simulated peer only; an EC2 SEV-SNP report is signed by the provider's VLEK"))
		}
		if t.Peer.Verifier.delegated() {
			errs = append(errs, errors.New("tee.peer.verifier: an aws-sev-snp peer is appraised by this verifier only — the evidence carries the VLEK beside the report, which the delegated Verifiers do not read yet (ADR 0038)"))
		}
		if t.Peer.AMDCertChainPath == "" {
			errs = append(errs, errors.New("tee.peer.amd_cert_chain_path required when tee.peer.provider=aws-sev-snp (the AMD ASVK+ARK chain a VLEK must chain to: acpctl tee fetch-amd-chain --signer vlek)"))
		}
		if t.Peer.VCEKCacheDir != "" || t.Peer.AMDKDSURL != "" {
			errs = append(errs, errors.New("tee.peer.vcek_cache_dir and amd_kds_url do not apply to an aws-sev-snp peer: there is no VCEK under a VLEK, and the VLEK travels with the report"))
		}
		if t.Peer.SEVSNP != nil && len(t.Peer.SEVSNP.ChipIDs) > 0 {
			errs = append(errs, errors.New("tee.peer.sev_snp.chip_ids does not apply to an aws-sev-snp peer: an EC2 report names no chip (CHIP_ID is zero under a VLEK); pin the measurement and csp_ids instead"))
		}
		if t.Peer.PCSURL != "" || t.Peer.PCSCacheDir != "" || len(t.Peer.AcceptableTCBStatuses) > 0 {
			errs = append(errs, errors.New("tee.peer.pcs_url, pcs_cache_dir and acceptable_tcb_statuses apply to a gcp-tdx peer only"))
		}
		for i, c := range t.Peer.CSPIDs {
			if strings.TrimSpace(c) == "" {
				errs = append(errs, fmt.Errorf("tee.peer.csp_ids[%d] is empty", i))
			}
		}
	case peer == tee.ProviderGCPSEVSNPVTPM:
		if t.Peer.PublicKeyPath != "" {
			errs = append(errs, errors.New("tee.peer.public_key_path applies to a simulated peer only; a SEV-SNP report is signed by the chip's VCEK"))
		}
		if t.Peer.Verifier.delegated() {
			errs = append(errs, errors.New("tee.peer.verifier: a gcp-sev-snp-vtpm peer is appraised by this verifier only — the delegated Verifiers read the chip's report, not the vTPM's quote beside it"))
		}
		if t.Peer.AMDCertChainPath == "" {
			errs = append(errs, errors.New("tee.peer.amd_cert_chain_path required when tee.peer.provider=gcp-sev-snp-vtpm (the AMD ASK+ARK chain the VCEK must chain to)"))
		}
		if len(t.Peer.PCRDigests) == 0 {
			errs = append(errs, errors.New("tee.peer.pcr_digests required when tee.peer.provider=gcp-sev-snp-vtpm: the boots the peer may run (its launch measurement is Google's firmware and says nothing of the kernel; ADR 0037)"))
		}
		if t.Peer.PCRSelection != "" {
			if err := tee.ValidatePCRSelection(t.Peer.PCRSelection); err != nil {
				errs = append(errs, fmt.Errorf("tee.peer.pcr_selection: %w", err))
			}
		}
		if t.Peer.PCSURL != "" || t.Peer.PCSCacheDir != "" || len(t.Peer.AcceptableTCBStatuses) > 0 {
			errs = append(errs, errors.New("tee.peer.pcs_url, pcs_cache_dir and acceptable_tcb_statuses apply to a gcp-tdx peer only"))
		}
	case peer == tee.ProviderGCPTDX:
		if t.Peer.PublicKeyPath != "" {
			errs = append(errs, errors.New("tee.peer.public_key_path applies to a simulated peer only; a TDX quote chains to the Intel SGX Root CA"))
		}
		if t.Peer.AMDCertChainPath != "" || t.Peer.AMDKDSURL != "" || t.Peer.VCEKCacheDir != "" || t.Peer.MinReportedTCB != 0 || t.Peer.SEVSNP != nil {
			errs = append(errs, errors.New("tee.peer.amd_cert_chain_path, amd_kds_url, vcek_cache_dir, min_reported_tcb and sev_snp apply to a gcp-sev-snp, azure-cgpu, azure-sev-snp or aws-sev-snp peer only"))
		}
	case peer == tee.ProviderAzureSEVSNP:
		if t.Peer.PublicKeyPath != "" {
			errs = append(errs, errors.New("tee.peer.public_key_path applies to a simulated peer only; an Azure SEV-SNP VM's report is signed by the chip's VCEK"))
		}
		if t.Peer.AMDCertChainPath == "" && !t.Peer.Verifier.delegated() {
			errs = append(errs, errors.New("tee.peer.amd_cert_chain_path required when tee.peer.provider=azure-sev-snp (the AMD ASK+ARK chain of the chip's product, Milan or Genoa as the report says)"))
		}
		if t.Peer.PCSURL != "" || t.Peer.PCSCacheDir != "" || len(t.Peer.AcceptableTCBStatuses) > 0 {
			errs = append(errs, errors.New("tee.peer.pcs_url, pcs_cache_dir and acceptable_tcb_statuses apply to a gcp-tdx peer only"))
		}
		if t.Peer.NRASJWKSURL != "" || t.Peer.NRASCacheDir != "" || t.Peer.GPUPolicy != nil {
			errs = append(errs, errors.New("tee.peer.nras_jwks_url, nras_cache_dir and gpu_policy apply to an azure-cgpu peer only (azure-sev-snp has no GPU)"))
		}
		if len(t.Peer.PCRDigests) == 0 {
			errs = append(errs, errors.New("tee.peer.pcr_digests required when tee.peer.provider=azure-sev-snp: the boots the peer may run (its launch measurement is Azure's paravisor and firmware and says nothing of the OS; ADR 0037)"))
		}
	case peer == tee.ProviderAzureCGPU:
		if t.Peer.PublicKeyPath != "" {
			errs = append(errs, errors.New("tee.peer.public_key_path applies to a simulated peer only; an Azure confidential GPU VM's report is signed by the chip's VCEK"))
		}
		if t.Peer.AMDCertChainPath == "" && !t.Peer.Verifier.delegated() {
			errs = append(errs, errors.New("tee.peer.amd_cert_chain_path required when tee.peer.provider=azure-cgpu (the AMD ASK+ARK chain of the chip's product, Genoa for NCC H100 v5)"))
		}
		if t.Peer.PCSURL != "" || t.Peer.PCSCacheDir != "" || len(t.Peer.AcceptableTCBStatuses) > 0 {
			errs = append(errs, errors.New("tee.peer.pcs_url, pcs_cache_dir and acceptable_tcb_statuses apply to a gcp-tdx peer only"))
		}
		if len(t.Peer.PCRDigests) == 0 {
			errs = append(errs, errors.New("tee.peer.pcr_digests required when tee.peer.provider=azure-cgpu: the boots the peer may run, OS and driver (its launch measurement is Azure's paravisor and firmware and says nothing of the OS; ADR 0037)"))
		}
	}
	if peer, err := t.Peer.ProviderKind(); err == nil {
		errs = append(errs, t.Peer.Verifier.validate(peer)...)
	} else {
		errs = append(errs, t.Peer.Verifier.validate("")...)
	}
	if err := t.Peer.GPUPolicy.validate(); err != nil {
		errs = append(errs, fmt.Errorf("tee.peer.%w", err))
	}
	if peer, _ := t.Peer.ProviderKind(); peer != tee.ProviderAzureCGPU && peer != tee.ProviderAzureSEVSNP && (t.Peer.NRASJWKSURL != "" || t.Peer.NRASCacheDir != "" || t.Peer.GPUPolicy != nil ||
		(len(t.Peer.PCRDigests) > 0 && peer != tee.ProviderGCPSEVSNPVTPM)) {
		errs = append(errs, errors.New("tee.peer.nras_jwks_url, nras_cache_dir and gpu_policy apply to an azure-cgpu peer, and pcr_digests to that, an azure-sev-snp and a gcp-sev-snp-vtpm peer only"))
	}
	if peer, _ := t.Peer.ProviderKind(); peer != tee.ProviderGCPSEVSNPVTPM && (t.Peer.PCRSelection != "" || len(t.Peer.GCEProjectIDs) > 0 || t.Peer.GCEEKAKRootsPath != "") {
		errs = append(errs, errors.New("tee.peer.pcr_selection, gce_project_ids and gce_ek_ak_roots_path apply to a gcp-sev-snp-vtpm peer only"))
	}
	if peer, _ := t.Peer.ProviderKind(); peer != tee.ProviderAWSSEVSNP && len(t.Peer.CSPIDs) > 0 {
		errs = append(errs, errors.New("tee.peer.csp_ids applies to an aws-sev-snp peer only (the VLEK's CSP_ID; ADR 0038)"))
	}
	if _, err := pcrDigests(t.Peer.PCRDigests); err != nil {
		errs = append(errs, fmt.Errorf("tee.peer.%w", err))
	}
	return errs
}

// KeysConfig bundles the key-material slots sagvd uses.
type KeysConfig struct {
	// AuthoritySigning is the key sagvd uses to sign
	// authority artifacts (ReconstructionJobManifest signatures,
	// ReleaseDecision, AttestationResult). Phase 1 uses it only for
	// provisioning parity with Phase 3; the investor demo does not
	// exercise authority signing on the hot path.
	AuthoritySigning SigningKeyConfig `json:"authority_signing"`

	// SessionSealing is the AES-256 key pre-shared between sagvd and
	// acp-compute. sagvd uses it to Seal SealedMaterial into
	// JobRequest; the worker uses it to Open the SealedMaterialRef
	// and extract the plaintext it will operate on.
	SessionSealing SealingKeyConfig `json:"session_sealing"`

	// AuditSigning is the key that signs the cross-cloud audit
	// log (keys.PurposeSigningAudit). It must stay the same across runs:
	// the log is one hash-linked chain, verified end to end whenever it
	// is opened. Required when crosscloud.enabled=true; its public half
	// (`sagvd identity`) is what auditors verify the log with.
	AuditSigning SigningKeyConfig `json:"audit_signing,omitempty"`
}

// SigningKeyConfig names a signing key: its kid, its key file and its
// signature suite (ADR 0031). SeedPath is the key file — the 32-byte seed
// of an ed25519 or ml-dsa-87 key, the PKCS#8 PEM of an ecdsa-p384-sha384
// key — bare, or sealed in place by seal-keys (ADR 0023). Suite names
// the suite the file is read under, never guessed from its length;
// absent, it is ed25519, what every configuration before ADR 0031 meant.
type SigningKeyConfig struct {
	KeyID    string `json:"kid"`
	SeedPath string `json:"seed_path"`
	Suite    string `json:"suite,omitempty"`
}

// signatureSuite is the suite the configuration names: ed25519 when absent.
func (k SigningKeyConfig) signatureSuite() (crypto.SignatureSuite, error) {
	return crypto.SuiteOrDefault(k.Suite)
}

// SealingKeyConfig points at a 32-byte AES-256 key-material file.
type SealingKeyConfig struct {
	KeyID        string `json:"kid"`
	MaterialPath string `json:"material_path"`
}

// WorkersConfig points at the JSON registry of known worker signing
// public keys. See workers.go for the file schema.
type WorkersConfig struct {
	// RegistryPath is a JSON file listing {kid, signing_pubkey_hex}
	// for every worker this vault will accept a CandidateOutputFrame
	// from. Out-of-band provisioning in Phase 1; attestation-bound
	// in Phase 3.
	RegistryPath string `json:"registry_path"`
}

// QueueConfig is the daemon's job store (ADR 0026).
type QueueConfig struct {
	// Path is the bbolt file every accepted job is recorded in — the
	// request as accepted, its status, and once finished its view — so
	// that a restart admits again what was queued or in flight and still
	// answers a GET for what was finished. Empty keeps the queue in
	// memory. It must not be the audit log's file: one process holds a
	// bbolt file at a time, and the two are opened separately.
	Path string `json:"path,omitempty"`

	// MaxResumeAttempts bounds how many times one job is admitted after
	// restarts before it is failed as a job the authority cannot finish
	// (a job that crashes the authority must not crash it forever);
	// 0 takes DefaultMaxResumeAttempts.
	MaxResumeAttempts int `json:"max_resume_attempts,omitempty"`

	// RetainFinishedSeconds is how long a finished job's record and view
	// stay in the store after it finished (ADR 0027): older ones are
	// deleted, in batches, at most once a minute, after a completion and
	// at start, and GET /v1/jobs/{id} answers 404 for them — the audit
	// log holds the decision under the job's request id. 0, the
	// default, keeps every finished job. Jobs queued or running are
	// never deleted.
	RetainFinishedSeconds int `json:"retain_finished_seconds,omitempty"`
}

// RetainFinished is QueueConfig.RetainFinishedSeconds as a duration.
func (q QueueConfig) RetainFinished() time.Duration {
	return time.Duration(q.RetainFinishedSeconds) * time.Second
}

// DefaultMaxResumeAttempts is QueueConfig.MaxResumeAttempts when unset.
const DefaultMaxResumeAttempts = 3

// MaxResume returns MaxResumeAttempts with the default applied.
func (q QueueConfig) MaxResume() int {
	if q.MaxResumeAttempts <= 0 {
		return DefaultMaxResumeAttempts
	}
	return q.MaxResumeAttempts
}

// RuntimeConfig bounds the accept / dispatch / HTTP timings.
type RuntimeConfig struct {
	// JobTimeoutSeconds caps the total wall-clock duration for a
	// single Return Path session from accept() to close. Guards
	// against a slow or wedged worker holding the dispatcher.
	JobTimeoutSeconds int `json:"job_timeout_seconds"`

	// HandshakeTimeoutSeconds caps the 4-frame handshake phase.
	HandshakeTimeoutSeconds int `json:"handshake_timeout_seconds"`

	// QueuePollMs is how long the dispatcher blocks waiting for the
	// next queued job before re-checking shutdown. Trades demo
	// responsiveness against idle CPU.
	QueuePollMs int `json:"queue_poll_ms"`

	// HTTPReadHeaderTimeoutSeconds bounds HTTP request header read
	// time (guards against slow-loris on the operator REST API).
	HTTPReadHeaderTimeoutSeconds int `json:"http_read_header_timeout_seconds"`

	// HTTPWriteTimeoutSeconds bounds the full response write
	// duration.
	HTTPWriteTimeoutSeconds int `json:"http_write_timeout_seconds"`

	// DefaultJobDeadlineSeconds is the default value when a POST
	// /v1/jobs body omits deadline_seconds_from_now. Also the
	// ceiling: submissions asking for longer are Structurally
	// rejected with 400.
	DefaultJobDeadlineSeconds int `json:"default_job_deadline_seconds"`

	// MaxPayloadBytes caps base64-decoded POST /v1/jobs payload
	// size. Prevents a single client from exhausting vault memory.
	MaxPayloadBytes uint64 `json:"max_payload_bytes"`

	// EvidenceMaxAgeSeconds is how old a worker's Return Path Evidence
	// may be when a job is handed to it. A session whose handshake is
	// older is closed with re_attest and the job stays queued (the worker
	// dials again, attests again). 0 takes the attestation default
	// (5 minutes).
	EvidenceMaxAgeSeconds int `json:"evidence_max_age_seconds,omitempty"`

	// MaxSessions is how many Return Path sessions the authority serves
	// at once — each a worker attested, a job dispatched, an answer
	// judged, on the record. 0 means 1: one session at a time, the
	// behaviour before this setting. A worker that connects while every
	// slot is taken waits up to handshake_timeout_seconds for one, then
	// is closed before any handshake and counted as refused (busy); it
	// dials again after its backoff. Every stage a session takes is
	// under the audit log's and the queue's own locks, so sessions do
	// not see each other's jobs.
	MaxSessions int `json:"max_sessions,omitempty"`
}

// SessionSlots returns RuntimeConfig.MaxSessions, 1 when unset.
func (r RuntimeConfig) SessionSlots() int {
	if r.MaxSessions <= 0 {
		return 1
	}
	return r.MaxSessions
}

// JobTimeout returns RuntimeConfig.JobTimeoutSeconds as a Duration.
func (r RuntimeConfig) JobTimeout() time.Duration {
	return time.Duration(r.JobTimeoutSeconds) * time.Second
}

// HandshakeTimeout returns RuntimeConfig.HandshakeTimeoutSeconds as
// a Duration.
func (r RuntimeConfig) HandshakeTimeout() time.Duration {
	return time.Duration(r.HandshakeTimeoutSeconds) * time.Second
}

// QueuePoll returns RuntimeConfig.QueuePollMs as a Duration.
func (r RuntimeConfig) QueuePoll() time.Duration {
	return time.Duration(r.QueuePollMs) * time.Millisecond
}

// HTTPReadHeaderTimeout returns the HTTP read-header bound.
func (r RuntimeConfig) HTTPReadHeaderTimeout() time.Duration {
	return time.Duration(r.HTTPReadHeaderTimeoutSeconds) * time.Second
}

// HTTPWriteTimeout returns the HTTP write bound.
func (r RuntimeConfig) HTTPWriteTimeout() time.Duration {
	return time.Duration(r.HTTPWriteTimeoutSeconds) * time.Second
}

// DefaultJobDeadline returns the default per-job deadline.
// EvidenceMaxAge is RuntimeConfig.EvidenceMaxAgeSeconds as a duration,
// the attestation default when unset.
func (r RuntimeConfig) EvidenceMaxAge() time.Duration {
	if r.EvidenceMaxAgeSeconds <= 0 {
		return attestation_result.DefaultTTL
	}
	return time.Duration(r.EvidenceMaxAgeSeconds) * time.Second
}

func (r RuntimeConfig) DefaultJobDeadline() time.Duration {
	return time.Duration(r.DefaultJobDeadlineSeconds) * time.Second
}

// HealthConfig controls the local /healthz /readyz /metrics server.
type HealthConfig struct {
	ListenAddress string `json:"listen_address"`
}

// LogConfig picks log verbosity and format.
type LogConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// CrossCloudConfig holds the operator-supplied configuration for the
// Phase 4 cross-cloud KMS-mediated restore capability. The whole
// block is optional (Enabled=false skips loading; Phase 1-3 daemons
// behave identically). When Enabled=true, the daemon's startup path
// loads:
//
//   - VerifierRegistryPath into a tee.Registry holding one Verifier
//     per cross-cloud destination this authority may target. Each
//     entry pins the destination's TEE family + attestor pubkey +
//     expected measurement.
//
//   - PolicyAllowListPath into a kms.AllowListPolicy. Entries are
//     (Provider, hex-encoded measurement) pairs. PolicyVersion is
//     recorded in the audit payload of every KEY_RELEASE_AUTHORIZED
//     event so historical decisions can be replayed against the
//     policy snapshot in force at the time.
//
//   - TransportTLS material into the http.Client passed to the
//     HTTPTransport. mTLS is required for production deployments;
//     the no-TLS path is permitted only for loopback/demo tests.
//
// The destination side (acp-bootstrap daemon) is configured
// independently — see cmd/acp-bootstrap/config.go.
type CrossCloudConfig struct {
	// Enabled gates the entire cross-cloud subsystem. When false,
	// every other field is ignored and the daemon behaves exactly
	// as a Phase 1-3 build.
	Enabled bool `json:"enabled"`

	// PolicyVersion is the operator-supplied identifier for the
	// current allow-list snapshot, recorded verbatim in audit
	// payloads. Bump it when the allow-list changes so auditors can
	// correlate decisions to policy state. Required when Enabled.
	PolicyVersion string `json:"policy_version,omitempty"`

	// PolicyAllowListPath is the JSON file describing the
	// (Provider, Measurement) pairs the policy authorises.
	// File schema:
	//
	//   {
	//     "version": "xcc-2026-05-09",
	//     "allowed": {
	//       "aws-nitro":   ["<PCR0: 96 hex>", "<the next image's PCR0>"],
	//       "gcp-sev-snp": ["<launch measurement: 96 hex>"]
	//     }
	//   }
	//
	// Required when Enabled.
	PolicyAllowListPath string `json:"policy_allow_list_path,omitempty"`

	// VerifierRegistryPath is the JSON file describing the verifiers
	// to instantiate at startup, one per cross-cloud destination.
	// File schema:
	//
	//   {
	//     "verifiers": [
	//       {
	//         "provider": "aws-nitro",
	//         "expected_measurement_hex": "<PCR0: 96 hex>",
	//         "nitro": {"pcrs": {"1": "<96 hex>", "2": "<96 hex>"}}
	//       },
	//       {
	//         "provider": "gcp-sev-snp",
	//         "expected_measurement_hex": "<96 hex>",
	//         "amd_cert_chain_path": "/etc/vg/amd-milan-cert_chain.pem"
	//       }
	//     ]
	//   }
	//
	// Required when Enabled.
	VerifierRegistryPath string `json:"verifier_registry_path,omitempty"`

	// TransportBearerToken, if non-empty, is sent as
	// "Authorization: Bearer <token>" on every outbound handshake +
	// token request. Defence-in-depth alongside cryptographic
	// signatures; pair with mTLS in production.
	TransportBearerToken string `json:"transport_bearer_token,omitempty"`

	// RequestTimeoutSeconds caps each individual handshake / token
	// round trip. Zero defers to context cancellation (no per-request
	// timeout). Defaults to 30 when Enabled and unset.
	RequestTimeoutSeconds int `json:"request_timeout_seconds,omitempty"`

	// TransportTLS configures mTLS for the HTTPTransport's
	// http.Client. Strongly recommended for production.
	TransportTLS TLSClientConfig `json:"transport_tls,omitempty"`

	// AuditLogPath is the append-only audit log (a bbolt file) every
	// release decision is written to — handshake, attestation verified,
	// release authorised — before the step it records is taken. The log
	// is verified end to end when it is opened; a log that does not
	// verify stops all releases. Required when enabled. One
	// crosscloud-restore run holds its lock at a time.
	AuditLogPath string `json:"audit_log_path,omitempty"`

	// KeyEscrowPath is the release authority's escrow private key: the
	// file `sagvd escrow-provision` writes, sealed to this host's TEE and
	// opened in memory at start (ADR 0016). Under tee.insecure_simulation
	// a raw 32-byte key (acpctl escrow keygen, mode 0600) is accepted
	// too; on a hardware TEE it is refused. Sealers encapsulate genome
	// keys to its public half, which `sagvd identity` prints;
	// `crosscloud-restore -key-escrow` and `failover` open envelopes with
	// it only to release the key. Optional.
	KeyEscrowPath string `json:"key_escrow_path,omitempty"`

	// InsecureSimulatedDestinations must be true for the verifier
	// registry to hold a "simulated" entry. A simulated destination's
	// Evidence is signed by a key from a file, so releasing keys to it
	// proves the protocol and nothing about hardware; development and
	// tests only.
	InsecureSimulatedDestinations bool `json:"insecure_simulated_destinations,omitempty"`

	// OperatorStop is the operator's signed stop list (ADR 0010):
	// every release is checked against it, and without a valid one
	// nothing is released. Required when enabled.
	OperatorStop OperatorStopConfig `json:"operator_stop,omitempty"`
}

// OperatorStopConfig points at the operator's stop list and the public
// key it must verify under. The matching private key stays with the
// operator (`acpctl stop keygen`), never on this host.
type OperatorStopConfig struct {
	KeyID         string `json:"kid"`
	PublicKeyPath string `json:"public_key_path"`
	ListPath      string `json:"list_path"`
}

// TLSClientConfig holds the source-side outbound mTLS material the
// HTTPTransport uses to authenticate to destination acp-bootstrap
// servers. All file paths are resolved relative to the process
// working directory.
type TLSClientConfig struct {
	Enabled    bool   `json:"enabled"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	CABundle   string `json:"ca_bundle"`
	// ServerName is the name the destination's certificate carries, when
	// it is not the host of the endpoint URL — a destination reached by
	// IP whose certificate names it otherwise. Empty: the endpoint's host.
	ServerName string `json:"server_name,omitempty"`
}

// RequestTimeout returns CrossCloudConfig.RequestTimeoutSeconds as a
// Duration. Returns the documented default (30s) if unset.
func (c CrossCloudConfig) RequestTimeout() time.Duration {
	if c.RequestTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.RequestTimeoutSeconds) * time.Second
}

// DefaultConfig returns a Config populated with sensible defaults.
// Callers typically decode a JSON file over this so that operators
// only need to specify fields they want to override.
func DefaultConfig() Config {
	return Config{
		Vault: VaultConfig{
			ListenAddress: "127.0.0.1:9443",
			TLS: TLSConfig{
				Enabled: false,
			},
		},
		HTTPAPI: HTTPAPIConfig{
			ListenAddress: "127.0.0.1:9080",
		},
		TEE: TEEConfig{
			WorkloadDescriptor: "sagvd-authority-v1",
		},
		Runtime: RuntimeConfig{
			JobTimeoutSeconds:            120,
			HandshakeTimeoutSeconds:      10,
			QueuePollMs:                  250,
			HTTPReadHeaderTimeoutSeconds: 5,
			HTTPWriteTimeoutSeconds:      30,
			DefaultJobDeadlineSeconds:    60,
			MaxPayloadBytes:              4 * 1024 * 1024, // 4 MiB
		},
		Health: HealthConfig{
			ListenAddress: "127.0.0.1:9091",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
		Genome: GenomeConfig{
			// The tolerance the hardware drills declared in advance
			// (VERIFIABLE-CLAIMS C5): measured cross-hardware error is
			// ~50x inside it.
			Gate: GateConfig{Atol: 1e-2, Rtol: 1e-3},
		},
	}
}

// LoadConfigFile reads and decodes a JSON configuration file on top
// of DefaultConfig(). Unknown JSON fields are rejected to catch
// typos in operator config during provisioning.
func LoadConfigFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("sagvd: open config %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	c, err := DecodeConfig(f)
	if err != nil {
		return Config{}, err
	}
	if err := c.TEE.ResolveAuto(); err != nil {
		return Config{}, fmt.Errorf("sagvd: %w", err)
	}
	return c, nil
}

// DecodeConfig decodes JSON from r into a Config, applied on top of
// DefaultConfig. Rejects unknown fields.
func DecodeConfig(r io.Reader) (Config, error) {
	c := DefaultConfig()
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("sagvd: decode config: %w", err)
	}
	return c, nil
}

// ResolveSecrets loads secret values that the config references by
// path rather than inline. Call it after Validate(). Today that is the
// REST API bearer token (http_api.bearer_token_file): the file is read,
// surrounding whitespace trimmed, and the result must be non-empty — and
// at least MinNonLoopbackTokenLen characters when the REST API is
// reachable beyond the local host.
func (c *Config) ResolveSecrets() error {
	if c.HTTPAPI.BearerTokenFile == "" {
		return nil
	}
	// The file may be sealed to this host (`sagvd seal-keys`, ADR 0023).
	raw, err := readSecret(c.TEE, c.HTTPAPI.BearerTokenFile, 0, "http_api.bearer_token_file")
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return fmt.Errorf("sagvd: http_api.bearer_token_file %q is empty", c.HTTPAPI.BearerTokenFile)
	}
	if c.HTTPAPI.ListenAddress != "" && !exposure.IsLoopback(c.HTTPAPI.ListenAddress) &&
		len(token) < MinNonLoopbackTokenLen {
		return fmt.Errorf("sagvd: token in %q too short for non-loopback listen_address %q (need >= %d characters)",
			c.HTTPAPI.BearerTokenFile, c.HTTPAPI.ListenAddress, MinNonLoopbackTokenLen)
	}
	c.HTTPAPI.BearerToken = token
	return nil
}

// Validate performs structural checks that do not require filesystem
// access. Returns a joined error listing every problem so operators
// see the full punch-list in one run.
func (c Config) Validate() error {
	var errs []error

	if _, err := c.Crypto.Policy(); err != nil {
		errs = append(errs, fmt.Errorf("crypto: %w", err))
	}
	// The signing keys must be of the suite the profile signs with: the
	// key material and the configuration's intent agree, or the daemon
	// does not start (ADR 0031).
	if sigPol, err := c.Crypto.SignaturePolicy(); err != nil {
		errs = append(errs, fmt.Errorf("crypto: %w", err))
	} else {
		if suite, err := c.Keys.AuthoritySigning.signatureSuite(); err == nil {
			if err := sigPol.CheckSigningKey("keys.authority_signing", suite); err != nil {
				errs = append(errs, err)
			}
		}
		if c.Keys.AuditSigning.KeyID != "" || c.Keys.AuditSigning.SeedPath != "" {
			if suite, err := c.Keys.AuditSigning.signatureSuite(); err == nil {
				if err := sigPol.CheckSigningKey("keys.audit_signing", suite); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	if strings.TrimSpace(c.Vault.ListenAddress) == "" {
		errs = append(errs, errors.New("vault.listen_address required"))
	} else if _, _, err := net.SplitHostPort(c.Vault.ListenAddress); err != nil {
		errs = append(errs, fmt.Errorf("vault.listen_address invalid: %w", err))
	}

	if c.Vault.TLS.Enabled {
		if c.Vault.TLS.ServerCert == "" {
			errs = append(errs, errors.New("vault.tls.server_cert required when TLS enabled"))
		}
		if c.Vault.TLS.ServerKey == "" {
			errs = append(errs, errors.New("vault.tls.server_key required when TLS enabled"))
		}
		if c.Vault.TLS.ClientCAs == "" {
			errs = append(errs, errors.New("vault.tls.client_cas required when TLS enabled"))
		}
	} else if _, _, err := net.SplitHostPort(c.Vault.ListenAddress); err == nil &&
		!exposure.IsLoopback(c.Vault.ListenAddress) {
		// Fail closed: a Return Path listener reachable from the
		// network must authenticate workers with mTLS.
		errs = append(errs, fmt.Errorf(
			"vault.tls.enabled required: listen_address %q is not loopback (workers across a network must use mTLS)",
			c.Vault.ListenAddress))
	}

	// http_api.listen_address is optional (empty → disabled); when
	// present it must parse as host:port.
	if c.HTTPAPI.BearerToken != "" && c.HTTPAPI.BearerTokenFile != "" {
		errs = append(errs, errors.New("http_api: set only one of bearer_token and bearer_token_file"))
	}
	if c.HTTPAPI.ListenAddress != "" {
		if _, _, err := net.SplitHostPort(c.HTTPAPI.ListenAddress); err != nil {
			errs = append(errs, fmt.Errorf("http_api.listen_address invalid: %w", err))
		} else if !exposure.IsLoopback(c.HTTPAPI.ListenAddress) {
			// Fail closed: an operator REST API reachable from the
			// network must require a bearer token.
			switch {
			case c.HTTPAPI.BearerToken == "" && c.HTTPAPI.BearerTokenFile == "":
				errs = append(errs, fmt.Errorf(
					"http_api.bearer_token or bearer_token_file required: listen_address %q is not loopback",
					c.HTTPAPI.ListenAddress))
			case c.HTTPAPI.BearerToken != "" && len(c.HTTPAPI.BearerToken) < MinNonLoopbackTokenLen:
				errs = append(errs, fmt.Errorf(
					"http_api.bearer_token too short for non-loopback listen_address %q (need >= %d characters)",
					c.HTTPAPI.ListenAddress, MinNonLoopbackTokenLen))
			}
		}
	}

	if strings.TrimSpace(c.TEE.WorkloadDescriptor) == "" {
		errs = append(errs, errors.New("tee.workload_descriptor required"))
	}
	errs = append(errs, validateTEE(c.TEE)...)

	if c.Keys.AuthoritySigning.KeyID == "" {
		errs = append(errs, errors.New("keys.authority_signing.kid required"))
	}
	if c.Keys.AuthoritySigning.SeedPath == "" {
		errs = append(errs, errors.New("keys.authority_signing.seed_path required"))
	}
	if _, err := c.Keys.AuthoritySigning.signatureSuite(); err != nil {
		errs = append(errs, fmt.Errorf("keys.authority_signing.suite: %w", err))
	}
	if _, err := c.Keys.AuditSigning.signatureSuite(); err != nil {
		errs = append(errs, fmt.Errorf("keys.audit_signing.suite: %w", err))
	}
	if c.Keys.SessionSealing.KeyID == "" {
		errs = append(errs, errors.New("keys.session_sealing.kid required"))
	}
	if c.Keys.SessionSealing.MaterialPath == "" {
		errs = append(errs, errors.New("keys.session_sealing.material_path required"))
	}

	if c.Workers.RegistryPath == "" {
		errs = append(errs, errors.New("workers.registry_path required"))
	}

	if c.Runtime.JobTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.job_timeout_seconds must be > 0"))
	}
	if c.Runtime.HandshakeTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.handshake_timeout_seconds must be > 0"))
	}
	if c.Runtime.QueuePollMs <= 0 {
		errs = append(errs, errors.New("runtime.queue_poll_ms must be > 0"))
	}
	if c.Runtime.HTTPReadHeaderTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.http_read_header_timeout_seconds must be > 0"))
	}
	if c.Runtime.HTTPWriteTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.http_write_timeout_seconds must be > 0"))
	}
	if c.Runtime.DefaultJobDeadlineSeconds <= 0 {
		errs = append(errs, errors.New("runtime.default_job_deadline_seconds must be > 0"))
	}
	if c.Runtime.MaxPayloadBytes == 0 {
		errs = append(errs, errors.New("runtime.max_payload_bytes must be > 0"))
	}
	if c.Runtime.MaxSessions < 0 {
		errs = append(errs, errors.New("runtime.max_sessions must be >= 0 (0 = one session at a time)"))
	}

	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level %q invalid (want debug|info|warn|error)", c.Log.Level))
	}
	switch strings.ToLower(c.Log.Format) {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("log.format %q invalid (want json|text)", c.Log.Format))
	}

	if g := c.Genome.Gate; g.Atol < 0 || g.Rtol < 0 {
		errs = append(errs, errors.New("genome.gate.atol and rtol must be >= 0"))
	}
	if c.Genome.Gate.MaxNonCriticalOutliers < 0 {
		errs = append(errs, errors.New("genome.gate.max_non_critical_outliers must be >= 0"))
	}
	if b := c.Genome.Gate.Bfloat16; b != nil && (b.Atol < 0 || b.Rtol < 0) {
		errs = append(errs, errors.New("genome.gate.bfloat16.atol and rtol must be >= 0"))
	}
	if c.Genome.BundleDir != "" && !filepath.IsAbs(c.Genome.BundleDir) {
		errs = append(errs, fmt.Errorf("genome.bundle_dir %q must be an absolute path", c.Genome.BundleDir))
	}
	if c.Genome.Enabled() && c.Audit.LogPath == "" {
		errs = append(errs, errors.New("audit.log_path required when genome.bundle_dir is set: a gate job is a decision, and no decision is taken off the record"))
	}
	if c.OperatorStopEnabled() {
		if s := c.OperatorStop; s.KeyID == "" || s.PublicKeyPath == "" || s.ListPath == "" {
			errs = append(errs, errors.New("operator_stop.kid, public_key_path and list_path are all required when any is set"))
		}
	}
	if c.Runtime.EvidenceMaxAgeSeconds < 0 {
		errs = append(errs, errors.New("runtime.evidence_max_age_seconds must be >= 0 (0 = the attestation default)"))
	}
	if c.Audit.LogPath != "" {
		if c.Keys.AuditSigning.KeyID == "" || c.Keys.AuditSigning.SeedPath == "" {
			errs = append(errs, errors.New("keys.audit_signing.kid and seed_path required when audit.log_path is set"))
		}
		if c.CrossCloud.AuditLogPath != "" && filepath.Clean(c.CrossCloud.AuditLogPath) == filepath.Clean(c.Audit.LogPath) {
			errs = append(errs, errors.New("audit.log_path and crosscloud.audit_log_path must be different files: the daemon holds its log open, and one process holds a log at a time"))
		}
		if c.Audit.SegmentEvents < 0 || c.Audit.SegmentEvents == 1 {
			errs = append(errs, errors.New("audit.segment_events must be 0 (never close a segment by count) or at least 2"))
		}
		if c.Audit.SegmentMaxAgeSeconds < 0 {
			errs = append(errs, errors.New("audit.segment_max_age_seconds must be >= 0 (0 = never close a segment by age)"))
		}
		if c.Audit.ArchiveDir != "" && !filepath.IsAbs(c.Audit.ArchiveDir) {
			errs = append(errs, fmt.Errorf("audit.archive_dir %q must be an absolute path", c.Audit.ArchiveDir))
		}
	} else if c.Audit.Rotates() || c.Audit.ArchiveDir != "" {
		errs = append(errs, errors.New("audit.segment_events, audit.segment_max_age_seconds and audit.archive_dir need audit.log_path"))
	}

	if c.Queue.Path != "" {
		if c.Audit.LogPath != "" && filepath.Clean(c.Queue.Path) == filepath.Clean(c.Audit.LogPath) {
			errs = append(errs, errors.New("queue.path and audit.log_path must be different files: each is a bbolt file the daemon holds open"))
		}
		if c.CrossCloud.AuditLogPath != "" && filepath.Clean(c.Queue.Path) == filepath.Clean(c.CrossCloud.AuditLogPath) {
			errs = append(errs, errors.New("queue.path and crosscloud.audit_log_path must be different files"))
		}
	}
	if c.Queue.MaxResumeAttempts < 0 {
		errs = append(errs, errors.New("queue.max_resume_attempts must be >= 0 (0 = the default of 3)"))
	}
	if c.Queue.RetainFinishedSeconds < 0 {
		errs = append(errs, errors.New("queue.retain_finished_seconds must be >= 0 (0 = keep every finished job)"))
	}
	if c.Queue.RetainFinishedSeconds > 0 && c.Queue.Path == "" {
		errs = append(errs, errors.New("queue.retain_finished_seconds needs queue.path: a queue in memory has nothing on disk to expire"))
	}

	// CrossCloud is opt-in; only validate fields when enabled.
	if c.CrossCloud.Enabled {
		if strings.TrimSpace(c.CrossCloud.PolicyVersion) == "" {
			errs = append(errs, errors.New("crosscloud.policy_version required when crosscloud.enabled=true"))
		}
		if c.CrossCloud.PolicyAllowListPath == "" {
			errs = append(errs, errors.New("crosscloud.policy_allow_list_path required when crosscloud.enabled=true"))
		}
		if c.CrossCloud.VerifierRegistryPath == "" {
			errs = append(errs, errors.New("crosscloud.verifier_registry_path required when crosscloud.enabled=true"))
		}
		if c.CrossCloud.AuditLogPath == "" {
			errs = append(errs, errors.New("crosscloud.audit_log_path required when crosscloud.enabled=true (no key is released without a durable audit record)"))
		}
		if c.Keys.AuditSigning.KeyID == "" || c.Keys.AuditSigning.SeedPath == "" {
			errs = append(errs, errors.New("keys.audit_signing.kid and seed_path required when crosscloud.enabled=true"))
		}
		if s := c.CrossCloud.OperatorStop; s.KeyID == "" || s.PublicKeyPath == "" || s.ListPath == "" {
			errs = append(errs, errors.New("crosscloud.operator_stop.kid, public_key_path and list_path required when crosscloud.enabled=true (the operator must be able to stop every release)"))
		}
		if c.CrossCloud.RequestTimeoutSeconds < 0 {
			errs = append(errs, errors.New("crosscloud.request_timeout_seconds must be >= 0 (0 = no per-request timeout)"))
		}
		if c.CrossCloud.TransportTLS.Enabled {
			if c.CrossCloud.TransportTLS.ClientCert == "" {
				errs = append(errs, errors.New("crosscloud.transport_tls.client_cert required when transport_tls.enabled=true"))
			}
			if c.CrossCloud.TransportTLS.ClientKey == "" {
				errs = append(errs, errors.New("crosscloud.transport_tls.client_key required when transport_tls.enabled=true"))
			}
			if c.CrossCloud.TransportTLS.CABundle == "" {
				errs = append(errs, errors.New("crosscloud.transport_tls.ca_bundle required when transport_tls.enabled=true"))
			}
		}
	}

	return errors.Join(errs...)
}
