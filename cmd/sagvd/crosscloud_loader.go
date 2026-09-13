// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ai-continuity-platform/core/internal/audit/chain"
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
	"github.com/ai-continuity-platform/core/internal/vault/kms"
)

// CrossCloudAuditSigningKeyID is the kid under which the cross-cloud
// audit-signing key is registered inside crossCloudMaterials. The
// audit-signing key is private to the cross-cloud subsystem and is
// regenerated at every daemon restart for the Phase 4 MVP — chain
// continuity across restart is a Phase 5 enhancement.
const CrossCloudAuditSigningKeyID ids.KeyID = "xcc-audit-1"

// crossCloudMaterials bundles every Phase 4 cross-cloud dependency
// the daemon assembles at startup. Constructed by
// LoadCrossCloudMaterials when CrossCloud.Enabled is true; nil
// otherwise.
//
// The Coordinator itself is NOT part of this bundle — it is wired
// into the Daemon at the call site (daemon.go) because it needs the
// Daemon's source-authority Signer (already loaded by LoadMaterials)
// alongside the cross-cloud-private dependencies bundled here.
type crossCloudMaterials struct {
	// VerifierRegistry holds one tee.Verifier per cross-cloud
	// destination this authority may release keys to.
	VerifierRegistry *tee.Registry

	// Policy is the loaded KeyReleasePolicy (allow-list MVP).
	Policy *kms.AllowListPolicy

	// Transport is the HTTPTransport configured against
	// CrossCloud.TransportTLS / TransportBearerToken /
	// RequestTimeoutSeconds. Used by the Coordinator to dispatch
	// handshakes and tokens to destination acp-bootstrap endpoints.
	Transport *kms.HTTPTransport

	// AuditChain is the in-process audit chain (in-memory for Phase 4
	// MVP) into which the Coordinator's chainAuditEmitter appends.
	// The chain is signed under AuditStore + CrossCloudAuditSigningKeyID,
	// keys.PurposeSigningAudit.
	AuditChain chain.Chain

	// AuditEmitter is the kms.AuditEmitter implementation the
	// Coordinator uses. Wraps AuditChain + AuditStore + signing kid.
	AuditEmitter kms.AuditEmitter

	// auditStore holds the audit-signing key. Kept private so the
	// daemon doesn't accidentally use it for non-audit signing.
	auditStore *keys.InMemoryStore

	// IDGenerator produces fresh RequestID / DecisionID per
	// cross-cloud invocation, backed by crypto/rand.
	IDGenerator kms.IDGenerator

	// NonceSource produces fresh handshake nonces for the
	// Coordinator, backed by crypto/rand.
	NonceSource kms.NonceSource
}

// verifierRegistryFile is the on-disk JSON schema for
// CrossCloud.VerifierRegistryPath.
type verifierRegistryFile struct {
	Verifiers []verifierEntry `json:"verifiers"`
}

type verifierEntry struct {
	Provider               string `json:"provider"`
	AttestorPubKeyPath     string `json:"attestor_pubkey_path"`
	ExpectedMeasurementHex string `json:"expected_measurement_hex"`
}

// allowListFile is the on-disk JSON schema for
// CrossCloud.PolicyAllowListPath.
type allowListFile struct {
	Version string              `json:"version"`
	Allowed map[string][]string `json:"allowed"`
}

// LoadCrossCloudMaterials reads the cross-cloud configuration from
// disk, builds the audit chain + emitter, and returns a fully-wired
// bundle. Returns nil, nil when CrossCloud.Enabled is false.
//
// File formats (all JSON):
//
//   - VerifierRegistryPath: see verifierRegistryFile schema.
//     Each entry's attestor_pubkey is loaded as either:
//
//   - a raw 32-byte file (Ed25519 public key), or
//
//   - a PEM-encoded SubjectPublicKeyInfo.
//     The format is auto-detected by checking the file's leading
//     bytes (the BEGIN PEM marker signals PEM; anything else is
//     treated as raw bytes).
//
//   - PolicyAllowListPath: see allowListFile schema. The version
//     in the file MUST equal CrossCloud.PolicyVersion to defend
//     against operator-mismatch (loading an old allow-list under
//     a new version label).
//
// Returns Structural errors for missing/malformed inputs.
func LoadCrossCloudMaterials(cfg Config, clock shared_time.Clock) (*crossCloudMaterials, error) {
	if !cfg.CrossCloud.Enabled {
		return nil, nil
	}
	if clock == nil {
		return nil, fmt.Errorf("sagvd: LoadCrossCloudMaterials: clock required when crosscloud.enabled=true")
	}

	registry, err := loadVerifierRegistry(cfg.CrossCloud.VerifierRegistryPath)
	if err != nil {
		return nil, err
	}

	policy, err := loadAllowListPolicy(cfg.CrossCloud.PolicyVersion, cfg.CrossCloud.PolicyAllowListPath)
	if err != nil {
		return nil, err
	}

	transport, err := buildHTTPTransport(cfg.CrossCloud)
	if err != nil {
		return nil, err
	}

	// Build audit chain + dedicated audit-signing keystore. The audit
	// signing key is generated fresh at every daemon startup; chain
	// continuity across restart is a Phase 5 enhancement.
	auditStore := keys.NewInMemoryStore(clock)
	if _, err := auditStore.GenerateSigning(CrossCloudAuditSigningKeyID, keys.PurposeSigningAudit); err != nil {
		return nil, fmt.Errorf("sagvd: generate cross-cloud audit signing key: %w", err)
	}
	auditChain := chain.NewInMemoryChain()
	emitter, err := newChainAuditEmitter(
		auditChain,
		auditStore,
		CrossCloudAuditSigningKeyID,
		clock,
		"xcc-evt-",
	)
	if err != nil {
		return nil, fmt.Errorf("sagvd: build cross-cloud audit emitter: %w", err)
	}

	return &crossCloudMaterials{
		VerifierRegistry: registry,
		Policy:           policy,
		Transport:        transport,
		AuditChain:       auditChain,
		AuditEmitter:     emitter,
		auditStore:       auditStore,
		IDGenerator:      newCryptoRandIDGenerator("xcc-req-", "xcc-dec-"),
		NonceSource:      freshNonceSource(),
	}, nil
}

// loadVerifierRegistry reads the JSON file at path and constructs a
// tee.Registry with one Verifier per entry.
func loadVerifierRegistry(path string) (*tee.Registry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sagvd: read verifier_registry_path %q: %w", path, err)
	}
	var file verifierRegistryFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("sagvd: decode verifier_registry_path %q: %w", path, err)
	}
	if len(file.Verifiers) == 0 {
		return nil, fmt.Errorf("sagvd: verifier_registry_path %q: at least one verifier entry required", path)
	}
	specs := make([]tee.RegistrySpec, 0, len(file.Verifiers))
	for i, e := range file.Verifiers {
		provider, err := tee.ParseProvider(e.Provider)
		if err != nil {
			return nil, fmt.Errorf("sagvd: verifier_registry[%d].provider %q invalid: %w", i, e.Provider, err)
		}
		measurementBytes, err := hex.DecodeString(e.ExpectedMeasurementHex)
		if err != nil {
			return nil, fmt.Errorf("sagvd: verifier_registry[%d].expected_measurement_hex: %w", i, err)
		}
		measurement, err := tee.MeasurementFromBytes(measurementBytes)
		if err != nil {
			return nil, fmt.Errorf("sagvd: verifier_registry[%d].expected_measurement_hex must be 32 bytes (64 hex chars): %w", i, err)
		}
		pub, err := loadAttestorPubKey(e.AttestorPubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("sagvd: verifier_registry[%d].attestor_pubkey_path %q: %w", i, e.AttestorPubKeyPath, err)
		}
		specs = append(specs, tee.RegistrySpec{
			Provider: provider,
			Spec: tee.VerifierSpec{
				Provider:            provider,
				AttestorPubKey:      pub,
				ExpectedMeasurement: measurement,
			},
		})
	}
	return tee.NewRegistry(specs)
}

// loadAttestorPubKey reads a public key from disk, accepting either a
// raw 32-byte Ed25519 key or a PEM-encoded SubjectPublicKeyInfo.
func loadAttestorPubKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// PEM-encoded SubjectPublicKeyInfo path.
	if strings.Contains(string(data), "-----BEGIN") {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("attestor_pubkey: invalid PEM")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("attestor_pubkey: parse PKIX: %w", err)
		}
		ed, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("attestor_pubkey: PEM key is %T, want ed25519.PublicKey", key)
		}
		return crypto.PublicKey(ed), nil
	}
	// Raw 32-byte path.
	if len(data) != crypto.Ed25519PublicKeySize {
		return nil, fmt.Errorf("attestor_pubkey: file %d bytes, want %d (raw Ed25519) or PEM-encoded", len(data), crypto.Ed25519PublicKeySize)
	}
	return crypto.PublicKey(data), nil
}

// loadAllowListPolicy parses the JSON allow-list file and constructs
// a kms.AllowListPolicy. The file's version field MUST equal the
// configured policyVersion — a mismatch signals operator drift and is
// rejected before any restore can run.
func loadAllowListPolicy(policyVersion, path string) (*kms.AllowListPolicy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sagvd: read policy_allow_list_path %q: %w", path, err)
	}
	var file allowListFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("sagvd: decode policy_allow_list_path %q: %w", path, err)
	}
	if file.Version != policyVersion {
		return nil, fmt.Errorf("sagvd: policy_allow_list_path %q version %q does not match crosscloud.policy_version %q (operator drift; refusing to load)",
			path, file.Version, policyVersion)
	}
	allowed := make(map[tee.Provider][][]byte, len(file.Allowed))
	for providerStr, hexList := range file.Allowed {
		provider, err := tee.ParseProvider(providerStr)
		if err != nil {
			return nil, fmt.Errorf("sagvd: policy_allow_list_path %q: provider %q invalid: %w", path, providerStr, err)
		}
		out := make([][]byte, 0, len(hexList))
		for i, h := range hexList {
			b, err := hex.DecodeString(h)
			if err != nil {
				return nil, fmt.Errorf("sagvd: policy_allow_list_path %q: %s[%d] hex decode: %w", path, providerStr, i, err)
			}
			if len(b) != crypto.HashSize {
				return nil, fmt.Errorf("sagvd: policy_allow_list_path %q: %s[%d] must be 32 bytes (64 hex chars); got %d", path, providerStr, i, len(b))
			}
			out = append(out, b)
		}
		allowed[provider] = out
	}
	return kms.NewAllowListPolicy(policyVersion, allowed)
}

// buildHTTPTransport constructs a kms.HTTPTransport configured with
// (optional) mTLS and Bearer auth.
func buildHTTPTransport(cfg CrossCloudConfig) (*kms.HTTPTransport, error) {
	httpClient := &http.Client{}
	if cfg.TransportTLS.Enabled {
		tlsConfig, err := buildClientTLSConfig(cfg.TransportTLS)
		if err != nil {
			return nil, err
		}
		httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
	httpClient.Timeout = cfg.RequestTimeout() + 5*time.Second // outer ceiling > per-request timeout
	return kms.NewHTTPTransport(kms.HTTPTransportConfig{
		HTTPClient:     httpClient,
		BearerToken:    cfg.TransportBearerToken,
		RequestTimeout: cfg.RequestTimeout(),
	}), nil
}

// buildClientTLSConfig assembles a *tls.Config from the operator-
// supplied client certificate, key, and CA bundle.
func buildClientTLSConfig(cfg TLSClientConfig) (*tls.Config, error) {
	clientCert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("sagvd: load mTLS client cert/key: %w", err)
	}
	caRaw, err := os.ReadFile(cfg.CABundle)
	if err != nil {
		return nil, fmt.Errorf("sagvd: read mTLS ca_bundle %q: %w", cfg.CABundle, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caRaw) {
		return nil, fmt.Errorf("sagvd: ca_bundle %q contained no valid PEM certificates", cfg.CABundle)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
