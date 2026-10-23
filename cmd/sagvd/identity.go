// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// authorityIdentity is what other hosts pin for this authority: the
// signing key a cross-cloud destination verifies every handshake and
// key-release token against, and this vault's TEE identity for the
// workers' pins.
type authorityIdentity struct {
	AuthorityKID            string `json:"authority_kid"`
	AuthorityPublicKeyPEM   string `json:"authority_public_key_pem"`
	AuthoritySignatureSuite string `json:"authority_signature_suite"`
	// TEEProvider names what attests for this vault on the Return Path:
	// gcp-sev-snp (the measurement is the chip's launch measurement, 48
	// bytes) or simulated (the key below signs).
	TEEProvider       string `json:"tee_provider"`
	TEEMeasurementHex string `json:"tee_measurement_hex"`
	TEEPublicKeyPEM   string `json:"tee_public_key_pem,omitempty"`
	// Sealer is how this host seals its key files (tee.sealer, ADR 0025):
	// sev-snp-derived-key, tpm2 or simulated.
	Sealer string `json:"sealer,omitempty"`
	// TDX is what a gcp-tdx measurement is made of.
	TDX *tdxIdentity `json:"tdx,omitempty"`
	// VTPM is what an azure-cgpu guest's vTPM measured of its boot.
	VTPM *vtpmIdentity `json:"vtpm,omitempty"`
	// SEVSNPPolicy is what a SEV-SNP peer's report is held to (ADR 0033).
	SEVSNPPolicy *tee.SEVSNPPolicySummary `json:"sev_snp_policy,omitempty"`
	// The key auditors verify the cross-cloud audit log with, when
	// keys.audit_signing is configured.
	AuditKID            string `json:"audit_kid,omitempty"`
	AuditPublicKeyPEM   string `json:"audit_public_key_pem,omitempty"`
	AuditSignatureSuite string `json:"audit_signature_suite,omitempty"`
	// The key sealers encapsulate genome keys to (acpctl genome seal
	// --escrow-to), when crosscloud.key_escrow_path is configured.
	KeyEscrowTag          string `json:"key_escrow_tag,omitempty"`
	KeyEscrowPublicKeyPEM string `json:"key_escrow_public_key_pem,omitempty"`
	// KeyEscrowStorage says how the private half is kept on this host:
	// "sealed:<tee>" (sagvd escrow-provision, ADR 0016) or "plaintext"
	// (simulation only). KeyEscrowSuite is the key's KEM suite (ADR 0029).
	KeyEscrowStorage string `json:"key_escrow_storage,omitempty"`
	KeyEscrowSuite   string `json:"key_escrow_suite,omitempty"`
	// The policy every gate-job session is pinned to, and the policy
	// profiles Trust Admission serves (ADR 0015), when gate jobs are
	// enabled.
	PolicyVersion  string   `json:"policy_version,omitempty"`
	PolicyProfiles []string `json:"policy_profiles,omitempty"`
	// CryptoProfile and KEMSuites are the cryptographic profile (ADR
	// 0029): the suite this authority encapsulates under first, and
	// every suite it accepts a destination's answer under.
	CryptoProfile string   `json:"crypto_profile"`
	KEMSuites     []string `json:"kem_suites"`
	// SignatureSuite is the suite this daemon signs with and
	// SignatureSuites the suites it accepts a signature under (ADR 0031).
	SignatureSuite  string   `json:"signature_suite"`
	SignatureSuites []string `json:"signature_suites"`
	// FIPS140 is the cryptographic module this process runs on (ADR 0030):
	// enabled, enforced (fips140=only), the module version, the build setting.
	FIPS140 crypto.FIPS140 `json:"fips140"`
}

// runIdentityCmd implements `sagvd identity -config <path>`: it loads the
// configured key material and prints the public half as JSON, without
// opening any listener.
func runIdentityCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("sagvd identity", flag.ContinueOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to sagvd JSON config (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("identity: -config required")
	}
	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("identity: config validation: %w", err)
	}
	// Identity prints public halves only: the materials are loaded
	// without the escrow key, so no TEE unseal happens here.
	public := cfg
	public.Genome.KeyEscrowPath, public.CrossCloud.KeyEscrowPath = "", ""
	mat, err := LoadMaterials(public, shared_time.NewSystemClock())
	if err != nil {
		return err
	}
	defer func() { mat.Store.Zeroize(); _ = mat.Close() }()

	authPEM, err := crypto.PublicKeyPEMSuite(mat.AuthoritySigningSuite, mat.AuthoritySigningPublicKey)
	if err != nil {
		return err
	}
	suites, err := cfg.Crypto.Policy()
	if err != nil {
		return fmt.Errorf("crypto: %w", err)
	}
	sigPol, err := cfg.Crypto.SignaturePolicy()
	if err != nil {
		return fmt.Errorf("crypto: %w", err)
	}
	id := authorityIdentity{
		SignatureSuite:          string(sigPol.SignsWith()),
		SignatureSuites:         sigPol.AcceptIDs(),
		AuthorityKID:            string(mat.AuthoritySigningKeyID),
		AuthorityPublicKeyPEM:   string(authPEM),
		AuthoritySignatureSuite: string(mat.AuthoritySigningSuite),
		TEEProvider:             string(mat.Provider),
		CryptoProfile:           string(suites.Profile()),
		FIPS140:                 crypto.FIPSStatus(),
		KEMSuites:               suites.SuiteIDs(),
		TEEMeasurementHex:       hex.EncodeToString(mat.Producer.Measurement()),
	}
	if kind, err := mat.SealerKind(); err == nil {
		id.Sealer = string(kind)
	}
	if sim, ok := mat.Producer.(*tee.Simulated); ok {
		teePEM, err := crypto.PublicKeyPEM(sim.PublicKey())
		if err != nil {
			return err
		}
		id.TEEPublicKeyPEM = string(teePEM)
	}
	id.TDX = tdxIdentityOf(mat.Producer)
	id.VTPM = vtpmIdentityOf(mat.Producer)
	id.SEVSNPPolicy = sevSNPPolicyIdentity(cfg.TEE.Peer.Provider, cfg.TEE.Peer.SEVSNP)
	if a := cfg.Keys.AuditSigning; a.KeyID != "" && a.SeedPath != "" {
		auditKey, err := loadSigningKey(cfg.TEE, a, "keys.audit_signing")
		if err != nil {
			return err
		}
		auditPEM, err := auditKey.Public().PEM()
		auditSuite := auditKey.Suite()
		auditKey.Zeroize()
		if err != nil {
			return err
		}
		id.AuditKID, id.AuditPublicKeyPEM, id.AuditSignatureSuite = a.KeyID, string(auditPEM), string(auditSuite)
	}
	if p := cfg.EscrowKeyPath(); p != "" {
		// The public half is read from the file itself: a sealed key
		// carries it in the clear, so identity never unseals anything.
		pub, storage, err := escrowPublicFromFile(p)
		if err != nil {
			return fmt.Errorf("identity: key_escrow_path: %w", err)
		}
		pemBytes, err := escrow.PublicPEM(pub)
		if err != nil {
			return err
		}
		id.KeyEscrowTag, id.KeyEscrowPublicKeyPEM, id.KeyEscrowStorage = escrow.KeyTag(pub), string(pemBytes), storage
		id.KeyEscrowSuite = string(pub.Suite())
	}
	if cfg.Genome.Enabled() {
		id.PolicyVersion, id.PolicyProfiles = cfg.PolicyVersion(), []string{PolicyProfileGate}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(id)
}

// tdxIdentity is what a TDX guest's measurement is made of: MRTD and the
// four RTMRs, hashed together (SHA-384) into the measurement above.
type tdxIdentity struct {
	MRTDHex string   `json:"mrtd_hex"`
	RTMRHex []string `json:"rtmr_hex"`
}

func tdxIdentityOf(p tee.Producer) *tdxIdentity {
	t, ok := p.(*tee.GCPTDXProducer)
	if !ok {
		return nil
	}
	mrtd := t.MRTD()
	rtmr := t.RTMRs()
	out := &tdxIdentity{MRTDHex: hex.EncodeToString(mrtd[:])}
	for i := range rtmr {
		out.RTMRHex = append(out.RTMRHex, hex.EncodeToString(rtmr[i][:]))
	}
	return out
}

// vtpmIdentity is what an Azure guest's vTPM (azure-cgpu, azure-sev-snp)
// measured of its boot: the PCRs quoted and their digest, which a peer may
// pin (pcr_digests).
type vtpmIdentity struct {
	PCRs         []string `json:"pcrs"`
	PCRDigestHex string   `json:"pcr_digest_hex"`
}

func vtpmIdentityOf(p tee.Producer) *vtpmIdentity {
	pcrs, digest, ok := tee.VTPMBootOf(p)
	if !ok {
		return nil
	}
	return &vtpmIdentity{PCRs: pcrs, PCRDigestHex: hex.EncodeToString(digest)}
}

// sevSNPPolicyIdentity is the policy a SEV-SNP peer's report is held to,
// for identity; nil for a peer of another family or a policy that does
// not load (validation reports that).
func sevSNPPolicyIdentity(peer string, c *tee.SEVSNPPolicyConfig) *tee.SEVSNPPolicySummary {
	p, err := tee.ParseProvider(peer)
	if err != nil || (p != tee.ProviderGCPSEVSNP && p != tee.ProviderAzureSEVSNP && p != tee.ProviderAzureCGPU) {
		return nil
	}
	pol, err := c.Policy()
	if err != nil {
		return nil
	}
	s := pol.Summary()
	return &s
}
