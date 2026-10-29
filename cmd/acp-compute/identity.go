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

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// workerIdentity is what sagvd pins for this worker: the key it signs
// every CandidateOutputFrame with (workers.registry_path), and the TEE
// identity its Return Path Evidence must carry (tee.peer).
type workerIdentity struct {
	SigningKID            string `json:"signing_kid"`
	SigningPublicKeyHex   string `json:"signing_public_key_hex"`
	SigningPublicKeyPEM   string `json:"signing_public_key_pem"`
	SigningSignatureSuite string `json:"signing_signature_suite"`
	// TEEProvider names what attests for this worker: gcp-sev-snp (the
	// measurement is the chip's launch measurement, 48 bytes) or
	// simulated (the key below signs).
	TEEProvider       string `json:"tee_provider"`
	TEEMeasurementHex string `json:"tee_measurement_hex"`
	TEEPublicKeyPEM   string `json:"tee_public_key_pem,omitempty"`
	// Sealer is how this host seals its key files (tee.sealer, ADR 0025).
	Sealer string `json:"sealer,omitempty"`
	// FIPS140 is the cryptographic module this process runs on (ADR 0030).
	FIPS140 crypto.FIPS140 `json:"fips140"`
	// TDX is what a gcp-tdx measurement is made of.
	TDX *tdxIdentity `json:"tdx,omitempty"`
	// VTPM is what an azure-cgpu guest's vTPM measured of its boot.
	VTPM *vtpmIdentity `json:"vtpm,omitempty"`
	// AWSSEVSNP is what an EC2 SEV-SNP guest's VLEK says (ADR 0038).
	AWSSEVSNP *awsSEVSNPIdentity `json:"aws_sev_snp,omitempty"`
	// SEVSNPPolicy is what the vault's SEV-SNP report is held to (ADR 0033).
	SEVSNPPolicy *tee.SEVSNPPolicySummary `json:"sev_snp_policy,omitempty"`
}

// runIdentityCmd implements `acp-compute identity -config <path>`: it
// loads the configured key material and prints the public half as JSON,
// without dialling anything.
func runIdentityCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("acp-compute identity", flag.ContinueOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to acp-compute JSON config (required)")
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
	mat, err := LoadMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		return err
	}
	defer mat.Store.Zeroize()

	signPEM, err := crypto.PublicKeyPEMSuite(mat.SigningSuite, mat.SigningPublicKey)
	if err != nil {
		return err
	}
	id := workerIdentity{
		SigningKID:            string(mat.SigningKeyID),
		SigningPublicKeyHex:   hex.EncodeToString(mat.SigningPublicKey),
		SigningPublicKeyPEM:   string(signPEM),
		SigningSignatureSuite: string(mat.SigningSuite),
		TEEProvider:           string(mat.Provider),
		TEEMeasurementHex:     hex.EncodeToString(mat.Producer.Measurement()),
	}
	id.FIPS140 = crypto.FIPSStatus()
	if kind, err := tee.SealerKindFor(mat.Producer, cfg.TEE.SealerMode()); err == nil {
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
	id.AWSSEVSNP = awsSEVSNPIdentityOf(mat.Producer)
	id.SEVSNPPolicy = sevSNPPolicyIdentity(cfg.TEE.Peer.Provider, cfg.TEE.Peer.SEVSNP, cfg.TEE.Peer.CSPIDs)
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

// sevSNPPolicyIdentity is the policy the vault's SEV-SNP report is held
// to, for identity; nil for a vault of another family.
func sevSNPPolicyIdentity(peer string, c *tee.SEVSNPPolicyConfig, cspIDs []string) *tee.SEVSNPPolicySummary {
	p, err := tee.ParseProvider(peer)
	if err != nil || (p != tee.ProviderGCPSEVSNP && p != tee.ProviderGCPSEVSNPVTPM && p != tee.ProviderAzureSEVSNP && p != tee.ProviderAzureCGPU && p != tee.ProviderAWSSEVSNP) {
		return nil
	}
	pol, err := c.Policy()
	if err != nil {
		return nil
	}
	s := pol.Summary()
	if p == tee.ProviderAWSSEVSNP {
		s.CSPIDs = cspIDs
	}
	return &s
}

// awsSEVSNPIdentity is what an EC2 SEV-SNP guest's VLEK says: whose it is
// (the provider's CSP_ID, which the authority pins as tee.peer.csp_ids),
// for which product and TCB, until when (ADR 0038).
type awsSEVSNPIdentity struct {
	CSPID        string `json:"csp_id"`
	Product      string `json:"product"`
	VLEKSHA256   string `json:"vlek_sha256"`
	VLEKNotAfter string `json:"vlek_not_after"`
}

func awsSEVSNPIdentityOf(p tee.Producer) *awsSEVSNPIdentity {
	d, ok := tee.VLEKOf(p)
	if !ok {
		return nil
	}
	return &awsSEVSNPIdentity{CSPID: d.CSPID, Product: d.ProductName, VLEKSHA256: d.SHA256, VLEKNotAfter: d.NotAfter}
}
