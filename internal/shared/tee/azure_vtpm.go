// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tee — the chip-and-vTPM half every Azure Confidential VM attests
// with, shared by azure-sev-snp (this alone) and azure-cgpu (this and
// NVIDIA's tokens for the H100).
//
// Azure mediates SEV-SNP through its paravisor: the guest has no
// /dev/sev-guest and no configfs-tsm. The SNP report is issued at boot and
// kept in the vTPM's NV index as the HCL report (azure_cgpu_hcl.go), and
// its REPORT_DATA names the vTPM's attestation key; a TPM quote by that
// key over the PCRs, with a challenger's nonce in extraData
// (azure_cgpu_tpm.go), binds the nonce to the report. The measurement is
// the SNP launch measurement (48 bytes: the paravisor and firmware Azure
// measures); the PCR digest of the quote is what the vTPM measured of
// this boot, which a peer may pin. Nothing here knows which Azure family
// it serves beyond the name it puts in its errors.
package tee

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// azureVTPM is the producer's half: the HCL report read once, the
// attestation key's handle, the measurement and the boot quote.
type azureVTPM struct {
	family      string // the provider's name, for errors
	tool        func(string) string
	timeout     time.Duration
	pcrs        string
	hcl         *hclReport
	akHandle    string
	measurement Measurement
	boot        *tpmQuote // a quote taken at construction: what the vTPM measured of this boot
}

// openAzureVTPM reads the HCL report from the vTPM, finds the attestation
// key the chip vouched for among the persistent keys (or takes akHandle),
// fixes the measurement, and takes one quote under a fixed challenge —
// what this boot measured into the vTPM, the PCR digest a peer may pin.
func openAzureVTPM(family, toolsDir, akHandle, pcrs string, timeout time.Duration) (*azureVTPM, error) {
	if pcrs == "" {
		pcrs = DefaultTPMQuotePCRs
	}
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	v := &azureVTPM{family: family, timeout: timeout, pcrs: pcrs}
	v.tool = func(name string) string {
		if toolsDir == "" {
			return name
		}
		return filepath.Join(toolsDir, name)
	}
	raw, err := runCommand(timeout, v.tool("tpm2_nvread"), "-C", "o", hclNVIndex)
	if err != nil {
		return nil, fmt.Errorf("%s: read the HCL report from the vTPM: %w", family, err)
	}
	h, err := parseHCLReport(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: HCL report: %w", family, err)
	}
	ak, err := h.attestationKey()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", family, err)
	}
	if akHandle == "" {
		akHandle, err = findAKHandle(v.tool, timeout, ak)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", family, err)
		}
	}
	m, err := MeasurementFromBytes(h.SNP.Measurement[:])
	if err != nil {
		return nil, err
	}
	v.hcl, v.akHandle, v.measurement = h, akHandle, m
	msg, sig, err := v.quote(tpmQuoteExtraDataFor([]byte("vault-genome " + family + " boot identity")))
	if err != nil {
		return nil, fmt.Errorf("%s: initial TPM quote: %w", family, err)
	}
	q, err := parseTPMQuote(msg)
	if err != nil {
		return nil, fmt.Errorf("%s: initial TPM quote: %w", family, err)
	}
	if err := verifyTPMQuoteSignature(ak, msg, sig); err != nil {
		return nil, fmt.Errorf("%s: initial TPM quote: %w", family, err)
	}
	v.boot = q
	return v, nil
}

// quote runs tpm2_quote for a challenge and returns the message and the
// raw signature.
func (v *azureVTPM) quote(challenge [32]byte) (msg, sig []byte, err error) {
	dir, err := os.MkdirTemp("", "vg-quote-*")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	msgPath, sigPath := filepath.Join(dir, "quote.msg"), filepath.Join(dir, "quote.sig")
	if _, err := runCommand(v.timeout, v.tool("tpm2_quote"), "-c", v.akHandle, "-l", v.pcrs, "-q", hex.EncodeToString(challenge[:]),
		"-g", "sha256", "-m", msgPath, "-s", sigPath, "-f", "plain"); err != nil {
		return nil, nil, fmt.Errorf("TPM quote: %w", err)
	}
	if msg, err = os.ReadFile(msgPath); err != nil {
		return nil, nil, err
	}
	if sig, err = os.ReadFile(sigPath); err != nil {
		return nil, nil, err
	}
	return msg, sig, nil
}

// findAKHandle lists the vTPM's persistent handles and returns the one
// whose public key is the HCL attestation key.
func findAKHandle(tool func(string) string, timeout time.Duration, ak *rsa.PublicKey) (string, error) {
	out, err := runCommand(timeout, tool("tpm2_getcap"), "handles-persistent")
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "vg-ak-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	for _, field := range strings.Fields(string(out)) {
		if !strings.HasPrefix(field, "0x") {
			continue
		}
		pem := filepath.Join(dir, field+".pem")
		if _, err := runCommand(timeout, tool("tpm2_readpublic"), "-c", field, "-f", "pem", "-o", pem); err != nil {
			continue
		}
		raw, err := os.ReadFile(pem)
		if err != nil {
			continue
		}
		pub, err := parsePEMRSAPublicKey(raw)
		if err != nil {
			continue
		}
		if pub.Equal(ak) {
			return field, nil
		}
	}
	return "", errors.New("no persistent vTPM key is the HCL attestation key")
}

// VTPMBootOf is what an Azure guest's vTPM measured of its boot — the
// PCRs quoted, as "bank:index,…", and their digest, which a peer may pin
// (pcr_digests) — for a producer of either Azure family; ok is false for
// any other producer.
func VTPMBootOf(p Producer) (pcrs []string, digest []byte, ok bool) {
	var boot *tpmQuote
	switch a := p.(type) {
	case *AzureCGPUProducer:
		boot = a.vtpm.boot
	case *AzureSEVSNPProducer:
		boot = a.vtpm.boot
	default:
		return nil, nil, false
	}
	for _, s := range boot.PCRSelections {
		pcrs = append(pcrs, s.String())
	}
	return pcrs, append([]byte(nil), boot.PCRDigest...), true
}

// azureSNPChecker is the verifier's half: the SNP report inside the HCL
// report held to AMD's root for its product, its policy, VMPL and TCB
// floor; then the vTPM's attestation key the report named, signing the
// challenge over the PCRs, with the PCR digest pinned when the policy
// names one.
type azureSNPChecker struct {
	family     string
	amdRootPEM []byte
	kdsURL     string
	cacheDir   string
	minTCB     uint64
	policy     SEVSNPPolicy
	pcrDigests [][]byte

	mu        sync.Mutex
	vcekCache map[string][]byte
}

// newAzureSNPChecker validates the AMD chain and fixes the defaults.
func newAzureSNPChecker(family string, amdRootPEM []byte, kdsURL, cacheDir string, minTCB uint64, pcrDigests [][]byte, policy SEVSNPPolicy) (*azureSNPChecker, error) {
	if len(amdRootPEM) == 0 {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, family+": AMDRootPEM (the product's ASK+ARK chain) required", nil)
	}
	if _, err := VerifyAMDCertChain(amdRootPEM); err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, family+": AMDRootPEM: "+err.Error(), err)
	}
	if kdsURL == "" {
		kdsURL = "https://kdsintf.amd.com"
	}
	return &azureSNPChecker{family: family, amdRootPEM: amdRootPEM, kdsURL: kdsURL, cacheDir: cacheDir, minTCB: minTCB, policy: policy, pcrDigests: pcrDigests, vcekCache: map[string][]byte{}}, nil
}

// check verifies the chip's report and the vTPM's quote for nonce and
// returns the HCL report, the chip's product name and the quote. Every
// refusal is an Integrity error naming the family.
func (c *azureSNPChecker) check(hclRaw, quoteMsg, quoteSig []byte, nonce Nonce) (*hclReport, string, *tpmQuote, *SEVSNPReportDetail, error) {
	integrity := func(code, msg string, err error) error {
		return shared_errors.Integrity(code, c.family+": "+msg, err)
	}
	// The chip: the SNP report inside the HCL report, verified to AMD.
	h, err := parseHCLReport(hclRaw)
	if err != nil {
		return nil, "", nil, nil, integrity(shared_errors.CodeSignatureInvalid, "HCL report: "+err.Error(), err)
	}
	report := h.SNP
	product := sevProductName(report)
	vcek, err := c.fetchVCEK(product, report.ChipID, report.ReportedTCB)
	if err != nil {
		return nil, "", nil, nil, integrity(shared_errors.CodeSignatureInvalid, "fetch VCEK: "+err.Error(), err)
	}
	if err := verifyAMDChain(vcek, c.amdRootPEM); err != nil {
		return nil, "", nil, nil, integrity(shared_errors.CodeSignatureInvalid, "AMD chain ("+product+"): "+err.Error(), err)
	}
	if err := verifySEVReportSignature(report, vcek); err != nil {
		return nil, "", nil, nil, integrity(shared_errors.CodeSignatureInvalid, "report signature: "+err.Error(), err)
	}
	if report.SignatureAlgo != 1 || report.SigningKey != 0 {
		return nil, "", nil, nil, integrity(shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("report signed with algorithm %d by key kind %d; this verifier accepts ECDSA P-384 (1) by the VCEK (0)", report.SignatureAlgo, report.SigningKey), nil)
	}
	if report.Policy&sevPolicyDebug != 0 {
		return nil, "", nil, nil, integrity(shared_errors.CodeAttestationDenied, "guest policy allows DEBUG — the hypervisor can read this guest's memory", nil)
	}
	if report.VMPL != 0 {
		return nil, "", nil, nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("report requested at VMPL %d, expected 0", report.VMPL), nil)
	}
	if report.ReportedTCB < c.minTCB {
		return nil, "", nil, nil, integrity(shared_errors.CodeSignatureInvalid, fmt.Sprintf("ReportedTCB %d below minimum %d", report.ReportedTCB, c.minTCB), nil)
	}
	snpDetail, err := checkSEVSNPPolicy(report, c.policy, c.family)
	if err != nil {
		return nil, "", nil, nil, err
	}

	// The vTPM: the attestation key the chip named signs the challenge.
	ak, err := h.attestationKey()
	if err != nil {
		return nil, "", nil, nil, integrity(shared_errors.CodeSignatureInvalid, err.Error(), err)
	}
	quote, err := parseTPMQuote(quoteMsg)
	if err != nil {
		return nil, "", nil, nil, integrity(shared_errors.CodeSignatureInvalid, "TPM quote: "+err.Error(), err)
	}
	if err := verifyTPMQuoteSignature(ak, quoteMsg, quoteSig); err != nil {
		return nil, "", nil, nil, integrity(shared_errors.CodeSignatureInvalid, "TPM quote: "+err.Error(), err)
	}
	challenge := tpmQuoteExtraDataFor(nonce)
	if !bytes.Equal(quote.ExtraData, challenge[:]) {
		return nil, "", nil, nil, integrity(shared_errors.CodeSignatureInvalid, "TPM quote does not bind challenger nonce (replay?)", nil)
	}
	if len(c.pcrDigests) > 0 {
		pinned := false
		for _, d := range c.pcrDigests {
			if bytes.Equal(d, quote.PCRDigest) {
				pinned = true
				break
			}
		}
		if !pinned {
			return nil, "", nil, nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("PCR digest %x is not in the acceptable set: the boot measured into the vTPM is not one the policy names", quote.PCRDigest), nil)
		}
	}
	return h, product, quote, snpDetail, nil
}

// fetchVCEK is the GCP verifier's cache, per product.
func (c *azureSNPChecker) fetchVCEK(product string, chipID [64]byte, tcb uint64) ([]byte, error) {
	key := fmt.Sprintf("%s-%x-%d", strings.ToLower(product), chipID, tcb)
	c.mu.Lock()
	defer c.mu.Unlock()
	if cached, ok := c.vcekCache[key]; ok {
		return cached, nil
	}
	var file string
	if c.cacheDir != "" {
		file = filepath.Join(c.cacheDir, key+".der")
		if cached, err := os.ReadFile(file); err == nil && len(cached) > 0 {
			c.vcekCache[key] = cached
			return cached, nil
		}
	}
	cert, err := amdKDSGetVCEKFor(c.kdsURL, product, chipID, tcb)
	if err != nil {
		return nil, err
	}
	c.vcekCache[key] = cert
	if file != "" {
		_ = writeFileAtomic(file, cert)
	}
	return cert, nil
}

// amdKDSGetVCEKFor fetches a VCEK from AMD KDS for a product; a var so
// tests run without network.
var amdKDSGetVCEKFor = func(baseURL, product string, chipID [64]byte, reportedTCB uint64) ([]byte, error) {
	return realAMDKDSGetVCEKFor(baseURL, product, chipID, reportedTCB)
}

// azureAcceptMeasurement holds the report's MEASUREMENT against the
// acceptable set.
func azureAcceptMeasurement(family string, report *sevSNPReport, acceptable []Measurement) (Measurement, error) {
	m, err := MeasurementFromBytes(report.Measurement[:])
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, family+": unexpected MEASUREMENT length: "+err.Error(), err)
	}
	for _, a := range acceptable {
		if a.Equal(m) {
			return m, nil
		}
	}
	return nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("%s: MEASUREMENT %x not in acceptable set", family, m), nil)
}
