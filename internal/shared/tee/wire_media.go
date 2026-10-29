// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// What a family's Evidence is called on the wire, and the shape it
// travels in (ADR 0025, step 2). The Return Path carries Evidence in a
// RATS CMW record (RFC 9999) whose type is the media type here. For the
// families whose reports come through the kernel's configfs-tsm — SEV-SNP,
// TDX, and CCA when it comes — the message is the TSM report as ratsd
// defines it and Veraison accepts it: the kernel's `outblob` (the report
// or quote), the `auxblob` beside it (on SEV-SNP the certificate table
// the host wrote, the VCEK among them) and the kernel's provider name;
// `application/vnd.veraison.tsm-report+json` is its JSON form, the one
// our JSON frames use. The other families keep the bytes their producers
// make, under a provisional type of ours until each has a registered one.
// Wrap and Unwrap are the two ends of the wire: the local producer's
// Evidence into the message, the peer's message back into the Evidence
// its builtin verifier reads — refusing, by name, a type that is not the
// peer's family's.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Media types of Evidence on the wire.
const (
	// MediaTypeTSMReportJSON is ratsd's TSM report in JSON (Veraison's
	// sevsnp scheme accepts it as Evidence); the configfs-tsm families.
	MediaTypeTSMReportJSON = "application/vnd.veraison.tsm-report+json"
	// MediaTypeTSMReportCBOR is the same report in CBOR; not produced
	// here yet, named so a Verifier's answer can be matched.
	MediaTypeTSMReportCBOR = "application/vnd.veraison.tsm-report+cbor"
	// MediaTypeSimulatedEvidence is the simulated TEE's signed statement.
	MediaTypeSimulatedEvidence = "application/vnd.vault-genome.simulated-evidence"
	// MediaTypeAzureCGPUEvidence is the Azure confidential-GPU composite
	// (the chip's report, the vTPM quote, NVIDIA's tokens), provisional
	// until it travels as a CMW collection.
	MediaTypeAzureCGPUEvidence = "application/vnd.vault-genome.azure-cgpu-evidence"
	// MediaTypeAzureSEVSNPEvidence is the Azure SEV-SNP chip-and-vTPM
	// envelope (azure_sev_snp.go): the HCL report and the TPM quote.
	MediaTypeAzureSEVSNPEvidence = "application/vnd.vault-genome.azure-sev-snp-evidence"
	// MediaTypeGCPSEVVTPMEvidence is the Compute Engine chip-and-vTPM
	// envelope (gcp_sev_snp_vtpm.go): the chip's report, the AK's
	// certificate chain and the TPM quote, provisional.
	MediaTypeGCPSEVVTPMEvidence = "application/vnd.vault-genome.gcp-sev-snp-vtpm-evidence"
	// MediaTypeAWSSEVSNPEvidence is the EC2 SEV-SNP envelope
	// (aws_sev_snp.go): the chip's report and the VLEK the host showed
	// beside it, provisional.
	MediaTypeAWSSEVSNPEvidence = "application/vnd.vault-genome.aws-sev-snp-evidence"
	// MediaTypeSGXQuote is a DCAP quote (azure-sgx, intel-sgx-dcap),
	// provisional.
	MediaTypeSGXQuote = "application/vnd.vault-genome.sgx-quote"
	// MediaTypeNitroAttestationDocument is the Nitro COSE_Sign1 document,
	// provisional.
	MediaTypeNitroAttestationDocument = "application/vnd.vault-genome.nitro-attestation-document"
)

// EvidenceMediaType is the media type a family's Evidence carries on the
// wire. auto has none: it resolves to a family first.
func EvidenceMediaType(p Provider) (string, error) {
	switch p {
	case ProviderGCPSEVSNP, ProviderGCPTDX:
		return MediaTypeTSMReportJSON, nil
	case ProviderSimulated:
		return MediaTypeSimulatedEvidence, nil
	case ProviderAzureCGPU:
		return MediaTypeAzureCGPUEvidence, nil
	case ProviderAzureSEVSNP:
		return MediaTypeAzureSEVSNPEvidence, nil
	case ProviderGCPSEVSNPVTPM:
		return MediaTypeGCPSEVVTPMEvidence, nil
	case ProviderAWSSEVSNP:
		return MediaTypeAWSSEVSNPEvidence, nil
	case ProviderAzureSGX, ProviderIntelSGXDCAP:
		return MediaTypeSGXQuote, nil
	case ProviderAWSNitro:
		return MediaTypeNitroAttestationDocument, nil
	default:
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("tee: no evidence media type for provider %q", p), nil)
	}
}

// TSMProviderName is the kernel's name for a configfs-tsm family — the
// `provider` attribute, which the TSM report repeats.
func TSMProviderName(p Provider) (string, error) {
	switch p {
	case ProviderGCPSEVSNP:
		return TSMProviderSEVGuest, nil
	case ProviderGCPTDX:
		return TSMProviderTDXGuest, nil
	default:
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("tee: %q is not a configfs-tsm family", p), nil)
	}
}

// tsmBytes is a byte string in the TSM report's JSON form: base64url
// without padding (ratsd's BinaryString).
type tsmBytes []byte

func (b tsmBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

func (b *tsmBytes) UnmarshalJSON(in []byte) error {
	var s string
	if err := json.Unmarshal(in, &s); err != nil {
		return err
	}
	d, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return err
	}
	*b = d
	return nil
}

// TSMReport is the configfs-tsm report as ratsd defines it (its
// docs/tsm-report.cddl): the kernel's outblob, the auxblob beside it and
// the provider's name. The manifest fields of a service provider are not
// used here.
type TSMReport struct {
	OutBlob  []byte
	AuxBlob  []byte
	Provider string
}

type tsmReportJSON struct {
	AuxBlob  tsmBytes `json:"auxblob,omitempty"`
	OutBlob  tsmBytes `json:"outblob"`
	Provider string   `json:"provider"`
}

// MarshalJSON writes the report in ratsd's JSON form.
func (t TSMReport) MarshalJSON() ([]byte, error) {
	if len(t.OutBlob) == 0 || t.Provider == "" {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "tee: a TSM report needs outblob and provider", nil)
	}
	return json.Marshal(tsmReportJSON{AuxBlob: t.AuxBlob, OutBlob: t.OutBlob, Provider: t.Provider})
}

// UnmarshalJSON reads ratsd's JSON form, requiring outblob and provider.
func (t *TSMReport) UnmarshalJSON(in []byte) error {
	var j tsmReportJSON
	if err := json.Unmarshal(in, &j); err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "tee: TSM report does not decode", err)
	}
	if len(j.OutBlob) == 0 || j.Provider == "" {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "tee: a TSM report needs outblob and provider", nil)
	}
	*t = TSMReport{OutBlob: j.OutBlob, AuxBlob: j.AuxBlob, Provider: j.Provider}
	return nil
}

// WrapEvidence makes the wire message of a family's Evidence: the media
// type and the bytes a CMW record carries. For the configfs-tsm
// families the report goes into a TSM report with the auxblob, if any,
// and the kernel's provider name; the other families' bytes travel as
// they are.
func WrapEvidence(p Provider, ev Evidence, auxblob []byte) (mediaType string, value []byte, err error) {
	mediaType, err = EvidenceMediaType(p)
	if err != nil {
		return "", nil, err
	}
	if len(ev) == 0 {
		return "", nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "tee: no evidence to wrap", nil)
	}
	if mediaType != MediaTypeTSMReportJSON {
		return mediaType, []byte(ev), nil
	}
	name, err := TSMProviderName(p)
	if err != nil {
		return "", nil, err
	}
	value, err = json.Marshal(TSMReport{OutBlob: ev, AuxBlob: auxblob, Provider: name})
	if err != nil {
		return "", nil, err
	}
	return mediaType, value, nil
}

// UnwrapEvidence is the other end: the message a peer of family p must
// have sent, back into the Evidence p's builtin verifier reads. A type
// that is not p's is refused by name; a TSM report whose provider is not
// p's kernel name is refused too. The auxblob is returned for a verifier
// that wants the certificate table.
func UnwrapEvidence(p Provider, mediaType string, value []byte) (Evidence, []byte, error) {
	want, err := EvidenceMediaType(p)
	if err != nil {
		return nil, nil, err
	}
	if mediaType != want {
		return nil, nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
			fmt.Sprintf("tee: evidence type %q, this peer verifier is %s and reads %s", mediaType, p, want), nil)
	}
	if len(value) == 0 {
		return nil, nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "tee: empty evidence", nil)
	}
	if want != MediaTypeTSMReportJSON {
		return Evidence(value), nil, nil
	}
	var t TSMReport
	if err := json.Unmarshal(value, &t); err != nil {
		return nil, nil, err
	}
	name, _ := TSMProviderName(p)
	if t.Provider != name {
		return nil, nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
			fmt.Sprintf("tee: TSM report from provider %q, this peer verifier is %s and expects %q", t.Provider, p, name), nil)
	}
	return Evidence(t.OutBlob), t.AuxBlob, nil
}

// AuxblobProducer is a Producer whose report comes with auxiliary data
// beside it: configfs-tsm's auxblob — on SEV-SNP the certificate table
// the host wrote, the VCEK among them. The auxblob is not Evidence: no
// verdict here depends on it, and the report does not sign it. It
// travels with the report inside the TSM report on the wire
// (WrapEvidence), so a Verifier that wants the certificates has them
// without a round trip to the vendor.
type AuxblobProducer interface {
	Producer
	// QuoteWithAux is Quote with the auxblob beside the Evidence; nil
	// when the provider showed none.
	QuoteWithAux(nonce Nonce) (Evidence, []byte, error)
}

// QuoteWithAux quotes with p and returns the auxblob when p has one; a
// plain Producer gives none.
func QuoteWithAux(p Producer, nonce Nonce) (Evidence, []byte, error) {
	if ap, ok := p.(AuxblobProducer); ok {
		return ap.QuoteWithAux(nonce)
	}
	ev, err := p.Quote(nonce)
	return ev, nil, err
}
