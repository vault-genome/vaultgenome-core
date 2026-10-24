// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// AttestationDetail is what a verifier can say about verified Evidence
// beyond the Measurement: the platform the evidence named and, for a
// confidential GPU host, the GPUs NVIDIA's tokens vouched for and this
// verifier's own evaluations of their reports (ADR 0021). It goes on the
// audit record that admits the peer (TRUST_EVALUATED) or releases a key
// to it (CROSS_CLOUD_ATTESTATION_VERIFIED), so the record says what was
// checked, not only that a measurement matched. Nil when the verifier
// has nothing beyond the measurement to say.
type AttestationDetail struct {
	Provider    Provider `json:"provider"`
	Product     string   `json:"product,omitempty"`
	ChipIDHex   string   `json:"chip_id_hex,omitempty"`
	ReportedTCB uint64   `json:"reported_tcb,omitempty"`
	// SEVSNP is what a SEV-SNP verifier read from the report beyond the
	// measurement, and the floor it held it to (ADR 0033).
	SEVSNP *SEVSNPReportDetail `json:"sev_snp,omitempty"`
	// Nitro is what the Nitro verifier read from the attestation document
	// beyond PCR0, and the PCRs it held to pins (ADR 0036).
	Nitro *NitroDocumentDetail `json:"nitro,omitempty"`
	// PCRSelection and PCRDigestHex are the vTPM quote's bank and PCRs
	// and the digest over them the pin was held against.
	PCRSelection string `json:"pcr_selection,omitempty"`
	PCRDigestHex string `json:"pcr_digest_hex,omitempty"`
	// GCEInstance is the Compute Engine instance a vTPM's attestation-key
	// certificate names (gcp-sev-snp-vtpm, ADR 0037).
	GCEInstance *GCEInstance `json:"gce_instance,omitempty"`
	// GPUs are the GPUs the verdict rests on, each with who vouched for
	// it: NVIDIA's token or the verifier's own evaluation.
	GPUs []GPUVerdict `json:"gpus,omitempty"`
	// Evaluations are the verifier's own evaluations of the GPUs'
	// reports, one per report, when the policy asked for them.
	Evaluations []GPUEvaluation `json:"evaluations,omitempty"`
	// Verifier is the delegated Verifier's result (ADR 0025, step 2b)
	// when appraisal was delegated: the EAR itself, re-verifiable
	// offline under the Verifier's key, and what this side read from it.
	Verifier *VerifierResult `json:"verifier,omitempty"`
}

// VerifierResult is what a delegated RATS Verifier said, as recorded.
type VerifierResult struct {
	// URL is the Verifier asked.
	URL string `json:"url"`
	// EAR is the attestation result as received: a compact JWS.
	EAR string `json:"ear"`
	// Submod is the appraisal this side judged by.
	Submod string `json:"submod"`
	// Status is that appraisal's ear.status.
	Status string `json:"status"`
	// PolicyID is its ear.appraisal-policy-id.
	PolicyID string `json:"policy_id,omitempty"`
	// TrustVector is its ear.trustworthiness-vector.
	TrustVector map[string]int `json:"trustworthiness_vector,omitempty"`
	// VerifierDeveloper and VerifierBuild are ear.verifier-id.
	VerifierDeveloper string `json:"verifier_developer,omitempty"`
	VerifierBuild     string `json:"verifier_build,omitempty"`
	// IssuedAt is the EAR's iat.
	IssuedAt int64 `json:"issued_at"`
}

// DetailedVerifier is a Verifier that can also say what it verified.
type DetailedVerifier interface {
	Verifier
	// VerifyDetailed is Verify with the detail beside the measurement.
	VerifyDetailed(evidence Evidence, nonce Nonce) (Measurement, *AttestationDetail, error)
}

// VerifyDetailed verifies evidence with v and returns the detail when v
// can give one; a plain Verifier gives none.
func VerifyDetailed(v Verifier, evidence Evidence, nonce Nonce) (Measurement, *AttestationDetail, error) {
	if dv, ok := v.(DetailedVerifier); ok {
		return dv.VerifyDetailed(evidence, nonce)
	}
	m, err := v.Verify(evidence, nonce)
	return m, nil, err
}
