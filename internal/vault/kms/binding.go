// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"crypto/sha512"
	"crypto/subtle"

	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
)

// RecipientBindingVerifier proves that a piece of attestation Evidence
// cryptographically binds a recipient public key: the TEE's caller-supplied
// REPORT_DATA (or the equivalent bound field for the TEE family) equals
// hash(recipientPub ‖ nonce). This is what makes the X25519 KEM recipient public
// key (ADR 0009) TEE-held rather than attacker-substituted — an attacker who
// swaps in their own public key cannot also forge a genuine report whose
// REPORT_DATA commits to it. Signature and certificate-chain verification remain
// the tee.Verifier's job; this checks only the pubkey binding.
type RecipientBindingVerifier interface {
	VerifyRecipientBinding(evidence, nonce, recipientPub []byte) error
}

// SEV-SNP report layout constants (mirrors internal/shared/tee/gcp_sev_snp_verify.go).
const (
	sevReportLen     = 1184
	sevReportDataOff = 0x050
	sevReportDataLen = 64
)

// SEVSNPRecipientBinder checks the KEM recipient binding for an AMD SEV-SNP
// report: the 64-byte REPORT_DATA field (offset 0x50 of the 1184-byte report)
// MUST equal SHA-512(recipientPub ‖ nonce). The destination's in-TEE key
// generator sets REPORT_DATA to exactly this value when it quotes, so a verified
// report proves the destination TEE committed to this public key under this
// challenge nonce.
type SEVSNPRecipientBinder struct{}

// VerifyRecipientBinding implements RecipientBindingVerifier for SEV-SNP.
func (SEVSNPRecipientBinder) VerifyRecipientBinding(evidence, nonce, recipientPub []byte) error {
	if len(recipientPub) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.binding: recipient public key required", nil)
	}
	if len(evidence) < sevReportLen {
		return shared_errors.Integrity(shared_errors.CodeAttestationDenied, "kms.binding: evidence shorter than a SEV-SNP report", nil)
	}
	got := evidence[sevReportDataOff : sevReportDataOff+sevReportDataLen]
	want := ExpectedReportData(recipientPub, nonce)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return shared_errors.Integrity(shared_errors.CodeAttestationDenied,
			"kms.binding: REPORT_DATA does not bind the recipient public key (substitution or replay?)", nil)
	}
	return nil
}

// ExpectedReportData is the canonical binding value a destination TEE must place
// in REPORT_DATA to bind its X25519 public key under a challenge nonce:
// SHA-512(recipientPub ‖ nonce) (64 bytes, exactly the REPORT_DATA width). Both
// the destination producer (when quoting) and the source binder use this.
func ExpectedReportData(recipientPub, nonce []byte) []byte {
	h := sha512.New()
	h.Write(recipientPub)
	h.Write(nonce)
	return h.Sum(nil)
}
