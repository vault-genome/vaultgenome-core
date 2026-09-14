// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"crypto/sha512"
	"testing"

	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
)

// craftSEVReport builds a minimal 1184-byte SEV-SNP report blob with the given
// 64-byte REPORT_DATA at offset 0x50 (the rest zero). The binder only reads
// REPORT_DATA; signature/chain verification is the tee.Verifier's separate job.
func craftSEVReport(reportData []byte) []byte {
	ev := make([]byte, sevReportLen)
	copy(ev[sevReportDataOff:sevReportDataOff+sevReportDataLen], reportData)
	return ev
}

var (
	bindPub   = []byte("x25519-recipient-public-key-0001")
	bindNonce = []byte("challenge-nonce-0001")
)

func TestSEVSNPRecipientBinder_AcceptsBoundReport(t *testing.T) {
	ev := craftSEVReport(ExpectedReportData(bindPub, bindNonce))
	if err := (SEVSNPRecipientBinder{}).VerifyRecipientBinding(ev, bindNonce, bindPub); err != nil {
		t.Fatalf("a report whose REPORT_DATA binds the pubkey must pass: %v", err)
	}
}

func TestSEVSNPRecipientBinder_RejectsSubstitutedPubkey(t *testing.T) {
	ev := craftSEVReport(ExpectedReportData(bindPub, bindNonce))
	attacker := []byte("attacker-substituted-pubkey-0002")
	err := (SEVSNPRecipientBinder{}).VerifyRecipientBinding(ev, bindNonce, attacker)
	if err == nil || !shared_errors.Is(err, shared_errors.CategoryIntegrity) {
		t.Fatalf("a substituted pubkey must fail with Integrity, got %v", err)
	}
}

func TestSEVSNPRecipientBinder_RejectsWrongNonce(t *testing.T) {
	ev := craftSEVReport(ExpectedReportData(bindPub, bindNonce))
	err := (SEVSNPRecipientBinder{}).VerifyRecipientBinding(ev, []byte("different-nonce-9999"), bindPub)
	if err == nil {
		t.Fatal("a report bound under a different nonce (replay) must fail")
	}
}

func TestSEVSNPRecipientBinder_RejectsShortEvidence(t *testing.T) {
	if err := (SEVSNPRecipientBinder{}).VerifyRecipientBinding(make([]byte, 100), bindNonce, bindPub); err == nil {
		t.Fatal("evidence shorter than a SEV-SNP report must fail")
	}
}

func TestSEVSNPRecipientBinder_RejectsEmptyPubkey(t *testing.T) {
	ev := craftSEVReport(make([]byte, sevReportDataLen))
	if err := (SEVSNPRecipientBinder{}).VerifyRecipientBinding(ev, bindNonce, nil); err == nil {
		t.Fatal("an empty recipient pubkey must be rejected")
	}
}

func TestExpectedReportData_IsSHA512Of64Bytes(t *testing.T) {
	rd := ExpectedReportData([]byte("pub"), []byte("nonce"))
	if len(rd) != sevReportDataLen {
		t.Fatalf("REPORT_DATA must be %d bytes, got %d", sevReportDataLen, len(rd))
	}
	want := sha512.Sum512([]byte("pubnonce"))
	if string(rd) != string(want[:]) {
		t.Fatal("ExpectedReportData must equal SHA-512(recipientPub || nonce)")
	}
}
