// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// RecordVerifier is a Verifier that reads the peer's Evidence record as
// it travelled — the media type and the message under it — rather than
// the family's bare Evidence. The delegated Verifier (ADR 0025, step 2b)
// is one: it hands the whole record, the TSM report with the certificate
// table inside, to the RATS Verifier it delegates to. The builtin
// verifiers read bare Evidence and never see the record.
type RecordVerifier interface {
	Verifier
	// VerifyRecord verifies the record over nonce and returns the
	// measurement for the pin and the detail for the audit record.
	VerifyRecord(mediaType string, value []byte, nonce Nonce) (Measurement, *AttestationDetail, error)
}

// VerifierUnwrapper is implemented by a wrapper around a Verifier (the
// metrics recorder) so RecordVerifierOf can look through it.
type VerifierUnwrapper interface {
	Unwrap() Verifier
}

// DescribeVerifier names a verifier for a log line: "builtin" for this
// side's own, "rats <url>" for the delegated one, looking through
// wrappers.
func DescribeVerifier(v Verifier) string {
	for v != nil {
		if r, ok := v.(*RATSVerifier); ok {
			return "rats " + r.URL()
		}
		w, ok := v.(VerifierUnwrapper)
		if !ok {
			break
		}
		v = w.Unwrap()
	}
	return "builtin"
}

// RecordVerifierOf returns v as a RecordVerifier when the verifier at
// the bottom of any wrappers reads records; nil when it reads bare
// Evidence. A wrapper that forwards VerifyRecord counts only if what it
// wraps is a RecordVerifier, so the handshake takes the record path for
// the delegated Verifier and the bare path for everything else.
func RecordVerifierOf(v Verifier) RecordVerifier {
	rv, ok := v.(RecordVerifier)
	if !ok {
		return nil
	}
	if w, ok := v.(VerifierUnwrapper); ok && RecordVerifierOf(w.Unwrap()) == nil {
		return nil
	}
	return rv
}
