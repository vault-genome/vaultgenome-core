// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package trust implements Trust Admission — the authority decision that
// either issues an AttestationResult with Outcome=allow, permitting the
// pipeline to proceed to session issuance, or with deny/restrict, blocking
// it.
//
// # Doctrinal role
//
// Trust is a gate, not a log. It is the enforcement point of the policy
// envelope named by the RecoveryRequest. It consumes the identity,
// contour, and policy profile, queries policy, and produces a signed
// AttestationResult.
//
// In MVP, the TEE quote underlying the attestation is produced by the
// software-emulated TEE in /internal/shared/tee
// (docs/doctrine/open-decisions-resolved.md R-10). In production, the same interface
// is served by a real TPM / TDX / SEV backend.
//
// Stage B: empty package, doctrinal purpose only.
package trust
