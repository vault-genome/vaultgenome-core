// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package errors defines the structured error types used across the
// platform. Errors are classified by doctrinal category:
//
//   - StructuralError — malformed contract, wrong schema version
//   - AuthorityError  — authority denied a request (trust/policy/session)
//   - OperationalError — an operational sub-check failed
//   - IntegrityError  — cryptographic or chain integrity violation
//   - IncidentError   — tamper or adversarial-condition signal
//
// # Doctrinal role
//
// Errors are not just diagnostics. Classification drives what AuditEvent
// kind is emitted and whether IncidentTermination must run. A caller that
// misclassifies an IntegrityError as a StructuralError is downgrading a
// critical signal — that is itself a reviewable doctrinal defect.
//
// # Message and cause
//
// A classified error prints itself as "category[code]: message: cause".
// The message says what failed, in the caller's terms; the cause is left
// to the error, which prints it after the message. A message that carries
// the cause as well — formatted into it, through its Error(), or in a
// variable built from it — says everything twice: the package's tests walk
// the module and refuse such a caller (callers_test.go), and Semgrep rule
// vg-error-cause-twice marks one in review.
package errors
