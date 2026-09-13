// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package intake is the entry point for RecoveryRequest objects into the
// vault. It performs the first shape / identity / rate-limit checks and
// hands validated requests to /internal/vault/trust for authority
// evaluation.
//
// # Doctrinal role
//
// Intake is not authority. It decides only whether a request is well-
// formed enough to present to trust. It may reject on structural grounds
// (malformed, duplicate, rate-limited) but never on continuity-policy
// grounds — that is trust's job.
//
// Stage B: empty package, doctrinal purpose only.
package intake
