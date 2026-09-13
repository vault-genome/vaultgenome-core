// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package worker implements the external compute worker loop that cmd/acp-compute
// runs. It receives ReconstructionJobManifest objects over the Return Path
// inbound side, unseals authorized DisclosureMessage payloads with the
// recipient key bound to the manifest, runs the reconstruction, and returns
// a CandidateOutput.
//
// # Doctrinal role
//
// The worker is explicitly non-authority. It does not decide anything
// continuity-relevant; it computes. It cannot import any package under
// /internal/vault (enforced by the import-graph doctrine test).
//
// # Backends
//
// Two Reconstructor implementations live in this package:
//
//   - DeterministicReconstructor (reconstruction.go). The V1 MVP: a
//     content-addressed SHA-256 expansion over the canonical digest of
//     (manifest, components). Pure, bounded, deterministic. Retained
//     as a test fixture and as the "before" half of the before/after
//     demo; never the production backend post-iteration-7.
//
//   - GenerativeReconstructor (generative.go). The V2 production
//     backend as of iteration 7 (task #78): a byte-level Markov model
//     of order 3 trained on the canonical concatenation of the
//     unsealed components, sampled via a deterministic SHA-256 stream
//     PRNG seeded from the same canonical digest. Output reflects the
//     training corpus's statistical structure; partial genomes
//     measurably degrade fidelity; all iteration-5 contract properties
//     are preserved (see generative_test.go Tier A).
//
// Both satisfy the frozen Reconstructor interface; the daemon
// (cmd/acp-compute/main.go) builds the V2 backend by default. Swapping
// either way is a one-line constructor change because the interface
// was locked in iteration 5 by frozen_test.go. Any future V3 backend
// must preserve the same interface and the same iteration-5 contract
// suite; see docs/doctrine/bootstrap-contracts.md §15 for the freeze
// policy and docs/doctrine/open-decisions-resolved.md R-11 for the doctrinal
// rationale.
package worker
