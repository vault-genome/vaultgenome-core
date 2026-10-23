// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Command acp-bootstrap is the destination-side daemon for cross-cloud
// key release. It hosts the /v1/crosscloud/handshake and
// /v1/crosscloud/token endpoints that `sagvd crosscloud-restore`
// dispatches to.
//
// Topology (per ADR 0006):
//
//	[ source: sagvd + Coordinator ]  --TLS 1.3-->  [ destination: acp-bootstrap ]
//
// The daemon loads:
//
//   - Local TEE producer: AMD SEV-SNP or Intel TDX through configfs-tsm
//     ("gcp-sev-snp", "gcp-tdx"), an Azure confidential GPU VM through the
//     vTPM and NVIDIA's attestation ("azure-cgpu"), an Azure SEV-SNP
//     Confidential VM without a GPU ("azure-sev-snp"), a Nitro enclave
//     through the NSM, reached over vsock, its key files opened through
//     KMS ("aws-nitro", ADR 0036), or the simulated backend for development
//   - Source-authority pubkey (pinned out-of-band from
//     `sagvd identity`; identifies the source authority)
//   - Local keystore (where released DEKs are registered)
//
// And exposes:
//
//   - The two crosscloud routes on the configured listen address.
//     Beyond loopback the listener must speak TLS (1.3 only) and
//     callers must present a client certificate or a bearer token;
//     Validate refuses anything weaker before the daemon binds.
//   - /healthz and /readyz on a separate health listener.
//
// Every handshake gets a fresh key pair under the KEM suite the two
// sides settle on — the first of the source's preferences this
// daemon's profile accepts (`crypto.profile`: general, fips or cnsa;
// ADR 0029) — and the Evidence the daemon returns is quoted over a
// challenge that binds that key and its suite to the source's nonce;
// each DEK in the matching token is encapsulated to it under that suite
// (ADR 0009). The private key never leaves process memory, opens one
// token, and expires after five minutes.
//
// `acp-bootstrap identity -config <path>` prints the TEE provider,
// measurement and attestation key a source operator pins for this
// destination, and the profile and suites it generates keys under,
// without opening a listener.
//
// See:
//
//   - ADR 0006 — docs/adr/0006-cross-cloud-kms-mediated-restore.md
//   - ADR 0009 — docs/adr/0009-x25519-kem-cross-cloud-key-delivery.md
//   - ADR 0029 — docs/adr/0029-kem-suites-and-the-cryptographic-profile.md
//   - Operator runbook 06 — docs/operator/06_cross_cloud_restore.md
//   - source-side equivalent: cmd/sagvd `crosscloud-restore` subcommand
package main
