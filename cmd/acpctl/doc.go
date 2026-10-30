// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package main (cmd/acpctl) is the administrative command-line interface for
// operators of the AI Continuity Platform.
//
// # Doctrinal role
//
// acpctl is a client to the sagvd authority, never a replacement for it. It
// issues read-only queries for operational status (session states, audit
// records, incident events) and submits governance requests that the vault
// independently authorizes. acpctl cannot short-circuit any authority path.
//
// # Commands
//
//   - status, audit query|verify, lineage: read an audit log — its closed
//     segments, then the live file (ADR 0027) — read-only; verify replays
//     every hash and signature from the first event and checks each
//     archive against the record that closed it.
//   - genome seal|open|verify|inspect|chain|lineage|gate: seal a model or a
//     directory into a bundle (its key to --key-out, or escrowed with
//     --escrow-to), restore it all or nothing, check it.
//   - stop keygen|issue|verify: the operator's signed stop list (ADR 0010).
//   - escrow keygen|recovery-keygen|recover: the operator's side of escrow
//     custody (ADR 0016); every key is under a KEM suite, --suite (ADR
//     0029) — keygen writes a plaintext escrow key, for the
//     simulated TEE only; a hardware release host makes its own sealed key
//     with `sagvd escrow-provision`, wrapped to the recovery key
//     recovery-keygen makes, and recover opens that envelope off the host
//     for `sagvd escrow-provision -stdin` on a new one.
//   - sentinel keygen|identity|seal-key|watch: on the primary, keep a running model's
//     state sealed generation by generation, attest every record with the
//     primary's TEE (--tee, ADR 0017), report when a tripwire fires
//     (ADR 0012); identity prints what the operator pins.
//   - console invite: a pass, the single-use file a person opens in vgconsole
//     (ADR 0039)
//   - failover issue|verify: the operator's signed failover policy — the
//     sentinel's key, the primary's TEE, the one standby, the triggers, the
//     grace on `stopped`, the quarantine, the required gate.
//   - recover: unseal a VG-VAULT-01 envelope with the TEE backend it names.
//   - tee prefetch / cache-status: a host that will have no route to the
//     vendors fills its peer verifier's caches while it has one (the VCEK
//     of its chip from AMD KDS, the TCB info and QE identity of its
//     platform from Intel PCS) and reads what they hold and until when.
//   - provision, provision authority|join|pin-worker: one command stands up a deployment — the release's
//     acp-keygen writes the key material, both daemons' configurations
//     are written for the family named, each daemon's identity is read
//     and pinned on the other side, the operator's token and audit key
//     are kept, each daemon's key files are sealed; provision.json says
//     what was done.
//   - tee fetch-amd-chain: the ASK+ARK chain of an AMD product line from
//     AMD KDS, verified against the roots this build pins (ADR 0024),
//     written for the daemons' amd_cert_chain_path.
package main
