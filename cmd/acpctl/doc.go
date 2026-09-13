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
// # Stage B status
//
// Scaffold only. main() prints version and exits.
package main
