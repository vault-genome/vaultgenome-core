// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/console"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// consoleCmd dispatches `acpctl console <subcommand>` (ADR 0039).
//
//	invite  — make a pass: the file a person opens in their console
func consoleCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: acpctl console <invite> [flags]")
		return 2
	}
	switch args[0] {
	case "invite":
		return consoleInviteCmd(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		fmt.Fprintln(stdout, "console subcommands:")
		fmt.Fprintln(stdout, "  invite  — make a pass: the file a person opens in their console")
		return 0
	default:
		fmt.Fprintf(stderr, "acpctl console: unknown subcommand %q\n", args[0])
		return 2
	}
}

// consolePeer is `tee.peer` of acp-compute.json: how this deployment pins the
// authority. A pass carries the same pin with its files inline, so a person's
// console holds the server to what the deployment's own worker holds it to.
type consolePeer struct {
	Provider              string                  `json:"provider"`
	MeasurementPath       string                  `json:"measurement_path"`
	PublicKeyPath         string                  `json:"public_key_path"`
	AMDCertChainPath      string                  `json:"amd_cert_chain_path"`
	AMDKDSURL             string                  `json:"amd_kds_url"`
	MinReportedTCB        uint64                  `json:"min_reported_tcb"`
	SEVSNP                *tee.SEVSNPPolicyConfig `json:"sev_snp"`
	CSPIDs                []string                `json:"csp_ids"`
	PCRDigests            []string                `json:"pcr_digests"`
	PCRSelection          string                  `json:"pcr_selection"`
	GCEProjectIDs         []string                `json:"gce_project_ids"`
	GCEEKAKRootsPath      string                  `json:"gce_ek_ak_roots_path"`
	PCSURL                string                  `json:"pcs_url"`
	AcceptableTCBStatuses []string                `json:"acceptable_tcb_statuses"`
}

func consoleInviteCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("console invite", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sagvdPath := fs.String("sagvd-config", "", "sagvd.json of this deployment (required)")
	workerPath := fs.String("worker-config", "", "acp-compute.json of this deployment: the pin of the authority (required)")
	auditPub := fs.String("audit-pubkey", "", "The audit public key (default: operator/audit_public_key.pem beside --sagvd-config)")
	address := fs.String("address", "", "host:port the person's computer reaches the listener at (required)")
	label := fs.String("label", "", "What the person sees this server called (default: the address)")
	name := fs.String("name", "", "The person's name (required)")
	role := fs.String("role", string(console.RoleOwner), "viewer, operator or owner; the first owner holds the emergency stop")
	valid := fs.Duration("valid", 72*time.Hour, "How long the pass may be used")
	out := fs.String("out", "", "Where to write the pass (required; created 0600, never overwritten)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl console invite --sagvd-config PATH --worker-config PATH --address HOST:PORT --name NAME [--role ROLE] [--label TEXT] [--valid DURATION] [--audit-pubkey PATH] --out FILE")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Make a pass on the authority's host: the file a person opens in their console.")
		fmt.Fprintln(stderr, "It says where the server is and what its chip must prove, and carries a")
		fmt.Fprintln(stderr, "single-use code. sagvd must have started once with console.listen_address set.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sagvdPath == "" || *workerPath == "" || *address == "" || *name == "" || *out == "" {
		fmt.Fprintln(stderr, "acpctl console invite: --sagvd-config, --worker-config, --address, --name and --out are required")
		return 2
	}
	r := console.Role(*role)
	if !r.Valid() {
		fmt.Fprintf(stderr, "acpctl console invite: --role %q must be viewer, operator or owner\n", *role)
		return 2
	}
	pass, inviteKey, invite, err := buildConsolePass(*sagvdPath, *workerPath, *auditPub, *address, *label, *name, r, *valid)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl console invite: %v\n", err)
		return 1
	}
	raw, err := json.MarshalIndent(pass, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "acpctl console invite: %v\n", err)
		return 1
	}
	if err := writeKeyFile(*out, append(raw, '\n'), false); err != nil {
		fmt.Fprintf(stderr, "acpctl console invite: write the pass: %v\n", err)
		return 1
	}
	inviteRaw, err := json.Marshal(invite)
	if err == nil {
		err = writeKeyFile(inviteKey, inviteRaw, false)
	}
	if err != nil {
		_ = os.Remove(*out)
		fmt.Fprintf(stderr, "acpctl console invite: write the invite: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "pass written: %s for %s (%s), valid until %s; it works once\n", *out, *name, r, invite.ExpiresAt.Format(time.RFC3339))
	return 0
}

// buildConsolePass assembles a pass and the invite the server keeps for it.
func buildConsolePass(sagvdPath, workerPath, auditPub, address, label, name string, role console.Role, valid time.Duration) (console.Pass, string, console.Invite, error) {
	var sagvd struct {
		Console struct {
			Dir string `json:"dir"`
		} `json:"console"`
		Keys struct {
			AuditSigning struct {
				KID string `json:"kid"`
			} `json:"audit_signing"`
		} `json:"keys"`
	}
	raw, err := os.ReadFile(sagvdPath)
	if err == nil {
		err = json.Unmarshal(raw, &sagvd)
	}
	if err != nil {
		return console.Pass{}, "", console.Invite{}, fmt.Errorf("--sagvd-config: %w", err)
	}
	if sagvd.Console.Dir == "" {
		return console.Pass{}, "", console.Invite{}, fmt.Errorf("--sagvd-config: no console.dir: this deployment has no console listener (acpctl provision --console-listen)")
	}
	cert, err := os.ReadFile(filepath.Join(sagvd.Console.Dir, "tls.crt"))
	if err != nil {
		return console.Pass{}, "", console.Invite{}, fmt.Errorf("the listener's certificate is written when sagvd first starts with the console on: %w", err)
	}
	if auditPub == "" {
		auditPub = filepath.Join(filepath.Dir(sagvdPath), "operator", "audit_public_key.pem")
	}
	auditKey, err := os.ReadFile(auditPub)
	if err != nil {
		return console.Pass{}, "", console.Invite{}, fmt.Errorf("--audit-pubkey: %w", err)
	}
	var worker struct {
		TEE struct {
			Peer consolePeer `json:"peer"`
		} `json:"tee"`
	}
	raw, err = os.ReadFile(workerPath)
	if err == nil {
		err = json.Unmarshal(raw, &worker)
	}
	if err != nil {
		return console.Pass{}, "", console.Invite{}, fmt.Errorf("--worker-config: %w", err)
	}
	pin, err := consolePinOf(worker.TEE.Peer)
	if err != nil {
		return console.Pass{}, "", console.Invite{}, err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return console.Pass{}, "", console.Invite{}, err
	}
	code := hex.EncodeToString(buf)
	expires := time.Now().UTC().Add(valid).Truncate(time.Second)
	if label == "" {
		label = address
	}
	pass := console.Pass{
		Schema: console.PassSchema, ServerLabel: label, Address: address, ServerCertPEM: string(cert), Pin: pin,
		AuditPublicKeyPEM: string(auditKey), AuditKeyID: sagvd.Keys.AuditSigning.KID,
		InviteCode: code, InviteName: name, InviteRole: role, ExpiresAt: expires,
	}
	inviteFile := filepath.Join(sagvd.Console.Dir, "invites", console.InviteKey(code)+".json")
	if err := os.MkdirAll(filepath.Dir(inviteFile), 0o700); err != nil {
		return console.Pass{}, "", console.Invite{}, err
	}
	return pass, inviteFile, console.Invite{Name: name, Role: role, ExpiresAt: expires}, nil
}

// consolePinOf reads the peer's files into the pin.
func consolePinOf(p consolePeer) (console.Pin, error) {
	pin := console.Pin{
		Provider: p.Provider, AMDKDSURL: p.AMDKDSURL, MinReportedTCB: p.MinReportedTCB, SEVSNP: p.SEVSNP, CSPIDs: p.CSPIDs,
		PCRDigests: p.PCRDigests, PCRSelection: p.PCRSelection, GCEProjectIDs: p.GCEProjectIDs, PCSURL: p.PCSURL, AcceptableTCBStatuses: p.AcceptableTCBStatuses,
	}
	measurement, err := os.ReadFile(p.MeasurementPath)
	if err != nil {
		return console.Pin{}, fmt.Errorf("the pin of the authority: tee.peer.measurement_path: %w", err)
	}
	pin.MeasurementHex = hex.EncodeToString(measurement)
	if p.AMDCertChainPath != "" {
		chain, err := os.ReadFile(p.AMDCertChainPath)
		if err != nil {
			return console.Pin{}, fmt.Errorf("the pin of the authority: tee.peer.amd_cert_chain_path: %w", err)
		}
		pin.AMDCertChainPEM = string(chain)
	}
	if p.GCEEKAKRootsPath != "" {
		roots, err := os.ReadFile(p.GCEEKAKRootsPath)
		if err != nil {
			return console.Pin{}, fmt.Errorf("the pin of the authority: tee.peer.gce_ek_ak_roots_path: %w", err)
		}
		pin.GCEEKAKRootsPEM = string(roots)
	}
	if p.PublicKeyPath != "" {
		key, err := os.ReadFile(p.PublicKeyPath)
		if err != nil {
			return console.Pin{}, fmt.Errorf("the pin of the authority: tee.peer.public_key_path: %w", err)
		}
		pin.AttestorPublicKeyHex = hex.EncodeToString(key)
	}
	return pin, nil
}
