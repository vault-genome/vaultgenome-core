//go:build integration

// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The three commands of a two-host deployment (ADR 0028), on one machine
// with two deployment directories standing in for the two hosts: the
// authority writes the worker's bundle and keeps none of the worker's
// secrets; the worker joins from the carried bundle and writes its
// identity; the authority pins it. The daemons start on what the two
// directories hold, a sealed genome goes over the Return Path and comes
// back EXACT, and the audit log verifies under the key the authority
// kept.
func TestLiveDaemons_ProvisionAcrossTwoHosts(t *testing.T) {
	authorityOut := filepath.Join(t.TempDir(), "authority")
	workerOut := filepath.Join(t.TempDir(), "worker")
	vaultAddr, apiAddr, healthAddr, workerHealth := loopback(t), loopback(t), loopback(t), loopback(t)
	bundleDir := t.TempDir()
	binDir := filepath.Dir(bins.sagvd)

	// 1. The authority's host.
	summary := acpctl(t, "provision", "authority", "--out", authorityOut, "--bin-dir", binDir, "--provider", "simulated", "--insecure-simulation",
		"--vault-listen", vaultAddr, "--api-listen", apiAddr, "--vault-health", healthAddr, "--genome-dir", bundleDir, "--log-level", "debug")
	if !strings.Contains(summary, "worker bundle:") || strings.Contains(summary, "the-bearer") {
		t.Fatalf("provision authority: %s", summary)
	}
	bundle := filepath.Join(authorityOut, "worker-bundle.tar")
	if _, err := os.Stat(bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(authorityOut, "secrets", "acp-compute")); !os.IsNotExist(err) {
		t.Fatalf("the worker's secrets stayed on the authority's host: %v", err)
	}

	// The bundle carried to the worker's host, once.
	carried := filepath.Join(t.TempDir(), "worker-bundle.tar")
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(carried, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. The worker's host.
	summary = acpctl(t, "provision", "join", "--bundle", carried, "--out", workerOut, "--bin-dir", binDir, "--provider", "simulated", "--insecure-simulation",
		"--door-command", bins.fakedoor, "--worker-health", workerHealth, "--log-level", "debug")
	identity := filepath.Join(workerOut, "acp-compute-identity.json")
	if !strings.Contains(summary, "identity for the authority: "+identity) {
		t.Fatalf("provision join: %s", summary)
	}
	if _, err := os.Stat(filepath.Join(workerOut, "secrets", "sagvd")); !os.IsNotExist(err) {
		t.Fatalf("the authority's secrets reached the worker's host: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workerOut, "secrets", "acp-compute", "sealing.key")); err != nil {
		t.Fatalf("the worker's sealing key is not on the worker's host: %v", err)
	}

	// 3. The authority's host again, with the identity carried back.
	acpctl(t, "provision", "pin-worker", "--out", authorityOut, "--identity", identity)
	raw, err := os.ReadFile(filepath.Join(authorityOut, "provision.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pj struct {
		Phase        string            `json:"phase"`
		Secrets      string            `json:"secrets"`
		Configs      map[string]string `json:"configs"`
		APITokenFile string            `json:"api_token_file"`
		Vault        struct {
			MeasurementHex string `json:"measurement_hex"`
		} `json:"vault"`
		Worker struct {
			MeasurementHex string `json:"measurement_hex"`
		} `json:"worker"`
	}
	if err := json.Unmarshal(raw, &pj); err != nil {
		t.Fatal(err)
	}
	if pj.Phase != "complete" || pj.Worker.MeasurementHex == "" || pj.Vault.MeasurementHex == "" {
		t.Fatalf("provision.json after pin-worker: %+v", pj)
	}
	pin, err := os.ReadFile(filepath.Join(authorityOut, "pins", "worker.measurement"))
	if err != nil || hex.EncodeToString(pin) != pj.Worker.MeasurementHex {
		t.Fatalf("the worker's pin on the authority: %x (%v), want %s", pin, err, pj.Worker.MeasurementHex)
	}
	workerPin, err := os.ReadFile(filepath.Join(workerOut, "pins", "vault.measurement"))
	if err != nil || hex.EncodeToString(workerPin) != pj.Vault.MeasurementHex {
		t.Fatalf("the authority's pin on the worker: %x (%v), want %s", workerPin, err, pj.Vault.MeasurementHex)
	}
	tok, err := os.ReadFile(pj.APITokenFile)
	if err != nil {
		t.Fatal(err)
	}

	// The daemons, each on its own directory.
	v := &vault{secrets: pj.Secrets, token: strings.TrimSpace(string(tok)), vaultAddr: vaultAddr, apiURL: "http://" + apiAddr,
		healthURL: "http://" + healthAddr, bundleDir: bundleDir, auditLog: filepath.Join(authorityOut, "audit", "returnpath-audit.db"), cfgPath: pj.Configs["sagvd"]}
	v.proc = startProc(t, "sagvd", bins.sagvd, "-config", v.cfgPath)
	waitReady(t, v.proc, v.healthURL+"/readyz")
	w := startProc(t, "acp-compute", bins.worker, "-config", filepath.Join(workerOut, "acp-compute.json"))
	waitReady(t, w, "http://"+workerHealth+"/healthz")

	sealed := v.sealGenome(t, "gen-0", true)
	id, _ := v.submitGenome(t, sealed)
	job := v.waitJob(t, id, "succeeded", jobTimeout)
	if job.Gate == nil || job.Gate.Level != "EXACT" || job.Gate.SignerKeyID != "sagvd-authority-demo" {
		t.Fatalf("gate verdict across the two directories: %+v", job.Gate)
	}
	if job.Flow == nil || job.Flow.Attestation == nil || job.Flow.Attestation.Outcome != "allow" {
		t.Fatalf("the worker was not admitted by the pin pin-worker wrote: %+v", job.Flow)
	}

	if took, killed := w.stop(); killed {
		t.Fatalf("acp-compute had to be killed after %s", took)
	}
	if took, killed := v.proc.stop(); killed {
		t.Fatalf("sagvd had to be killed after %s", took)
	}
	var verified struct {
		OK         bool `json:"ok"`
		EventCount int  `json:"event_count"`
	}
	if err := json.Unmarshal([]byte(acpctl(t, "audit", "verify", "--audit", v.auditLog, "--audit-pubkey", filepath.Join(authorityOut, "operator", "audit_public_key.pem"),
		"--audit-kid", "sagvd-audit-demo", "--json")), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.OK || verified.EventCount < 10 {
		t.Fatalf("the audit log under the key the authority kept: %+v", verified)
	}
}
