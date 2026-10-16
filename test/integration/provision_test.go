//go:build integration

// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One command stands up the deployment the other tests build by hand:
// acpctl provision runs the release's acp-keygen, writes both daemons'
// configurations, reads each daemon's identity and pins it on the other
// side, keeps the operator's copy of the REST token and the audit public
// key, and seals every key file to the host. The daemons start on what it
// wrote, a sealed genome goes over the Return Path and comes back EXACT,
// and the audit log verifies under the key provision kept.
func TestLiveDaemons_ProvisionStandsUpTheDeployment(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	vaultAddr, apiAddr, healthAddr, workerHealth := loopback(t), loopback(t), loopback(t), loopback(t)
	bundleDir := t.TempDir()
	summary := acpctl(t, "provision", "--out", out, "--bin-dir", filepath.Dir(bins.sagvd), "--provider", "simulated", "--insecure-simulation",
		"--door-command", bins.fakedoor, "--vault-listen", vaultAddr, "--api-listen", apiAddr, "--vault-health", healthAddr, "--worker-health", workerHealth,
		"--genome-dir", bundleDir, "--log-level", "debug")
	if strings.Contains(summary, "not printed") == false {
		t.Fatalf("provision did not say where the token is: %s", summary)
	}
	raw, err := os.ReadFile(filepath.Join(out, "provision.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pj struct {
		Secrets      string            `json:"secrets"`
		Configs      map[string]string `json:"configs"`
		APITokenFile string            `json:"api_token_file"`
		Vault        struct {
			MeasurementHex    string `json:"measurement_hex"`
			AuditPublicKeyPEM string `json:"audit_public_key_pem"`
		} `json:"vault"`
		Worker struct {
			MeasurementHex string `json:"measurement_hex"`
		} `json:"worker"`
		Sealed map[string][]string `json:"sealed"`
	}
	if err := json.Unmarshal(raw, &pj); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(summary, "the-bearer") || len(pj.Sealed["sagvd"]) < 3 || len(pj.Sealed["acp-compute"]) < 2 {
		t.Fatalf("provision.json sealed: %v", pj.Sealed)
	}
	tok, err := os.ReadFile(pj.APITokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if sealedTok, _ := os.ReadFile(filepath.Join(pj.Secrets, "sagvd", "api_token")); string(sealedTok) == string(tok) || !strings.Contains(string(sealedTok), `"schema"`) {
		t.Fatalf("the token on the host is not sealed: %s", sealedTok)
	}
	for side, pin := range map[string]string{"vault": pj.Vault.MeasurementHex, "worker": pj.Worker.MeasurementHex} {
		got, err := os.ReadFile(filepath.Join(out, "pins", side+".measurement"))
		if err != nil || len(got) != 32 {
			t.Fatalf("pin %s: %v (%d bytes)", side, err, len(got))
		}
		if pin == "" {
			t.Fatalf("provision.json has no %s measurement", side)
		}
	}

	v := &vault{secrets: pj.Secrets, token: strings.TrimSpace(string(tok)), vaultAddr: vaultAddr, apiURL: "http://" + apiAddr,
		healthURL: "http://" + healthAddr, bundleDir: bundleDir, auditLog: filepath.Join(out, "audit", "returnpath-audit.db"), cfgPath: pj.Configs["sagvd"]}
	v.proc = startProc(t, "sagvd", bins.sagvd, "-config", v.cfgPath)
	waitReady(t, v.proc, v.healthURL+"/readyz")
	w := startProc(t, "acp-compute", bins.worker, "-config", pj.Configs["acp-compute"])
	waitReady(t, w, "http://"+workerHealth+"/healthz")

	sealed := v.sealGenome(t, "gen-0", true)
	id, _ := v.submitGenome(t, sealed)
	job := v.waitJob(t, id, "succeeded", jobTimeout)
	if job.Gate == nil || job.Gate.Level != "EXACT" || job.Gate.SignerKeyID != "sagvd-authority-demo" {
		t.Fatalf("gate verdict on the provisioned deployment: %+v", job.Gate)
	}
	if job.Flow == nil || job.Flow.Attestation == nil || job.Flow.Attestation.Outcome != "allow" {
		t.Fatalf("the worker was not admitted by the pin provision wrote: %+v", job.Flow)
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
	if err := json.Unmarshal([]byte(acpctl(t, "audit", "verify", "--audit", v.auditLog, "--audit-pubkey", filepath.Join(out, "operator", "audit_public_key.pem"),
		"--audit-kid", "sagvd-audit-demo", "--json")), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.OK || verified.EventCount < 10 {
		t.Fatalf("the audit log under the key provision kept: %+v", verified)
	}
}
