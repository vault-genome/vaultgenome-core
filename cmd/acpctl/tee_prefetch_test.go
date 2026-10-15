// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTEEConfig(t *testing.T, dir string, cfg map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"tee": cfg})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "daemon.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func vcekLikeDER(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "SEV-VCEK"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestTeeCacheStatus_ReadsTheConfiguredCaches(t *testing.T) {
	dir := t.TempDir()
	vcek := filepath.Join(dir, "vcek-cache")
	if err := os.MkdirAll(vcek, 0o755); err != nil {
		t.Fatal(err)
	}
	chip := strings.Repeat("cd", 64)
	if err := os.WriteFile(filepath.Join(vcek, chip+"-15.der"), vcekLikeDER(t, time.Now().Add(400*24*time.Hour)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeTEEConfig(t, dir, map[string]any{
		"provider": "gcp-sev-snp",
		"peer":     map[string]any{"provider": "gcp-sev-snp", "amd_cert_chain_path": filepath.Join(dir, "chain.pem"), "vcek_cache_dir": vcek},
	})

	var out, errOut bytes.Buffer
	if code := teeCmd([]string{"cache-status", "--config", cfgPath}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"vcek      current", chip + "-15.der", "SEV-VCEK", "TCB 15", "1 of 1 current", "the earliest expiry is"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}

	// --json: the entries as the tee package reports them.
	out.Reset()
	if code := teeCmd([]string{"cache-status", "--config", cfgPath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("json exit %d: %s", code, errOut.String())
	}
	var entries []map[string]any
	if err := json.Unmarshal(out.Bytes(), &entries); err != nil || len(entries) != 1 || entries[0]["kind"] != "vcek" || entries[0]["current"] != true {
		t.Fatalf("json entries: %v %s", err, out.String())
	}

	// An expired VCEK beside it: exit 1, named as such.
	if err := os.WriteFile(filepath.Join(vcek, chip+"-7.der"), vcekLikeDER(t, time.Now().Add(-time.Minute)), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := teeCmd([]string{"cache-status", "--config", cfgPath}, &out, &errOut); code != 1 {
		t.Fatalf("exit %d with an expired VCEK: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "EXPIRED or unusable") || !strings.Contains(out.String(), "1 of 2 current") {
		t.Fatalf("expired VCEK not reported:\n%s", out.String())
	}
}

func TestTeeCacheStatus_RefusesWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	// No cache directory named at all.
	cfgPath := writeTEEConfig(t, dir, map[string]any{"provider": "simulated", "peer": map[string]any{"provider": "simulated"}})
	if code := teeCmd([]string{"cache-status", "--config", cfgPath}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "names no cache directory") {
		t.Fatalf("no cache dirs: exit %d: %s", code, errOut.String())
	}
	// A cache directory that is empty (or absent).
	errOut.Reset()
	cfgPath = writeTEEConfig(t, dir, map[string]any{"provider": "gcp-tdx", "peer": map[string]any{"provider": "gcp-tdx", "pcs_cache_dir": filepath.Join(dir, "pcs")}})
	if code := teeCmd([]string{"cache-status", "--config", cfgPath}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "the caches are empty") {
		t.Fatalf("empty cache: exit %d: %s", code, errOut.String())
	}
	// No --config.
	if code := teeCmd([]string{"cache-status"}, &out, &errOut); code != 2 {
		t.Fatalf("no --config: exit %d", code)
	}
	// A file that is not a configuration.
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{"), 0o600)
	if code := teeCmd([]string{"cache-status", "--config", bad}, &out, &errOut); code != 1 {
		t.Fatalf("bad config: exit %d", code)
	}
}

func TestTeePrefetch_RefusalsBeforeAnyHardwareIsTouched(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	run := func(cfg map[string]any) (int, string, string) {
		out.Reset()
		errOut.Reset()
		code := teeCmd([]string{"prefetch", "--config", writeTEEConfig(t, dir, cfg)}, &out, &errOut)
		return code, out.String(), errOut.String()
	}

	// A simulated TEE asks no vendor: nothing to do, not an error.
	if code, o, _ := run(map[string]any{"provider": "simulated", "peer": map[string]any{"provider": "simulated"}}); code != 0 || !strings.Contains(o, "nothing to prefetch") {
		t.Fatalf("simulated: exit %d: %s", code, o)
	}
	// This host's family and the peer's differ: prefetch runs on a host of the peer's family.
	if code, _, e := run(map[string]any{"provider": "gcp-sev-snp", "peer": map[string]any{"provider": "gcp-tdx", "pcs_cache_dir": dir}}); code != 1 || !strings.Contains(e, "this host is gcp-sev-snp and the peer is gcp-tdx") {
		t.Fatalf("families differ: exit %d: %s", code, e)
	}
	// auto off a confidential VM: the refusal names configfs-tsm, nothing else is tried.
	if code, _, e := run(map[string]any{"provider": "auto", "tsm_report_dir": dir, "peer": map[string]any{"provider": "gcp-sev-snp", "vcek_cache_dir": dir}}); code != 1 || !strings.Contains(e, "configfs-tsm") {
		t.Fatalf("auto off hardware: exit %d: %s", code, e)
	}
	// No cache directory to fill.
	if code, _, e := run(map[string]any{"provider": "gcp-sev-snp", "peer": map[string]any{"provider": "gcp-sev-snp", "amd_cert_chain_path": filepath.Join(dir, "chain.pem")}}); code != 1 || !strings.Contains(e, "vcek_cache_dir is not set") {
		t.Fatalf("no vcek cache: exit %d: %s", code, e)
	}
	if code, _, e := run(map[string]any{"provider": "gcp-tdx", "peer": map[string]any{"provider": "gcp-tdx"}}); code != 1 || !strings.Contains(e, "pcs_cache_dir is not set") {
		t.Fatalf("no pcs cache: exit %d: %s", code, e)
	}
	// The AMD chain file is missing: the refusal names fetch-amd-chain.
	if code, _, e := run(map[string]any{"provider": "gcp-sev-snp", "peer": map[string]any{"provider": "gcp-sev-snp", "amd_cert_chain_path": filepath.Join(dir, "missing.pem"), "vcek_cache_dir": dir}}); code != 1 || !strings.Contains(e, "fetch-amd-chain") {
		t.Fatalf("missing chain: exit %d: %s", code, e)
	}
	// A family prefetch does not cover.
	if code, _, e := run(map[string]any{"provider": "azure-cgpu", "peer": map[string]any{"provider": "azure-cgpu", "vcek_cache_dir": dir}}); code != 1 || !strings.Contains(e, "prefetch covers gcp-sev-snp and gcp-tdx") {
		t.Fatalf("uncovered family: exit %d: %s", code, e)
	}
	// Nothing set.
	if code, _, e := run(map[string]any{"peer": map[string]any{"provider": "gcp-sev-snp"}}); code != 1 || !strings.Contains(e, "tee.provider is not set") {
		t.Fatalf("no provider: exit %d: %s", code, e)
	}
	if code, _, e := run(map[string]any{"provider": "gcp-sev-snp"}); code != 1 || !strings.Contains(e, "tee.peer.provider is not set") {
		t.Fatalf("no peer: exit %d: %s", code, e)
	}
	if code := teeCmd([]string{"prefetch"}, &out, &errOut); code != 2 {
		t.Fatalf("no --config: exit %d", code)
	}
}

func TestTeeHelp_ListsTheNewSubcommands(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := teeCmd([]string{"help"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"fetch-amd-chain", "prefetch", "cache-status"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("help lacks %s:\n%s", want, out.String())
		}
	}
}
