//go:build integration

// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Continuity Drill in miniature, with the shipping binaries: a genome
// sealed on the source (acpctl) sits on the destination as an opaque
// bundle; the operator's policy releases its key to the attested
// destination (sagvd crosscloud-restore); the destination restores it by
// itself (acp-bootstrap); the source confirms the restore from the
// destination's TEE-signed receipt (sagvd crosscloud-confirm). Every step
// is on the audit record, and the restored tree is the sealed tree, byte
// for byte.

// confirmResult is what `sagvd crosscloud-confirm` prints.
type confirmResult struct {
	Status string `json:"status"`
	Error  *struct {
		Category string `json:"category"`
		Message  string `json:"message"`
	} `json:"error"`
	KeyID                  string  `json:"key_id"`
	DestinationMeasurement string  `json:"destination_measurement_hex"`
	BundleSHA256           string  `json:"bundle_sha256"`
	PayloadSHA256          string  `json:"payload_sha256"`
	TreeSHA256             string  `json:"tree_sha256"`
	Files                  int     `json:"files"`
	Bytes                  int64   `json:"bytes"`
	RestoreSeconds         float64 `json:"restore_seconds"`
	KeyToRestoredSeconds   float64 `json:"key_to_restored_seconds"`
	MatchedOperatorBundle  bool    `json:"matched_operator_bundle"`
	AuditID                string  `json:"audit_id"`
	AuditChainLength       int     `json:"audit_chain_length"`
	AuditTip               string  `json:"audit_tip"`
}

// fineTuneOutput writes what a LoRA fine-tune leaves behind; the weights
// are random, so nothing about them compresses or repeats, and large
// enough to span several bundle segments.
func fineTuneOutput(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	weights := make([]byte, 3<<20+12345)
	if _, err := rand.Read(weights); err != nil {
		t.Fatal(err)
	}
	for rel, data := range map[string][]byte{
		"adapter_config.json":             []byte(`{"base_model_name_or_path":"Qwen/Qwen2.5-0.5B","r":16,"lora_alpha":32,"target_modules":["q_proj","v_proj"]}`),
		"adapter_model.safetensors":       weights,
		"tokenizer/tokenizer_config.json": []byte(`{"eos_token":"<|im_end|>"}`),
	} {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func treeOf(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		out[filepath.ToSlash(rel)] = data
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// replicate copies a bundle into dir the way an operator's sync should:
// under a temporary name, then renamed, so no half-written bundle is
// ever visible as *.genome.
func replicate(t *testing.T, bundle, dir string) {
	t.Helper()
	raw, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, ".incoming-"+filepath.Base(bundle))
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, filepath.Base(bundle))); err != nil {
		t.Fatal(err)
	}
}

func (x *xcc) confirm(t *testing.T, config string, args ...string) (confirmResult, string, error) {
	t.Helper()
	var res confirmResult
	out, err := runJSON(t, &res, bins.sagvd, append([]string{"crosscloud-confirm", "-config", config}, args...)...)
	return res, out, err
}

// destinationGET calls the destination API as the source does: mTLS and
// the bearer token.
func (x *xcc) destinationGET(t *testing.T, path string) (int, []byte) {
	t.Helper()
	sec := func(p ...string) string { return filepath.Join(append([]string{x.secrets}, p...)...) }
	cert, err := tls.LoadX509KeyPair(sec("acp-compute", "tls", "client.crt"), sec("acp-compute", "tls", "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(sec("shared", "tls", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool,
	}}}
	req, err := http.NewRequest(http.MethodGet, x.endpoint+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+x.token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func TestLiveGenomeDrill_SealReleaseRestoreConfirm(t *testing.T) {
	x := newXCC(t)

	// 1. Seal the fine-tune output. The key goes to a 0600 file; the
	// bundle holds no key.
	adapter := fineTuneOutput(t)
	vault := t.TempDir()
	bundlePath, keyPath := filepath.Join(vault, "gen-0.genome"), filepath.Join(vault, "gen-0.key")
	var sealed struct {
		KeyID         string `json:"key_id"`
		PayloadSHA256 string `json:"payload_sha256"`
		BundleBytes   int64  `json:"bundle_bytes"`
	}
	if err := json.Unmarshal([]byte(acpctl(t, "genome", "seal", "--content-dir", adapter,
		"--output", bundlePath, "--key-out", keyPath, "--json")), &sealed); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed.KeyID, "genome-") {
		t.Fatalf("seal: key id %q", sealed.KeyID)
	}

	// 2. The destination holds the bundle before any release: opaque
	// without its key.
	root := t.TempDir()
	bundles, restored := filepath.Join(root, "bundles"), filepath.Join(root, "restored")
	if err := os.MkdirAll(bundles, 0o755); err != nil {
		t.Fatal(err)
	}
	replicate(t, bundlePath, bundles)
	destCfg := x.destinationConfig(t, "destination", map[string]any{
		"genome": map[string]any{"bundle_dir": bundles, "restore_dir": restored, "rescan_seconds": 1},
	})
	id := identityOf(t, bins.bootstrap, destCfg)
	x.startDestination(t, destCfg)
	srcCfg := x.sourceConfig(t, id, id["measurement_hex"])

	// Nothing to confirm before a release.
	if res, _, err := x.confirm(t, srcCfg, "-decision-id", "drill-genome-1",
		"-destination-endpoint", x.endpoint, "-bundle", bundlePath); err == nil || res.Error == nil || res.Error.Category != "authority" {
		t.Fatalf("confirm before any release: err=%v result=%+v", err, res)
	}

	// 3. The operator's policy releases the genome key.
	rel, out, err := x.release(t, srcCfg, x.endpoint, "drill-genome-1", sealed.KeyID+":"+keyPath)
	if err != nil || rel.Status != "ok" {
		t.Fatalf("release: %v\n%s", err, out)
	}

	// 4. The destination restores by itself; the source confirms from its
	// signed receipt, checked against the bundle it holds.
	conf, out, err := x.confirm(t, srcCfg, "-decision-id", "drill-genome-1",
		"-destination-endpoint", x.endpoint, "-bundle", bundlePath, "-wait", "30s")
	if err != nil || conf.Status != "ok" {
		t.Fatalf("confirm: %v\n%s", err, out)
	}
	if !conf.MatchedOperatorBundle || conf.KeyID != sealed.KeyID || conf.PayloadSHA256 != sealed.PayloadSHA256 ||
		conf.DestinationMeasurement != id["measurement_hex"] || conf.Files != 3 {
		t.Fatalf("confirmation: %+v", conf)
	}
	t.Logf("drill: %d files, %d bytes restored in %.3fs (key to restored %.3fs); tree %s",
		conf.Files, conf.Bytes, conf.RestoreSeconds, conf.KeyToRestoredSeconds, conf.TreeSHA256)

	// 5. The restored tree is the sealed tree, and acpctl agrees with the
	// key the operator holds.
	target := filepath.Join(restored, sealed.KeyID)
	want, got := treeOf(t, adapter), treeOf(t, target)
	if len(want) != len(got) {
		t.Fatalf("restored %d files, sealed %d", len(got), len(want))
	}
	for p, data := range want {
		if !bytes.Equal(got[p], data) {
			t.Fatalf("restored %s differs from the sealed file", p)
		}
	}
	var verified struct {
		OK            bool   `json:"ok"`
		Authenticated bool   `json:"authenticated"`
		TreeSHA256    string `json:"tree_sha256"`
	}
	if err := json.Unmarshal([]byte(acpctl(t, "genome", "verify", "--bundle", bundlePath,
		"--key-file", keyPath, "--restored", target, "--json")), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.OK || !verified.Authenticated || verified.TreeSHA256 != conf.TreeSHA256 {
		t.Fatalf("acpctl genome verify: %+v, confirmed tree %s", verified, conf.TreeSHA256)
	}

	// 6. On record: handshake, attestation, release, restore confirmed —
	// and the log verifies to the tip the confirmation reported.
	if ok, events, tip := x.auditVerify(t); !ok || events != 4 || tip != conf.AuditTip {
		t.Fatalf("audit log: ok=%v events=%d tip=%s, confirm tip %s", ok, events, tip, conf.AuditTip)
	}

	// 7. The destination's own account, over its authenticated API.
	code, body := x.destinationGET(t, "/v1/genome/restores")
	if code != http.StatusOK || !strings.Contains(string(body), `"state":"restored"`) || !strings.Contains(string(body), sealed.KeyID) {
		t.Fatalf("GET /v1/genome/restores: %d %s", code, body)
	}
	if n := len(x.destLog("genome restored")); n != 1 {
		t.Fatalf("destination logged %d restores, want 1", n)
	}
	if n := len(x.destLog("genome key erased after restore")); n != 1 {
		t.Fatalf("destination erased %d keys after the restore, want 1", n)
	}

	// 8. A confirmation cannot be claimed for a genome the operator does
	// not hold: a different bundle is refused, and nothing is recorded.
	other := filepath.Join(vault, "other.genome")
	acpctl(t, "genome", "seal", "--content-dir", fineTuneOutput(t), "--output", other, "--key-out", filepath.Join(vault, "other.key"))
	res, _, err := x.confirm(t, srcCfg, "-decision-id", "drill-genome-1", "-destination-endpoint", x.endpoint, "-bundle", other)
	if err == nil || res.Error == nil || res.Error.Category != "authority" {
		t.Fatalf("confirm with a genome that was not released: err=%v result=%+v", err, res)
	}
	if ok, events, _ := x.auditVerify(t); !ok || events != 4 {
		t.Fatalf("a refused confirmation changed the audit log: ok=%v events=%d", ok, events)
	}
}
