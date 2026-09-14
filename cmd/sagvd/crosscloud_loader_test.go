// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ai-continuity-platform/core/internal/contracts/audit_event"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
)

// writeFile is a t.Helper that writes data to <dir>/<name> with
// 0600 permissions and returns the absolute path. Used to lay down
// fixtures (allow-list JSON, attestor pubkey files, registry JSON)
// in temp directories.
func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// makeMeasurementHex returns 64 hex chars (32 bytes) where every
// byte equals fillByte. Useful for distinct measurements per test.
func makeMeasurementHex(fillByte byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fillByte
	}
	return hex.EncodeToString(b)
}

// generateEd25519PubRaw returns a fresh 32-byte Ed25519 public key
// (raw, no PEM wrap).
func generateEd25519PubRaw(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub
}

// generateEd25519PubPEM returns a PEM-encoded SubjectPublicKeyInfo
// for a fresh Ed25519 key.
func generateEd25519PubPEM(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// --- LoadCrossCloudMaterials top-level path ------------------------

func TestLoadCrossCloudMaterials_DisabledReturnsNil(t *testing.T) {
	cfg := Config{} // CrossCloud.Enabled defaults to false
	materials, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatalf("LoadCrossCloudMaterials(disabled): %v", err)
	}
	if materials != nil {
		t.Fatal("LoadCrossCloudMaterials(disabled): want nil bundle")
	}
}

// --- loadVerifierRegistry -----------------------------------------

func TestLoadVerifierRegistry_HappyPath_RawPubkey(t *testing.T) {
	dir := t.TempDir()
	pubRaw := generateEd25519PubRaw(t)
	pubPath := writeFile(t, dir, "attestor.pub", pubRaw)

	registryJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "` + makeMeasurementHex(0x42) + `"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))

	registry, err := loadVerifierRegistry(regPath)
	if err != nil {
		t.Fatalf("loadVerifierRegistry: %v", err)
	}
	if registry.Len() != 1 {
		t.Errorf("registry.Len() = %d; want 1", registry.Len())
	}
	if !registry.Has(tee.ProviderSimulated) {
		t.Error("registry must hold ProviderSimulated entry")
	}
}

func TestLoadVerifierRegistry_HappyPath_PEMPubkey(t *testing.T) {
	dir := t.TempDir()
	pubPEM := generateEd25519PubPEM(t)
	pubPath := writeFile(t, dir, "attestor.pem", pubPEM)

	registryJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "` + makeMeasurementHex(0x42) + `"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))

	registry, err := loadVerifierRegistry(regPath)
	if err != nil {
		t.Fatalf("loadVerifierRegistry(PEM): %v", err)
	}
	if !registry.Has(tee.ProviderSimulated) {
		t.Error("registry must hold the PEM-keyed simulated entry")
	}
}

// Real SEV-SNP: the Evidence is signed by the chip's VCEK, which must
// chain to the AMD root the operator pins; measurements are 48 bytes.
func TestLoadVerifierRegistry_SEVSNP(t *testing.T) {
	dir := t.TempDir()
	chain := writeFile(t, dir, "amd-chain.pem", []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"))
	m48 := strings.Repeat("ab", 48)
	entry := func(extra string) string {
		return `{"verifiers":[{"provider":"gcp-sev-snp","expected_measurement_hex":"` + m48 + `"` + extra + `}]}`
	}

	reg, err := loadVerifierRegistry(writeFile(t, dir, "ok.json", []byte(entry(`,"amd_cert_chain_path":"`+chain+`","min_reported_tcb":7`))))
	if err != nil {
		t.Fatalf("loadVerifierRegistry(gcp-sev-snp): %v", err)
	}
	if !reg.Has(tee.ProviderGCPSEVSNP) {
		t.Fatal("registry must hold the gcp-sev-snp entry")
	}
	if _, err := loadVerifierRegistry(writeFile(t, dir, "nochain.json", []byte(entry("")))); err == nil || !strings.Contains(err.Error(), "amd_cert_chain_path") {
		t.Fatalf("gcp-sev-snp without an AMD chain: err = %v", err)
	}
	if _, err := loadVerifierRegistry(writeFile(t, dir, "badchain.json", []byte(entry(`,"amd_cert_chain_path":"`+filepath.Join(dir, "absent.pem")+`"`)))); err == nil {
		t.Fatal("gcp-sev-snp with an unreadable AMD chain was accepted")
	}
}

// Fail closed: a family whose verifier this build cannot run end to end
// is refused when the registry loads, not discovered at release time.
func TestLoadVerifierRegistry_RefusesFamiliesWithoutAWorkingVerifier(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pem", generateEd25519PubPEM(t))
	for _, provider := range []string{"aws-nitro", "azure-sgx", "intel-sgx-dcap"} {
		reg := `{"verifiers":[{"provider":"` + provider + `","attestor_pubkey_path":"` + pubPath + `","expected_measurement_hex":"` + makeMeasurementHex(0x42) + `"}]}`
		_, err := loadVerifierRegistry(writeFile(t, dir, provider+".json", []byte(reg)))
		if err == nil || !strings.Contains(err.Error(), "no verifier this build can run end to end") {
			t.Errorf("%s: err = %v, want a fail-closed refusal", provider, err)
		}
	}
}

func TestLoadVerifierRegistry_MissingFile(t *testing.T) {
	_, err := loadVerifierRegistry("/nonexistent/path/registry.json")
	if err == nil {
		t.Fatal("loadVerifierRegistry: want error on missing file")
	}
}

func TestLoadVerifierRegistry_EmptyVerifiersRejected(t *testing.T) {
	dir := t.TempDir()
	regPath := writeFile(t, dir, "registry.json", []byte(`{"verifiers":[]}`))
	_, err := loadVerifierRegistry(regPath)
	if err == nil || !strings.Contains(err.Error(), "at least one verifier") {
		t.Fatalf("loadVerifierRegistry(empty): err = %v", err)
	}
}

func TestLoadVerifierRegistry_BadProviderRejected(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))
	registryJSON := `{
		"verifiers": [
			{
				"provider": "vibes-tee",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "` + makeMeasurementHex(0x42) + `"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))
	_, err := loadVerifierRegistry(regPath)
	if err == nil || !strings.Contains(err.Error(), "vibes-tee") {
		t.Fatalf("loadVerifierRegistry(bad provider): err = %v", err)
	}
}

func TestLoadVerifierRegistry_BadHexRejected(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))
	registryJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "not-hex"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))
	_, err := loadVerifierRegistry(regPath)
	if err == nil {
		t.Fatal("loadVerifierRegistry(bad hex): want error")
	}
}

func TestLoadVerifierRegistry_WrongMeasurementSizeRejected(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))
	registryJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "1234"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))
	_, err := loadVerifierRegistry(regPath)
	if err == nil || !strings.Contains(err.Error(), "32-, 48- or 64-byte measurement") {
		t.Fatalf("loadVerifierRegistry(short measurement): err = %v", err)
	}
}

func TestLoadVerifierRegistry_UnknownJSONFieldRejected(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))
	registryJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "` + makeMeasurementHex(0x42) + `",
				"mystery_field": 1
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))
	_, err := loadVerifierRegistry(regPath)
	if err == nil || !strings.Contains(err.Error(), "mystery_field") {
		t.Fatalf("loadVerifierRegistry(unknown field): err = %v", err)
	}
}

// --- loadAttestorPubKey -------------------------------------------

func TestLoadAttestorPubKey_RawWrongSize(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "shortkey.pub", []byte{1, 2, 3})
	_, err := loadAttestorPubKey(pubPath)
	if err == nil || !strings.Contains(err.Error(), "want 32") {
		t.Fatalf("loadAttestorPubKey(short raw): err = %v", err)
	}
}

func TestLoadAttestorPubKey_PEMNonEd25519Rejected(t *testing.T) {
	dir := t.TempDir()
	// A valid-looking PEM block but with bogus DER inside.
	bogus := []byte("-----BEGIN PUBLIC KEY-----\nMTIz\n-----END PUBLIC KEY-----\n")
	pubPath := writeFile(t, dir, "bogus.pem", bogus)
	_, err := loadAttestorPubKey(pubPath)
	if err == nil {
		t.Fatal("loadAttestorPubKey(bogus PEM): want error")
	}
}

// --- loadAllowListPolicy -------------------------------------------

func TestLoadAllowListPolicy_HappyPath(t *testing.T) {
	dir := t.TempDir()
	allowJSON := `{
		"version": "xcc-test-v1",
		"allowed": {
			"aws-nitro": ["` + makeMeasurementHex(0x10) + `", "` + makeMeasurementHex(0x11) + `"],
			"azure-sgx": ["` + makeMeasurementHex(0x20) + `"]
		}
	}`
	path := writeFile(t, dir, "allow.json", []byte(allowJSON))
	policy, err := loadAllowListPolicy("xcc-test-v1", path)
	if err != nil {
		t.Fatalf("loadAllowListPolicy: %v", err)
	}
	if policy.PolicyVersion() != "xcc-test-v1" {
		t.Errorf("PolicyVersion = %q; want xcc-test-v1", policy.PolicyVersion())
	}
}

func TestLoadAllowListPolicy_VersionMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	allowJSON := `{
		"version": "xcc-test-OLD",
		"allowed": {"aws-nitro": ["` + makeMeasurementHex(0x10) + `"]}
	}`
	path := writeFile(t, dir, "allow.json", []byte(allowJSON))
	_, err := loadAllowListPolicy("xcc-test-NEW", path)
	if err == nil || !strings.Contains(err.Error(), "operator drift") {
		t.Fatalf("loadAllowListPolicy(version mismatch): err = %v", err)
	}
}

func TestLoadAllowListPolicy_BadHexRejected(t *testing.T) {
	dir := t.TempDir()
	allowJSON := `{
		"version": "v1",
		"allowed": {"aws-nitro": ["not-hex"]}
	}`
	path := writeFile(t, dir, "allow.json", []byte(allowJSON))
	_, err := loadAllowListPolicy("v1", path)
	if err == nil {
		t.Fatal("loadAllowListPolicy(bad hex): want error")
	}
}

func TestLoadAllowListPolicy_WrongMeasurementSizeRejected(t *testing.T) {
	dir := t.TempDir()
	allowJSON := `{
		"version": "v1",
		"allowed": {"aws-nitro": ["1234"]}
	}`
	path := writeFile(t, dir, "allow.json", []byte(allowJSON))
	_, err := loadAllowListPolicy("v1", path)
	if err == nil || !strings.Contains(err.Error(), "32-, 48- or 64-byte measurement") {
		t.Fatalf("loadAllowListPolicy(short measurement): err = %v", err)
	}
}

// A real SEV-SNP or Nitro measurement is 48 bytes and must be pinned
// whole, not rejected or truncated.
func TestLoadAllowListPolicy_AcceptsHardwareMeasurement(t *testing.T) {
	dir := t.TempDir()
	m48 := strings.Repeat("ab", 48)
	path := writeFile(t, dir, "allow.json", []byte(`{"version":"v1","allowed":{"gcp-sev-snp":["`+m48+`"]}}`))
	p, err := loadAllowListPolicy("v1", path)
	if err != nil {
		t.Fatalf("loadAllowListPolicy(48-byte measurement): %v", err)
	}
	m, _ := hex.DecodeString(m48)
	v, err := p.AuthorizeKeyRelease(tee.ProviderGCPSEVSNP, m, "dec-1", []ids.KeyID{"k1"})
	if err != nil || !v.Authorized {
		t.Fatalf("48-byte measurement not authorized: %+v, %v", v, err)
	}
}

func TestLoadAllowListPolicy_BadProviderRejected(t *testing.T) {
	dir := t.TempDir()
	allowJSON := `{
		"version": "v1",
		"allowed": {"vibes-tee": ["` + makeMeasurementHex(0x10) + `"]}
	}`
	path := writeFile(t, dir, "allow.json", []byte(allowJSON))
	_, err := loadAllowListPolicy("v1", path)
	if err == nil || !strings.Contains(err.Error(), "vibes-tee") {
		t.Fatalf("loadAllowListPolicy(bad provider): err = %v", err)
	}
}

// --- buildHTTPTransport -------------------------------------------

func TestBuildHTTPTransport_NoTLS(t *testing.T) {
	cfg := CrossCloudConfig{
		Enabled:               true,
		TransportBearerToken:  "secret",
		RequestTimeoutSeconds: 15,
	}
	tx, err := buildHTTPTransport(cfg)
	if err != nil {
		t.Fatalf("buildHTTPTransport: %v", err)
	}
	if tx == nil {
		t.Fatal("buildHTTPTransport returned nil transport")
	}
}

// --- LoadCrossCloudMaterials end-to-end happy path ----------------

func TestLoadCrossCloudMaterials_HappyPath(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))

	measHex := makeMeasurementHex(0x55)
	registryJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "` + measHex + `"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))

	allowJSON := `{
		"version": "xcc-2026-05-09",
		"allowed": {"simulated": ["` + measHex + `"]}
	}`
	allowPath := writeFile(t, dir, "allow.json", []byte(allowJSON))

	cfg := Config{
		CrossCloud: CrossCloudConfig{
			Enabled:               true,
			PolicyVersion:         "xcc-2026-05-09",
			PolicyAllowListPath:   allowPath,
			VerifierRegistryPath:  regPath,
			RequestTimeoutSeconds: 30,
		},
	}
	withAuditLog(t, dir, &cfg)
	materials, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatalf("LoadCrossCloudMaterials: %v", err)
	}
	if materials == nil {
		t.Fatal("LoadCrossCloudMaterials returned nil bundle (Enabled=true)")
	}
	defer func() { _ = materials.Close() }()
	if materials.VerifierRegistry == nil || materials.Policy == nil || materials.Transport == nil {
		t.Fatal("LoadCrossCloudMaterials: every field must be populated")
	}
	if !materials.VerifierRegistry.Has(tee.ProviderSimulated) {
		t.Error("registry must hold ProviderSimulated")
	}
	if materials.Policy.PolicyVersion() != "xcc-2026-05-09" {
		t.Errorf("policy version = %q; want xcc-2026-05-09", materials.Policy.PolicyVersion())
	}
}

// withAuditLog points cfg at a fresh durable audit log in dir and a
// signing seed for it, as `keygen` provisions them.
func withAuditLog(t *testing.T, dir string, cfg *Config) {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	cfg.Keys.AuditSigning = SigningKeyConfig{KeyID: "xcc-audit-test", SeedPath: writeFile(t, dir, "audit_signing_seed", seed)}
	cfg.CrossCloud.AuditLogPath = filepath.Join(dir, "xcc-audit.db")
}

// simulatedCrossCloudConfig is a minimal enabled cross-cloud config in dir.
func simulatedCrossCloudConfig(t *testing.T, dir string) Config {
	t.Helper()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))
	meas := makeMeasurementHex(0x55)
	reg := writeFile(t, dir, "registry.json", []byte(`{"verifiers":[{"provider":"simulated","attestor_pubkey_path":"`+pubPath+`","expected_measurement_hex":"`+meas+`"}]}`))
	allow := writeFile(t, dir, "allow.json", []byte(`{"version":"v1","allowed":{"simulated":["`+meas+`"]}}`))
	cfg := Config{CrossCloud: CrossCloudConfig{Enabled: true, PolicyVersion: "v1", PolicyAllowListPath: allow, VerifierRegistryPath: reg}}
	withAuditLog(t, dir, &cfg)
	return cfg
}

// The audit log is one chain across runs: a second crosscloud-restore
// sees the first one's events, continues their numbering, and extends
// the same verified chain.
func TestLoadCrossCloudMaterials_AuditLogSpansRuns(t *testing.T) {
	cfg := simulatedCrossCloudConfig(t, t.TempDir())
	emit := func(m *crossCloudMaterials) ids.AuditEventID {
		id, err := m.AuditEmitter.Emit(audit_event.KindCrossCloudHandshakeInitiated, []byte(`{}`), "", "", "req-1")
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	first, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatal(err)
	}
	emit(first)
	emit(first)
	tip := first.AuditChain.Tip()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatalf("reopening a verified log: %v", err)
	}
	defer func() { _ = second.Close() }()
	if second.AuditChain.Len() != 2 || string(second.AuditChain.Tip()) != string(tip) {
		t.Fatalf("second run sees %d events; want the first run's 2 with the same tip", second.AuditChain.Len())
	}
	if id := emit(second); id != "xcc-evt-0000000000000003" {
		t.Fatalf("event ID %q does not continue the log", id)
	}
}

// A log signed under a different audit key does not verify, and a log
// that does not verify stops every release.
func TestLoadCrossCloudMaterials_RefusesLogItCannotVerify(t *testing.T) {
	dir := t.TempDir()
	cfg := simulatedCrossCloudConfig(t, dir)
	m, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AuditEmitter.Emit(audit_event.KindCrossCloudHandshakeInitiated, []byte(`{}`), "", "", "req-1"); err != nil {
		t.Fatal(err)
	}
	_ = m.Close()

	other := make([]byte, 32)
	if _, err := rand.Read(other); err != nil {
		t.Fatal(err)
	}
	cfg.Keys.AuditSigning.SeedPath = writeFile(t, dir, "other_seed", other)
	if m, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock()); err == nil {
		_ = m.Close()
		t.Fatal("a log signed under another audit key was accepted")
	} else if !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}
