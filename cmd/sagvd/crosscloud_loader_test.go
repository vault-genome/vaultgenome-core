// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
				"provider": "aws-nitro",
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
	if !registry.Has(tee.ProviderAWSNitro) {
		t.Error("registry must hold ProviderAWSNitro entry")
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
	materials, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatalf("LoadCrossCloudMaterials: %v", err)
	}
	if materials == nil {
		t.Fatal("LoadCrossCloudMaterials returned nil bundle (Enabled=true)")
	}
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
