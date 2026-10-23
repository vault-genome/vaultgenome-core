// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The delegated verifier against a live Veraison with a real GCP SEV-SNP
// report (testdata/veraison): the session is opened with the report's
// REPORT_DATA — what the handshake would derive for this report's
// challenge — the TSM report is posted in its JSON form under its media
// type, the EAR comes back signed by Veraison's key (taken from its
// well-known document over the same TLS), is verified and judged, and
// the measurement read from the report is what the Verifier affirmed.
// Runs only with VG_VERAISON_URL set (scripts/hardware-test/veraison-live);
// VG_VERAISON_CA, VG_VERAISON_CLIENT_CERT and VG_VERAISON_CLIENT_KEY are
// the bench's TLS files; VG_VERAISON_EVIDENCE_DIR keeps the record.
func TestRATSVerifier_LiveVeraison_GCPSEVSNPReport(t *testing.T) {
	url := os.Getenv("VG_VERAISON_URL")
	if url == "" {
		t.Skip("VG_VERAISON_URL not set: the live Veraison bench run (scripts/hardware-test/veraison-live)")
	}
	read := func(env string) []byte {
		p := os.Getenv(env)
		if p == "" {
			return nil
		}
		b, err := os.ReadFile(p)
		require.NoError(t, err, env)
		return b
	}
	caPEM, clientCert, clientKey := read("VG_VERAISON_CA"), read("VG_VERAISON_CLIENT_CERT"), read("VG_VERAISON_CLIENT_KEY")

	value, err := os.ReadFile(filepath.Join("testdata", "veraison", "sevsnp-gcp-tsm-report.json"))
	require.NoError(t, err)
	fixtureSum := sha256.Sum256(value)
	report, aux, err := UnwrapEvidence(ProviderGCPSEVSNP, MediaTypeTSMReportJSON, value)
	require.NoError(t, err)
	require.Len(t, report, 1184)
	reportData := []byte(report[0x50:0x90])
	measurement := Measurement(report[0x90:0xC0])

	// The Verifier's key, as its well-known document publishes it.
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPEM != nil {
		pool := x509.NewCertPool()
		require.True(t, pool.AppendCertsFromPEM(caPEM))
		tlsCfg.RootCAs = pool
	}
	if clientCert != nil {
		pair, err := tls.X509KeyPair(clientCert, clientKey)
		require.NoError(t, err)
		tlsCfg.Certificates = []tls.Certificate{pair}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}, Timeout: 20 * time.Second}
	resp, err := client.Get(url + "/.well-known/veraison/verification")
	require.NoError(t, err)
	wellKnown, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(wellKnown))
	var wk struct {
		Key        json.RawMessage `json:"ear-verification-key"`
		MediaTypes []string        `json:"media-types"`
		Version    string          `json:"version"`
	}
	require.NoError(t, json.Unmarshal(wellKnown, &wk))
	require.Contains(t, wk.MediaTypes, MediaTypeTSMReportJSON, "Veraison takes the TSM report in JSON")
	key, err := ParseEARPublicKey(wk.Key)
	require.NoError(t, err)

	v, err := NewRATSVerifier(ProviderGCPSEVSNP, measurement, RATSVerifierConfig{
		URL: url, EARPublicKey: key, CAPEM: caPEM, ClientCertPEM: clientCert, ClientKeyPEM: clientKey, Submod: "SEVSNP", Timeout: 20 * time.Second,
	})
	require.NoError(t, err)

	// The session as the handshake opens it for this report.
	start := time.Now()
	ear, err := v.appraise(MediaTypeTSMReportJSON, value, reportData)
	elapsed := time.Since(start)
	require.NoError(t, err)
	require.Equal(t, reportData, ear.Nonce, "eat_nonce is the session's nonce, the report's REPORT_DATA")
	sub, ok := ear.Submods["SEVSNP"]
	require.True(t, ok, "submods: %v", submodNames(ear))
	t.Logf("Veraison %s: SEVSNP %s, policy %q, trust vector %v, verifier %+v, %s", wk.Version, sub.Status, sub.PolicyID, sub.TrustVector, ear.VerifierID, elapsed)

	// The pin is read from the report this side posted — the field Veraison appraised.
	local, err := localMeasurement(ProviderGCPSEVSNP, value)
	require.NoError(t, err)
	require.True(t, measurement.Equal(local))
	require.Equal(t, EARStatusAffirming, sub.Status, "the report is one Veraison was provisioned for (the launch measurement as a reference value, AMD's root as the trust anchor)")
	require.Equal(t, 2, sub.TrustVector["hardware"], "genuine hardware")
	require.Equal(t, 2, sub.TrustVector["runtime-opaque"], "encrypted memory")

	if dir := os.Getenv("VG_VERAISON_EVIDENCE_DIR"); dir != "" {
		require.NoError(t, os.MkdirAll(dir, 0o755))
		write := func(name string, b []byte) { require.NoError(t, os.WriteFile(filepath.Join(dir, name), b, 0o644)) }
		write("well-known.json", wellKnown)
		write("ear.jwt", []byte(ear.Raw))
		summary, _ := json.MarshalIndent(map[string]any{
			"verifier_url": url, "veraison_version": wk.Version, "media_type": MediaTypeTSMReportJSON,
			"fixture": "testdata/veraison/sevsnp-gcp-tsm-report.json", "fixture_sha256": hex.EncodeToString(fixtureSum[:]),
			"report_bytes": len(report), "auxblob_bytes": len(aux), "posted_bytes": len(value),
			"session_nonce_hex": hex.EncodeToString(reportData), "measurement_hex": hex.EncodeToString(measurement),
			"ear_submod": "SEVSNP", "ear_status": sub.Status, "ear_policy_id": sub.PolicyID, "ear_trust_vector": sub.TrustVector,
			"ear_verifier_id": ear.VerifierID, "ear_iat": ear.IssuedAt, "ear_nonce_equals_session": bytes.Equal(ear.Nonce, reportData),
			"local_measurement_equals_pin": measurement.Equal(local), "round_trip_ms": elapsed.Milliseconds(),
		}, "", "  ")
		write("summary.json", summary)
	}
}
