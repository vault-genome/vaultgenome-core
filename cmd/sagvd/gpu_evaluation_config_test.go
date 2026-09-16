// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ai-continuity-platform/core/internal/shared/tee"
	"github.com/stretchr/testify/require"
)

// The GPU policy names whose evaluation the verdict rests on: NVIDIA's
// (the default), both, or the verifier's own — which this build refuses,
// since it does not verify the manifests' signatures.
func TestGPUPolicyConfig_Evaluation(t *testing.T) {
	var none *GPUPolicyConfig
	require.NoError(t, none.validate())
	for _, ok := range []string{"", "nras", "both"} {
		require.NoError(t, (&GPUPolicyConfig{Evaluation: ok}).validate(), ok)
	}
	require.ErrorContains(t, (&GPUPolicyConfig{Evaluation: "own"}).validate(), "XML signatures")
	require.ErrorContains(t, (&GPUPolicyConfig{Evaluation: "nvidia-plus"}).validate(), "one of nras, both")

	dir := t.TempDir()
	root := filepath.Join(dir, "root.pem")
	require.NoError(t, os.WriteFile(root, []byte(tee.NVIDIADeviceRootPEM), 0o600))
	g := &GPUPolicyConfig{Evaluation: "both", RIMServiceURL: "https://rim.example/v1/rim/", RIMCacheDir: dir, NVIDIADeviceRootPath: root}
	var cfg tee.AzureCGPUVerifierConfig
	require.NoError(t, g.apply(&cfg))
	require.Equal(t, tee.GPUEvaluationBoth, cfg.GPUEvaluation)
	require.Equal(t, "https://rim.example/v1/rim/", cfg.RIMServiceURL)
	require.Equal(t, dir, cfg.RIMCacheDir)
	require.Equal(t, []byte(tee.NVIDIADeviceRootPEM), cfg.NVIDIADeviceRootPEM)
	require.Nil(t, cfg.NVIDIARIMRootPEM, "the pinned RIM root stays")
	g.NVIDIARIMRootPath = filepath.Join(dir, "missing.pem")
	require.ErrorContains(t, g.apply(&cfg), "nvidia_rim_root_path")
	require.NoError(t, none.apply(&cfg))
}

// A peer or registry entry that asks for "own" is refused at validation,
// before any handshake.
func TestConfig_RefusesOwnGPUEvaluationInThisBuild(t *testing.T) {
	c := minimalValidConfig()
	c.TEE.Provider = "azure-cgpu"
	c.TEE.GPUAttestCommand = []string{"gpu-token"}
	c.TEE.Peer = PeerTEEConfig{Provider: "azure-cgpu", MeasurementPath: "/m", AMDCertChainPath: "/c", GPUPolicy: &GPUPolicyConfig{Evaluation: "own"}}
	require.ErrorContains(t, c.Validate(), "gpu_policy.evaluation")
	c.TEE.Peer.GPUPolicy.Evaluation = "both"
	err := c.Validate()
	if err != nil {
		require.NotContains(t, err.Error(), "gpu_policy.evaluation")
	}
}
