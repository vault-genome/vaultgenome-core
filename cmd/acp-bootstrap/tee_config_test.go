// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// The sev-guest device the sealing key is derived through is the
// operator's when named and the kernel's default otherwise.
func TestTEEConfig_SEVDevice(t *testing.T) {
	if got := (TEEConfig{}).SEVDevice(); got != DefaultSEVGuestDevice {
		t.Fatalf("default device: %q", got)
	}
	if got := (TEEConfig{SEVGuestDevice: "/dev/sev-guest-1"}).SEVDevice(); got != "/dev/sev-guest-1" {
		t.Fatalf("named device: %q", got)
	}
}

// Each hardware provider takes its own fields and refuses the others':
// the attest command, the tpm2-tools and the attestation key handle
// belong to azure-cgpu, the sev-guest device to gcp-sev-snp, the vTPM
// PCR selection to the two vTPM hosts, and a selection is checked where
// it applies.
func TestValidate_HardwareProviderFields(t *testing.T) {
	hardware := func(c *Config, provider string) {
		c.TEE.Provider = provider
		c.TEE.SeedPath = ""
		c.TEE.InsecureSimulation = false
	}
	azure := func(c *Config) {
		hardware(c, "azure-cgpu")
		c.TEE.GPUAttestCommand = []string{"/opt/nvidia/attest", "--nonce"}
	}
	for name, tc := range map[string]struct {
		mutate func(c *Config)
		want   string // empty: the config is valid
	}{
		"tdx clean": {func(c *Config) {
			hardware(c, "gcp-tdx")
			c.TEE.TSMReportDir = "/sys/kernel/config/tsm/report"
			c.TEE.VTPMSealPCRs = "sha256:0,1,2,3,4,5,6,7"
		}, ""},
		"tdx with a seed": {func(c *Config) {
			hardware(c, "gcp-tdx")
			c.TEE.SeedPath = "/etc/acp/tee_seed"
		}, "tee.seed_path applies to the simulated provider only"},
		"azure clean": {func(c *Config) {
			azure(c)
			c.TEE.TPM2ToolsDir = "/usr/bin"
			c.TEE.AKHandle = "0x81000001"
			c.TEE.VTPMSealPCRs = "sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14"
		}, ""},
		"azure with simulated leftovers": {func(c *Config) {
			c.TEE.Provider = "azure-cgpu"
			c.TEE.GPUAttestCommand = []string{"/opt/nvidia/attest"}
		}, "tee.seed_path and tee.insecure_simulation apply to the simulated provider only"},
		"azure with a tsm dir": {func(c *Config) {
			azure(c)
			c.TEE.TSMReportDir = "/sys/kernel/config/tsm/report"
		}, "tee.tsm_report_dir does not apply to azure-cgpu"},
		"azure without the attest command": {func(c *Config) { hardware(c, "azure-cgpu") },
			"tee.gpu_attest_command required when tee.provider=azure-cgpu"},
		"attest command on simulated": {func(c *Config) { c.TEE.GPUAttestCommand = []string{"/opt/nvidia/attest"} },
			"tee.gpu_attest_command and ak_handle apply to azure-cgpu and azure-sev-snp only, and tpm2_tools_dir to those and gcp-sev-snp-vtpm"},
		"tpm2 dir on sev-snp": {func(c *Config) {
			hardware(c, "gcp-sev-snp")
			c.TEE.TPM2ToolsDir = "/usr/bin"
		}, "apply to azure-cgpu and azure-sev-snp only"},
		"ak handle on tdx": {func(c *Config) {
			hardware(c, "gcp-tdx")
			c.TEE.AKHandle = "0x81000001"
		}, "apply to azure-cgpu and azure-sev-snp only"},
		"sev device on sev-snp": {func(c *Config) {
			hardware(c, "gcp-sev-snp")
			c.TEE.SEVGuestDevice = "/dev/sev-guest-1"
		}, ""},
		"sev device on simulated": {func(c *Config) { c.TEE.SEVGuestDevice = "/dev/sev-guest-1" },
			"tee.sev_guest_device applies to gcp-sev-snp, gcp-sev-snp-vtpm and aws-sev-snp only"},
		"sev device on tdx": {func(c *Config) {
			hardware(c, "gcp-tdx")
			c.TEE.SEVGuestDevice = "/dev/sev-guest"
		}, "tee.sev_guest_device applies to gcp-sev-snp, gcp-sev-snp-vtpm and aws-sev-snp only"},
		"vtpm pcrs on simulated": {func(c *Config) { c.TEE.VTPMSealPCRs = "sha256:0" },
			"tee.vtpm_seal_pcrs applies where a vTPM seals"},
		"vtpm pcrs on sev-snp": {func(c *Config) {
			hardware(c, "gcp-sev-snp")
			c.TEE.VTPMSealPCRs = "sha256:0"
		}, "tee.vtpm_seal_pcrs applies where a vTPM seals"},
		"vtpm pcrs as a range on tdx": {func(c *Config) {
			hardware(c, "gcp-tdx")
			c.TEE.VTPMSealPCRs = "sha256:0-14"
		}, `tee.vtpm_seal_pcrs: PCR selection "sha256:0-14"`},
		"vtpm pcrs in another bank on azure": {func(c *Config) {
			azure(c)
			c.TEE.VTPMSealPCRs = "sha1:0,1"
		}, "tee.vtpm_seal_pcrs: PCR selection"},
		"vtpm pcr listed twice on tdx": {func(c *Config) {
			hardware(c, "gcp-tdx")
			c.TEE.VTPMSealPCRs = "sha256:0,0"
		}, "listed twice"},
		// The quote selection is the vTPM families' (ADR 0037, amendment of
		// 2026-10-28): the boot without IMA's PCR 10 on an Azure host; the
		// intermediates stay gcp-sev-snp-vtpm's.
		"azure-sev-snp with the boot pcrs": {func(c *Config) {
			hardware(c, "azure-sev-snp")
			c.TEE.VTPMQuotePCRs = tee.TPMBootPCRsWithoutIMA
			c.TEE.VTPMSealPCRs = tee.TPMBootPCRsWithoutIMA
		}, ""},
		"azure-cgpu with the boot pcrs": {func(c *Config) {
			azure(c)
			c.TEE.VTPMQuotePCRs = tee.TPMBootPCRsWithoutIMA
		}, ""},
		"bad quote pcrs on azure": {func(c *Config) {
			azure(c)
			c.TEE.VTPMQuotePCRs = "sha1:0"
		}, "tee.vtpm_quote_pcrs: PCR selection"},
		"quote pcrs on tdx": {func(c *Config) {
			hardware(c, "gcp-tdx")
			c.TEE.VTPMQuotePCRs = "sha256:0"
		}, "tee.vtpm_quote_pcrs applies to gcp-sev-snp-vtpm, azure-sev-snp and azure-cgpu only"},
		"intermediates on azure-sev-snp": {func(c *Config) {
			hardware(c, "azure-sev-snp")
			c.TEE.AKIntermediatesPath = "/inter.pem"
		}, "tee.ak_intermediates_path applies to gcp-sev-snp-vtpm only"},
	} {
		t.Run(name, func(t *testing.T) {
			c := minimalValidConfig()
			tc.mutate(&c)
			if tc.want == "" {
				requireValid(t, c)
				return
			}
			requireInvalid(t, c, tc.want)
		})
	}
}
