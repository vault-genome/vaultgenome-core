// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// tee.provider "auto" under Azure's paravisor (ADR 0025). An Azure
// confidential VM has no configfs-tsm and no /dev/sev-guest: its SEV-SNP
// report is issued at boot and kept in the vTPM's NV index as the HCL
// report (azure_vtpm.go, azure_cgpu_hcl.go). When the kernel has nothing
// to say, ResolveAuto reads that index and names the family by the
// report's type — azure-sev-snp for an SNP report; a report of another
// type is refused by its number, not mistaken for one this build runs.
//
// A confidential GPU VM carries the same HCL report and resolves the same
// way; the azure-cgpu family — this and NVIDIA's tokens for the H100 — is
// the operator's to name, with its GPU attestation command and policy.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// AutoResolvedFromAzureHCL is the name ResolveAuto returns, in place of
// the kernel's provider name, when the family came from the vTPM's HCL
// report.
const AutoResolvedFromAzureHCL = "vtpm-hcl"

// azureHCLReadTimeout bounds the tpm2_nvread of the detection.
const azureHCLReadTimeout = 30 * time.Second

// readAzureHCL reads the HCL report from the vTPM's NV index with
// tpm2_nvread on PATH. A var so tests substitute it.
var readAzureHCL = func() ([]byte, error) {
	return runCommand(azureHCLReadTimeout, "tpm2_nvread", "-C", "o", hclNVIndex)
}

// errHCLOtherType marks an HCL report that is there but not SEV-SNP: a
// definite answer about this host, which ResolveAuto reports as it is.
var errHCLOtherType = errors.New("the vTPM's HCL report is not an SEV-SNP report")

// hclReportType reads the report type of an HCL blob without verifying
// it: the magic, then the runtime data header's type field.
func hclReportType(raw []byte) (uint32, error) {
	if len(raw) < hclHeaderLen+sevReportLen+hclRuntimeHeaderLen {
		return 0, fmt.Errorf("NV index %s holds %d bytes, not an HCL report", hclNVIndex, len(raw))
	}
	if string(raw[:4]) != hclMagic {
		return 0, fmt.Errorf("NV index %s does not hold an HCL report (no %q magic)", hclNVIndex, hclMagic)
	}
	rt := raw[hclHeaderLen+sevReportLen:]
	return binary.LittleEndian.Uint32(rt[8:12]), nil
}

// DetectAzureHCL names the family of an Azure confidential VM from the
// HCL report in its vTPM: azure-sev-snp for an SNP report. A host whose
// vTPM holds no HCL report, or none this process may read, is an error
// that says so; a report of another type is refused by its number.
func DetectAzureHCL() (Provider, error) {
	raw, err := readAzureHCL()
	if err != nil {
		return "", fmt.Errorf("vTPM: read the HCL report (tpm2_nvread -C o %s): %w", hclNVIndex, err)
	}
	rt, err := hclReportType(raw)
	if err != nil {
		return "", fmt.Errorf("vTPM: %w", err)
	}
	if rt != hclReportTypeSNP {
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("tee: %v: report type %d, not %d; this build has no producer for it (ADR 0025)", errHCLOtherType, rt, hclReportTypeSNP), errHCLOtherType)
	}
	return ProviderAzureSEVSNP, nil
}
