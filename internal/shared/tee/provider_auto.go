// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// tee.provider "auto" (ADR 0025): the daemon does not name its hardware;
// the kernel does. Linux's configfs-tsm serves every confidential-
// computing family through one interface and names the family in the
// `provider` attribute of a report entry — the guest driver's module
// name: sev_guest, tdx_guest, arm_cca_guest (drivers/virt/coco/*, v7.0).
// ResolveAuto reads it and returns the Provider this build runs for it.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// ProviderAuto asks a daemon to take its family from configfs-tsm. It
// names no producer or verifier itself — ResolveAuto turns it into the
// family served on this host — so it is valid for a daemon's own
// tee.provider only, never for a peer, a registry entry or the wire.
const ProviderAuto Provider = "auto"

// The provider names the kernel's guest drivers register with configfs-tsm
// (tsm_report_ops.name = KBUILD_MODNAME, Linux v7.0).
const (
	TSMProviderSEVGuest    = "sev_guest"
	TSMProviderTDXGuest    = "tdx_guest"
	TSMProviderArmCCAGuest = "arm_cca_guest"
)

// providerAliases are the family names of ADR 0025 accepted on input
// beside the names this tree has used, which stay the canonical values
// until the wire names the family (ADR 0025, plan step 2).
var providerAliases = map[Provider]Provider{
	"sev-snp":  ProviderGCPSEVSNP,
	"tdx":      ProviderGCPTDX,
	"nitro":    ProviderAWSNitro,
	"sgx-dcap": ProviderIntelSGXDCAP,
}

// ProviderAliases lists the family names ParseProvider accepts for
// providers of this build, in stable order, for messages and listings.
func ProviderAliases() []string {
	out := make([]string, 0, len(providerAliases))
	for a := range providerAliases {
		out = append(out, string(a))
	}
	sortStrings(out)
	return out
}

// DetectTSMProvider reads which family the kernel's configfs-tsm serves
// on this host: it makes a report entry, reads its `provider` attribute
// and removes the entry. dir empty means DefaultTSMReportDir. A host
// without configfs-tsm — not a confidential VM, a kernel before 6.7, the
// guest driver not loaded — is an error that says so.
func DetectTSMProvider(dir string) (string, error) {
	return detectTSMProvider(dir, osTSMFS{})
}

func detectTSMProvider(dir string, fs tsmFS) (string, error) {
	if dir == "" {
		dir = DefaultTSMReportDir
	}
	entry := filepath.Join(dir, fmt.Sprintf("acp-detect-%d-%d", os.Getpid(), tsmEntrySeq.Add(1)))
	if err := fs.Mkdir(entry); err != nil {
		return "", fmt.Errorf("configfs-tsm: no report entry can be made under %s (this host is not a confidential VM with Linux 6.7 or later, or its guest driver is not loaded): %w", dir, err)
	}
	defer func() { _ = fs.Remove(entry) }()
	raw, err := fs.ReadFile(filepath.Join(entry, "provider"))
	if err != nil {
		return "", fmt.Errorf("configfs-tsm: read provider of %s: %w", entry, err)
	}
	name := strings.TrimSpace(string(raw))
	if name == "" {
		return "", errors.New("configfs-tsm: the provider attribute is empty")
	}
	return name, nil
}

// FamilyForTSMProvider maps the kernel's provider name to the Provider
// this build runs for it. A family the kernel serves and this build does
// not is refused by name, not mistaken for another.
func FamilyForTSMProvider(name string) (Provider, error) {
	switch name {
	case TSMProviderSEVGuest:
		return ProviderGCPSEVSNP, nil
	case TSMProviderTDXGuest:
		return ProviderGCPTDX, nil
	case TSMProviderArmCCAGuest:
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			"tee: configfs-tsm serves arm_cca_guest (Arm CCA): this build has no producer or verifier for it yet (ADR 0025)", nil)
	default:
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("tee: configfs-tsm provider %q is not one this build knows (sev_guest, tdx_guest; arm_cca_guest known and not yet served)", name), nil)
	}
}

// ResolveAuto returns the family configfs-tsm serves on this host and
// the kernel's name for it, for a daemon whose tee.provider is "auto".
func ResolveAuto(dir string) (Provider, string, error) {
	name, err := DetectTSMProvider(dir)
	if err != nil {
		return "", "", err
	}
	family, err := FamilyForTSMProvider(name)
	if err != nil {
		return "", name, err
	}
	return family, name, nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
