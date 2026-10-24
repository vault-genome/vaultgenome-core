// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The chip and the vTPM together (ADR 0037). On a SEV-SNP guest whose
// launch measurement covers the firmware alone — a Compute Engine
// Confidential VM, where the measurement is Google's UEFI, precomputed by
// Google per vCPU count — the chip's derived key binds a sealed file to the
// chip, the firmware and the guest policy, and not to the kernel or the
// disk: another operating system booted on the same chip derives the same
// key. The vTPM measures the boot chain (the boot loader, the kernel, its
// command line and initrd) into its PCRs, but its keys are the virtual
// TPM's, not the chip's. Sealed with both, a file opens only where both
// agree: on this chip, at this launch measurement and policy, and on a boot
// whose PCRs the vTPM's policy names.
//
// The construction nests the two sealers and adds no cryptography of its
// own: the chip seals the plaintext, the vTPM seals the chip's blob. Unseal
// runs them in reverse — the vTPM first, so a changed boot is refused
// before the chip is asked — and either refusal is final.

import (
	"errors"
	"fmt"
)

// SEVSNPVTPMSealer seals with the chip's derived key and the guest's vTPM,
// nested. See the file comment.
type SEVSNPVTPMSealer struct {
	chip Sealer
	vtpm Sealer
}

// NewSEVSNPVTPMSealer nests the chip's sealer inside the vTPM's.
func NewSEVSNPVTPMSealer(chip *GCPSEVSealer, vtpm *VTPMSealer) (*SEVSNPVTPMSealer, error) {
	if chip == nil || vtpm == nil {
		return nil, errors.New("sev-snp+tpm2: both the chip's sealer and the vTPM's are required")
	}
	return &SEVSNPVTPMSealer{chip: chip, vtpm: vtpm}, nil
}

// Seal implements Sealer: the chip seals, then the vTPM seals the chip's blob.
func (s *SEVSNPVTPMSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	inner, err := s.chip.Seal(plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("sev-snp+tpm2: the chip: %w", err)
	}
	outer, err := s.vtpm.Seal(inner, aad)
	if err != nil {
		return nil, fmt.Errorf("sev-snp+tpm2: the vTPM: %w", err)
	}
	return outer, nil
}

// Unseal implements Sealer: the vTPM opens its layer only on a boot its
// policy names, then the chip opens the plaintext only on this chip, at this
// measurement and policy.
func (s *SEVSNPVTPMSealer) Unseal(sealed, aad []byte) ([]byte, error) {
	inner, err := s.vtpm.Unseal(sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("sev-snp+tpm2: the vTPM refuses this boot: %w", err)
	}
	plain, err := s.chip.Unseal(inner, aad)
	if err != nil {
		return nil, fmt.Errorf("sev-snp+tpm2: the chip refuses: %w", err)
	}
	return plain, nil
}

var _ Sealer = (*SEVSNPVTPMSealer)(nil)
