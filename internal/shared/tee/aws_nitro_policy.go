// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// AWSNitroPolicyConfig is a Nitro destination's policy as an operator
// writes it in the source's verifier registry (ADR 0036): beyond PCR0 —
// the expected measurement — the PCRs the document must carry, and the
// largest skew between the document's timestamp and the source's clock.
type AWSNitroPolicyConfig struct {
	// PCRs pins PCRs by index ("1", "2", "3", "4", "8") to 48 bytes of
	// hex: PCR1, PCR2 and PCR8 as `nitro-cli describe-eif` prints them,
	// PCR3 and PCR4 as AWS's guide computes them from the parent's IAM
	// role and instance id.
	PCRs map[string]string `json:"pcrs,omitempty"`

	// MaxClockSkewSeconds bounds the difference between the document's
	// timestamp and the source's clock; 0 is the default, five minutes.
	MaxClockSkewSeconds int `json:"max_clock_skew_seconds,omitempty"`
}

// VerifierConfig converts the policy into the verifier's configuration; a
// nil receiver is the default policy. What the pins mean is checked where
// the verifier is built (NewAWSNitroVerifier).
func (c *AWSNitroPolicyConfig) VerifierConfig() (AWSNitroVerifierConfig, error) {
	var cfg AWSNitroVerifierConfig
	if c == nil {
		return cfg, nil
	}
	if c.MaxClockSkewSeconds < 0 || c.MaxClockSkewSeconds > 3600 {
		return cfg, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("nitro.max_clock_skew_seconds %d: want 1 to 3600, or 0 for five minutes", c.MaxClockSkewSeconds), nil)
	}
	cfg.MaxClockSkew = time.Duration(c.MaxClockSkewSeconds) * time.Second
	for key, value := range c.PCRs {
		i, err := strconv.Atoi(key)
		if err != nil || strconv.Itoa(i) != key {
			return AWSNitroVerifierConfig{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("nitro.pcrs[%q]: the key is a PCR's index (\"1\", \"2\", \"3\", \"4\", \"8\")", key), nil)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(value))
		if err != nil {
			return AWSNitroVerifierConfig{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("nitro.pcrs[%q]: not hex", key), err)
		}
		if cfg.PCRPins == nil {
			cfg.PCRPins = map[int][]byte{}
		}
		cfg.PCRPins[i] = raw
	}
	return cfg, nil
}
