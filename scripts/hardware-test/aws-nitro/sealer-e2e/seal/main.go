// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command seal seals a secret for a Nitro enclave image on the operator's
// machine (ADR 0036, part four, stage one) with the shipping sealer: KMS
// GenerateDataKey under the run's key, AES-256-GCM, the image's PCR0 and
// the secret's name bound into the encryption context. No enclave is
// needed to seal; only the enclave opens. The credentials are the
// environment's (the kit exports its role's), read here, in main.
//
// -as-name writes the file under another name than the one it was sealed
// as — the refusal case where an enclave is handed a secret for the
// wrong purpose, which KMS must catch even if nothing else did.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/shared/awskms"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

func main() {
	region := flag.String("region", "us-east-2", "the key's Region")
	keyARN := flag.String("key-arn", "", "the run's KMS key")
	pcr0Hex := flag.String("pcr0", "", "the image's PCR0 (SHA-384, hex)")
	name := flag.String("name", "", "the name the secret is sealed as")
	asName := flag.String("as-name", "", "write the file under this name instead (a refusal case)")
	in := flag.String("in", "", "the secret")
	out := flag.String("out", "", "the sealed file")
	flag.Parse()
	if err := run(*region, *keyARN, *pcr0Hex, *name, *asName, *in, *out); err != nil {
		fmt.Fprintln(os.Stderr, "seal:", err)
		os.Exit(1)
	}
}

func run(region, keyARN, pcr0Hex, name, asName, in, out string) error {
	if keyARN == "" || pcr0Hex == "" || name == "" || in == "" || out == "" {
		return fmt.Errorf("-key-arn, -pcr0, -name, -in and -out are required")
	}
	pcr0, err := hex.DecodeString(pcr0Hex)
	if err != nil {
		return fmt.Errorf("-pcr0: %w", err)
	}
	m, err := tee.MeasurementFromBytes(pcr0)
	if err != nil {
		return err
	}
	creds := awskms.StaticCredentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
	client, err := awskms.New(awskms.Config{Region: region, Credentials: creds})
	if err != nil {
		return err
	}
	sealer, err := tee.NewAWSNitroSealer(tee.AWSNitroSealerConfig{KeyARN: keyARN, Measurement: m, KMS: client})
	if err != nil {
		return err
	}
	secret, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	file, err := tee.SealSecretWith(secret, sealer, tee.SealerKindAWSKMSAttested, tee.ProviderAWSNitro, m, name)
	clear(secret)
	if err != nil {
		return err
	}
	if asName != "" {
		var s tee.SealedSecret
		if err := json.Unmarshal(file, &s); err != nil {
			return err
		}
		s.Name = asName
		if file, err = json.MarshalIndent(s, "", "  "); err != nil {
			return err
		}
		file = append(file, '\n')
	}
	return os.WriteFile(out, file, 0o600)
}
