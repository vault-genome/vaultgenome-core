// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/shared/awskms"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// operatorKMS builds the KMS client an operator seals a Nitro enclave's
// key files with; a variable so the tests stand in for KMS.
var operatorKMS = func(region, endpoint string, creds awskms.Credentials) (*awskms.Client, error) {
	return awskms.New(awskms.Config{Region: region, Endpoint: endpoint, Credentials: creds})
}

type sealKeysOutput struct {
	TEE            string           `json:"tee"`
	Sealer         string           `json:"sealer"`
	MeasurementHex string           `json:"measurement_hex"`
	Sealed         []sealedKeyEntry `json:"sealed"`
	AlreadySealed  []sealedKeyEntry `json:"already_sealed,omitempty"`
}

type sealedKeyEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// secretFiles are the secret files the config names: the TLS server key
// when TLS is on, and the bearer token file when one is set. Each is
// sealed under its config name, so a file sealed as one does not open as
// the other.
func secretFiles(cfg Config) []sealedKeyEntry {
	var files []sealedKeyEntry
	if cfg.HTTP.TLS.Enabled && cfg.HTTP.TLS.ServerKey != "" {
		files = append(files, sealedKeyEntry{Name: "http.tls.server_key", Path: cfg.HTTP.TLS.ServerKey})
	}
	if cfg.HTTP.BearerTokenFile != "" {
		files = append(files, sealedKeyEntry{Name: "http.bearer_token_file", Path: cfg.HTTP.BearerTokenFile})
	}
	return files
}

// runSealKeys implements `acp-bootstrap seal-keys -config <path>`: every
// secret file the config names — the TLS server key, the bearer token —
// is sealed in place to this host's TEE (ADR 0023), each under its name,
// after being opened once from the sealed form; the daemon then reads
// them sealed. A file already sealed is left as it is. Run it once the
// config is final and before the daemon's first start; a new chip, image
// or boot of a vTPM host needs new files.
//
// A Nitro enclave's files are sealed outside it, for its image (ADR 0036):
// `seal-keys -config <path> -pcr0 <hex> [-root <dir>]` under the
// operator's AWS credentials, the files read at the config's paths under
// -root (the enclave's files, staged on this machine) and sealed there;
// the parent hands them to the enclave, where KMS opens them for that
// image's attestation only.
func runSealKeys(args []string, stdout, stderr io.Writer, creds awskms.StaticCredentials) error {
	fs := flag.NewFlagSet("acp-bootstrap seal-keys", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath, pcr0Hex, root string
	fs.StringVar(&configPath, "config", "", "path to JSON config file (required)")
	fs.StringVar(&pcr0Hex, "pcr0", "", "aws-nitro: the image's PCR0, hex, as `nitro-cli describe-eif` prints it; the files are sealed for that image, outside the enclave")
	fs.StringVar(&root, "root", "", "aws-nitro: the directory the config's key-file paths are read under on this machine (the enclave's files, staged)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("acp-bootstrap seal-keys: -config is required")
	}
	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("acp-bootstrap seal-keys: config validation: %w", err)
	}
	if provider, _ := tee.ParseProvider(cfg.TEE.Provider); provider == tee.ProviderAWSNitro || pcr0Hex != "" || root != "" {
		return sealNitroKeys(cfg, pcr0Hex, root, stdout, stderr, creds)
	}
	producer, err := buildTEEProducer(cfg.TEE)
	if err != nil {
		return err
	}
	sealer, closer, provider, kind, err := hostSealer(cfg.TEE)
	if err != nil {
		return err
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	if kind == tee.SealerKindSimulated {
		fmt.Fprintln(stderr, "acp-bootstrap seal-keys: SIMULATED TEE: the files are sealed under a key derived from the simulated measurement, with no hardware behind it; development and tests only")
	}
	measurement := producer.Measurement()
	out := sealKeysOutput{TEE: string(provider), MeasurementHex: hex.EncodeToString(measurement), Sealer: string(kind)}
	for _, f := range secretFiles(cfg) {
		raw, err := os.ReadFile(f.Path)
		if err != nil {
			return fmt.Errorf("acp-bootstrap seal-keys: read %s (%q): %w", f.Name, f.Path, err)
		}
		if tee.IsSealedSecret(raw) {
			if _, err := readSecret(cfg.TEE, f.Path, 0, f.Name); err != nil {
				return fmt.Errorf("acp-bootstrap seal-keys: %s is sealed, and this host cannot open it: %w", f.Name, err)
			}
			out.AlreadySealed = append(out.AlreadySealed, f)
			continue
		}
		if len(raw) == 0 {
			return fmt.Errorf("acp-bootstrap seal-keys: %s (%q) is empty", f.Name, f.Path)
		}
		sealed, err := tee.SealSecretWith(raw, sealer, kind, provider, measurement, f.Name)
		zero(raw)
		if err != nil {
			return fmt.Errorf("acp-bootstrap seal-keys: %s: %w", f.Name, err)
		}
		back, err := tee.OpenSecretWith(sealed, sealer, kind, provider, f.Name)
		zero(back)
		if err != nil {
			return fmt.Errorf("acp-bootstrap seal-keys: %s: the sealed file does not open on this host: %w", f.Name, err)
		}
		if err := replaceFile(f.Path, sealed); err != nil {
			return fmt.Errorf("acp-bootstrap seal-keys: write %s (%q): %w", f.Name, f.Path, err)
		}
		out.Sealed = append(out.Sealed, f)
	}
	if out.Sealed == nil {
		out.Sealed = []sealedKeyEntry{}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// sealNitroKeys seals a Nitro enclave's key files outside it, for the
// image whose PCR0 is given (ADR 0036): a data key from KMS's
// GenerateDataKey under the encryption context naming that PCR0 and the
// file, the file sealed under it. The files cannot be opened here — only
// the enclave can, through KMS, released to its attestation — so a file
// already sealed is kept when it names this image and its own name, and
// refused otherwise.
func sealNitroKeys(cfg Config, pcr0Hex, root string, stdout, stderr io.Writer, creds awskms.StaticCredentials) error {
	if provider, _ := tee.ParseProvider(cfg.TEE.Provider); provider != tee.ProviderAWSNitro {
		return fmt.Errorf("acp-bootstrap seal-keys: -pcr0 and -root seal a Nitro enclave's key files; this config's tee.provider is %s", cfg.TEE.Provider)
	}
	if pcr0Hex == "" {
		return errors.New("acp-bootstrap seal-keys: on aws-nitro the key files are sealed outside the enclave, for its image: -pcr0 <the image's PCR0, from nitro-cli describe-eif>")
	}
	raw, err := hex.DecodeString(strings.TrimSpace(pcr0Hex))
	if err != nil || len(raw) != 48 {
		return errors.New("acp-bootstrap seal-keys: -pcr0 is the image's PCR0: a SHA-384, 96 hex characters")
	}
	measurement := tee.Measurement(raw)
	if measurement.IsZero() {
		return errors.New("acp-bootstrap seal-keys: -pcr0 is zero, a debug-mode enclave's; key files are sealed to a production-mode image only")
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return errors.New("acp-bootstrap seal-keys: sealing for a Nitro image asks KMS for a data key under the operator's AWS credentials: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN for a role's)")
	}
	region, err := tee.ParseAWSKMSKeyARN(cfg.TEE.AWSKMS.KeyARN)
	if err != nil {
		return fmt.Errorf("acp-bootstrap seal-keys: tee.aws_kms.key_arn: %w", err)
	}
	client, err := operatorKMS(region, cfg.TEE.AWSKMS.Endpoint, creds)
	if err != nil {
		return fmt.Errorf("acp-bootstrap seal-keys: %w", err)
	}
	sealer, err := tee.NewAWSNitroSealer(tee.AWSNitroSealerConfig{KeyARN: cfg.TEE.AWSKMS.KeyARN, Measurement: measurement, KMS: client})
	if err != nil {
		return fmt.Errorf("acp-bootstrap seal-keys: %w", err)
	}
	pcr0 := hex.EncodeToString(measurement)
	out := sealKeysOutput{TEE: string(tee.ProviderAWSNitro), MeasurementHex: pcr0, Sealer: string(tee.SealerKindAWSKMSAttested)}
	for _, f := range secretFiles(cfg) {
		path := f.Path
		if root != "" {
			path = filepath.Join(root, f.Path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("acp-bootstrap seal-keys: read %s (%q): %w", f.Name, path, err)
		}
		if tee.IsSealedSecret(data) {
			s, err := tee.ParseSealedSecret(data)
			if err != nil {
				return fmt.Errorf("acp-bootstrap seal-keys: %s (%q): %w", f.Name, path, err)
			}
			if s.TEE != string(tee.ProviderAWSNitro) || s.Sealer != string(tee.SealerKindAWSKMSAttested) || s.MeasurementHex != pcr0 || s.Name != f.Name {
				return fmt.Errorf("acp-bootstrap seal-keys: %s (%q) is already sealed, but on %s for %s… as %q; give the bare file to seal it for this image", f.Name, path, s.TEE, s.MeasurementHex[:min(16, len(s.MeasurementHex))], s.Name)
			}
			out.AlreadySealed = append(out.AlreadySealed, f)
			continue
		}
		if len(data) == 0 {
			return fmt.Errorf("acp-bootstrap seal-keys: %s (%q) is empty", f.Name, path)
		}
		sealed, err := tee.SealSecretWith(data, sealer, tee.SealerKindAWSKMSAttested, tee.ProviderAWSNitro, measurement, f.Name)
		zero(data)
		if err != nil {
			return fmt.Errorf("acp-bootstrap seal-keys: %s: %w", f.Name, err)
		}
		if err := replaceFile(path, sealed); err != nil {
			return fmt.Errorf("acp-bootstrap seal-keys: write %s (%q): %w", f.Name, path, err)
		}
		out.Sealed = append(out.Sealed, f)
	}
	if out.Sealed == nil {
		out.Sealed = []sealedKeyEntry{}
	}
	fmt.Fprintf(stderr, "acp-bootstrap seal-keys: sealed for the image whose PCR0 is %s…: the files open only in its enclave, through KMS, released to its attestation\n", pcr0[:16])
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// replaceFile writes data beside path, mode 0600, and renames it over
// path: the old bytes are never half-replaced.
func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".seal-keys-*")
	if err != nil {
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
