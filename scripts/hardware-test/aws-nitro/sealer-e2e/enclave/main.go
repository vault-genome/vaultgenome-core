// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command enclave is the program of the sealer's hardware run (ADR 0036,
// part four, stage one): the whole of a Nitro enclave image. It attests
// itself through the NSM with the shipping producer, opens the sealed
// secrets its parent hands it with the shipping sealer — KMS Decrypt with
// its own attestation document as Recipient, KMS's CMS answer opened in
// here — and reports to its parent what opened and what was refused. It
// never sends a secret out: what it reports of one is its SHA-256.
//
// Its configuration is in the image (/etc/vg/enclave.json), so PCR0 covers
// it: the KMS keys and the parent's vsock ports. The parent is not trusted:
// what it hands in is ciphertext, and what it relays to KMS is TLS.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/awskms"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/shared/vsock"
)

const (
	configPath    = "/etc/vg/enclave.json"
	maxBundle     = 1 << 20
	dialTimeout   = 30 * time.Second
	reportTimeout = 30 * time.Second
)

// config is the image's own word, under PCR0.
type config struct {
	Region          string `json:"region"`
	KeyARN          string `json:"kms_key_arn"`
	OtherKeyARN     string `json:"other_kms_key_arn"`
	KMSVsockPort    uint32 `json:"kms_vsock_port"`
	IMDSVsockPort   uint32 `json:"imds_vsock_port"`
	FilesVsockPort  uint32 `json:"files_vsock_port"`
	ReportVsockPort uint32 `json:"report_vsock_port"`
}

// bundle is what the parent hands in: the sealed files and, for the
// debug-mode run, the PCR0 the image has in production mode.
type bundle struct {
	Cases []struct {
		Case   string `json:"case"`
		Name   string `json:"name"`
		Key    string `json:"key"` // "kms_key_arn" or "other_kms_key_arn"
		File   []byte `json:"file"`
		Expect string `json:"expect"` // "open" or "refuse"
	} `json:"cases"`
	ProductionPCR0Hex string `json:"production_pcr0_hex"`
}

type selfReport struct {
	ModuleID  string            `json:"module_id"`
	Timestamp time.Time         `json:"document_timestamp"`
	Clock     time.Time         `json:"enclave_clock"`
	Debug     bool              `json:"debug"`
	PCRs      map[string]string `json:"pcrs"`
	Chain     []string          `json:"chain"`
}

type caseReport struct {
	Case       string `json:"case"`
	Expect     string `json:"expect"`
	Outcome    string `json:"outcome"` // "opened" or "refused"
	SHA256     string `json:"plaintext_sha256,omitempty"`
	Error      string `json:"error,omitempty"`
	Millis     int64  `json:"millis"`
	AsExpected bool   `json:"as_expected"`
}

type report struct {
	Kernel    string       `json:"enclave_kernel,omitempty"`
	Self      *selfReport  `json:"self_attestation,omitempty"`
	SelfError string       `json:"self_attestation_error,omitempty"`
	Cases     []caseReport `json:"cases"`
	Fatal     string       `json:"fatal,omitempty"`
}

func main() {
	var cfg config
	rep := &report{}
	if err := readConfig(&cfg); err != nil {
		fmt.Fprintln(os.Stderr, "enclave:", err)
		os.Exit(2)
	}
	defer func() {
		if err := sendReport(cfg, rep); err != nil {
			fmt.Fprintln(os.Stderr, "enclave: report:", err)
		}
	}()
	if err := run(cfg, rep); err != nil {
		rep.Fatal = err.Error()
	}
}

func readConfig(cfg *config) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(cfg)
}

func run(cfg config, rep *report) error {
	if k, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		rep.Kernel = string(bytes.TrimSpace(k))
	}
	// The shipping producer: it attests itself at start against the
	// pinned AWS root and takes PCR0 from its own document.
	producer, err := tee.NewAWSNitroProducer(tee.AWSNitroProducerConfig{})
	if err != nil {
		rep.SelfError = err.Error()
		return fmt.Errorf("the producer: %w", err)
	}
	defer func() { _ = producer.Close() }()
	rep.Self, err = audit(producer)
	if err != nil {
		rep.SelfError = err.Error()
	}

	b, err := fetchBundle(cfg)
	if err != nil {
		return fmt.Errorf("the sealed files: %w", err)
	}
	for _, c := range b.Cases {
		keyARN := cfg.KeyARN
		if c.Key == "other_kms_key_arn" {
			keyARN = cfg.OtherKeyARN
		}
		expect := c.Expect
		if rep.Self != nil && rep.Self.Debug {
			expect = "refuse" // nothing opens in a debug-mode enclave
		}
		start := time.Now()
		cr := caseReport{Case: c.Case, Expect: expect}
		plain, err := openWithShippingSealer(producer, cfg, keyARN, c.Name, c.File)
		cr.Millis = time.Since(start).Milliseconds()
		record(&cr, plain, err)
		rep.Cases = append(rep.Cases, cr)
	}

	// In debug mode PCR0 is zero and the shipping sealer is not built on
	// it. What KMS itself says to a debug-mode document is asked by
	// sealing for the production PCR0 and attesting with this enclave's
	// own document.
	if rep.Self != nil && rep.Self.Debug && b.ProductionPCR0Hex != "" && len(b.Cases) > 0 {
		start := time.Now()
		cr := caseReport{Case: "kms-to-a-debug-mode-document", Expect: "refuse"}
		plain, err := openAsProduction(cfg, b.ProductionPCR0Hex, b.Cases[0].Name, b.Cases[0].File)
		cr.Millis = time.Since(start).Milliseconds()
		record(&cr, plain, err)
		rep.Cases = append(rep.Cases, cr)
	}
	return nil
}

func record(cr *caseReport, plain []byte, err error) {
	if err != nil {
		cr.Outcome, cr.Error = "refused", err.Error()
	} else {
		sum := sha256.Sum256(plain)
		cr.Outcome, cr.SHA256 = "opened", hex.EncodeToString(sum[:])
		clear(plain)
	}
	cr.AsExpected = (cr.Expect == "open") == (cr.Outcome == "opened")
}

// audit takes a document over a fresh nonce and reads it with the
// shipping verifier's audit, against the pinned AWS root.
func audit(p *tee.AWSNitroProducer) (*selfReport, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	doc, err := p.Quote(nonce)
	if err != nil {
		return nil, err
	}
	r, err := tee.AuditAWSNitroDocument(doc, nil, time.Time{})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r.Nonce, nonce) {
		return nil, errors.New("the document carries another nonce")
	}
	out := &selfReport{ModuleID: r.ModuleID, Timestamp: r.Timestamp, Clock: time.Now().UTC(), Debug: r.Debug, PCRs: map[string]string{}, Chain: r.Chain}
	for i, v := range r.PCRs {
		if i <= 8 {
			out.PCRs[fmt.Sprint(i)] = hex.EncodeToString(v)
		}
	}
	return out, nil
}

// openWithShippingSealer is what acp-bootstrap does with a sealed file in
// an enclave: tee.SealerFor on the producer, then tee.OpenSecretWith.
func openWithShippingSealer(p *tee.AWSNitroProducer, cfg config, keyARN, name string, file []byte) ([]byte, error) {
	sealer, closer, kind, err := tee.SealerFor(p, tee.SealerOptions{AWSKMS: &tee.AWSKMSSealerOptions{
		KeyARN: keyARN, KMSVsockPort: cfg.KMSVsockPort, IMDSVsockPort: cfg.IMDSVsockPort,
	}})
	if err != nil {
		return nil, err
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	return tee.OpenSecretWith(file, sealer, kind, tee.ProviderAWSNitro, name)
}

// openAsProduction builds the sealer for the production PCR0 and attests
// with a document of this (debug-mode) enclave carrying the sealer's key,
// so the decision is KMS's.
func openAsProduction(cfg config, pcr0Hex, name string, file []byte) ([]byte, error) {
	pcr0, err := hex.DecodeString(pcr0Hex)
	if err != nil {
		return nil, err
	}
	m, err := tee.MeasurementFromBytes(pcr0)
	if err != nil {
		return nil, err
	}
	client, err := enclaveKMSClient(cfg)
	if err != nil {
		return nil, err
	}
	sealer, err := tee.NewAWSNitroSealer(tee.AWSNitroSealerConfig{
		KeyARN: cfg.KeyARN, Measurement: m, KMS: client,
		Attest: func(pub crypto.PublicKey) ([]byte, error) {
			q, err := tee.NewAWSNitroProducer(tee.AWSNitroProducerConfig{IncludePublicKey: pub})
			if err != nil {
				return nil, err
			}
			defer func() { _ = q.Close() }()
			nonce := make([]byte, 32)
			if _, err := rand.Read(nonce); err != nil {
				return nil, err
			}
			return q.Quote(nonce)
		},
	})
	if err != nil {
		return nil, err
	}
	return tee.OpenSecretWith(file, sealer, tee.SealerKindAWSKMSAttested, tee.ProviderAWSNitro, name)
}

func enclaveKMSClient(cfg config) (*awskms.Client, error) {
	return awskms.New(awskms.Config{
		Region: cfg.Region,
		Dial: func(ctx context.Context) (net.Conn, error) {
			return vsock.Dial(ctx, vsock.CIDNitroParent, cfg.KMSVsockPort)
		},
		Credentials: &awskms.IMDSCredentials{Dial: func(ctx context.Context) (net.Conn, error) {
			return vsock.Dial(ctx, vsock.CIDNitroParent, cfg.IMDSVsockPort)
		}},
	})
}

func fetchBundle(cfg config) (*bundle, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	c, err := vsock.Dial(ctx, vsock.CIDNitroParent, cfg.FilesVsockPort)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(dialTimeout))
	// One JSON value, then this side closes; the parent waits for that
	// before it closes its own.
	var b bundle
	dec := json.NewDecoder(io.LimitReader(c, maxBundle))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

func sendReport(cfg config, rep *report) error {
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(raw)) // the console, in debug mode
	ctx, cancel := context.WithTimeout(context.Background(), reportTimeout)
	defer cancel()
	c, err := vsock.Dial(ctx, vsock.CIDNitroParent, cfg.ReportVsockPort)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetWriteDeadline(time.Now().Add(reportTimeout))
	_, err = c.Write(raw)
	return err
}
