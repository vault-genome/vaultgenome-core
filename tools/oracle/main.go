// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command oracle is a second opinion on a SEV-SNP attestation report
// (ADR 0034): Google's go-sev-guest parses and verifies the report
// independently of the product's own verifier, and prints what it read
// as JSON for the differential test to hold against the product's
// reading, field by field. It is a separate module on purpose: the
// product's dependency allowlist stays as it is, and nothing here ships
// in a binary.
//
//	oracle sevsnp -report report.bin -vcek vcek.der|pem -chain ask_ark.pem [-product Milan] [-sweep]
//
// -sweep flips every byte of the report in turn and prints, per offset,
// whether the mutated report still verifies — the same sweep the product
// side runs, so that the two refusal maps can be compared.
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"google.golang.org/protobuf/encoding/protojson"
)

const toolVersion = "go-sev-guest v0.15.0"

type output struct {
	Tool        string          `json:"tool"`
	Parsed      bool            `json:"parsed"`
	ParseError  string          `json:"parse_error,omitempty"`
	ProductLine string          `json:"product_line,omitempty"`
	Verified    bool            `json:"verified"`
	VerifyError string          `json:"verify_error,omitempty"`
	Report      json.RawMessage `json:"report,omitempty"`
	Sweep       string          `json:"sweep,omitempty"` // one letter per byte offset: V verified, P parse refused, S verification refused
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "sevsnp" {
		fmt.Fprintln(os.Stderr, "usage: oracle sevsnp -report FILE -vcek FILE -chain FILE [-product LINE] [-sweep]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("sevsnp", flag.ExitOnError)
	reportPath := fs.String("report", "", "the raw 1184-byte attestation report")
	vcekPath := fs.String("vcek", "", "the VCEK (DER or PEM)")
	chainPath := fs.String("chain", "", "AMD's ASK+ARK bundle for the product (PEM, as KDS serves it)")
	product := fs.String("product", "", "product line (Milan, Genoa, Turin); taken from the report's CPUID when empty")
	sweep := fs.Bool("sweep", false, "flip every byte in turn and record which mutants still verify")
	_ = fs.Parse(os.Args[2:])
	raw, err := os.ReadFile(*reportPath)
	must(err)
	vcek, err := readDER(*vcekPath)
	must(err)
	chainPEM, err := os.ReadFile(*chainPath)
	must(err)
	ask, ark, err := splitChain(chainPEM)
	must(err)

	out := output{Tool: toolVersion}
	r, err := abi.ReportToProto(raw)
	if err != nil {
		out.ParseError = err.Error()
	} else {
		out.Parsed = true
		if *product == "" && r.GetCpuid1EaxFms() != 0 {
			*product = kds.ProductLineFromFms(r.GetCpuid1EaxFms())
		}
		out.ProductLine = *product
		b, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(r)
		out.Report = b
		if err := verifyOne(raw, vcek, ask, ark, chainPEM, *product); err != nil {
			out.VerifyError = err.Error()
		} else {
			out.Verified = true
		}
	}
	if *sweep && out.Parsed {
		var sb strings.Builder
		for i := range raw {
			m := append([]byte(nil), raw...)
			m[i] ^= 0xFF
			if _, err := abi.ReportToProto(m); err != nil {
				sb.WriteByte('P')
				continue
			}
			if err := verifyOne(m, vcek, ask, ark, chainPEM, *product); err != nil {
				sb.WriteByte('S')
			} else {
				sb.WriteByte('V')
			}
		}
		out.Sweep = sb.String()
	}
	enc := json.NewEncoder(os.Stdout)
	must(enc.Encode(out))
	if !out.Verified {
		os.Exit(1)
	}
}

// verifyOne runs go-sev-guest's verification with the given VCEK and
// product chain as the only trust material: no fetching, the chain's ARK
// as the root for the product line.
func verifyOne(raw, vcek, ask, ark, chainPEM []byte, product string) error {
	r, err := abi.ReportToProto(raw)
	if err != nil {
		return err
	}
	att := &spb.Attestation{Report: r, CertificateChain: &spb.CertificateChain{VcekCert: vcek, AskCert: ask, ArkCert: ark}}
	root := trust.AMDRootCertsProduct(product)
	if err := root.FromKDSCertBytes(chainPEM); err != nil {
		return fmt.Errorf("chain: %w", err)
	}
	opts := &verify.Options{
		DisableCertFetching: true,
		TrustedRoots:        map[string][]*trust.AMDRootCerts{product: {root}},
		Now:                 time.Now(),
	}
	return verify.SnpAttestation(att, opts)
}

func readDER(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(string(b), "-----BEGIN") {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s: no PEM block", path)
		}
		b = blk.Bytes
	}
	if _, err := x509.ParseCertificate(b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

// splitChain returns (ASK, ARK) DER from a PEM bundle holding both, in
// either order: the self-signed one is the ARK.
func splitChain(chainPEM []byte) (ask, ark []byte, err error) {
	rest := chainPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, err
		}
		if c.Subject.String() == c.Issuer.String() {
			ark = blk.Bytes
		} else {
			ask = blk.Bytes
		}
	}
	if ask == nil || ark == nil {
		return nil, nil, fmt.Errorf("chain: want ASK and ARK, got ask=%v ark=%v", ask != nil, ark != nil)
	}
	return ask, ark, nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "oracle:", err)
		os.Exit(2)
	}
}
