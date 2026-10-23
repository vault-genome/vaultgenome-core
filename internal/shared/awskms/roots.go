// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package awskms

import (
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
)

// Amazon Trust Services' four root certificates, byte for byte as the
// repository publishes them (https://www.amazontrust.com/repository/,
// read 2026-10-23; their SHA-256 fingerprints match the repository page,
// library 86caa31e9b7c…). KMS's endpoints chain to Amazon Root CA 1
// (observed for us-east-1 and us-east-2 on 2026-10-23: the endpoint's
// certificate, Amazon RSA 2048 M01, Amazon Root CA 1; TLS 1.3). The
// client verifies KMS against these and nothing else: in an enclave the
// bytes pass through the parent, which must not be able to stand in for
// KMS with a certificate a wider store would take.
//
//go:embed roots/AmazonRootCA1.pem roots/AmazonRootCA2.pem roots/AmazonRootCA3.pem roots/AmazonRootCA4.pem
var rootFiles embed.FS

var rootNames = []string{"AmazonRootCA1.pem", "AmazonRootCA2.pem", "AmazonRootCA3.pem", "AmazonRootCA4.pem"}

// AmazonRoots returns a pool of the four roots, parsed fresh each call.
func AmazonRoots() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, n := range rootNames {
		cert, err := amazonRoot(n)
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

func amazonRoot(name string) (*x509.Certificate, error) {
	raw, err := rootFiles.ReadFile("roots/" + name)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) > 0 && string(rest) != "\n" {
		return nil, fmt.Errorf("awskms: roots/%s is not one PEM certificate", name)
	}
	return x509.ParseCertificate(block.Bytes)
}
