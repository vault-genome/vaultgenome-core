// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The AMD root keys this build trusts: one ARK per EPYC product line —
// Milan, Genoa, Turin — the certificate bytes as AMD's Key Distribution
// Service serves them under /vcek/v1/<product>/cert_chain. Every VCEK
// chain a verifier is given (the operator's amd_cert_chain_path) must end
// in one of them: a chain whose root is self-signed but not AMD's is
// refused, however well its signatures check (ADR 0024). The same bytes
// are the fixtures under testdata/amd/, whose README records how the three
// fingerprints were read from three independent sources on 2026-10-15.

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// AMDRootFingerprintSHA256 holds the SHA-256 fingerprint (hex) of each
// pinned certificate, by product line; a test asserts the embedded bytes
// hash to them, so an accidental edit of a certificate trips CI.
var AMDRootFingerprintSHA256 = map[string]string{
	"Milan": "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
	"Genoa": "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
	"Turin": "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a",
}

// AMDProducts are the product lines with a pinned root, in the order AMD
// shipped them.
var AMDProducts = []string{"Milan", "Genoa", "Turin"}

const amdARKMilanPEM = `-----BEGIN CERTIFICATE-----
MIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC
BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS
BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg
Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp
Y2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy
MTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS
BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j
ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg
W41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta
1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2
SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0
60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05
gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg
bKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs
+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi
Qi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ
eTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18
fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j
WhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI
rFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG
KWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG
SIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI
AWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel
ETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw
STjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK
dHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq
zT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp
KGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e
pmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq
HnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh
3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn
JZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH
CViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4
AFZEAwoKCQ==
-----END CERTIFICATE-----`

const amdARKGenoaPEM = `-----BEGIN CERTIFICATE-----
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
/wMz1R1BHg==
-----END CERTIFICATE-----`

const amdARKTurinPEM = `-----BEGIN CERTIFICATE-----
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
zpacMwFusA==
-----END CERTIFICATE-----`

type amdRoot struct {
	product     string
	cert        *x509.Certificate
	fingerprint string
}

var (
	amdRootsOnce sync.Once
	amdRoots     []amdRoot
	amdRootsErr  error
)

// pinnedAMDRoots parses the embedded certificates once.
func pinnedAMDRoots() ([]amdRoot, error) {
	amdRootsOnce.Do(func() {
		for _, r := range []struct{ product, pemText string }{
			{"Milan", amdARKMilanPEM}, {"Genoa", amdARKGenoaPEM}, {"Turin", amdARKTurinPEM},
		} {
			blk, _ := pem.Decode([]byte(r.pemText))
			if blk == nil {
				amdRootsErr = fmt.Errorf("pinned AMD root %s: no PEM block", r.product)
				return
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				amdRootsErr = fmt.Errorf("pinned AMD root %s: %w", r.product, err)
				return
			}
			sum := sha256.Sum256(c.Raw)
			amdRoots = append(amdRoots, amdRoot{product: r.product, cert: c, fingerprint: hex.EncodeToString(sum[:])})
		}
	})
	return amdRoots, amdRootsErr
}

// pinnedAMDRootFor reports which product line's pinned root the
// certificate is, byte for byte; "" when it is none of them.
func pinnedAMDRootFor(c *x509.Certificate) string {
	roots, err := pinnedAMDRoots()
	if err != nil {
		return ""
	}
	for _, r := range roots {
		if bytes.Equal(r.cert.Raw, c.Raw) {
			return r.product
		}
	}
	return ""
}

// certFingerprintSHA256 is the hex SHA-256 of the certificate's DER bytes,
// what `openssl x509 -fingerprint -sha256` prints without the colons.
func certFingerprintSHA256(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// errForeignAMDRoot is the refusal every verifier gives a chain whose root
// is not one this build pins.
func errForeignAMDRoot(ark *x509.Certificate) error {
	return fmt.Errorf("ARK %q (sha256 %s) is not an AMD root this build pins (ARK-Milan, ARK-Genoa, ARK-Turin; ADR 0024)",
		ark.Subject.CommonName, certFingerprintSHA256(ark))
}

// AMDChainInfo is what VerifyAMDCertChain learned about a chain.
type AMDChainInfo struct {
	// Product is the line whose pinned root the chain ends in: Milan,
	// Genoa or Turin.
	Product string
	// ASKSubjectCN and ARKSubjectCN are the certificates' common names
	// (SEV-<product>, ARK-<product>).
	ASKSubjectCN string
	ARKSubjectCN string
	// ARKFingerprintSHA256 is the root's fingerprint, hex.
	ARKFingerprintSHA256 string
}

// VerifyAMDCertChain checks an ASK+ARK bundle (PEM, either order) the way
// the verifiers will use it: the ASK signed by the ARK, the ARK
// self-signed, and the ARK one of the roots this build pins. The daemons
// call it when they load amd_cert_chain_path, so a wrong file is refused
// at start, not at the first handshake.
func VerifyAMDCertChain(chainPEM []byte) (AMDChainInfo, error) {
	ask, ark, err := parseASKARK(chainPEM)
	if err != nil {
		return AMDChainInfo{}, err
	}
	if err := ark.CheckSignature(ask.SignatureAlgorithm, ask.RawTBSCertificate, ask.Signature); err != nil {
		return AMDChainInfo{}, fmt.Errorf("ASK not signed by ARK: %w", err)
	}
	if err := ark.CheckSignature(ark.SignatureAlgorithm, ark.RawTBSCertificate, ark.Signature); err != nil {
		return AMDChainInfo{}, fmt.Errorf("ARK not self-signed (root mismatch): %w", err)
	}
	product := pinnedAMDRootFor(ark)
	if product == "" {
		return AMDChainInfo{}, errForeignAMDRoot(ark)
	}
	return AMDChainInfo{
		Product:              product,
		ASKSubjectCN:         ask.Subject.CommonName,
		ARKSubjectCN:         ark.Subject.CommonName,
		ARKFingerprintSHA256: certFingerprintSHA256(ark),
	}, nil
}

// amdProductName canonicalises a product line name as KDS spells it.
func amdProductName(product string) (string, error) {
	for _, p := range AMDProducts {
		if strings.EqualFold(p, product) {
			return p, nil
		}
	}
	return "", fmt.Errorf("unknown AMD product line %q (one of milan, genoa, turin)", product)
}

// FetchAMDCertChain fetches the ASK+ARK bundle of a product line from AMD
// KDS (baseURL "" for https://kdsintf.amd.com; a mirror otherwise) and
// verifies it against the pinned roots before returning it, so what it
// returns is a chain the verifiers will accept and nothing else.
func FetchAMDCertChain(baseURL, product string) ([]byte, AMDChainInfo, error) {
	p, err := amdProductName(product)
	if err != nil {
		return nil, AMDChainInfo{}, err
	}
	chain, err := realAMDKDSGetCertChainFor(baseURL, p)
	if err != nil {
		return nil, AMDChainInfo{}, fmt.Errorf("fetch %s chain: %w", p, err)
	}
	info, err := VerifyAMDCertChain(chain)
	if err != nil {
		return nil, AMDChainInfo{}, fmt.Errorf("the %s chain served does not verify: %w", p, err)
	}
	if info.Product != p {
		return nil, AMDChainInfo{}, errors.New("the server returned a " + info.Product + " chain for " + p)
	}
	return chain, info, nil
}
