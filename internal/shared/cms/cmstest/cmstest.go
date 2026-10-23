// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cmstest writes CMS EnvelopedData in the profile KMS answers an
// attested request with, for the fakes of KMS in tests (ADR 0036, part
// three). The product reads that profile (internal/shared/cms) and never
// writes it; only tests import this package.
package cmstest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// EnvelopedData encrypts plaintext to pub as KMS does: a random AES-256
// content key wrapped with RSAES-OAEP-SHA-256 (MGF1-SHA-256, no label),
// the content in AES-256-CBC with PKCS #7 padding, one recipient named by
// a subject key identifier, DER.
func EnvelopedData(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	cek := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := rand.Read(cek); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	defer clear(cek)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, cek, nil)
	if err != nil {
		return nil, fmt.Errorf("cmstest: wrap: %w", err)
	}
	pad := 16 - len(plaintext)%16
	padded := make([]byte, len(plaintext)+pad)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	clear(padded)

	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	ski := sha256.Sum256(spki)

	sha256Alg := seq(oid(2, 16, 840, 1, 101, 3, 4, 2, 1))
	oaep := seq(oid(1, 2, 840, 113549, 1, 1, 7), seq(
		tagged(0xa0, sha256Alg),
		tagged(0xa1, seq(oid(1, 2, 840, 113549, 1, 1, 8), sha256Alg)),
	))
	ktri := seq(integer(2), tagged(0x80, ski[:20]), oaep, tagged(0x04, wrapped))
	eci := seq(
		oid(1, 2, 840, 113549, 1, 7, 1),
		seq(oid(2, 16, 840, 1, 101, 3, 4, 1, 42), tagged(0x04, iv)),
		tagged(0x80, ct),
	)
	ed := seq(integer(2), tagged(0x31, ktri), eci)
	return seq(oid(1, 2, 840, 113549, 1, 7, 3), tagged(0xa0, ed)), nil
}

func tagged(tag byte, content ...[]byte) []byte {
	var c []byte
	for _, p := range content {
		c = append(c, p...)
	}
	n := len(c)
	var head []byte
	switch {
	case n < 0x80:
		head = []byte{tag, byte(n)}
	case n < 0x100:
		head = []byte{tag, 0x81, byte(n)}
	default:
		head = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	}
	return append(head, c...)
}

func seq(c ...[]byte) []byte { return tagged(0x30, c...) }
func integer(v byte) []byte  { return tagged(0x02, []byte{v}) }

func oid(ids ...int) []byte {
	der, err := asn1.Marshal(asn1.ObjectIdentifier(ids))
	if err != nil {
		panic(err)
	}
	return der
}
