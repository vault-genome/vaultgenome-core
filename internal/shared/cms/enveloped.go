// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cms opens the CMS EnvelopedData that AWS KMS answers an attested
// request with (CiphertextForRecipient; ADR 0036, part three): one
// recipient, named by its subject key identifier, whose content key is
// wrapped with RSAES-OAEP — SHA-256, MGF1 with SHA-256, no label — and
// content encrypted with AES-256-CBC. That is the whole profile, read from
// the AWS Nitro Enclaves SDK's own parser (aws-nitro-enclaves-sdk-c at
// cd61b61, source/cms.c, library 4a1eb8e896d2…) and the standards it
// follows — RFC 5652 (CMS), RFC 3560 and RFC 4055 (RSAES-OAEP in CMS and
// its parameters), RFC 3565 (AES in CMS) — and held to vectors OpenSSL 3
// made (testdata). Anything else is refused by name: another algorithm,
// another recipient form, a second recipient, an attribute, trailing bytes.
//
// CBC carries no authentication. What KMS puts in it is a key, and what
// that key opens is authenticated (AES-256-GCM, ADR 0036 decision 4); the
// answer itself came over TLS from KMS.
package cms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

// MaxInputBytes bounds what is parsed. KMS's CiphertextForRecipient is at
// most 6144 bytes (the Decrypt reference); a 4096-byte plaintext — KMS's
// largest — under a 4096-bit key fits well inside.
const MaxInputBytes = 16 << 10

// The versions of the profile: RFC 5652 §6.1 sets EnvelopedData's to 2
// when a recipient is version 2, and §6.2.1 a KeyTransRecipientInfo's to
// 2 when it names its recipient by subject key identifier.
const (
	envelopedDataVersion = 2
	recipientVersion     = 2
	aesBlockSize         = 16
	contentKeyBytes      = 32
)

// EnvelopedData is what was read: the recipient's subject key identifier,
// its wrapped content key, the IV, and the encrypted content.
type EnvelopedData struct {
	SubjectKeyIdentifier []byte
	EncryptedKey         []byte
	IV                   []byte
	EncryptedContent     []byte
}

// Parse reads ber as a ContentInfo carrying EnvelopedData in the profile.
func Parse(ber []byte) (*EnvelopedData, error) {
	if len(ber) == 0 {
		return nil, errors.New("cms: empty")
	}
	if len(ber) > MaxInputBytes {
		return nil, fmt.Errorf("cms: %d bytes; at most %d are read", len(ber), MaxInputBytes)
	}
	ci, rest, err := parseTLV(ber, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("cms: %d bytes after the ContentInfo", len(rest))
	}
	if err := expect(ci, classUniversal, true, tagSequence, "ContentInfo"); err != nil {
		return nil, err
	}
	kids, err := children(ci, 0)
	if err != nil {
		return nil, err
	}
	if len(kids) != 2 {
		return nil, fmt.Errorf("cms: ContentInfo has %d fields, want contentType and content", len(kids))
	}
	ct, err := readOID(kids[0], "ContentInfo.contentType")
	if err != nil {
		return nil, err
	}
	if !ct.equal(oidEnvelopedData) {
		return nil, fmt.Errorf("cms: the content type is %s, not id-envelopedData (1.2.840.113549.1.7.3)", ct)
	}
	if err := expect(kids[1], classContext, true, 0, "ContentInfo.content [0]"); err != nil {
		return nil, err
	}
	wrapped, err := children(kids[1], 1)
	if err != nil {
		return nil, err
	}
	if len(wrapped) != 1 {
		return nil, fmt.Errorf("cms: ContentInfo.content holds %d elements, want one EnvelopedData", len(wrapped))
	}
	return parseEnvelopedData(wrapped[0])
}

func parseEnvelopedData(t tlv) (*EnvelopedData, error) {
	if err := expect(t, classUniversal, true, tagSequence, "EnvelopedData"); err != nil {
		return nil, err
	}
	f, err := children(t, 2)
	if err != nil {
		return nil, err
	}
	if len(f) < 3 {
		return nil, fmt.Errorf("cms: EnvelopedData has %d fields, want version, recipientInfos and encryptedContentInfo", len(f))
	}
	v, err := smallInt(f[0], "EnvelopedData.version")
	if err != nil {
		return nil, err
	}
	if v != envelopedDataVersion {
		return nil, fmt.Errorf("cms: EnvelopedData version %d; the profile is version %d", v, envelopedDataVersion)
	}
	if f[1].class == classContext && f[1].tag == 0 {
		return nil, errors.New("cms: EnvelopedData carries originatorInfo; the profile has none")
	}
	if len(f) != 3 {
		if f[3].class == classContext && f[3].tag == 1 {
			return nil, errors.New("cms: EnvelopedData carries unprotectedAttrs; the profile has none")
		}
		return nil, fmt.Errorf("cms: EnvelopedData has %d fields; the profile has three", len(f))
	}
	ed := &EnvelopedData{}
	if err := parseRecipients(f[1], ed); err != nil {
		return nil, err
	}
	if err := parseEncryptedContentInfo(f[2], ed); err != nil {
		return nil, err
	}
	return ed, nil
}

func parseRecipients(t tlv, ed *EnvelopedData) error {
	if err := expect(t, classUniversal, true, tagSet, "EnvelopedData.recipientInfos"); err != nil {
		return err
	}
	ris, err := children(t, 3)
	if err != nil {
		return err
	}
	if len(ris) != 1 {
		return fmt.Errorf("cms: %d recipients; the profile has exactly one", len(ris))
	}
	ri := ris[0]
	if !ri.is(classUniversal, true, tagSequence) {
		return fmt.Errorf("cms: the recipient is %s, not a KeyTransRecipientInfo", ri.describe())
	}
	f, err := children(ri, 4)
	if err != nil {
		return err
	}
	if len(f) != 4 {
		return fmt.Errorf("cms: KeyTransRecipientInfo has %d fields, want four", len(f))
	}
	v, err := smallInt(f[0], "KeyTransRecipientInfo.version")
	if err != nil {
		return err
	}
	if v != recipientVersion {
		return fmt.Errorf("cms: KeyTransRecipientInfo version %d — the recipient named by issuer and serial number; the profile names it by subject key identifier (version %d)", v, recipientVersion)
	}
	if err := expect(f[1], classContext, false, 0, "KeyTransRecipientInfo.rid [0] subjectKeyIdentifier"); err != nil {
		return err
	}
	if len(f[1].content) == 0 || len(f[1].content) > 64 {
		return fmt.Errorf("cms: a subject key identifier of %d bytes", len(f[1].content))
	}
	ed.SubjectKeyIdentifier = f[1].content
	if err := checkOAEP(f[2]); err != nil {
		return err
	}
	if !f[3].is(classUniversal, false, tagOctetString) && !f[3].is(classUniversal, true, tagOctetString) {
		return fmt.Errorf("cms: KeyTransRecipientInfo.encryptedKey: found %s", f[3].describe())
	}
	ed.EncryptedKey, err = octets(f[3], 5)
	if err != nil {
		return err
	}
	if len(ed.EncryptedKey) == 0 {
		return errors.New("cms: an empty encrypted key")
	}
	return nil
}

// checkOAEP holds keyEncryptionAlgorithm to RSAES-OAEP with SHA-256, MGF1
// with SHA-256 and the empty label (RFC 4055 §3.1). The parameters'
// defaults are SHA-1, so absent parameters are refused, not assumed.
func checkOAEP(t tlv) error {
	if err := expect(t, classUniversal, true, tagSequence, "keyEncryptionAlgorithm"); err != nil {
		return err
	}
	f, err := children(t, 5)
	if err != nil {
		return err
	}
	if len(f) == 0 {
		return errors.New("cms: an empty keyEncryptionAlgorithm")
	}
	alg, err := readOID(f[0], "keyEncryptionAlgorithm.algorithm")
	if err != nil {
		return err
	}
	if !alg.equal(oidRSAESOAEP) {
		return fmt.Errorf("cms: the content key is wrapped with %s, not RSAES-OAEP (1.2.840.113549.1.1.7)", alg)
	}
	if len(f) != 2 {
		return errors.New("cms: RSAES-OAEP without parameters — SHA-1 and MGF1-SHA-1 by default; the profile is SHA-256")
	}
	if err := expect(f[1], classUniversal, true, tagSequence, "RSAES-OAEP-params"); err != nil {
		return err
	}
	params, err := children(f[1], 6)
	if err != nil {
		return err
	}
	var hash, mgf bool
	last := -1
	for _, p := range params {
		if p.class != classContext || !p.constructed || p.tag > 2 || p.tag <= last {
			return fmt.Errorf("cms: RSAES-OAEP-params: %s out of place", p.describe())
		}
		last = p.tag
		inner, err := children(p, 7)
		if err != nil {
			return err
		}
		if len(inner) != 1 {
			return fmt.Errorf("cms: RSAES-OAEP-params [%d] holds %d elements", p.tag, len(inner))
		}
		switch p.tag {
		case 0:
			if err := checkSHA256(inner[0], "the OAEP hash", 8); err != nil {
				return err
			}
			hash = true
		case 1:
			if err := checkMGF1SHA256(inner[0]); err != nil {
				return err
			}
			mgf = true
		case 2:
			if err := checkEmptyLabel(inner[0]); err != nil {
				return err
			}
		}
	}
	if !hash {
		return errors.New("cms: RSAES-OAEP-params without hashAlgorithm — SHA-1 by default; the profile is SHA-256")
	}
	if !mgf {
		return errors.New("cms: RSAES-OAEP-params without maskGenAlgorithm — MGF1-SHA-1 by default; the profile is MGF1-SHA-256")
	}
	return nil
}

// checkSHA256 accepts id-sha256 with absent or NULL parameters, the two
// encodings RFC 4055 §2.1 requires an implementation to accept.
func checkSHA256(t tlv, what string, depth int) error {
	if err := expect(t, classUniversal, true, tagSequence, what); err != nil {
		return err
	}
	f, err := children(t, depth)
	if err != nil {
		return err
	}
	if len(f) == 0 || len(f) > 2 {
		return fmt.Errorf("cms: %s: %d fields", what, len(f))
	}
	alg, err := readOID(f[0], what)
	if err != nil {
		return err
	}
	if !alg.equal(oidSHA256) {
		return fmt.Errorf("cms: %s is %s, not SHA-256 (2.16.840.1.101.3.4.2.1)", what, alg)
	}
	if len(f) == 2 && (!f[1].is(classUniversal, false, tagNull) || len(f[1].content) != 0) {
		return fmt.Errorf("cms: %s: parameters other than NULL", what)
	}
	return nil
}

func checkMGF1SHA256(t tlv) error {
	if err := expect(t, classUniversal, true, tagSequence, "the OAEP mask generation function"); err != nil {
		return err
	}
	f, err := children(t, 8)
	if err != nil {
		return err
	}
	if len(f) != 2 {
		return fmt.Errorf("cms: the OAEP mask generation function has %d fields, want MGF1 and its hash", len(f))
	}
	alg, err := readOID(f[0], "the OAEP mask generation function")
	if err != nil {
		return err
	}
	if !alg.equal(oidMGF1) {
		return fmt.Errorf("cms: the OAEP mask generation function is %s, not MGF1 (1.2.840.113549.1.1.8)", alg)
	}
	return checkSHA256(f[1], "the MGF1 hash", 9)
}

func checkEmptyLabel(t tlv) error {
	if err := expect(t, classUniversal, true, tagSequence, "the OAEP label source"); err != nil {
		return err
	}
	f, err := children(t, 8)
	if err != nil {
		return err
	}
	if len(f) != 2 {
		return fmt.Errorf("cms: the OAEP label source has %d fields", len(f))
	}
	alg, err := readOID(f[0], "the OAEP label source")
	if err != nil {
		return err
	}
	if !alg.equal(oidPSpecified) {
		return fmt.Errorf("cms: the OAEP label source is %s, not id-pSpecified", alg)
	}
	if !f[1].is(classUniversal, false, tagOctetString) || len(f[1].content) != 0 {
		return errors.New("cms: an OAEP label; the profile's label is empty")
	}
	return nil
}

func parseEncryptedContentInfo(t tlv, ed *EnvelopedData) error {
	if err := expect(t, classUniversal, true, tagSequence, "EncryptedContentInfo"); err != nil {
		return err
	}
	f, err := children(t, 3)
	if err != nil {
		return err
	}
	if len(f) == 2 {
		return errors.New("cms: EncryptedContentInfo without encryptedContent — detached content; the profile carries it")
	}
	if len(f) != 3 {
		return fmt.Errorf("cms: EncryptedContentInfo has %d fields, want three", len(f))
	}
	ct, err := readOID(f[0], "EncryptedContentInfo.contentType")
	if err != nil {
		return err
	}
	if !ct.equal(oidData) {
		return fmt.Errorf("cms: the encrypted content type is %s, not id-data (1.2.840.113549.1.7.1)", ct)
	}
	if err := expect(f[1], classUniversal, true, tagSequence, "contentEncryptionAlgorithm"); err != nil {
		return err
	}
	alg, err := children(f[1], 4)
	if err != nil {
		return err
	}
	if len(alg) != 2 {
		return fmt.Errorf("cms: contentEncryptionAlgorithm has %d fields, want the algorithm and its IV", len(alg))
	}
	a, err := readOID(alg[0], "contentEncryptionAlgorithm.algorithm")
	if err != nil {
		return err
	}
	if !a.equal(oidAES256CBC) {
		return fmt.Errorf("cms: the content is encrypted with %s, not AES-256-CBC (2.16.840.1.101.3.4.1.42)", a)
	}
	// RFC 3565 §4.1: AES-IV ::= OCTET STRING (SIZE(16)).
	if err := expect(alg[1], classUniversal, false, tagOctetString, "the AES-CBC IV"); err != nil {
		return err
	}
	if len(alg[1].content) != aesBlockSize {
		return fmt.Errorf("cms: an IV of %d bytes; AES-CBC's is %d", len(alg[1].content), aesBlockSize)
	}
	ed.IV = alg[1].content
	if f[2].class != classContext || f[2].tag != 0 {
		return fmt.Errorf("cms: EncryptedContentInfo.encryptedContent: found %s, want [0]", f[2].describe())
	}
	ed.EncryptedContent, err = octets(f[2], 4)
	if err != nil {
		return err
	}
	if n := len(ed.EncryptedContent); n == 0 || n%aesBlockSize != 0 {
		return fmt.Errorf("cms: %d bytes of AES-CBC ciphertext; it comes in whole blocks of %d", n, aesBlockSize)
	}
	return nil
}

// Decrypt opens ber with key, the private half of the key KMS wrapped the
// content key to: RSAES-OAEP-SHA-256 unwraps the 32-byte content key,
// AES-256-CBC decrypts the content, and its PKCS #7 padding (RFC 5652
// §6.3) is removed.
func Decrypt(ber []byte, key *rsa.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("cms: no key")
	}
	ed, err := Parse(ber)
	if err != nil {
		return nil, err
	}
	if len(ed.EncryptedKey) != key.Size() {
		return nil, fmt.Errorf("cms: an encrypted key of %d bytes for a %d-bit key; not wrapped to this key", len(ed.EncryptedKey), key.N.BitLen())
	}
	cek, err := rsa.DecryptOAEP(sha256.New(), nil, key, ed.EncryptedKey, nil)
	if err != nil {
		return nil, errors.New("cms: the content key does not unwrap with this key (RSAES-OAEP-SHA-256)")
	}
	defer clear(cek)
	if len(cek) != contentKeyBytes {
		return nil, fmt.Errorf("cms: a content key of %d bytes; AES-256's is %d", len(cek), contentKeyBytes)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("cms: %w", err)
	}
	plain := make([]byte, len(ed.EncryptedContent))
	cipher.NewCBCDecrypter(block, ed.IV).CryptBlocks(plain, ed.EncryptedContent)
	n := int(plain[len(plain)-1])
	ok := n >= 1 && n <= aesBlockSize
	if ok {
		for _, c := range plain[len(plain)-n:] {
			if int(c) != n {
				ok = false
			}
		}
	}
	if !ok {
		clear(plain)
		return nil, errors.New("cms: the decrypted content's padding is not PKCS #7")
	}
	out := append([]byte(nil), plain[:len(plain)-n]...)
	clear(plain)
	return out, nil
}
