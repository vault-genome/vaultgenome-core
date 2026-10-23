// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package cms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func readVector(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return b
}

func vectorKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(readVector(t, "recipient-key.pem"))
	require.NotNil(t, block)
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	return k.(*rsa.PrivateKey)
}

// OpenSSL's profile vectors open to their plaintext — DER and BER, the
// content whole and in chunks, 32 bytes and KMS's largest 4096.
func TestOpenSSLProfileVectorsOpen(t *testing.T) {
	key := vectorKey(t)
	for file, plain := range map[string]string{
		"kms-profile-32.der":          "plain-32.bin",
		"kms-profile-32-stream.ber":   "plain-32.bin",
		"kms-profile-4096.der":        "plain-4096.bin",
		"kms-profile-4096-stream.ber": "plain-4096.bin",
	} {
		t.Run(file, func(t *testing.T) {
			got, err := Decrypt(readVector(t, file), key)
			require.NoError(t, err)
			require.Equal(t, readVector(t, plain), got)
		})
	}
}

// What was read from a profile vector is what OpenSSL wrote: the
// certificate's subject key identifier, a 384-byte wrapped key for the
// 3072-bit key, a 16-byte IV, whole blocks of ciphertext.
func TestParseReadsTheProfile(t *testing.T) {
	block, _ := pem.Decode(readVector(t, "recipient-cert.pem"))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	for _, f := range []string{"kms-profile-32.der", "kms-profile-32-stream.ber"} {
		ed, err := Parse(readVector(t, f))
		require.NoError(t, err)
		require.Equal(t, cert.SubjectKeyId, ed.SubjectKeyIdentifier, f)
		require.Len(t, ed.EncryptedKey, 384, f)
		require.Len(t, ed.IV, 16, f)
		require.Len(t, ed.EncryptedContent, 48, f)
	}
}

// OpenSSL's vectors outside the profile are refused, each by name.
func TestOpenSSLVectorsOutsideTheProfileAreRefused(t *testing.T) {
	key := vectorKey(t)
	for file, want := range map[string]string{
		"oaep-sha1.der":       "RSAES-OAEP-params without hashAlgorithm — SHA-1 by default",
		"pkcs1v15.der":        "wrapped with 1.2.840.113549.1.1.1, not RSAES-OAEP",
		"aes128cbc.der":       "encrypted with 2.16.840.1.101.3.4.1.2, not AES-256-CBC",
		"issuer-serial.der":   "EnvelopedData version 0",
		"two-recipients.der":  "2 recipients",
		"aes256gcm.der":       "content type is 1.2.840.113549.1.9.16.1.23, not id-envelopedData",
		"other-recipient.der": "does not unwrap with this key",
	} {
		t.Run(file, func(t *testing.T) {
			_, err := Decrypt(readVector(t, file), key)
			require.ErrorContains(t, err, want)
		})
	}
}

func TestDecryptRefusesAKeyOfAnotherSize(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = Decrypt(readVector(t, "kms-profile-32.der"), small)
	require.ErrorContains(t, err, "not wrapped to this key")
	_, err = Decrypt(readVector(t, "kms-profile-32.der"), nil)
	require.ErrorContains(t, err, "no key")
}

// Every prefix of a profile vector is refused, and none panics.
func TestEveryTruncationIsRefused(t *testing.T) {
	for _, f := range []string{"kms-profile-32.der", "kms-profile-32-stream.ber"} {
		b := readVector(t, f)
		for i := 0; i < len(b); i++ {
			_, err := Parse(b[:i])
			require.Error(t, err, "%s cut at %d", f, i)
		}
	}
}

// ---- a test encoder for what OpenSSL does not write ------------------------

func der(tag byte, content ...[]byte) []byte {
	var c []byte
	for _, p := range content {
		c = append(c, p...)
	}
	return append(derHeader(tag, len(c)), c...)
}

func derHeader(tag byte, n int) []byte {
	switch {
	case n < 0x80:
		return []byte{tag, byte(n)}
	case n < 0x100:
		return []byte{tag, 0x81, byte(n)}
	default:
		return []byte{tag, 0x82, byte(n >> 8), byte(n)}
	}
}

func indef(tag byte, content ...[]byte) []byte {
	out := []byte{tag, 0x80}
	for _, p := range content {
		out = append(out, p...)
	}
	return append(out, 0, 0)
}

func seq(c ...[]byte) []byte          { return der(0x30, c...) }
func set(c ...[]byte) []byte          { return der(0x31, c...) }
func octet(b []byte) []byte           { return der(0x04, b) }
func integer(v byte) []byte           { return der(0x02, []byte{v}) }
func null() []byte                    { return []byte{0x05, 0x00} }
func ctxC(n byte, c ...[]byte) []byte { return der(0xa0|n, c...) }
func oidTLV(o oid) []byte             { return der(0x06, o) }
func algID(o oid, params ...[]byte) []byte {
	return seq(append([][]byte{oidTLV(o)}, params...)...)
}

// build is a valid profile message, with each part replaceable.
type build struct {
	version, riVersion []byte
	rid                []byte
	keyAlg             []byte
	encKey             []byte
	contentType        []byte
	contentAlg         []byte
	content            []byte
	extraBefore        [][]byte // fields between version and recipientInfos
	extraAfter         [][]byte // fields after encryptedContentInfo
	recipients         [][]byte
	recipientSet       []byte // replaces the whole recipientInfos field
	contentInfo        []byte // replaces the whole encryptedContentInfo field
}

func oaepParams(hash, mgf, label []byte) []byte {
	var p [][]byte
	if hash != nil {
		p = append(p, ctxC(0, hash))
	}
	if mgf != nil {
		p = append(p, ctxC(1, mgf))
	}
	if label != nil {
		p = append(p, ctxC(2, label))
	}
	return seq(p...)
}

func sha256Alg() []byte    { return algID(oidSHA256) }
func mgf1(h []byte) []byte { return algID(oidMGF1, h) }

// newBuild encrypts plain to key's public half in the profile.
func newBuild(t *testing.T, key *rsa.PrivateKey, plain []byte, cek []byte) build {
	t.Helper()
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	require.NoError(t, err)
	if cek == nil {
		cek = make([]byte, 32)
		_, err = rand.Read(cek)
		require.NoError(t, err)
	}
	pad := 16 - len(plain)%16
	padded := append(append([]byte(nil), plain...), make([]byte, pad)...)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	blockKey := cek
	if len(blockKey) != 16 && len(blockKey) != 24 && len(blockKey) != 32 {
		blockKey = make([]byte, 32)
	}
	block, err := aes.NewCipher(blockKey)
	require.NoError(t, err)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, cek, nil)
	require.NoError(t, err)
	return build{
		version:     integer(2),
		riVersion:   integer(2),
		rid:         der(0x80, []byte("subject-key-identifier")),
		keyAlg:      algID(oidRSAESOAEP, oaepParams(sha256Alg(), mgf1(sha256Alg()), nil)),
		encKey:      octet(wrapped),
		contentType: oidTLV(oidData),
		contentAlg:  algID(oidAES256CBC, octet(iv)),
		content:     der(0x80, ct),
	}
}

func (b build) bytes() []byte {
	ri := seq(b.riVersion, b.rid, b.keyAlg, b.encKey)
	recips := b.recipients
	if recips == nil {
		recips = [][]byte{ri}
	}
	fields := [][]byte{b.version}
	fields = append(fields, b.extraBefore...)
	if b.recipientSet != nil {
		fields = append(fields, b.recipientSet)
	} else {
		fields = append(fields, set(recips...))
	}
	if b.contentInfo != nil {
		fields = append(fields, b.contentInfo)
	} else {
		fields = append(fields, seq(b.contentType, b.contentAlg, b.content))
	}
	fields = append(fields, b.extraAfter...)
	return seq(oidTLV(oidEnvelopedData), ctxC(0, seq(fields...)))
}

func testKey(t *testing.T) *rsa.PrivateKey { return vectorKey(t) }

func TestTheTestEncoderMakesTheProfile(t *testing.T) {
	key := testKey(t)
	got, err := Decrypt(newBuild(t, key, []byte("a data key, 32 bytes long......."), nil).bytes(), key)
	require.NoError(t, err)
	require.Equal(t, []byte("a data key, 32 bytes long......."), got)
}

// The variants the standards allow and the profile can carry open: a NULL
// parameter after SHA-256 (RFC 4055 §2.1 makes it equal to absent), the
// empty label written out, the content as nested constructed strings.
func TestEquivalentEncodingsOpen(t *testing.T) {
	key := testKey(t)
	plain := []byte("thirty-two bytes of a data key!!")
	b := newBuild(t, key, plain, nil)
	b.keyAlg = algID(oidRSAESOAEP, oaepParams(algID(oidSHA256, null()), mgf1(algID(oidSHA256, null())), algID(oidPSpecified, octet(nil))))
	got, err := Decrypt(b.bytes(), key)
	require.NoError(t, err)
	require.Equal(t, plain, got)

	// The ciphertext as [0] constructed, indefinite, of a constructed
	// OCTET STRING of two parts.
	b = newBuild(t, key, plain, nil)
	ct := b.content[2:]
	b.content = indef(0xa0, der(0x24, octet(ct[:16]), octet(ct[16:])))
	got, err = Decrypt(b.bytes(), key)
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

// Each part outside the profile is refused by name.
func TestRefusalsOutsideTheProfile(t *testing.T) {
	key := testKey(t)
	plain := []byte("thirty-two bytes of a data key!!")
	for name, tc := range map[string]struct {
		edit func(b *build)
		want string
	}{
		"originatorInfo":      {func(b *build) { b.extraBefore = [][]byte{ctxC(0)} }, "originatorInfo"},
		"unprotectedAttrs":    {func(b *build) { b.extraAfter = [][]byte{der(0xa1)} }, "unprotectedAttrs"},
		"a fourth field":      {func(b *build) { b.extraAfter = [][]byte{integer(1)} }, "the profile has three"},
		"version 3":           {func(b *build) { b.version = integer(3) }, "EnvelopedData version 3"},
		"recipient version 0": {func(b *build) { b.riVersion = integer(0) }, "KeyTransRecipientInfo version 0"},
		"rid not [0]":         {func(b *build) { b.rid = seq() }, "subjectKeyIdentifier"},
		"empty rid":           {func(b *build) { b.rid = der(0x80) }, "subject key identifier of 0 bytes"},
		"OAEP without hash":   {func(b *build) { b.keyAlg = algID(oidRSAESOAEP, oaepParams(nil, mgf1(sha256Alg()), nil)) }, "without hashAlgorithm"},
		"OAEP without MGF":    {func(b *build) { b.keyAlg = algID(oidRSAESOAEP, oaepParams(sha256Alg(), nil, nil)) }, "without maskGenAlgorithm"},
		"OAEP with SHA-384": {func(b *build) {
			b.keyAlg = algID(oidRSAESOAEP, oaepParams(algID(mustOID(2, 16, 840, 1, 101, 3, 4, 2, 2)), mgf1(sha256Alg()), nil))
		}, "the OAEP hash is 2.16.840.1.101.3.4.2.2"},
		"MGF1 with SHA-1": {func(b *build) {
			b.keyAlg = algID(oidRSAESOAEP, oaepParams(sha256Alg(), mgf1(algID(mustOID(1, 3, 14, 3, 2, 26))), nil))
		}, "the MGF1 hash is 1.3.14.3.2.26"},
		"not MGF1": {func(b *build) {
			b.keyAlg = algID(oidRSAESOAEP, oaepParams(sha256Alg(), algID(oidSHA256, sha256Alg()), nil))
		}, "not MGF1"},
		"a label": {func(b *build) {
			b.keyAlg = algID(oidRSAESOAEP, oaepParams(sha256Alg(), mgf1(sha256Alg()), algID(oidPSpecified, octet([]byte("label")))))
		}, "an OAEP label"},
		"params out of order": {func(b *build) { b.keyAlg = algID(oidRSAESOAEP, seq(ctxC(1, mgf1(sha256Alg())), ctxC(0, sha256Alg()))) }, "out of place"},
		"hash parameter": {func(b *build) {
			b.keyAlg = algID(oidRSAESOAEP, oaepParams(algID(oidSHA256, octet([]byte{1})), mgf1(sha256Alg()), nil))
		}, "parameters other than NULL"},
		"IV of 8 bytes":       {func(b *build) { b.contentAlg = algID(oidAES256CBC, octet(make([]byte, 8))) }, "an IV of 8 bytes"},
		"no IV":               {func(b *build) { b.contentAlg = algID(oidAES256CBC) }, "the algorithm and its IV"},
		"content type":        {func(b *build) { b.contentType = oidTLV(mustOID(1, 2, 840, 113549, 1, 7, 2)) }, "not id-data"},
		"detached content":    {func(b *build) { b.content = nil }, "detached content"},
		"half a block":        {func(b *build) { b.content = der(0x80, make([]byte, 8)) }, "whole blocks"},
		"content not [0]":     {func(b *build) { b.content = octet(make([]byte, 16)) }, "want [0]"},
		"chunk not a string":  {func(b *build) { b.content = indef(0xa0, integer(1)) }, "not an OCTET STRING"},
		"two recipients":      {func(b *build) { r := seq(b.riVersion, b.rid, b.keyAlg, b.encKey); b.recipients = [][]byte{r, r} }, "2 recipients"},
		"no recipient":        {func(b *build) { b.recipients = [][]byte{} }, "0 recipients"},
		"password recipient":  {func(b *build) { b.recipients = [][]byte{der(0xa3, integer(0))} }, "not a KeyTransRecipientInfo"},
		"encrypted key a SET": {func(b *build) { b.encKey = set() }, "encryptedKey: found universal 17"},
		"empty encrypted key": {func(b *build) { b.encKey = octet(nil) }, "an empty encrypted key"},
		"three-field ktri":    {func(b *build) { b.recipients = [][]byte{seq(b.riVersion, b.rid, b.keyAlg)} }, "want four"},
		"version a string":    {func(b *build) { b.version = octet([]byte{2}) }, "EnvelopedData.version: found universal 4"},
		"version 300":         {func(b *build) { b.version = der(0x02, []byte{0x01, 0x2c}) }, "not a small non-negative integer"},
		"an empty key alg":    {func(b *build) { b.keyAlg = seq() }, "an empty keyEncryptionAlgorithm"},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBuild(t, key, plain, nil)
			tc.edit(&b)
			_, err := Decrypt(b.bytes(), key)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestDecryptRefusesWhatOpensWrong(t *testing.T) {
	key := testKey(t)
	// A 16-byte content key: AES-128 is not the profile.
	b := newBuild(t, key, []byte("x"), make([]byte, 16))
	_, err := Decrypt(b.bytes(), key)
	require.ErrorContains(t, err, "a content key of 16 bytes")

	// Bad padding: the last block decrypts to anything but PKCS #7.
	b = newBuild(t, key, []byte("thirty-two bytes of a data key!!"), nil)
	ct := append([]byte(nil), b.content[2:]...)
	ct[len(ct)-17] ^= 0x01 // flips the last byte of the last plaintext block
	b.content = der(0x80, ct)
	_, err = Decrypt(b.bytes(), key)
	require.ErrorContains(t, err, "padding is not PKCS #7")
}

func TestTheEnvelopeAroundTheEnvelopedData(t *testing.T) {
	key := testKey(t)
	good := newBuild(t, key, []byte("x"), nil).bytes()
	for name, tc := range map[string]struct {
		in   []byte
		want string
	}{
		"empty":             {nil, "empty"},
		"too large":         {make([]byte, MaxInputBytes+1), "at most"},
		"trailing bytes":    {append(append([]byte(nil), good...), 0x00), "1 bytes after the ContentInfo"},
		"not a SEQUENCE":    {octet([]byte{1}), "ContentInfo: found universal 4"},
		"one field":         {seq(oidTLV(oidEnvelopedData)), "has 1 fields"},
		"signed data":       {seq(oidTLV(mustOID(1, 2, 840, 113549, 1, 7, 2)), ctxC(0, seq())), "content type is 1.2.840.113549.1.7.2"},
		"content not [0]":   {seq(oidTLV(oidEnvelopedData), seq()), "ContentInfo.content [0]: found universal 16"},
		"two inside [0]":    {seq(oidTLV(oidEnvelopedData), ctxC(0, seq(), seq())), "holds 2 elements"},
		"EnvelopedData SET": {seq(oidTLV(oidEnvelopedData), ctxC(0, set())), "EnvelopedData: found universal 17"},
		"two fields":        {seq(oidTLV(oidEnvelopedData), ctxC(0, seq(integer(2), set()))), "has 2 fields"},
		"empty OID":         {seq(der(0x06), ctxC(0, seq())), "an empty object identifier"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decrypt(tc.in, key)
			require.ErrorContains(t, err, tc.want)
		})
	}
}
