// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package cms

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// broken is a SEQUENCE whose only child claims more octets than it has:
// dropped in at any position, the reader's refusal comes up through every
// level.
var broken = der(0x30, []byte{0x02, 0x05, 0x00})

// Each structural fault, at each level of the message, is refused, and
// the refusal names the level where the shape is wrong.
func TestStructuralFaultsAtEveryLevel(t *testing.T) {
	key := testKey(t)
	plain := []byte("thirty-two bytes of a data key!!")
	oaep := func(params ...[]byte) []byte { return algID(oidRSAESOAEP, params...) }
	for name, tc := range map[string]struct {
		edit func(b *build)
		want string
	}{
		"OAEP without parameters":  {func(b *build) { b.keyAlg = oaep() }, "RSAES-OAEP without parameters"},
		"OAEP parameters a string": {func(b *build) { b.keyAlg = oaep(octet(nil)) }, "RSAES-OAEP-params: found universal 4"},
		"key algorithm a string":   {func(b *build) { b.keyAlg = octet(nil) }, "keyEncryptionAlgorithm: found universal 4"},
		"key algorithm not an OID": {func(b *build) { b.keyAlg = seq(integer(1)) }, "keyEncryptionAlgorithm.algorithm: found universal 2"},
		"key algorithm broken":     {func(b *build) { b.keyAlg = broken }, "a length of 5"},
		"OAEP parameters broken":   {func(b *build) { b.keyAlg = oaep(broken) }, "a length of 5"},
		"[0] holds two":            {func(b *build) { b.keyAlg = oaep(seq(ctxC(0, sha256Alg(), sha256Alg()))) }, "[0] holds 2 elements"},
		"[0] primitive":            {func(b *build) { b.keyAlg = oaep(seq(der(0x80, sha256Alg()))) }, "out of place"},
		"[0] broken":               {func(b *build) { b.keyAlg = oaep(seq(der(0xa0, broken[2:]))) }, "a length of 5"},
		"hash a string":            {func(b *build) { b.keyAlg = oaep(oaepParams(octet(nil), mgf1(sha256Alg()), nil)) }, "the OAEP hash: found universal 4"},
		"hash with three fields": {func(b *build) {
			b.keyAlg = oaep(oaepParams(seq(oidTLV(oidSHA256), null(), null()), mgf1(sha256Alg()), nil))
		}, "the OAEP hash: 3 fields"},
		"hash empty":        {func(b *build) { b.keyAlg = oaep(oaepParams(seq(), mgf1(sha256Alg()), nil)) }, "the OAEP hash: 0 fields"},
		"hash not an OID":   {func(b *build) { b.keyAlg = oaep(oaepParams(seq(integer(1)), mgf1(sha256Alg()), nil)) }, "the OAEP hash: found universal 2"},
		"hash broken":       {func(b *build) { b.keyAlg = oaep(oaepParams(broken, mgf1(sha256Alg()), nil)) }, "a length of 5"},
		"MGF a string":      {func(b *build) { b.keyAlg = oaep(oaepParams(sha256Alg(), octet(nil), nil)) }, "mask generation function: found universal 4"},
		"MGF one field":     {func(b *build) { b.keyAlg = oaep(oaepParams(sha256Alg(), seq(oidTLV(oidMGF1)), nil)) }, "has 1 fields"},
		"MGF not an OID":    {func(b *build) { b.keyAlg = oaep(oaepParams(sha256Alg(), seq(integer(1), sha256Alg()), nil)) }, "mask generation function: found universal 2"},
		"MGF hash a string": {func(b *build) { b.keyAlg = oaep(oaepParams(sha256Alg(), mgf1(octet(nil)), nil)) }, "the MGF1 hash: found universal 4"},
		"MGF broken":        {func(b *build) { b.keyAlg = oaep(oaepParams(sha256Alg(), broken, nil)) }, "a length of 5"},
		"label a string":    {func(b *build) { b.keyAlg = oaep(oaepParams(sha256Alg(), mgf1(sha256Alg()), octet(nil))) }, "label source: found universal 4"},
		"label one field": {func(b *build) {
			b.keyAlg = oaep(oaepParams(sha256Alg(), mgf1(sha256Alg()), seq(oidTLV(oidPSpecified))))
		}, "label source has 1 fields"},
		"label not pSpecified": {func(b *build) {
			b.keyAlg = oaep(oaepParams(sha256Alg(), mgf1(sha256Alg()), algID(oidSHA256, octet(nil))))
		}, "not id-pSpecified"},
		"label not an OID": {func(b *build) {
			b.keyAlg = oaep(oaepParams(sha256Alg(), mgf1(sha256Alg()), seq(integer(1), octet(nil))))
		}, "label source: found universal 2"},
		"label broken":              {func(b *build) { b.keyAlg = oaep(oaepParams(sha256Alg(), mgf1(sha256Alg()), broken)) }, "a length of 5"},
		"recipients not a SET":      {func(b *build) { b.recipientSet = seq() }, "recipientInfos: found universal 16"},
		"recipients broken":         {func(b *build) { b.recipientSet = der(0x31, []byte{0x02, 0x05, 0x00}) }, "a length of 5"},
		"recipient broken":          {func(b *build) { b.recipients = [][]byte{broken} }, "a length of 5"},
		"recipient version string":  {func(b *build) { b.riVersion = octet([]byte{2}) }, "KeyTransRecipientInfo.version: found universal 4"},
		"encrypted key broken":      {func(b *build) { b.encKey = der(0x24, []byte{0x04, 0x05, 0x00}) }, "a length of 5"},
		"encrypted key chunk a SET": {func(b *build) { b.encKey = der(0x24, set()) }, "not an OCTET STRING"},
		"content info a SET":        {func(b *build) { b.contentInfo = set() }, "EncryptedContentInfo: found universal 17"},
		"content info broken":       {func(b *build) { b.contentInfo = broken }, "a length of 5"},
		"content info four fields":  {func(b *build) { b.contentInfo = seq(b.contentType, b.contentAlg, b.content, null()) }, "has 4 fields"},
		"content type not an OID":   {func(b *build) { b.contentType = integer(1) }, "EncryptedContentInfo.contentType: found universal 2"},
		"content algorithm string":  {func(b *build) { b.contentAlg = octet(nil) }, "contentEncryptionAlgorithm: found universal 4"},
		"content algorithm broken":  {func(b *build) { b.contentAlg = broken }, "a length of 5"},
		"content algorithm not OID": {func(b *build) { b.contentAlg = seq(integer(1), octet(make([]byte, 16))) }, "contentEncryptionAlgorithm.algorithm: found universal 2"},
		"IV constructed":            {func(b *build) { b.contentAlg = algID(oidAES256CBC, der(0x24, octet(make([]byte, 16)))) }, "the AES-CBC IV: found universal 4 (constructed)"},
		"content chunk broken":      {func(b *build) { b.content = der(0xa0, []byte{0x04, 0x05, 0x00}) }, "a length of 5"},
		"version swallows fields":   {func(b *build) { b.version = []byte{0x02, 0x05} }, "EnvelopedData.version: not a small non-negative integer"},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBuild(t, key, plain, nil)
			tc.edit(&b)
			_, err := Decrypt(b.bytes(), key)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// The wrapped key as a constructed OCTET STRING — BER allows it — opens.
func TestAConstructedEncryptedKeyOpens(t *testing.T) {
	key := testKey(t)
	plain := []byte("thirty-two bytes of a data key!!")
	b := newBuild(t, key, plain, nil)
	w := b.encKey[4:] // 384 bytes behind a three-octet long length
	require.Len(t, w, 384)
	b.encKey = indef(0x24, octet(w[:100]), octet(w[100:]))
	got, err := Decrypt(b.bytes(), key)
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

// A padding byte wrong inside the padding, not only in its last octet.
func TestPaddingCheckedWhole(t *testing.T) {
	key := testKey(t)
	b := newBuild(t, key, []byte("thirty-two bytes of a data key!!"), nil)
	ct := append([]byte(nil), b.content[2:]...)
	ct[len(ct)-18] ^= 0x01 // the padding block's 15th byte; its last stays 0x10
	b.content = der(0x80, ct)
	_, err := Decrypt(b.bytes(), key)
	require.ErrorContains(t, err, "padding is not PKCS #7")
}

func TestContentInfoLevelFaults(t *testing.T) {
	key := testKey(t)
	for name, tc := range map[string]struct {
		in   []byte
		want string
	}{
		"ContentInfo broken":   {der(0x30, []byte{0x06, 0x05, 0x00}), "a length of 5"},
		"content [0] broken":   {seq(oidTLV(oidEnvelopedData), der(0xa0, []byte{0x30, 0x05, 0x00})), "a length of 5"},
		"EnvelopedData broken": {seq(oidTLV(oidEnvelopedData), ctxC(0, broken)), "a length of 5"},
		"type not an OID":      {seq(integer(1), ctxC(0, seq())), "ContentInfo.contentType: found universal 2"},
		"cut ContentInfo":      {[]byte{0x30, 0x05, 0x06}, "a length of 5"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decrypt(tc.in, key)
			require.ErrorContains(t, err, tc.want)
		})
	}
}
