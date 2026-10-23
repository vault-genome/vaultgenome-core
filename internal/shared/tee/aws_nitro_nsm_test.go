// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The request is held byte for byte to what AWS's NSM API sends for
// Request::Attestation (src/api/mod.rs, serde's default enum form): a
// one-entry map from "Attestation" to the map of its three fields in
// declaration order, None as null, Some(bytes) as a byte string. The
// vectors are written out per RFC 8949 so a reader can check each byte.
func TestNSM_EncodeAttestationRequest_ByteForByte(t *testing.T) {
	const (
		mapOne      = "a1"
		attestation = "6b" + "4174746573746174696f6e" // text(11) "Attestation"
		mapThree    = "a3"
		userData    = "69" + "757365725f64617461"   // text(9) "user_data"
		nonce       = "65" + "6e6f6e6365"           // text(5) "nonce"
		publicKey   = "6a" + "7075626c69635f6b6579" // text(10) "public_key"
		null        = "f6"
	)
	got, err := encodeNSMAttestationRequest(nil, []byte{1, 2, 3}, nil)
	require.NoError(t, err)
	require.Equal(t, mapOne+attestation+mapThree+userData+null+nonce+"43010203"+publicKey+null, hex.EncodeToString(got))

	// A 64-byte nonce takes a one-byte length (0x58 0x40); 1024 bytes of
	// user_data a two-byte one (0x59 0x0400); an empty public_key is
	// Some of nothing (0x40), not null.
	n64 := bytes.Repeat([]byte{0xAB}, 64)
	ud := bytes.Repeat([]byte{0x01}, 1024)
	got, err = encodeNSMAttestationRequest(ud, n64, []byte{})
	require.NoError(t, err)
	want := mapOne + attestation + mapThree + userData + "590400" + strings.Repeat("01", 1024) +
		nonce + "5840" + strings.Repeat("ab", 64) + publicKey + "40"
	require.Equal(t, want, hex.EncodeToString(got))
	require.LessOrEqual(t, len(got), nsmRequestMaxBytes)
}

func TestNSM_EncodeAttestationRequest_Limits(t *testing.T) {
	for _, tc := range []struct {
		name            string
		userData, n, pk []byte
		want            string
	}{
		{"user_data", make([]byte, 1025), nil, nil, "user_data is 1025 bytes"},
		{"nonce", nil, make([]byte, 1025), nil, "nonce is 1025 bytes"},
		{"public_key", nil, nil, make([]byte, 1025), "public_key is 1025 bytes"},
	} {
		_, err := encodeNSMAttestationRequest(tc.userData, tc.n, tc.pk)
		requireStructuralErr(t, err, tc.want)
	}
	// All three at the limit still fit the device's 4096-byte request.
	got, err := encodeNSMAttestationRequest(make([]byte, 1024), make([]byte, 1024), make([]byte, 1024))
	require.NoError(t, err)
	require.LessOrEqual(t, len(got), nsmRequestMaxBytes)
}

// The public key travels as PKIX DER, what the document's public_key
// carries for a relying party (and what KMS takes for a recipient).
func TestNSM_PublicKeyTravelsAsPKIX(t *testing.T) {
	teeFakeMu.Lock()
	t.Cleanup(teeFakeMu.Unlock)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	var sent []byte
	raw := nsmRawCall
	t.Cleanup(func() { nsmRawCall = raw })
	nsmRawCall = func(_ *os.File, req []byte) ([]byte, error) {
		sent = append([]byte(nil), req...)
		return nsmAnswerError("InvalidOperation"), nil
	}
	_, err = nsmGetAttestationDoc(nil, nsmAttestationRequest{Nonce: make([]byte, 32), PublicKey: &key.PublicKey})
	requireIntegrityErr(t, err, "InvalidOperation")
	it, err := cborDecode(sent)
	require.NoError(t, err)
	att, _ := it.mapLookup("Attestation")
	pk, _ := att.mapLookup("public_key")
	require.Equal(t, der, pk.b)
	_, err = nsmGetAttestationDoc(nil, nsmAttestationRequest{Nonce: make([]byte, 32), PublicKey: "not a key"})
	requireStructuralErr(t, err, "not a PKIX key")
}

func TestNSM_DecodeAttestationResponse(t *testing.T) {
	answer := func(build func(e *cborEncoder)) []byte {
		var e cborEncoder
		build(&e)
		return e.buf
	}
	doc := []byte{0xd2, 0x84, 0x44}
	ok := answer(func(e *cborEncoder) {
		e.mapping(1)
		e.text("Attestation")
		e.mapping(1)
		e.text("document")
		e.bytes(doc)
	})
	got, err := decodeNSMAttestationResponse(ok)
	require.NoError(t, err)
	require.Equal(t, doc, got)

	// Every error code of the NSM API is named in the refusal.
	for _, code := range nsmErrorCodes {
		_, err := decodeNSMAttestationResponse(nsmAnswerError(code))
		requireIntegrityErr(t, err, "refused the attestation request: "+code)
	}

	for _, tc := range []struct {
		name string
		resp []byte
		want string
	}{
		{"unknown_error_code", nsmAnswerError("Bogus"), `unknown code "Bogus"`},
		{"unit_variant", answer(func(e *cborEncoder) { e.text("LockPCR") }), "not one response variant"},
		{"other_variant", answer(func(e *cborEncoder) {
			e.mapping(1)
			e.text("GetRandom")
			e.mapping(1)
			e.text("random")
			e.bytes([]byte{1})
		}), `"GetRandom", not Attestation`},
		{"two_variants", answer(func(e *cborEncoder) {
			e.mapping(2)
			e.text("Attestation")
			e.null()
			e.text("Error")
			e.text("InternalError")
		}), "not one response variant"},
		{"extra_field", answer(func(e *cborEncoder) {
			e.mapping(1)
			e.text("Attestation")
			e.mapping(2)
			e.text("document")
			e.bytes(doc)
			e.text("extra")
			e.null()
		}), "without exactly one document"},
		{"document_as_text", answer(func(e *cborEncoder) {
			e.mapping(1)
			e.text("Attestation")
			e.mapping(1)
			e.text("document")
			e.text("d284")
		}), "without exactly one document"},
		{"empty_document", answer(func(e *cborEncoder) {
			e.mapping(1)
			e.text("Attestation")
			e.mapping(1)
			e.text("document")
			e.bytes(nil)
		}), "empty document"},
		{"error_not_text", answer(func(e *cborEncoder) {
			e.mapping(1)
			e.text("Error")
			e.uint(7)
		}), "Error without a code"},
		// DescribePCR's answer carries a boolean; the document's decoder
		// takes none, and the producer never asks for it (ADR 0036).
		{"describe_pcr_boolean", append(answer(func(e *cborEncoder) {
			e.mapping(1)
			e.text("DescribePCR")
			e.mapping(2)
			e.text("lock")
		}), 0xf4), "not CBOR the NSM writes"},
		{"trailing_bytes", append(append([]byte(nil), ok...), 0x00), "not CBOR the NSM writes"},
		{"too_long", make([]byte, nsmResponseMaxBytes+1), "more than the device writes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeNSMAttestationResponse(tc.resp)
			requireIntegrityErr(t, err, tc.want)
		})
	}
}
