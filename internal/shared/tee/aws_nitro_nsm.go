// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The NSM spoken from its interface (ADR 0036, part one).
//
// /dev/nsm takes one ioctl, NSM_IOCTL_RAW = _IOWR(0x0A, 0, struct
// nsm_raw): two iovecs, a request of at most 4096 bytes and a response
// buffer of at most 12288 (Linux include/uapi/linux/nsm.h; AWS's NSM API
// driver, src/driver/mod.rs, uses the same request code). The request
// and the response are CBOR: the enums of AWS's NSM API (src/api/mod.rs)
// as serde writes them by default — a variant with fields is a one-entry
// map from the variant's name to a map of its fields in declaration
// order, an absent Option is null, a byte buffer is a byte string, a
// unit variant is its name. This file encodes the one request the
// producer sends, Attestation, byte for byte as that code does (held by a
// test), and decodes its two answers, Attestation and Error, with the
// attestation document's own strict decoder (ADR 0035): any other answer
// is refused. The ioctl itself is aws_nitro_nsm_linux.go; nsmRawCall is
// the only seam the tests replace.

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

const (
	// nsmRequestMaxBytes is NSM_REQUEST_MAX_SIZE.
	nsmRequestMaxBytes = 0x1000
	// nsmResponseMaxBytes is NSM_RESPONSE_MAX_SIZE.
	nsmResponseMaxBytes = 0x3000
	// nsmFieldMaxBytes bounds user_data, nonce and public_key (the
	// attestation document's specification: user_data = bytes .size (0..1024)).
	nsmFieldMaxBytes = 1024
)

// nsmErrorCodes are the ErrorCode variants of AWS's NSM API, in the order
// the source declares them.
var nsmErrorCodes = []string{
	"Success", "InvalidArgument", "InvalidIndex", "InvalidResponse", "ReadOnlyIndex",
	"InvalidOperation", "BufferTooSmall", "InputTooLarge", "InternalError",
}

// nsmAttestationRequest is what the producer asks the NSM to sign: the
// verifier's challenge in Nonce; UserData and PublicKey when configured.
type nsmAttestationRequest struct {
	Nonce     []byte
	UserData  []byte
	PublicKey crypto.PublicKey
}

// nsmRawCall sends one request through NSM_IOCTL_RAW and returns the
// response the device wrote. It is the ioctl on Linux and a refusal
// elsewhere; the tests replace it with a device that answers in CBOR.
var nsmRawCall = nsmRawCallOS

// nsmGetAttestationDoc asks the NSM for an attestation document over req
// and returns the raw COSE_Sign1 bytes, as Evidence must carry them.
func nsmGetAttestationDoc(f *os.File, req nsmAttestationRequest) ([]byte, error) {
	var pub []byte
	if req.PublicKey != nil {
		der, err := x509.MarshalPKIXPublicKey(req.PublicKey)
		if err != nil {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				"aws-nitro: the public key for the NSM is not a PKIX key", err)
		}
		pub = der
	}
	enc, err := encodeNSMAttestationRequest(req.UserData, req.Nonce, pub)
	if err != nil {
		return nil, err
	}
	resp, err := nsmRawCall(f, enc)
	if err != nil {
		return nil, err
	}
	return decodeNSMAttestationResponse(resp)
}

// encodeNSMAttestationRequest writes Request::Attestation { user_data,
// nonce, public_key } as AWS's NSM API serialises it. A nil field is the
// absent Option (null); a non-nil empty one is Some of zero bytes.
func encodeNSMAttestationRequest(userData, nonce, publicKey []byte) ([]byte, error) {
	fields := []struct {
		name string
		b    []byte
	}{{"user_data", userData}, {"nonce", nonce}, {"public_key", publicKey}}
	var e cborEncoder
	e.mapping(1)
	e.text("Attestation")
	e.mapping(len(fields))
	for _, f := range fields {
		if len(f.b) > nsmFieldMaxBytes {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("aws-nitro: the NSM's %s is %d bytes; it takes at most %d", f.name, len(f.b), nsmFieldMaxBytes), nil)
		}
		e.text(f.name)
		if f.b == nil {
			e.null()
		} else {
			e.bytes(f.b)
		}
	}
	if len(e.buf) > nsmRequestMaxBytes {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("aws-nitro: an NSM request of %d bytes exceeds the device's %d", len(e.buf), nsmRequestMaxBytes), nil)
	}
	return e.buf, nil
}

// decodeNSMAttestationResponse reads Response::Attestation { document }
// and returns the document; Response::Error(code) is a refusal naming the
// code; any other answer is refused.
func decodeNSMAttestationResponse(resp []byte) ([]byte, error) {
	refuse := func(why string) error {
		return shared_errors.Integrity(shared_errors.CodeAttestationDenied, "aws-nitro: the NSM's answer "+why, nil)
	}
	if len(resp) > nsmResponseMaxBytes {
		return nil, refuse(fmt.Sprintf("is %d bytes, more than the device writes", len(resp)))
	}
	it, err := cborDecode(resp)
	if err != nil {
		return nil, refuse(fmt.Sprintf("is not CBOR the NSM writes: %v", err))
	}
	if it.kind != cborMap || len(it.items) != 2 || it.items[0].kind != cborText {
		return nil, refuse("is not one response variant")
	}
	variant, val := string(it.items[0].b), it.items[1]
	switch variant {
	case "Attestation":
		if val.kind != cborMap || len(val.items) != 2 || val.items[0].kind != cborText || string(val.items[0].b) != "document" || val.items[1].kind != cborBytes {
			return nil, refuse("is an Attestation without exactly one document")
		}
		if len(val.items[1].b) == 0 {
			return nil, refuse("is an empty document")
		}
		return val.items[1].b, nil
	case "Error":
		if val.kind != cborText {
			return nil, refuse("is an Error without a code")
		}
		code := string(val.b)
		for _, c := range nsmErrorCodes {
			if c == code {
				return nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
					fmt.Sprintf("aws-nitro: the NSM refused the attestation request: %s", code), nil)
			}
		}
		return nil, refuse(fmt.Sprintf("is an Error with an unknown code %q", code))
	default:
		return nil, refuse(fmt.Sprintf("is %q, not Attestation", variant))
	}
}
