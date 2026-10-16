// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

// The Evidence on the Return Path wire is a RATS Conceptual Message
// Wrapper record (RFC 9999 §3.1), in its JSON form: an array of the
// message's media type, its bytes as base64url without padding, and the
// indicator saying it is Evidence (§3.1.1). Until this record, the two
// evidence fields of the handshake carried bytes that named nothing;
// the family was whatever the peer's configuration assumed. With it,
// every piece of Evidence says what it is, a verifier of another family
// refuses it before reading a byte, and a delegated Verifier (ADR 0025,
// step 2) receives the type it must be given. The record is not signed
// here: the handshake transcript and the TEE's own signature over its
// report cover it (RFC 9999 §8.1 leaves protection to the protocol).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// CMWIndEvidence is the indicator bit for Evidence (RFC 9999 §3.1.1,
// cm-type evidence = 2).
const CMWIndEvidence uint32 = 1 << 2

// cmwIndMax bounds the indicator: five bits are registered (§3.1.1).
const cmwIndMax uint32 = 31

// CMWRecord is one RATS conceptual message with its type.
type CMWRecord struct {
	// Type is the media type of Value (a text string in the JSON form;
	// CoAP content-format numbers are not used in JSON).
	Type string
	// Value is the conceptual message, serialized as Type says.
	Value []byte
	// Ind is the conceptual-message indicator bitmap; zero means the
	// field is absent — no information, not "none".
	Ind uint32
}

// NewEvidenceRecord makes the record the handshake puts on the wire:
// Type and Value required, the indicator set to Evidence.
func NewEvidenceRecord(mediaType string, value []byte) (CMWRecord, error) {
	r := CMWRecord{Type: mediaType, Value: value, Ind: CMWIndEvidence}
	if err := r.check(); err != nil {
		return CMWRecord{}, err
	}
	return r, nil
}

// IsEvidence reports whether the record may be read as Evidence: the
// indicator carries the Evidence bit, or is absent (§3.1: absence means
// the consumer decides from context — here the handshake's).
func (r CMWRecord) IsEvidence() bool {
	return r.Ind == 0 || r.Ind&CMWIndEvidence != 0
}

func (r CMWRecord) check() error {
	switch {
	case r.Type == "":
		return cmwErr("type required", nil)
	case len(r.Type) > 255 || strings.ContainsAny(r.Type, " \t\r\n\"") || strings.Count(r.Type, "/") < 1:
		return cmwErr(fmt.Sprintf("type %q is not a media type", r.Type), nil)
	case len(r.Value) == 0:
		return cmwErr("value required", nil)
	case r.Ind > cmwIndMax:
		return cmwErr(fmt.Sprintf("indicator %d exceeds the registered bits (1..%d)", r.Ind, cmwIndMax), nil)
	}
	return nil
}

func cmwErr(msg string, cause error) error {
	return shared_errors.Structural(CodeProtocolViolation, "returnpath/transport: CMW record: "+msg, cause)
}

// MarshalJSON writes the json-record of RFC 9999 §3.1: [type, value, ?ind].
func (r CMWRecord) MarshalJSON() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	arr := []any{r.Type, base64.RawURLEncoding.EncodeToString(r.Value)}
	if r.Ind != 0 {
		arr = append(arr, r.Ind)
	}
	return json.Marshal(arr)
}

// UnmarshalJSON reads a json-record strictly: an array of two or three
// members, the type a media type, the value base64url without padding,
// the indicator, when present, a non-zero integer within the registered
// bits. Anything else is a protocol violation.
func (r *CMWRecord) UnmarshalJSON(b []byte) error {
	var arr []json.RawMessage
	if err := json.Unmarshal(b, &arr); err != nil {
		return cmwErr("not a JSON array", err)
	}
	if len(arr) < 2 || len(arr) > 3 {
		return cmwErr(fmt.Sprintf("array of %d members, want 2 or 3", len(arr)), nil)
	}
	var typ, val string
	if err := json.Unmarshal(arr[0], &typ); err != nil {
		return cmwErr("type is not a string", err)
	}
	if err := json.Unmarshal(arr[1], &val); err != nil {
		return cmwErr("value is not a string", err)
	}
	if strings.ContainsAny(val, "=+/") {
		return cmwErr("value is not base64url without padding", nil)
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(val)
	if err != nil {
		return cmwErr("value is not base64url", err)
	}
	out := CMWRecord{Type: typ, Value: value}
	if len(arr) == 3 {
		var ind uint64
		if err := json.Unmarshal(arr[2], &ind); err != nil {
			return cmwErr("indicator is not an unsigned integer", err)
		}
		if ind == 0 || ind > uint64(cmwIndMax) {
			return cmwErr(fmt.Sprintf("indicator %d outside 1..%d", ind, cmwIndMax), nil)
		}
		out.Ind = uint32(ind)
	}
	if err := out.check(); err != nil {
		return err
	}
	*r = out
	return nil
}
