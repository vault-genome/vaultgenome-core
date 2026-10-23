// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package cms

// A reader of BER — the Basic Encoding Rules of ITU-T X.690 (02/2021),
// library 6ac799a2d1eb… — enough for CMS as KMS sends it: definite and
// indefinite lengths (§8.1.3), constructed strings (§8.7.3), the
// low-tag-number form only (§8.1.2.2; CMS needs no tag above 30), and
// nothing parsed deeper than maxDepth. encoding/asn1 reads DER and refuses
// an indefinite length, which KMS uses.

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

const (
	classUniversal = 0
	classContext   = 2

	tagInteger     = 2
	tagOctetString = 4
	tagNull        = 5
	tagOID         = 6
	tagSequence    = 16
	tagSet         = 17

	maxDepth = 32
)

// tlv is one element: its identifier and its contents — for a constructed
// element of indefinite length, the contents up to the end-of-contents
// octets.
type tlv struct {
	class       byte
	constructed bool
	tag         int
	indefinite  bool
	content     []byte
}

// parseTLV reads one element from the front of b and returns the bytes
// after it.
func parseTLV(b []byte, depth int) (tlv, []byte, error) {
	if depth > maxDepth {
		return tlv{}, nil, fmt.Errorf("cms: nested deeper than %d", maxDepth)
	}
	if len(b) < 2 {
		return tlv{}, nil, errors.New("cms: truncated: an element needs at least two octets")
	}
	t := tlv{class: b[0] >> 6, constructed: b[0]&0x20 != 0, tag: int(b[0] & 0x1f)}
	if t.tag == 0x1f {
		return tlv{}, nil, errors.New("cms: a tag in the high-tag-number form; CMS uses none")
	}
	l := b[1]
	rest := b[2:]
	switch {
	case l < 0x80:
		if int(l) > len(rest) {
			return tlv{}, nil, fmt.Errorf("cms: truncated: a length of %d with %d octets left", l, len(rest))
		}
		t.content, rest = rest[:l], rest[l:]
	case l == 0x80:
		if !t.constructed {
			return tlv{}, nil, errors.New("cms: an indefinite length on a primitive element (X.690 §8.1.3.2)")
		}
		t.indefinite = true
		start := rest
		consumed := 0
		for {
			if len(rest) >= 2 && rest[0] == 0 && rest[1] == 0 {
				t.content = start[:consumed]
				rest = rest[2:]
				break
			}
			if len(rest) == 0 {
				return tlv{}, nil, errors.New("cms: truncated: an indefinite length without its end-of-contents octets")
			}
			_, after, err := parseTLV(rest, depth+1)
			if err != nil {
				return tlv{}, nil, err
			}
			consumed += len(rest) - len(after)
			rest = after
		}
	case l == 0xff:
		return tlv{}, nil, errors.New("cms: the reserved length octet 0xFF (X.690 §8.1.3.5)")
	default:
		n := int(l & 0x7f)
		if n > 4 {
			return tlv{}, nil, fmt.Errorf("cms: a length of %d octets; nothing here is longer than 4 GiB", n)
		}
		if n > len(rest) {
			return tlv{}, nil, errors.New("cms: truncated in a length")
		}
		var v uint64
		for _, c := range rest[:n] {
			v = v<<8 | uint64(c)
		}
		rest = rest[n:]
		if v > uint64(len(rest)) {
			return tlv{}, nil, fmt.Errorf("cms: truncated: a length of %d with %d octets left", v, len(rest))
		}
		t.content, rest = rest[:v], rest[v:]
	}
	return t, rest, nil
}

// children reads the elements inside a constructed element.
func children(t tlv, depth int) ([]tlv, error) {
	if !t.constructed {
		return nil, errors.New("cms: a primitive element where a constructed one belongs")
	}
	var out []tlv
	b := t.content
	for len(b) > 0 {
		c, rest, err := parseTLV(b, depth+1)
		if err != nil {
			return nil, err
		}
		if c.class == classUniversal && c.tag == 0 && !c.constructed {
			return nil, errors.New("cms: end-of-contents octets inside an element of definite length")
		}
		out = append(out, c)
		b = rest
	}
	return out, nil
}

func (t tlv) is(class byte, constructed bool, tag int) bool {
	return t.class == class && t.constructed == constructed && t.tag == tag
}

func (t tlv) describe() string {
	kind := "primitive"
	if t.constructed {
		kind = "constructed"
	}
	switch t.class {
	case classUniversal:
		return fmt.Sprintf("universal %d (%s)", t.tag, kind)
	case classContext:
		return fmt.Sprintf("[%d] (%s)", t.tag, kind)
	default:
		return fmt.Sprintf("class %d tag %d (%s)", t.class, t.tag, kind)
	}
}

func expect(t tlv, class byte, constructed bool, tag int, what string) error {
	if !t.is(class, constructed, tag) {
		return fmt.Errorf("cms: %s: found %s", what, t.describe())
	}
	return nil
}

// octets reads an OCTET STRING whose tag the caller checked: primitive,
// or — BER — constructed of OCTET STRINGs, joined (X.690 §8.7.3).
func octets(t tlv, depth int) ([]byte, error) {
	if !t.constructed {
		return t.content, nil
	}
	if depth > maxDepth {
		return nil, fmt.Errorf("cms: nested deeper than %d", maxDepth)
	}
	parts, err := children(t, depth)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, p := range parts {
		if p.class != classUniversal || p.tag != tagOctetString {
			return nil, fmt.Errorf("cms: a constructed string carries %s, not an OCTET STRING", p.describe())
		}
		b, err := octets(p, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

// smallInt reads a non-negative INTEGER below 128 — a version number.
func smallInt(t tlv, what string) (int, error) {
	if err := expect(t, classUniversal, false, tagInteger, what); err != nil {
		return 0, err
	}
	if len(t.content) != 1 || t.content[0] >= 0x80 {
		return 0, fmt.Errorf("cms: %s: not a small non-negative integer", what)
	}
	return int(t.content[0]), nil
}

// oid is the contents octets of an OBJECT IDENTIFIER, which X.690 §8.19
// makes unique for each identifier, so equal identifiers have equal octets.
type oid []byte

func mustOID(ids ...int) oid {
	der, err := asn1.Marshal(asn1.ObjectIdentifier(ids))
	if err != nil || len(der) < 2 || int(der[1]) != len(der)-2 {
		panic("cms: bad object identifier constant")
	}
	return oid(der[2:])
}

var (
	oidEnvelopedData = mustOID(1, 2, 840, 113549, 1, 7, 3)
	oidData          = mustOID(1, 2, 840, 113549, 1, 7, 1)
	oidRSAESOAEP     = mustOID(1, 2, 840, 113549, 1, 1, 7)
	oidMGF1          = mustOID(1, 2, 840, 113549, 1, 1, 8)
	oidPSpecified    = mustOID(1, 2, 840, 113549, 1, 1, 9)
	oidSHA256        = mustOID(2, 16, 840, 1, 101, 3, 4, 2, 1)
	oidAES256CBC     = mustOID(2, 16, 840, 1, 101, 3, 4, 1, 42)
)

func readOID(t tlv, what string) (oid, error) {
	if err := expect(t, classUniversal, false, tagOID, what); err != nil {
		return nil, err
	}
	if len(t.content) == 0 {
		return nil, fmt.Errorf("cms: %s: an empty object identifier", what)
	}
	return oid(t.content), nil
}

func (o oid) equal(p oid) bool { return string(o) == string(p) }

// String renders the identifier in dotted form, for the refusals.
func (o oid) String() string {
	if len(o) < 128 {
		var id asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(append([]byte{tagOID, byte(len(o))}, o...), &id); err == nil && len(rest) == 0 {
			return id.String()
		}
	}
	return fmt.Sprintf("%x", []byte(o))
}
