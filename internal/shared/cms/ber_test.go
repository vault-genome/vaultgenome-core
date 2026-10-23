// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package cms

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBERReaderRefusals(t *testing.T) {
	deep := []byte{}
	for range maxDepth + 2 {
		deep = append(deep, 0x30, 0x80)
	}
	for range maxDepth + 2 {
		deep = append(deep, 0, 0)
	}
	for name, tc := range map[string]struct {
		in   []byte
		want string
	}{
		"one octet":               {[]byte{0x30}, "at least two octets"},
		"high tag number":         {[]byte{0x1f, 0x01, 0x00}, "high-tag-number"},
		"short length too long":   {[]byte{0x04, 0x05, 0x00}, "a length of 5 with 1 octets left"},
		"indefinite primitive":    {[]byte{0x04, 0x80, 0x00, 0x00}, "indefinite length on a primitive"},
		"reserved length":         {[]byte{0x04, 0xff, 0x00}, "reserved length octet"},
		"five length octets":      {[]byte{0x04, 0x85, 0, 0, 0, 0, 1}, "a length of 5 octets"},
		"cut in the length":       {[]byte{0x04, 0x82, 0x01}, "truncated in a length"},
		"long length too long":    {[]byte{0x04, 0x81, 0x09, 0x00}, "a length of 9 with 1 octets left"},
		"no end-of-contents":      {[]byte{0x30, 0x80, 0x02, 0x01, 0x00}, "without its end-of-contents"},
		"nested too deep":         {deep, "nested deeper than"},
		"bad child in indefinite": {[]byte{0x30, 0x80, 0x04, 0x05, 0x00, 0x00, 0x00}, "a length of 5"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := parseTLV(tc.in, 0)
			require.ErrorContains(t, err, tc.want)
		})
	}
	// End-of-contents octets inside an element of definite length.
	t1, _, err := parseTLV([]byte{0x30, 0x04, 0x00, 0x00, 0x02, 0x00}, 0)
	require.NoError(t, err)
	_, err = children(t1, 0)
	require.ErrorContains(t, err, "end-of-contents octets inside")
	_, err = children(tlv{content: []byte{1}}, 0)
	require.ErrorContains(t, err, "primitive element where a constructed")
	_, err = octets(tlv{constructed: true, tag: tagOctetString}, maxDepth+1)
	require.ErrorContains(t, err, "nested deeper")
}

func TestBERReaderReadsDefiniteAndIndefinite(t *testing.T) {
	// The same SEQUENCE { INTEGER 2, OCTET STRING "ab" }, three ways: DER,
	// a non-minimal long length (BER allows it), and indefinite.
	for _, in := range [][]byte{
		{0x30, 0x07, 0x02, 0x01, 0x02, 0x04, 0x02, 'a', 'b'},
		{0x30, 0x81, 0x07, 0x02, 0x01, 0x02, 0x04, 0x02, 'a', 'b'},
		{0x30, 0x80, 0x02, 0x01, 0x02, 0x04, 0x02, 'a', 'b', 0x00, 0x00},
	} {
		el, rest, err := parseTLV(append(in, 0xEE), 0)
		require.NoError(t, err)
		require.Equal(t, []byte{0xEE}, rest)
		kids, err := children(el, 0)
		require.NoError(t, err)
		require.Len(t, kids, 2)
		v, err := smallInt(kids[0], "v")
		require.NoError(t, err)
		require.Equal(t, 2, v)
		s, err := octets(kids[1], 1)
		require.NoError(t, err)
		require.Equal(t, "ab", string(s))
	}
}

func TestOIDRendering(t *testing.T) {
	require.Equal(t, "1.2.840.113549.1.7.3", oidEnvelopedData.String())
	require.Equal(t, "2.16.840.1.101.3.4.1.42", oidAES256CBC.String())
	require.Equal(t, "ff", oid{0xff}.String(), "not an identifier: shown in hex")
	require.True(t, strings.HasPrefix(oid(bytes.Repeat([]byte{1}, 200)).String(), "0101"))
	require.Contains(t, tlv{class: 1, tag: 3}.describe(), "class 1 tag 3")
	require.Panics(t, func() { mustOID(3) })
}

// FuzzParse: nothing panics, and what parses holds the profile's sizes.
func FuzzParse(f *testing.F) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, ".der") || strings.HasSuffix(n, ".ber") {
			b, err := os.ReadFile(filepath.Join("testdata", n))
			if err != nil {
				f.Fatal(err)
			}
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		ed, err := Parse(in)
		if err != nil {
			return
		}
		if len(ed.IV) != 16 || len(ed.EncryptedContent)%16 != 0 || len(ed.EncryptedContent) == 0 || len(ed.EncryptedKey) == 0 {
			t.Fatalf("parsed outside the profile: %+v", ed)
		}
	})
}
