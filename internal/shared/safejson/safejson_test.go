// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package safejson

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A decoder has ended when nothing but white space follows the value it
// decoded: not before a bracket or a brace that closes nothing, which
// Decoder.More takes for the end.
func TestEnded(t *testing.T) {
	for raw, ended := range map[string]bool{
		`{"a":1}`:             true,
		`{"a":1}` + "\n":      true,
		`{"a":1} ` + "\t\r\n": true,
		`[1]`:                 true,
		`7`:                   true,
		`{"a":1}}`:            false,
		`{"a":1}]`:            false,
		`{"a":1} }`:           false,
		`{"a":1}` + "\n]":     false,
		`{"a":1}{}`:           false,
		`{"a":1} 1`:           false,
		`{"a":1},`:            false,
		`{"a":1}:`:            false,
		`{"a":1}x`:            false,
		`[1]]`:                false,
		`7 }`:                 false,
	} {
		dec := json.NewDecoder(strings.NewReader(raw))
		var v any
		require.NoError(t, dec.Decode(&v), "%q", raw)
		require.Equal(t, ended, Ended(dec), "%q", raw)
	}
	// What Decoder.More says where a brace or a bracket follows the value:
	// no more.
	for _, raw := range []string{`{"a":1}}`, `{"a":1}]`, `[1]]`} {
		dec := json.NewDecoder(strings.NewReader(raw))
		var v any
		require.NoError(t, dec.Decode(&v), "%q", raw)
		require.False(t, dec.More(), "%q", raw)
		require.False(t, Ended(dec), "%q", raw)
	}
}
