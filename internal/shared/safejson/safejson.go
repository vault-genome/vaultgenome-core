// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package safejson holds JSON that came from elsewhere to what its reader
// takes: a document is one value, and nothing but white space after it.
package safejson

import (
	"encoding/json"
	"errors"
	"io"
)

// Ended says whether dec has read all there was: nothing but white space
// follows the value it decoded. Decoder.More says less — it is false
// before a ']' and before a '}' —, so that a document with one of them
// after it passed for the document alone.
func Ended(dec *json.Decoder) bool {
	_, err := dec.Token()
	return errors.Is(err, io.EOF)
}
