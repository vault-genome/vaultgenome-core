// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "strings"

// logSafe strips line breaks from a value that came from the peer before
// it goes into a log line, so a record is one line whatever was sent.
func logSafe(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
}
