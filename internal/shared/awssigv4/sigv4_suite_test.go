// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package awssigv4

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const suiteDir = "testdata/aws-signing-test-suite/v4"

// suiteContext is a case's context.json.
type suiteContext struct {
	Credentials struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		Token           string `json:"token"`
	} `json:"credentials"`
	ExpirationInSeconds int    `json:"expiration_in_seconds"`
	Normalize           bool   `json:"normalize"`
	Region              string `json:"region"`
	Service             string `json:"service"`
	SignBody            bool   `json:"sign_body"`
	OmitSessionToken    bool   `json:"omit_session_token"`
	Timestamp           string `json:"timestamp"`
}

// parseSuiteRequest reads a request the way the suite writes it: the
// request line, the header fields — a line starting with a space continues
// the field before it (obs-fold, which RFC 9112 §5.2 replaces with spaces)
// — an empty line, and the body.
func parseSuiteRequest(t *testing.T, raw string) Request {
	t.Helper()
	lines := strings.Split(raw, "\n")
	first := lines[0]
	sp := strings.IndexByte(first, ' ')
	last := strings.LastIndexByte(first, ' ')
	require.True(t, sp > 0 && last > sp, "request line %q", first)
	method, target := first[:sp], first[sp+1:last]
	path, query, _ := strings.Cut(target, "?")
	r := Request{Method: method, Path: path, Query: query}
	i := 1
	for ; i < len(lines) && lines[i] != ""; i++ {
		l := lines[i]
		if l[0] == ' ' || l[0] == '\t' {
			require.NotEmpty(t, r.Header, "a continuation line before any field")
			r.Header[len(r.Header)-1].Value += " " + l
			continue
		}
		name, value, ok := strings.Cut(l, ":")
		require.True(t, ok, "header line %q", l)
		r.Header = append(r.Header, Field{Name: name, Value: value})
	}
	if i < len(lines) {
		r.Body = []byte(strings.Join(lines[i+1:], "\n"))
	}
	return r
}

func readCase(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	require.NoError(t, err)
	return string(b)
}

func fieldLines(fs []Field) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = strings.ToLower(f.Name) + ":" + f.Value
	}
	sort.Strings(out)
	return out
}

// TestAWSSigningSuite: every case of AWS's suite, signed in the header,
// comes out as AWS's answer — the canonical request, the string to sign,
// the signature, the Authorization header, and the signed request's fields.
func TestAWSSigningSuite(t *testing.T) {
	entries, err := os.ReadDir(suiteDir)
	require.NoError(t, err)
	var cases []string
	for _, e := range entries {
		if e.IsDir() {
			cases = append(cases, e.Name())
		}
	}
	require.Len(t, cases, 38, "the suite at 84a26ea has 38 cases")
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(suiteDir, name)
			var ctx suiteContext
			require.NoError(t, json.Unmarshal([]byte(readCase(t, dir, "context.json")), &ctx))
			ts, err := time.Parse(time.RFC3339, ctx.Timestamp)
			require.NoError(t, err)
			req := parseSuiteRequest(t, readCase(t, dir, "request.txt"))
			sig, err := Sign(req, Credentials{
				AccessKeyID:     ctx.Credentials.AccessKeyID,
				SecretAccessKey: ctx.Credentials.SecretAccessKey,
				SessionToken:    ctx.Credentials.Token,
			}, Options{
				Region:           ctx.Region,
				Service:          ctx.Service,
				Time:             ts,
				NormalizePath:    ctx.Normalize,
				SignBody:         ctx.SignBody,
				OmitSessionToken: ctx.OmitSessionToken,
			})
			require.NoError(t, err)
			require.Equal(t, readCase(t, dir, "header-canonical-request.txt"), sig.CanonicalRequest, "canonical request")
			require.Equal(t, readCase(t, dir, "header-string-to-sign.txt"), sig.StringToSign, "string to sign")
			require.Equal(t, readCase(t, dir, "header-signature.txt"), sig.Signature, "signature")

			signed := parseSuiteRequest(t, readCase(t, dir, "header-signed-request.txt"))
			var auth string
			for _, f := range signed.Header {
				if strings.EqualFold(f.Name, "Authorization") {
					auth = f.Value
				}
			}
			require.Equal(t, auth, sig.Authorization, "Authorization header")
			require.Equal(t, fieldLines(signed.Header), fieldLines(append(append([]Field(nil), req.Header...), sig.Header...)), "the signed request's fields")
			require.Equal(t, string(signed.Body), string(req.Body), "the body is unchanged")
		})
	}
}
