// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package awssigv4

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	testCreds = Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	testTime  = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	testOpts  = Options{Region: "us-east-1", Service: "service", Time: testTime, NormalizePath: true}
)

func hostOnly() []Field { return []Field{{Name: "Host", Value: "example.amazonaws.com"}} }

// The suite's post-vanilla, signed through SignHTTP: the same signature as
// Sign, the added fields set, the body set from what was signed.
func TestSignHTTPMatchesSign(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.amazonaws.com/", nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "not signed")
	require.NoError(t, SignHTTP(req, nil, testCreds, testOpts))
	require.Equal(t, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b", req.Header.Get("Authorization"))
	require.Equal(t, "20150830T123600Z", req.Header.Get("X-Amz-Date"))
	require.Equal(t, int64(0), req.ContentLength)

	// A KMS-shaped request: content-type and x-amz-target signed, the
	// token signed, the body what was hashed.
	body := []byte(`{"NumberOfBytes":32}`)
	req, err = http.NewRequest(http.MethodPost, "https://kms.us-east-2.amazonaws.com/", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.GenerateRandom")
	creds := testCreds
	creds.SessionToken = "FQoGZXIvYXdzEXAMPLE"
	opts := Options{Region: "us-east-2", Service: "kms", Time: testTime, NormalizePath: true}
	require.NoError(t, SignHTTP(req, body, creds, opts))
	want, err := Sign(Request{Method: "POST", Path: "/", Header: []Field{
		{Name: "Host", Value: "kms.us-east-2.amazonaws.com"},
		{Name: "Content-Type", Value: "application/x-amz-json-1.1"},
		{Name: "X-Amz-Target", Value: "TrentService.GenerateRandom"},
	}, Body: body}, creds, opts)
	require.NoError(t, err)
	require.Equal(t, want.Authorization, req.Header.Get("Authorization"))
	require.Contains(t, want.Authorization, "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target,")
	require.Equal(t, creds.SessionToken, req.Header.Get("X-Amz-Security-Token"))
	sent, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, body, sent)
	again, err := req.GetBody()
	require.NoError(t, err)
	sentAgain, _ := io.ReadAll(again)
	require.Equal(t, body, sentAgain)
	require.Equal(t, int64(len(body)), req.ContentLength)
}

func TestSignHTTPRefusals(t *testing.T) {
	require.ErrorContains(t, SignHTTP(nil, nil, testCreds, testOpts), "no request")
	req, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	req.Header.Set("Host", "other.example")
	require.ErrorContains(t, SignHTTP(req, nil, testCreds, testOpts), "not in its header")
	req, _ = http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	req.Header.Set("Content-Length", "3")
	require.ErrorContains(t, SignHTTP(req, nil, testCreds, testOpts), "not in its header")
	req, _ = http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	req.Host, req.URL.Host = "", ""
	require.ErrorContains(t, SignHTTP(req, nil, testCreds, testOpts), "names no host")
	req, _ = http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	req.URL.Opaque = "//example.amazonaws.com/x"
	require.ErrorContains(t, SignHTTP(req, nil, testCreds, testOpts), "opaque")
	req, _ = http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	require.ErrorContains(t, SignHTTP(req, nil, Credentials{}, testOpts), "access key")
}

// The signer refuses what it cannot sign, or what would be signed one way
// and sent another.
func TestSignRefusals(t *testing.T) {
	ok := Request{Method: "GET", Path: "/", Header: hostOnly()}
	for name, tc := range map[string]struct {
		r    Request
		c    Credentials
		o    Options
		want string
	}{
		"no access key":        {ok, Credentials{SecretAccessKey: "s"}, testOpts, "access key ID and a secret"},
		"no secret":            {ok, Credentials{AccessKeyID: "AKID"}, testOpts, "access key ID and a secret"},
		"slash in access key":  {ok, Credentials{AccessKeyID: "AK/ID", SecretAccessKey: "s"}, testOpts, "credential scope"},
		"token with a space":   {ok, Credentials{AccessKeyID: "AKID", SecretAccessKey: "s", SessionToken: "a b"}, testOpts, "session token"},
		"upper-case region":    {ok, testCreds, Options{Region: "US-EAST-1", Service: "kms", Time: testTime}, "lowercase"},
		"empty service":        {ok, testCreds, Options{Region: "us-east-1", Time: testTime}, "lowercase"},
		"slash in service":     {ok, testCreds, Options{Region: "us-east-1", Service: "k/ms", Time: testTime}, "lowercase"},
		"no time":              {ok, testCreds, Options{Region: "us-east-1", Service: "kms"}, "time is required"},
		"no method":            {Request{Path: "/", Header: hostOnly()}, testCreds, testOpts, "not an HTTP token"},
		"method with a space":  {Request{Method: "G ET", Path: "/", Header: hostOnly()}, testCreds, testOpts, "not an HTTP token"},
		"relative path":        {Request{Method: "GET", Path: "x", Header: hostOnly()}, testCreds, testOpts, "does not start"},
		"question mark":        {Request{Method: "GET", Path: "/a?b", Header: hostOnly()}, testCreds, testOpts, "'?' or '#'"},
		"fragment in query":    {Request{Method: "GET", Path: "/", Query: "a#b", Header: hostOnly()}, testCreds, testOpts, "'?' or '#'"},
		"no host":              {Request{Method: "GET", Path: "/"}, testCreds, testOpts, "host header is required"},
		"bad header name":      {Request{Method: "GET", Path: "/", Header: append(hostOnly(), Field{Name: "My Header", Value: "v"})}, testCreds, testOpts, "not an HTTP token"},
		"newline in value":     {Request{Method: "GET", Path: "/", Header: append(hostOnly(), Field{Name: "My-Header", Value: "a\nb"})}, testCreds, testOpts, "control character"},
		"tab in value":         {Request{Method: "GET", Path: "/", Header: append(hostOnly(), Field{Name: "My-Header", Value: "a\tb"})}, testCreds, testOpts, "control character"},
		"delete in value":      {Request{Method: "GET", Path: "/", Header: append(hostOnly(), Field{Name: "My-Header", Value: "a\x7fb"})}, testCreds, testOpts, "control character"},
		"already authorized":   {Request{Method: "GET", Path: "/", Header: append(hostOnly(), Field{Name: "Authorization", Value: "x"})}, testCreds, testOpts, "already carries"},
		"already dated":        {Request{Method: "GET", Path: "/", Header: append(hostOnly(), Field{Name: "X-Amz-Date", Value: "x"})}, testCreds, testOpts, "already carries"},
		"token twice":          {Request{Method: "GET", Path: "/", Header: append(hostOnly(), Field{Name: "X-Amz-Security-Token", Value: "x"})}, Credentials{AccessKeyID: "AKID", SecretAccessKey: "s", SessionToken: "t"}, testOpts, "already carries X-Amz-Security-Token"},
		"content hash twice":   {Request{Method: "GET", Path: "/", Header: append(hostOnly(), Field{Name: "X-Amz-Content-Sha256", Value: "x"})}, testCreds, Options{Region: "us-east-1", Service: "s3", Time: testTime, SignBody: true}, "already carries X-Amz-Content-Sha256"},
		"bad escape in query":  {Request{Method: "GET", Path: "/", Query: "a=%zz", Header: hostOnly()}, testCreds, testOpts, "two hexadecimal digits"},
		"short escape in name": {Request{Method: "GET", Path: "/", Query: "a%2=b", Header: hostOnly()}, testCreds, testOpts, "two hexadecimal digits"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Sign(tc.r, tc.c, tc.o)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// A field the request carries that the signer would also add is allowed
// when the signer does not add it: X-Amz-Security-Token without a session
// token, X-Amz-Content-Sha256 without SignBody.
func TestSignKeepsFieldsItDoesNotAdd(t *testing.T) {
	r := Request{Method: "GET", Path: "/", Header: append(hostOnly(),
		Field{Name: "X-Amz-Security-Token", Value: "given"},
		Field{Name: "X-Amz-Content-Sha256", Value: "UNSIGNED-PAYLOAD"})}
	sig, err := Sign(r, testCreds, testOpts)
	require.NoError(t, err)
	require.Contains(t, sig.CanonicalRequest, "x-amz-content-sha256:UNSIGNED-PAYLOAD\n")
	require.Contains(t, sig.CanonicalRequest, "x-amz-security-token:given\n")
}

func TestCanonicalPieces(t *testing.T) {
	for in, want := range map[string]string{
		"":          "",
		"a":         "a=",
		"a&&b=1":    "a=&b=1",
		"b=2&a=1":   "a=1&b=2",
		"a=2&a=1":   "a=1&a=2",
		"a=x+y":     "a=x%2By",
		"a=%7e%2F":  "a=~%2F",
		"k%20=v%20": "k%20=v%20",
	} {
		got, err := canonicalQuery(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}
	for in, want := range map[string]string{
		"/":        "/",
		"/a/./b":   "/a/b",
		"/a/../b":  "/b",
		"/a/b/..":  "/a/",
		"/a/.":     "/a/",
		"/../a":    "/a",
		"///":      "/",
		"/a//b///": "/a/b/",
	} {
		require.Equal(t, want, normalizePath(in), in)
	}
	require.Equal(t, "/a%2520b/%E2%9C%93", uriEncode("/a%20b/✓", true), "the wire path is encoded once more")
	require.Equal(t, "a%2Fb", uriEncode("a/b", false))
	require.Equal(t, "a b", trimAll("  a    b  "))
	require.Equal(t, "ab", trimAll("ab"))
}

func TestCredentialsNeverPrintTheSecret(t *testing.T) {
	c := Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", SessionToken: "TOKENVALUE"}
	for _, s := range []string{c.String(), fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprint(c)} {
		require.Contains(t, s, "AKIDEXAMPLE")
		require.NotContains(t, s, "EXAMPLEKEY")
		require.NotContains(t, s, "TOKENVALUE")
	}
}

// Signing does not depend on the order the request's header map is walked
// in: two equal requests sign the same.
func TestSignHTTPIsDeterministic(t *testing.T) {
	sign := func() string {
		req, _ := http.NewRequest(http.MethodPost, "https://kms.us-east-1.amazonaws.com/", bytes.NewReader(nil))
		for _, h := range []string{"X-B", "X-A", "X-C", "Content-Type", "X-Amz-Target"} {
			req.Header.Set(h, strings.ToLower(h))
		}
		require.NoError(t, SignHTTP(req, []byte("{}"), testCreds, Options{Region: "us-east-1", Service: "kms", Time: testTime}))
		return req.Header.Get("Authorization")
	}
	first := sign()
	for range 20 {
		require.Equal(t, first, sign())
	}
}
