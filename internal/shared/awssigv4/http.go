// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package awssigv4

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
)

// unsigned are the header fields the specification says not to sign:
// hop-by-hop and volatile fields that proxies, load balancers and the
// transport itself change on the way (IAM User Guide, "Create a signed AWS
// API request", CanonicalHeaders).
var unsigned = map[string]bool{
	"connection":          true,
	"x-amzn-trace-id":     true,
	"user-agent":          true,
	"keep-alive":          true,
	"transfer-encoding":   true,
	"te":                  true,
	"trailer":             true,
	"upgrade":             true,
	"proxy-authorization": true,
	"proxy-authenticate":  true,
}

// SignHTTP signs req, which will send body, and adds the signature's header
// fields to it. It signs the host and every field req carries but the
// volatile ones; the body is set on req from body, so what is signed is
// what is sent.
func SignHTTP(req *http.Request, body []byte, c Credentials, o Options) error {
	if req == nil || req.URL == nil {
		return errors.New("awssigv4: no request")
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		return errors.New("awssigv4: the request names no host")
	}
	fields := []Field{{Name: "Host", Value: host}}
	names := make([]string, 0, len(req.Header))
	for n := range req.Header {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		lower := strings.ToLower(n)
		if unsigned[lower] {
			continue
		}
		if lower == "host" || lower == "content-length" {
			return errors.New("awssigv4: set the host and the content length on the request, not in its header")
		}
		for _, v := range req.Header[n] {
			fields = append(fields, Field{Name: n, Value: v})
		}
	}
	path := req.URL.EscapedPath()
	if req.URL.Opaque != "" {
		return errors.New("awssigv4: an opaque URL cannot be signed")
	}
	sig, err := Sign(Request{
		Method: req.Method,
		Path:   path,
		Query:  req.URL.RawQuery,
		Header: fields,
		Body:   body,
	}, c, o)
	if err != nil {
		return err
	}
	for _, f := range sig.Header {
		req.Header.Set(f.Name, f.Value)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	req.ContentLength = int64(len(body))
	return nil
}
