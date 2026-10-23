// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package awskms

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeIMDS is the Instance Metadata Service, version 2: a token by PUT
// with a TTL, then the role and its credentials with the token.
func fakeIMDS(t *testing.T, role string, doc func() string, status map[string]int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := status[r.URL.Path]; s != 0 {
			w.WriteHeader(s)
			return
		}
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			require.Equal(t, "21600", r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds"))
			_, _ = w.Write([]byte("TOKEN\n"))
		case r.Header.Get("X-aws-ec2-metadata-token") != "TOKEN":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			_, _ = w.Write([]byte(role))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/"+strings.TrimSpace(role):
			fetches.Add(1)
			_, _ = w.Write([]byte(doc()))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &fetches
}

func dialTo(srv *httptest.Server) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}
}

func TestIMDSCredentials(t *testing.T) {
	now := time.Date(2026, 10, 23, 3, 0, 0, 0, time.UTC)
	expiry := now.Add(1 * time.Hour)
	doc := func() string {
		return `{"Code":"Success","LastUpdated":"2026-10-23T02:55:00Z","Type":"AWS-HMAC","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"s3cr3t","Token":"tok","Expiration":"` + expiry.Format(time.RFC3339) + `"}`
	}
	srv, fetches := fakeIMDS(t, "enclave-parent-role\n", doc, nil)
	clock := now
	m := &IMDSCredentials{Dial: dialTo(srv), Now: func() time.Time { return clock }}
	c, err := m.Retrieve(context.Background())
	require.NoError(t, err)
	require.Equal(t, "ASIAEXAMPLE", c.AccessKeyID)
	require.Equal(t, "tok", c.SessionToken)
	_, err = m.Retrieve(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, fetches.Load(), "kept until five minutes before expiry")
	clock = expiry.Add(-4 * time.Minute)
	_, err = m.Retrieve(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 2, fetches.Load(), "fetched again inside the last five minutes")
}

func TestIMDSRefusals(t *testing.T) {
	good := func() string {
		return `{"Code":"Success","AccessKeyId":"ASIA","SecretAccessKey":"s","Token":"t","Expiration":"2099-01-01T00:00:00Z"}`
	}
	for name, tc := range map[string]struct {
		role   string
		doc    func() string
		status map[string]int
		want   string
	}{
		"no token":         {"r", good, map[string]int{"/latest/api/token": 403}, "session token: HTTP 403"},
		"no role":          {"", good, nil, "names no usable role"},
		"role with slash":  {"a/b", good, nil, "names no usable role"},
		"role list fails":  {"r", good, map[string]int{"/latest/meta-data/iam/security-credentials/": 404}, "role: HTTP 404"},
		"not JSON":         {"r", func() string { return "<html>" }, nil, "do not parse"},
		"code not success": {"r", func() string { return `{"Code":"Failure"}` }, nil, `code "Failure"`},
		"no token field": {"r", func() string {
			return `{"Code":"Success","AccessKeyId":"A","SecretAccessKey":"s","Expiration":"2099-01-01T00:00:00Z"}`
		}, nil, "not usable"},
		"too large": {"r", func() string { return string(make([]byte, imdsMaxBodyBytes+1)) }, nil, "more than"},
	} {
		t.Run(name, func(t *testing.T) {
			srv, _ := fakeIMDS(t, tc.role, tc.doc, tc.status)
			_, err := (&IMDSCredentials{Dial: dialTo(srv)}).Retrieve(context.Background())
			require.ErrorContains(t, err, tc.want)
		})
	}
	// Without a Dial the service's own address is dialled; with a context
	// already done, nothing is reached.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&IMDSCredentials{}).Retrieve(ctx)
	require.Error(t, err)
}
