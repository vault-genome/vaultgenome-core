// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package awskms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/awssigv4"
)

// Credentials is where the signing credentials come from.
type Credentials interface {
	Retrieve(ctx context.Context) (awssigv4.Credentials, error)
}

// StaticCredentials are fixed credentials.
type StaticCredentials awssigv4.Credentials

// Retrieve returns the credentials.
func (s StaticCredentials) Retrieve(context.Context) (awssigv4.Credentials, error) {
	c := awssigv4.Credentials(s)
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return awssigv4.Credentials{}, errors.New("awskms: static credentials without an access key or its secret")
	}
	return c, nil
}

// String never prints the secret.
func (s StaticCredentials) String() string { return awssigv4.Credentials(s).String() }

// GoString is String.
func (s StaticCredentials) GoString() string { return s.String() }

// EnvironmentCredentials reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and
// AWS_SESSION_TOKEN at each Retrieve — the variables AWS's tools set and
// read.
type EnvironmentCredentials struct{}

// Retrieve reads the environment.
func (EnvironmentCredentials) Retrieve(context.Context) (awssigv4.Credentials, error) {
	c := awssigv4.Credentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return awssigv4.Credentials{}, errors.New("awskms: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not both set")
	}
	return c, nil
}

// IMDSCredentials are the instance role's credentials from the EC2
// Instance Metadata Service, version 2 (the EC2 User Guide, "Use the
// Instance Metadata Service", library 09dd71ced78c…, and "Retrieve security
// credentials from instance metadata", f9c715a466d1…): a session token by
// PUT, the role's name, then its credentials, kept until five minutes
// before they expire. In an enclave the service is reached through the
// parent (Dial); the parent can hand the enclave any credentials — they
// buy it nothing, because the key's policy releases only to the enclave's
// attestation document.
type IMDSCredentials struct {
	// Dial reaches the service; nil dials 169.254.169.254:80 over TCP.
	Dial func(ctx context.Context) (net.Conn, error)
	// Now is the clock the expiry is read against; nil is time.Now.
	Now func() time.Time

	mu     sync.Mutex
	cached awssigv4.Credentials
	until  time.Time
}

const (
	imdsHost         = "169.254.169.254"
	imdsTokenTTL     = "21600"
	imdsMaxBodyBytes = 16 << 10
	imdsRefreshAhead = 5 * time.Minute
)

// imdsRoleCredentials is the document the role's path answers with.
type imdsRoleCredentials struct {
	Code            string
	Type            string
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string
	Token           string
	Expiration      time.Time
}

// Retrieve returns the role's credentials, fetched again when they are
// within five minutes of expiring.
func (m *IMDSCredentials) Retrieve(ctx context.Context) (awssigv4.Credentials, error) {
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cached.AccessKeyID != "" && now().Before(m.until) {
		return m.cached, nil
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:                  nil,
		DialContext:            m.dialer(),
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: imdsMaxBodyBytes,
	}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	token, err := imdsCall(ctx, client, http.MethodPut, "/latest/api/token", map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": imdsTokenTTL})
	if err != nil {
		return awssigv4.Credentials{}, fmt.Errorf("awskms: instance metadata session token: %w", err)
	}
	auth := map[string]string{"X-aws-ec2-metadata-token": strings.TrimSpace(string(token))}
	roles, err := imdsCall(ctx, client, http.MethodGet, "/latest/meta-data/iam/security-credentials/", auth)
	if err != nil {
		return awssigv4.Credentials{}, fmt.Errorf("awskms: instance metadata role: %w", err)
	}
	role, _, _ := strings.Cut(strings.TrimSpace(string(roles)), "\n")
	role = strings.TrimSpace(role)
	if role == "" || strings.ContainsAny(role, "/?#% ") {
		return awssigv4.Credentials{}, fmt.Errorf("awskms: the instance names no usable role (%q); is an instance profile attached?", role)
	}
	doc, err := imdsCall(ctx, client, http.MethodGet, "/latest/meta-data/iam/security-credentials/"+role, auth)
	if err != nil {
		return awssigv4.Credentials{}, fmt.Errorf("awskms: instance metadata credentials of role %s: %w", role, err)
	}
	var rc imdsRoleCredentials
	dec := json.NewDecoder(bytes.NewReader(doc))
	if err := dec.Decode(&rc); err != nil {
		return awssigv4.Credentials{}, fmt.Errorf("awskms: the credentials of role %s do not parse: %w", role, err)
	}
	if rc.Code != "Success" || rc.AccessKeyID == "" || rc.SecretAccessKey == "" || rc.Token == "" || rc.Expiration.IsZero() {
		return awssigv4.Credentials{}, fmt.Errorf("awskms: the credentials of role %s are not usable (code %q)", role, rc.Code)
	}
	m.cached = awssigv4.Credentials{AccessKeyID: rc.AccessKeyID, SecretAccessKey: rc.SecretAccessKey, SessionToken: rc.Token}
	m.until = rc.Expiration.Add(-imdsRefreshAhead)
	return m.cached, nil
}

func (m *IMDSCredentials) dialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if m.Dial != nil {
		return func(ctx context.Context, _, _ string) (net.Conn, error) { return m.Dial(ctx) }
	}
	var d net.Dialer
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", net.JoinHostPort(imdsHost, "80"))
	}
}

func imdsCall(ctx context.Context, c *http.Client, method, path string, header map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://"+imdsHost+path, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, imdsMaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > imdsMaxBodyBytes {
		return nil, fmt.Errorf("more than %d bytes", imdsMaxBodyBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body, nil
}
