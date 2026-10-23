// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package awskms is a client of AWS KMS for the three operations the
// Nitro sealer uses (ADR 0036, part three) — GenerateDataKey, Decrypt and
// GenerateRandom, the last two with a Recipient: the enclave's attestation
// document — written from the KMS API Reference (library: Decrypt
// 5ed19c1a739c…, RecipientInfo 4a45ca57400f…, GenerateDataKey bcb16c3e1177…,
// GenerateRandom 4b19bdb59224…, common parameters 0331794914fb…, common
// errors af3b4fa90d2a…) with the standard library: JSON over HTTPS, signed
// with Signature Version 4 (internal/shared/awssigv4), TLS 1.3 to the
// endpoint verified against Amazon's four roots and no other, no proxy
// from the environment. In an enclave the connection is a vsock to the
// parent's proxy (Dial), and TLS runs end to end through it.
package awskms

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/awssigv4"
)

// The service's limits (API Reference): a ciphertext blob and a
// CiphertextForRecipient are at most 6144 bytes, a plaintext at most 4096,
// an attestation document at most 262144 bytes.
const (
	MaxCiphertextBytes  = 6144
	MaxPlaintextBytes   = 4096
	MaxAttestationBytes = 262144
	maxResponseBytes    = 64 << 10
	defaultTimeout      = 30 * time.Second
	jsonContentType     = "application/x-amz-json-1.1"
	targetPrefix        = "TrentService."
)

// KeyEncryptionAlgorithm is the only algorithm a Recipient takes.
const KeyEncryptionAlgorithm = "RSAES_OAEP_SHA_256"

// Config configures a Client.
type Config struct {
	// Region is the key's Region, e.g. "us-east-2".
	Region string
	// Endpoint is the host KMS is reached at; empty means
	// kms.<Region>.amazonaws.com (kms-fips.<Region>.amazonaws.com is the
	// FIPS endpoint).
	Endpoint string
	// Credentials sign the requests.
	Credentials Credentials
	// Dial reaches the endpoint's port 443; nil dials it over TCP. In an
	// enclave it is the vsock to the parent's proxy.
	Dial func(ctx context.Context) (net.Conn, error)
	// RootCAs verify the endpoint; nil means Amazon's four roots.
	RootCAs *x509.CertPool
	// Timeout bounds each request; zero means 30 seconds.
	Timeout time.Duration
	// Now is the signing clock; nil is time.Now.
	Now func() time.Time
}

// Client calls KMS.
type Client struct {
	region string
	host   string
	creds  Credentials
	http   *http.Client
	now    func() time.Time
}

// New builds a Client.
func New(cfg Config) (*Client, error) {
	if !validRegion(cfg.Region) {
		return nil, fmt.Errorf("awskms: region %q is not a Region code", cfg.Region)
	}
	if cfg.Credentials == nil {
		return nil, errors.New("awskms: no credentials")
	}
	host := cfg.Endpoint
	if host == "" {
		host = "kms." + cfg.Region + ".amazonaws.com"
	}
	if strings.ContainsAny(host, "/:@ ?#") || host == "" {
		return nil, fmt.Errorf("awskms: endpoint %q is not a host name", host)
	}
	roots := cfg.RootCAs
	if roots == nil {
		var err error
		if roots, err = AmazonRoots(); err != nil {
			return nil, err
		}
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	}
	if cfg.Dial != nil {
		dial = func(ctx context.Context, _, _ string) (net.Conn, error) { return cfg.Dial(ctx) }
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	transport := &http.Transport{
		Proxy:       nil,
		DialContext: dial,
		TLSClientConfig: &tls.Config{
			ServerName: host,
			RootCAs:    roots,
			MinVersion: tls.VersionTLS13,
		},
		ForceAttemptHTTP2:      false,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: maxResponseBytes,
		DisableCompression:     true,
	}
	return &Client{
		region: cfg.Region,
		host:   host,
		creds:  cfg.Credentials,
		http: &http.Client{
			Transport:     transport,
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: now,
	}, nil
}

// Recipient is the attested caller: its attestation document, which
// carries the public key KMS encrypts the answer to.
type Recipient struct {
	AttestationDocument []byte
}

type recipientJSON struct {
	AttestationDocument    []byte `json:"AttestationDocument"`
	KeyEncryptionAlgorithm string `json:"KeyEncryptionAlgorithm"`
}

func (r *Recipient) wire() (*recipientJSON, error) {
	if r == nil {
		return nil, nil
	}
	if n := len(r.AttestationDocument); n == 0 || n > MaxAttestationBytes {
		return nil, fmt.Errorf("awskms: an attestation document of %d bytes (1 to %d)", n, MaxAttestationBytes)
	}
	return &recipientJSON{AttestationDocument: r.AttestationDocument, KeyEncryptionAlgorithm: KeyEncryptionAlgorithm}, nil
}

// APIError is KMS's answer when it refuses: the HTTP status, the error's
// type (the part after '#', e.g. AccessDeniedException), its message and
// the request's ID.
type APIError struct {
	StatusCode int
	Type       string
	Message    string
	RequestID  string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("awskms: KMS refused (HTTP %d, %s, request %s): %s", e.StatusCode, e.Type, e.RequestID, e.Message)
}

// IsAccessDenied reports whether err is KMS's AccessDeniedException — the
// key's policy, or the caller's, did not allow the call; for an attested
// call, the document's measurements did not satisfy the policy.
func IsAccessDenied(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Type == "AccessDeniedException"
}

// call sends one operation and decodes its answer into out.
func (c *Client) call(ctx context.Context, op string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	creds, err := c.creds.Retrieve(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.host+"/", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", jsonContentType)
	req.Header.Set("X-Amz-Target", targetPrefix+op)
	if err := awssigv4.SignHTTP(req, body, creds, awssigv4.Options{
		Region: c.region, Service: "kms", Time: c.now(), NormalizePath: true,
	}); err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("awskms: %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("awskms: %s: reading the answer: %w", op, err)
	}
	if len(raw) > maxResponseBytes {
		return fmt.Errorf("awskms: %s: an answer of more than %d bytes", op, maxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return apiError(resp, raw)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("awskms: %s: the answer does not parse: %w", op, err)
	}
	if dec.More() {
		return fmt.Errorf("awskms: %s: data after the answer", op)
	}
	return nil
}

func apiError(resp *http.Response, raw []byte) error {
	var e struct {
		Type     string `json:"__type"`
		Message  string `json:"message"`
		MessageU string `json:"Message"`
	}
	_ = json.Unmarshal(raw, &e)
	t := e.Type
	if i := strings.LastIndexByte(t, '#'); i >= 0 {
		t = t[i+1:]
	}
	if t == "" {
		t = "unknown"
	}
	msg := e.Message
	if msg == "" {
		msg = e.MessageU
	}
	if len(msg) > 512 {
		msg = msg[:512] + "…"
	}
	return &APIError{StatusCode: resp.StatusCode, Type: t, Message: msg, RequestID: resp.Header.Get("X-Amzn-Requestid")}
}

// ---- operations ------------------------------------------------------------

// DataKey is a new AES-256 data key: its plaintext — zero it when done —
// and the same key encrypted under the KMS key, with that key's ARN.
type DataKey struct {
	Plaintext      []byte
	CiphertextBlob []byte
	KeyID          string
}

// GenerateDataKey asks for a 256-bit data key under keyID, bound to
// encryptionContext.
func (c *Client) GenerateDataKey(ctx context.Context, keyID string, encryptionContext map[string]string) (*DataKey, error) {
	if keyID == "" {
		return nil, errors.New("awskms: GenerateDataKey: no key ID")
	}
	in := struct {
		KeyID             string            `json:"KeyId"`
		KeySpec           string            `json:"KeySpec"`
		EncryptionContext map[string]string `json:"EncryptionContext,omitempty"`
	}{keyID, "AES_256", encryptionContext}
	var out struct {
		CiphertextBlob []byte `json:"CiphertextBlob"`
		Plaintext      []byte `json:"Plaintext"`
		KeyID          string `json:"KeyId"`
	}
	if err := c.call(ctx, "GenerateDataKey", in, &out); err != nil {
		return nil, err
	}
	if len(out.Plaintext) != 32 {
		clear(out.Plaintext)
		return nil, fmt.Errorf("awskms: GenerateDataKey: a data key of %d bytes, want 32", len(out.Plaintext))
	}
	if n := len(out.CiphertextBlob); n == 0 || n > MaxCiphertextBytes {
		clear(out.Plaintext)
		return nil, fmt.Errorf("awskms: GenerateDataKey: a ciphertext blob of %d bytes", n)
	}
	if err := sameKey(keyID, out.KeyID); err != nil {
		clear(out.Plaintext)
		return nil, fmt.Errorf("awskms: GenerateDataKey: %w", err)
	}
	return &DataKey{Plaintext: out.Plaintext, CiphertextBlob: out.CiphertextBlob, KeyID: out.KeyID}, nil
}

// DecryptInput is a Decrypt request.
type DecryptInput struct {
	CiphertextBlob    []byte
	KeyID             string
	EncryptionContext map[string]string
	// Recipient, when set, has KMS answer with CiphertextForRecipient —
	// the plaintext encrypted to the document's key — and no plaintext.
	Recipient *Recipient
}

// DecryptOutput is Decrypt's answer: the plaintext, or — for a Recipient —
// CiphertextForRecipient, the CMS EnvelopedData only the recipient's key
// opens; and the ARN of the key that decrypted.
type DecryptOutput struct {
	Plaintext              []byte
	CiphertextForRecipient []byte
	KeyID                  string
}

// Decrypt decrypts in.CiphertextBlob under in.KeyID, which is required: KMS
// then uses that key and no other (the API Reference recommends it).
func (c *Client) Decrypt(ctx context.Context, in DecryptInput) (*DecryptOutput, error) {
	if in.KeyID == "" {
		return nil, errors.New("awskms: Decrypt: no key ID; it is required here so no other key is used")
	}
	if n := len(in.CiphertextBlob); n == 0 || n > MaxCiphertextBytes {
		return nil, fmt.Errorf("awskms: Decrypt: a ciphertext blob of %d bytes (1 to %d)", n, MaxCiphertextBytes)
	}
	rcp, err := in.Recipient.wire()
	if err != nil {
		return nil, err
	}
	req := struct {
		CiphertextBlob    []byte            `json:"CiphertextBlob"`
		KeyID             string            `json:"KeyId"`
		EncryptionContext map[string]string `json:"EncryptionContext,omitempty"`
		Recipient         *recipientJSON    `json:"Recipient,omitempty"`
	}{in.CiphertextBlob, in.KeyID, in.EncryptionContext, rcp}
	var out struct {
		CiphertextForRecipient []byte `json:"CiphertextForRecipient"`
		Plaintext              []byte `json:"Plaintext"`
		KeyID                  string `json:"KeyId"`
		EncryptionAlgorithm    string `json:"EncryptionAlgorithm"`
	}
	if err := c.call(ctx, "Decrypt", req, &out); err != nil {
		return nil, err
	}
	if err := checkAnswer("Decrypt", in.Recipient != nil, out.Plaintext, out.CiphertextForRecipient); err != nil {
		return nil, err
	}
	if out.EncryptionAlgorithm != "" && out.EncryptionAlgorithm != "SYMMETRIC_DEFAULT" {
		clear(out.Plaintext)
		return nil, fmt.Errorf("awskms: Decrypt: answered with %s, not SYMMETRIC_DEFAULT", out.EncryptionAlgorithm)
	}
	if err := sameKey(in.KeyID, out.KeyID); err != nil {
		clear(out.Plaintext)
		return nil, fmt.Errorf("awskms: Decrypt: %w", err)
	}
	return &DecryptOutput{Plaintext: out.Plaintext, CiphertextForRecipient: out.CiphertextForRecipient, KeyID: out.KeyID}, nil
}

// GenerateRandomOutput is GenerateRandom's answer: the bytes, or — for a
// Recipient — CiphertextForRecipient.
type GenerateRandomOutput struct {
	Plaintext              []byte
	CiphertextForRecipient []byte
}

// GenerateRandom asks for n random bytes (1 to 1024). It needs no key, so
// it is how the client and the signature are checked against the service
// without one.
func (c *Client) GenerateRandom(ctx context.Context, n int, recipient *Recipient) (*GenerateRandomOutput, error) {
	if n < 1 || n > 1024 {
		return nil, fmt.Errorf("awskms: GenerateRandom: %d bytes (1 to 1024)", n)
	}
	rcp, err := recipient.wire()
	if err != nil {
		return nil, err
	}
	in := struct {
		NumberOfBytes int            `json:"NumberOfBytes"`
		Recipient     *recipientJSON `json:"Recipient,omitempty"`
	}{n, rcp}
	var out struct {
		CiphertextForRecipient []byte `json:"CiphertextForRecipient"`
		Plaintext              []byte `json:"Plaintext"`
	}
	if err := c.call(ctx, "GenerateRandom", in, &out); err != nil {
		return nil, err
	}
	if err := checkAnswer("GenerateRandom", recipient != nil, out.Plaintext, out.CiphertextForRecipient); err != nil {
		return nil, err
	}
	if recipient == nil && len(out.Plaintext) != n {
		return nil, fmt.Errorf("awskms: GenerateRandom: %d bytes for %d asked", len(out.Plaintext), n)
	}
	return &GenerateRandomOutput{Plaintext: out.Plaintext, CiphertextForRecipient: out.CiphertextForRecipient}, nil
}

// checkAnswer holds an answer to its form: for a Recipient, a
// CiphertextForRecipient and no plaintext (the API Reference: "the
// Plaintext field ... is null or empty"); otherwise a plaintext.
func checkAnswer(op string, attested bool, plaintext, forRecipient []byte) error {
	if attested {
		if len(plaintext) != 0 {
			clear(plaintext)
			return fmt.Errorf("awskms: %s: plaintext in the answer to an attested request", op)
		}
		if n := len(forRecipient); n == 0 || n > MaxCiphertextBytes {
			return fmt.Errorf("awskms: %s: a CiphertextForRecipient of %d bytes (1 to %d)", op, n, MaxCiphertextBytes)
		}
		return nil
	}
	if len(forRecipient) != 0 {
		clear(plaintext)
		return fmt.Errorf("awskms: %s: a CiphertextForRecipient in the answer to a request without a recipient", op)
	}
	if n := len(plaintext); n == 0 || n > MaxPlaintextBytes {
		clear(plaintext)
		return fmt.Errorf("awskms: %s: a plaintext of %d bytes (1 to %d)", op, n, MaxPlaintextBytes)
	}
	return nil
}

// sameKey holds the key KMS names in its answer — always the key's ARN —
// to the key asked for, when that was given as an ARN.
func sameKey(asked, answered string) error {
	if answered == "" {
		return errors.New("the answer names no key")
	}
	if strings.HasPrefix(asked, "arn:") && !strings.Contains(asked, ":alias/") && asked != answered {
		return fmt.Errorf("the answer names key %s, not %s", answered, asked)
	}
	return nil
}

func validRegion(r string) bool {
	if r == "" || len(r) > 32 {
		return false
	}
	for i := 0; i < len(r); i++ {
		c := r[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
