// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package awskms

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/awssigv4"
)

// The four roots are Amazon's, by the SHA-256 fingerprints the repository
// page publishes (library 86caa31e9b7c…, read 2026-10-23).
func TestAmazonRootsArePinned(t *testing.T) {
	want := map[string]string{
		"AmazonRootCA1.pem": "8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e",
		"AmazonRootCA2.pem": "1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4",
		"AmazonRootCA3.pem": "18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4",
		"AmazonRootCA4.pem": "e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092",
	}
	for _, n := range rootNames {
		c, err := amazonRoot(n)
		require.NoError(t, err)
		sum := sha256.Sum256(c.Raw)
		require.Equal(t, want[n], hex.EncodeToString(sum[:]), n)
		require.True(t, c.IsCA, n)
		require.Equal(t, c.Subject.String(), c.Issuer.String(), "%s is self-signed", n)
	}
	pool, err := AmazonRoots()
	require.NoError(t, err)
	require.NotNil(t, pool)
}

// fakeKMS answers like KMS, and checks each request as KMS would see it:
// POST /, the JSON content type, the target, the date, and an
// Authorization header that recomputes over what arrived.
type fakeKMS struct {
	t       *testing.T
	creds   awssigv4.Credentials
	answer  func(op string, body map[string]any) (int, any)
	raw     func(op string) []byte
	calls   atomic.Int32
	lastReq atomic.Value
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	body, err := io.ReadAll(r.Body)
	require.NoError(f.t, err)
	require.Equal(f.t, http.MethodPost, r.Method)
	require.Equal(f.t, "/", r.URL.Path)
	require.Equal(f.t, "application/x-amz-json-1.1", r.Header.Get("Content-Type"))
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
	f.lastReq.Store(op)
	date, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	require.NoError(f.t, err)
	var signed []awssigv4.Field
	auth := r.Header.Get("Authorization")
	_, sh, ok := strings.Cut(auth, "SignedHeaders=")
	require.True(f.t, ok, auth)
	sh, _, _ = strings.Cut(sh, ",")
	for _, n := range strings.Split(sh, ";") {
		switch n {
		case "host":
			signed = append(signed, awssigv4.Field{Name: "Host", Value: r.Host})
		case "x-amz-date":
		case "x-amz-security-token":
			if f.creds.SessionToken == "" {
				signed = append(signed, awssigv4.Field{Name: n, Value: r.Header.Get(n)})
			}
		default:
			signed = append(signed, awssigv4.Field{Name: n, Value: r.Header.Get(n)})
		}
	}
	re, err := awssigv4.Sign(awssigv4.Request{Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery, Header: signed, Body: body},
		f.creds, awssigv4.Options{Region: "us-east-2", Service: "kms", Time: date, NormalizePath: true})
	require.NoError(f.t, err)
	if re.Authorization != auth {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"InvalidSignatureException","message":"The request signature we calculated does not match"}`))
		return
	}
	if f.raw != nil {
		if b := f.raw(op); b != nil {
			_, _ = w.Write(b)
			return
		}
	}
	var in map[string]any
	require.NoError(f.t, json.Unmarshal(body, &in))
	status, out := f.answer(op, in)
	w.Header().Set("X-Amzn-RequestId", "req-123")
	w.WriteHeader(status)
	require.NoError(f.t, json.NewEncoder(w).Encode(out))
}

const keyARN = "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

func newFake(t *testing.T, creds awssigv4.Credentials, answer func(op string, body map[string]any) (int, any)) (*fakeKMS, *Client) {
	t.Helper()
	f := &fakeKMS{t: t, creds: creds, answer: answer}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c, err := New(Config{
		Region:      "us-east-2",
		Endpoint:    "example.com",
		Credentials: StaticCredentials(creds),
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
		},
		RootCAs: pool,
	})
	require.NoError(t, err)
	return f, c
}

var creds = awssigv4.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", SessionToken: "IQoJb3JpZ2luX2VjEXAMPLE"}

func TestOperationsOnTheWire(t *testing.T) {
	ctx := context.Background()
	f, c := newFake(t, creds, func(op string, in map[string]any) (int, any) {
		switch op {
		case "GenerateDataKey":
			require.Equal(t, keyARN, in["KeyId"])
			require.Equal(t, "AES_256", in["KeySpec"])
			require.Equal(t, map[string]any{"purpose": "test"}, in["EncryptionContext"])
			return 200, map[string]any{"CiphertextBlob": make([]byte, 184), "Plaintext": make([]byte, 32), "KeyId": keyARN}
		case "Decrypt":
			require.Equal(t, keyARN, in["KeyId"])
			if r, ok := in["Recipient"].(map[string]any); ok {
				require.Equal(t, "RSAES_OAEP_SHA_256", r["KeyEncryptionAlgorithm"])
				require.NotEmpty(t, r["AttestationDocument"])
				return 200, map[string]any{"CiphertextForRecipient": make([]byte, 600), "KeyId": keyARN, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}
			}
			return 200, map[string]any{"Plaintext": []byte("secret"), "KeyId": keyARN, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}
		case "GenerateRandom":
			require.EqualValues(t, 32, in["NumberOfBytes"])
			if _, ok := in["Recipient"]; ok {
				return 200, map[string]any{"CiphertextForRecipient": make([]byte, 600)}
			}
			return 200, map[string]any{"Plaintext": make([]byte, 32)}
		}
		t.Fatalf("unexpected operation %s", op)
		return 0, nil
	})
	dk, err := c.GenerateDataKey(ctx, keyARN, map[string]string{"purpose": "test"})
	require.NoError(t, err)
	require.Len(t, dk.Plaintext, 32)
	require.Equal(t, keyARN, dk.KeyID)

	out, err := c.Decrypt(ctx, DecryptInput{CiphertextBlob: dk.CiphertextBlob, KeyID: keyARN, Recipient: &Recipient{AttestationDocument: []byte{0x84, 0x44}}})
	require.NoError(t, err)
	require.Len(t, out.CiphertextForRecipient, 600)
	require.Empty(t, out.Plaintext)

	out, err = c.Decrypt(ctx, DecryptInput{CiphertextBlob: dk.CiphertextBlob, KeyID: keyARN})
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), out.Plaintext)

	r, err := c.GenerateRandom(ctx, 32, nil)
	require.NoError(t, err)
	require.Len(t, r.Plaintext, 32)
	r, err = c.GenerateRandom(ctx, 32, &Recipient{AttestationDocument: []byte{1}})
	require.NoError(t, err)
	require.Len(t, r.CiphertextForRecipient, 600)
	require.EqualValues(t, 5, f.calls.Load())
}

func TestAnswersOutsideTheirFormAreRefused(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		answer any
		do     func(c *Client) error
		want   string
	}{
		"plaintext to an attested Decrypt": {map[string]any{"CiphertextForRecipient": []byte{1}, "Plaintext": []byte{2}, "KeyId": keyARN},
			func(c *Client) error {
				_, err := c.Decrypt(ctx, DecryptInput{CiphertextBlob: []byte{1}, KeyID: keyARN, Recipient: &Recipient{AttestationDocument: []byte{1}}})
				return err
			}, "plaintext in the answer to an attested request"},
		"no CiphertextForRecipient": {map[string]any{"KeyId": keyARN},
			func(c *Client) error {
				_, err := c.Decrypt(ctx, DecryptInput{CiphertextBlob: []byte{1}, KeyID: keyARN, Recipient: &Recipient{AttestationDocument: []byte{1}}})
				return err
			}, "a CiphertextForRecipient of 0 bytes"},
		"CiphertextForRecipient unasked": {map[string]any{"CiphertextForRecipient": []byte{1}, "Plaintext": []byte{2}, "KeyId": keyARN},
			func(c *Client) error {
				_, err := c.Decrypt(ctx, DecryptInput{CiphertextBlob: []byte{1}, KeyID: keyARN})
				return err
			}, "without a recipient"},
		"another key": {map[string]any{"Plaintext": []byte{2}, "KeyId": "arn:aws:kms:us-east-2:111122223333:key/other"},
			func(c *Client) error {
				_, err := c.Decrypt(ctx, DecryptInput{CiphertextBlob: []byte{1}, KeyID: keyARN})
				return err
			}, "names key arn:aws:kms:us-east-2:111122223333:key/other"},
		"no key named": {map[string]any{"Plaintext": []byte{2}},
			func(c *Client) error {
				_, err := c.Decrypt(ctx, DecryptInput{CiphertextBlob: []byte{1}, KeyID: keyARN})
				return err
			}, "names no key"},
		"an asymmetric algorithm": {map[string]any{"Plaintext": []byte{2}, "KeyId": keyARN, "EncryptionAlgorithm": "RSAES_OAEP_SHA_1"},
			func(c *Client) error {
				_, err := c.Decrypt(ctx, DecryptInput{CiphertextBlob: []byte{1}, KeyID: keyARN})
				return err
			}, "not SYMMETRIC_DEFAULT"},
		"empty plaintext": {map[string]any{"KeyId": keyARN},
			func(c *Client) error {
				_, err := c.Decrypt(ctx, DecryptInput{CiphertextBlob: []byte{1}, KeyID: keyARN})
				return err
			}, "a plaintext of 0 bytes"},
		"a 16-byte data key": {map[string]any{"Plaintext": make([]byte, 16), "CiphertextBlob": []byte{1}, "KeyId": keyARN},
			func(c *Client) error { _, err := c.GenerateDataKey(ctx, keyARN, nil); return err }, "a data key of 16 bytes"},
		"no ciphertext blob": {map[string]any{"Plaintext": make([]byte, 32), "KeyId": keyARN},
			func(c *Client) error { _, err := c.GenerateDataKey(ctx, keyARN, nil); return err }, "a ciphertext blob of 0 bytes"},
		"data key under another key": {map[string]any{"Plaintext": make([]byte, 32), "CiphertextBlob": []byte{1}, "KeyId": "arn:aws:kms:us-east-2:1:key/x"},
			func(c *Client) error { _, err := c.GenerateDataKey(ctx, keyARN, nil); return err }, "not " + keyARN},
		"short random": {map[string]any{"Plaintext": make([]byte, 31)},
			func(c *Client) error { _, err := c.GenerateRandom(ctx, 32, nil); return err }, "31 bytes for 32 asked"},
		"refused": {nil,
			func(c *Client) error { _, err := c.GenerateRandom(ctx, 32, nil); return err }, "AccessDeniedException"},
	} {
		t.Run(name, func(t *testing.T) {
			_, c := newFake(t, creds, func(string, map[string]any) (int, any) {
				if tc.answer == nil {
					return 400, map[string]any{"__type": "com.amazon.coral.service#AccessDeniedException", "message": "not authorized"}
				}
				return 200, tc.answer
			})
			err := tc.do(c)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestAPIErrorsAreNamed(t *testing.T) {
	_, c := newFake(t, creds, func(string, map[string]any) (int, any) {
		return 400, map[string]any{"__type": "com.amazon.coral.service#AccessDeniedException", "Message": strings.Repeat("m", 600)}
	})
	_, err := c.GenerateRandom(context.Background(), 8, nil)
	require.True(t, IsAccessDenied(err))
	var e *APIError
	require.ErrorAs(t, err, &e)
	require.Equal(t, 400, e.StatusCode)
	require.Equal(t, "req-123", e.RequestID)
	require.Len(t, e.Message, 512+len("…"))
	require.False(t, IsAccessDenied(io.EOF))

	_, c = newFake(t, creds, func(string, map[string]any) (int, any) { return 500, map[string]any{} })
	_, err = c.GenerateRandom(context.Background(), 8, nil)
	require.ErrorAs(t, err, &e)
	require.Equal(t, "unknown", e.Type)
}

// A signature that does not recompute is what the fake — and KMS — refuse.
func TestTheFakeChecksTheSignature(t *testing.T) {
	f := &fakeKMS{t: t, creds: creds, answer: func(string, map[string]any) (int, any) { return 200, map[string]any{"Plaintext": make([]byte, 8)} }}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	wrong := creds
	wrong.SecretAccessKey = "another secret"
	c, err := New(Config{Region: "us-east-2", Endpoint: "example.com", Credentials: StaticCredentials(wrong), RootCAs: pool,
		Dial: func(ctx context.Context) (net.Conn, error) { return net.Dial("tcp", srv.Listener.Addr().String()) }})
	require.NoError(t, err)
	_, err = c.GenerateRandom(context.Background(), 8, nil)
	var e *APIError
	require.ErrorAs(t, err, &e)
	require.Equal(t, "InvalidSignatureException", e.Type)
}

func TestMalformedAnswers(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  []byte
		want string
	}{
		"not JSON":        {[]byte("<html>"), "does not parse"},
		"trailing data":   {[]byte(`{"Plaintext":"AAAAAAAAAAA="} {}`), "data after the answer"},
		"too large":       {[]byte(`{"Plaintext":"` + strings.Repeat("A", maxResponseBytes) + `"}`), "more than"},
		"bad base64 blob": {[]byte(`{"Plaintext":"%%%"}`), "does not parse"},
	} {
		t.Run(name, func(t *testing.T) {
			f, c := newFake(t, creds, nil)
			f.raw = func(string) []byte { return tc.raw }
			_, err := c.GenerateRandom(context.Background(), 8, nil)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// The endpoint is verified against the pool and nothing else: a server
// whose certificate is not under it is refused at the handshake, with
// Amazon's roots too.
func TestTLSIsVerifiedAgainstThePool(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("reached") }))
	t.Cleanup(srv.Close)
	for _, pool := range []*x509.CertPool{x509.NewCertPool(), nil} {
		c, err := New(Config{Region: "us-east-2", Endpoint: "example.com", Credentials: StaticCredentials(creds), RootCAs: pool,
			Dial: func(ctx context.Context) (net.Conn, error) { return net.Dial("tcp", srv.Listener.Addr().String()) }})
		require.NoError(t, err)
		_, err = c.GenerateRandom(context.Background(), 8, nil)
		require.ErrorContains(t, err, "certificate")
	}
}

// No proxy from the environment: with HTTPS_PROXY pointing nowhere the
// request still reaches the endpoint directly.
func TestNoProxyFromTheEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	_, c := newFake(t, creds, func(string, map[string]any) (int, any) { return 200, map[string]any{"Plaintext": make([]byte, 8)} })
	_, err := c.GenerateRandom(context.Background(), 8, nil)
	require.NoError(t, err)
}

func TestRequestRefusals(t *testing.T) {
	ctx := context.Background()
	_, c := newFake(t, creds, func(string, map[string]any) (int, any) { t.Fatal("sent"); return 0, nil })
	_, err := c.Decrypt(ctx, DecryptInput{CiphertextBlob: []byte{1}})
	require.ErrorContains(t, err, "no key ID")
	_, err = c.Decrypt(ctx, DecryptInput{KeyID: keyARN})
	require.ErrorContains(t, err, "a ciphertext blob of 0 bytes")
	_, err = c.Decrypt(ctx, DecryptInput{KeyID: keyARN, CiphertextBlob: make([]byte, MaxCiphertextBytes+1)})
	require.ErrorContains(t, err, "6145 bytes")
	_, err = c.Decrypt(ctx, DecryptInput{KeyID: keyARN, CiphertextBlob: []byte{1}, Recipient: &Recipient{}})
	require.ErrorContains(t, err, "an attestation document of 0 bytes")
	_, err = c.GenerateRandom(ctx, 0, nil)
	require.ErrorContains(t, err, "1 to 1024")
	_, err = c.GenerateRandom(ctx, 8, &Recipient{AttestationDocument: make([]byte, MaxAttestationBytes+1)})
	require.ErrorContains(t, err, "an attestation document of")
	_, err = c.GenerateDataKey(ctx, "", nil)
	require.ErrorContains(t, err, "no key ID")

	for name, cfg := range map[string]Config{
		"no region":       {Credentials: StaticCredentials(creds)},
		"upper region":    {Region: "US-EAST-2", Credentials: StaticCredentials(creds)},
		"no credentials":  {Region: "us-east-2"},
		"endpoint a URL":  {Region: "us-east-2", Endpoint: "https://kms", Credentials: StaticCredentials(creds)},
		"endpoint a port": {Region: "us-east-2", Endpoint: "kms:443", Credentials: StaticCredentials(creds)},
	} {
		_, err := New(cfg)
		require.Error(t, err, name)
	}
	c2, err := New(Config{Region: "us-east-2", Credentials: StaticCredentials{}})
	require.NoError(t, err)
	_, err = c2.GenerateRandom(ctx, 8, nil)
	require.ErrorContains(t, err, "static credentials without")
	require.Equal(t, "kms.us-east-2.amazonaws.com", c2.host)
}

func TestStaticCredentials(t *testing.T) {
	_, err := StaticCredentials{AccessKeyID: "AKID"}.Retrieve(context.Background())
	require.ErrorContains(t, err, "without an access key or its secret")
	want := awssigv4.Credentials{AccessKeyID: "AKIDSTATIC", SecretAccessKey: "s3cr3t-value", SessionToken: "token-value"}
	c, err := StaticCredentials(want).Retrieve(context.Background())
	require.NoError(t, err)
	require.Equal(t, want, c)
	for _, s := range []string{StaticCredentials(c).String(), StaticCredentials(c).GoString()} {
		require.Contains(t, s, "AKIDSTATIC")
		require.NotContains(t, s, "s3cr3t-value")
		require.NotContains(t, s, "token-value")
	}
}
