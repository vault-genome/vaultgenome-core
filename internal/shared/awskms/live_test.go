// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build kmslive

package awskms

// The signer and the client against AWS KMS itself (ADR 0036, part
// three), run by scripts/hardware-test/aws-nitro/kms-live/run.sh with
// credentials in the environment. KMS checks a request's signature before
// it asks whether the caller may make it, so an answer of
// AccessDeniedException to a correctly signed request is the service
// accepting the signature, and InvalidSignatureException to a wrongly
// signed one is the service refusing it. Nothing here needs a key or
// creates anything.

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/awssigv4"
)

var accountInARN = regexp.MustCompile(`arn:aws:([a-z]+)::?(\d{12}):`)

func TestLiveKMS(t *testing.T) {
	region := os.Getenv("VG_KMS_LIVE_REGION")
	if region == "" {
		region = "us-east-2"
	}
	ctx := context.Background()
	// The credentials come in through the environment, as run.sh exports
	// them; a test may read it, the library does not.
	creds := awssigv4.Credentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
	require.True(t, creds.AccessKeyID != "" && creds.SecretAccessKey != "", "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set")
	redact := func(s string) string {
		s = strings.ReplaceAll(s, creds.AccessKeyID, creds.AccessKeyID[:4]+"…")
		return accountInARN.ReplaceAllString(s, "arn:aws:$1::<account>:")
	}
	apiErr := func(t *testing.T, err error) *APIError {
		t.Helper()
		var e *APIError
		require.ErrorAs(t, err, &e, "%s", redact(errString(err)))
		return e
	}
	newClient := func(t *testing.T, cfg Config) *Client {
		t.Helper()
		cfg.Region = region
		if cfg.Credentials == nil {
			cfg.Credentials = StaticCredentials(creds)
		}
		c, err := New(cfg)
		require.NoError(t, err)
		return c
	}
	t.Logf("region %s, endpoint kms.%s.amazonaws.com, TLS 1.3, Amazon's four roots", region, region)

	t.Run("signed right, KMS accepts the signature", func(t *testing.T) {
		out, err := newClient(t, Config{}).GenerateRandom(ctx, 32, nil)
		if err == nil {
			require.Len(t, out.Plaintext, 32)
			t.Logf("GenerateRandom: 32 bytes")
			return
		}
		e := apiErr(t, err)
		require.Equal(t, "AccessDeniedException", e.Type, redact(e.Message))
		t.Logf("GenerateRandom: HTTP %d %s (request %s): %s", e.StatusCode, e.Type, e.RequestID, redact(e.Message))
	})

	t.Run("the wrong secret, KMS refuses the signature", func(t *testing.T) {
		wrong := creds
		wrong.SecretAccessKey = flipLast(wrong.SecretAccessKey)
		_, err := newClient(t, Config{Credentials: StaticCredentials(wrong)}).GenerateRandom(ctx, 32, nil)
		e := apiErr(t, err)
		require.Equal(t, "InvalidSignatureException", e.Type, redact(e.Message))
		t.Logf("GenerateRandom: HTTP %d %s (request %s): %s", e.StatusCode, e.Type, e.RequestID, redact(e.Message))
	})

	t.Run("twenty minutes behind, the signature has expired", func(t *testing.T) {
		late := func() time.Time { return time.Now().Add(-20 * time.Minute) }
		_, err := newClient(t, Config{Now: late}).GenerateRandom(ctx, 32, nil)
		e := apiErr(t, err)
		require.Equal(t, "InvalidSignatureException", e.Type, redact(e.Message))
		require.Contains(t, e.Message, "Signature expired")
		t.Logf("GenerateRandom: HTTP %d %s (request %s): %s", e.StatusCode, e.Type, e.RequestID, redact(e.Message))
	})

	t.Run("an access key nobody has, KMS does not recognise it", func(t *testing.T) {
		unknown := creds
		unknown.AccessKeyID = "AKIA" + strings.Repeat("Z", 16)
		unknown.SessionToken = ""
		_, err := newClient(t, Config{Credentials: StaticCredentials(unknown)}).GenerateRandom(ctx, 32, nil)
		e := apiErr(t, err)
		require.Equal(t, "UnrecognizedClientException", e.Type, redact(e.Message))
		t.Logf("GenerateRandom: HTTP %d %s (request %s): %s", e.StatusCode, e.Type, e.RequestID, redact(e.Message))
	})

	t.Run("without Amazon's roots, the endpoint is refused at the handshake", func(t *testing.T) {
		_, err := newClient(t, Config{RootCAs: x509.NewCertPool()}).GenerateRandom(ctx, 32, nil)
		require.ErrorContains(t, err, "certificate signed by unknown authority")
		t.Logf("GenerateRandom with an empty pool: %s", redact(err.Error()))
	})

	t.Run("Decrypt and GenerateDataKey reach authorization", func(t *testing.T) {
		blob := make([]byte, 64)
		_, err := rand.Read(blob)
		require.NoError(t, err)
		key := "arn:aws:kms:" + region + ":111122223333:key/00000000-0000-0000-0000-000000000000"
		c := newClient(t, Config{})
		_, err = c.Decrypt(ctx, DecryptInput{CiphertextBlob: blob, KeyID: key, EncryptionContext: map[string]string{"vault-genome:check": "live"}})
		e := apiErr(t, err)
		require.NotContains(t, []string{"InvalidSignatureException", "IncompleteSignatureException", "SerializationException", "ValidationException"}, e.Type, redact(e.Message))
		t.Logf("Decrypt: HTTP %d %s (request %s): %s", e.StatusCode, e.Type, e.RequestID, redact(e.Message))
		_, err = c.GenerateDataKey(ctx, key, map[string]string{"vault-genome:check": "live"})
		e = apiErr(t, err)
		require.NotContains(t, []string{"InvalidSignatureException", "IncompleteSignatureException", "SerializationException", "ValidationException"}, e.Type, redact(e.Message))
		t.Logf("GenerateDataKey: HTTP %d %s (request %s): %s", e.StatusCode, e.Type, e.RequestID, redact(e.Message))
	})
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func flipLast(s string) string {
	b := []byte(s)
	if b[len(b)-1] == 'A' {
		b[len(b)-1] = 'B'
	} else {
		b[len(b)-1] = 'A'
	}
	return string(b)
}
