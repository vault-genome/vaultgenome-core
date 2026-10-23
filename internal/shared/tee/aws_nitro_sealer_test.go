// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/awskms"
	"github.com/vault-genome/vaultgenome-core/internal/shared/cms/cmstest"
)

const fakeNitroKeyARN = "arn:aws:kms:us-east-2:111122223333:key/0b7c3a6e-1f2d-4e5a-8b9c-0d1e2f3a4b5c"

// fakeNitroKMS behaves as KMS does under the key policy the operator guide
// writes (ADR 0036): data keys kept with the encryption context they were
// made under, Decrypt only under that context, and only to a Recipient
// whose attestation document verifies and whose PCR0 the policy admits;
// the answer is CMS, the KMS profile, to the document's key.
type fakeNitroKMS struct {
	keyARN   string
	roots    [][]byte
	admitted []Measurement

	mu            sync.Mutex
	keys          map[string]fakeNitroDataKey
	recipientBits int
	// answer, when set, replaces the data key KMS encrypts to the
	// recipient, or the key it encrypts it to.
	answer      func(key []byte, pub *rsa.PublicKey) ([]byte, *rsa.PublicKey)
	generateErr error
	decryptErr  error
}

type fakeNitroDataKey struct {
	key []byte
	ec  map[string]string
}

func newFakeNitroKMS(_ testing.TB, fh *fakeHardware) *fakeNitroKMS {
	return &fakeNitroKMS{keyARN: fakeNitroKeyARN, roots: [][]byte{fh.nitro.rootDER}, admitted: []Measurement{fh.measure}, keys: map[string]fakeNitroDataKey{}}
}

func kmsRefusal(t, msg string) error {
	return &awskms.APIError{StatusCode: 400, Type: t, Message: msg, RequestID: "fake"}
}

func (k *fakeNitroKMS) GenerateDataKey(_ context.Context, keyID string, ec map[string]string) (*awskms.DataKey, error) {
	if k.generateErr != nil {
		return nil, k.generateErr
	}
	if keyID != k.keyARN {
		return nil, kmsRefusal("NotFoundException", "no such key")
	}
	key := make([]byte, 32)
	blob := make([]byte, 96)
	_, _ = rand.Read(key)
	_, _ = rand.Read(blob)
	k.mu.Lock()
	k.keys[hex.EncodeToString(blob)] = fakeNitroDataKey{key: bytes.Clone(key), ec: maps.Clone(ec)}
	k.mu.Unlock()
	return &awskms.DataKey{Plaintext: key, CiphertextBlob: blob, KeyID: k.keyARN}, nil
}

func (k *fakeNitroKMS) Decrypt(_ context.Context, in awskms.DecryptInput) (*awskms.DecryptOutput, error) {
	if k.decryptErr != nil {
		return nil, k.decryptErr
	}
	if in.KeyID != k.keyARN {
		return nil, kmsRefusal("IncorrectKeyException", "another key")
	}
	k.mu.Lock()
	entry, ok := k.keys[hex.EncodeToString(in.CiphertextBlob)]
	k.mu.Unlock()
	if !ok || !maps.Equal(entry.ec, in.EncryptionContext) {
		return nil, kmsRefusal("InvalidCiphertextException", "")
	}
	if in.Recipient == nil {
		return nil, kmsRefusal("AccessDeniedException", "the key policy releases only to an attested enclave")
	}
	report, err := AuditAWSNitroDocument(in.Recipient.AttestationDocument, k.roots, time.Time{})
	if err != nil {
		return nil, kmsRefusal("ValidationException", "the attestation document does not verify: "+err.Error())
	}
	admitted := false
	for _, m := range k.admitted {
		admitted = admitted || bytes.Equal(m, report.PCRs[0])
	}
	if !admitted || report.Debug {
		return nil, kmsRefusal("AccessDeniedException", "kms:RecipientAttestation:ImageSha384 does not match")
	}
	pubAny, err := x509.ParsePKIXPublicKey(report.PublicKey)
	if err != nil {
		return nil, kmsRefusal("ValidationException", "the document carries no public key")
	}
	pub := pubAny.(*rsa.PublicKey)
	k.mu.Lock()
	k.recipientBits = pub.N.BitLen()
	k.mu.Unlock()
	key := entry.key
	if k.answer != nil {
		key, pub = k.answer(key, pub)
	}
	cfr, err := cmstest.EnvelopedData(pub, key)
	if err != nil {
		return nil, err
	}
	return &awskms.DecryptOutput{CiphertextForRecipient: cfr, KeyID: k.keyARN}, nil
}

// nitroSealers are the operator's sealer (no enclave: Attest nil, sealing
// for PCR0 sealedFor) and the enclave's (its producer, its own PCR0).
func nitroSealers(t *testing.T, fh *fakeHardware, sealedFor Measurement) (operator, enclave *AWSNitroSealer, p *AWSNitroProducer) {
	t.Helper()
	p, err := NewAWSNitroProducer(AWSNitroProducerConfig{NSMDevicePath: "/fake/nsm", pinnedRoots: [][]byte{fh.nitro.rootDER}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	operator, err = NewAWSNitroSealer(AWSNitroSealerConfig{KeyARN: fakeNitroKeyARN, Measurement: sealedFor, kms: fh.nitroKMS})
	require.NoError(t, err)
	enclave, err = NewAWSNitroSealer(AWSNitroSealerConfig{KeyARN: fakeNitroKeyARN, Measurement: p.Measurement(), Attest: p.attestRecipient, kms: fh.nitroKMS})
	require.NoError(t, err)
	return operator, enclave, p
}

func TestAWSNitroSealerOpensInTheEnclave(t *testing.T) {
	fh := newFakeHardware(t, "nitro-sealer")
	installAWSNitroFake(t, fh)
	operator, enclave, p := nitroSealers(t, fh, fh.measure)
	require.Equal(t, fh.measure, p.Measurement())

	secret := []byte("-----BEGIN PRIVATE KEY----- the TLS server key")
	aad := []byte("http.tls.server_key")
	sealed, err := operator.Seal(secret, aad)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "the TLS server key")
	got, err := enclave.Unseal(sealed, aad)
	require.NoError(t, err)
	require.Equal(t, secret, got)
	require.Equal(t, 3072, fh.nitroKMS.recipientBits, "KMS's answer goes to a fresh RSA-3072 key")

	// The data key was made under the context naming the image and the
	// secret, which is what KMS logs.
	var env awsNitroSealed
	require.NoError(t, json.Unmarshal(sealed, &env))
	entry := fh.nitroKMS.keys[hex.EncodeToString(env.DataKey)]
	require.Equal(t, hex.EncodeToString(fh.measure), entry.ec["vault-genome:pcr0"])
	require.Len(t, entry.ec["vault-genome:aad-sha256"], 64)
	require.Equal(t, "v1", entry.ec["vault-genome:sealed-secret"])
}

func TestAWSNitroSealerRefusals(t *testing.T) {
	fh := newFakeHardware(t, "nitro-sealer-refusals")
	installAWSNitroFake(t, fh)
	aad := []byte("http.bearer_token_file")
	operator, enclave, p := nitroSealers(t, fh, fh.measure)
	sealed, err := operator.Seal([]byte("token"), aad)
	require.NoError(t, err)

	t.Run("outside the enclave", func(t *testing.T) {
		_, err := operator.Unseal(sealed, aad)
		requireIntegrityErr(t, err, "opens only in the enclave it was sealed for")
	})
	t.Run("sealed for another image", func(t *testing.T) {
		other := MeasurementFromBytesMust(t, bytes.Repeat([]byte{0x5a}, 48))
		op2, err := NewAWSNitroSealer(AWSNitroSealerConfig{KeyARN: fakeNitroKeyARN, Measurement: other, kms: fh.nitroKMS})
		require.NoError(t, err)
		s2, err := op2.Seal([]byte("token"), aad)
		require.NoError(t, err)
		_, err = enclave.Unseal(s2, aad)
		requireIntegrityErr(t, err, "sealed for another image")
	})
	t.Run("as another secret", func(t *testing.T) {
		_, err := enclave.Unseal(sealed, []byte("http.tls.server_key"))
		requireIntegrityErr(t, err, "or as another secret")
	})
	t.Run("the policy does not admit this image", func(t *testing.T) {
		saved := fh.nitroKMS.admitted
		t.Cleanup(func() { fh.nitroKMS.admitted = saved })
		fh.nitroKMS.admitted = []Measurement{MeasurementFromBytesMust(t, bytes.Repeat([]byte{1}, 48))}
		_, err := enclave.Unseal(sealed, aad)
		requireIntegrityErr(t, err, "does not admit its attestation")
	})
	t.Run("under another KMS key", func(t *testing.T) {
		var env awsNitroSealed
		require.NoError(t, json.Unmarshal(sealed, &env))
		env.KeyARN = "arn:aws:kms:us-east-2:111122223333:key/another"
		b, _ := json.Marshal(env)
		_, err := enclave.Unseal(b, aad)
		requireStructuralErr(t, err, "sealed under KMS key arn:aws:kms:us-east-2:111122223333:key/another")
	})
	t.Run("the ciphertext changed", func(t *testing.T) {
		var env awsNitroSealed
		require.NoError(t, json.Unmarshal(sealed, &env))
		env.Ciphertext[0] ^= 1
		b, _ := json.Marshal(env)
		_, err := enclave.Unseal(b, aad)
		requireIntegrityErr(t, err, "does not authenticate")
	})
	t.Run("KMS answers to another key", func(t *testing.T) {
		stranger, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		fh.nitroKMS.answer = func(key []byte, _ *rsa.PublicKey) ([]byte, *rsa.PublicKey) { return key, &stranger.PublicKey }
		t.Cleanup(func() { fh.nitroKMS.answer = nil })
		_, err = enclave.Unseal(sealed, aad)
		requireIntegrityErr(t, err, "does not open with this enclave's key")
	})
	t.Run("KMS answers with a short key", func(t *testing.T) {
		fh.nitroKMS.answer = func(key []byte, pub *rsa.PublicKey) ([]byte, *rsa.PublicKey) { return key[:16], pub }
		t.Cleanup(func() { fh.nitroKMS.answer = nil })
		_, err := enclave.Unseal(sealed, aad)
		requireIntegrityErr(t, err, "a data key of 16 bytes")
	})
	t.Run("KMS fails", func(t *testing.T) {
		fh.nitroKMS.decryptErr = errors.New("throttled")
		_, err := enclave.Unseal(sealed, aad)
		require.ErrorContains(t, err, "KMS Decrypt: throttled")
		fh.nitroKMS.decryptErr = nil
		fh.nitroKMS.generateErr = errors.New("throttled")
		_, err = operator.Seal([]byte("x"), aad)
		require.ErrorContains(t, err, "KMS GenerateDataKey under "+fakeNitroKeyARN+": throttled")
		fh.nitroKMS.generateErr = nil
	})
	t.Run("the attestation fails", func(t *testing.T) {
		bad, err := NewAWSNitroSealer(AWSNitroSealerConfig{KeyARN: fakeNitroKeyARN, Measurement: fh.measure, kms: fh.nitroKMS,
			Attest: func(crypto.PublicKey) ([]byte, error) { return nil, errors.New("nsm down") }})
		require.NoError(t, err)
		_, err = bad.Unseal(sealed, aad)
		require.ErrorContains(t, err, "attestation for KMS: nsm down")
	})
	t.Run("a closed producer", func(t *testing.T) {
		p2, err := NewAWSNitroProducer(AWSNitroProducerConfig{NSMDevicePath: "/fake/nsm", pinnedRoots: [][]byte{fh.nitro.rootDER}})
		require.NoError(t, err)
		require.NoError(t, p2.Close())
		_, err = p2.attestRecipient(nil)
		require.ErrorContains(t, err, "not open")
	})
	t.Run("nothing to seal", func(t *testing.T) {
		_, err := operator.Seal(nil, aad)
		require.ErrorContains(t, err, "nothing to seal")
	})
	t.Run("not a sealed secret", func(t *testing.T) {
		var env awsNitroSealed
		require.NoError(t, json.Unmarshal(sealed, &env))
		for name, tc := range map[string]struct {
			raw  []byte
			want string
		}{
			"not JSON":      {[]byte("{"), "not a sealed secret of this sealer"},
			"unknown field": {[]byte(`{"schema":"x","extra":1}`), "not a sealed secret of this sealer"},
			"two values":    {append(append([]byte(nil), sealed...), []byte(" {}")...), "not a sealed secret of this sealer"},
			"schema":        {mutateSealed(t, env, func(e *awsNitroSealed) { e.Schema = "v0" }), `schema "v0"`},
			"short nonce":   {mutateSealed(t, env, func(e *awsNitroSealed) { e.Nonce = e.Nonce[:8] }), "incomplete"},
			"no data key":   {mutateSealed(t, env, func(e *awsNitroSealed) { e.DataKey = nil }), "incomplete"},
			"big data key":  {mutateSealed(t, env, func(e *awsNitroSealed) { e.DataKey = make([]byte, awskms.MaxCiphertextBytes+1) }), "incomplete"},
			"no ciphertext": {mutateSealed(t, env, func(e *awsNitroSealed) { e.Ciphertext = e.Ciphertext[:16] }), "incomplete"},
		} {
			_, err := enclave.Unseal(tc.raw, aad)
			require.ErrorContains(t, err, tc.want, name)
		}
	})
	_ = p
}

func mutateSealed(t *testing.T, env awsNitroSealed, f func(*awsNitroSealed)) []byte {
	t.Helper()
	e := env
	e.Nonce = bytes.Clone(env.Nonce)
	e.Ciphertext = bytes.Clone(env.Ciphertext)
	e.DataKey = bytes.Clone(env.DataKey)
	f(&e)
	b, err := json.Marshal(e)
	require.NoError(t, err)
	return b
}

func MeasurementFromBytesMust(t *testing.T, b []byte) Measurement {
	t.Helper()
	m, err := MeasurementFromBytes(b)
	require.NoError(t, err)
	return m
}

func TestNewAWSNitroSealerRefusals(t *testing.T) {
	m := MeasurementFromBytesMust(t, bytes.Repeat([]byte{7}, 48))
	client, err := awskms.New(awskms.Config{Region: "us-east-2", Credentials: awskms.StaticCredentials{AccessKeyID: "A", SecretAccessKey: "s"}})
	require.NoError(t, err)
	for name, tc := range map[string]struct {
		cfg  AWSNitroSealerConfig
		want string
	}{
		"no key":          {AWSNitroSealerConfig{Measurement: m, KMS: client}, "not a KMS key ARN"},
		"an alias":        {AWSNitroSealerConfig{KeyARN: "arn:aws:kms:us-east-2:111122223333:alias/vg", Measurement: m, KMS: client}, "not a KMS key ARN"},
		"a key ID":        {AWSNitroSealerConfig{KeyARN: "key-1234", Measurement: m, KMS: client}, "not a KMS key ARN"},
		"another service": {AWSNitroSealerConfig{KeyARN: "arn:aws:s3:us-east-2:111122223333:key/x", Measurement: m, KMS: client}, "not a KMS key ARN"},
		"a short account": {AWSNitroSealerConfig{KeyARN: "arn:aws:kms:us-east-2:1:key/x", Measurement: m, KMS: client}, "not a KMS key ARN"},
		"a 32-byte PCR0":  {AWSNitroSealerConfig{KeyARN: fakeNitroKeyARN, Measurement: MeasurementFromBytesMust(t, make([]byte, 32)), KMS: client}, "48 bytes"},
		"a zero PCR0":     {AWSNitroSealerConfig{KeyARN: fakeNitroKeyARN, Measurement: make(Measurement, 48), KMS: client}, "production-mode image"},
		"no KMS client":   {AWSNitroSealerConfig{KeyARN: fakeNitroKeyARN, Measurement: m}, "no KMS client"},
	} {
		_, err := NewAWSNitroSealer(tc.cfg)
		require.ErrorContains(t, err, tc.want, name)
	}
	for arn, region := range map[string]string{
		fakeNitroKeyARN: "us-east-2",
		"arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/k": "us-gov-west-1",
		"arn:aws-cn:kms:cn-north-1:111122223333:key/mrk-1":    "cn-north-1",
	} {
		got, err := ParseAWSKMSKeyARN(arn)
		require.NoError(t, err, arn)
		require.Equal(t, region, got, arn)
	}
}

// The sealed-secret file of a Nitro enclave: sealed by the operator for
// the image, opened by the enclave, and refused before KMS when it names
// another sealer.
func TestNitroSealedSecretFiles(t *testing.T) {
	fh := newFakeHardware(t, "nitro-sealed-files")
	installAWSNitroFake(t, fh)
	operator, enclave, _ := nitroSealers(t, fh, fh.measure)
	file, err := SealSecretWith([]byte("bearer token"), operator, SealerKindAWSKMSAttested, ProviderAWSNitro, fh.measure, "http.bearer_token_file")
	require.NoError(t, err)
	got, err := OpenSecretWith(file, enclave, SealerKindAWSKMSAttested, ProviderAWSNitro, "http.bearer_token_file")
	require.NoError(t, err)
	require.Equal(t, []byte("bearer token"), got)
	_, err = OpenSecretWith(file, enclave, SealerKindAWSKMSAttested, ProviderAWSNitro, "http.tls.server_key")
	require.ErrorContains(t, err, `the file is "http.bearer_token_file"`)
	_, err = OpenSecretWith(file, enclave, SealerKindTPM2, ProviderAWSNitro, "http.bearer_token_file")
	require.ErrorContains(t, err, "sealed with aws-kms-attested")
}

func TestNitroSealerSelection(t *testing.T) {
	for _, mode := range []SealerMode{"", SealerModeAuto, SealerModeTEE} {
		k, err := SealerKindForProvider(ProviderAWSNitro, mode)
		require.NoError(t, err)
		require.Equal(t, SealerKindAWSKMSAttested, k)
	}
	_, err := SealerKindForProvider(ProviderAWSNitro, SealerModeTPM2)
	require.ErrorContains(t, err, "a Nitro enclave has no TPM")

	fh := newFakeHardware(t, "nitro-sealer-for")
	installAWSNitroFake(t, fh)
	p, err := NewAWSNitroProducer(AWSNitroProducerConfig{NSMDevicePath: "/fake/nsm", pinnedRoots: [][]byte{fh.nitro.rootDER}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	_, _, _, err = SealerFor(p, SealerOptions{})
	require.ErrorContains(t, err, "needs tee.aws_kms")
	_, _, _, err = SealerFor(p, SealerOptions{AWSKMS: &AWSKMSSealerOptions{KeyARN: fakeNitroKeyARN, KMSVsockPort: 8000, IMDSVsockPort: 8000}})
	require.ErrorContains(t, err, "two distinct vsock ports")
	_, _, _, err = SealerFor(p, SealerOptions{AWSKMS: &AWSKMSSealerOptions{KeyARN: "arn:aws:kms:us-east-2:111122223333:alias/x", KMSVsockPort: 8000, IMDSVsockPort: 8002}})
	require.ErrorContains(t, err, "not a KMS key ARN")
	s, closer, kind, err := SealerFor(p, SealerOptions{AWSKMS: &AWSKMSSealerOptions{KeyARN: fakeNitroKeyARN, KMSVsockPort: 8000, IMDSVsockPort: 8002}})
	require.NoError(t, err)
	require.Nil(t, closer)
	require.Equal(t, SealerKindAWSKMSAttested, kind)
	ns := s.(*AWSNitroSealer)
	require.Equal(t, fakeNitroKeyARN, ns.keyARN)
	require.Equal(t, p.Measurement(), ns.measurement)
	require.NotNil(t, ns.attest)
	kindFor, err := SealerKindFor(p, SealerModeAuto)
	require.NoError(t, err)
	require.Equal(t, SealerKindAWSKMSAttested, kindFor)
}
