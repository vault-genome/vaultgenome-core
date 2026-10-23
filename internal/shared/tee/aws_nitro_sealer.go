// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The Nitro enclave's sealer (ADR 0036, decision 4, part three). A Nitro
// enclave has no key of its own to seal with; what it has is an
// attestation document KMS will release a key to. So a secret is sealed
// in an envelope: AES-256-GCM under a data key KMS generates and keeps
// encrypted under a KMS key, and opened in the enclave by asking KMS to
// decrypt that data key for a Recipient — the enclave's own document,
// carrying a public key made for this one call — so the answer is CMS
// only the enclave opens. KMS does that only when the key's policy admits
// the document's measurements (kms:RecipientAttestation:ImageSha384 is
// PCR0), and only under the encryption context the data key was made
// with, which names the image the secret was sealed for and the secret
// itself: a file sealed for one image does not open in another, nor as
// another secret, whatever the policy admits.
//
// Sealing needs no enclave: the operator's credentials ask KMS for a data
// key (kms:GenerateDataKey — a permission the operator's role has and the
// instance's does not). Opening is only in the enclave.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/awskms"
	"github.com/vault-genome/vaultgenome-core/internal/shared/cms"
	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// SealerKindAWSKMSAttested names the Nitro enclave's sealer in a sealed
// file: KMS, released to the enclave's attestation.
const SealerKindAWSKMSAttested SealerKind = "aws-kms-attested"

const (
	awsNitroSealedSchema = "vault-genome/aws-kms-attested/v1"
	awsNitroGCMLabel     = "vault-genome aws-kms-attested v1\x00"
	// awsNitroRecipientBits is the size of the key KMS encrypts its answer
	// to: 3072 bits, 128-bit strength (NIST SP 800-57 Part 1); AWS's SDK
	// offers 2048, 3072 and 4096 and uses 2048.
	awsNitroRecipientBits = 3072
	awsNitroCallTimeout   = 60 * time.Second
)

// awsKMSKeyARN is a KMS key's ARN: arn:<partition>:kms:<region>:<account>:key/<id>.
var awsKMSKeyARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):kms:([a-z0-9-]+):(\d{12}):key/([A-Za-z0-9-]{1,128})$`)

// ParseAWSKMSKeyARN checks that arn names a KMS key — not an alias, not a
// bare key ID: the sealer pins the very key — and returns its Region.
func ParseAWSKMSKeyARN(arn string) (region string, err error) {
	m := awsKMSKeyARN.FindStringSubmatch(arn)
	if m == nil {
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("aws-nitro sealer: %q is not a KMS key ARN (arn:aws:kms:<region>:<account>:key/<id>); an alias or a key ID is not pinned enough", arn), nil)
	}
	return m[2], nil
}

// awsNitroKMS is what the sealer asks of KMS.
type awsNitroKMS interface {
	GenerateDataKey(ctx context.Context, keyID string, encryptionContext map[string]string) (*awskms.DataKey, error)
	Decrypt(ctx context.Context, in awskms.DecryptInput) (*awskms.DecryptOutput, error)
}

// AWSNitroSealerConfig configures the sealer.
type AWSNitroSealerConfig struct {
	// KeyARN is the KMS key, as an ARN; the image's configuration names it,
	// so PCR0 covers it.
	KeyARN string
	// Measurement is the PCR0 the secrets are sealed for: in the enclave
	// its own, from its self-attestation; when sealing, the image's, from
	// the build's measurements.
	Measurement Measurement
	// KMS reaches the service; in an enclave through the parent's vsock.
	KMS *awskms.Client
	// Attest returns an attestation document carrying pub — the enclave's
	// NSM. Nil where there is no enclave; Unseal is then refused.
	Attest func(pub crypto.PublicKey) ([]byte, error)

	kms awsNitroKMS // tests
}

// AWSNitroSealer seals to a Nitro enclave image through KMS.
type AWSNitroSealer struct {
	keyARN      string
	measurement Measurement
	kms         awsNitroKMS
	attest      func(pub crypto.PublicKey) ([]byte, error)
}

// NewAWSNitroSealer builds the sealer.
func NewAWSNitroSealer(cfg AWSNitroSealerConfig) (*AWSNitroSealer, error) {
	if _, err := ParseAWSKMSKeyARN(cfg.KeyARN); err != nil {
		return nil, err
	}
	if len(cfg.Measurement) != 48 {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("aws-nitro sealer: a measurement of %d bytes; PCR0 is a SHA-384, 48 bytes", len(cfg.Measurement)), nil)
	}
	if cfg.Measurement.IsZero() {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			"aws-nitro sealer: PCR0 is zero, a debug-mode enclave; secrets are sealed only to a production-mode image", nil)
	}
	k := cfg.kms
	if k == nil {
		if cfg.KMS == nil {
			return nil, errors.New("aws-nitro sealer: no KMS client")
		}
		k = cfg.KMS
	}
	return &AWSNitroSealer{
		keyARN:      cfg.KeyARN,
		measurement: append(Measurement(nil), cfg.Measurement...),
		kms:         k,
		attest:      cfg.Attest,
	}, nil
}

// awsNitroSealed is the sealed form: the data key as KMS keeps it, and the
// secret under it.
type awsNitroSealed struct {
	Schema     string `json:"schema"`
	KeyARN     string `json:"kms_key_arn"`
	DataKey    []byte `json:"data_key"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// encryptionContext binds the data key to the image and to the secret:
// KMS decrypts only under the same context (it is also in CloudTrail,
// where it names what was opened without revealing it).
func (s *AWSNitroSealer) encryptionContext(aad []byte) map[string]string {
	sum := sha256.Sum256(aad)
	return map[string]string{
		"vault-genome:sealed-secret": "v1",
		"vault-genome:pcr0":          hex.EncodeToString(s.measurement),
		"vault-genome:aad-sha256":    hex.EncodeToString(sum[:]),
	}
}

func (s *AWSNitroSealer) gcmAAD(aad []byte) []byte {
	out := []byte(awsNitroGCMLabel)
	out = append(out, s.keyARN...)
	out = append(out, 0)
	return append(out, aad...)
}

// Seal seals plaintext for the sealer's image under aad.
func (s *AWSNitroSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("aws-nitro sealer: nothing to seal")
	}
	ctx, cancel := context.WithTimeout(context.Background(), awsNitroCallTimeout)
	defer cancel()
	dk, err := s.kms.GenerateDataKey(ctx, s.keyARN, s.encryptionContext(aad))
	if err != nil {
		return nil, fmt.Errorf("aws-nitro sealer: KMS GenerateDataKey under %s: %w", s.keyARN, err)
	}
	defer clear(dk.Plaintext)
	nonce, ct, err := shared_crypto.Seal(dk.Plaintext, plaintext, s.gcmAAD(aad))
	if err != nil {
		return nil, err
	}
	return json.Marshal(awsNitroSealed{Schema: awsNitroSealedSchema, KeyARN: s.keyARN, DataKey: dk.CiphertextBlob, Nonce: nonce, Ciphertext: ct})
}

// Unseal opens sealed in the enclave: KMS decrypts the data key for the
// enclave's document, under the context of this enclave's PCR0 and aad.
func (s *AWSNitroSealer) Unseal(sealed, aad []byte) ([]byte, error) {
	var env awsNitroSealed
	dec := json.NewDecoder(bytes.NewReader(sealed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil || dec.More() {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "aws-nitro sealer: not a sealed secret of this sealer", err)
	}
	if env.Schema != awsNitroSealedSchema {
		return nil, shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported,
			fmt.Sprintf("aws-nitro sealer: schema %q, want %q", env.Schema, awsNitroSealedSchema), nil)
	}
	if n := len(env.DataKey); n == 0 || n > awskms.MaxCiphertextBytes || len(env.Nonce) != shared_crypto.GCMNonceSize || len(env.Ciphertext) <= shared_crypto.GCMTagSize {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "aws-nitro sealer: the sealed secret is incomplete", nil)
	}
	if env.KeyARN != s.keyARN {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("aws-nitro sealer: sealed under KMS key %s; this image's key is %s", env.KeyARN, s.keyARN), nil)
	}
	if s.attest == nil {
		return nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
			"aws-nitro sealer: a Nitro-sealed secret opens only in the enclave it was sealed for — KMS releases its data key only to that enclave's attestation document", nil)
	}
	key, err := rsa.GenerateKey(rand.Reader, awsNitroRecipientBits)
	if err != nil {
		return nil, fmt.Errorf("aws-nitro sealer: the recipient key: %w", err)
	}
	doc, err := s.attest(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("aws-nitro sealer: attestation for KMS: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), awsNitroCallTimeout)
	defer cancel()
	out, err := s.kms.Decrypt(ctx, awskms.DecryptInput{
		CiphertextBlob:    env.DataKey,
		KeyID:             s.keyARN,
		EncryptionContext: s.encryptionContext(aad),
		Recipient:         &awskms.Recipient{AttestationDocument: doc},
	})
	if err != nil {
		var apiErr *awskms.APIError
		switch {
		case awskms.IsAccessDenied(err):
			return nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
				fmt.Sprintf("aws-nitro sealer: KMS does not release the data key to this enclave — the key's policy does not admit its attestation (PCR0 %s…)", hex.EncodeToString(s.measurement[:8])), err)
		case errors.As(err, &apiErr) && apiErr.Type == "InvalidCiphertextException":
			return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
				fmt.Sprintf("aws-nitro sealer: KMS does not decrypt the data key under this enclave's context — the secret was sealed for another image than PCR0 %s… or as another secret", hex.EncodeToString(s.measurement[:8])), err)
		}
		return nil, fmt.Errorf("aws-nitro sealer: KMS Decrypt: %w", err)
	}
	dataKey, err := cms.Decrypt(out.CiphertextForRecipient, key)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "aws-nitro sealer: KMS's answer does not open with this enclave's key", err)
	}
	defer clear(dataKey)
	if len(dataKey) != shared_crypto.AES256KeySize {
		return nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("aws-nitro sealer: a data key of %d bytes", len(dataKey)), nil)
	}
	plain, err := shared_crypto.Open(dataKey, env.Nonce, env.Ciphertext, s.gcmAAD(aad))
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "aws-nitro sealer: the secret does not authenticate under its data key", err)
	}
	return plain, nil
}

// attestRecipient is the NSM's document over a fresh nonce carrying pub,
// for KMS's Recipient: KMS encrypts its answer to pub.
func (p *AWSNitroProducer) attestRecipient(pub crypto.PublicKey) ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nsmHandle == nil {
		return nil, errors.New("aws-nitro: NSM handle not open (producer was closed)")
	}
	return nsmGetAttestationDoc(p.nsmHandle, nsmAttestationRequest{Nonce: nonce, PublicKey: pub})
}
