// SPDX-License-Identifier: AGPL-3.0-or-later

package teeconformance_test

// Self-test for the conformance suite.
//
// Implements a minimal reference Producer/Verifier/Sealer trio using
// stdlib Ed25519 + AES-GCM, then runs the public RunProducerVerifierContract
// and RunSealerContract against it. A passing build is the first-line
// evidence that the suite itself is correctly wired — third-party
// adapter authors can read this file as a 100-line worked example of
// what a conformant TEE adapter looks like in code.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/ai-continuity-platform/core/pkg/teeconformance"
)

// ---- reference adapter -----------------------------------------------------

type refProducer struct {
	measurement teeconformance.Measurement
	priv        ed25519.PrivateKey
}

type refVerifier struct {
	measurement teeconformance.Measurement
	pub         ed25519.PublicKey
}

type refSealer struct {
	key []byte // 32 bytes derived from the workload identity
}

const refMagic = "REF-CONFORMANCE-V1\x00"

func newRefBackend(t testing.TB, label string) (*refProducer, *refVerifier, *refSealer, func() *refSealer) {
	t.Helper()
	seed := sha256.Sum256([]byte("ref-seed-" + label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	measurement := sha256.Sum256([]byte("ref-workload-" + label))

	keyDigest := sha256.Sum256(append([]byte("ref-sealing-key-"), measurement[:]...))
	sealingKey := make([]byte, 32)
	copy(sealingKey, keyDigest[:])

	p := &refProducer{measurement: measurement, priv: priv}
	v := &refVerifier{measurement: measurement, pub: pub}
	s := &refSealer{key: sealingKey}
	rebuild := func() *refSealer { return &refSealer{key: append([]byte(nil), sealingKey...)} }
	return p, v, s, rebuild
}

// Quote produces evidence: refMagic || nonce-len(BE32) || nonce ||
// measurement || ed25519(measurement || nonce).
func (p *refProducer) Quote(nonce teeconformance.Nonce) (teeconformance.Evidence, error) {
	if len(nonce) < teeconformance.NonceMinBytes {
		return nil, errors.New("ref: nonce below floor")
	}
	signedBlob := append(append([]byte(nil), p.measurement[:]...), nonce...)
	sig := ed25519.Sign(p.priv, signedBlob)

	var buf bytes.Buffer
	buf.WriteString(refMagic)
	var nlen [4]byte
	binary.BigEndian.PutUint32(nlen[:], uint32(len(nonce)))
	buf.Write(nlen[:])
	buf.Write(nonce)
	buf.Write(p.measurement[:])
	buf.Write(sig)
	return buf.Bytes(), nil
}

func (p *refProducer) Measurement() teeconformance.Measurement {
	return p.measurement
}

func (v *refVerifier) Verify(ev teeconformance.Evidence, nonce teeconformance.Nonce) (teeconformance.Measurement, error) {
	var zero teeconformance.Measurement
	if len(nonce) < teeconformance.NonceMinBytes {
		return zero, errors.New("ref: nonce below floor")
	}
	if len(ev) < len(refMagic)+4 {
		return zero, errors.New("ref: evidence too short")
	}
	if string(ev[:len(refMagic)]) != refMagic {
		return zero, errors.New("ref: magic mismatch")
	}
	off := len(refMagic)
	nlen := binary.BigEndian.Uint32(ev[off : off+4])
	off += 4
	if uint32(len(ev)-off) < nlen+teeconformance.MeasurementSize+ed25519.SignatureSize {
		return zero, errors.New("ref: truncated")
	}
	gotNonce := ev[off : off+int(nlen)]
	off += int(nlen)
	mBytes := ev[off : off+teeconformance.MeasurementSize]
	off += teeconformance.MeasurementSize
	sig := ev[off : off+ed25519.SignatureSize]

	if !bytes.Equal(gotNonce, nonce) {
		return zero, errors.New("ref: nonce mismatch (replay?)")
	}
	signedBlob := append(append([]byte(nil), mBytes...), gotNonce...)
	if !ed25519.Verify(v.pub, signedBlob, sig) {
		return zero, errors.New("ref: signature invalid")
	}
	var m teeconformance.Measurement
	copy(m[:], mBytes)
	return m, nil
}

func (s *refSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)
	return append(nonce, ct...), nil
}

func (s *refSealer) Unseal(sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("ref: sealed truncated")
	}
	nonce := sealed[:aead.NonceSize()]
	ct := sealed[aead.NonceSize():]
	return aead.Open(nil, nonce, ct, aad)
}

// ---- conformance harness invocation ---------------------------------------

func TestConformance_ReferenceBackend_ProducerVerifier(t *testing.T) {
	t.Parallel()
	teeconformance.RunProducerVerifierContract(t, func(t teeconformance.Tester) (teeconformance.Producer, teeconformance.Verifier) {
		gt, ok := t.(*testing.T)
		if !ok {
			t.Fatal("expected *testing.T")
		}
		p, v, _, _ := newRefBackend(gt, "prod-verifier")
		return p, v
	})
}

func TestConformance_ReferenceBackend_Sealer(t *testing.T) {
	t.Parallel()
	teeconformance.RunSealerContract(t, func(t teeconformance.Tester) (teeconformance.Sealer, func(t teeconformance.Tester) teeconformance.Sealer) {
		gt, ok := t.(*testing.T)
		if !ok {
			t.Fatal("expected *testing.T")
		}
		_, _, s, rebuild := newRefBackend(gt, "sealer")
		rebuildAdapter := func(t teeconformance.Tester) teeconformance.Sealer {
			return rebuild()
		}
		return s, rebuildAdapter
	})
}

// TestConformance_DirectVerify confirms the reference adapter produces
// evidence the reference verifier accepts on the round-trip path
// outside of the conformance harness — a sanity check that the example
// is also a working example.
func TestConformance_DirectVerify(t *testing.T) {
	t.Parallel()
	p, v, _, _ := newRefBackend(t, "direct")
	nonce := bytes.Repeat([]byte{0x42}, teeconformance.NonceMinBytes)
	ev, err := p.Quote(nonce)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	got, err := v.Verify(ev, nonce)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != p.Measurement() {
		t.Errorf("measurement mismatch")
	}
}
