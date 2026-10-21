// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

// The KEM suites of ADR 0029. Every encapsulation the product writes is
// RFC 9180 HPKE in base mode — a KEM, a KDF and an AEAD, named together
// by a suite id — through crypto/hpke of the standard library. The suite
// is what the two sides of a handshake settle on under a profile
// (profile.go), what the handshake answer names, what the token carries
// beside each wrapped key, and what the audit chain records as the
// delivery mode.
//
// The ECIES of ADR 0009 (x25519-kem-v1: an ephemeral X25519 key,
// HKDF-SHA256, AES-256-GCM; kem.go) is not a suite here. Nothing writes
// it any more; the escrow package still reads what earlier releases
// wrote under it.
//
// Wire layout of a wrapped value: enc (Nenc bytes, the KEM's
// encapsulated key) ‖ the AEAD ciphertext with its tag. HPKE derives the
// AEAD nonce from the key schedule, so none travels.

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"slices"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Suite names an HPKE ciphersuite the product may encapsulate under.
type Suite string

const (
	// SuiteHPKEX25519 is DHKEM(X25519, HKDF-SHA256) 0x0020 with
	// HKDF-SHA256 0x0001 and AES-256-GCM 0x0002 (RFC 9180 §7): what the
	// general profile writes.
	SuiteHPKEX25519 Suite = "hpke-x25519-v2"
	// SuiteHPKEP384 is DHKEM(P-384, HKDF-SHA384) 0x0011 with HKDF-SHA384
	// 0x0002 and AES-256-GCM — approved key establishment (SP 800-56A
	// Rev. 3; CMVP #5247 lists KAS-ECC on P-384 and the HKDF of SP
	// 800-56C Rev. 2): what the fips profile writes.
	SuiteHPKEP384 Suite = "hpke-p384-v2"
	// SuiteHPKEMLKEM768 is ML-KEM-768 0x0041 (FIPS 203, through
	// draft-ietf-hpke-pq) with HKDF-SHA256 and AES-256-GCM.
	SuiteHPKEMLKEM768 Suite = "hpke-mlkem768-v2"
	// SuiteHPKEMLKEM1024P384 is MLKEM1024-P384 0x0051, the PQ/T hybrid of
	// draft-ietf-hpke-pq (a composite KEM in the sense of SP 800-227
	// §4.6), with HKDF-SHA384 and AES-256-GCM: what the cnsa profile
	// writes.
	SuiteHPKEMLKEM1024P384 Suite = "hpke-mlkem1024-p384-v2"
	// SuiteHPKEXWing is MLKEM768-X25519 0x647a (X-Wing) with HKDF-SHA256
	// and AES-256-GCM.
	SuiteHPKEXWing Suite = "hpke-xwing-v2"

	// The v1 suites of 0.7.0 (ADR 0029): the same KEMs and KDFs, with
	// the AEAD inside HPKE — AES-256-GCM under a nonce HPKE derives
	// outside the cryptographic module, which the module's approved mode
	// does not allow and fips140=only refuses (ADR 0030). Read-only since
	// 0.8: what 0.7.0 wrapped still opens on a build without
	// enforcement; nothing writes them.
	SuiteHPKEX25519V1        Suite = "hpke-x25519-v1"
	SuiteHPKEP384V1          Suite = "hpke-p384-v1"
	SuiteHPKEMLKEM768V1      Suite = "hpke-mlkem768-v1"
	SuiteHPKEMLKEM1024P384V1 Suite = "hpke-mlkem1024-p384-v1"
	SuiteHPKEXWingV1         Suite = "hpke-xwing-v1"

	// SuiteLegacyX25519 names the ECIES of ADR 0009 where a record of an
	// earlier release has to be read (the escrow documents of 0.1.0 to
	// 0.6.1). It is not an HPKE suite: Known reports false for it, and
	// nothing encapsulates under it.
	SuiteLegacyX25519 Suite = "x25519-kem-v1"
)

// Purposes separate the HPKE info of one use of a suite from another's:
// a value wrapped for one purpose never opens under another.
const (
	// PurposeCrossCloudDEK is a DEK encapsulated to a destination's
	// handshake key, carried by a KeyReleaseToken.
	PurposeCrossCloudDEK = "xcc-dek"
	// PurposeEscrowDEK is a genome's DEK encapsulated to an escrow key.
	PurposeEscrowDEK = "escrow-dek"
	// PurposeEscrowRecovery is an escrow private key encapsulated to a
	// recovery key.
	PurposeEscrowRecovery = "escrow-recovery"
)

// hpkeInfoLabel leads the HPKE info of every suite; with the suite id and
// the purpose behind it, each length-prefixed.
const hpkeInfoLabel = "vault-genome hpke v1"

// hpkeExportContext is the exporter context of a v2 suite: the HPKE
// context, opened export-only (RFC 9180 §5.3, AEAD id 0xFFFF), derives the
// 32-byte key the cryptographic module's AES-256-GCM seals under, with
// the nonce the module generates (ADR 0030).
const hpkeExportContext = "vault-genome hpke v2 wrap key"

// aeadIDExportOnly is RFC 9180's AEAD id for export-only contexts.
const aeadIDExportOnly = 0xFFFF

// kemBindLabelV2 is the key-binding challenge's label of ADR 0029: the
// challenge commits to the suite as well as to the key and the nonce.
const kemBindLabelV2 = "vault-genome xcc-kem-bind v2"

// aeadTagSize is the AES-256-GCM tag every suite's AEAD appends.
const aeadTagSize = 16

type suiteSpec struct {
	kem    func() hpke.KEM
	kdf    func() hpke.KDF
	aead   func() hpke.AEAD
	kemID  uint16
	kdfID  uint16
	aeadID uint16
	// pkLen and encLen are Npk and Nenc of the KEM — RFC 9180 §7.1 for
	// the DHKEMs, draft-ietf-hpke-pq-05 §8 for ML-KEM and the hybrids.
	// The wire carries no other length, so the table is the parser.
	pkLen  int
	encLen int
	// x25519 marks a KEM whose public key is a bare X25519 point, which
	// must not be a low-order one (every encapsulation to it would share
	// an all-zero secret).
	x25519 bool
	// export marks a v2 suite: HPKE export-only, the AEAD the module's.
	export bool
	// family names the KEM and KDF shared by a v1 and its v2.
	family string
	// readOnly marks a v1 suite: opened, never written.
	readOnly bool
}

var suiteSpecs = map[Suite]suiteSpec{
	SuiteHPKEX25519: {
		kem: func() hpke.KEM { return hpke.DHKEM(ecdh.X25519()) }, kdf: hpke.HKDFSHA256,
		kemID: 0x0020, kdfID: 0x0001, aeadID: aeadIDExportOnly, pkLen: 32, encLen: 32, x25519: true, export: true, family: "hpke-x25519",
	},
	SuiteHPKEP384: {
		kem: func() hpke.KEM { return hpke.DHKEM(ecdh.P384()) }, kdf: hpke.HKDFSHA384,
		kemID: 0x0011, kdfID: 0x0002, aeadID: aeadIDExportOnly, pkLen: 97, encLen: 97, export: true, family: "hpke-p384",
	},
	SuiteHPKEMLKEM768: {
		kem: hpke.MLKEM768, kdf: hpke.HKDFSHA256,
		kemID: 0x0041, kdfID: 0x0001, aeadID: aeadIDExportOnly, pkLen: 1184, encLen: 1088, export: true, family: "hpke-mlkem768",
	},
	SuiteHPKEMLKEM1024P384: {
		kem: hpke.MLKEM1024P384, kdf: hpke.HKDFSHA384,
		kemID: 0x0051, kdfID: 0x0002, aeadID: aeadIDExportOnly, pkLen: 1665, encLen: 1665, export: true, family: "hpke-mlkem1024-p384",
	},
	SuiteHPKEXWing: {
		kem: hpke.MLKEM768X25519, kdf: hpke.HKDFSHA256,
		kemID: 0x647a, kdfID: 0x0001, aeadID: aeadIDExportOnly, pkLen: 1216, encLen: 1120, export: true, family: "hpke-xwing",
	},
	// v1: the AEAD inside HPKE (read-only)
	SuiteHPKEX25519V1: {
		kem: func() hpke.KEM { return hpke.DHKEM(ecdh.X25519()) }, kdf: hpke.HKDFSHA256, aead: hpke.AES256GCM,
		kemID: 0x0020, kdfID: 0x0001, aeadID: 0x0002, pkLen: 32, encLen: 32, x25519: true, family: "hpke-x25519", readOnly: true,
	},
	SuiteHPKEP384V1: {
		kem: func() hpke.KEM { return hpke.DHKEM(ecdh.P384()) }, kdf: hpke.HKDFSHA384, aead: hpke.AES256GCM,
		kemID: 0x0011, kdfID: 0x0002, aeadID: 0x0002, pkLen: 97, encLen: 97, family: "hpke-p384", readOnly: true,
	},
	SuiteHPKEMLKEM768V1: {
		kem: hpke.MLKEM768, kdf: hpke.HKDFSHA256, aead: hpke.AES256GCM,
		kemID: 0x0041, kdfID: 0x0001, aeadID: 0x0002, pkLen: 1184, encLen: 1088, family: "hpke-mlkem768", readOnly: true,
	},
	SuiteHPKEMLKEM1024P384V1: {
		kem: hpke.MLKEM1024P384, kdf: hpke.HKDFSHA384, aead: hpke.AES256GCM,
		kemID: 0x0051, kdfID: 0x0002, aeadID: 0x0002, pkLen: 1665, encLen: 1665, family: "hpke-mlkem1024-p384", readOnly: true,
	},
	SuiteHPKEXWingV1: {
		kem: hpke.MLKEM768X25519, kdf: hpke.HKDFSHA256, aead: hpke.AES256GCM,
		kemID: 0x647a, kdfID: 0x0001, aeadID: 0x0002, pkLen: 1216, encLen: 1120, family: "hpke-xwing", readOnly: true,
	},
}

// allSuites is every suite this build opens, the current ones first.
var allSuites = []Suite{SuiteHPKEX25519, SuiteHPKEP384, SuiteHPKEMLKEM768, SuiteHPKEMLKEM1024P384, SuiteHPKEXWing,
	SuiteHPKEX25519V1, SuiteHPKEP384V1, SuiteHPKEMLKEM768V1, SuiteHPKEMLKEM1024P384V1, SuiteHPKEXWingV1}

// currentSuites is every suite this build writes.
var currentSuites = []Suite{SuiteHPKEX25519, SuiteHPKEP384, SuiteHPKEMLKEM768, SuiteHPKEMLKEM1024P384, SuiteHPKEXWing}

// AllSuites returns every HPKE suite of this build, in a fixed order.
func AllSuites() []Suite { return append([]Suite(nil), allSuites...) }

// CurrentSuites returns the suites this build writes (the v2 suites of
// ADR 0030), in the general profile's order.
func CurrentSuites() []Suite { return append([]Suite(nil), currentSuites...) }

// Family names the KEM and KDF a suite is built on, shared by a v1 and
// its v2 ("hpke-p384"); a recipient key belongs to a family, not to a
// version.
func (s Suite) Family() string { return suiteSpecs[s].family }

// Available reports whether this process can make keys and wrap under s:
// false for the X25519 and X-Wing families under fips140=only, where the
// module refuses X25519 (ADR 0030); a read-only v1 suite is never
// available for writing.
func (s Suite) Available() bool {
	sp, ok := suiteSpecs[s]
	if !ok || sp.readOnly {
		return false
	}
	if sp.x25519 || s == SuiteHPKEXWing {
		return !shared_crypto.FIPSOnly()
	}
	return true
}

// ReadOnly reports whether s is a v1 suite: opened, never written.
func (s Suite) ReadOnly() bool { return suiteSpecs[s].readOnly }

// Latest returns the suite this build writes for s's family — s itself
// for a v2 suite, its v2 for a v1 one; an unknown suite is returned as
// it is.
func (s Suite) Latest() Suite {
	sp, ok := suiteSpecs[s]
	if !ok || !sp.readOnly {
		return s
	}
	for _, c := range currentSuites {
		if suiteSpecs[c].family == sp.family {
			return c
		}
	}
	return s
}

// SameFamily reports whether two suites share their KEM and KDF — the
// test a document's suite passes against a key's.
func (s Suite) SameFamily(o Suite) bool {
	return s.Known() && o.Known() && suiteSpecs[s].family == suiteSpecs[o].family
}

// Known reports whether s is an HPKE suite this build encapsulates under.
func (s Suite) Known() bool { _, ok := suiteSpecs[s]; return ok }

// ParseSuite accepts a suite id from a configuration, a wire field or a
// record.
func ParseSuite(id string) (Suite, error) {
	s := Suite(id)
	if !s.Known() {
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms: unknown KEM suite %q (this build knows %v)", id, allSuites), nil)
	}
	return s, nil
}

func (s Suite) spec() (suiteSpec, error) {
	sp, ok := suiteSpecs[s]
	if !ok {
		return suiteSpec{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms: unknown KEM suite %q", string(s)), nil)
	}
	return sp, nil
}

// IDs returns the suite's HPKE identifiers: KEM, KDF, AEAD. Zero for an
// unknown suite.
func (s Suite) IDs() (kem, kdf, aead uint16) {
	sp, ok := suiteSpecs[s]
	if !ok {
		return 0, 0, 0
	}
	return sp.kemID, sp.kdfID, sp.aeadID
}

// PublicKeySize is Npk of the suite's KEM; zero for an unknown suite.
func (s Suite) PublicKeySize() int { return suiteSpecs[s].pkLen }

// EncapsulationSize is Nenc of the suite's KEM; zero for an unknown suite.
func (s Suite) EncapsulationSize() int { return suiteSpecs[s].encLen }

// GenerateRecipientKey makes a fresh key pair under s — a destination's
// key for one handshake, or an escrow key. The private key is the KEM's
// SerializePrivateKey output, the public its SerializePublicKey (RFC
// 9180 §7.1.2); NewPublicKey and Unwrap read them back.
func (s Suite) GenerateRecipientKey() (priv, pub []byte, err error) {
	sp, err := s.spec()
	if err != nil {
		return nil, nil, err
	}
	k, err := sp.kem().GenerateKey()
	if err != nil {
		return nil, nil, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("kms: %s recipient key generation failed", s), err)
	}
	priv, err = k.Bytes()
	if err != nil {
		return nil, nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms: %s recipient private key serialization failed", s), err)
	}
	return priv, k.PublicKey().Bytes(), nil
}

// ValidateRecipientPublicKey accepts pub only if it is a key of s: Npk
// bytes long, deserializable under the KEM (on the curve; a well-formed
// ML-KEM encapsulation key), and — for a bare X25519 key — not a
// low-order point.
func (s Suite) ValidateRecipientPublicKey(pub []byte) error {
	sp, err := s.spec()
	if err != nil {
		return err
	}
	if len(pub) != sp.pkLen {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms: a %s recipient public key is %d bytes; got %d", s, sp.pkLen, len(pub)), nil)
	}
	if _, err := sp.kem().NewPublicKey(pub); err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms: invalid %s recipient public key", s), err)
	}
	if sp.x25519 {
		return ValidateRecipientPublicKey(pub)
	}
	return nil
}

// Wrap encapsulates plaintext to recipientPub under s for purpose; aad is
// bound into the AEAD tag. The result is enc ‖ ciphertext.
func (s Suite) Wrap(purpose string, plaintext, recipientPub, aad []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.Wrap: plaintext required", nil)
	}
	if purpose == "" {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.Wrap: purpose required", nil)
	}
	sp, err := s.spec()
	if err != nil {
		return nil, err
	}
	if err := s.ValidateRecipientPublicKey(recipientPub); err != nil {
		return nil, err
	}
	pk, err := sp.kem().NewPublicKey(recipientPub)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.Wrap: invalid %s recipient public key", s), err)
	}
	if sp.readOnly {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.Wrap: %s is read-only since 0.8 (ADR 0030): its AEAD takes a nonce from outside the cryptographic module; write %s", s, s.Latest()), nil)
	}
	// Export-only HPKE: the KEM and the KDF of the suite derive the key;
	// the cryptographic module's AES-256-GCM seals under it with the nonce
	// it generates, stored in front of the ciphertext (ADR 0030).
	enc, sender, err := hpke.NewSender(pk, sp.kdf(), hpke.ExportOnly(), suiteInfo(s, purpose))
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.Wrap: %s encapsulation failed", s), err)
	}
	if len(enc) != sp.encLen {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.Wrap: %s encapsulated %d bytes, not the %d the suite table says", s, len(enc), sp.encLen), nil)
	}
	key, err := sender.Export(hpkeExportContext+":"+purpose, shared_crypto.AES256KeySize)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.Wrap: %s key export failed", s), err)
	}
	nonce, ct, err := shared_crypto.Seal(key, plaintext, aad)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.Wrap: %s seal failed", s), err)
	}
	// enc ‖ nonce ‖ ciphertext ‖ tag; slices.Concat sizes the join itself.
	return slices.Concat(enc, nonce, ct), nil
}

// Unwrap recovers the plaintext of a Wrap under s for purpose with the
// recipient's private key (the KEM's SerializePrivateKey form).
func (s Suite) Unwrap(purpose string, wrapped, recipientPriv, aad []byte) ([]byte, error) {
	if purpose == "" {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.Unwrap: purpose required", nil)
	}
	sp, err := s.spec()
	if err != nil {
		return nil, err
	}
	minLen := sp.encLen + aeadTagSize
	if sp.export {
		minLen += shared_crypto.GCMNonceSize
	}
	if len(wrapped) < minLen {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("kms.Unwrap: wrapped material too short for %s (%d bytes; the encapsulation alone is %d)", s, len(wrapped), sp.encLen), nil)
	}
	if sp.readOnly && shared_crypto.FIPSOnly() {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.Unwrap: %s cannot open under fips140=only (its AEAD takes a nonce from outside the cryptographic module); open it on a build without enforcement and re-wrap under %s", s, s.Latest()), nil)
	}
	k, err := sp.kem().NewPrivateKey(recipientPriv)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.Unwrap: invalid %s recipient private key", s), err)
	}
	if !sp.export {
		// v1: the AEAD inside HPKE, as 0.7.0 wrote it
		rcpt, err := hpke.NewRecipient(wrapped[:sp.encLen], k, sp.kdf(), sp.aead(), suiteInfo(s, purpose))
		if err != nil {
			return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
				fmt.Sprintf("kms.Unwrap: %s decapsulation failed", s), err)
		}
		plain, err := rcpt.Open(aad, wrapped[sp.encLen:])
		if err != nil {
			return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
				"kms.Unwrap: tag verification failed (wrong key, suite, purpose or AAD, or tampering)", err)
		}
		return plain, nil
	}
	rcpt, err := hpke.NewRecipient(wrapped[:sp.encLen], k, sp.kdf(), hpke.ExportOnly(), suiteInfo(s, purpose))
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("kms.Unwrap: %s decapsulation failed", s), err)
	}
	key, err := rcpt.Export(hpkeExportContext+":"+purpose, shared_crypto.AES256KeySize)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.Unwrap: %s key export failed", s), err)
	}
	nonce := wrapped[sp.encLen : sp.encLen+shared_crypto.GCMNonceSize]
	plain, err := shared_crypto.Open(key, nonce, wrapped[sp.encLen+shared_crypto.GCMNonceSize:], aad)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
			"kms.Unwrap: tag verification failed (wrong key, suite, purpose or AAD, or tampering)", err)
	}
	return plain, nil
}

// suiteInfo is the HPKE info of a suite and a purpose: the product's
// label, the suite id and the purpose, each behind a 32-bit length, so
// no choice of one can be read as another.
func suiteInfo(s Suite, purpose string) []byte {
	parts := [][]byte{[]byte(hpkeInfoLabel), []byte(s), []byte(purpose)}
	n := 0
	for _, p := range parts {
		n += 4 + len(p)
	}
	out := make([]byte, 0, n)
	var l [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		out = append(out, l[:]...)
		out = append(out, p...)
	}
	return out
}

// RecipientChallengeV2 is the attestation challenge a destination quotes
// over when it answers a handshake carrying nonce with a key under suite
// (ADR 0029):
//
//	SHA-512(label ‖ len32(suite) ‖ suite ‖ len32(pk) ‖ pk ‖ len32(nonce) ‖ nonce)
//
// Like RecipientChallenge of ADR 0009 it turns every verifier's freshness
// check into the key binding; it also commits to the suite, so a suite
// label swapped in transit changes the challenge and genuine Evidence no
// longer verifies. The label differs from the v1 label, so a quote under
// one never satisfies the other.
func RecipientChallengeV2(suite Suite, recipientPub, nonce []byte) []byte {
	h := sha512.New()
	h.Write([]byte(kemBindLabelV2))
	var n [4]byte
	for _, part := range [][]byte{[]byte(suite), recipientPub, nonce} {
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		h.Write(n[:])
		h.Write(part)
	}
	return h.Sum(nil)
}

// PublicKeyOf derives the public key of a private key in the KEM's
// SerializePrivateKey form, as GenerateRecipientKey returns it; what an
// escrow key file or a sealed key holds is enough to name its public
// half without a second file.
func (s Suite) PublicKeyOf(priv []byte) ([]byte, error) {
	sp, err := s.spec()
	if err != nil {
		return nil, err
	}
	k, err := sp.kem().NewPrivateKey(priv)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms: invalid %s private key", s), err)
	}
	return k.PublicKey().Bytes(), nil
}
