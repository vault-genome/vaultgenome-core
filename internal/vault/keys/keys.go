// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"crypto/rand"
	"io"
	"sync"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// Purpose enumerates the uses a key may be authorized for. A key MUST NOT
// be used outside its declared purpose — the Resolver enforces this.
type Purpose uint8

const (
	PurposeUnknown Purpose = 0

	// PurposeSigningAuthority — vault signing for authority
	// artifacts (SessionObject, AttestationResult, DisclosureMessage,
	// ReconstructionJobManifest, ReleaseDecision).
	PurposeSigningAuthority Purpose = 1

	// PurposeSigningAudit — vault signing for AuditEvent records.
	// Kept separate from authority signing so that a compromised authority
	// key does not automatically compromise audit-chain continuity.
	PurposeSigningAudit Purpose = 2

	// PurposeSealing — AES-256-GCM sealing of DisclosureMessage payloads
	// and of persisted vault material.
	PurposeSealing Purpose = 3

	// PurposeSigningWitness — signing for the transparency log's
	// SignedTreeHead. Kept separate from authority and audit so that a
	// compromised authority or audit key cannot forge an STH that covers
	// the same history with a different Merkle root. The doctrinal role
	// of the witness log is to be the one place an adversary cannot
	// silently rewrite even if they compromise the vault; giving it its
	// own key purpose is the minimal cryptographic expression of that.
	PurposeSigningWitness Purpose = 4
)

// String returns a stable, lowercase identifier for p.
func (p Purpose) String() string {
	switch p {
	case PurposeSigningAuthority:
		return "signing_authority"
	case PurposeSigningAudit:
		return "signing_audit"
	case PurposeSealing:
		return "sealing"
	case PurposeSigningWitness:
		return "signing_witness"
	default:
		return "unknown"
	}
}

// VerifyingKey is the public half of a signing key, together with its
// KeyID, Purpose and signature suite (ADR 0031). Safe to hand to any
// party that needs to verify vault signatures.
type VerifyingKey struct {
	KeyID   ids.KeyID
	Purpose Purpose
	// Suite is the signature suite the key signs under. A record signed
	// with this key carries crypto.RecordAlg(Suite) as its alg: absent
	// for ed25519, the suite id otherwise.
	Suite crypto.SignatureSuite
	// PublicKey is the suite's raw public-key encoding: 32 bytes for
	// ed25519, the 97-byte uncompressed point for ecdsa-p384-sha384,
	// 2592 bytes for ml-dsa-87.
	PublicKey []byte
	CreatedAt int64 // unix-nanos of creation; used for rotation ordering
}

// Verify checks sig over msg under the key's suite.
func (vk VerifyingKey) Verify(msg, sig []byte) error {
	if vk.Suite == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"keys: verifying key names no signature suite",
			nil,
		)
	}
	return crypto.VerifySuite(vk.Suite, vk.PublicKey, msg, sig)
}

// VerifyRecord checks the signature a record carries: the record's alg
// (absent means ed25519) must be the key's suite — a record does not
// choose an algorithm the key was not made for — and sig must verify
// over msg under it. A mismatch is an Integrity-classified error, as a
// bad signature is.
func (vk VerifyingKey) VerifyRecord(alg crypto.SignatureSuite, msg, sig []byte) error {
	return crypto.VerifyRecord(vk.Suite, vk.PublicKey, alg, msg, sig)
}

// Public returns the key's public half named with its suite — what a
// peer pins.
func (vk VerifyingKey) Public() crypto.SuitePublicKey {
	return crypto.SuitePublicKey{Suite: vk.Suite, Bytes: append([]byte(nil), vk.PublicKey...)}
}

// signingKey is the full key pair. It is never returned by the Resolver
// interface — only used internally by the Signer.
type signingKey struct {
	VerifyingKey
	Priv *crypto.SigningKey
}

// sealingKey is a 32-byte AES-256 key plus its ID/purpose metadata.
type sealingKey struct {
	KeyID     ids.KeyID
	Purpose   Purpose
	Material  []byte // 32 bytes
	CreatedAt int64
}

// Resolver is the read-side capability: given a KeyID, return the
// verifying key for signature checks. Implementations MUST refuse to
// return a key whose Purpose does not match the caller's declared intent.
type Resolver interface {
	// Resolve returns the verifying key for kid, provided its Purpose
	// matches want. An unknown kid or a purpose mismatch returns an
	// error classified as Authority (unknown kid) or Integrity (purpose
	// mismatch — a programming bug or attempted cross-purpose abuse).
	Resolve(kid ids.KeyID, want Purpose) (VerifyingKey, error)
}

// Signer is the write-side capability: sign cover-bytes under a specific
// KeyID. Implementations enforce purpose bindings identically to Resolver.
type Signer interface {
	// Sign returns the signature of msg under kid's key, in the key's
	// suite. Purpose must match the key's declared Purpose. Sealing keys
	// cannot be used here.
	Sign(kid ids.KeyID, purpose Purpose, msg []byte) ([]byte, error)

	// Suite reports the signature suite of kid's key: what Sign produces,
	// and what a record signed under kid carries as its alg (RecordAlg).
	// An unknown kid is an Authority-classified error.
	Suite(kid ids.KeyID) (crypto.SignatureSuite, error)
}

// RecordAlg is the alg a record signed by signer under kid carries:
// absent for ed25519, the suite id otherwise (ADR 0031). Every
// contract's SignWith sets it before taking the cover-bytes, so the
// suite is under the signature.
func RecordAlg(signer Signer, kid ids.KeyID) (crypto.SignatureSuite, error) {
	suite, err := signer.Suite(kid)
	if err != nil {
		return "", err
	}
	return crypto.RecordAlg(suite), nil
}

// Sealer is the symmetric-key capability. The vault uses this to wrap
// DisclosureMessage payloads and to encrypt persisted state.
type Sealer interface {
	Seal(kid ids.KeyID, plaintext, aad []byte) (nonce, ciphertext []byte, err error)
	Open(kid ids.KeyID, nonce, ciphertext, aad []byte) (plaintext []byte, err error)
}

// ---- in-memory keystore ----------------------------------------------------

// InMemoryStore is the MVP keystore. It holds keys in process memory with
// a mutex. Production would replace this with a store that sealed its
// state under the TEE's sealing key and loaded only measured material.
//
// Exported methods satisfy Resolver, Signer, and Sealer.
type InMemoryStore struct {
	mu      sync.RWMutex
	signing map[ids.KeyID]signingKey
	sealing map[ids.KeyID]sealingKey
	clock   shared_time.Clock
}

// NewInMemoryStore constructs an empty store. clock may be nil, in which
// case SystemClock is used.
func NewInMemoryStore(clock shared_time.Clock) *InMemoryStore {
	if clock == nil {
		clock = shared_time.SystemClock{}
	}
	return &InMemoryStore{
		signing: make(map[ids.KeyID]signingKey),
		sealing: make(map[ids.KeyID]sealingKey),
		clock:   clock,
	}
}

// GenerateSigning creates a fresh Ed25519 key pair and registers it under
// kid with the given purpose — the suite every deployment before ADR
// 0031 signs under. GenerateSigningSuite takes the suite.
func (s *InMemoryStore) GenerateSigning(kid ids.KeyID, purpose Purpose) (VerifyingKey, error) {
	return s.GenerateSigningSuite(kid, purpose, crypto.SuiteEd25519)
}

// GenerateSigningSuite creates a fresh key of suite and registers it under
// kid with the given purpose. purpose must be a signing purpose. A suite
// this build cannot sign under (ml-dsa-87 on the FIPS module v1.0.0) is
// refused with the module's reason. Returns the VerifyingKey so callers
// can hand it to out-of-band distribution.
func (s *InMemoryStore) GenerateSigningSuite(kid ids.KeyID, purpose Purpose, suite crypto.SignatureSuite) (VerifyingKey, error) {
	if err := suite.Available(); err != nil {
		return VerifyingKey{}, err
	}
	key, err := crypto.GenerateSigningKey(suite, nil)
	if err != nil {
		return VerifyingKey{}, err
	}
	return s.RegisterSigningKey(kid, purpose, key)
}

// RegisterSigningKey registers a caller-built signing key (from a seed, a
// PKCS#8 file or a derivation) under kid with the given purpose. The
// store takes ownership: Zeroize wipes it. Re-registering an existing
// kid is a structural error (no silent overwrite of operator intent).
func (s *InMemoryStore) RegisterSigningKey(kid ids.KeyID, purpose Purpose, key *crypto.SigningKey) (VerifyingKey, error) {
	if kid.IsZero() {
		return VerifyingKey{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"keys: KeyID required",
			nil,
		)
	}
	if purpose != PurposeSigningAuthority &&
		purpose != PurposeSigningAudit &&
		purpose != PurposeSigningWitness {
		return VerifyingKey{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"keys: purpose must be a signing purpose",
			nil,
		)
	}
	if key == nil || !key.Suite().Valid() {
		return VerifyingKey{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"keys: signing key required",
			nil,
		)
	}
	if err := key.Suite().Available(); err != nil {
		return VerifyingKey{}, err
	}
	pub := key.PublicKeyBytes()
	if len(pub) != key.Suite().PublicKeySize() {
		return VerifyingKey{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"keys: signing key has no public key",
			nil,
		)
	}
	vk := VerifyingKey{
		KeyID:     kid,
		Purpose:   purpose,
		Suite:     key.Suite(),
		PublicKey: pub,
		CreatedAt: s.clock.Now().UnixNano(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.signing[kid]; exists {
		return VerifyingKey{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"keys: kid already registered (signing)",
			nil,
		)
	}
	s.signing[kid] = signingKey{VerifyingKey: vk, Priv: key}
	return vk, nil
}

// RegisterSigningFromSeed registers a signing key pair derived
// deterministically from a 32-byte Ed25519 seed. This is the
// Phase-1 affordance that lets the acp-compute daemon load a stable
// signing identity from operator config so that the key the vault
// pinned out-of-band survives a worker restart. In Phase 3 this is
// replaced by TEE-attested key derivation.
//
// The purpose field must be one of the signing purposes — the same
// constraint as GenerateSigning. Re-registering an existing kid is
// a structural error (no silent overwrite of operator intent).
func (s *InMemoryStore) RegisterSigningFromSeed(kid ids.KeyID, purpose Purpose, seed []byte) (VerifyingKey, error) {
	if kid.IsZero() {
		return VerifyingKey{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"keys: KeyID required",
			nil,
		)
	}
	if purpose != PurposeSigningAuthority &&
		purpose != PurposeSigningAudit &&
		purpose != PurposeSigningWitness {
		return VerifyingKey{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"keys: purpose must be a signing purpose",
			nil,
		)
	}
	if len(seed) != crypto.Ed25519SeedSize {
		return VerifyingKey{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"keys: seed must be 32 bytes (Ed25519 seed size)",
			nil,
		)
	}
	key, err := crypto.SigningKeyFromSeed(crypto.SuiteEd25519, seed)
	if err != nil {
		return VerifyingKey{}, err
	}
	return s.RegisterSigningKey(kid, purpose, key)
}

// RegisterSealing installs a caller-supplied AES-256 key under kid.
// This is the Phase-1 affordance that lets the sagvd and acp-compute
// daemons pre-share a session-recipient sealing key via operator
// config. In Phase 3 both sides derive the same material from their
// TEEs' hardware sealing capability after a successful attestation
// exchange.
//
// The material must be exactly AES256KeySize (32) bytes; anything
// else is a Structural error. The stored slice is a defensive copy.
// Re-registering an existing kid is a Structural error — operators
// who need to rotate keys must Zeroize() first.
func (s *InMemoryStore) RegisterSealing(kid ids.KeyID, material []byte) error {
	if kid.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"keys: KeyID required",
			nil,
		)
	}
	if len(material) != crypto.AES256KeySize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"keys: sealing material must be AES256KeySize bytes",
			nil,
		)
	}
	mat := make([]byte, len(material))
	copy(mat, material)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sealing[kid]; exists {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"keys: kid already registered (sealing)",
			nil,
		)
	}
	s.sealing[kid] = sealingKey{
		KeyID:     kid,
		Purpose:   PurposeSealing,
		Material:  mat,
		CreatedAt: s.clock.Now().UnixNano(),
	}
	return nil
}

// GenerateSealing creates a fresh AES-256 key under kid.
func (s *InMemoryStore) GenerateSealing(kid ids.KeyID) error {
	if kid.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"keys: KeyID required",
			nil,
		)
	}
	mat := make([]byte, crypto.AES256KeySize)
	if _, err := io.ReadFull(rand.Reader, mat); err != nil {
		return shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"keys: sealing key RNG failed",
			err,
		)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sealing[kid]; exists {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"keys: kid already registered (sealing)",
			nil,
		)
	}
	s.sealing[kid] = sealingKey{
		KeyID:     kid,
		Purpose:   PurposeSealing,
		Material:  mat,
		CreatedAt: s.clock.Now().UnixNano(),
	}
	return nil
}

// Resolve implements Resolver.
func (s *InMemoryStore) Resolve(kid ids.KeyID, want Purpose) (VerifyingKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sk, ok := s.signing[kid]
	if !ok {
		return VerifyingKey{}, shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			"keys: unknown kid",
			nil,
		)
	}
	if sk.Purpose != want {
		return VerifyingKey{}, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"keys: purpose mismatch on resolve",
			nil,
		)
	}
	return sk.VerifyingKey, nil
}

// Sign implements Signer.
func (s *InMemoryStore) Sign(kid ids.KeyID, purpose Purpose, msg []byte) ([]byte, error) {
	s.mu.RLock()
	sk, ok := s.signing[kid]
	s.mu.RUnlock()
	if !ok {
		return nil, shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			"keys: unknown kid on sign",
			nil,
		)
	}
	if sk.Purpose != purpose {
		return nil, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"keys: purpose mismatch on sign",
			nil,
		)
	}
	return sk.Priv.Sign(msg)
}

// Suite implements Signer.
func (s *InMemoryStore) Suite(kid ids.KeyID) (crypto.SignatureSuite, error) {
	s.mu.RLock()
	sk, ok := s.signing[kid]
	s.mu.RUnlock()
	if !ok {
		return "", shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			"keys: unknown kid on suite",
			nil,
		)
	}
	return sk.Suite, nil
}

// Seal implements Sealer.
func (s *InMemoryStore) Seal(kid ids.KeyID, plaintext, aad []byte) ([]byte, []byte, error) {
	s.mu.RLock()
	k, ok := s.sealing[kid]
	s.mu.RUnlock()
	if !ok {
		return nil, nil, shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			"keys: unknown sealing kid",
			nil,
		)
	}
	return crypto.Seal(k.Material, plaintext, aad)
}

// Open implements Sealer.
func (s *InMemoryStore) Open(kid ids.KeyID, nonce, ciphertext, aad []byte) ([]byte, error) {
	s.mu.RLock()
	k, ok := s.sealing[kid]
	s.mu.RUnlock()
	if !ok {
		return nil, shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			"keys: unknown sealing kid",
			nil,
		)
	}
	return crypto.Open(k.Material, nonce, ciphertext, aad)
}

// EraseSealing wipes and forgets one sealing key. It reports whether the
// key was held. A destination erases a genome's key once the genome is
// restored, so the key does not outlive its use in memory.
func (s *InMemoryStore) EraseSealing(kid ids.KeyID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.sealing[kid]
	if !ok {
		return false
	}
	for i := range k.Material {
		k.Material[i] = 0
	}
	delete(s.sealing, kid)
	return true
}

// Zeroize wipes all key material. Called by incident termination per
// patent P1 §[0020]. Callers should expect the store to be unusable
// afterward.
func (s *InMemoryStore) Zeroize() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for kid, sk := range s.signing {
		sk.Priv.Zeroize()
		delete(s.signing, kid)
	}
	for kid, k := range s.sealing {
		for i := range k.Material {
			k.Material[i] = 0
		}
		delete(s.sealing, kid)
	}
}

// Compile-time interface assertions.
var (
	_ Resolver = (*InMemoryStore)(nil)
	_ Signer   = (*InMemoryStore)(nil)
	_ Sealer   = (*InMemoryStore)(nil)
)
