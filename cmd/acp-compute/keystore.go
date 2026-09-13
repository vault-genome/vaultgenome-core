// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
)

// materials bundles every piece of key/identity material the daemon
// loads from disk at startup. It is the single construction point for
// the worker's cryptographic surface — main() passes this bundle into
// Daemon, Daemon hands the relevant pieces into returnpath/client at
// session time, and nothing in the hot path ever touches the filesystem.
//
// Lifecycle: produced by LoadMaterials; owned by Daemon until shutdown;
// Zeroize() is called on shutdown to wipe the in-memory keystore.
type materials struct {
	// Store is the InMemoryStore that holds the worker's signing private
	// half and the session-sealing key. It is handed to client.SessionConfig
	// as both Signer and (wrapped as KeyStoreOpener) Opener.
	Store *keys.InMemoryStore

	// SigningKeyID is the kid under which the worker's signing key is
	// registered. The vault side's PublicKeyResolver MUST have the
	// matching VerifyingKey (same kid, same 32-byte pubkey) registered
	// for CandidateOutputFrame signatures to verify.
	SigningKeyID ids.KeyID

	// SigningPublicKey is the 32-byte Ed25519 public key corresponding
	// to SigningKeyID. Exposed only so the daemon can log it once at
	// startup (operators copy it into sagvd config).
	SigningPublicKey crypto.PublicKey

	// SealingKeyID is the kid under which the session-sealing material
	// is registered. JobRequest.SealedMaterialRef.RecipientKeyID on the
	// wire MUST match this string form.
	SealingKeyID ids.KeyID

	// Producer is the worker's simulated TEE (Phase 1). In Phase 3 this
	// is replaced by a hardware-backed tee.Producer; the daemon wiring
	// does not change.
	Producer tee.Producer

	// Verifier verifies sagvd's TEE evidence during the 4-frame
	// handshake. Pinned to the peer's measurement and public key loaded
	// from disk.
	Verifier tee.Verifier
}

// LoadMaterials reads all key material referenced by cfg from disk,
// registers the signing and sealing keys in a fresh InMemoryStore, and
// constructs the local simulated TEE plus the peer verifier.
//
// File formats (all raw binary, no encoding):
//   - TEE seed file:            32 bytes (Ed25519 seed for TEE attestation)
//   - Worker signing seed file: 32 bytes (Ed25519 seed for CandidateOutputFrame signing)
//   - Session sealing key file: 32 bytes (AES-256 key, pre-shared with sagvd)
//   - Peer TEE pubkey file:     32 bytes (Ed25519 public key for sagvd's attestor)
//   - Peer TEE measurement:     32 bytes (SHA-256 measurement sagvd will attest)
//
// Every file is read with strict length checking; anything else is a
// Structural configuration error. Modes are not inspected here — operator
// hygiene is a deployment concern, not a runtime one.
func LoadMaterials(cfg Config, clock shared_time.Clock) (*materials, error) {
	// 1. Local TEE seed → Simulated producer.
	teeSeed, err := readExactly(cfg.TEE.SeedPath, crypto.Ed25519SeedSize, "tee.seed_path")
	if err != nil {
		return nil, err
	}
	producer, err := tee.NewSimulated([]byte(cfg.TEE.WorkloadDescriptor), teeSeed)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: construct simulated TEE: %w", err)
	}

	// 2. Peer TEE pubkey + measurement → SimulatedVerifier pinned to them.
	peerPub, err := readExactly(cfg.TEE.Peer.PublicKeyPath, crypto.Ed25519PublicKeySize, "tee.peer.public_key_path")
	if err != nil {
		return nil, err
	}
	peerMeas, err := readExactly(cfg.TEE.Peer.MeasurementPath, crypto.HashSize, "tee.peer.measurement_path")
	if err != nil {
		return nil, err
	}
	peerMeasurement, err := tee.MeasurementFromBytes(peerMeas)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: peer measurement: %w", err)
	}
	verifier := tee.NewSimulatedVerifier(crypto.PublicKey(peerPub), peerMeasurement)

	// 3. Worker signing seed → register under cfg.Keys.WorkerSigning.KeyID.
	signingSeed, err := readExactly(cfg.Keys.WorkerSigning.SeedPath, crypto.Ed25519SeedSize, "keys.worker_signing.seed_path")
	if err != nil {
		return nil, err
	}
	store := keys.NewInMemoryStore(clock)
	signingKID := ids.KeyID(cfg.Keys.WorkerSigning.KeyID)
	vk, err := store.RegisterSigningFromSeed(signingKID, keys.PurposeSigningAuthority, signingSeed)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: register worker signing key: %w", err)
	}

	// 4. Session sealing key → register under cfg.Keys.SessionSealing.KeyID.
	sealingMat, err := readExactly(cfg.Keys.SessionSealing.MaterialPath, crypto.AES256KeySize, "keys.session_sealing.material_path")
	if err != nil {
		return nil, err
	}
	sealingKID := ids.KeyID(cfg.Keys.SessionSealing.KeyID)
	if err := store.RegisterSealing(sealingKID, sealingMat); err != nil {
		return nil, fmt.Errorf("acp-compute: register session sealing key: %w", err)
	}
	// Sealing material has been defensively copied inside the store;
	// wipe our in-process copy so a post-mortem core dump does not leak
	// it through this code path.
	for i := range sealingMat {
		sealingMat[i] = 0
	}

	return &materials{
		Store:            store,
		SigningKeyID:     signingKID,
		SigningPublicKey: vk.PublicKey,
		SealingKeyID:     sealingKID,
		Producer:         producer,
		Verifier:         verifier,
	}, nil
}

// readExactly reads path and returns its contents if and only if the
// file is exactly wantLen bytes. Any other length is a Structural error
// wrapped with the logical config field name for operator diagnosis.
// Errors are plain errors (not shared_errors.*) because this is main-
// package provisioning, not contract-surface logic.
func readExactly(path string, wantLen int, fieldName string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: read %s (%q): %w", fieldName, path, err)
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf(
			"acp-compute: %s (%q) must be exactly %d bytes (got %d)",
			fieldName, path, wantLen, len(b))
	}
	return b, nil
}
