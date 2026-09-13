// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/ai-continuity-platform/core/internal/compute/returnpath/server"
	"github.com/ai-continuity-platform/core/internal/observability/teemetrics"
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
)

// materials bundles every piece of key / identity material the sagvd
// daemon loads from disk at startup. It is the single construction
// point for the vault's cryptographic surface — main() passes this
// bundle into Daemon, Daemon hands the relevant pieces into
// returnpath/server at session time, and nothing in the hot path ever
// touches the filesystem.
//
// Lifecycle: produced by LoadMaterials; owned by Daemon until
// shutdown; Zeroize() is called on shutdown to wipe the in-memory
// keystore.
type materials struct {
	// Store is the InMemoryStore that holds the vault's authority-
	// signing private half and the session-sealing key. It is used
	// as Signer (for authority artifacts, Phase 3 forward) and as
	// Sealer (for SealedMaterialRef production on every JobRequest).
	Store *keys.InMemoryStore

	// AuthoritySigningKeyID is the kid under which the vault's
	// authority-signing key is registered.
	AuthoritySigningKeyID ids.KeyID

	// AuthoritySigningPublicKey is the 32-byte Ed25519 public key
	// corresponding to AuthoritySigningKeyID. Exposed only so the
	// daemon can log it once at startup.
	AuthoritySigningPublicKey crypto.PublicKey

	// SessionSealingKeyID is the kid under which the session-sealing
	// material is registered. JobRequest.SealedMaterialRef.RecipientKeyID
	// on the wire equals this string form.
	SessionSealingKeyID ids.KeyID

	// Producer is the vault's simulated TEE (Phase 1). In Phase 3
	// this is replaced by a hardware-backed tee.Producer; the daemon
	// wiring does not change.
	Producer tee.Producer

	// Verifier verifies the worker's TEE evidence during the 4-frame
	// handshake. Pinned to the peer's measurement and public key
	// loaded from disk.
	Verifier tee.Verifier

	// WorkerResolver is the read-only keys.Resolver that produces a
	// VerifyingKey for each CandidateOutputFrame.WorkerSigningKeyID
	// the server receives. Loaded from the workers.registry_path
	// JSON file.
	WorkerResolver *server.PublicKeyResolver

	// WorkerEntries is the parsed registry file (kid + note),
	// exposed only so the daemon can log accepted workers once at
	// startup.
	WorkerEntries []WorkerEntry
}

// LoadMaterials reads all key material referenced by cfg from disk,
// registers the authority-signing and session-sealing keys in a fresh
// InMemoryStore, constructs the local simulated TEE plus the peer
// verifier, and builds a PublicKeyResolver over the worker registry.
//
// File formats (all raw binary, no encoding — matches the shapes
// acp-compute uses):
//
//   - TEE seed file:              32 bytes (Ed25519 seed)
//   - Authority signing seed:     32 bytes (Ed25519 seed)
//   - Session sealing key file:   32 bytes (AES-256 key, pre-shared with worker)
//   - Peer (worker) TEE pubkey:   32 bytes (Ed25519 public key)
//   - Peer (worker) TEE measure:  32 bytes (SHA-256 measurement)
//
// Worker registry file is JSON — see workers.go.
//
// Every binary file is read with strict length checking; anything
// else is a Structural configuration error. File modes are not
// inspected here — operator hygiene is a deployment concern, not a
// runtime one.
func LoadMaterials(cfg Config, clock shared_time.Clock) (*materials, error) {
	// 1. Local TEE seed → Simulated producer.
	teeSeed, err := readExactly(cfg.TEE.SeedPath, crypto.Ed25519SeedSize, "tee.seed_path")
	if err != nil {
		return nil, err
	}
	producer, err := tee.NewSimulated([]byte(cfg.TEE.WorkloadDescriptor), teeSeed)
	if err != nil {
		return nil, fmt.Errorf("sagvd: construct simulated TEE: %w", err)
	}

	// 2. Peer TEE pubkey + measurement → SimulatedVerifier pinned to
	//    them. In Phase 1 we pin exactly one expected worker TEE;
	//    Phase 2 generalises to a policy-driven verifier.
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
		return nil, fmt.Errorf("sagvd: peer measurement: %w", err)
	}
	verifier := tee.NewSimulatedVerifier(crypto.PublicKey(peerPub), peerMeasurement)

	// 3. Authority signing seed → register under cfg.Keys.AuthoritySigning.KeyID.
	authSeed, err := readExactly(cfg.Keys.AuthoritySigning.SeedPath, crypto.Ed25519SeedSize, "keys.authority_signing.seed_path")
	if err != nil {
		return nil, err
	}
	store := keys.NewInMemoryStore(clock)
	authKID := ids.KeyID(cfg.Keys.AuthoritySigning.KeyID)
	vk, err := store.RegisterSigningFromSeed(authKID, keys.PurposeSigningAuthority, authSeed)
	if err != nil {
		return nil, fmt.Errorf("sagvd: register authority signing key: %w", err)
	}

	// 4. Session sealing key → register under cfg.Keys.SessionSealing.KeyID.
	sealingMat, err := readExactly(cfg.Keys.SessionSealing.MaterialPath, crypto.AES256KeySize, "keys.session_sealing.material_path")
	if err != nil {
		return nil, err
	}
	sealingKID := ids.KeyID(cfg.Keys.SessionSealing.KeyID)
	if err := store.RegisterSealing(sealingKID, sealingMat); err != nil {
		return nil, fmt.Errorf("sagvd: register session sealing key: %w", err)
	}
	// Sealing material has been defensively copied inside the store;
	// wipe our in-process copy so a post-mortem core dump does not
	// leak it through this code path.
	for i := range sealingMat {
		sealingMat[i] = 0
	}

	// 5. Worker registry → PublicKeyResolver for CandidateOutputFrame
	//    signature verification.
	resolver, entries, err := LoadWorkerRegistry(cfg.Workers.RegistryPath)
	if err != nil {
		return nil, err
	}

	return &materials{
		Store:                     store,
		AuthoritySigningKeyID:     authKID,
		AuthoritySigningPublicKey: vk.PublicKey,
		SessionSealingKeyID:       sealingKID,
		Producer:                  producer,
		Verifier:                  verifier,
		WorkerResolver:            resolver,
		WorkerEntries:             entries,
	}, nil
}

// InstrumentTEE wraps the materials' Producer and Verifier with the
// teemetrics.Recorder so every Quote / Verify call records the
// vg_tee_attestation_* counters and histograms. Call this once during
// daemon startup after the metrics registry has been created and
// before the daemon takes ownership of the materials.
//
// The provider label is "simulated" in Phase 1; when the daemon's
// keystore loader supports the real-hardware backends (AWS Nitro,
// Azure SGX, GCP SEV-SNP, Intel SGX bare metal), the value moves to
// the configured tee.Provider name and the wrapper is identical.
func (m *materials) InstrumentTEE(rec *teemetrics.Recorder, provider string) {
	if rec == nil || m == nil {
		return
	}
	if m.Producer != nil {
		m.Producer = rec.WrapProducer(provider, m.Producer)
	}
	if m.Verifier != nil {
		m.Verifier = rec.WrapVerifier(provider, m.Verifier)
	}
}

// readExactly reads path and returns its contents if and only if the
// file is exactly wantLen bytes. Any other length is a Structural
// error wrapped with the logical config field name for operator
// diagnosis. Errors are plain errors (not shared_errors.*) because
// this is main-package provisioning, not contract-surface logic.
func readExactly(path string, wantLen int, fieldName string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sagvd: read %s (%q): %w", fieldName, path, err)
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf(
			"sagvd: %s (%q) must be exactly %d bytes (got %d)",
			fieldName, path, wantLen, len(b))
	}
	return b, nil
}
