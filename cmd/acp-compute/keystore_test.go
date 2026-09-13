// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
	"github.com/stretchr/testify/require"
)

// testKeyDir lays down a complete set of key material files of the
// right sizes and returns a Config that points at them. Returned
// bytes are deterministic so tests can hash / compare them.
func testKeyDir(t *testing.T) (Config, string) {
	t.Helper()
	dir := t.TempDir()

	writeBytes := func(name string, b []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, b, 0o600))
		return path
	}

	teeSeed := bytes.Repeat([]byte{0x11}, crypto.Ed25519SeedSize)
	workerSeed := bytes.Repeat([]byte{0x22}, crypto.Ed25519SeedSize)
	sessionKey := bytes.Repeat([]byte{0x33}, crypto.AES256KeySize)
	peerPub, _, err := crypto.Ed25519FromSeed(bytes.Repeat([]byte{0x44}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	peerMeas := bytes.Repeat([]byte{0x55}, crypto.HashSize)

	cfg := DefaultConfig()
	cfg.TEE.WorkloadDescriptor = "acp-compute-test-worker"
	cfg.TEE.SeedPath = writeBytes("tee.seed", teeSeed)
	cfg.TEE.Peer.PublicKeyPath = writeBytes("peer.pub", peerPub)
	cfg.TEE.Peer.MeasurementPath = writeBytes("peer.meas", peerMeas)
	cfg.Keys.WorkerSigning.KeyID = "worker-sign-1"
	cfg.Keys.WorkerSigning.SeedPath = writeBytes("worker.seed", workerSeed)
	cfg.Keys.SessionSealing.KeyID = "session-seal-1"
	cfg.Keys.SessionSealing.MaterialPath = writeBytes("session.key", sessionKey)
	return cfg, dir
}

func testClock(t *testing.T) shared_time.Clock {
	t.Helper()
	return shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
}

func TestLoadMaterials_HappyPath(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	mat, err := LoadMaterials(cfg, testClock(t))
	require.NoError(t, err)
	require.NotNil(t, mat.Store)
	require.NotNil(t, mat.Producer)
	require.NotNil(t, mat.Verifier)
	require.Equal(t, ids.KeyID("worker-sign-1"), mat.SigningKeyID)
	require.Equal(t, ids.KeyID("session-seal-1"), mat.SealingKeyID)
	require.Len(t, mat.SigningPublicKey, crypto.Ed25519PublicKeySize)

	// The signing key must be usable under the declared purpose.
	_, err = mat.Store.Sign(mat.SigningKeyID, keys.PurposeSigningAuthority, []byte("cover"))
	require.NoError(t, err)

	// The sealing key must round-trip under its kid.
	nonce, ct, err := mat.Store.Seal(mat.SealingKeyID, []byte("pt"), []byte("aad"))
	require.NoError(t, err)
	got, err := mat.Store.Open(mat.SealingKeyID, nonce, ct, []byte("aad"))
	require.NoError(t, err)
	require.Equal(t, []byte("pt"), got)
}

func TestLoadMaterials_Deterministic_SameSeedSamePubkey(t *testing.T) {
	t.Parallel()
	// Two loads of the same files must yield the same signing pubkey —
	// the property the Phase 1 "worker pubkey published out-of-band"
	// affordance depends on.
	cfg, _ := testKeyDir(t)
	a, err := LoadMaterials(cfg, testClock(t))
	require.NoError(t, err)
	b, err := LoadMaterials(cfg, testClock(t))
	require.NoError(t, err)
	require.Equal(t, a.SigningPublicKey, b.SigningPublicKey)
}

func TestLoadMaterials_RejectsShortTEESeed(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	// Overwrite the TEE seed with the wrong length.
	require.NoError(t, os.WriteFile(cfg.TEE.SeedPath, []byte{0x00}, 0o600))
	_, err := LoadMaterials(cfg, testClock(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "tee.seed_path")
}

func TestLoadMaterials_RejectsShortWorkerSeed(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	require.NoError(t, os.WriteFile(cfg.Keys.WorkerSigning.SeedPath, make([]byte, 31), 0o600))
	_, err := LoadMaterials(cfg, testClock(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "keys.worker_signing.seed_path")
}

func TestLoadMaterials_RejectsShortSealingKey(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	require.NoError(t, os.WriteFile(cfg.Keys.SessionSealing.MaterialPath, make([]byte, 33), 0o600))
	_, err := LoadMaterials(cfg, testClock(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "keys.session_sealing.material_path")
}

func TestLoadMaterials_RejectsWrongPeerPublicKeyLen(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	require.NoError(t, os.WriteFile(cfg.TEE.Peer.PublicKeyPath, make([]byte, 31), 0o600))
	_, err := LoadMaterials(cfg, testClock(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "tee.peer.public_key_path")
}

func TestLoadMaterials_RejectsWrongPeerMeasurementLen(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	require.NoError(t, os.WriteFile(cfg.TEE.Peer.MeasurementPath, make([]byte, 33), 0o600))
	_, err := LoadMaterials(cfg, testClock(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "tee.peer.measurement_path")
}

func TestLoadMaterials_MissingFileReportsFieldName(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	require.NoError(t, os.Remove(cfg.Keys.WorkerSigning.SeedPath))
	_, err := LoadMaterials(cfg, testClock(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "keys.worker_signing.seed_path")
}
