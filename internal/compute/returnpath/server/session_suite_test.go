// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/transport"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// The worker's CandidateOutputFrame is signed under the worker key's
// suite and verified under it (ADR 0031): the frame names the suite
// (worker_signature_alg, absent for ed25519) under the signature, the
// server checks it against the key it resolves, and a frame whose suite
// does not match the key — or whose alg was swapped — is refused as a
// worker signature failure. On 2026-10-22 reference design 01 under
// cnsa failed exactly here, the server verifying every frame as Ed25519.
func TestVerifyWorkerSignature_UnderEverySuite(t *testing.T) {
	t.Parallel()
	for _, suite := range crypto.Suites() {
		suite := suite
		if suite.Available() != nil {
			continue
		}
		t.Run(string(suite), func(t *testing.T) {
			t.Parallel()
			clock := shared_time.NewFakeClock(time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC))
			store := keys.NewInMemoryStore(clock)
			kid := ids.KeyID("worker-" + string(suite))
			vk, err := store.GenerateSigningSuite(kid, keys.PurposeSigningAuthority, suite)
			require.NoError(t, err)
			resolver := NewPublicKeyResolver(map[ids.KeyID]keys.VerifyingKey{kid: vk})
			s := &Session{cfg: SessionConfig{WorkerKeyResolver: resolver, WorkerKeyPurpose: keys.PurposeSigningAuthority}}

			frame := transport.CandidateOutputFrame{
				Type: transport.FrameTypeCandidateOutput, ManifestID: "rjm-1", SessionID: "ses-1",
				OutputKind: "bytes/fixed-length", Bytes: []byte("x"), ProducedAt: clock.Now().UTC(),
				WorkerSigningKeyID: string(kid),
			}
			alg, err := keys.RecordAlg(store, kid)
			require.NoError(t, err)
			frame.WorkerSignatureAlg = alg
			cover, err := frame.CoverBytes()
			require.NoError(t, err)
			frame.WorkerSignature, err = store.Sign(kid, keys.PurposeSigningAuthority, cover)
			require.NoError(t, err)
			require.Len(t, frame.WorkerSignature, suite.SignatureSize())
			require.NoError(t, s.verifyWorkerSignature(frame))

			// The suite is under the signature: a swapped alg is a different
			// cover, and a cover under another suite than the key's is refused
			// before any signature is checked.
			swapped := frame
			if suite == crypto.SuiteEd25519 {
				swapped.WorkerSignatureAlg = crypto.SuiteECDSAP384SHA384
			} else {
				swapped.WorkerSignatureAlg = ""
			}
			err = s.verifyWorkerSignature(swapped)
			require.Error(t, err)
			require.Equal(t, shared_errors.CodeOf(err), CodeWorkerSignatureInvalid)

			// A key of another suite registered under the same kid refuses
			// the frame — the record's alg and the key's suite disagree.
			for _, other := range crypto.Suites() {
				if other == suite || other.Available() != nil {
					continue
				}
				otherStore := keys.NewInMemoryStore(clock)
				ovk, err := otherStore.GenerateSigningSuite(kid, keys.PurposeSigningAuthority, other)
				require.NoError(t, err)
				so := &Session{cfg: SessionConfig{WorkerKeyResolver: NewPublicKeyResolver(map[ids.KeyID]keys.VerifyingKey{kid: ovk}), WorkerKeyPurpose: keys.PurposeSigningAuthority}}
				err = so.verifyWorkerSignature(frame)
				require.Error(t, err)
				require.Contains(t, err.Error(), "does not match the key's suite")
			}
		})
	}
}
