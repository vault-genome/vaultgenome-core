// SPDX-License-Identifier: AGPL-3.0-or-later

package release_decision

import (
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
)

// SignWith signs the canonical cover-bytes of this ReleaseDecision under
// r.SigningKeyID, bound to keys.PurposeSigningAuthority.
func (r *ReleaseDecision) SignWith(signer keys.Signer) error {
	if r == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"release_decision: nil receiver",
			nil,
		)
	}
	if r.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"release_decision: signing_key_id required before sign",
			nil,
		)
	}
	cp := *r
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"release_decision: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(r.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	r.Signature = sig
	return nil
}

// VerifySignature resolves r.SigningKeyID under
// keys.PurposeSigningAuthority and checks the stored signature.
func (r *ReleaseDecision) VerifySignature(resolver keys.Resolver) error {
	cb, err := r.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(r.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, r.Signature)
}
