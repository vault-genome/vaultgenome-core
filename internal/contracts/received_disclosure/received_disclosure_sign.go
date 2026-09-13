// SPDX-License-Identifier: AGPL-3.0-or-later

package received_disclosure

import (
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
)

// SignWith signs the canonical cover-bytes of this ReceivedDisclosure
// under r.SigningKeyID, bound to keys.PurposeSigningAuthority. The key
// is the receive-side signing-authority key — distinct from the
// release-side authority. The two authorities never share a key; an
// observer cross-checking the two ledgers is looking for exactly that
// separation.
func (r *ReceivedDisclosure) SignWith(signer keys.Signer) error {
	if r == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"received_disclosure: nil receiver",
			nil,
		)
	}
	if r.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"received_disclosure: signing_key_id required before sign",
			nil,
		)
	}
	cp := *r
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"received_disclosure: canonical encode failed",
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
func (r *ReceivedDisclosure) VerifySignature(resolver keys.Resolver) error {
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
