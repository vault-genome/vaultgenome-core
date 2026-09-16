// SPDX-License-Identifier: AGPL-3.0-or-later

package release_decision

import (
	"testing"

	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	"github.com/stretchr/testify/require"
)

// VerifySignature refuses what it cannot check: no resolver, a decision
// that fails its own shape rules, a key the resolver does not hold, the
// same key id under another key.
func TestReleaseDecision_VerifySignature_RefusesWhatItCannotCheck(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("authority-signer-1")
	store := newAuthStore(t, kid)
	r := validPassFixture()
	r.SigningKeyID = kid
	require.NoError(t, r.SignWith(store))
	require.NoError(t, r.VerifySignature(store))

	err := r.VerifySignature(nil)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))

	malformed := r
	malformed.AuditEventID = ""
	err = malformed.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), "%v", err)

	stranger := newAuthStore(t, ids.KeyID("someone-else"))
	require.Error(t, r.VerifySignature(stranger), "a resolver without the key cannot vouch for the signature")

	other := newAuthStore(t, kid)
	require.Error(t, r.VerifySignature(other), "the same key id under another key is not the signer")
}
