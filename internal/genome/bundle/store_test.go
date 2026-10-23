// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	dir := t.TempDir()
	blob, _, err := SealBytes(Header{ContentKind: ContentDir, ContentRef: "store-test"}, []byte("a sealed payload"))
	require.NoError(t, err)
	br, err := NewReader(bytes.NewReader(blob))
	require.NoError(t, err)
	kid := br.Header.KeyID
	leftovers := func() []string {
		names, _ := filepath.Glob(filepath.Join(dir, ".upload-*"))
		return names
	}

	got, err := Store(dir, bytes.NewReader(blob), 1<<20)
	require.NoError(t, err)
	sum := sha256.Sum256(blob)
	require.Equal(t, hex.EncodeToString(sum[:]), got.SHA256)
	require.Equal(t, kid, got.KeyID)
	require.EqualValues(t, len(blob), got.Bytes)
	require.False(t, got.AlreadyHere)
	stored, err := os.ReadFile(got.Path)
	require.NoError(t, err)
	require.Equal(t, blob, stored)

	again, err := Store(dir, bytes.NewReader(blob), 1<<20)
	require.NoError(t, err)
	require.True(t, again.AlreadyHere)

	_, err = Store(dir, bytes.NewReader(append(append([]byte(nil), blob...), 0)), 1<<20)
	var taken *KeyTakenError
	require.True(t, errors.As(err, &taken))
	require.ErrorIs(t, err, ErrStoreKeyTaken)
	require.Equal(t, kid, taken.KeyID)
	require.Equal(t, filepath.Base(got.Path), taken.Existing)

	_, err = Store(dir, bytes.NewReader(blob), int64(len(blob))-1)
	require.ErrorIs(t, err, ErrStoreTooLarge)
	_, err = Store(dir, bytes.NewReader(nil), 1<<20)
	require.ErrorIs(t, err, ErrStoreEmpty)
	_, err = Store(dir, bytes.NewReader([]byte("not a bundle at all")), 1<<20)
	require.ErrorIs(t, err, ErrStoreNotBundle)
	_, err = Store(dir, bytes.NewReader(blob), 0)
	require.ErrorContains(t, err, "must be positive")
	_, err = Store(filepath.Join(dir, "missing"), bytes.NewReader(blob), 1<<20)
	require.ErrorContains(t, err, "stage")

	require.Empty(t, leftovers(), "nothing is left half-written")
	names, _ := filepath.Glob(filepath.Join(dir, "*.genome"))
	require.Len(t, names, 1, "only the stored bundle")
}
