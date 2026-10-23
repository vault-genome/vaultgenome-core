// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bundle

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Errors of Store, for a caller that answers over a protocol.
var (
	ErrStoreTooLarge  = errors.New("bundle: larger than the bound")
	ErrStoreEmpty     = errors.New("bundle: empty")
	ErrStoreNotBundle = errors.New("bundle: not a v3 genome bundle")
	ErrStoreKeyTaken  = errors.New("bundle: another bundle for the same key is already stored")
)

// KeyTakenError is ErrStoreKeyTaken with the key and the bundle already
// stored for it.
type KeyTakenError struct {
	KeyID    string
	Existing string // the stored bundle's file name
}

func (e *KeyTakenError) Error() string {
	return fmt.Sprintf("%v: key %s, %s", ErrStoreKeyTaken, e.KeyID, e.Existing)
}

// Is makes errors.Is(err, ErrStoreKeyTaken) hold.
func (e *KeyTakenError) Is(target error) bool { return target == ErrStoreKeyTaken }

// Stored is what Store did with a sealed bundle.
type Stored struct {
	Path        string
	KeyID       string
	SHA256      string // hex, of the bundle's bytes
	Bytes       int64
	AlreadyHere bool // the same bytes were stored before; nothing new written
}

// Store takes a sealed bundle from r into dir (ADR 0036): the way a bundle
// reaches a destination that has no disk anyone else can write, such as a
// Nitro enclave. A sealed bundle is ciphertext without its key; storing it
// exports nothing. At most max bytes are read; they are staged beside the
// other bundles under a name a scan for *.genome ignores, refused unless
// the header is a v3 bundle's, and stored as <sha256>.genome by a rename,
// so no reader ever sees a half-written bundle. A second bundle for a key
// that already has one is refused: one key, one bundle, so a receipt's
// digest names the only candidate. The same bytes again are AlreadyHere.
// Callers serialise Store per directory.
func Store(dir string, r io.Reader, max int64) (Stored, error) {
	if max <= 0 {
		return Stored{}, fmt.Errorf("bundle: store bound %d must be positive", max)
	}
	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return Stored{}, fmt.Errorf("bundle: stage: %w", err)
	}
	staged, kept := tmp.Name(), false
	defer func() {
		if !kept {
			_ = os.Remove(staged)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, max+1))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return Stored{}, fmt.Errorf("bundle: receive: %w", err)
	case n > max:
		return Stored{}, fmt.Errorf("%w: more than %d bytes", ErrStoreTooLarge, max)
	case n == 0:
		return Stored{}, ErrStoreEmpty
	}
	kid := storedKeyID(staged)
	if kid == "" {
		return Stored{}, ErrStoreNotBundle
	}
	out := Stored{KeyID: kid, SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n}
	out.Path = filepath.Join(dir, out.SHA256+".genome")
	if _, err := os.Stat(out.Path); err == nil {
		out.AlreadyHere = true
		return out, nil
	}
	others, err := filepath.Glob(filepath.Join(dir, "*.genome"))
	if err != nil {
		return Stored{}, fmt.Errorf("bundle: list %s: %w", dir, err)
	}
	for _, other := range others {
		if storedKeyID(other) == kid {
			return Stored{}, &KeyTakenError{KeyID: kid, Existing: filepath.Base(other)}
		}
	}
	if err := os.Rename(staged, out.Path); err != nil {
		return Stored{}, fmt.Errorf("bundle: store: %w", err)
	}
	kept = true
	return out, nil
}

// storedKeyID is the key ID a v3 bundle's header names, or "".
func storedKeyID(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	br, err := NewReader(bufio.NewReader(f))
	if err != nil {
		return ""
	}
	return br.Header.KeyID
}
