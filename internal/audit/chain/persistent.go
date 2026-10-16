// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package chain

import (
	"errors"
	"sync"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Persister is where a PersistentChain keeps its events, in order.
// store.BBoltStore implements it. The chain keeps nothing it persisted
// in memory: it reads the events back through Walk (one at a time, in
// order), At (one, by index) and Load (every one, for export).
type Persister interface {
	Append(evt audit_event.AuditEvent) error
	Load() ([]audit_event.AuditEvent, error)
	// Walk calls fn for every event in order, one at a time, and stops
	// at the first error, which it returns as it is.
	Walk(fn func(idx int, evt audit_event.AuditEvent) error) error
	// At returns the event at idx, counting from 0 in order; the bool is
	// false when idx is out of range.
	At(idx int) (audit_event.AuditEvent, bool, error)
}

// PersistentChain is a Chain whose events survive the process: an event
// is durably persisted before Append returns it, and a chain reopened
// later continues where it stopped.
//
// Opening verifies the whole stored chain first — every hash link and
// every signature — and refuses a log that was edited, reordered,
// spliced, or signed by another key. What a chain cannot detect by
// itself is its tail being cut off; compare Tip() against a value
// recorded elsewhere (the crosscloud-restore report prints it) to catch
// that.
//
// The chain holds its tip and its length, not its events: those live in
// the store, and only there. An authority that serves a job every few
// seconds for a month has a log of tens of millions of events, and
// neither opening it nor running beside it may cost that much memory
// (KNOWN_ISSUES #18). Opening and Verify walk the store one event at a
// time; EventAt and Events read it.
type PersistentChain struct {
	mu    sync.RWMutex
	store Persister
	n     int
	tip   []byte
}

// OpenPersistentChain walks every event in store, verifying the chain
// under resolver, before accepting appends; it keeps the count and the
// tip, not the events.
func OpenPersistentChain(store Persister, resolver keys.Resolver) (*PersistentChain, error) {
	if store == nil || resolver == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing,
			"audit/chain: persistent chain needs a store and a resolver", nil)
	}
	n, tip, err := walkVerify(store, resolver)
	if err != nil {
		var broken *linkError
		if errors.As(err, &broken) {
			return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
				"audit/chain: the stored audit log does not verify; refusing to extend it", broken.err)
		}
		return nil, err
	}
	return &PersistentChain{store: store, n: n, tip: tip}, nil
}

// linkError marks a link or signature that did not verify during a walk,
// as distinct from the store's own failure to read.
type linkError struct{ err error }

func (e *linkError) Error() string { return e.err.Error() }
func (e *linkError) Unwrap() error { return e.err }

// walkVerify walks the store once, in order, checking every link and
// signature as verifyEvents does but holding one event at a time; it
// returns the count and the last hash (zeros for an empty store).
func walkVerify(store Persister, resolver keys.Resolver) (int, []byte, error) {
	expectedPrev := make([]byte, audit_event.HashSize) // genesis
	n := 0
	err := store.Walk(func(idx int, evt audit_event.AuditEvent) error {
		if err := verifyLink(idx, evt, expectedPrev, resolver); err != nil {
			return &linkError{err: err}
		}
		expectedPrev = append(expectedPrev[:0], evt.Hash...)
		n++
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return n, expectedPrev, nil
}

// Append seals evt against the current tip and persists it; only then
// does the chain advance. If persisting fails, nothing changes and the
// caller must treat the decision the event describes as not taken.
func (c *PersistentChain) Append(evt audit_event.AuditEvent, signer keys.Signer) (audit_event.AuditEvent, error) {
	if signer == nil {
		return audit_event.AuditEvent{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing, "audit/chain: signer required", nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	sealed, err := seal(evt, c.tip, signer)
	if err != nil {
		return audit_event.AuditEvent{}, err
	}
	if err := c.store.Append(sealed); err != nil {
		return audit_event.AuditEvent{}, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			"audit/chain: persisting the event failed; the chain did not advance", err)
	}
	c.n++
	c.tip = append([]byte(nil), sealed.Hash...)
	return cloneEvent(sealed), nil
}

// Verify implements Chain: it walks the store, one event at a time.
func (c *PersistentChain) Verify(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit/chain: resolver required", nil)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, _, err := walkVerify(c.store, resolver)
	var broken *linkError
	if errors.As(err, &broken) {
		return broken.err
	}
	return err
}

// Tip implements Chain.
func (c *PersistentChain) Tip() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]byte(nil), c.tip...)
}

// Len implements Chain.
func (c *PersistentChain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.n
}

// EventAt implements Chain: the event is read from the store. A store
// that cannot be read answers as out of range.
func (c *PersistentChain) EventAt(idx int) (audit_event.AuditEvent, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	evt, ok, err := c.store.At(idx)
	if err != nil || !ok {
		return audit_event.AuditEvent{}, false
	}
	return cloneEvent(evt), true
}

// Events implements Chain: every event, read from the store, each a
// copy. A store that cannot be read answers with no events.
func (c *PersistentChain) Events() []audit_event.AuditEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()
	events, err := c.store.Load()
	if err != nil {
		return nil
	}
	out := make([]audit_event.AuditEvent, len(events))
	for i := range events {
		out[i] = cloneEvent(events[i])
	}
	return out
}

var _ Chain = (*PersistentChain)(nil)
