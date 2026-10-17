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

// Segmented is a Persister that holds one segment of a longer log
// (ADR 0027): Start says where the segment's events begin — the index of
// its first event in the whole log and the hash that event links to —
// 0 and genesis for a log's first segment. A Persister that is not
// Segmented is a whole log.
type Segmented interface {
	Start() (first int, prevTip []byte, err error)
}

// PersistentChain is a Chain whose events survive the process: an event
// is durably persisted before Append returns it, and a chain reopened
// later continues where it stopped.
//
// Opening verifies the whole stored segment first — every hash link and
// every signature, from the hash the segment starts at — and refuses a
// log that was edited, reordered, spliced, or signed by another key.
// What a chain cannot detect by itself is its tail being cut off;
// compare Tip() against a value recorded elsewhere (the crosscloud-restore
// report prints it) to catch that.
//
// The chain holds its tip and its length, not its events: those live in
// the store, and only there. An authority that serves a job every few
// seconds for a month has a log of tens of millions of events, and
// neither opening it nor running beside it may cost that much memory
// (KNOWN_ISSUES #18). Opening and Verify walk the store one event at a
// time; EventAt and Events read it.
//
// The store may be one segment of the log (Segmented, ADR 0027): the
// chain's count and tip are the log's, and Rotate moves the chain on to
// the next segment without a gap in the links.
type PersistentChain struct {
	mu    sync.RWMutex
	store Persister
	// base is the index, in the log, of the store's first event; prev
	// the hash before it (genesis for a log's first segment).
	base int
	prev []byte
	n    int
	tip  []byte
	// unrecorded is set when a rotation's closing record was not
	// written; the chain refuses to go on until a fresh open records it.
	unrecorded error
}

// OpenPersistentChain walks every event in store, verifying the chain
// under resolver, before accepting appends; it keeps the count and the
// tip, not the events.
func OpenPersistentChain(store Persister, resolver keys.Resolver) (*PersistentChain, error) {
	if store == nil || resolver == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing,
			"audit/chain: persistent chain needs a store and a resolver", nil)
	}
	base, prev := 0, make([]byte, audit_event.HashSize)
	if sg, ok := store.(Segmented); ok {
		first, prevTip, err := sg.Start()
		if err != nil {
			return nil, err
		}
		if first < 0 || len(prevTip) != audit_event.HashSize {
			return nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid,
				"audit/chain: the store's segment start is not an index and a 32-byte hash", nil)
		}
		base, prev = first, append([]byte(nil), prevTip...)
	}
	n, tip, err := walkVerify(store, resolver, base, prev)
	if err != nil {
		var broken *linkError
		if errors.As(err, &broken) {
			return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
				"audit/chain: the stored audit log does not verify; refusing to extend it", broken.err)
		}
		return nil, err
	}
	return &PersistentChain{store: store, base: base, prev: prev, n: n, tip: tip}, nil
}

// linkError marks a link or signature that did not verify during a walk,
// as distinct from the store's own failure to read.
type linkError struct{ err error }

func (e *linkError) Error() string { return e.err.Error() }
func (e *linkError) Unwrap() error { return e.err }

// walkVerify walks the store once, in order, checking every link and
// signature as verifyEvents does but holding one event at a time: the
// store's events are the log's events base, base+1, ..., and the first
// links to prev. It returns the log's count after the store's last
// event and that event's hash (prev when the store is empty).
func walkVerify(store Persister, resolver keys.Resolver, base int, prev []byte) (int, []byte, error) {
	expectedPrev := append([]byte(nil), prev...)
	n := base
	err := store.Walk(func(idx int, evt audit_event.AuditEvent) error {
		if err := verifyLink(base+idx, evt, expectedPrev, resolver); err != nil {
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
	if c.unrecorded != nil {
		return audit_event.AuditEvent{}, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			"audit/chain: the closing of the previous segment is not on the record; open the log again to record it", c.unrecorded)
	}
	return c.appendLocked(evt, signer)
}

func (c *PersistentChain) appendLocked(evt audit_event.AuditEvent, signer keys.Signer) (audit_event.AuditEvent, error) {
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

// Rotate closes the chain's segment and continues on the next (ADR 0027),
// all under the chain's lock. rotate is given the index the live segment
// starts at, the log's count and its tip, and returns the next segment's
// store — or nil, when the rotation is no longer due. closing then builds
// the event that records the closed segment, which the chain seals and
// appends as the first event of the next segment before any other writer
// can. It reports whether the chain moved on.
//
// An error from closing, or from appending its event, leaves the chain
// on the next segment and refusing every append: the record of the
// closing is missing, and a fresh open of the log writes it
// (store.OpenLive).
func (c *PersistentChain) Rotate(
	rotate func(base, n int, tip []byte) (Persister, error),
	closing func() (audit_event.AuditEvent, keys.Signer, error),
) (bool, error) {
	if rotate == nil || closing == nil {
		return false, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing,
			"audit/chain: rotate needs both functions", nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.unrecorded != nil {
		return false, c.unrecorded
	}
	next, err := rotate(c.base, c.n, append([]byte(nil), c.tip...))
	if err != nil {
		return false, err
	}
	if next == nil {
		return false, nil
	}
	c.store = next
	c.base = c.n
	c.prev = append([]byte(nil), c.tip...)
	evt, signer, err := closing()
	if err == nil {
		if signer == nil {
			err = shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit/chain: signer required", nil)
		} else {
			_, err = c.appendLocked(evt, signer)
		}
	}
	if err != nil {
		c.unrecorded = err
		return true, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			"audit/chain: the segment closed but its closing was not recorded; the chain refuses to go on until the log is opened again", err)
	}
	return true, nil
}

// Verify implements Chain: it walks the store, one event at a time, from
// the hash the segment starts at.
func (c *PersistentChain) Verify(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit/chain: resolver required", nil)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, _, err := walkVerify(c.store, resolver, c.base, c.prev)
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

// Len implements Chain: the log's count, across every segment.
func (c *PersistentChain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.n
}

// Base is the index, in the log, of the live segment's first event: the
// live segment holds Len()-Base() events.
func (c *PersistentChain) Base() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.base
}

// EventAt implements Chain: the event is read from the store. An index
// before the live segment, or a store that cannot be read, answers as
// out of range.
func (c *PersistentChain) EventAt(idx int) (audit_event.AuditEvent, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if idx < c.base {
		return audit_event.AuditEvent{}, false
	}
	evt, ok, err := c.store.At(idx - c.base)
	if err != nil || !ok {
		return audit_event.AuditEvent{}, false
	}
	return cloneEvent(evt), true
}

// Events implements Chain: every event of the live segment, read from
// the store, each a copy. A store that cannot be read answers with no
// events.
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
