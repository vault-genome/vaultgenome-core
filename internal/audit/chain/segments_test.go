// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package chain

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// A chain across segments (ADR 0027): the count and the tip are the
// log's, the closing of a segment is the first event of the next, and a
// reopened live segment verifies from the archive's tip.

// segmentedLog opens a chain on a bbolt file at live with three events
// on it.
func segmentedLog(t *testing.T) (c *PersistentChain, s *store.BBoltStore, live, archive string, ks *keys.InMemoryStore, kid ids.KeyID) {
	t.Helper()
	kid = ids.KeyID("audit-key-1")
	ks = newAuditStore(t, kid)
	dir := t.TempDir()
	live, archive = filepath.Join(dir, "audit.db"), filepath.Join(dir, "archive")
	s, err := store.Open(live)
	require.NoError(t, err)
	c, err = OpenPersistentChain(s, ks)
	require.NoError(t, err)
	for i := 1; i <= 3; i++ {
		_, err := c.Append(skeleton(fmt.Sprintf("evt-%d", i), kid), ks)
		require.NoError(t, err)
	}
	return c, s, live, archive, ks, kid
}

// closingEvent is what a daemon records as the first event of a fresh
// segment: the closed segment, as its payload.
func closingEvent(kid ids.KeyID, closed store.ClosedSegment) audit_event.AuditEvent {
	evt := skeleton("evt-closing", kid)
	evt.Kind = audit_event.KindAuditSegmentClosed
	evt.Payload, _ = json.Marshal(closed)
	return evt
}

func TestPersistentChain_RotatesWithoutAGapInTheLinks(t *testing.T) {
	t.Parallel()
	c, s, live, archive, ks, kid := segmentedLog(t)
	tip := c.Tip()

	var closed store.ClosedSegment
	rotated, err := c.Rotate(func(base, n int, tip2 []byte) (Persister, error) {
		require.Equal(t, 0, base)
		require.Equal(t, 3, n)
		require.Equal(t, tip, tip2)
		next, cs, err := store.Rotate(s, archive, base, n, tip2)
		if err != nil {
			return nil, err
		}
		s, closed = next, cs
		return next, nil
	}, func() (audit_event.AuditEvent, keys.Signer, error) {
		return closingEvent(kid, closed), ks, nil
	})
	require.NoError(t, err)
	require.True(t, rotated)
	defer func() { _ = s.Close() }()

	require.Equal(t, 4, c.Len(), "the log counts the closing record")
	require.Equal(t, 3, c.Base())
	first, ok := c.EventAt(3)
	require.True(t, ok)
	require.Equal(t, audit_event.KindAuditSegmentClosed, first.Kind)
	require.Equal(t, tip, first.PrevHash, "the closing record links to the archive's last event")
	var payload store.ClosedSegment
	require.NoError(t, json.Unmarshal(first.Payload, &payload))
	require.Equal(t, closed.Segment, payload.Segment)
	require.Equal(t, closed.SHA256Hex, payload.SHA256Hex)
	_, ok = c.EventAt(2)
	require.False(t, ok, "an archived event is not read from the live segment")
	require.Len(t, c.Events(), 1)

	fifth, err := c.Append(skeleton("evt-5", kid), ks)
	require.NoError(t, err)
	require.Equal(t, first.Hash, fifth.PrevHash)
	require.Equal(t, 5, c.Len())
	require.NoError(t, c.Verify(ks))

	// Reopened, the live segment verifies from the archive's tip and
	// counts the log, not the file.
	require.NoError(t, s.Close())
	reopened, err := store.Open(live)
	require.NoError(t, err)
	s = reopened
	c2, err := OpenPersistentChain(reopened, ks)
	require.NoError(t, err)
	require.Equal(t, 5, c2.Len())
	require.Equal(t, 3, c2.Base())
	require.Equal(t, c.Tip(), c2.Tip())
	require.NoError(t, c2.Verify(ks))

	// The archive verifies on its own, from genesis.
	ro, err := store.OpenReadOnly(closed.Path)
	require.NoError(t, err)
	defer func() { _ = ro.Close() }()
	ca, err := OpenPersistentChain(ro, ks)
	require.NoError(t, err)
	require.Equal(t, 3, ca.Len())
	require.Equal(t, 0, ca.Base())
	require.Equal(t, tip, ca.Tip())
}

func TestPersistentChain_RotateDeclinedOrFailedLeavesTheChainAsItWas(t *testing.T) {
	t.Parallel()
	c, s, _, _, ks, kid := segmentedLog(t)
	defer func() { _ = s.Close() }()
	tip := c.Tip()
	notCalled := func() (audit_event.AuditEvent, keys.Signer, error) {
		t.Fatal("closing called without a rotation")
		return audit_event.AuditEvent{}, nil, nil
	}

	rotated, err := c.Rotate(func(int, int, []byte) (Persister, error) { return nil, nil }, notCalled)
	require.NoError(t, err)
	require.False(t, rotated)

	boom := errors.New("disk full")
	rotated, err = c.Rotate(func(int, int, []byte) (Persister, error) { return nil, boom }, notCalled)
	require.ErrorIs(t, err, boom)
	require.False(t, rotated)

	_, err = c.Rotate(nil, nil)
	require.Error(t, err)

	require.Equal(t, 3, c.Len())
	require.Equal(t, 0, c.Base())
	require.Equal(t, tip, c.Tip())
	_, err = c.Append(skeleton("evt-4", kid), ks)
	require.NoError(t, err)
}

func TestPersistentChain_WithoutTheClosingRecordRefusesToGoOn(t *testing.T) {
	t.Parallel()
	c, s, live, archive, ks, kid := segmentedLog(t)
	var closed store.ClosedSegment
	rotated, err := c.Rotate(func(base, n int, tip []byte) (Persister, error) {
		next, cs, err := store.Rotate(s, archive, base, n, tip)
		if err != nil {
			return nil, err
		}
		s, closed = next, cs
		return next, nil
	}, func() (audit_event.AuditEvent, keys.Signer, error) {
		return audit_event.AuditEvent{}, nil, errors.New("could not hash the archive")
	})
	require.True(t, rotated)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not recorded")

	_, err = c.Append(skeleton("evt-4", kid), ks)
	require.Error(t, err, "no decision goes on a segment whose opening is off the record")
	_, err = c.Rotate(func(int, int, []byte) (Persister, error) { return nil, nil }, nil)
	require.Error(t, err)
	require.NoError(t, s.Close())

	// A fresh open of the log finds the closing still to be recorded,
	// records it, and the log goes on.
	fresh, unrecorded, err := store.OpenLive(live, archive)
	require.NoError(t, err)
	defer func() { _ = fresh.Close() }()
	require.NotNil(t, unrecorded)
	require.Equal(t, closed, *unrecorded)
	c2, err := OpenPersistentChain(fresh, ks)
	require.NoError(t, err)
	require.Equal(t, 3, c2.Len())
	_, err = c2.Append(closingEvent(kid, *unrecorded), ks)
	require.NoError(t, err)
	_, err = c2.Append(skeleton("evt-5", kid), ks)
	require.NoError(t, err)
	require.Equal(t, 5, c2.Len())
	require.NoError(t, c2.Verify(ks))
}

func TestPersistentChain_RefusesALiveSegmentThatDoesNotLinkToItsStart(t *testing.T) {
	t.Parallel()
	c, s, live, archive, ks, kid := segmentedLog(t)
	var closed store.ClosedSegment
	_, err := c.Rotate(func(base, n int, tip []byte) (Persister, error) {
		next, cs, err := store.Rotate(s, archive, base, n, tip)
		if err != nil {
			return nil, err
		}
		s, closed = next, cs
		return next, nil
	}, func() (audit_event.AuditEvent, keys.Signer, error) {
		return closingEvent(kid, closed), ks, nil
	})
	require.NoError(t, err)
	events, err := s.Load()
	require.NoError(t, err)
	require.NoError(t, s.Close())

	// The same events in a file whose start names another tip: the first
	// event does not link to it, and the chain refuses the segment.
	forged := filepath.Join(filepath.Dir(live), "forged.db")
	f, err := store.Create(forged, store.SegmentStart{
		Schema: store.SegmentStartSchema, FirstIndex: 3, PrevSegment: closed.Segment,
		PrevTipHex: "00000000000000000000000000000000000000000000000000000000000000ff",
	})
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	for _, evt := range events {
		require.NoError(t, f.Append(evt))
	}
	_, err = OpenPersistentChain(f, ks)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not verify")
}

// A Persister whose Start is not an index and a hash is refused.
type badStart struct{ memPersister }

func (badStart) Start() (int, []byte, error) { return -1, nil, nil }

func TestPersistentChain_RefusesABrokenSegmentStart(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	ks := newAuditStore(t, kid)
	_, err := OpenPersistentChain(&badStart{}, ks)
	require.Error(t, err)
}
