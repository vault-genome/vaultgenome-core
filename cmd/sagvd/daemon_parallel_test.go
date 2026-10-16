// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func countKind(kinds []string, want string) int {
	n := 0
	for _, k := range kinds {
		if k == want {
			n++
		}
	}
	return n
}

// With runtime.max_sessions = 2, two workers are inside their jobs at
// once while a third waits for a slot; every job is judged on its own
// flow, every decision on the one audit chain, which verifies.
func TestDaemon_ServesSessionsInParallelUpToTheLimit(t *testing.T) {
	f := newDaemonFixture(t, func(c *Config) { c.Runtime.MaxSessions = 2; c.Runtime.HandshakeTimeoutSeconds = 10 })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	right := f.sealed.rightOutput(t, nil)
	ids := []string{f.submit(PolicyProfileGate), f.submit(PolicyProfileGate), f.submit(PolicyProfileGate)}

	var inside atomic.Int32
	release := make(chan struct{})
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() {
			errs <- f.worker(ctx, func(string) []byte {
				inside.Add(1)
				<-release
				return right
			})
		}()
	}
	require.Eventually(t, func() bool { return inside.Load() == 2 }, 10*time.Second, 10*time.Millisecond, "two sessions inside their jobs")
	require.Equal(t, `sagvd_sessions_active 2`, f.metric("sagvd_sessions_active"))
	require.Equal(t, `sagvd_sessions_limit 2`, f.metric("sagvd_sessions_limit"))
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, int32(2), inside.Load(), "a third session ran while the limit is two")
	close(release)
	for i := 0; i < 3; i++ {
		require.NoError(t, <-errs)
	}
	for _, id := range ids {
		view := f.waitJob(id, "succeeded")
		require.NotNil(t, view.Gate)
		require.Equal(t, "EXACT", view.Gate.Level)
	}
	require.NoError(t, f.audit.chain.Verify(f.audit.keys))
	require.Equal(t, 3, countKind(f.kinds(), "RELEASE_DECIDED"))
	require.Equal(t, 3, countKind(f.kinds(), "SESSION_ISSUED"))
	require.Eventually(t, func() bool { return f.metric("sagvd_sessions_active") == `sagvd_sessions_active 0` }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, `sagvd_sessions_opened_total 3`, f.metric("sagvd_sessions_opened_total"))
	require.Equal(t, `sagvd_jobs_completed_total{outcome="success"} 3`, f.metric(`sagvd_jobs_completed_total{outcome="success"}`))
}

// With one slot taken, a second connection waits the handshake timeout
// for one and is then closed before any handshake: counted as busy, no
// trust decision, no session; the worker dials again later. The job in
// the first session is unaffected.
func TestDaemon_RefusesTheConnectionWhenEverySlotIsTaken(t *testing.T) {
	f := newDaemonFixture(t, func(c *Config) { c.Runtime.MaxSessions = 1; c.Runtime.HandshakeTimeoutSeconds = 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	right := f.sealed.rightOutput(t, nil)
	id := f.submit(PolicyProfileGate)

	var inside atomic.Int32
	release := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- f.worker(ctx, func(string) []byte {
			inside.Add(1)
			<-release
			return right
		})
	}()
	require.Eventually(t, func() bool { return inside.Load() == 1 }, 10*time.Second, 10*time.Millisecond)

	start := time.Now()
	err := f.worker(ctx, func(string) []byte { return right })
	require.Error(t, err, "the second connection was served while the only slot was taken")
	require.GreaterOrEqual(t, time.Since(start), 900*time.Millisecond, "the second connection was closed before the wait for a slot")
	require.Eventually(t, func() bool {
		return f.metric(`sagvd_sessions_refused_total{reason="busy"}`) == `sagvd_sessions_refused_total{reason="busy"} 1`
	}, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, 1, countKind(f.kinds(), "TRUST_EVALUATED"), "the first session's admission is the only trust decision: a busy refusal is not one")
	require.Equal(t, `sagvd_sessions_opened_total 1`, f.metric("sagvd_sessions_opened_total"))

	close(release)
	require.NoError(t, <-first)
	view := f.waitJob(id, "succeeded")
	require.Equal(t, "EXACT", view.Gate.Level)
	require.Equal(t, 1, countKind(f.kinds(), "RELEASE_DECIDED"))
	require.NoError(t, f.audit.chain.Verify(f.audit.keys))
}

// runtime.max_sessions: 0 is one session (the old behaviour), a positive
// number is that many, a negative one is refused.
func TestConfig_MaxSessions(t *testing.T) {
	c := minimalValidConfig()
	require.Equal(t, 1, c.Runtime.SessionSlots())
	c.Runtime.MaxSessions = 4
	require.Equal(t, 4, c.Runtime.SessionSlots())
	require.NoError(t, c.Validate())
	c.Runtime.MaxSessions = -1
	err := c.Validate()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "runtime.max_sessions"), err.Error())
}
