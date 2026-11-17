// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package restorer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// goingOn is a restorer with a gate and an after-restore command.
func (f *fixture) goingOn(gate *GateConfig, after *AfterRestoreConfig) *Restorer {
	f.t.Helper()
	r, err := New(Config{BundleDir: f.bundles, RestoreDir: f.restores, Keys: f.keys, Erase: f.keys.EraseSealing,
		TEE: f.tee, Kind: tee.ProviderSimulated, Rescan: 20 * time.Millisecond, Gate: gate, AfterRestore: after,
		Logger: f.r.log})
	require.NoError(f.t, err)
	return r
}

// noting is an after-restore command that writes what it was given, one
// line a run, to the file it returns.
func noting(t *testing.T) (*AfterRestoreConfig, string) {
	t.Helper()
	notes := filepath.Join(t.TempDir(), "ran")
	return &AfterRestoreConfig{Command: []string{"sh", "-c", `printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$WHO" >> "` + notes + `"`,
		"go-on", GenomePlaceholder, BundlePlaceholder, "generation " + GenerationPlaceholder}, Env: []string{"WHO=the standby"}}, notes
}

func exactDoor(t *testing.T) *GateConfig {
	t.Helper()
	return &GateConfig{Command: door(t, []float32{1.5, -2}, []float32{0.25, 3}), Tolerance: equivalence.Tolerance{Atol: 1e-3}, Required: true}
}

func ran(t *testing.T, notes string) []string {
	t.Helper()
	raw, err := os.ReadFile(notes)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

// A restore whose gate passed runs the command once, with the restored
// tree, the bundle it came from and its generation — and not again for a
// key released twice, or by a daemon that restarts.
func TestAfterRestore_RunsOnceAfterAGateThatPassed(t *testing.T) {
	f := newFixture(t)
	after, notes := noting(t)
	f.r = f.goingOn(exactDoor(t), after)
	blob, dek, kid := f.seal(modelGenome(t))
	bundle := filepath.Join(f.bundles, "g.genome")
	require.NoError(t, os.WriteFile(bundle, blob, 0o644))
	f.release(kid, dek, "failover")
	f.r.work(context.Background())

	rec := f.record(kid)
	require.Equal(t, StateRestored, rec.State, rec.Error)
	require.Equal(t, []string{filepath.Join(f.restores, kid) + "|" + bundle + "|generation 0|the standby"}, ran(t, notes))
	require.NotNil(t, rec.AfterRestore)
	require.Zero(t, rec.AfterRestore.ExitCode)
	require.Empty(t, rec.AfterRestore.Error)
	require.False(t, rec.AfterRestore.StartedAt.IsZero())
	// The receipt was signed before the command ran and says nothing of it.
	require.Equal(t, kid, verified(t, f, kid).KeyID)

	f.deliver(kid, "again")
	f.r.work(context.Background())
	require.Len(t, ran(t, notes), 1, "a finished restore stays done")

	again := f.goingOn(exactDoor(t), after)
	again.work(context.Background())
	_, rec2, ok := again.Receipt(kid)
	require.True(t, ok)
	require.Equal(t, StateRestored, rec2.State)
	require.Len(t, ran(t, notes), 1, "a restarted daemon does not run it again")
}

// Nothing starts on a model that missed its references, or on a restore
// that did not happen.
func TestAfterRestore_NothingStartsWithoutAGateThatPassed(t *testing.T) {
	f := newFixture(t)
	after, notes := noting(t)
	f.r = f.goingOn(&GateConfig{Command: door(t, []float32{9, -2}, []float32{0.25, 3}), Tolerance: equivalence.Tolerance{Atol: 1e-3}, Required: true}, after)
	blob, dek, kid := f.seal(modelGenome(t))
	require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "g.genome"), blob, 0o644))
	f.release(kid, dek, "failover")
	f.r.work(context.Background())
	rec := f.record(kid)
	require.Equal(t, StateGateFailed, rec.State)
	require.Nil(t, rec.AfterRestore)
	require.Empty(t, ran(t, notes))

	// A bundle that does not open.
	f2 := newFixture(t)
	after2, notes2 := noting(t)
	f2.r = f2.goingOn(exactDoor(t), after2)
	blob2, dek2, kid2 := f2.seal(modelGenome(t))
	blob2[len(blob2)-3] ^= 0x01
	require.NoError(t, os.WriteFile(filepath.Join(f2.bundles, "g.genome"), blob2, 0o644))
	f2.release(kid2, dek2, "failover")
	f2.r.work(context.Background())
	require.Equal(t, StateFailed, f2.record(kid2).State)
	require.Nil(t, f2.record(kid2).AfterRestore)
	require.Empty(t, ran(t, notes2))
}

// A command that fails, or does not end, is on the restore's record; the
// restore is signed for and stays restored.
func TestAfterRestore_WhatTheCommandDidIsOnTheRecord(t *testing.T) {
	for name, tc := range map[string]struct {
		after *AfterRestoreConfig
		code  int
		says  string
	}{
		"it fails":         {&AfterRestoreConfig{Command: []string{"sh", "-c", "echo no such unit >&2; exit 7"}}, 7, "no such unit"},
		"it does not end":  {&AfterRestoreConfig{Command: []string{"sh", "-c", "sleep 30"}, Timeout: 50 * time.Millisecond}, -1, "ran out of time after 50ms"},
		"it cannot be run": {&AfterRestoreConfig{Command: []string{filepath.Join(t.TempDir(), "absent")}}, -1, "no such file"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.r = f.goingOn(exactDoor(t), tc.after)
			blob, dek, kid := f.seal(modelGenome(t))
			require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "g.genome"), blob, 0o644))
			f.release(kid, dek, "failover")
			f.r.work(context.Background())
			rec := f.record(kid)
			require.Equal(t, StateRestored, rec.State, rec.Error)
			require.NotNil(t, rec.AfterRestore)
			require.Equal(t, tc.code, rec.AfterRestore.ExitCode)
			require.Contains(t, rec.AfterRestore.Error, tc.says)
			require.NotNil(t, verified(t, f, kid).Gate)
		})
	}
}

// The command needs a required gate: without one a restore is signed for
// without a verdict, and nothing may start on that.
func TestNew_AnAfterRestoreCommandNeedsARequiredGate(t *testing.T) {
	f := newFixture(t)
	base := Config{BundleDir: f.bundles, RestoreDir: f.restores, Keys: f.keys, TEE: f.tee, Kind: tee.ProviderSimulated}
	after := &AfterRestoreConfig{Command: []string{"true"}}

	cfg := base
	cfg.AfterRestore = after
	_, err := New(cfg)
	require.ErrorContains(t, err, "needs a required gate")

	cfg.Gate = &GateConfig{Command: []string{"true"}}
	_, err = New(cfg)
	require.ErrorContains(t, err, "needs a required gate")

	cfg.Gate = &GateConfig{Command: []string{"true"}, Required: true}
	_, err = New(cfg)
	require.NoError(t, err)

	cfg.AfterRestore = &AfterRestoreConfig{}
	_, err = New(cfg)
	require.ErrorContains(t, err, "needs a command")

	cfg.AfterRestore = &AfterRestoreConfig{Command: []string{"true"}, Timeout: -time.Second}
	_, err = New(cfg)
	require.ErrorContains(t, err, "must not be negative")
}
