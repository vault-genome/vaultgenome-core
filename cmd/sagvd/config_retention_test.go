// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
	"time"
)

// The retention keys (ADR 0027): segments need a log, a count of one is
// no segment, the archive directory is absolute, and a window on
// finished jobs needs a store.
func TestValidate_Retention(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(c *Config)
		want   string
	}{
		"segment of one": {func(c *Config) {
			c.Audit.LogPath, c.Keys.AuditSigning = "/var/lib/acp/audit.db", SigningKeyConfig{KeyID: "a", SeedPath: "/s"}
			c.Audit.SegmentEvents = 1
		}, "audit.segment_events must be 0"},
		"segment count negative": {func(c *Config) {
			c.Audit.LogPath, c.Keys.AuditSigning = "/var/lib/acp/audit.db", SigningKeyConfig{KeyID: "a", SeedPath: "/s"}
			c.Audit.SegmentEvents = -5
		}, "audit.segment_events must be 0"},
		"segment age negative": {func(c *Config) {
			c.Audit.LogPath, c.Keys.AuditSigning = "/var/lib/acp/audit.db", SigningKeyConfig{KeyID: "a", SeedPath: "/s"}
			c.Audit.SegmentMaxAgeSeconds = -1
		}, "audit.segment_max_age_seconds must be >= 0"},
		"archive dir relative": {func(c *Config) {
			c.Audit.LogPath, c.Keys.AuditSigning = "/var/lib/acp/audit.db", SigningKeyConfig{KeyID: "a", SeedPath: "/s"}
			c.Audit.ArchiveDir = "archive"
		}, "audit.archive_dir \"archive\" must be an absolute path"},
		"segments without a log": {func(c *Config) {
			c.Audit.LogPath = ""
			c.Audit.SegmentEvents = 100
		}, "need audit.log_path"},
		"archive dir without a log": {func(c *Config) {
			c.Audit.LogPath = ""
			c.Audit.ArchiveDir = "/var/lib/acp/archive"
		}, "need audit.log_path"},
		"retention negative": {func(c *Config) {
			c.Queue.Path = "/var/lib/acp/jobs.db"
			c.Queue.RetainFinishedSeconds = -1
		}, "queue.retain_finished_seconds must be >= 0"},
		"retention without a store": {func(c *Config) {
			c.Queue.Path = ""
			c.Queue.RetainFinishedSeconds = 3600
		}, "queue.retain_finished_seconds needs queue.path"},
	} {
		t.Run(name, func(t *testing.T) {
			c := minimalValidConfig()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}

	// The keys accepted together.
	c := minimalValidConfig()
	c.Audit.LogPath, c.Keys.AuditSigning = "/var/lib/acp/audit.db", SigningKeyConfig{KeyID: "a", SeedPath: "/s"}
	c.Audit.SegmentEvents, c.Audit.SegmentMaxAgeSeconds, c.Audit.ArchiveDir = 100000, 86400, "/var/lib/acp/audit-archive"
	c.Queue.Path, c.Queue.RetainFinishedSeconds = "/var/lib/acp/jobs.db", 30*86400
	if err := c.Validate(); err != nil {
		t.Fatalf("the retention keys were refused: %v", err)
	}
	if !c.Audit.Rotates() || c.Audit.SegmentMaxAge() != 24*time.Hour || c.Audit.ArchiveDirectory() != "/var/lib/acp/audit-archive" {
		t.Fatal("AuditConfig accessors")
	}
	if c.Queue.RetainFinished() != 30*24*time.Hour {
		t.Fatal("RetainFinished")
	}
	if (AuditConfig{}).Rotates() || (AuditConfig{LogPath: "/var/lib/acp/audit.db"}).ArchiveDirectory() != "/var/lib/acp/archive" || (AuditConfig{}).ArchiveDirectory() != "" {
		t.Fatal("AuditConfig defaults")
	}
}
