// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.etcd.io/bbolt"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// A log in segments (ADR 0027).
//
// A log that nothing rotates grows by every decision, and a bbolt file
// never shrinks. So a daemon writes its log in segments: the live file
// holds the newest, and a closed segment is moved, as a file, into the
// archive directory under the indices of its first and last events. The
// fresh live file records in a bucket of its own where it starts — the
// index of its first event, the hash that event links to, the archive it
// continues — and the chain above it counts and links across the
// boundary as if the file had never been cut. Nothing here deletes an
// event; the operator moves closed segments where their policy keeps
// them, and an archive is opened read-only, so that its hash stays what
// the chain records.

const (
	// bucketSegment holds one key, keySegmentStart: where this file's
	// events start, in a file that is not the first segment of its log.
	bucketSegment   = "segment"
	keySegmentStart = "start"

	// SegmentStartSchema names the SegmentStart record.
	SegmentStartSchema = "vault-genome/audit-segment/v1"
	// SegmentClosedSchema names the ClosedSegment record: the payload of
	// the AUDIT_SEGMENT_CLOSED event that opens the segment after it.
	SegmentClosedSchema = "vault-genome/audit-segment-closed/v1"

	// segmentIndexDigits is the width of the indices in an archive's
	// name: ten digits is nineteen years at a thousand events a minute.
	segmentIndexDigits = 10
)

// SegmentStart is where a segment's events start, kept in the segment
// bucket of every live file that continues an archive.
type SegmentStart struct {
	Schema string `json:"schema"`
	// FirstIndex is the index, in the whole log, of the first event in
	// this file.
	FirstIndex int `json:"first_index"`
	// PrevTipHex is the hash of the event before the first one here —
	// the tip of the archive this file continues — which the first event
	// links to.
	PrevTipHex string `json:"prev_tip_hex"`
	// PrevSegment is the archive's file name.
	PrevSegment string `json:"prev_segment"`
}

// PrevTip decodes PrevTipHex.
func (s SegmentStart) PrevTip() ([]byte, error) {
	tip, err := hex.DecodeString(s.PrevTipHex)
	if err != nil || len(tip) != audit_event.HashSize {
		return nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid,
			"audit/store: the segment's prev_tip_hex is not a 32-byte hash", err)
	}
	return tip, nil
}

func (s SegmentStart) validate() error {
	if s.Schema != SegmentStartSchema {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported,
			fmt.Sprintf("audit/store: segment start schema %q, want %q", s.Schema, SegmentStartSchema), nil)
	}
	if s.FirstIndex <= 0 {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			"audit/store: a segment that continues an archive starts after index 0", nil)
	}
	if s.PrevSegment == "" || s.PrevSegment != filepath.Base(s.PrevSegment) {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			"audit/store: the segment's prev_segment must be a file name", nil)
	}
	_, err := s.PrevTip()
	return err
}

// SegmentStart returns where this file's events start, and whether the
// file says so at all: the first segment of a log does not.
func (s *BBoltStore) SegmentStart() (SegmentStart, bool, error) {
	if s.db == nil {
		return SegmentStart{}, false, shared_errors.Operational(
			shared_errors.CodeResourceExhausted, "audit/store: read on closed store", ErrStoreClosed)
	}
	var raw []byte
	if err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketSegment))
		if b == nil {
			return nil
		}
		if v := b.Get([]byte(keySegmentStart)); v != nil {
			raw = append([]byte(nil), v...)
		}
		return nil
	}); err != nil {
		return SegmentStart{}, false, shared_errors.Operational(
			shared_errors.CodeResourceExhausted, "audit/store: read segment start", err)
	}
	if raw == nil {
		return SegmentStart{}, false, nil
	}
	var start SegmentStart
	if err := json.Unmarshal(raw, &start); err != nil {
		return SegmentStart{}, false, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid, "audit/store: segment start does not decode", err)
	}
	if err := start.validate(); err != nil {
		return SegmentStart{}, false, err
	}
	return start, true, nil
}

// Start reports where the store's events start in its log: the index of
// the first event here and the hash it links to — 0 and genesis (zeros)
// for a file that is the first segment of its log. It is what the chain
// reads (chain.Segmented).
func (s *BBoltStore) Start() (int, []byte, error) {
	start, ok, err := s.SegmentStart()
	if err != nil {
		return 0, nil, err
	}
	if !ok {
		return 0, make([]byte, audit_event.HashSize), nil
	}
	prev, err := start.PrevTip()
	if err != nil {
		return 0, nil, err
	}
	return start.FirstIndex, prev, nil
}

// Create creates a fresh store at path for a segment that continues an
// archive, as start says. It refuses a path that exists: a live file is
// never overwritten.
func Create(path string, start SegmentStart) (*BBoltStore, error) {
	if path == "" {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit/store: path required", nil)
	}
	if err := start.validate(); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: %q exists; a live segment is never overwritten", filepath.Clean(path)), nil)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: stat %q", filepath.Clean(path)), err)
	}
	raw, err := json.Marshal(start)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "audit/store: encode segment start", err)
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: openTimeout})
	if err != nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: create %q failed", filepath.Clean(path)), err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketName)); err != nil {
			return err
		}
		b, err := tx.CreateBucketIfNotExists([]byte(bucketSegment))
		if err != nil {
			return err
		}
		return b.Put([]byte(keySegmentStart), raw)
	}); err != nil {
		_ = db.Close()
		_ = os.Remove(path)
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			"audit/store: segment initialisation failed", err)
	}
	return &BBoltStore{db: db, path: path}, nil
}

// OpenReadOnly opens an existing file for reading only. An archive is
// read this way — by acpctl, and by a daemon continuing from it — so that
// no byte of it changes and its hash stays what the chain records; a
// read-write open commits a transaction and moves the file's bytes even
// when it writes no event. A missing file is refused, not created.
func OpenReadOnly(path string) (*BBoltStore, error) {
	if path == "" {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit/store: path required", nil)
	}
	db, err := bbolt.Open(path, 0o400, &bbolt.Options{Timeout: openTimeout, ReadOnly: true})
	if err != nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: open %q read-only failed", filepath.Clean(path)), err)
	}
	return &BBoltStore{db: db, path: path}, nil
}

// ReadOnly reports whether the store was opened read-only.
func (s *BBoltStore) ReadOnly() bool {
	return s.db != nil && s.db.IsReadOnly()
}

// SegmentName is the file name of the archive holding the events
// first..last of the log whose live file is livePath:
// `<name>.<first>-<last><ext>`, the indices ten digits wide.
func SegmentName(livePath string, first, last int) string {
	base := filepath.Base(livePath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return fmt.Sprintf("%s.%0*d-%0*d%s", stem, segmentIndexDigits, first, segmentIndexDigits, last, ext)
}

// archivePattern matches the names SegmentName gives the archives of the
// log at livePath, capturing the two indices.
func archivePattern(livePath string) *regexp.Regexp {
	base := filepath.Base(livePath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return regexp.MustCompile(fmt.Sprintf(`^%s\.(\d{%d})-(\d{%d})%s$`,
		regexp.QuoteMeta(stem), segmentIndexDigits, segmentIndexDigits, regexp.QuoteMeta(ext)))
}

// Archive is a closed segment on disk, as its name describes it.
type Archive struct {
	Path       string
	Name       string
	FirstIndex int
	LastIndex  int
}

// ListArchives lists the archives of the log at livePath that are in
// archiveDir, in the order of their first index. A directory that does
// not exist holds none; files named otherwise are not archives.
func ListArchives(livePath, archiveDir string) ([]Archive, error) {
	entries, err := os.ReadDir(archiveDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: list %q", filepath.Clean(archiveDir)), err)
	}
	re := archivePattern(livePath)
	var out []Archive
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		m := re.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		first, err1 := strconv.Atoi(m[1])
		last, err2 := strconv.Atoi(m[2])
		if err1 != nil || err2 != nil || first > last {
			continue
		}
		out = append(out, Archive{Path: filepath.Join(archiveDir, e.Name()), Name: e.Name(), FirstIndex: first, LastIndex: last})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstIndex < out[j].FirstIndex })
	return out, nil
}

// HashFile returns the SHA-256 of the file at path and its length.
func HashFile(path string) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: open %q", filepath.Clean(path)), err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return nil, 0, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: read %q", filepath.Clean(path)), err)
	}
	return h.Sum(nil), n, nil
}

// ClosedSegment describes an archived segment: the payload of the
// AUDIT_SEGMENT_CLOSED event recorded as the first event of the segment
// after it (SegmentClosedSchema), so that the live file names the file
// it continues and what that file must hash to.
type ClosedSegment struct {
	Schema string `json:"schema"`
	// Segment is the archive's file name in the archive directory.
	Segment string `json:"segment"`
	// FirstIndex and LastIndex are the indices of its first and last
	// events in the whole log.
	FirstIndex int `json:"first_index"`
	LastIndex  int `json:"last_index"`
	// TipHex is the hash of its last event: what the event after it
	// links to.
	TipHex string `json:"tip_hex"`
	// Bytes and SHA256Hex are the closed file's length and hash.
	Bytes     int64  `json:"bytes"`
	SHA256Hex string `json:"sha256_hex"`
	// Path is where the file is; it is not part of the record.
	Path string `json:"-"`
}

// describeArchive hashes the archive a and fills its ClosedSegment with
// tip as the hash of its last event.
func describeArchive(a Archive, tip []byte) (ClosedSegment, error) {
	sum, size, err := HashFile(a.Path)
	if err != nil {
		return ClosedSegment{}, err
	}
	return ClosedSegment{
		Schema: SegmentClosedSchema, Segment: a.Name, FirstIndex: a.FirstIndex, LastIndex: a.LastIndex,
		TipHex: hex.EncodeToString(tip), Bytes: size, SHA256Hex: hex.EncodeToString(sum), Path: a.Path,
	}, nil
}

// Rotate closes s — the live segment holding the events first..n-1 of its
// log, tip the hash of the last — moves its file into archiveDir under
// its SegmentName, and returns a fresh store at the same path that
// continues from it, with the closed segment described. The caller
// records the ClosedSegment as the first event of the new store.
//
// An error before the move leaves s open and usable; an error after it
// leaves the archive in place and the live path empty, and the next
// OpenLive of the path finishes the rotation from the archive.
func Rotate(s *BBoltStore, archiveDir string, first, n int, tip []byte) (*BBoltStore, ClosedSegment, error) {
	if s == nil || s.db == nil {
		return nil, ClosedSegment{}, shared_errors.Operational(
			shared_errors.CodeResourceExhausted, "audit/store: rotate on closed store", ErrStoreClosed)
	}
	if s.db.IsReadOnly() {
		return nil, ClosedSegment{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid, "audit/store: a read-only store is not rotated", nil)
	}
	if n <= first || first < 0 {
		return nil, ClosedSegment{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid, "audit/store: nothing to close: the segment holds no event", nil)
	}
	if len(tip) != audit_event.HashSize {
		return nil, ClosedSegment{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid, "audit/store: the tip must be a 32-byte hash", nil)
	}
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		return nil, ClosedSegment{}, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: create %q", filepath.Clean(archiveDir)), err)
	}
	a := Archive{Name: SegmentName(s.path, first, n-1), FirstIndex: first, LastIndex: n - 1}
	a.Path = filepath.Join(archiveDir, a.Name)
	if _, err := os.Lstat(a.Path); err == nil {
		return nil, ClosedSegment{}, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: archive %q exists already", a.Path), nil)
	}
	livePath := s.path
	if err := s.Close(); err != nil {
		return nil, ClosedSegment{}, err
	}
	if err := os.Rename(livePath, a.Path); err != nil {
		// The live segment stays where it is, and open.
		if db, reopenErr := bbolt.Open(livePath, 0o600, &bbolt.Options{Timeout: openTimeout}); reopenErr == nil {
			s.db = db
		}
		return nil, ClosedSegment{}, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: move %q to %q failed (the archive directory must be on the live file's filesystem)", livePath, a.Path), err)
	}
	closed, err := describeArchive(a, tip)
	if err != nil {
		return nil, ClosedSegment{}, err
	}
	next, err := Create(livePath, SegmentStart{
		Schema: SegmentStartSchema, FirstIndex: n, PrevTipHex: closed.TipHex, PrevSegment: a.Name,
	})
	if err != nil {
		return nil, closed, err
	}
	return next, closed, nil
}

// OpenLive opens the live segment of the log at livePath, whose closed
// segments are in archiveDir, finishing a rotation a crash interrupted:
// a live file that is absent — or empty, with no start of its own —
// beside archives is created to continue the newest archive. The
// returned ClosedSegment, when not nil, is an archive whose closing is
// not yet on the record: the live file holds no event, and the caller
// records it before anything else. That archive must be present, with
// its name and length as its name says; an absent one is an error, since
// a segment closed off the record is a decision off the record.
func OpenLive(livePath, archiveDir string) (*BBoltStore, *ClosedSegment, error) {
	if livePath == "" {
		return nil, nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit/store: path required", nil)
	}
	archives, err := ListArchives(livePath, archiveDir)
	if err != nil {
		return nil, nil, err
	}
	info, statErr := os.Lstat(livePath)
	switch {
	case statErr == nil && !info.Mode().IsRegular():
		return nil, nil, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: %q is not a regular file", filepath.Clean(livePath)), nil)
	case statErr != nil && !errors.Is(statErr, fs.ErrNotExist):
		return nil, nil, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: stat %q", filepath.Clean(livePath)), statErr)
	case statErr != nil:
		if len(archives) == 0 {
			s, err := Open(livePath)
			return s, nil, err
		}
		return continueFrom(livePath, archives[len(archives)-1])
	}

	s, err := Open(livePath)
	if err != nil {
		return nil, nil, err
	}
	start, hasStart, err := s.SegmentStart()
	if err != nil {
		_ = s.Close()
		return nil, nil, err
	}
	n, err := s.Len()
	if err != nil {
		_ = s.Close()
		return nil, nil, err
	}
	switch {
	case hasStart && n > 0:
		return s, nil, nil
	case hasStart:
		// Created, not yet written to: the closing of the archive it
		// continues is still to be recorded.
		var prev *Archive
		for i := range archives {
			if archives[i].Name == start.PrevSegment {
				prev = &archives[i]
			}
		}
		if prev == nil {
			_ = s.Close()
			return nil, nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("audit/store: %q continues the closed segment %q, whose closing is not on the record yet, and that segment is not in %q: put it back and start again",
					filepath.Clean(livePath), start.PrevSegment, filepath.Clean(archiveDir)), nil)
		}
		if prev.LastIndex+1 != start.FirstIndex {
			_ = s.Close()
			return nil, nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("audit/store: %q starts at index %d but the segment it continues, %q, ends at %d",
					filepath.Clean(livePath), start.FirstIndex, prev.Name, prev.LastIndex), nil)
		}
		tip, err := start.PrevTip()
		if err != nil {
			_ = s.Close()
			return nil, nil, err
		}
		closed, err := describeArchive(*prev, tip)
		if err != nil {
			_ = s.Close()
			return nil, nil, err
		}
		return s, &closed, nil
	case len(archives) == 0:
		return s, nil, nil
	case n == 0:
		// A fresh first segment beside archives: a rotation a crash
		// interrupted, and a start that did not know the archives. The
		// log continues from the newest archive instead.
		_ = s.Close()
		if err := os.Remove(livePath); err != nil {
			return nil, nil, shared_errors.Operational(shared_errors.CodeResourceExhausted,
				fmt.Sprintf("audit/store: remove the empty %q", filepath.Clean(livePath)), err)
		}
		return continueFrom(livePath, archives[len(archives)-1])
	default:
		_ = s.Close()
		return nil, nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("audit/store: %q starts a chain of its own (%d events from genesis) while %d closed segments of this log are in %q: restore the live file that continued them, or move them away",
				filepath.Clean(livePath), n, len(archives), filepath.Clean(archiveDir)), nil)
	}
}

// continueFrom creates the live segment at livePath to continue the
// archive a: its first index is the archive's last plus one, its prev
// tip the archive's last event's hash. The archive is read read-only.
func continueFrom(livePath string, a Archive) (*BBoltStore, *ClosedSegment, error) {
	ro, err := OpenReadOnly(a.Path)
	if err != nil {
		return nil, nil, err
	}
	first, _, err := ro.Start()
	if err != nil {
		_ = ro.Close()
		return nil, nil, err
	}
	n, err := ro.Len()
	if err != nil {
		_ = ro.Close()
		return nil, nil, err
	}
	if first != a.FirstIndex || n == 0 || a.FirstIndex+n-1 != a.LastIndex {
		_ = ro.Close()
		return nil, nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("audit/store: archive %q holds %d events from index %d, not %d..%d as its name says",
				a.Path, n, first, a.FirstIndex, a.LastIndex), nil)
	}
	last, ok, err := ro.At(n - 1)
	_ = ro.Close()
	if err != nil {
		return nil, nil, err
	}
	if !ok || len(last.Hash) != audit_event.HashSize {
		return nil, nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("audit/store: archive %q: its last event has no hash", a.Path), nil)
	}
	closed, err := describeArchive(a, last.Hash)
	if err != nil {
		return nil, nil, err
	}
	s, err := Create(livePath, SegmentStart{
		Schema: SegmentStartSchema, FirstIndex: a.LastIndex + 1, PrevTipHex: closed.TipHex, PrevSegment: a.Name,
	})
	if err != nil {
		return nil, nil, err
	}
	return s, &closed, nil
}

// ProbeArchiveDir creates archiveDir and proves that a file beside
// livePath can be moved into it: a closed segment is renamed, not copied,
// so the two must be on one filesystem. A daemon runs it at start, so
// that a configuration that cannot rotate is refused before the first
// segment closes.
func ProbeArchiveDir(livePath, archiveDir string) error {
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		return shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: create %q", filepath.Clean(archiveDir)), err)
	}
	f, err := os.CreateTemp(filepath.Dir(livePath), ".audit-segment-probe-*")
	if err != nil {
		return shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: write beside %q", filepath.Clean(livePath)), err)
	}
	src := f.Name()
	_ = f.Close()
	dst := filepath.Join(archiveDir, filepath.Base(src))
	if err := os.Rename(src, dst); err != nil {
		_ = os.Remove(src)
		return shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: a file beside %q cannot be moved into %q: the archive directory must be on the live file's filesystem",
				filepath.Clean(livePath), filepath.Clean(archiveDir)), err)
	}
	_ = os.Remove(dst)
	return nil
}
