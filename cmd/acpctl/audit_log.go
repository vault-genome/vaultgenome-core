// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// An audit log in segments (ADR 0027), as acpctl reads it: the closed
// segments in the archive directory, oldest first, then the live file.
// Every file is opened read-only — an archive's bytes are what the chain
// records, and a read-write open would move them — and a daemon holding
// the live file open is refused as before (one holder at a time).

// auditLog names a log's files.
type auditLog struct {
	livePath   string
	archiveDir string
	archives   []store.Archive
}

// openAuditLog checks that the live file is there, lists the log's
// archives in archiveDir — "archive" beside the live file when empty —
// and remembers both. Nothing is opened yet.
func openAuditLog(livePath, archiveDir string) (*auditLog, error) {
	if livePath == "" {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit log path required", nil)
	}
	if _, err := os.Stat(livePath); err != nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit log %q", filepath.Clean(livePath)), err)
	}
	if archiveDir == "" {
		archiveDir = filepath.Join(filepath.Dir(livePath), "archive")
	}
	archives, err := store.ListArchives(livePath, archiveDir)
	if err != nil {
		return nil, err
	}
	return &auditLog{livePath: livePath, archiveDir: archiveDir, archives: archives}, nil
}

// segmentRef is one file of the log.
type segmentRef struct {
	Path    string
	Name    string
	Archive *store.Archive // nil for the live file
}

func (l *auditLog) segments() []segmentRef {
	out := make([]segmentRef, 0, len(l.archives)+1)
	for i := range l.archives {
		a := l.archives[i]
		out = append(out, segmentRef{Path: a.Path, Name: a.Name, Archive: &a})
	}
	return append(out, segmentRef{Path: l.livePath, Name: filepath.Base(l.livePath)})
}

// openSegment opens one file read-only and reads where it starts: the
// index of its first event in the log and the hash that event links to.
func openSegment(seg segmentRef) (s *store.BBoltStore, first int, prev []byte, err error) {
	s, err = store.OpenReadOnly(seg.Path)
	if err != nil {
		return nil, 0, nil, err
	}
	first, prev, err = s.Start()
	if err != nil {
		_ = s.Close()
		return nil, 0, nil, err
	}
	return s, first, prev, nil
}

// load returns every event of the log in order, archives first.
func (l *auditLog) load() ([]audit_event.AuditEvent, error) {
	var out []audit_event.AuditEvent
	for _, seg := range l.segments() {
		s, _, _, err := openSegment(seg)
		if err != nil {
			return nil, err
		}
		err = s.Walk(func(_ int, evt audit_event.AuditEvent) error {
			out = append(out, evt)
			return nil
		})
		_ = s.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// segmentReport is one file of the log as the verifier saw it.
type segmentReport struct {
	Path       string `json:"path"`
	FirstIndex int    `json:"first_index"`
	Events     int    `json:"events"`
	// Tip is the hash of the file's last event; empty for an empty file.
	Tip string `json:"tip,omitempty"`
	// SHA256 and Bytes are the archived file's, checked against the
	// record that closed it; absent for the live file.
	SHA256 string `json:"sha256,omitempty"`
	Bytes  int64  `json:"bytes,omitempty"`
	Live   bool   `json:"live,omitempty"`
}

// logVerifyResult is what verifying a log in segments found.
type logVerifyResult struct {
	Segments []segmentReport
	// Count is the log's count after the last event; Tip its hash.
	Count int
	Tip   []byte
	// StartsAfter is the hash the oldest present segment continues from
	// when it is not genesis: the history before it is not here.
	StartsAfter []byte
}

// errIncomplete says the chain cannot be verified back to genesis from
// what is present.
type errIncomplete struct{ msg string }

func (e *errIncomplete) Error() string { return e.msg }

// chainError is a verdict on the chain — a link, a signature, a segment
// or an archive that does not verify — as distinct from a file that
// could not be read.
type chainError struct{ err error }

func (e *chainError) Error() string { return e.err.Error() }
func (e *chainError) Unwrap() error { return e.err }

// broken is a chain that does not verify.
func broken(msg string) error {
	return &chainError{err: shared_errors.Integrity(shared_errors.CodeSignatureInvalid, msg, nil)}
}

// isVerdict reports whether err is a verdict on the chain (exit 4)
// rather than a failure to read it (exit 1).
func isVerdict(err error) bool {
	var ce *chainError
	var incomplete *errIncomplete
	return errors.As(err, &ce) || errors.As(err, &incomplete)
}

// verifyAuditLog walks every segment in order, checking that each starts
// where the previous ended (index and tip), that every link and every
// signature verify under resolver, that every segment after the first
// of the log opens with the record of the one it continues, and that an
// archive is as that record says: its length and SHA-256. It needs the
// oldest present segment to start at genesis, or fromTip to be the hash
// it continues from — the operator's word that the earlier segments
// were verified where they are.
func verifyAuditLog(l *auditLog, resolver keys.Resolver, fromTip []byte) (logVerifyResult, error) {
	var res logVerifyResult
	segs := l.segments()
	genesis := make([]byte, audit_event.HashSize)
	var (
		expectedIdx  int
		expectedPrev []byte
		prevArchive  *store.Archive
		prevHash     []byte
		prevBytes    int64
	)
	for k, seg := range segs {
		report := segmentReport{Path: seg.Path, Live: seg.Archive == nil}
		if seg.Archive != nil {
			sum, size, err := store.HashFile(seg.Path)
			if err != nil {
				return res, err
			}
			report.SHA256, report.Bytes = hex.EncodeToString(sum), size
		}
		s, first, prev, err := openSegment(seg)
		if err != nil {
			return res, err
		}
		if k == 0 {
			// The oldest present segment: genesis, or the operator's word.
			if !(first == 0 && bytes.Equal(prev, genesis)) {
				res.StartsAfter = prev
				if fromTip == nil {
					_ = s.Close()
					return res, &errIncomplete{msg: fmt.Sprintf(
						"%s starts at event #%d after tip %s, and the segments before it are not in %s: verify them where they are and pass --from-tip %s, or put them back",
						seg.Name, first, hex.EncodeToString(prev), l.archiveDir, hex.EncodeToString(prev))}
				}
				if !bytes.Equal(fromTip, prev) {
					_ = s.Close()
					return res, &errIncomplete{msg: fmt.Sprintf(
						"%s starts after tip %s, not after --from-tip %s", seg.Name, hex.EncodeToString(prev), hex.EncodeToString(fromTip))}
				}
			}
			expectedIdx, expectedPrev = first, append([]byte(nil), prev...)
		} else if first != expectedIdx || !bytes.Equal(prev, expectedPrev) {
			_ = s.Close()
			return res, broken(fmt.Sprintf("%s starts at event #%d after tip %s, but %s ended at event #%d with tip %s",
				seg.Name, first, hex.EncodeToString(prev), segs[k-1].Name, expectedIdx-1, hex.EncodeToString(expectedPrev)))
		}
		count := 0
		var tip []byte
		err = s.Walk(func(local int, evt audit_event.AuditEvent) error {
			idx := first + local
			if !bytes.Equal(evt.PrevHash, expectedPrev) {
				return broken(fmt.Sprintf("%s: event #%d: prev_hash does not link to event #%d", seg.Name, idx, idx-1))
			}
			if err := evt.VerifySignature(resolver); err != nil {
				return &chainError{err: fmt.Errorf("%s: event #%d: %w", seg.Name, idx, err)}
			}
			switch {
			case evt.Kind == audit_event.KindAuditSegmentClosed && local != 0:
				return broken(fmt.Sprintf("%s: event #%d records a closing but is not the segment's first event", seg.Name, idx))
			case evt.Kind == audit_event.KindAuditSegmentClosed:
				if err := checkClosing(seg, evt, prevArchive, prevHash, prevBytes); err != nil {
					return err
				}
			case local == 0 && first > 0:
				return broken(fmt.Sprintf("%s: its first event #%d is %s, not the record of the segment it continues", seg.Name, idx, evt.Kind))
			}
			count++
			expectedIdx = idx + 1
			expectedPrev = append([]byte(nil), evt.Hash...)
			tip = evt.Hash
			return nil
		})
		_ = s.Close()
		if err != nil {
			return res, err
		}
		if seg.Archive != nil {
			if first != seg.Archive.FirstIndex || first+count-1 != seg.Archive.LastIndex {
				return res, broken(fmt.Sprintf("%s holds events #%d..#%d, not #%d..#%d as its name says",
					seg.Name, first, first+count-1, seg.Archive.FirstIndex, seg.Archive.LastIndex))
			}
			sum, _ := hex.DecodeString(report.SHA256)
			prevArchive, prevHash, prevBytes = seg.Archive, sum, report.Bytes
		}
		report.FirstIndex, report.Events = first, count
		if tip != nil {
			report.Tip = hex.EncodeToString(tip)
		}
		res.Segments = append(res.Segments, report)
	}
	res.Count, res.Tip = expectedIdx, expectedPrev
	return res, nil
}

// checkClosing checks the AUDIT_SEGMENT_CLOSED record evt that opens seg
// against the archive before it, when that archive is present: the
// name, the indices, the tip it links to, the length and the hash.
func checkClosing(seg segmentRef, evt audit_event.AuditEvent, prev *store.Archive, prevHash []byte, prevBytes int64) error {
	var closed store.ClosedSegment
	if err := json.Unmarshal(evt.Payload, &closed); err != nil || closed.Schema != store.SegmentClosedSchema {
		return broken(fmt.Sprintf("%s: the closing record does not decode as %s", seg.Name, store.SegmentClosedSchema))
	}
	if closed.TipHex != hex.EncodeToString(evt.PrevHash) {
		return broken(fmt.Sprintf("%s: the closing record names tip %s but links to %s", seg.Name, closed.TipHex, hex.EncodeToString(evt.PrevHash)))
	}
	if prev == nil {
		return nil // the segment it names is not here; --from-tip vouched for it
	}
	switch {
	case closed.Segment != prev.Name:
		return broken(fmt.Sprintf("%s: the closing record names %s, but the segment before it is %s", seg.Name, closed.Segment, prev.Name))
	case closed.FirstIndex != prev.FirstIndex || closed.LastIndex != prev.LastIndex:
		return broken(fmt.Sprintf("%s: the closing record says %s holds #%d..#%d; its name says #%d..#%d",
			seg.Name, prev.Name, closed.FirstIndex, closed.LastIndex, prev.FirstIndex, prev.LastIndex))
	case closed.SHA256Hex != hex.EncodeToString(prevHash) || closed.Bytes != prevBytes:
		return broken(fmt.Sprintf("%s: %s is not the file the chain recorded: sha256 %s, %d bytes on disk; %s, %d bytes on the record",
			seg.Name, prev.Name, hex.EncodeToString(prevHash), prevBytes, closed.SHA256Hex, closed.Bytes))
	}
	return nil
}
