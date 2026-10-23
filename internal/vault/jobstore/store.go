// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jobstore keeps the release authority's accepted jobs on disk,
// so that a restart resumes what was queued or in flight instead of
// losing it (ADR 0026). One bbolt file, two buckets: every job's record
// — the submission as accepted, its status, how many times it was
// admitted — and the final view of every finished job, so that an
// operator's GET of a job that finished before a restart still answers.
//
// The store is a record, not the queue: the daemon's in-memory queue
// orders and dispatches, and writes its transitions here. A write that
// fails does not stop the job; it is logged, and durability is what is
// lost, not the decision (the audit log is the decision's record).
//
// Finished jobs expire (ADR 0027): Sweep deletes the records and views
// of jobs that finished before a cutoff the daemon derives from
// queue.retain_finished_seconds, oldest first, through an index by
// completion time; a store written before the index existed is indexed
// when it is opened. Jobs queued or running are never swept.
package jobstore

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"go.etcd.io/bbolt"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

const (
	bucketJobs  = "jobs"  // id -> Record (JSON)
	bucketViews = "views" // id -> the finished job's view (JSON, opaque here)
	// bucketFinished indexes the finished jobs by when they finished:
	// key = 8-byte big-endian UnixNano of the record's UpdatedAt at its
	// terminal transition, then the id; no value. Sweep walks it from
	// the oldest (ADR 0027), so a sweep costs what it deletes.
	bucketFinished = "finished"

	// openTimeout bounds the wait for bbolt's file lock: a second process
	// on the same file is a configuration error, reported as such.
	openTimeout = 5 * time.Second
)

// The status strings a Record carries: the daemon's own job statuses.
const (
	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
)

// Record is what the store keeps about one job: enough to admit it again
// after a restart, and where it stands.
type Record struct {
	// ID is the job's id (NewJobID), the key of the record.
	ID string `json:"id"`
	// Request is the submission as POST /v1/jobs accepted it, re-encoded
	// from the parsed body; a resume admits it again verbatim.
	Request json.RawMessage `json:"request,omitempty"`
	// RequestID is the RecoveryRequest's id the first admission used,
	// minted or given; a resume names the same request.
	RequestID string `json:"request_id,omitempty"`
	// DeadlineSeconds is how long the worker has from dispatch, as
	// resolved at the first admission (the default applied).
	DeadlineSeconds int `json:"deadline_seconds"`
	// SubmittedAt is when the job was first accepted; a resume keeps it.
	SubmittedAt time.Time `json:"submitted_at"`
	// Status is one of the Status constants.
	Status string `json:"status"`
	// Attempts counts admissions: 1 at submission, one more per resume.
	Attempts int `json:"attempts"`
	// LastError is why the job failed, when it did.
	LastError string `json:"last_error,omitempty"`
	// UpdatedAt is when the record last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// Terminal reports whether the record's status is final.
func (r Record) Terminal() bool {
	return r.Status == StatusSucceeded || r.Status == StatusFailed
}

// Store is an open job store.
type Store struct {
	db   *bbolt.DB
	path string
}

// Open opens or creates the store at path (mode 0600; the parent
// directory must exist). It takes bbolt's file lock: a second process on
// the same file is refused after openTimeout.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "jobstore: path required", nil)
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: openTimeout})
	if err != nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			fmt.Sprintf("jobstore: open %q failed", filepath.Clean(path)), err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		for _, b := range []string{bucketJobs, bucketViews} {
			if _, err := tx.CreateBucketIfNotExists([]byte(b)); err != nil {
				return err
			}
		}
		if tx.Bucket([]byte(bucketFinished)) != nil {
			return nil
		}
		// A store from before the index: index its finished jobs once.
		idx, err := tx.CreateBucket([]byte(bucketFinished))
		if err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketJobs)).ForEach(func(_, raw []byte) error {
			var rec Record
			if err := json.Unmarshal(raw, &rec); err != nil {
				return err
			}
			if !rec.Terminal() {
				return nil
			}
			return idx.Put(finishedKey(rec.UpdatedAt, rec.ID), nil)
		})
	}); err != nil {
		_ = db.Close()
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted, "jobstore: bucket initialisation failed", err)
	}
	return &Store{db: db, path: path}, nil
}

// Path is the file the store holds.
func (s *Store) Path() string { return s.path }

// Close releases the file. Safe on a nil receiver.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Put writes rec under its id, replacing an existing record.
func (s *Store) Put(rec Record) error {
	if rec.ID == "" {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "jobstore: record id required", nil)
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "jobstore: encode record", err)
	}
	return s.update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketJobs))
		if old := b.Get([]byte(rec.ID)); old != nil {
			if err := unindexFinished(tx, old); err != nil {
				return err
			}
		}
		if err := b.Put([]byte(rec.ID), raw); err != nil {
			return err
		}
		return indexFinished(tx, rec)
	})
}

// finishedKey is the index key of a job that finished at t.
func finishedKey(t time.Time, id string) []byte {
	key := make([]byte, 8, 8+len(id))
	binary.BigEndian.PutUint64(key, uint64(t.UTC().UnixNano()))
	return append(key, id...)
}

// indexFinished puts rec in the finished index when it is terminal.
func indexFinished(tx *bbolt.Tx, rec Record) error {
	if !rec.Terminal() {
		return nil
	}
	return tx.Bucket([]byte(bucketFinished)).Put(finishedKey(rec.UpdatedAt, rec.ID), nil)
}

// unindexFinished removes the index entry of the stored record raw, if
// it was terminal.
func unindexFinished(tx *bbolt.Tx, raw []byte) error {
	var old Record
	if err := json.Unmarshal(raw, &old); err != nil {
		return err
	}
	if !old.Terminal() {
		return nil
	}
	return tx.Bucket([]byte(bucketFinished)).Delete(finishedKey(old.UpdatedAt, old.ID))
}

// Get returns the record for id, and whether there is one.
func (s *Store) Get(id string) (Record, bool, error) {
	var rec Record
	found := false
	err := s.db.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket([]byte(bucketJobs)).Get([]byte(id))
		if raw == nil {
			return nil
		}
		found = true
		return json.Unmarshal(raw, &rec)
	})
	if err != nil {
		return Record{}, false, shared_errors.Operational(shared_errors.CodeResourceExhausted, "jobstore: read record", err)
	}
	return rec, found, nil
}

// SetStatus moves the record for id to status at now, keeping everything
// else; lastError is recorded when non-empty. An unknown id is an error:
// a transition belongs to a job the store knows.
func (s *Store) SetStatus(id, status, lastError string, now time.Time) error {
	return s.update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketJobs))
		raw := b.Get([]byte(id))
		if raw == nil {
			return fmt.Errorf("no record for job %s", id)
		}
		var rec Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if err := unindexFinished(tx, raw); err != nil {
			return err
		}
		rec.Status = status
		rec.UpdatedAt = now.UTC()
		if lastError != "" {
			rec.LastError = lastError
		}
		out, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(id), out); err != nil {
			return err
		}
		return indexFinished(tx, rec)
	})
}

// Sweep deletes the records and views of jobs that finished before
// cutoff — at most max of them, oldest first — and returns how many it
// deleted (ADR 0027). Jobs queued or running are not touched. The file
// does not shrink: bbolt reuses the pages, so it plateaus at the
// window's high-water mark.
func (s *Store) Sweep(cutoff time.Time, max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	limit := finishedKey(cutoff, "")
	deleted := 0
	err := s.update(func(tx *bbolt.Tx) error {
		idx := tx.Bucket([]byte(bucketFinished))
		jobs := tx.Bucket([]byte(bucketJobs))
		views := tx.Bucket([]byte(bucketViews))
		var keys [][]byte
		c := idx.Cursor()
		for k, _ := c.First(); k != nil && len(keys) < max; k, _ = c.Next() {
			if len(k) < 8 || bytes.Compare(k[:8], limit[:8]) >= 0 {
				break
			}
			keys = append(keys, append([]byte(nil), k...))
		}
		for _, k := range keys {
			id := k[8:]
			if err := jobs.Delete(id); err != nil {
				return err
			}
			if err := views.Delete(id); err != nil {
				return err
			}
			if err := idx.Delete(k); err != nil {
				return err
			}
			deleted++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// Finished is the number of finished jobs on record.
func (s *Store) Finished() (int, error) {
	n := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		n = tx.Bucket([]byte(bucketFinished)).Stats().KeyN
		return nil
	})
	if err != nil {
		return 0, shared_errors.Operational(shared_errors.CodeResourceExhausted, "jobstore: count finished", err)
	}
	return n, nil
}

// Pending returns the records that are not terminal — queued or running
// — oldest submission first, then by id, so a resume admits them in the
// order they were accepted.
func (s *Store) Pending() ([]Record, error) {
	var out []Record
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketJobs)).ForEach(func(_, raw []byte) error {
			var rec Record
			if err := json.Unmarshal(raw, &rec); err != nil {
				return err
			}
			if !rec.Terminal() {
				out = append(out, rec)
			}
			return nil
		})
	})
	if err != nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted, "jobstore: list pending", err)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].SubmittedAt.Equal(out[j].SubmittedAt) {
			return out[i].SubmittedAt.Before(out[j].SubmittedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// PutView keeps the finished job's view, as GET /v1/jobs/{id} renders
// it, so the answer outlives the process.
func (s *Store) PutView(id string, view []byte) error {
	if id == "" || len(view) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "jobstore: view needs an id and a body", nil)
	}
	return s.update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketViews)).Put([]byte(id), view)
	})
}

// View returns the kept view for id, and whether there is one.
func (s *Store) View(id string) ([]byte, bool, error) {
	var out []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket([]byte(bucketViews)).Get([]byte(id))
		if raw != nil {
			out = append([]byte(nil), raw...)
		}
		return nil
	})
	if err != nil {
		return nil, false, shared_errors.Operational(shared_errors.CodeResourceExhausted, "jobstore: read view", err)
	}
	return out, out != nil, nil
}

// Len is the number of records.
func (s *Store) Len() (int, error) {
	n := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		n = tx.Bucket([]byte(bucketJobs)).Stats().KeyN
		return nil
	})
	if err != nil {
		return 0, shared_errors.Operational(shared_errors.CodeResourceExhausted, "jobstore: count", err)
	}
	return n, nil
}

func (s *Store) update(fn func(tx *bbolt.Tx) error) error {
	if s == nil || s.db == nil {
		return errors.New("jobstore: store is closed")
	}
	if err := s.db.Update(fn); err != nil {
		return shared_errors.Operational(shared_errors.CodeResourceExhausted, "jobstore: write failed", err)
	}
	return nil
}
