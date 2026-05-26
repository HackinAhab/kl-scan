// Package state implements a persistent, single-instance dedup store for
// kl-scan findings.
//
// The store is an append-only NDJSON file protected by a non-blocking flock,
// so two concurrent kl-scan processes pointing at the same path will be
// rejected with ErrAlreadyRunning. Each record is keyed by
//
//	<podUID>|<detector>|<ruleID>|<sha256(value)>
//
// On Open(), the existing file is replayed into an in-memory sync.Map so the
// caller can ask "have we ever seen this finding before?" via MarkSeen.
// MarkSeen only appends a new line when the key is genuinely new — already
// known keys are silently suppressed (per the user requirement: "we shouldn't
// keep re-writing the same secrets unless it's a different source").
package state

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// ErrAlreadyRunning is returned by Open when another process holds the flock.
var ErrAlreadyRunning = errors.New("state file is locked by another kl-scan process")

// Record is the on-disk representation of a single dedup entry.
type Record struct {
	Key       string    `json:"k"`
	Namespace string    `json:"ns,omitempty"`
	Pod       string    `json:"pod,omitempty"`
	Container string    `json:"container,omitempty"`
	Detector  string    `json:"detector,omitempty"`
	Rule      string    `json:"rule,omitempty"`
	First     time.Time `json:"first"`
}

// Store is a flock'd append-only NDJSON dedup store.
type Store struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	enc      *json.Encoder
	seen     map[string]struct{}
	disabled bool
}

// Open opens (or creates) the state file at path, acquires an exclusive
// non-blocking flock, and replays existing records into memory.
//
// Pass disabled=true to skip file IO entirely; the returned Store still
// satisfies the API but tracks dedup keys only in memory for the lifetime of
// the process.
func Open(path string, disabled bool) (*Store, error) {
	s := &Store{
		path:     path,
		seen:     make(map[string]struct{}),
		disabled: disabled,
	}
	if disabled {
		return s, nil
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open state file %q: %w", path, err)
	}

	// Single-instance: non-blocking exclusive flock.
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("flock state file %q: %w", path, err)
	}

	// Replay existing entries to seed the seen map.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
		return nil, fmt.Errorf("seek state file: %w", err)
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			// Corrupt line: ignore but don't abort — let the caller continue.
			continue
		}
		if r.Key != "" {
			s.seen[r.Key] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
		return nil, fmt.Errorf("replay state file: %w", err)
	}

	// Position writes at end of file (append).
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
		return nil, fmt.Errorf("seek-end state file: %w", err)
	}

	s.f = f
	s.enc = json.NewEncoder(f)
	s.enc.SetEscapeHTML(false)
	return s, nil
}

// Path returns the on-disk path (empty string if disabled).
func (s *Store) Path() string {
	if s.disabled {
		return ""
	}
	return s.path
}

// SeenCount returns the number of unique dedup keys known to the store.
func (s *Store) SeenCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// MarkSeen records that the given key has been observed. Returns true if the
// key is new (and thus the caller should emit the finding); false if it was
// already known (suppress).
//
// On a new key, when the store is enabled, the record is appended to disk.
// Already-seen keys are never rewritten, satisfying the project's "don't keep
// re-writing the same secrets" rule.
func (s *Store) MarkSeen(r Record) (isNew bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.seen[r.Key]; ok {
		return false, nil
	}
	s.seen[r.Key] = struct{}{}

	if s.disabled || s.f == nil {
		return true, nil
	}

	if r.First.IsZero() {
		r.First = time.Now().UTC()
	}
	if err := s.enc.Encode(r); err != nil {
		return true, fmt.Errorf("append state record: %w", err)
	}
	// Best-effort fsync so a crash doesn't lose the most recent records.
	_ = s.f.Sync()
	return true, nil
}

// Close releases the flock and closes the underlying file. Safe to call
// multiple times.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.f == nil {
		return nil
	}
	_ = unix.Flock(int(s.f.Fd()), unix.LOCK_UN)
	err := s.f.Close()
	s.f = nil
	return err
}
