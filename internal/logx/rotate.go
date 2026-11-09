package logx

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"claude-utilities/internal/credfile"
)

const (
	// DefaultLogMaxBytes and DefaultLogKeep are the service's explicit retention: 10 MiB a file,
	// five files, a 50 MiB cap. Never-expire is a cost leak, so the numbers live here and the
	// service entry points take them from here rather than each naming their own.
	DefaultLogMaxBytes int64 = 10 << 20
	DefaultLogKeep           = 5
)

// ErrWriterClosed is returned by a write after Close. A late line gets an error rather than a panic
// or a silent drop, because the shutdown path logs too.
var ErrWriterClosed = errors.New("logx: the rotating writer is closed")

// rotatingWriter is the service's log file: a size check on write and a rename chain, stdlib only.
// A service has no console, so this is where the JSON lines go; `logx.New` still applies the
// allowlist and the redaction, which is the whole reason the service logs through logx and not
// through its own handler.
type rotatingWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	size     int64
	closed   bool
}

// NewRotatingWriter opens path for appending and keeps it under maxBytes, renaming path to path.1,
// path.1 to path.2 and so on, keeping keep files in all (the live file plus keep-1 rotations) and
// deleting what falls off the end.
//
// The size of an existing file counts: a service restart must not reset the accounting, or a log
// already at the cap would grow until the next restart. The directory is created owner-only and
// every file it writes is owner-only - a log line carries whatever a log line carries.
func NewRotatingWriter(path string, maxBytes int64, keep int) (io.WriteCloser, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("logx: maxBytes must be positive, got %d", maxBytes)
	}
	if keep < 1 {
		return nil, fmt.Errorf("logx: keep must be at least 1, got %d", keep)
	}
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := credfile.RestrictDir(dir); err != nil {
		return nil, err
	}
	w := &rotatingWriter{path: path, maxBytes: maxBytes, keep: keep}
	if err := w.open(); err != nil {
		return nil, err
	}
	w.pruneAboveTheChain()
	return w, nil
}

// pruneAboveTheChain deletes path.N for every N at or above keep. The rename chain only ever touches
// .1 … keep-1, so a generation above it is never renamed over and never deleted - and a retention
// that leaves a file behind for ever is not an explicit retention. The real source is a run with a
// larger keep, or a keep this repo lowers later.
//
// A failure is not reported: it is housekeeping, and a stray file an operator holds open must not
// stop a service from logging. A suffix that is not a generation number (server.log.old) is left
// alone - this writer deletes only what it could have written.
func (w *rotatingWriter) pruneAboveTheChain() {
	matches, err := filepath.Glob(w.path + ".*")
	if err != nil {
		return
	}
	for _, m := range matches {
		n, err := strconv.Atoi(strings.TrimPrefix(m, w.path+"."))
		if err != nil || n < w.keep {
			continue
		}
		_ = os.Remove(m)
	}
}

// open attaches to the live file and reads its current size.
func (w *rotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := credfile.RestrictFile(w.path); err != nil {
		_ = f.Close()
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.f, w.size = f, fi.Size()
	return nil
}

// Write appends p, rotating first when p would take the file past the cap. A line larger than the
// cap is written whole: splitting it would corrupt a JSON line, and dropping it would lose the one
// line a reader needs. It rotates once for such a line and not in a loop, because an empty live
// file is never rotated.
func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, ErrWriterClosed
	}
	if w.size > 0 && w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate closes the live file, shifts the chain down by one, drops the oldest and opens a new live
// file. It runs under the same lock as the write, so no goroutine can write to the file it closes.
//
// The live file is reopened whatever the shift did. A shift that returned early with the file closed
// would break every later write for the lifetime of the process - the next one would try to rotate a
// closed file and fail on the close - so one stray directory or one .1 another process holds open on
// Windows would silence a service's log for good. Reopening instead leaves the size at the cap, so
// the next write retries the whole rotation and the writer heals itself once the obstruction clears.
func (w *rotatingWriter) rotate() error {
	if err := w.f.Close(); err != nil {
		return err
	}
	shifted := w.shift()
	if err := w.open(); err != nil {
		return errors.Join(shifted, err)
	}
	return shifted
}

// shift moves the chain down by one and drops the oldest generation.
//
// A missing generation is not an error: the chain is short-lived and a file an operator moved aside
// must not stop the service from logging.
func (w *rotatingWriter) shift() error {
	if w.keep == 1 {
		// The live file only: truncate by replacing it.
		if err := os.Remove(w.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	oldest := w.generation(w.keep - 1)
	if err := os.Remove(oldest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for i := w.keep - 2; i >= 1; i-- {
		if err := os.Rename(w.generation(i), w.generation(i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(w.path, w.generation(1)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// generation names the nth rotation: server.log.1 … server.log.<keep-1>.
func (w *rotatingWriter) generation(n int) string {
	return fmt.Sprintf("%s.%d", w.path, n)
}

// Close closes the live file. It is idempotent: the shutdown path may run twice, and a second close
// must not report a failure the operator cannot act on.
func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.f.Close()
}
