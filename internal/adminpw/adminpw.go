// Package adminpw stores the admin UI password as an argon2id hash in one file in the data dir.
//
// A stored hash always wins: the bootstrap value (the CLAUDESWAP_ADMIN_PASSWORD environment
// variable) authenticates only while no hash file exists. Comparisons are constant time, the file
// is replaced atomically at 0600 (owner-only ACL on Windows), and the password itself is never
// written, logged or returned.
package adminpw

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"claude-utilities/internal/credfile"
)

const (
	// MinLength is the shortest admin password accepted, counted in characters.
	MinLength = 12
	// FileName is the hash file's name inside the data directory.
	FileName = "admin-password.json"

	version   = 1
	algo      = "argon2id"
	saltLen   = 16
	keyLen    = 32
	argonTime = 3
	argonMem  = 64 * 1024 // KiB
	argonPar  = 4

	// maxMemKiB caps the memory a file may ask argon2 for, so a tampered record cannot make
	// verification allocate without bound.
	maxMemKiB = 1 << 20 // 1 GiB
	// minMemKiB is argon2's own floor (8 KiB per lane).
	minMemKiB = 8
	// maxFile bounds the hash file: it holds one small JSON record.
	maxFile = 4 << 10
)

var (
	// ErrTooShort means the password is shorter than MinLength characters.
	ErrTooShort = fmt.Errorf("adminpw: password must be at least %d characters", MinLength)

	// errCorrupt is fixed text: a decoder error can quote file content.
	errCorrupt = errors.New("adminpw: malformed admin password file")

	// renameFn is replaced in tests to inject write failures.
	renameFn = os.Rename
)

// record is the stored hash and the parameters it was derived with. Verification uses the
// record's own parameters, so a file written by an older build keeps working.
type record struct {
	Version int    `json:"v"`
	Algo    string `json:"algo"`
	Time    uint32 `json:"time"`
	MemKiB  uint32 `json:"memKiB"`
	Par     uint8  `json:"par"`
	Salt    []byte `json:"salt"`
	Hash    []byte `json:"hash"`
}

// check rejects a record this build cannot verify or should not trust.
func (r *record) check() error {
	switch {
	case r.Version != version, r.Algo != algo:
		return errCorrupt
	case r.Time < 1, r.Par < 1:
		return errCorrupt
	case r.MemKiB < minMemKiB, r.MemKiB > maxMemKiB:
		return errCorrupt
	case len(r.Salt) != saltLen, len(r.Hash) != keyLen:
		return errCorrupt
	}
	return nil
}

// match reports, in constant time, whether password derives this record's hash. check has
// already pinned the hash to keyLen bytes, so the length is not read back from the file.
func (r *record) match(password string) bool {
	got := argon2.IDKey([]byte(password), r.Salt, r.Time, r.MemKiB, r.Par, keyLen)
	return subtle.ConstantTimeCompare(got, r.Hash) == 1
}

// Store is the admin password, file-backed and safe for concurrent use.
type Store struct {
	mu        sync.Mutex
	path      string
	bootstrap string
	rec       *record // nil while no hash file exists
}

// Open reads the hash file at path if it exists. bootstrap authenticates only while no hash is
// stored; pass "" when there is none. A missing file is not an error: the store falls back to
// bootstrap and the first Set writes the file. A malformed file is an error, so a tampered or
// truncated record fails loudly instead of silently reviving the environment variable.
func Open(path, bootstrap string) (*Store, error) {
	s := &Store{path: path, bootstrap: bootstrap}
	data, err := os.ReadFile(filepath.Clean(path))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("adminpw: read: %w", err)
	case len(data) > maxFile:
		return nil, errCorrupt
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, errCorrupt
	}
	if err := rec.check(); err != nil {
		return nil, err
	}
	s.rec = &rec
	return s, nil
}

// Stored reports whether a hash backs this store, in which case the bootstrap is ignored.
func (s *Store) Stored() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec != nil
}

// Verify reports whether password authenticates. An empty password never does, so a blank form
// field cannot match an unset bootstrap.
func (s *Store) Verify(password string) bool {
	if password == "" {
		return false
	}
	s.mu.Lock()
	rec, bootstrap := s.rec, s.bootstrap
	s.mu.Unlock()
	if rec != nil { // the stored hash wins; the bootstrap is dead once one exists
		return rec.match(password)
	}
	if bootstrap == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(password), []byte(bootstrap)) == 1
}

// Set hashes password and replaces the file atomically. A password shorter than MinLength
// characters is refused with ErrTooShort and nothing is written. A failed write leaves the
// previous password in force.
func (s *Store) Set(password string) error {
	if utf8.RuneCountInString(password) < MinLength {
		return ErrTooShort
	}
	rec := &record{Version: version, Algo: algo, Time: argonTime, MemKiB: argonMem, Par: argonPar,
		Salt: make([]byte, saltLen)}
	if _, err := rand.Read(rec.Salt); err != nil {
		return fmt.Errorf("adminpw: salt: %w", err)
	}
	rec.Hash = argon2.IDKey([]byte(password), rec.Salt, rec.Time, rec.MemKiB, rec.Par, keyLen)
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("adminpw: encode: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeFile(s.path, data); err != nil {
		return err
	}
	s.rec = rec
	return nil
}

// writeFile replaces path atomically at 0600, with an owner-only ACL on Windows where the mode
// bits do nothing.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("adminpw: data dir: %w", err)
	}
	if err := credfile.RestrictDir(dir); err != nil {
		return fmt.Errorf("adminpw: restrict data dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".adminpw-*.tmp")
	if err != nil {
		return fmt.Errorf("adminpw: temp: %w", err)
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		removeQuiet(name)
		return fmt.Errorf("adminpw: write: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return fail(err)
	}
	if err := credfile.RestrictFile(name); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		removeQuiet(name)
		return fmt.Errorf("adminpw: close: %w", err)
	}
	if err := renameFn(name, path); err != nil {
		removeQuiet(name)
		return fmt.Errorf("adminpw: rename: %w", err)
	}
	credfile.SyncDir(dir)
	return nil
}

// removeQuiet deletes a temp file on a failure path that already returns its own error, so a
// failed delete is not actionable.
func removeQuiet(p string) { _ = os.Remove(p) }
