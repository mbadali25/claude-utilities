// Package credfile reads and atomically replaces the claudeAiOauth block of a
// Claude Code credentials file, preserving every other top-level key
// (notably mcpOAuth) byte-for-byte. It never logs or returns token values.
package credfile

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	oauthKey   = "claudeAiOauth"
	backupDir  = ".swap-backups"
	backupKeep = 5
	lockSuffix = ".swaplock"
	// reclaimSuffix names the guard that serialises stale-lock reclaim.
	reclaimSuffix = ".reclaim"
	credName      = ".credentials.json"
	configEnv     = "CLAUDE_CONFIG_DIR"
	backupExt     = ".json"
	backupStamp   = "20060102T150405.000000000Z"
	// maxBackupCollisions bounds the -NNNNNN suffix search for a free backup name.
	maxBackupCollisions = 100000
	// staleLockAge is how old a .swaplock must be before it is treated as left
	// behind by a crashed process and reclaimed. A swap takes milliseconds.
	staleLockAge = 2 * time.Minute
	// maxExpiryMs bounds refreshTokenExpiresAt before the float64 to int64 conversion.
	maxExpiryMs = 1e15
	tempPattern = ".credentials-*.tmp"
)

var (
	// ErrBusy means another swap holds the lock file.
	ErrBusy = errors.New("credfile: another swap is in progress")
	// ErrNoBlock means the file has no claudeAiOauth block.
	ErrNoBlock = errors.New("credfile: no claudeAiOauth block")
	// ErrChangedDuringSwap means the file changed after we read it; nothing was written.
	ErrChangedDuringSwap = errors.New("credfile: credentials file changed during swap")
	// ErrRefreshExpired means the block's refresh token is already expired.
	ErrRefreshExpired = errors.New("credfile: refresh token expired")

	// errMalformed is fixed text: encoding/json errors can quote file content.
	errMalformed = errors.New("credfile: malformed credentials file")
)

// requiredKeys are the keys every claudeAiOauth block must carry.
var requiredKeys = []string{
	"accessToken", "refreshToken", "expiresAt", "refreshTokenExpiresAt",
	"scopes", "subscriptionType", "subscriptionTypeSource", "rateLimitTier",
}

// Test seams.
var (
	renameFn       = os.Rename
	beforeRenameFn = func() {}
	nowFn          = time.Now
	// afterBackupFn runs right after the backup is written, before the temp file.
	afterBackupFn = func(string) {}
)

// ResolvePath returns the credentials file path, honouring CLAUDE_CONFIG_DIR.
func ResolvePath() (string, error) {
	if dir := os.Getenv(configEnv); dir != "" {
		return filepath.Join(dir, credName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("credfile: resolve home: %w", err)
	}
	return filepath.Join(home, ".claude", credName), nil
}

// entry is one top-level key with its raw, untouched value.
type entry struct {
	key string
	val json.RawMessage
}

// parseTop decodes a top-level JSON object keeping key order and raw values.
// Empty (or whitespace-only) input yields no entries.
func parseTop(data []byte) ([]entry, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, errMalformed
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("credfile: credentials file is not a JSON object")
	}
	var out []entry
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, errMalformed
		}
		key, _ := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, errMalformed
		}
		out = append(out, entry{key, append(json.RawMessage(nil), raw...)})
	}
	if _, err := dec.Token(); err != nil {
		return nil, errMalformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("credfile: trailing data in credentials file")
	}
	return out, nil
}

func encodeTop(entries []entry) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, e := range entries {
		if i > 0 {
			b.WriteByte(',')
		}
		var kb bytes.Buffer
		enc := json.NewEncoder(&kb)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(e.key); err != nil {
			return nil, err
		}
		b.Write(bytes.TrimSuffix(kb.Bytes(), []byte("\n")))
		b.WriteByte(':')
		b.Write(e.val)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// setOAuth returns entries with claudeAiOauth set to block (nil block removes it).
func setOAuth(entries []entry, block json.RawMessage) []entry {
	out := make([]entry, 0, len(entries)+1)
	done := false
	for _, e := range entries {
		if e.key == oauthKey {
			if !done && block != nil {
				out = append(out, entry{oauthKey, block})
			}
			done = true
			continue
		}
		out = append(out, e)
	}
	if !done && block != nil {
		out = append(out, entry{oauthKey, block})
	}
	return out
}

func findOAuth(entries []entry) (json.RawMessage, bool) {
	for _, e := range entries {
		if e.key == oauthKey {
			return e.val, true
		}
	}
	return nil, false
}

// ReadBlock returns the raw claudeAiOauth value, or ErrNoBlock if absent.
func ReadBlock(path string) (json.RawMessage, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("credfile: read: %w", err)
	}
	entries, err := parseTop(data)
	if err != nil {
		return nil, err
	}
	b, ok := findOAuth(entries)
	if !ok || string(bytes.TrimSpace(b)) == "null" {
		return nil, ErrNoBlock
	}
	return b, nil
}

// checkShape verifies b is an object carrying every required key with a
// non-null value, and returns its fields.
func checkShape(b json.RawMessage) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return nil, errors.New("credfile: block is not a JSON object")
	}
	var missing []string
	for _, k := range requiredKeys {
		if v, ok := m[k]; !ok || string(bytes.TrimSpace(v)) == "null" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("credfile: block missing keys: %s", strings.Join(missing, ", "))
	}
	return m, nil
}

// ValidateBlock checks the block has all required keys (non-null) and an
// unexpired refresh token. refreshTokenExpiresAt may be any JSON number.
func ValidateBlock(b json.RawMessage) error {
	m, err := checkShape(b)
	if err != nil {
		return err
	}
	var ms float64
	if err := json.Unmarshal(m["refreshTokenExpiresAt"], &ms); err != nil {
		return errors.New("credfile: refreshTokenExpiresAt is not a number")
	}
	// Converting a float64 outside the int64 range is implementation-defined, so
	// reject anything beyond a sane millisecond timestamp (about year 33658).
	if ms != ms || ms > maxExpiryMs || ms < -maxExpiryMs {
		return errors.New("credfile: refreshTokenExpiresAt out of range")
	}
	if !time.UnixMilli(int64(ms)).After(nowFn()) {
		return ErrRefreshExpired
	}
	return nil
}

// newToken returns a random owner token for a lock file.
func newToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", nowFn().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// acquire takes the swap lock. The lock file holds a random owner token and
// release only removes the file while it still carries that token. A lock older
// than staleLockAge is assumed to belong to a crashed process and is reclaimed;
// reclaimers are serialised by a second O_EXCL guard file and re-check the
// lock's age under that guard, so one reclaimer cannot delete a lock another
// reclaimer has just taken.
func acquire(path string) (release func(), err error) {
	lock := path + lockSuffix
	token := newToken()
	for attempt := 0; attempt < 3; attempt++ {
		f, err := os.OpenFile(filepath.Clean(lock), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, werr := f.WriteString(token)
			cerr := f.Close()
			if e := errors.Join(werr, cerr); e != nil {
				removeQuiet(lock)
				return nil, fmt.Errorf("credfile: lock: %w", e)
			}
			return func() {
				if data, rerr := os.ReadFile(filepath.Clean(lock)); rerr == nil && string(data) == token {
					removeQuiet(lock)
				}
			}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("credfile: lock: %w", err)
		}
		st, serr := os.Stat(lock)
		if serr != nil {
			continue // lock vanished between open and stat; retry
		}
		if time.Since(st.ModTime()) < staleLockAge {
			return nil, ErrBusy
		}
		if !reclaimStale(lock) {
			return nil, ErrBusy
		}
	}
	return nil, ErrBusy
}

// reclaimStale removes a stale lock under an exclusive guard. It reports false
// when another reclaimer holds the guard.
func reclaimStale(lock string) bool {
	guard := lock + reclaimSuffix
	g, err := os.OpenFile(filepath.Clean(guard), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		// A guard left by a crashed reclaimer would block forever: age it out.
		if st, serr := os.Stat(guard); serr == nil && time.Since(st.ModTime()) >= staleLockAge {
			removeQuiet(guard)
		}
		return false
	}
	_ = g.Close()
	defer removeQuiet(guard)
	// Re-check under the guard: the lock may have been replaced by a fresh one.
	if st, serr := os.Stat(lock); serr == nil && time.Since(st.ModTime()) >= staleLockAge {
		removeQuiet(lock)
	}
	return true
}

func hashFile(path string) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return sha256.Sum256(nil), nil
	}
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// isObject reports whether b is a valid JSON object.
func isObject(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && t[0] == '{' && json.Valid(t)
}

// resolvePath follows a symlinked credentials file so the swap replaces the
// target, not the link. A path that does not exist yet is returned unchanged;
// a dangling symlink is an error.
func resolvePath(path string) (string, error) {
	r, err := filepath.EvalSymlinks(path)
	if err == nil {
		return r, nil
	}
	// A dangling symlink must not be replaced by a regular file.
	if st, lerr := os.Lstat(path); lerr == nil && st.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("credfile: credentials path is a dangling symlink")
	}
	return path, nil
}

// Replace swaps only the claudeAiOauth block, after backing up the previous
// block. It returns the backup path. On a rename failure the backup is kept and
// returned with the error; on every other failure the path is "". Callers should
// treat the path as meaningful only when it names an existing file. The block must be a JSON object; callers
// should also run ValidateBlock. Backups hold old refresh tokens at 0600 in a
// 0700 directory, are capped at backupKeep, and are retained after success by
// design so a bad swap can be undone. On Windows owner-only ACLs (icacls) replace
// the mode bits for the temp file, backup directory and backups.
//
// On Unix, when the agent runs as root the new file, the backup directory and the
// backup keep the replaced file's uid and gid, so a swap done for another user
// does not leave that user locked out of their own credentials. A chown that
// fails aborts the swap rather than installing a root-owned file.
//
// Residual race: Claude Code can write the file between the final hash check
// and the rename. ErrChangedDuringSwap narrows that window but cannot close it
// without a cross-process lock Claude Code does not take.
func Replace(path string, block json.RawMessage) (string, error) {
	return ReplaceWith(path, block, nil)
}

// ReplaceWith is Replace plus a callback that receives the block being replaced (nil when there is
// none) as read under the swap lock, before the backup is written. A caller that journals the
// swap derives its pre-swap digest there, so a refresh between its own earlier read and the lock
// cannot desynchronise the digest from the backup. A callback error aborts with nothing written.
func ReplaceWith(path string, block json.RawMessage, onPrev func(prev json.RawMessage) error) (string, error) {
	if !isObject(block) {
		return "", errors.New("credfile: new block is not a JSON object")
	}
	return swap(path, block, true, onPrev)
}

// Restore puts the block saved in backup back into the credentials file.
// backup must live inside the credentials file's .swap-backups directory.
func Restore(path, backup string) error {
	path, rerr := resolvePath(path)
	if rerr != nil {
		return rerr
	}
	bd, err1 := filepath.Abs(filepath.Join(filepath.Dir(path), backupDir))
	ba, err2 := filepath.Abs(backup)
	if err1 != nil || err2 != nil {
		return errors.New("credfile: backup path not resolvable")
	}
	if err := requireRealDir(bd); err != nil {
		return err
	}
	rel, err := filepath.Rel(bd, ba)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("credfile: backup is outside the backup directory")
	}
	// Reject symlinks and other non-regular files: confinement above is lexical.
	if st, lerr := os.Lstat(ba); lerr != nil || !st.Mode().IsRegular() {
		return errors.New("credfile: backup is not a regular file")
	}
	data, err := os.ReadFile(filepath.Clean(ba))
	if err != nil {
		return fmt.Errorf("credfile: read backup: %w", err)
	}
	data = bytes.TrimSpace(data)
	var block json.RawMessage
	if string(data) != "null" {
		if !isObject(data) {
			return errors.New("credfile: backup is not a JSON object")
		}
		// Shape only: an old block may legitimately hold an expired refresh token.
		if _, serr := checkShape(data); serr != nil {
			return fmt.Errorf("credfile: backup rejected: %w", serr)
		}
		block = data
	}
	// The current block is backed up first, so a restore can itself be undone.
	_, err = swap(path, block, true, nil)
	return err
}

// requireRealDir fails unless dir is a real directory, not a symlink: a
// symlinked backup dir would send token backups (and chmod) elsewhere.
func requireRealDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("credfile: backup dir: %w", err)
	}
	if !st.IsDir() {
		return errors.New("credfile: backup dir is not a real directory")
	}
	return nil
}

// removeQuiet deletes a file on a best-effort cleanup path: the caller is already
// returning its own error or the file is optional, so a failed delete is not actionable.
func removeQuiet(p string) { _ = os.Remove(p) }

// removeStaleTemps deletes leftover temp files (they may hold live tokens) from
// a crash between writeTemp and rename. Called under the swap lock; only temps
// older than staleLockAge go, so a concurrent writer is never affected.
func removeStaleTemps(dir string) {
	matches, _ := filepath.Glob(filepath.Join(dir, tempPattern))
	for _, m := range matches {
		if st, err := os.Lstat(m); err == nil && st.Mode().IsRegular() && time.Since(st.ModTime()) >= staleLockAge {
			removeQuiet(m)
		}
	}
}

func swap(path string, block json.RawMessage, withBackup bool, onPrev func(json.RawMessage) error) (backup string, err error) {
	path, err = resolvePath(path)
	if err != nil {
		return "", err
	}
	release, err := acquire(path)
	if err != nil {
		return "", err
	}
	defer release()
	removeStaleTemps(filepath.Dir(path))

	original, err := os.ReadFile(filepath.Clean(path))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("credfile: read: %w", err)
	}
	entries, err := parseTop(original)
	if err != nil {
		return "", err
	}
	before := sha256.Sum256(original)
	// The owner of the file being replaced, so a root agent swapping for another
	// user hands every file it writes back to that user. nil when there is no
	// file yet, or it cannot be stat'ed: then the default owner stands.
	var owner os.FileInfo
	if fi, serr := os.Stat(filepath.Clean(path)); serr == nil {
		owner = fi
	}

	if withBackup {
		prev, _ := findOAuth(entries)
		if onPrev != nil {
			if err = onPrev(prev); err != nil {
				return "", fmt.Errorf("credfile: pre-swap hook: %w", err)
			}
		}
		if backup, err = writeBackup(filepath.Dir(path), prev); err != nil {
			return "", err
		}
		// A root-owned .swap-backups breaks the next non-root swap outright: its
		// os.Chmod on the directory fails and writeBackup returns an error.
		if err = preserveOwner(filepath.Dir(backup), owner); err != nil {
			removeQuiet(backup)
			return "", err
		}
		if err = preserveOwner(backup, owner); err != nil {
			removeQuiet(backup)
			return "", err
		}
		afterBackupFn(backup)
	}

	// A clean abort before the rename deletes the backup it just wrote so
	// failed attempts do not evict real history from the capped set.
	abort := func(e error) (string, error) {
		if backup != "" {
			removeQuiet(backup)
		}
		return "", e
	}
	out, err := encodeTop(setOAuth(entries, block))
	if err != nil {
		return abort(err)
	}
	// Always 0600: never inherit a looser mode from the existing file.
	tmp, err := writeTemp(filepath.Dir(path), out, 0o600)
	if err != nil {
		return abort(err)
	}
	// Before the rename, never after: a file renamed into place with the wrong
	// owner is already the breakage, and there is no second chance to fix it.
	if err := preserveOwner(tmp, owner); err != nil {
		removeQuiet(tmp)
		return abort(err)
	}
	beforeRenameFn()
	after, herr := hashFile(path)
	if herr != nil {
		removeQuiet(tmp)
		return abort(fmt.Errorf("credfile: re-read: %w", herr))
	}
	if after != before {
		removeQuiet(tmp)
		return abort(ErrChangedDuringSwap)
	}
	if err := renameFn(tmp, path); err != nil {
		removeQuiet(tmp)
		return backup, fmt.Errorf("credfile: rename: %w", err)
	}
	syncDir(filepath.Dir(path))
	return backup, nil
}

func writeTemp(dir string, data []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(dir, tempPattern)
	if err != nil {
		return "", fmt.Errorf("credfile: temp: %w", err)
	}
	name := f.Name()
	// Lock the ACL down before any token bytes are written (Windows).
	if err := restrictACL(name, false); err != nil {
		_ = f.Close()
		removeQuiet(name)
		return "", err
	}
	fail := func(e error) (string, error) {
		_ = f.Close()
		removeQuiet(name)
		return "", fmt.Errorf("credfile: write temp: %w", e)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Chmod(mode); err != nil && !isWindows {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		removeQuiet(name)
		return "", fmt.Errorf("credfile: close temp: %w", err)
	}
	return name, nil
}

// writeBackup stores the previous block (or null) at 0600 and prunes old backups.
func writeBackup(dir string, prev json.RawMessage) (string, error) {
	bdir := filepath.Join(dir, backupDir)
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		return "", fmt.Errorf("credfile: backup dir: %w", err)
	}
	if err := requireRealDir(bdir); err != nil {
		return "", err
	}
	if err := restrictACL(bdir, true); err != nil {
		return "", err
	}
	// MkdirAll does not tighten a pre-existing directory; backups hold old refresh tokens.
	if !isWindows {
		if err := os.Chmod(bdir, 0o700); err != nil { // #nosec G302 -- directory needs the owner execute bit; 0o700 is owner-only
			return "", fmt.Errorf("credfile: backup dir mode: %w", err)
		}
	}
	data := []byte(prev)
	if prev == nil {
		data = []byte("null")
	}
	created := false
	name := filepath.Join(bdir, nowFn().UTC().Format(backupStamp)+backupExt)
	for i := 1; i <= maxBackupCollisions; i++ {
		f, err := os.OpenFile(filepath.Clean(name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, werr := f.Write(data)
			serr := f.Sync()
			cerr := f.Close()
			if err := errors.Join(werr, serr, cerr); err != nil {
				removeQuiet(name)
				return "", fmt.Errorf("credfile: write backup: %w", err)
			}
			created = true
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("credfile: create backup: %w", err)
		}
		name = filepath.Join(bdir, fmt.Sprintf("%s-%06d%s", nowFn().UTC().Format(backupStamp), i, backupExt))
	}
	if !created {
		return "", errors.New("credfile: too many backup name collisions")
	}
	pruneBackups(bdir, filepath.Base(name))
	return name, nil
}

// pruneBackups keeps the newest backupKeep files, never removing keep (the
// backup just written). Names sort by stem so "X" < "X-000001" < "X-000002";
// sorting the raw name would put "X-1.json" before "X.json" ('-' < '.').
func pruneBackups(bdir, keep string) {
	ents, err := os.ReadDir(bdir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), backupExt) {
			names = append(names, e.Name())
		}
	}
	stem := func(n string) string { return strings.TrimSuffix(n, backupExt) }
	sort.Slice(names, func(a, b int) bool { return stem(names[a]) < stem(names[b]) })
	for len(names) > backupKeep {
		i := 0
		if names[0] == keep {
			i = 1
		}
		removeQuiet(filepath.Join(bdir, names[i]))
		names = append(names[:i], names[i+1:]...)
	}
}
