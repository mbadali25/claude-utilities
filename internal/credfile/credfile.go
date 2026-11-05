// Package credfile reads and atomically replaces the claudeAiOauth block of a
// Claude Code credentials file, preserving every other top-level key
// (notably mcpOAuth) byte-for-byte. It never logs or returns token values.
package credfile

import (
	"bytes"
	"crypto/sha256"
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
	oauthKey    = "claudeAiOauth"
	backupDir   = ".swap-backups"
	backupKeep  = 5
	lockSuffix  = ".swaplock"
	credName    = ".credentials.json"
	configEnv   = "CLAUDE_CONFIG_DIR"
	backupExt   = ".json"
	backupStamp = "20060102T150405.000000000Z"
	// staleLockAge is how old a .swaplock must be before it is treated as left
	// behind by a crashed process and reclaimed. A swap takes milliseconds.
	staleLockAge = 2 * time.Minute
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
		return nil, fmt.Errorf("credfile: malformed credentials file: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("credfile: credentials file is not a JSON object")
	}
	var out []entry
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("credfile: malformed credentials file: %w", err)
		}
		key, _ := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("credfile: malformed credentials file: %w", err)
		}
		out = append(out, entry{key, append(json.RawMessage(nil), raw...)})
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("credfile: malformed credentials file: %w", err)
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
		k, err := json.Marshal(e.key)
		if err != nil {
			return nil, err
		}
		b.Write(k)
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
	data, err := os.ReadFile(path)
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

// ValidateBlock checks the block has all required keys and an unexpired refresh token.
func ValidateBlock(b json.RawMessage) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("credfile: block is not a JSON object: %w", err)
	}
	var missing []string
	for _, k := range requiredKeys {
		if _, ok := m[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("credfile: block missing keys: %s", strings.Join(missing, ", "))
	}
	var ms int64
	if err := json.Unmarshal(m["refreshTokenExpiresAt"], &ms); err != nil {
		return errors.New("credfile: refreshTokenExpiresAt is not a number")
	}
	if !time.UnixMilli(ms).After(nowFn()) {
		return ErrRefreshExpired
	}
	return nil
}

// acquire takes the swap lock. A lock older than staleLockAge is assumed to
// belong to a crashed process and is reclaimed.
func acquire(path string) (release func(), err error) {
	lock := path + lockSuffix
	for attempt := 0; attempt < 3; attempt++ {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(lock) }, nil
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
		os.Remove(lock)
	}
	return nil, ErrBusy
}

func hashFile(path string) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(path)
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
// target, not the link. A path that does not exist yet is returned unchanged.
func resolvePath(path string) string {
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	return path
}

// Replace swaps only the claudeAiOauth block, after backing up the previous
// block. It returns the backup path. The block must be a JSON object; callers
// should also run ValidateBlock. Backups hold old refresh tokens at 0600 in a
// 0700 directory, are capped at backupKeep, and are retained after success by
// design so a bad swap can be undone. On Windows mode bits are not enforced;
// files inherit the parent directory's ACL.
//
// Residual race: Claude Code can write the file between the final hash check
// and the rename. ErrChangedDuringSwap narrows that window but cannot close it
// without a cross-process lock Claude Code does not take.
func Replace(path string, block json.RawMessage) (string, error) {
	if !isObject(block) {
		return "", errors.New("credfile: new block is not a JSON object")
	}
	return swap(path, block, true)
}

// Restore puts the block saved in backup back into the credentials file.
// backup must live inside the credentials file's .swap-backups directory.
func Restore(path, backup string) error {
	path = resolvePath(path)
	bd, err1 := filepath.Abs(filepath.Join(filepath.Dir(path), backupDir))
	ba, err2 := filepath.Abs(backup)
	if err1 != nil || err2 != nil {
		return errors.New("credfile: backup path not resolvable")
	}
	rel, err := filepath.Rel(bd, ba)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("credfile: backup is outside the backup directory")
	}
	data, err := os.ReadFile(ba)
	if err != nil {
		return fmt.Errorf("credfile: read backup: %w", err)
	}
	data = bytes.TrimSpace(data)
	var block json.RawMessage
	if string(data) != "null" {
		if !isObject(data) {
			return errors.New("credfile: backup is not a JSON object")
		}
		block = data
	}
	_, err = swap(path, block, false)
	return err
}

func swap(path string, block json.RawMessage, withBackup bool) (backup string, err error) {
	path = resolvePath(path)
	release, err := acquire(path)
	if err != nil {
		return "", err
	}
	defer release()

	original, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("credfile: read: %w", err)
	}
	entries, err := parseTop(original)
	if err != nil {
		return "", err
	}
	before := sha256.Sum256(original)

	if withBackup {
		prev, _ := findOAuth(entries)
		if backup, err = writeBackup(filepath.Dir(path), prev); err != nil {
			return "", err
		}
	}

	// A clean abort before the rename deletes the backup it just wrote so
	// failed attempts do not evict real history from the capped set.
	abort := func(e error) (string, error) {
		if backup != "" {
			os.Remove(backup)
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
	beforeRenameFn()
	after, herr := hashFile(path)
	if herr != nil {
		os.Remove(tmp)
		return abort(fmt.Errorf("credfile: re-read: %w", herr))
	}
	if after != before {
		os.Remove(tmp)
		return abort(ErrChangedDuringSwap)
	}
	if err := renameFn(tmp, path); err != nil {
		os.Remove(tmp)
		return backup, fmt.Errorf("credfile: rename: %w", err)
	}
	syncDir(filepath.Dir(path))
	return backup, nil
}

func writeTemp(dir string, data []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(dir, ".credentials-*.tmp")
	if err != nil {
		return "", fmt.Errorf("credfile: temp: %w", err)
	}
	name := f.Name()
	fail := func(e error) (string, error) {
		f.Close()
		os.Remove(name)
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
		os.Remove(name)
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
	data := []byte(prev)
	if prev == nil {
		data = []byte("null")
	}
	name := filepath.Join(bdir, nowFn().UTC().Format(backupStamp)+backupExt)
	for i := 1; ; i++ {
		f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, werr := f.Write(data)
			serr := f.Sync()
			cerr := f.Close()
			if err := errors.Join(werr, serr, cerr); err != nil {
				os.Remove(name)
				return "", fmt.Errorf("credfile: write backup: %w", err)
			}
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("credfile: create backup: %w", err)
		}
		name = filepath.Join(bdir, fmt.Sprintf("%s-%06d%s", nowFn().UTC().Format(backupStamp), i, backupExt))
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
		os.Remove(filepath.Join(bdir, names[i]))
		names = append(names[:i], names[i+1:]...)
	}
}
