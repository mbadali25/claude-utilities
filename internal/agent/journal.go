package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"claude-utilities/internal/credfile"
)

const (
	journalName   = "swap-journal.json"
	journalSwap   = "swapping"
	nullBlockHash = "null"
	backupDirName = ".swap-backups" // mirrors credfile's backup directory
)

// journal records an unfinished swap. It holds no secret: PrevHash is a digest of the block the
// swap replaces, NewHash a digest of the incoming block, BackupPath names the credfile backup
// once Replace has written one. Recovery only ever rolls back (it never finishes a swap), and
// only while the live block still equals NewHash: any other live block was written by someone
// else (Claude Code rotates refresh tokens) and must not be overwritten with an older backup.
type journal struct {
	State      string `json:"state"`
	BackupPath string `json:"backupPath,omitempty"`
	PrevHash   string `json:"prevHash"`
	NewHash    string `json:"newHash,omitempty"`
}

// errJournalCorrupt marks a journal file that cannot be parsed.
var errJournalCorrupt = errors.New("agent: journal unreadable")

func journalPath(stateDir string) string { return filepath.Join(stateDir, journalName) }

// hashBlock digests a raw block, ignoring whitespace; nil (no block) hashes as the JSON literal
// null, which is how credfile stores an absent block in a backup.
func hashBlock(b json.RawMessage) string {
	t := bytes.TrimSpace(b)
	if len(t) == 0 {
		t = []byte(nullBlockHash)
	}
	var c bytes.Buffer
	if json.Compact(&c, t) == nil {
		t = c.Bytes()
	}
	sum := sha256.Sum256(t)
	return hex.EncodeToString(sum[:])
}

// currentHash digests the live block. A missing file or block counts as null; any other read
// failure returns "" so a caller treats the file as not matching anything.
func currentHash(path string) string {
	b, err := credfile.ReadBlock(path)
	switch {
	case err == nil:
		return hashBlock(b)
	case errors.Is(err, credfile.ErrNoBlock), errors.Is(err, os.ErrNotExist):
		return hashBlock(nil)
	}
	return ""
}

func readJournal(stateDir string) (*journal, error) {
	data, err := os.ReadFile(journalPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agent: read journal: %w", err)
	}
	var j journal
	if err := json.Unmarshal(data, &j); err != nil || j.State != journalSwap || j.PrevHash == "" {
		return nil, errJournalCorrupt
	}
	return &j, nil
}

// quarantineJournal moves an unparseable journal aside so it cannot block swaps for ever.
func quarantineJournal(stateDir string) error {
	dst := journalPath(stateDir) + ".corrupt"
	if err := os.Rename(journalPath(stateDir), dst); err != nil {
		return fmt.Errorf("agent: quarantine journal: %w", err)
	}
	return nil
}

func writeJournal(stateDir string, j journal) error {
	data, err := json.Marshal(j)
	if err != nil {
		return fmt.Errorf("agent: marshal journal: %w", err)
	}
	return writePrivate(journalPath(stateDir), data)
}

func clearJournal(stateDir string) error {
	err := os.Remove(journalPath(stateDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("agent: clear journal: %w", err)
	}
	return nil
}

// findBackup returns the backup that restores the block with digest prevHash. A recorded path
// wins if it still holds that block; otherwise the backup directory is searched, because a
// crash can land between the credfile rename and the journal update that records the path.
func findBackup(credsPath, recorded, prevHash string) (string, bool) {
	matches := func(p string) bool {
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			return false
		}
		data, err := os.ReadFile(p)
		return err == nil && hashBlock(data) == prevHash
	}
	if recorded != "" && matches(recorded) {
		return recorded, true
	}
	dir := filepath.Dir(credsPath)
	if r, err := filepath.EvalSymlinks(credsPath); err == nil {
		dir = filepath.Dir(r)
	}
	bdir := filepath.Join(dir, backupDirName)
	ents, err := os.ReadDir(bdir)
	if err != nil {
		return "", false
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if p := filepath.Join(bdir, e.Name()); matches(p) {
			return p, true
		}
	}
	return "", false
}

// writePrivate atomically replaces path with b. The temp file is owner-only before any byte is
// written, so the content is never readable under an inherited ACL.
func writePrivate(path string, b []byte) (err error) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	f, err := os.CreateTemp(dir, "."+base+"-*.tmp")
	if err != nil {
		return fmt.Errorf("agent: write %s: %w", base, err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Close(); err != nil {
		return fmt.Errorf("agent: write %s: %w", base, err)
	}
	if err = credfile.RestrictFile(tmp); err != nil {
		return fmt.Errorf("agent: restrict %s: %w", base, err)
	}
	f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("agent: write %s: %w", base, err)
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("agent: write %s: %w", base, err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("agent: replace %s: %w", base, err)
	}
	credfile.SyncDir(dir)
	return nil
}
