package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"claude-utilities/internal/credfile"
)

// This file holds the one data-dir lock: whoever may write the vault, the keyring or the journal
// holds it, and nobody else may. Neither vault.bin nor tunnelkeys.bin had a lock before v2 added
// CLI mutators, and the repository's existing precedent - credfile.acquire's O_EXCL lock file plus
// a staleness age - is deliberately not what this is. An OS lock on an open handle dies with the
// process, so a server that runs for months never needs a reclaim age, and a crash leaves nothing
// to clean up. The pid in the lock file is for the error message only; the OS lock is the arbiter.
//
// Who takes it: `server run` for its whole lifetime, acquired before EnsureCert, and every vault
// mutator (init, migrate, add-slot, remove-slot, rotate, change-passphrase, downgrade,
// finalize-migration, purge-backups) for the length of the command. `vault status` and
// `vault verify` are read-only and take no lock.

const (
	// LockFileName is the lock file's name inside the data dir.
	LockFileName = ".claude-swap.lock"

	// lockOffset is the single byte the OS lock covers, and lockLen its length.
	//
	// One byte at 1 TiB, not the whole file, because Windows byte-range locks are mandatory: a
	// ReadFile overlapping another process's exclusive range fails with ERROR_LOCK_VIOLATION, so a
	// whole-file lock would hide the holder's pid from the one process that has to print it. The
	// offset is past any plausible metadata and is never written to, so the file stays a few
	// hundred bytes - locking beyond the end of a file does not extend it. On Linux flock is
	// whole-file, so the offset is irrelevant there and reads are never blocked either way.
	lockOffset uint64 = 1 << 40
	lockLen    uint64 = 1

	// lockMetaMax bounds the holder line: it lives in the first 4 KiB, far below lockOffset, so a
	// contender's read never touches the locked byte.
	lockMetaMax = 4 << 10

	// lockCmdMax bounds a command name read back from the file. The line is attacker-writable -
	// anyone who can write the data dir can put anything in it - and it ends up in a message an
	// operator reads, so a long or unprintable value is treated as no metadata at all.
	lockCmdMax = 32
)

// ErrLockHeld marks the one failure the lock exists to report: someone else holds it. It is the
// sentinel a caller matches with errors.Is; the text an operator sees comes from the returned
// error, which carries the holder's pid when the holder line could be read and the lock file's
// path when it could not. The CLI maps it to exit 2.
var ErrLockHeld = errors.New("vault: the data-dir lock is held by another process")

// ErrLockPathNotRegular marks a lock path that is not a plain file: a symlink, a directory, a
// device node. It matters because the lock file is opened for writing, truncated, and then handed
// to credfile.RestrictFile by path - so a link planted at the lock path by anyone who can write the
// data dir would make all three happen to whatever it points at. Refusing is the only safe answer:
// there is no legitimate reason for the data dir's lock to be anything but a file.
var ErrLockPathNotRegular = errors.New("vault: the lock path is not a regular file")

// heldError carries the operator-facing message while still matching ErrLockHeld.
type heldError struct{ msg string }

func (e heldError) Error() string { return e.msg }
func (e heldError) Unwrap() error { return ErrLockHeld }

// Seams. restrictFile is credfile.RestrictFile, and proveExclusive is the per-OS check that the
// lock the OS just gave is one this process may rely on; both are replaced in tests, the way
// renameFn, randRead and nowFn already are. There is no test machine with an NFS mount and a
// mapped drive, so the refusal path has to be forceable.
var (
	restrictFile   = credfile.RestrictFile
	restrictDir    = credfile.RestrictDir
	proveExclusive = osProveExclusive
)

// errLockBusy is what the per-OS lock call returns when the range is already locked. It never
// reaches a caller: AcquireLock turns it into the message with the holder's pid.
var errLockBusy = errors.New("vault: lock range busy")

// A Lock is a held data-dir lock. Release gives it up; the OS gives it up anyway when the process
// ends, including through os.Exit after a fatal.
type Lock struct {
	f    *os.File
	path string
	once sync.Once
	err  error
}

// lockHolder is the holder line, one JSON object in the first 4 KiB of the lock file. It carries
// no secret: a pid, a command name this binary chose, and a stamp.
type lockHolder struct {
	PID     int    `json:"pid"`
	Cmd     string `json:"cmd"`
	Started string `json:"started"`
}

// LockPath is the lock file's path for a data dir.
func LockPath(dataDir string) string { return filepath.Join(dataDir, LockFileName) }

// AcquireLock takes the data dir's exclusive lock for cmd, creating the data dir and the lock file
// if they do not exist yet - `vault init` takes the lock before anything in the data dir exists.
//
// It never blocks. A lock held elsewhere comes back as an error wrapping ErrLockHeld whose text is
// what the command prints: the holder's pid, command and start time when the holder line reads
// back plausibly, and the lock file's path when it does not. Any other failure - an unusable path,
// a filesystem whose lock cannot be relied on (see proveExclusive) - is returned as itself, and
// the handle is closed before returning so a refusal leaves nothing locked.
func AcquireLock(dataDir, cmd string) (*Lock, error) {
	dataDir = filepath.Clean(dataDir)
	path := LockPath(dataDir)
	if err := makeDataDir(dataDir); err != nil {
		return nil, err
	}
	// Before the open, because the open creates the file, writeHolder truncates it and restrictFile
	// rewrites its ACL by path: a symlink here would send all three somewhere else. os.Lstat does
	// not follow the link, so what it describes is the lock path itself.
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		return nil, fmt.Errorf("vault: %s is a %s: %w", path, lockPathKind(st.Mode()), ErrLockPathNotRegular)
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDWR|os.O_CREATE|lockOpenNoFollow, 0o600)
	if err != nil {
		return nil, fmt.Errorf("vault: open %s: %w", path, err)
	}
	// And again on the open handle, which is what will actually be written: the Lstat above leaves
	// a window where the path could be swapped, lockOpenNoFollow closes it where the OS has an
	// O_NOFOLLOW to close it with, and this fstat is what is left on the OS that does not.
	if st, err := f.Stat(); err != nil {
		return nil, closeAfter(f, fmt.Errorf("vault: stat %s: %w", path, err))
	} else if !st.Mode().IsRegular() {
		return nil, closeAfter(f, fmt.Errorf("vault: %s is a %s: %w", path, lockPathKind(st.Mode()), ErrLockPathNotRegular))
	}
	// Owner-only before the first byte is written. The lock file is not written through
	// replaceFile, so it needs the mode and the Windows ACL set here; the holder line names a pid
	// and a command, not a secret, but the data dir's files are owner-only as a class.
	if err := f.Chmod(0o600); err != nil && !isWindowsChmodQuirk(err) {
		return nil, closeAfter(f, fmt.Errorf("vault: chmod %s: %w", path, err))
	}
	if err := restrictFile(path); err != nil {
		return nil, closeAfter(f, fmt.Errorf("vault: restrict %s: %w", path, err))
	}
	if err := lockHandle(f); err != nil {
		if errors.Is(err, errLockBusy) {
			_ = f.Close()
			pid, hcmd, started, ok := ReadLockHolder(dataDir)
			return nil, heldError{msg: lockHeldMessage(dataDir, pid, hcmd, started, ok)}
		}
		return nil, closeAfter(f, fmt.Errorf("vault: lock %s: %w", path, err))
	}
	// After the lock, before the holder line: a lock the filesystem will not honour is worse than
	// no lock, because both writers believe they are alone. Refuse rather than report success.
	if err := proveExclusive(dataDir); err != nil {
		_ = unlockHandle(f)
		return nil, closeAfter(f, fmt.Errorf("vault: %s cannot hold a reliable lock: %w", dataDir, err))
	}
	l := &Lock{f: f, path: path}
	if err := l.writeHolder(cmd); err != nil {
		_ = unlockHandle(f)
		return nil, closeAfter(f, err)
	}
	return l, nil
}

func closeAfter(f *os.File, err error) error {
	_ = f.Close()
	return err
}

// makeDataDir creates the data dir if it is not there, owner-only: `vault init` takes the lock
// before anything in the data dir exists, so the first holder creates it. The MkdirAll is paired
// with credfile.RestrictDir the way every other MkdirAll in this repository is (hub/enrol.go:91,
// hub/adminpw.go:185) - the mode is nearly meaningless on Windows and the inheritable grant is what
// makes the files written into it afterwards owner-only.
//
// It restricts only a directory it created. AcquireLock runs on every `server run` and every
// mutator, and the data dir of a registered Windows service carries grants `service install` wrote
// with /T, for the service account and BUILTIN\Administrators. Rewriting those on every start
// would lock the operator out of a directory that already holds data, which is the rule
// install.go already follows for the agent's state dir.
// The data dir is the directory the operator named with --data-dir. It is the command's subject,
// not input to be confined to a tree, so there is no traversal here to prevent - which is also why
// AcquireLock's one filepath.Clean is all the normalising it gets.
func makeDataDir(dataDir string) error {
	dataDir = filepath.Clean(dataDir)
	// #nosec G703 -- the data dir is the operator's own --data-dir, cleaned above
	switch st, err := os.Stat(dataDir); {
	case err == nil && st.IsDir():
		return nil
	case err == nil:
		return fmt.Errorf("vault: data dir %s is a %s: %w", dataDir, lockPathKind(st.Mode()), ErrLockPathNotRegular)
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("vault: stat data dir %s: %w", dataDir, err)
	}
	// #nosec G703 -- same path, same reason
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("vault: create data dir %s: %w", dataDir, err)
	}
	if err := restrictDir(dataDir); err != nil {
		return fmt.Errorf("vault: restrict data dir %s: %w", dataDir, err)
	}
	return nil
}

// lockPathKind names what is at a path for the refusal message, so an operator is told whether to
// look for a link, a directory or something stranger. "regular file" never appears: the callers
// only reach this when the mode is not one.
func lockPathKind(m os.FileMode) string {
	switch {
	case m&os.ModeSymlink != 0:
		return "symbolic link"
	case m.IsDir():
		return "directory"
	case m&os.ModeDevice != 0:
		return "device"
	case m&os.ModeNamedPipe != 0:
		return "named pipe"
	case m&os.ModeSocket != 0:
		return "socket"
	default:
		return "not a regular file"
	}
}

// writeHolder replaces the first 4 KiB with this process's holder line and fsyncs it, so a
// contender that is already waiting reads a complete line rather than a half-written one.
func (l *Lock) writeHolder(cmd string) error {
	line, err := json.Marshal(lockHolder{
		PID:     os.Getpid(),
		Cmd:     sanitiseCmd(cmd),
		Started: nowFn().UTC().Truncate(time.Second).Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("vault: holder line: %w", err)
	}
	if len(line) > lockMetaMax {
		return fmt.Errorf("vault: holder line is %d bytes, over %d", len(line), lockMetaMax)
	}
	if err := l.f.Truncate(0); err != nil {
		return fmt.Errorf("vault: truncate %s: %w", l.path, err)
	}
	if _, err := l.f.WriteAt(line, 0); err != nil {
		return fmt.Errorf("vault: write %s: %w", l.path, err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("vault: sync %s: %w", l.path, err)
	}
	return nil
}

// Release gives the lock up. It is safe to call twice, so a command can release explicitly and
// still defer a release; the second call returns the first one's result. The lock file itself
// stays: deleting it would let the next holder lock a different file from the one a contender has
// open, which is the race an O_EXCL lock file has and this one does not.
func (l *Lock) Release() error {
	l.once.Do(func() {
		err := unlockHandle(l.f)
		if cerr := l.f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			l.err = fmt.Errorf("vault: release %s: %w", l.path, err)
		}
	})
	return l.err
}

// ReadLockHolder reads the holder line. ok is false when there is nothing to read or when what is
// there is not a plausible holder line - an empty or truncated file, a pid of zero or less, an
// unprintable or over-long command, a stamp this binary cannot parse. The file is opened for
// reading only and only the first 4 KiB are read, which is outside the locked byte, so this never
// blocks and never fails because someone holds the lock.
//
// Nothing decides anything on what this returns: it is the error message's input. The OS lock is
// what says whether the data dir is in use.
func ReadLockHolder(dataDir string) (pid int, cmd string, started time.Time, ok bool) {
	f, err := os.Open(filepath.Clean(LockPath(dataDir)))
	if err != nil {
		return 0, "", time.Time{}, false
	}
	defer func() { _ = f.Close() }()
	// io.ReadFull, not f.Read: a single Read may stop short of the buffer without an error, and a
	// holder line cut in half unmarshals to nothing and reads as "no metadata", which prints the
	// message without the pid an operator needs. The buffer is the 4 KiB cap and a holder line is
	// about ninety bytes, so io.ErrUnexpectedEOF is the ordinary outcome here, not a failure - what
	// matters is how many bytes came back.
	buf := make([]byte, lockMetaMax)
	n, err := io.ReadFull(f, buf)
	if n <= 0 || (err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)) {
		return 0, "", time.Time{}, false
	}
	var h lockHolder
	if err := json.Unmarshal(trimNUL(buf[:n]), &h); err != nil {
		return 0, "", time.Time{}, false
	}
	if h.PID <= 0 || !printableCmd(h.Cmd) {
		return 0, "", time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, h.Started)
	if err != nil {
		return 0, "", time.Time{}, false
	}
	return h.PID, h.Cmd, t.UTC(), true
}

// trimNUL drops the trailing NUL padding a truncate-then-write can leave behind.
func trimNUL(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0x00 {
		b = b[:len(b)-1]
	}
	return b
}

// printableCmd reports whether a command name read back from the file may be printed: 1 to
// lockCmdMax bytes of printable ASCII. A newline or a control byte in an operator-facing message
// is how a crafted file forges a second line of output.
func printableCmd(s string) bool {
	if len(s) == 0 || len(s) > lockCmdMax {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// sanitiseCmd holds this process's own command name to the same shape it will be read back in, so
// a caller cannot write a line that ReadLockHolder would then refuse to read.
func sanitiseCmd(cmd string) string {
	if printableCmd(cmd) {
		return cmd
	}
	return "unknown"
}

// lockHeldMessage is the text a command prints when it cannot take the lock. Two shapes, exactly
// as the spec gives them: with the holder line, the pid an operator needs to stop the right
// process; without it, the lock file's path. haveMeta says which.
func lockHeldMessage(dataDir string, pid int, cmd string, started time.Time, haveMeta bool) string {
	if !haveMeta {
		return fmt.Sprintf("another process holds %s: stop it first", LockPath(dataDir))
	}
	return fmt.Sprintf("server is running (pid %d, cmd %s, started %s): stop it first",
		pid, cmd, started.UTC().Format(time.RFC3339))
}
