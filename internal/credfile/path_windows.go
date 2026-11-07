//go:build windows

package credfile

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"syscall"
)

const isWindows = true

// Win32 codes (winerror.h) the syscall package does not name.
const (
	errAccessDenied     syscall.Errno = 5
	errSharingViolation syscall.Errno = 32
)

// syncDir is a no-op on Windows: directories cannot be fsynced.
func syncDir(string) {}

// preserveOwner is a no-op on Windows: there is no uid/gid to hand over, and
// restrictACL already pins the new file's ACL to the current user.
func preserveOwner(string, os.FileInfo) error { return nil }

// renameTransient reports whether a rename failed because another process briefly holds the
// destination open. Go opens files without FILE_SHARE_DELETE, so any reader of the credentials file
// (the agent's own report loop, Claude Code, Defender, an indexer) makes MoveFileEx fail with
// access denied or a sharing violation until it closes the handle.
func renameTransient(err error) bool {
	if errors.Is(err, fs.ErrPermission) {
		return true
	}
	var en syscall.Errno
	return errors.As(err, &en) && (en == errAccessDenied || en == errSharingViolation)
}

// wellKnownSIDs are the accounts a freshly created file can carry as explicit (not inherited) ACEs:
// a process under an elevated token takes its default DACL from the token, which names SYSTEM and
// Administrators, and a temp dir without inheritable ACEs adds nothing to undo that. /inheritance:r
// only drops inherited entries, so these are removed by name before the owner grant.
var wellKnownSIDs = []string{"*S-1-5-18", "*S-1-5-32-544", "*S-1-5-11", "*S-1-5-32-545", "*S-1-1-0"}

// restrictACL removes inherited access and any explicit ACE for the well-known accounts, then grants
// the current user full control only, so token files do not inherit the parent directory's ACL. For a
// directory the grant is inheritable, so files created inside stay owner-only.
func restrictACL(path string, dir bool) error {
	u, err := user.Current()
	if err != nil || u.Uid == "" {
		return errors.New("credfile: resolve current user for ACL")
	}
	grant := "*" + u.Uid + ":F"
	if dir {
		grant = "*" + u.Uid + ":(OI)(CI)F"
	}
	// Two calls, remove then grant: when the current user is itself one of the well-known accounts
	// (SYSTEM), the grant must land after the removal.
	rm := append([]string{path, "/inheritance:r", "/remove:g"}, wellKnownSIDs...)
	if err := exec.Command("icacls", rm...).Run(); err != nil { // #nosec G204 -- fixed binary, fixed SIDs; path is a file this package just created
		return errors.New("credfile: clear ACL failed")
	}
	if err := exec.Command("icacls", path, "/grant:r", grant).Run(); err != nil { // #nosec G204 -- fixed binary; path is a file this package just created
		return errors.New("credfile: set owner-only ACL failed")
	}
	return nil
}
