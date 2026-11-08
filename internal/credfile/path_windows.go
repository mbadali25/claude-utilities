//go:build windows

package credfile

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
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
// the current user, plus every SID the process ACL policy names, full control. Token files therefore
// do not inherit the parent directory's ACL. For a directory the grants are inheritable, so files
// created inside start with the same access. With the default empty policy this is owner-only, which
// is what the agent's credentials file needs.
func restrictACL(path string, dir bool) error {
	u, err := user.Current()
	if err != nil || u.Uid == "" {
		return errors.New("credfile: resolve current user for ACL")
	}
	p, err := icaclsPath(path)
	if err != nil {
		return err
	}
	// Two calls, remove then grant: when the current user is itself one of the well-known accounts
	// (SYSTEM), the grant must land after the removal.
	rm := append([]string{p, "/inheritance:r", "/remove:g"}, wellKnownSIDs...)
	if err := exec.Command("icacls", rm...).Run(); err != nil { // #nosec G204 -- fixed binary, fixed SIDs; path is a file this package just created
		return errors.New("credfile: clear ACL failed")
	}
	// #nosec G204 -- fixed binary; path is a file this package just created, and the grant terms are
	// SIDs the process itself set through SetACLPolicy, never anything a remote caller supplies.
	if err := exec.Command("icacls", grantArgs(p, u.Uid, dir, aclPolicy())...).Run(); err != nil {
		return errors.New("credfile: set ACL failed")
	}
	return nil
}

// maxPathArg is the classic MAX_PATH limit. icacls is an ordinary Win32 console program, so a path
// at or past it has to be handed over in extended-length form even though Go's own file calls take
// it as it is.
const maxPathArg = 260

// icaclsPath returns path in the form icacls can take: unchanged while it is short, and \\?\-prefixed
// once it reaches MAX_PATH, which also requires it to be absolute and clean. A path that cannot be
// made absolute is an error, never a silently unrestricted file.
func icaclsPath(path string) (string, error) {
	if len(path) < maxPathArg || strings.HasPrefix(path, `\\?\`) {
		return path, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("credfile: resolve long path for ACL")
	}
	if strings.HasPrefix(abs, `\\`) { // a UNC path takes the \\?\UNC\server\share form
		return `\\?\UNC` + abs[1:], nil
	}
	return `\\?\` + abs, nil
}
