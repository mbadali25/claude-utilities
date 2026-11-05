//go:build windows

package credfile

import (
	"errors"
	"os/exec"
	"os/user"
)

const isWindows = true

// syncDir is a no-op on Windows: directories cannot be fsynced.
func syncDir(string) {}

// restrictACL removes inherited access and grants the current user full control
// only, so token files do not inherit the parent directory's ACL. For a
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
	if err := exec.Command("icacls", path, "/inheritance:r", "/grant:r", grant).Run(); err != nil { // #nosec G204 -- fixed binary; path is a file this package just created
		return errors.New("credfile: set owner-only ACL failed")
	}
	return nil
}
