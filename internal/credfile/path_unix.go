//go:build !windows

package credfile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

const isWindows = false

// Test seams: a test process cannot be root, so both the euid check and the
// chown itself have to be replaceable.
var (
	chownFn   = os.Chown
	geteuidFn = os.Geteuid
)

// preserveOwner gives path the uid and gid of from, so an agent running as root
// for another user leaves that user's files owned by that user. Without it a
// swap renames a root-owned file over the user's .credentials.json and that
// user's Claude Code can no longer read or refresh its own login.
//
// It is a no-op unless the process is root: only root can give a file away, and
// a non-root agent already creates files as the owner. A nil from (no file to
// inherit from yet) keeps the default owner. The error text carries no path: a
// credentials path names the user's home.
func preserveOwner(path string, from os.FileInfo) error {
	if from == nil || geteuidFn() != 0 {
		return nil
	}
	st, ok := from.Sys().(*syscall.Stat_t)
	if !ok { // no uid/gid to copy on this platform
		return nil
	}
	if err := chownFn(path, int(st.Uid), int(st.Gid)); err != nil {
		return errors.New("credfile: preserve owner failed")
	}
	return nil
}

// syncDir fsyncs the directory so the rename is durable. Best effort.
func syncDir(dir string) {
	if d, err := os.Open(filepath.Clean(dir)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// restrictACL is a no-op: Unix modes (0600/0700) are set directly.
func restrictACL(string, bool) error { return nil }
