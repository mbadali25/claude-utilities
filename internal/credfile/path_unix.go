//go:build !windows

package credfile

import (
	"os"
	"path/filepath"
)

const isWindows = false

// syncDir fsyncs the directory so the rename is durable. Best effort.
func syncDir(dir string) {
	if d, err := os.Open(filepath.Clean(dir)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// restrictACL is a no-op: Unix modes (0600/0700) are set directly.
func restrictACL(string, bool) error { return nil }
