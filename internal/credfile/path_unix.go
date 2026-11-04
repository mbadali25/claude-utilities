//go:build !windows

package credfile

import "os"

const isWindows = false

// syncDir fsyncs the directory so the rename is durable. Best effort.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
