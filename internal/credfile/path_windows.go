//go:build windows

package credfile

const isWindows = true

// syncDir is a no-op on Windows: directories cannot be fsynced.
func syncDir(string) {}
