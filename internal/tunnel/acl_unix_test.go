//go:build !windows

package tunnel

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"testing"
)

// On Unix the mode is the control: ssh refuses a key file that is group or world readable.
func checkKeyFileRestricted(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("the key file is group or world readable: %v", perm)
	}
}

func TestKeyDirIs0700AndKeyFileIs0600(t *testing.T) {
	dir := t.TempDir()
	kd, err := keyDir(dir)
	if err != nil {
		t.Fatalf("keyDir: %v", err)
	}
	fi, err := os.Stat(kd)
	if err != nil {
		t.Fatalf("stat key dir: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("the key dir is group or world accessible: %v", perm)
	}
	p, err := writeKeyFile(kd, "h-1", bytes.Repeat([]byte{4}, ed25519.SeedSize))
	if err != nil {
		t.Fatalf("writeKeyFile: %v", err)
	}
	checkKeyFileRestricted(t, p)
}
